#include "host_session.h"
#include "key_vault.h"
#include "secure_server.h"
#include "../crypto/crypto_utils.h"

#include <QFileInfo>
#include <QSettings>
#include <QUuid>

#include <algorithm>

namespace Intercli {

namespace {

// Each ban is kept as "name<TAB>address" (address empty if none was banned).
const char kBans[] = "host/bans";

void saveBans(const std::vector<SecureComm::ServerOptions::Ban>& bans);

// An earlier version kept names and addresses in two unpaired lists. They are
// carried over (each address as its own entry, listed under the address) so
// no ban is lost, and the old lists are removed once the new one is written.
void migrateOldBans() {
    QSettings settings;
    const QStringList names = settings.value("host/bannedNames").toStringList();
    const QStringList addresses = settings.value("host/bannedAddresses").toStringList();
    if (names.isEmpty() && addresses.isEmpty()) {
        return;
    }
    std::vector<SecureComm::ServerOptions::Ban> bans;
    for (const QString& entry : settings.value(kBans).toStringList()) {
        const QStringList parts = entry.split(QLatin1Char('\t'));
        bans.push_back({parts.value(0).toStdString(), parts.value(1).toStdString()});
    }
    for (const QString& name : names) {
        bans.push_back({name.toStdString(), std::string()});
    }
    for (const QString& address : addresses) {
        bans.push_back({address.toStdString(), address.toStdString()});
    }
    saveBans(bans);
    settings.remove("host/bannedNames");
    settings.remove("host/bannedAddresses");
}

std::vector<SecureComm::ServerOptions::Ban> loadBans() {
    migrateOldBans();
    std::vector<SecureComm::ServerOptions::Ban> out;
    for (const QString& entry : QSettings().value(kBans).toStringList()) {
        const QStringList parts = entry.split(QLatin1Char('	'));
        if (!parts.value(0).isEmpty()) {
            out.push_back({parts.value(0).toStdString(), parts.value(1).toStdString()});
        }
    }
    return out;
}

void saveBans(const std::vector<SecureComm::ServerOptions::Ban>& bans) {
    QStringList list;
    for (const auto& ban : bans) {
        list.append(QString::fromStdString(ban.name) + QLatin1Char('	') + QString::fromStdString(ban.address));
    }
    QSettings settings;
    if (list.isEmpty()) {
        settings.remove(kBans);
    } else {
        settings.setValue(kBans, list);
    }
}

// 8081 is left out: the "who is hosting?" questions use it.
const quint16 kPorts[] = {8080, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089};

} // namespace

HostSession::HostSession(const QString& dataDir, QObject* parent) : QObject(parent) {
    const QString keyPath = dataDir + QStringLiteral("/host.key");
    // A new identity key means a new chat: otherwise everyone who joined before
    // would be refused with "identity has changed".
    const bool newIdentity = !QFileInfo::exists(keyPath);
    QSettings settings;
    chat_id_ = settings.value("host/chatId").toString();
    if (chat_id_.isEmpty() || newIdentity) {
        chat_id_ = QUuid::createUuid().toString(QUuid::WithoutBraces);
        settings.setValue("host/chatId", chat_id_);
    }
    // The room code stays the same every time this PC hosts (owner's choice).
    room_code_ = settings.value("host/roomCode").toString();
    if (room_code_.size() != 6) {
        SecureComm::CryptoManager crypto;
        room_code_ = QString::fromStdString(crypto.generate_room_code());
        settings.setValue("host/roomCode", room_code_);
    }

    identity_private_ = loadOrCreateSecret(keyPath, 32);
    if (identity_private_.size() == 32) {
        SecureComm::CryptoManager crypto;
        const std::vector<uint8_t> raw(identity_private_.begin(), identity_private_.end());
        const std::vector<uint8_t> pub = crypto.identity_from_private(raw).public_raw;
        identity_public_ = QByteArray(reinterpret_cast<const char*>(pub.data()), static_cast<qsizetype>(pub.size()));
    }

    people_timer_.setInterval(2000);
    connect(&people_timer_, &QTimer::timeout, this, &HostSession::pollPeople);
}

HostSession::~HostSession() {
    stop();
}

QString HostSession::safetyCode() const {
    const std::vector<uint8_t> pub(identity_public_.begin(), identity_public_.end());
    return QString::fromStdString(SecureComm::safety_code(pub));
}

void HostSession::setPeoplePollForTests(int ms) {
    people_timer_.setInterval(ms);
}

void HostSession::start(const QString& hostName, quint16 discoveryPort) {
    if (running()) {
        emit started(port_);
        return;
    }
    if (identity_private_.size() != 32) {
        emit failed(QStringLiteral("This PC can't keep the chat's identity key safe, so it can't host."));
        return;
    }
    host_name_ = hostName;
    chat_name_ = hostName + QStringLiteral("'s chat");

    std::string last_error;
    for (quint16 port : kPorts) {
        SecureComm::ServerOptions options;
        options.port = port;
        options.room_code = room_code_.toStdString();
        options.identity_private.assign(identity_private_.begin(), identity_private_.end());
        options.bans = loadBans();
        auto server = std::make_unique<SecureComm::SecureServer>(options);
        if (server->start(&last_error)) {
            server_ = std::move(server);
            port_ = port;
            break;
        }
    }
    if (!server_) {
        emit failed(QStringLiteral("No free port to host on (tried 8080 and 8082 to 8089)."));
        return;
    }

    // The accept loop blocks, so it gets its own thread; binding happened above.
    runner_ = std::thread([server = server_.get()] { server->run(); });

    discoverable_ = beacon_.start(discoveryPort);
    people_ = 0;
    announce();
    people_timer_.start();
    emit started(port_);
}

void HostSession::stop() {
    people_timer_.stop();
    beacon_.stop();
    if (server_) {
        server_->stop();
    }
    if (runner_.joinable()) {
        runner_.join();
    }
    server_.reset();
    port_ = 0;
    discoverable_ = false;
    if (people_ != 0) {
        people_ = 0;
        emit peopleChanged();
    }
}

bool HostSession::kick(const QString& name) {
    return server_ && server_->kick(name.toStdString());
}

bool HostSession::ban(const QString& name) {
    if (!server_ || !server_->ban(name.toStdString())) {
        return false;
    }
    saveBans(server_->bans());
    return true;
}

bool HostSession::unban(const QString& name) {
    std::vector<SecureComm::ServerOptions::Ban> bans = loadBans();
    const auto before = bans.size();
    bans.erase(std::remove_if(bans.begin(), bans.end(),
                              [&](const auto& ban) { return ban.name == name.toStdString(); }),
               bans.end());
    if (server_) {
        server_->unban(name.toStdString());
    }
    saveBans(bans);
    return bans.size() != before;
}

void HostSession::clearBans() {
    if (server_) {
        server_->clear_bans();
    }
    saveBans({});
}

QStringList HostSession::bannedNames() const {
    QStringList out;
    for (const auto& ban : loadBans()) {
        out.append(QString::fromStdString(ban.name));
    }
    return out;
}

int HostSession::bannedCount() const {
    return static_cast<int>(loadBans().size());
}

bool HostSession::newRoomCode() {
    if (!server_) {
        return false;
    }
    SecureComm::CryptoManager crypto;
    const QString code = QString::fromStdString(crypto.generate_room_code());
    if (!server_->set_room_code(code.toStdString())) {
        return false;
    }
    room_code_ = code;
    QSettings().setValue("host/roomCode", room_code_);
    return true;
}

int HostSession::peopleNow() const {
    return server_ ? static_cast<int>(server_->people()) : 0;
}

bool HostSession::running() const {
    return server_ != nullptr;
}

void HostSession::pollPeople() {
    if (!server_) {
        return;
    }
    const int now = static_cast<int>(server_->people());
    if (now != people_) {
        people_ = now;
        announce();
        emit peopleChanged();
    }
}

void HostSession::announce() {
    ChatAnnouncement a;
    a.chatId = chat_id_;
    a.chatName = chat_name_;
    a.hostName = host_name_;
    a.safetyCode = safetyCode();
    a.identityKey = identity_public_;
    a.port = port_;
    a.people = people_;
    beacon_.setAnnouncement(a);
}

} // namespace Intercli
