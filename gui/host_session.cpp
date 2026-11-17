#include "host_session.h"
#include "key_vault.h"
#include "secure_server.h"
#include "../crypto/crypto_utils.h"

#include <QFileInfo>
#include <QSettings>
#include <QUuid>

namespace Intercli {

namespace {

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
    return server_ && server_->ban(name.toStdString());
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
