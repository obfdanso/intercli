#include "chat_controller.h"
#include "text_utils.h"
#include "host_session.h"
#include "network_check.h"
#include "../crypto/crypto_utils.h"

#include <QDateTime>
#include <QSettings>
#include <QClipboard>
#include <QNetworkInterface>
#include <QGuiApplication>
#include <QTimer>

namespace Intercli {

namespace {

QString qs(const std::string& s) {
    return QString::fromUtf8(s.data(), static_cast<qsizetype>(s.size()));
}

std::string ss(const QString& s) {
    return s.toUtf8().toStdString();
}

} // namespace

ChatController::ChatController(HistoryStore* history, HostSession* host, quint16 discoveryPort, QObject* parent)
    : QObject(parent), list_(new ConversationListModel(this)), filter_(new QSortFilterProxyModel(this)),
      history_(history), host_session_(host), finder_(new ChatFinder(this)) {
    // Always looking: the sign-in list needs it, and so does Reconnect when a
    // chat's address has changed.
    discovery_port_ = discoveryPort;
    finder_->start(discoveryPort);
    if (host_session_) {
        connect(host_session_, &HostSession::started, this, &ChatController::onHostStarted);
        connect(host_session_, &HostSession::failed, this, &ChatController::onHostFailed);
        connect(host_session_, &HostSession::peopleChanged, this, &ChatController::peopleInChatChanged);
    }
    filter_->setSourceModel(list_);
    filter_->setFilterRole(ConversationListModel::TitleRole);
    filter_->setFilterCaseSensitivity(Qt::CaseInsensitive);
    connect(list_, &ConversationListModel::onlineCountChanged, this, &ChatController::onlineCountChanged);

    QSettings settings;
    host_ = settings.value("lastHost", "127.0.0.1").toString();
    port_ = settings.value("lastPort", 8080).toInt();
    my_name_ = settings.value("lastName").toString();
}

ChatController::~ChatController() {
    ++generation_;
    abandonConnection();
    // Only here, at exit, do we wait for cancelled connects to wind down.
    for (Retired& r : retired_) {
        if (r.thread.joinable()) {
            r.thread.join();
        }
    }
}

// Only called once the worker has reported back, so the join is instant.
void ChatController::finishWorker() {
    if (worker_.joinable()) {
        worker_.join();
    }
}

void ChatController::reapRetired() {
    for (auto it = retired_.begin(); it != retired_.end();) {
        if (it->done && *it->done) {
            it->thread.join();
            it = retired_.erase(it);
        } else {
            ++it;
        }
    }
}

// Lets go of the current connection without ever blocking the UI thread on a
// connect in flight: that client is cancelled and its worker set aside.
void ChatController::abandonConnection() {
    const bool connecting = worker_.joinable() && !(worker_done_ && *worker_done_);
    if (client_) {
        if (connecting) {
            client_->cancel();
        } else {
            client_->disconnect();
        }
        client_.reset();
    }
    if (worker_.joinable()) {
        if (connecting) {
            retired_.push_back(Retired{std::move(worker_), worker_done_});
        } else {
            worker_.join();
        }
    }
    worker_done_.reset();
    reapRetired();
}

void ChatController::setState(State s) {
    if (state_ != s) {
        state_ = s;
        emit stateChanged();
    }
}

void ChatController::setErrors(const QString& connectError, const QString& nameError, const QString& codeError,
                               const QString& hostError) {
    if (connect_error_ != connectError || name_error_ != nameError || code_error_ != codeError ||
        host_error_ != hostError) {
        connect_error_ = connectError;
        name_error_ = nameError;
        code_error_ = codeError;
        host_error_ = hostError;
        emit errorsChanged();
    }
}

bool ChatController::isValidName(const QString& name) {
    return Intercli::isValidName(name);
}

int ChatController::utf8Length(const QString& text) {
    return Intercli::utf8Length(text);
}

QVariantList ChatController::avatarColors(const QString& name) {
    const auto pair = Intercli::avatarColors(name);
    return {pair.first, pair.second};
}

QString ChatController::initialFor(const QString& name) {
    return Intercli::initialFor(name);
}

// Every callback hops onto the UI thread and is dropped if the connection it
// came from has since been abandoned.
std::shared_ptr<SecureComm::ChatClient> ChatController::makeClient() {
    const quint64 gen = generation_;
    auto post = [this, gen](auto fn) {
        QMetaObject::invokeMethod(this, [this, gen, fn] {
            if (gen == generation_) {
                fn();
            }
        }, Qt::QueuedConnection);
    };

    SecureComm::ChatEvents ev;
    ev.on_registered = [this, post](const std::string& n) { post([this, n] { onRegistered(qs(n)); }); };
    ev.on_register_failed = [this, post](const std::string& r) { post([this, r] { onRegisterFailed(qs(r)); }); };
    ev.on_direct = [this, post](const std::string& f, const std::string& t) {
        post([this, f, t] { onDirect(qs(f), qs(t)); });
    };
    ev.on_broadcast = [this, post](const std::string& f, const std::string& t) {
        post([this, f, t] { onBroadcast(qs(f), qs(t)); });
    };
    ev.on_roster = [this, post](const std::vector<std::string>& names, const std::string&) {
        QStringList list;
        for (const auto& n : names) {
            list.append(qs(n));
        }
        post([this, list] { onRoster(list); });
    };
    ev.on_presence = [this, post](const std::string& n, bool joined, const std::string& raw) {
        post([this, n, joined, raw] { onPresence(qs(n), joined, qs(raw)); });
    };
    ev.on_notice = [this, post](const std::string& t) { post([this, t] { onNotice(qs(t)); }); };
    ev.on_server_error = [this, post](const std::string& t) {
        post([this, t] { onNotice(QStringLiteral("Server error: ") + qs(t)); });
    };
    ev.on_send_key_rotated = [this, post] { post([this] { onSendKeyRotated(); }); };
    ev.on_receive_key_rotated = [this, post] { post([this] { emit sessionChanged(); }); };
    ev.on_disconnected = [this, post](const std::string& r) { post([this, r] { onDisconnected(qs(r)); }); };
    return std::make_shared<SecureComm::ChatClient>(ev);
}

// Connects and asks for the name on a worker thread: RSA key generation, DNS and
// the handshake all block.
void ChatController::startConnect(const QString& name) {
    abandonConnection();
    ++generation_;
    client_ = makeClient();

    // Trust on first use: a chat we have joined before must prove the same
    // identity key, or nothing (not even the room code) is sent to it.
    const QByteArray pinned = QByteArray::fromHex(QSettings().value("identities/" + pinKey()).toByteArray());
    identity_was_known_ = pinned.size() == 32;
    if (identity_was_known_) {
        client_->set_expected_identity(std::vector<uint8_t>(pinned.begin(), pinned.end()));
    } else if (announced_identity_.size() == 32) {
        // A first join from the list: the server must prove the key the chat
        // announced, so redirecting the connection can't capture the code.
        client_->set_expected_identity(std::vector<uint8_t>(announced_identity_.begin(), announced_identity_.end()));
    }

    const quint64 gen = generation_;
    auto client = client_;
    const std::string host = ss(host_);
    const auto port = static_cast<uint16_t>(port_);
    const std::string wanted = ss(name);
    const std::string code = ss(room_code_);
    auto done = std::make_shared<std::atomic<bool>>(false);
    worker_done_ = done;
    worker_ = std::thread([this, gen, client, host, port, wanted, code, done] {
        std::string error;
        const bool ok = client->connect(host, port, &error);
        if (ok) {
            client->request_name(wanted, code);
        }
        *done = true;
        QMetaObject::invokeMethod(this, [this, gen, ok, error] {
            if (gen == generation_) {
                onConnectResult(ok, qs(error));
            }
        }, Qt::QueuedConnection);
    });
}

// Shared by every way of signing in; host_, port_, chat_id_ and room_code_
// are set by the caller.
bool ChatController::beginSignIn(const QString& name) {
    if (state_ != SignedOut) {
        return false;
    }
    if (!Intercli::isValidName(name)) {
        setErrors(QString(), QStringLiteral("Names are 1-31 characters with no spaces"));
        return false;
    }
    my_name_ = name;
    emit serverChanged();
    emit myNameChanged();

    QSettings settings;
    settings.setValue("lastName", my_name_);

    identity_changed_ = false;
    setErrors(QString(), QString());
    needs_sign_in_ = false;
    register_retries_ = 0;
    // Saved history follows the chat, not its address, when we know the chat.
    identity_ = chat_id_.isEmpty() ? identityKey(host_, port_, my_name_)
                                   : QStringLiteral("chat:%1/%2").arg(chat_id_, my_name_);
    history_loaded_ = false;
    emit historyChoiceChanged();
    setState(Connecting);
    startConnect(name);
    return true;
}

void ChatController::signIn(const QString& host, int port, const QString& name, const QString& roomCode) {
    if (state_ != SignedOut) {
        return;
    }
    if (!Intercli::isValidName(name)) {
        setErrors(QString(), QStringLiteral("Names are 1-31 characters with no spaces"));
        return;
    }
    QString address = host.trimmed();
    // The details panel shows a hosted chat as "192.168.1.20:8080"; take the
    // port from an address pasted in that form.
    // An IPv6 address has colons of its own, so with a port it is written
    // "[fe80::1]:8080"; the brackets come off either way.
    const qsizetype colon = address.lastIndexOf(QLatin1Char(':'));
    const qsizetype bracket = address.indexOf(QLatin1Char(']'));
    if (address.startsWith(QLatin1Char('[')) && bracket > 0) {
        const QString rest = address.mid(bracket + 1);
        bool isNumber = false;
        const int pasted = rest.mid(1).toInt(&isNumber);
        if (rest.startsWith(QLatin1Char(':')) && isNumber) {
            port = pasted;
        }
        address = address.mid(1, bracket - 1).trimmed();
    } else if (colon > 0 && address.count(QLatin1Char(':')) == 1) {
        bool isNumber = false;
        const int pasted = address.mid(colon + 1).toInt(&isNumber);
        if (isNumber) {
            port = pasted;
            address = address.left(colon).trimmed();
        }
    }
    if (address.isEmpty() || port < 1 || port > 65535) {
        setErrors(QStringLiteral("Enter a server address and a port from 1 to 65535"), QString());
        return;
    }
    host_ = address;
    port_ = port;
    emit serverChanged();
    chat_id_.clear();
    announced_identity_.clear();
    room_code_ = QString::fromStdString(SecureComm::normalize_room_code(ss(roomCode)));
    QSettings settings;
    settings.setValue("lastHost", host_);
    settings.setValue("lastPort", port_);
    beginSignIn(name);
}

void ChatController::joinChat(const QString& chatId, const QString& roomCode, const QString& name) {
    if (state_ != SignedOut) {
        return;
    }
    const QString code = QString::fromStdString(SecureComm::normalize_room_code(ss(roomCode)));
    if (code.isEmpty()) {
        setErrors(QString(), QString(), QStringLiteral("Enter the room code"));
        return;
    }
    const auto chat = finder_->find(chatId);
    if (!chat) {
        setErrors(QStringLiteral("That chat is no longer on this network"), QString());
        return;
    }
    host_ = chat->address.toString();
    port_ = chat->port;
    chat_id_ = chatId;
    room_code_ = code;
    announced_identity_ = chat->identityKey;
    beginSignIn(name);
}

void ChatController::hostChat(const QString& name) {
    if (state_ != SignedOut || hosting_) {
        return;
    }
    if (!host_session_) {
        setErrors(QString(), QString(), QString(), QStringLiteral("Hosting isn't available"));
        return;
    }
    if (!Intercli::isValidName(name)) {
        setErrors(QString(), QStringLiteral("Names are 1-31 characters with no spaces"));
        return;
    }
    refreshNetworkCheck();
    my_name_ = name;
    setErrors(QString(), QString());
    hosting_ = true;
    emit hostingChanged();
    host_session_->start(name, discovery_port_);
}

void ChatController::onHostStarted(quint16 port) {
    if (!hosting_ || state_ != SignedOut) {
        return;
    }
    QSettings().setValue("host/firewallNoteShown", true);
    // Join our own chat like anyone else, over this PC's loopback.
    host_ = QStringLiteral("127.0.0.1");
    port_ = port;
    chat_id_ = host_session_->chatId();
    room_code_ = host_session_->roomCode();
    announced_identity_ = host_session_->identityPublic();
    // We know our own identity, so it is pinned from the start.
    QSettings().setValue("identities/chat:" + chat_id_, host_session_->identityPublic().toHex());
    emit hostingChanged();
    if (!beginSignIn(my_name_)) {
        host_session_->stop();
        hosting_ = false;
        emit hostingChanged();
    }
}

void ChatController::onHostFailed(const QString& reason) {
    hosting_ = false;
    emit hostingChanged();
    setErrors(QString(), QString(), QString(), reason);
}

void ChatController::endChat() {
    if (hosting_ && host_session_) {
        // Sign out first so our own connection closes cleanly, then stop.
        hosting_ = false;
        signOut();
        host_session_->stop();
        emit hostingChanged();
        emit peopleInChatChanged();
        return;
    }
    signOut();
}

bool ChatController::needsEndChatConfirm() const {
    // The live count: someone who joined a moment ago counts too.
    return hosting_ && host_session_ && host_session_->peopleNow() > 1;
}

QString ChatController::roomCode() const {
    return hosting_ && host_session_ ? QString::fromStdString(SecureComm::format_room_code(ss(host_session_->roomCode())))
                                     : QString();
}

int ChatController::peopleInChat() const {
    return hosting_ && host_session_ ? host_session_->people() : 0;
}

QString ChatController::safetyCode() const {
    if (server_identity_.size() != 32) {
        return QString();
    }
    const std::vector<uint8_t> raw(server_identity_.begin(), server_identity_.end());
    return QString::fromStdString(SecureComm::safety_code(raw));
}

bool ChatController::firewallNoteNeeded() const {
    return !QSettings().value("host/firewallNoteShown", false).toBool();
}

QString ChatController::rememberedCode(const QString& chatId) const {
    const QString code = QSettings().value("codes/" + chatId).toString();
    return code.isEmpty() ? QString() : QString::fromStdString(SecureComm::format_room_code(ss(code)));
}

bool ChatController::kickPerson(const QString& name) {
    return hosting_ && host_session_ && name != my_name_ && host_session_->kick(name);
}

bool ChatController::banPerson(const QString& name) {
    return hosting_ && host_session_ && name != my_name_ && host_session_->ban(name);
}

void ChatController::changeRoomCode() {
    if (!hosting_ || !host_session_ || !host_session_->newRoomCode()) {
        return;
    }
    // Our own reconnects need the new code too.
    room_code_ = host_session_->roomCode();
    if (!chat_id_.isEmpty()) {
        QSettings().setValue("codes/" + chat_id_, room_code_);
    }
    emit hostingChanged();
}

void ChatController::copyRoomCode() const {
    if (QClipboard* clipboard = QGuiApplication::clipboard()) {
        clipboard->setText(roomCode());
    }
}

void ChatController::refreshNetworkCheck() {
    const bool isPublic = onPublicNetwork();
    if (isPublic != public_network_) {
        public_network_ = isPublic;
        emit publicNetworkChanged();
    }
}

QString ChatController::pinKey() const {
    return chat_id_.isEmpty() ? QStringLiteral("addr:%1:%2").arg(host_).arg(port_) : QStringLiteral("chat:") + chat_id_;
}

void ChatController::onConnectResult(bool ok, const QString& error) {
    finishWorker();
    if (ok) {
        return;  // the name answer arrives through onRegistered / onRegisterFailed
    }
    // The client library says what went wrong: not found, unreachable, no answer.
    const QString reason = error.isEmpty() ? QStringLiteral("Couldn't reach %1:%2").arg(host_).arg(port_) : error;
    if (error.startsWith(QStringLiteral("This chat's identity")) && client_) {
        // Keep what it presented, so its safety code can be compared and trusted.
        const std::vector<uint8_t> presented = client_->server_identity();
        new_identity_ = QByteArray(reinterpret_cast<const char*>(presented.data()), static_cast<qsizetype>(presented.size()));
        identity_changed_ = new_identity_.size() == 32;
    }
    abandonConnection();
    if (state_ == Connecting) {
        if (hosting_ && host_session_) {
            host_session_->stop();
            hosting_ = false;
            emit hostingChanged();
        }
        setErrors(reason, QString());
        setState(SignedOut);
    } else if (state_ == Reconnecting) {
        disconnect_reason_ = reason;
        setState(Disconnected);
        emit stateChanged();
    }
}

void ChatController::onRegistered(const QString& name) {
    my_name_ = name;
    emit myNameChanged();
    disconnect_reason_.clear();
    if (client_) {
        const std::vector<uint8_t> id = client_->server_identity();
        server_identity_ = QByteArray(reinterpret_cast<const char*>(id.data()), static_cast<qsizetype>(id.size()));
        QSettings settings;
        if (!identity_was_known_) {
            settings.setValue("identities/" + pinKey(), server_identity_.toHex());
        }
        if (!chat_id_.isEmpty() && !room_code_.isEmpty()) {
            settings.setValue("codes/" + chat_id_, room_code_);
        }
    }
    if (!history_loaded_) {
        history_loaded_ = true;
        loadSavedHistory();
    }
    setState(Online);
    if (client_) {
        client_->request_roster();
    }
    emit sessionChanged();
}

void ChatController::onRegisterFailed(const QString& reason) {
    if (state_ == Connecting) {
        ++generation_;
        abandonConnection();
        const bool codeProblem = reason == QStringLiteral("Wrong room code") || reason.startsWith(QStringLiteral("Too many wrong"));
        const bool wasHosting = hosting_;
        if (hosting_ && host_session_) {
            host_session_->stop();
            hosting_ = false;
            emit hostingChanged();
        }
        if (wasHosting) {
            setErrors(QString(), QString(), QString(), reason);  // shown by the Host button
        } else if (codeProblem) {
            setErrors(QString(), QString(), reason);
        } else {
            setErrors(QString(), reason);
        }
        setState(SignedOut);
        return;
    }
    if (state_ == Reconnecting) {
        // The server may not have noticed the old connection close yet; give it a moment.
        if (reason.contains(QStringLiteral("taken")) && register_retries_ < 3 && client_) {
            ++register_retries_;
            const quint64 gen = generation_;
            QTimer::singleShot(1000, this, [this, gen] {
                if (gen == generation_ && state_ == Reconnecting && client_) {
                    client_->request_name(ss(my_name_), ss(room_code_));
                }
            });
            return;
        }
        ++generation_;
        abandonConnection();
        disconnect_reason_ = reason;
        needs_sign_in_ = true;
        setState(Disconnected);
        emit stateChanged();
    }
}

MessageModel* ChatController::modelFor(const QString& id) {
    const QString key = id.isNull() ? QStringLiteral("") : id;
    auto it = models_.find(key);
    if (it == models_.end()) {
        it = models_.insert(key, new MessageModel(key.isEmpty(), this));
    }
    return it.value();
}

MessageModel* ChatController::messages() {
    return modelFor(current_);
}

void ChatController::setCurrentConversation(const QString& id) {
    const QString key = id.isNull() ? QStringLiteral("") : id;
    if (!key.isEmpty()) {
        list_->ensure(key);
    }
    list_->markRead(key);
    if (current_ != key) {
        current_ = key;
        emit currentConversationChanged();
    }
}

void ChatController::setWindowActive(bool active) {
    if (window_active_ != active) {
        window_active_ = active;
        if (active) {
            list_->markRead(current_);
        }
        emit windowActiveChanged();
    }
}

void ChatController::clearErrors() {
    identity_changed_ = false;
    setErrors(QString(), QString());
}

QString ChatController::hostAddress() const {
    if (!hosting_ || !host_session_ || host_session_->port() == 0) {
        return QString();
    }
    QStringList addresses;
    for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
        const auto flags = iface.flags();
        if (!(flags & QNetworkInterface::IsUp) || !(flags & QNetworkInterface::IsRunning) ||
            (flags & QNetworkInterface::IsLoopBack)) {
            continue;
        }
        for (const QNetworkAddressEntry& entry : iface.addressEntries()) {
            if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol) {
                addresses << entry.ip().toString() + QLatin1Char(':') + QString::number(host_session_->port());
            }
        }
    }
    return addresses.join(QStringLiteral(", "));
}

QString ChatController::newSafetyCode() const {
    if (new_identity_.size() != 32) {
        return QString();
    }
    const std::vector<uint8_t> raw(new_identity_.begin(), new_identity_.end());
    return QString::fromStdString(SecureComm::safety_code(raw));
}

void ChatController::trustNewIdentity() {
    if (!identity_changed_ || state_ != SignedOut) {
        return;
    }
    QSettings().setValue("identities/" + pinKey(), new_identity_.toHex());
    identity_changed_ = false;
    beginSignIn(my_name_);
}

void ChatController::setSearch(const QString& text) {
    filter_->setFilterFixedString(text);
}

int ChatController::historyChoice() const {
    return history_ && !identity_.isEmpty() ? static_cast<int>(history_->choice(identity_)) : 0;
}

bool ChatController::saving() const {
    return history_ && !identity_.isEmpty() && history_->choice(identity_) == HistoryChoice::Save;
}

void ChatController::setHistoryChoice(int choice, bool deleteExisting) {
    if (!history_ || identity_.isEmpty() || choice < 0 || choice > 2) {
        return;
    }
    const auto c = static_cast<HistoryChoice>(choice);
    history_->setChoice(identity_, c);
    if (c == HistoryChoice::DontSave && deleteExisting) {
        history_->deleteAll(identity_);
    }
    emit historyChoiceChanged();
}

// Brings back the conversations saved for this name on this server: the sidebar
// rows (offline until the roster says otherwise) and each one's latest messages.
void ChatController::loadSavedHistory() {
    if (!saving()) {
        return;
    }
    for (const ConversationSummary& c : history_->conversations(identity_)) {
        QString preview = c.lastText;
        if (c.lastKind == MessageModel::Outgoing) {
            preview = QStringLiteral("You: ") + c.lastText;
        } else if (c.conversation.isEmpty()) {
            preview = c.lastSender + QStringLiteral(": ") + c.lastText;
        }
        list_->touch(c.conversation, preview, c.lastTime, false);

        QList<ChatEntry> entries;
        for (const StoredMessage& m : history_->loadPage(identity_, c.conversation, 50)) {
            entries.append(ChatEntry{m.id, static_cast<MessageModel::Kind>(m.kind), m.sender, m.text, m.time});
        }
        modelFor(c.conversation)->prepend(entries);
    }
}

void ChatController::loadOlder() {
    if (!saving()) {
        return;
    }
    MessageModel* model = modelFor(current_);
    const qint64 oldest = model->oldestId();
    if (oldest <= 0) {
        return;  // nothing saved above what is shown
    }
    QList<ChatEntry> entries;
    for (const StoredMessage& m : history_->loadPage(identity_, current_, 50, oldest)) {
        entries.append(ChatEntry{m.id, static_cast<MessageModel::Kind>(m.kind), m.sender, m.text, m.time});
    }
    model->prepend(entries);
}

void ChatController::addRow(const QString& conversation, MessageModel::Kind kind, const QString& sender,
                            const QString& text, bool persist) {
    ChatEntry e;
    e.kind = kind;
    e.sender = sender;
    e.text = text;
    e.time = QDateTime::currentDateTime();
    e.id = 0;
    if (persist && saving()) {
        StoredMessage m;
        m.conversation = conversation;
        m.kind = static_cast<int>(kind);
        m.sender = sender;
        m.text = text;
        m.time = e.time;
        e.id = history_->append(identity_, m);
    }
    if (e.id <= 0) {
        e.id = next_local_id_--;
    }
    modelFor(conversation)->append(e);
}

void ChatController::onDirect(const QString& from, const QString& text) {
    addRow(from, MessageModel::Incoming, from, text, true);
    const bool unseen = from != current_ || !window_active_;
    list_->touch(from, text, QDateTime::currentDateTime(), unseen);
    emit messageArrived(from);
}

void ChatController::onBroadcast(const QString& from, const QString& text) {
    addRow(QString(), MessageModel::Incoming, from, text, true);
    const bool unseen = !current_.isEmpty() || !window_active_;
    list_->touch(QString(), from + QStringLiteral(": ") + text, QDateTime::currentDateTime(), unseen);
    emit messageArrived(QString());
}

void ChatController::onRoster(const QStringList& names) {
    list_->setRoster(names, my_name_);
    emit onlineCountChanged();
}

void ChatController::onPresence(const QString& name, bool joined, const QString& raw) {
    if (name == my_name_) {
        return;
    }
    const bool known = models_.contains(name);
    list_->setOnline(name, joined);
    addRow(QString(), MessageModel::System, QString(), raw, true);
    if (known) {
        addRow(name, MessageModel::System, QString(), raw, true);
    }
}

void ChatController::onNotice(const QString& text) {
    addRow(last_target_, MessageModel::System, QString(), text, false);
}

void ChatController::onSendKeyRotated() {
    addRow(current_, MessageModel::System, QString(), QStringLiteral("Your send key rotated"), false);
    emit sessionChanged();
}

void ChatController::onDisconnected(const QString& reason) {
    if (state_ == Online) {
        Q_UNUSED(reason);
        // Close our end too: after a receive error the socket is still open
        // and the server would keep showing us online.
        ++generation_;
        abandonConnection();
        disconnect_reason_ = QStringLiteral("Disconnected from server");
        needs_sign_in_ = false;
        // Nobody can be known to be online while we are cut off; the roster
        // comes back after reconnecting.
        list_->setRoster({}, my_name_);
        setState(Disconnected);
        emit stateChanged();
        emit onlineCountChanged();
    } else if (state_ == Connecting) {
        ++generation_;
        abandonConnection();
        if (hosting_ && host_session_) {
            // Our own join failed: don't leave the chat running with nobody
            // able to sign in or host again.
            host_session_->stop();
            hosting_ = false;
            emit hostingChanged();
            setErrors(QString(), QString(), QString(), reason);
        } else {
            setErrors(reason, QString());
        }
        setState(SignedOut);
    } else if (state_ == Reconnecting) {
        ++generation_;
        abandonConnection();
        disconnect_reason_ = reason;
        setState(Disconnected);
        emit stateChanged();
    }
}

bool ChatController::send(const QString& text) {
    if (state_ != Online || !client_ || text.trimmed().isEmpty() || Intercli::utf8Length(text) > 1024) {
        return false;
    }
    const std::string body = ss(text);
    const bool ok = current_.isEmpty() ? client_->send_broadcast(body) : client_->send_direct(ss(current_), body);
    if (!ok) {
        return false;
    }
    last_target_ = current_;
    addRow(current_, MessageModel::Outgoing, my_name_, text, true);
    list_->touch(current_, QStringLiteral("You: ") + text, QDateTime::currentDateTime(), false);
    emit sessionChanged();
    return true;
}

void ChatController::rotateKey() {
    if (state_ == Online && client_) {
        client_->rotate_send_key();
    }
}

void ChatController::reconnect() {
    if (state_ != Disconnected || needs_sign_in_) {
        return;
    }
    register_retries_ = 0;
    // A chat from the list may have a new address or port by now.
    if (!chat_id_.isEmpty() && !hosting_) {
        if (const auto chat = finder_->find(chat_id_)) {
            host_ = chat->address.toString();
            port_ = chat->port;
        }
    }
    setState(Reconnecting);
    startConnect(my_name_);
}

void ChatController::signOut() {
    ++generation_;
    abandonConnection();
    if (hosting_ && host_session_) {
        host_session_->stop();
        hosting_ = false;
        emit hostingChanged();
        emit peopleInChatChanged();
    }
    server_identity_.clear();
    list_->clear();
    for (MessageModel* m : models_) {
        m->clear();
    }
    current_ = QStringLiteral("");
    last_target_.clear();
    history_loaded_ = false;
    disconnect_reason_.clear();
    needs_sign_in_ = false;
    setErrors(QString(), QString());
    emit currentConversationChanged();
    emit onlineCountChanged();
    setState(SignedOut);
}

void ChatController::simulateReceiveError() {
    if (client_) {
        client_->fail_receive_for_test();
    }
}

void ChatController::simulateConnectionLoss() {
    if (client_) {
        client_->drop_connection_for_test();
    }
}

QVariantMap ChatController::session() const {
    SecureComm::SessionStatus st = client_ ? client_->status() : SecureComm::SessionStatus{};
    QVariantMap m;
    m["cipher"] = qs(st.cipher);
    m["keyExchange"] = qs(st.key_exchange);
    m["serverIdentity"] = server_identity_.isEmpty() ? QStringLiteral("Not verified")
                        : identity_was_known_      ? QStringLiteral("Verified")
                                                   : QStringLiteral("First join");
    m["sendRotations"] = static_cast<int>(st.send_rotations);
    m["receiveRotations"] = static_cast<int>(st.receive_rotations);
    m["messagesUntilRotation"] = static_cast<int>(st.messages_until_rotation);
    m["lastSendRotation"] = st.last_send_rotation
        ? QDateTime::fromMSecsSinceEpoch(std::chrono::duration_cast<std::chrono::milliseconds>(
              st.last_send_rotation->time_since_epoch()).count())
        : QDateTime();
    return m;
}

} // namespace Intercli
