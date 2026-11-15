#include "chat_controller.h"
#include "text_utils.h"

#include <QDateTime>
#include <QSettings>
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

ChatController::ChatController(QObject* parent)
    : QObject(parent), list_(new ConversationListModel(this)), filter_(new QSortFilterProxyModel(this)) {
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
    finishWorker();
    dropClient();
}

void ChatController::finishWorker() {
    if (worker_.joinable()) {
        worker_.join();
    }
}

void ChatController::dropClient() {
    if (client_) {
        client_->disconnect();
        client_.reset();
    }
}

void ChatController::setState(State s) {
    if (state_ != s) {
        state_ = s;
        emit stateChanged();
    }
}

void ChatController::setErrors(const QString& connectError, const QString& nameError) {
    if (connect_error_ != connectError || name_error_ != nameError) {
        connect_error_ = connectError;
        name_error_ = nameError;
        emit errorsChanged();
    }
}

bool ChatController::isValidName(const QString& name) {
    return Intercli::isValidName(name);
}

int ChatController::utf8Length(const QString& text) {
    return Intercli::utf8Length(text);
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
    finishWorker();
    dropClient();
    ++generation_;
    client_ = makeClient();

    const quint64 gen = generation_;
    auto client = client_;
    const std::string host = ss(host_);
    const auto port = static_cast<uint16_t>(port_);
    const std::string wanted = ss(name);
    worker_ = std::thread([this, gen, client, host, port, wanted] {
        std::string error;
        const bool ok = client->connect(host, port, &error);
        if (ok) {
            client->request_name(wanted);
        }
        QMetaObject::invokeMethod(this, [this, gen, ok, error] {
            if (gen == generation_) {
                onConnectResult(ok, qs(error));
            }
        }, Qt::QueuedConnection);
    });
}

void ChatController::signIn(const QString& host, int port, const QString& name) {
    if (state_ != SignedOut) {
        return;
    }
    if (!Intercli::isValidName(name)) {
        setErrors(QString(), QStringLiteral("Names are 1-31 characters with no spaces"));
        return;
    }
    if (host.trimmed().isEmpty() || port < 1 || port > 65535) {
        setErrors(QStringLiteral("Enter a server address and a port from 1 to 65535"), QString());
        return;
    }

    host_ = host.trimmed();
    port_ = port;
    my_name_ = name;
    emit serverChanged();
    emit myNameChanged();

    QSettings settings;
    settings.setValue("lastHost", host_);
    settings.setValue("lastPort", port_);
    settings.setValue("lastName", my_name_);

    setErrors(QString(), QString());
    needs_sign_in_ = false;
    register_retries_ = 0;
    setState(Connecting);
    startConnect(name);
}

void ChatController::onConnectResult(bool ok, const QString& error) {
    Q_UNUSED(error);
    finishWorker();
    if (ok) {
        return;  // the name answer arrives through onRegistered / onRegisterFailed
    }
    const QString reason = QStringLiteral("Couldn't reach %1:%2").arg(host_).arg(port_);
    dropClient();
    if (state_ == Connecting) {
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
    setState(Online);
    if (client_) {
        client_->request_roster();
    }
    emit sessionChanged();
}

void ChatController::onRegisterFailed(const QString& reason) {
    if (state_ == Connecting) {
        ++generation_;
        dropClient();
        setErrors(QString(), reason);
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
                    client_->request_name(ss(my_name_));
                }
            });
            return;
        }
        ++generation_;
        dropClient();
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

void ChatController::setSearch(const QString& text) {
    filter_->setFilterFixedString(text);
}

void ChatController::addRow(const QString& conversation, MessageModel::Kind kind, const QString& sender,
                            const QString& text) {
    ChatEntry e;
    e.id = next_local_id_--;
    e.kind = kind;
    e.sender = sender;
    e.text = text;
    e.time = QDateTime::currentDateTime();
    modelFor(conversation)->append(e);
}

void ChatController::onDirect(const QString& from, const QString& text) {
    addRow(from, MessageModel::Incoming, from, text);
    const bool unseen = from != current_ || !window_active_;
    list_->touch(from, text, QDateTime::currentDateTime(), unseen);
    emit messageArrived(from);
}

void ChatController::onBroadcast(const QString& from, const QString& text) {
    addRow(QString(), MessageModel::Incoming, from, text);
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
    addRow(QString(), MessageModel::System, QString(), raw);
    if (known) {
        addRow(name, MessageModel::System, QString(), raw);
    }
}

void ChatController::onNotice(const QString& text) {
    addRow(last_target_, MessageModel::System, QString(), text);
}

void ChatController::onSendKeyRotated() {
    addRow(current_, MessageModel::System, QString(), QStringLiteral("Your send key rotated"));
    emit sessionChanged();
}

void ChatController::onDisconnected(const QString& reason) {
    if (state_ == Online) {
        Q_UNUSED(reason);
        disconnect_reason_ = QStringLiteral("Disconnected from server");
        needs_sign_in_ = false;
        setState(Disconnected);
        emit stateChanged();
        emit onlineCountChanged();
    } else if (state_ == Connecting) {
        ++generation_;
        finishWorker();
        dropClient();
        setErrors(reason, QString());
        setState(SignedOut);
    } else if (state_ == Reconnecting) {
        ++generation_;
        finishWorker();
        dropClient();
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
    addRow(current_, MessageModel::Outgoing, my_name_, text);
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
    setState(Reconnecting);
    startConnect(my_name_);
}

void ChatController::signOut() {
    ++generation_;
    finishWorker();
    dropClient();
    list_->clear();
    for (MessageModel* m : models_) {
        m->clear();
    }
    current_ = QStringLiteral("");
    last_target_.clear();
    disconnect_reason_.clear();
    needs_sign_in_ = false;
    setErrors(QString(), QString());
    emit currentConversationChanged();
    emit onlineCountChanged();
    setState(SignedOut);
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
    m["serverIdentity"] = QStringLiteral("Not verified");
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
