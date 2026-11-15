#pragma once

#include "chat_client.h"
#include "conversation_list_model.h"
#include "message_model.h"

#include <QAbstractItemModel>
#include <QHash>
#include <QObject>
#include <QSortFilterProxyModel>
#include <QString>
#include <QStringList>
#include <QVariantMap>

#include <memory>
#include <thread>

namespace Intercli {

// Joins the client library to the QML views. Owns the connection, the sidebar
// list and one message list per conversation. All public methods run on the UI
// thread; the client's callbacks are hopped onto it before touching anything.
class ChatController : public QObject {
    Q_OBJECT
    Q_PROPERTY(State state READ state NOTIFY stateChanged)
    Q_PROPERTY(QString myName READ myName NOTIFY myNameChanged)
    Q_PROPERTY(QString serverHost READ serverHost NOTIFY serverChanged)
    Q_PROPERTY(int serverPort READ serverPort NOTIFY serverChanged)
    Q_PROPERTY(QString connectError READ connectError NOTIFY errorsChanged)
    Q_PROPERTY(QString nameError READ nameError NOTIFY errorsChanged)
    Q_PROPERTY(QString disconnectReason READ disconnectReason NOTIFY stateChanged)
    Q_PROPERTY(bool needsSignIn READ needsSignIn NOTIFY stateChanged)
    Q_PROPERTY(QAbstractItemModel* conversations READ conversations CONSTANT)
    Q_PROPERTY(QString currentConversation READ currentConversation WRITE setCurrentConversation
                   NOTIFY currentConversationChanged)
    Q_PROPERTY(Intercli::MessageModel* messages READ messages NOTIFY currentConversationChanged)
    Q_PROPERTY(int onlineCount READ onlineCount NOTIFY onlineCountChanged)
    Q_PROPERTY(QStringList onlineNames READ onlineNames NOTIFY onlineCountChanged)
    Q_PROPERTY(QVariantMap session READ session NOTIFY sessionChanged)
    Q_PROPERTY(bool windowActive READ windowActive WRITE setWindowActive NOTIFY windowActiveChanged)

public:
    enum State { SignedOut, Connecting, Online, Disconnected, Reconnecting };
    Q_ENUM(State)

    explicit ChatController(QObject* parent = nullptr);
    ~ChatController() override;

    State state() const { return state_; }
    QString myName() const { return my_name_; }
    QString serverHost() const { return host_; }
    int serverPort() const { return port_; }
    QString connectError() const { return connect_error_; }
    QString nameError() const { return name_error_; }
    QString disconnectReason() const { return disconnect_reason_; }
    bool needsSignIn() const { return needs_sign_in_; }
    QAbstractItemModel* conversations() const { return filter_; }
    QString currentConversation() const { return current_; }
    void setCurrentConversation(const QString& id);
    MessageModel* messages();
    int onlineCount() const { return list_->onlineCount(); }
    QStringList onlineNames() const { return list_->onlineNames(); }
    QVariantMap session() const;
    bool windowActive() const { return window_active_; }
    void setWindowActive(bool active);

    Q_INVOKABLE void signIn(const QString& host, int port, const QString& name);
    // Sends to the current conversation. False when blank, too long or offline.
    Q_INVOKABLE bool send(const QString& text);
    Q_INVOKABLE void rotateKey();
    Q_INVOKABLE void reconnect();
    Q_INVOKABLE void signOut();
    Q_INVOKABLE void setSearch(const QString& text);
    // Called when the user edits a sign-in field, so a stale error goes away.
    Q_INVOKABLE void clearErrors();

    Q_INVOKABLE static bool isValidName(const QString& name);
    Q_INVOKABLE static int utf8Length(const QString& text);
    // [top, bottom] gradient colours for a person's avatar.
    Q_INVOKABLE static QVariantList avatarColors(const QString& name);
    Q_INVOKABLE static QString initialFor(const QString& name);

    // Test only: drops the connection as if the network failed.
    void simulateConnectionLoss();

signals:
    void stateChanged();
    void myNameChanged();
    void serverChanged();
    void errorsChanged();
    void currentConversationChanged();
    void onlineCountChanged();
    void sessionChanged();
    void windowActiveChanged();
    // An incoming message arrived (used to flash the taskbar button).
    void messageArrived(const QString& conversationId);

private:
    std::shared_ptr<SecureComm::ChatClient> makeClient();
    void startConnect(const QString& name);
    void finishWorker();
    void setState(State s);
    void setErrors(const QString& connectError, const QString& nameError);
    MessageModel* modelFor(const QString& id);
    void addRow(const QString& conversation, MessageModel::Kind kind, const QString& sender,
                const QString& text);
    void dropClient();

    // Handlers, always on the UI thread and only for the current connection.
    void onConnectResult(bool ok, const QString& error);
    void onRegistered(const QString& name);
    void onRegisterFailed(const QString& reason);
    void onDirect(const QString& from, const QString& text);
    void onBroadcast(const QString& from, const QString& text);
    void onRoster(const QStringList& names);
    void onPresence(const QString& name, bool joined, const QString& raw);
    void onNotice(const QString& text);
    void onSendKeyRotated();
    void onDisconnected(const QString& reason);

    State state_ = SignedOut;
    QString host_;
    int port_ = 8080;
    QString my_name_;
    QString connect_error_;
    QString name_error_;
    QString disconnect_reason_;
    bool needs_sign_in_ = false;
    int register_retries_ = 0;

    ConversationListModel* list_;
    QSortFilterProxyModel* filter_;
    QHash<QString, MessageModel*> models_;
    QString current_;
    QString last_target_;
    bool window_active_ = true;
    qint64 next_local_id_ = -1;

    // Bumped whenever a connection is abandoned, so late callbacks from it are ignored.
    quint64 generation_ = 0;
    std::shared_ptr<SecureComm::ChatClient> client_;
    std::thread worker_;
};

} // namespace Intercli
