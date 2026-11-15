#pragma once

#include "chat_client.h"
#include "conversation_list_model.h"
#include "discovery.h"
#include "history_store.h"
#include "message_model.h"

#include <QAbstractItemModel>
#include <QHash>
#include <QObject>
#include <QSortFilterProxyModel>
#include <QString>
#include <QStringList>
#include <QVariantMap>

#include <atomic>
#include <memory>
#include <vector>
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
    Q_PROPERTY(bool historyAvailable READ historyAvailable CONSTANT)
    Q_PROPERTY(int historyChoice READ historyChoice NOTIFY historyChoiceChanged)
    // Same-room chats.
    Q_PROPERTY(Intercli::ChatFinder* nearby READ nearby CONSTANT)
    Q_PROPERTY(bool hostingAvailable READ hostingAvailable CONSTANT)
    Q_PROPERTY(bool hosting READ hosting NOTIFY hostingChanged)
    Q_PROPERTY(QString roomCode READ roomCode NOTIFY hostingChanged)
    Q_PROPERTY(int peopleInChat READ peopleInChat NOTIFY peopleInChatChanged)
    Q_PROPERTY(QString safetyCode READ safetyCode NOTIFY sessionChanged)
    Q_PROPERTY(QString codeError READ codeError NOTIFY errorsChanged)
    Q_PROPERTY(QString hostError READ hostError NOTIFY errorsChanged)
    Q_PROPERTY(bool publicNetwork READ publicNetwork NOTIFY publicNetworkChanged)
    Q_PROPERTY(bool firewallNoteNeeded READ firewallNoteNeeded NOTIFY hostingChanged)
    // After "This chat's identity has changed": the safety code it has now.
    Q_PROPERTY(bool identityChanged READ identityChanged NOTIFY errorsChanged)
    // Where others can reach this PC's chat ("192.168.1.20:8080"), for Join by address.
    Q_PROPERTY(QString hostAddress READ hostAddress NOTIFY hostingChanged)
    Q_PROPERTY(QString newSafetyCode READ newSafetyCode NOTIFY errorsChanged)

public:
    enum State { SignedOut, Connecting, Online, Disconnected, Reconnecting };
    Q_ENUM(State)

    // history may be null (saving is then unavailable); it must outlive the controller.
    // host may be null (hosting is then unavailable); like history, it must
    // outlive the controller. discoveryPort is where chats nearby answer.
    explicit ChatController(HistoryStore* history = nullptr, class HostSession* host = nullptr,
                            quint16 discoveryPort = kDiscoveryPort, QObject* parent = nullptr);
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
    bool historyAvailable() const { return history_ != nullptr; }
    int historyChoice() const;
    void setWindowActive(bool active);

    ChatFinder* nearby() const { return finder_; }
    bool hostingAvailable() const { return host_session_ != nullptr; }
    bool hosting() const { return hosting_; }
    QString roomCode() const;
    int peopleInChat() const;
    QString safetyCode() const;
    QString codeError() const { return code_error_; }
    QString hostError() const { return host_error_; }
    bool publicNetwork() const { return public_network_; }
    bool firewallNoteNeeded() const;
    bool identityChanged() const { return identity_changed_; }
    QString hostAddress() const;
    QString newSafetyCode() const;
    QString historyIdentityForTests() const { return identity_; }

    // By address; room_code only for a chat that has one.
    Q_INVOKABLE void signIn(const QString& host, int port, const QString& name, const QString& roomCode = QString());
    // Joins a chat from the "Chats nearby" list.
    Q_INVOKABLE void joinChat(const QString& chatId, const QString& roomCode, const QString& name);
    // Starts a chat on this PC and joins it.
    Q_INVOKABLE void hostChat(const QString& name);
    // The host ends the chat for everyone and signs out.
    Q_INVOKABLE void endChat();
    // True when signing out or closing would disconnect other people.
    Q_INVOKABLE bool needsEndChatConfirm() const;
    // The code that worked last time for this chat, formatted, or empty.
    Q_INVOKABLE QString rememberedCode(const QString& chatId) const;
    Q_INVOKABLE void copyRoomCode() const;
    Q_INVOKABLE void refreshNetworkCheck();
    // After comparing the new safety code with the host: remember the new
    // identity for this chat and join again.
    Q_INVOKABLE void trustNewIdentity();
    // Sends to the current conversation. False when blank, too long or offline.
    Q_INVOKABLE bool send(const QString& text);
    Q_INVOKABLE void rotateKey();
    Q_INVOKABLE void reconnect();
    Q_INVOKABLE void signOut();
    Q_INVOKABLE void setSearch(const QString& text);
    // Called when the user edits a sign-in field, so a stale error goes away.
    Q_INVOKABLE void clearErrors();
    // HistoryChoice values. Turning saving off with deleteExisting removes what
    // is already saved for this name on this server.
    Q_INVOKABLE void setHistoryChoice(int choice, bool deleteExisting);
    // Adds the next page of saved messages above the current conversation.
    Q_INVOKABLE void loadOlder();

    Q_INVOKABLE static bool isValidName(const QString& name);
    Q_INVOKABLE static int utf8Length(const QString& text);
    // [top, bottom] gradient colours for a person's avatar.
    Q_INVOKABLE static QVariantList avatarColors(const QString& name);
    Q_INVOKABLE static QString initialFor(const QString& name);

    // Test only: drops the connection as if the network failed.
    void simulateConnectionLoss();
    // Test only: reports a receive error without closing the socket.
    void simulateReceiveError();

signals:
    void stateChanged();
    void myNameChanged();
    void serverChanged();
    void errorsChanged();
    void currentConversationChanged();
    void onlineCountChanged();
    void sessionChanged();
    void windowActiveChanged();
    void historyChoiceChanged();
    void hostingChanged();
    void peopleInChatChanged();
    void publicNetworkChanged();
    // An incoming message arrived (used to flash the taskbar button).
    void messageArrived(const QString& conversationId);

private:
    std::shared_ptr<SecureComm::ChatClient> makeClient();
    void startConnect(const QString& name);
    bool beginSignIn(const QString& name);
    QString pinKey() const;
    void onHostStarted(quint16 port);
    void onHostFailed(const QString& reason);
    void finishWorker();
    void abandonConnection();
    void reapRetired();
    void setState(State s);
    void setErrors(const QString& connectError, const QString& nameError, const QString& codeError = QString(),
                   const QString& hostError = QString());
    MessageModel* modelFor(const QString& id);
    void addRow(const QString& conversation, MessageModel::Kind kind, const QString& sender,
                const QString& text, bool persist);
    void loadSavedHistory();
    bool saving() const;

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

    HistoryStore* history_ = nullptr;

    class HostSession* host_session_ = nullptr;
    ChatFinder* finder_ = nullptr;
    bool hosting_ = false;
    quint16 discovery_port_ = kDiscoveryPort;
    bool public_network_ = false;
    QString chat_id_;      // set for chats joined from the list or hosted here
    QString room_code_;    // normalised code used for this chat
    QString code_error_;
    QString host_error_;
    QByteArray server_identity_;
    bool identity_was_known_ = false;
    QByteArray announced_identity_;  // from the list; expected on a first join
    bool identity_changed_ = false;
    QByteArray new_identity_;
    QString identity_;
    bool history_loaded_ = false;

    // Bumped whenever a connection is abandoned, so late callbacks from it are ignored.
    quint64 generation_ = 0;
    std::shared_ptr<SecureComm::ChatClient> client_;
    std::thread worker_;
    // Set by the worker just before it reports back, so we know joining is instant.
    std::shared_ptr<std::atomic<bool>> worker_done_;
    // Workers whose connect was cancelled but may still be finishing (RSA key
    // generation can't be interrupted). Joined once done, or at destruction.
    struct Retired {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::vector<Retired> retired_;
};

} // namespace Intercli
