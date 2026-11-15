#pragma once

// Finding chats on the local network without typing addresses.
//
// A joiner's app asks "who is hosting?" (a small UDP broadcast, every couple of
// seconds, from a throwaway port) and a hosting app answers it directly. The
// joiner never listens on a fixed port, so only the host needs to be let
// through the firewall.

#include <QAbstractListModel>
#include <QDateTime>
#include <QHostAddress>
#include <QObject>
#include <QTimer>
#include <QVector>

#include <optional>

class QUdpSocket;

namespace Intercli {

constexpr quint16 kDiscoveryPort = 8081;

struct ChatAnnouncement {
    QString chatId;
    QString chatName;
    QString hostName;
    QString safetyCode;
    quint16 port = 0;
    int people = 0;
    QHostAddress address;  // where the reply came from (finder side only)
};

// Host side: answers queries with what this chat is called and where it is.
class ChatBeacon : public QObject {
    Q_OBJECT
public:
    explicit ChatBeacon(QObject* parent = nullptr);
    ~ChatBeacon() override;

    bool start(quint16 discoveryPort = kDiscoveryPort);
    void stop();
    bool running() const;
    void setAnnouncement(const ChatAnnouncement& announcement);

private:
    void answer();

    QUdpSocket* socket_ = nullptr;
    ChatAnnouncement announcement_;
};

// Joiner side: the "Chats nearby" list.
class ChatFinder : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(int count READ count NOTIFY countChanged)

public:
    enum Role {
        ChatIdRole = Qt::UserRole + 1,
        ChatNameRole,
        HostNameRole,
        PeopleRole,
        SafetyCodeRole,
        AddressRole,
        PortRole,
    };

    explicit ChatFinder(QObject* parent = nullptr);
    ~ChatFinder() override;

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;
    int count() const { return static_cast<int>(rows_.size()); }

    void start(quint16 discoveryPort = kDiscoveryPort);
    void stop();
    bool running() const;
    std::optional<ChatAnnouncement> find(const QString& chatId) const;

    void setTimingForTests(int queryMs, int expiryMs);
    // Feeds a reply as if it had arrived from `from`.
    void injectReplyForTests(const QByteArray& datagram, const QHostAddress& from);

signals:
    void countChanged();

private:
    struct Row {
        ChatAnnouncement chat;
        QDateTime lastSeen;
    };

    void query();
    void receive();
    void handleReply(const QByteArray& datagram, const QHostAddress& from);
    void expire();

    QUdpSocket* socket_ = nullptr;
    QTimer query_timer_;
    QTimer expiry_timer_;
    quint16 port_ = kDiscoveryPort;
    int expiry_ms_ = 6000;
    QVector<Row> rows_;
};

} // namespace Intercli
