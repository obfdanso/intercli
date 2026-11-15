#include "discovery.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkInterface>
#include <QSet>
#include <QUdpSocket>

namespace Intercli {

namespace {

const QByteArray kQuery = QByteArrayLiteral("INTERCLI?2");
const QByteArray kReply = QByteArrayLiteral("INTERCLI!2");
constexpr int kMaxDatagram = 1024;
constexpr int kQuerySize = 256;          // queries are at least this big
constexpr int kMaxRows = 64;             // the whole "Chats nearby" list
constexpr int kMaxRowsPerAddress = 4;    // chats one address can list
constexpr qint64 kReplyIntervalMs = 500; // at most one answer per sender per interval

// Everything in a reply comes from whoever sent it, so it is checked before use.
std::optional<ChatAnnouncement> parseReply(const QByteArray& datagram) {
    if (datagram.size() > kMaxDatagram || !datagram.startsWith(kReply)) {
        return std::nullopt;
    }
    QJsonParseError error{};
    const QJsonDocument doc = QJsonDocument::fromJson(datagram.mid(kReply.size()), &error);
    if (error.error != QJsonParseError::NoError || !doc.isObject()) {
        return std::nullopt;
    }
    const QJsonObject o = doc.object();
    ChatAnnouncement a;
    a.chatId = o.value("id").toString();
    a.chatName = o.value("name").toString();
    a.hostName = o.value("host").toString();
    a.safetyCode = o.value("code").toString();
    const int port = o.value("port").toInt(0);
    a.people = o.value("people").toInt(-1);
    if (a.chatId.isEmpty() || a.chatId.size() > 64 || a.chatName.isEmpty() || a.chatName.size() > 64 ||
        a.hostName.size() > 31 || a.safetyCode.size() > 32 || port < 1 || port > 65535 || a.people < 0 ||
        a.people > 100000) {
        return std::nullopt;
    }
    a.port = static_cast<quint16>(port);
    return a;
}

} // namespace

// --- ChatBeacon --------------------------------------------------------------

ChatBeacon::ChatBeacon(QObject* parent) : QObject(parent) {}

ChatBeacon::~ChatBeacon() {
    stop();
}

bool ChatBeacon::start(quint16 discoveryPort) {
    stop();
    socket_ = new QUdpSocket(this);
    if (!socket_->bind(QHostAddress::AnyIPv4, discoveryPort,
                       QUdpSocket::ShareAddress | QUdpSocket::ReuseAddressHint)) {
        delete socket_;
        socket_ = nullptr;
        return false;
    }
    connect(socket_, &QUdpSocket::readyRead, this, &ChatBeacon::answer);
    return true;
}

void ChatBeacon::stop() {
    if (socket_) {
        socket_->close();
        socket_->deleteLater();
        socket_ = nullptr;
    }
}

bool ChatBeacon::running() const {
    return socket_ != nullptr;
}

void ChatBeacon::setAnnouncement(const ChatAnnouncement& announcement) {
    announcement_ = announcement;
}

void ChatBeacon::answer() {
    while (socket_ && socket_->hasPendingDatagrams()) {
        const qint64 size = socket_->pendingDatagramSize();
        QByteArray datagram(static_cast<int>(qBound<qint64>(0, size, qint64(kMaxDatagram))), 0);
        QHostAddress from;
        quint16 fromPort = 0;
        socket_->readDatagram(datagram.data(), datagram.size(), &from, &fromPort);
        if (datagram.size() < kQuerySize || !datagram.startsWith(kQuery) || announcement_.chatId.isEmpty() ||
            !onLocalNetwork(from)) {
            continue;
        }
        // One answer per sender per half second, however fast it asks.
        const QString sender = from.toString() + QLatin1Char(':') + QString::number(fromPort);
        const qint64 now = QDateTime::currentMSecsSinceEpoch();
        if (now - last_reply_ms_.value(sender, 0) < kReplyIntervalMs) {
            continue;
        }
        if (last_reply_ms_.size() > 1024) {
            last_reply_ms_.clear();
        }
        last_reply_ms_.insert(sender, now);
        QJsonObject o;
        o["id"] = announcement_.chatId;
        o["name"] = announcement_.chatName;
        o["host"] = announcement_.hostName;
        o["code"] = announcement_.safetyCode;
        o["port"] = announcement_.port;
        o["people"] = announcement_.people;
        socket_->writeDatagram(kReply + QJsonDocument(o).toJson(QJsonDocument::Compact), from, fromPort);
    }
}

// Only machines on a network this PC is directly on (or this PC itself) get
// an answer; anything routed from further away is ignored.
bool ChatBeacon::onLocalNetwork(const QHostAddress& from) const {
    bool ok = false;
    const QHostAddress v4(from.toIPv4Address(&ok));
    const QHostAddress sender = ok ? v4 : from;
    if (sender.isLoopback()) {
        return true;
    }
    for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
        for (const QNetworkAddressEntry& entry : iface.addressEntries()) {
            if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol &&
                sender.isInSubnet(entry.ip(), entry.prefixLength())) {
                return true;
            }
        }
    }
    return false;
}

// --- ChatFinder --------------------------------------------------------------

QByteArray ChatFinder::queryDatagram() {
    QByteArray q = kQuery;
    q.append(QByteArray(kQuerySize - q.size(), '\0'));
    return q;
}

ChatFinder::ChatFinder(QObject* parent) : QAbstractListModel(parent) {
    query_timer_.setInterval(2000);
    expiry_timer_.setInterval(1000);
    connect(&query_timer_, &QTimer::timeout, this, &ChatFinder::query);
    connect(&expiry_timer_, &QTimer::timeout, this, &ChatFinder::expire);
}

ChatFinder::~ChatFinder() {
    stop();
}

void ChatFinder::setTimingForTests(int queryMs, int expiryMs) {
    query_timer_.setInterval(queryMs);
    expiry_ms_ = expiryMs;
    expiry_timer_.setInterval(qMax(100, expiryMs / 4));
}

void ChatFinder::start(quint16 discoveryPort) {
    stop();
    port_ = discoveryPort;
    socket_ = new QUdpSocket(this);
    // A throwaway port: replies come back to it, nothing listens on a fixed port.
    socket_->bind(QHostAddress::AnyIPv4, 0);
    connect(socket_, &QUdpSocket::readyRead, this, &ChatFinder::receive);
    query_timer_.start();
    expiry_timer_.start();
    query();
}

void ChatFinder::stop() {
    query_timer_.stop();
    expiry_timer_.stop();
    if (socket_) {
        socket_->close();
        socket_->deleteLater();
        socket_ = nullptr;
    }
}

bool ChatFinder::running() const {
    return socket_ != nullptr;
}

// Asks every network this PC is on, plus this PC itself.
void ChatFinder::query() {
    if (!socket_) {
        return;
    }
    QSet<QHostAddress> targets{QHostAddress::Broadcast, QHostAddress::LocalHost};
    for (const QNetworkInterface& iface : QNetworkInterface::allInterfaces()) {
        const auto flags = iface.flags();
        if (!(flags & QNetworkInterface::IsUp) || !(flags & QNetworkInterface::IsRunning)) {
            continue;
        }
        for (const QNetworkAddressEntry& entry : iface.addressEntries()) {
            if (entry.ip().protocol() == QAbstractSocket::IPv4Protocol && !entry.broadcast().isNull()) {
                targets.insert(entry.broadcast());
            }
        }
    }
    const QByteArray q = queryDatagram();
    for (const QHostAddress& target : targets) {
        socket_->writeDatagram(q, target, port_);
    }
}

void ChatFinder::receive() {
    while (socket_ && socket_->hasPendingDatagrams()) {
        const qint64 size = socket_->pendingDatagramSize();
        if (size > kMaxDatagram) {
            QByteArray skip(1, 0);
            socket_->readDatagram(skip.data(), skip.size());
            continue;
        }
        QByteArray datagram(static_cast<int>(qMax<qint64>(0, size)), 0);
        QHostAddress from;
        socket_->readDatagram(datagram.data(), datagram.size(), &from);
        handleReply(datagram, from);
    }
}

void ChatFinder::injectReplyForTests(const QByteArray& datagram, const QHostAddress& from) {
    handleReply(datagram, from);
}

void ChatFinder::handleReply(const QByteArray& datagram, const QHostAddress& from) {
    std::optional<ChatAnnouncement> a = parseReply(datagram);
    if (!a) {
        return;
    }
    // IPv4-mapped addresses (::ffff:a.b.c.d) are shown and dialled as a.b.c.d.
    bool ok = false;
    const quint32 v4 = from.toIPv4Address(&ok);
    a->address = ok ? QHostAddress(v4) : from;

    int fromSameAddress = 0;
    for (int r = 0; r < rows_.size(); ++r) {
        if (rows_[r].chat.chatId == a->chatId) {
            // A listed chat keeps the address it was first heard from, so a
            // reply from somewhere else can't redirect it. (Joining still
            // checks the host's identity key.) The same chat heard through
            // another of this PC's networks stays one row.
            if (rows_[r].chat.address != a->address) {
                return;
            }
            rows_[r].chat = *a;
            rows_[r].lastSeen = QDateTime::currentDateTimeUtc();
            emit dataChanged(index(r), index(r));
            return;
        }
        if (rows_[r].chat.address == a->address) {
            ++fromSameAddress;
        }
    }
    if (rows_.size() >= kMaxRows || fromSameAddress >= kMaxRowsPerAddress) {
        return;
    }
    const int row = static_cast<int>(rows_.size());
    beginInsertRows(QModelIndex(), row, row);
    rows_.append(Row{*a, QDateTime::currentDateTimeUtc()});
    endInsertRows();
    emit countChanged();
}

void ChatFinder::expire() {
    const QDateTime cutoff = QDateTime::currentDateTimeUtc().addMSecs(-expiry_ms_);
    for (int r = static_cast<int>(rows_.size()) - 1; r >= 0; --r) {
        if (rows_[r].lastSeen < cutoff) {
            beginRemoveRows(QModelIndex(), r, r);
            rows_.removeAt(r);
            endRemoveRows();
            emit countChanged();
        }
    }
}

std::optional<ChatAnnouncement> ChatFinder::find(const QString& chatId) const {
    for (const Row& r : rows_) {
        if (r.chat.chatId == chatId) {
            return r.chat;
        }
    }
    return std::nullopt;
}

int ChatFinder::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(rows_.size());
}

QVariant ChatFinder::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= rows_.size()) {
        return {};
    }
    const ChatAnnouncement& a = rows_.at(index.row()).chat;
    switch (role) {
        case ChatIdRole: return a.chatId;
        case Qt::DisplayRole:
        case ChatNameRole: return a.chatName;
        case HostNameRole: return a.hostName;
        case PeopleRole: return a.people;
        case SafetyCodeRole: return a.safetyCode;
        case AddressRole: return a.address.toString();
        case PortRole: return a.port;
        default: return {};
    }
}

QHash<int, QByteArray> ChatFinder::roleNames() const {
    return {
        {ChatIdRole, "chatId"},
        {ChatNameRole, "chatName"},
        {HostNameRole, "hostName"},
        {PeopleRole, "people"},
        {SafetyCodeRole, "safetyCode"},
        {AddressRole, "address"},
        {PortRole, "port"},
    };
}

} // namespace Intercli
