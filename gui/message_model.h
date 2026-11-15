#pragma once

#include <QAbstractListModel>
#include <QDateTime>
#include <QList>
#include <QString>

namespace Intercli {

struct ChatEntry;

// One conversation's messages, with the grouping flags the bubbles need:
// a run is consecutive non-system rows of the same kind and sender, each at most
// five minutes after the previous one.
class MessageModel : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(int count READ count NOTIFY countChanged)

public:
    enum Kind { Incoming = 0, Outgoing = 1, System = 2 };
    Q_ENUM(Kind)

    enum Role {
        MessageIdRole = Qt::UserRole + 1,
        KindRole,
        SenderRole,
        TextRole,
        TimeRole,
        FirstInRunRole,
        LastInRunRole,
        ShowSenderRole,
        ShowTimestampRole,
    };

    explicit MessageModel(bool isEveryone, QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    void append(const ChatEntry& entry);
    // Older messages, oldest first, placed above everything already here.
    void prepend(const QList<ChatEntry>& olderOldestFirst);
    void clear();

    int count() const;
    qint64 oldestId() const;
    bool isEveryone() const { return is_everyone_; }
    const ChatEntry& entryAt(int row) const;

signals:
    void countChanged();

private:
    bool continuesRun(int row) const;   // row joins the run of row - 1
    bool showsTimestamp(int row) const;

    bool is_everyone_;
    QList<ChatEntry> rows_;
};

struct ChatEntry {
    qint64 id = 0;
    MessageModel::Kind kind = MessageModel::Incoming;
    QString sender;
    QString text;
    QDateTime time;
};

} // namespace Intercli
