#pragma once

#include <QAbstractListModel>
#include <QDateTime>
#include <QStringList>
#include <QVector>

namespace Intercli {

// The sidebar: "Everyone" pinned first, then people online, then people offline,
// each group ordered by latest activity. The Everyone conversation's id is "".
class ConversationListModel : public QAbstractListModel {
    Q_OBJECT
    Q_PROPERTY(int onlineCount READ onlineCount NOTIFY onlineCountChanged)

public:
    enum Role {
        ConversationIdRole = Qt::UserRole + 1,
        TitleRole,
        OnlineRole,
        PreviewRole,
        LastActivityRole,
        UnreadRole,
        SectionRole,
    };

    explicit ConversationListModel(QObject* parent = nullptr);

    int rowCount(const QModelIndex& parent = QModelIndex()) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QHash<int, QByteArray> roleNames() const override;

    void ensure(const QString& id);
    void setRoster(const QStringList& online, const QString& me);
    void setOnline(const QString& name, bool online);
    void touch(const QString& id, const QString& preview, const QDateTime& when, bool countUnread);
    void markRead(const QString& id);
    // Takes a row out of the list (leaving a room). Everyone can't be removed.
    void remove(const QString& id);
    // The ids of the room rows ("#name").
    QStringList roomIds() const;
    void clear();

    int onlineCount() const;
    int indexOf(const QString& id) const;
    int unreadTotal() const;
    QStringList onlineNames() const;

signals:
    void onlineCountChanged();

private:
    struct Row {
        QString id;
        bool online = false;
        QString preview;
        QDateTime lastActivity;
        int unread = 0;
    };

    static bool sortsBefore(const Row& a, const Row& b);
    void reposition(int row);
    void rowChanged(int row);

    QVector<Row> rows_;
};

} // namespace Intercli
