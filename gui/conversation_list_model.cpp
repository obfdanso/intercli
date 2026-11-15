#include "conversation_list_model.h"

#include <algorithm>

namespace Intercli {

ConversationListModel::ConversationListModel(QObject* parent) : QAbstractListModel(parent) {
    rows_.append(Row{});
}

int ConversationListModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(rows_.size());
}

QVariant ConversationListModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= rows_.size()) {
        return {};
    }
    const Row& r = rows_.at(index.row());
    switch (role) {
        case ConversationIdRole: return r.id.isNull() ? QStringLiteral("") : r.id;
        case Qt::DisplayRole:
        case TitleRole: return r.id.isEmpty() ? QStringLiteral("Everyone") : r.id;
        case OnlineRole: return r.online;
        case PreviewRole: return r.preview;
        case LastActivityRole: return r.lastActivity;
        case UnreadRole: return r.unread;
        case SectionRole:
            return r.id.isEmpty() ? QStringLiteral("everyone")
                                  : (r.online ? QStringLiteral("online") : QStringLiteral("offline"));
        default: return {};
    }
}

QHash<int, QByteArray> ConversationListModel::roleNames() const {
    return {
        {ConversationIdRole, "conversationId"},
        {TitleRole, "title"},
        {OnlineRole, "online"},
        {PreviewRole, "preview"},
        {LastActivityRole, "lastActivity"},
        {UnreadRole, "unread"},
        {SectionRole, "section"},
    };
}

// Everyone first; then online before offline; then most recent activity; then name.
bool ConversationListModel::sortsBefore(const Row& a, const Row& b) {
    if (a.id.isEmpty() != b.id.isEmpty()) {
        return a.id.isEmpty();
    }
    if (a.online != b.online) {
        return a.online;
    }
    if (a.lastActivity != b.lastActivity) {
        if (!a.lastActivity.isValid()) return false;
        if (!b.lastActivity.isValid()) return true;
        return a.lastActivity > b.lastActivity;
    }
    return a.id.compare(b.id, Qt::CaseInsensitive) < 0;
}

void ConversationListModel::rowChanged(int row) {
    const QModelIndex i = index(row);
    emit dataChanged(i, i);
}

// Moves one row whose sort key changed to where it now belongs.
void ConversationListModel::reposition(int row) {
    const Row moving = rows_.at(row);
    QVector<Row> others = rows_;
    others.removeAt(row);
    const auto it = std::lower_bound(others.begin(), others.end(), moving, sortsBefore);
    const int target = static_cast<int>(it - others.begin());
    if (target == row) {
        return;
    }
    // beginMoveRows takes the destination as a position in the list before the move.
    beginMoveRows(QModelIndex(), row, row, QModelIndex(), target > row ? target + 1 : target);
    rows_.removeAt(row);
    rows_.insert(target, moving);
    endMoveRows();
}

void ConversationListModel::ensure(const QString& id) {
    if (indexOf(id) >= 0) {
        return;
    }
    Row r;
    r.id = id;
    const auto it = std::lower_bound(rows_.begin(), rows_.end(), r, sortsBefore);
    const int at = static_cast<int>(it - rows_.begin());
    beginInsertRows(QModelIndex(), at, at);
    rows_.insert(at, r);
    endInsertRows();
}

void ConversationListModel::setRoster(const QStringList& online, const QString& me) {
    const int before_count = onlineCount();
    beginResetModel();
    for (Row& r : rows_) {
        r.online = false;
    }
    for (const QString& name : online) {
        if (name == me || name.isEmpty()) {
            continue;
        }
        const int i = indexOf(name);
        if (i >= 0) {
            rows_[i].online = true;
        } else {
            Row r;
            r.id = name;
            r.online = true;
            rows_.append(r);
        }
    }
    std::stable_sort(rows_.begin(), rows_.end(), sortsBefore);
    endResetModel();
    if (onlineCount() != before_count) {
        emit onlineCountChanged();
    }
}

void ConversationListModel::setOnline(const QString& name, bool online) {
    if (name.isEmpty()) {
        return;
    }
    ensure(name);
    const int i = indexOf(name);
    if (rows_[i].online == online) {
        return;
    }
    rows_[i].online = online;
    rowChanged(i);
    reposition(i);
    emit onlineCountChanged();
}

void ConversationListModel::touch(const QString& id, const QString& preview, const QDateTime& when,
                                  bool countUnread) {
    ensure(id);
    const int i = indexOf(id);
    Row& r = rows_[i];
    r.preview = preview;
    r.lastActivity = when;
    if (countUnread) {
        ++r.unread;
    }
    rowChanged(i);
    reposition(i);
}

void ConversationListModel::markRead(const QString& id) {
    const int i = indexOf(id);
    if (i < 0 || rows_[i].unread == 0) {
        return;
    }
    rows_[i].unread = 0;
    rowChanged(i);
}

void ConversationListModel::clear() {
    const bool had_online = onlineCount() > 0;
    beginResetModel();
    rows_.clear();
    rows_.append(Row{});
    endResetModel();
    if (had_online) {
        emit onlineCountChanged();
    }
}

int ConversationListModel::onlineCount() const {
    return static_cast<int>(std::count_if(rows_.begin(), rows_.end(), [](const Row& r) { return r.online; }));
}

int ConversationListModel::indexOf(const QString& id) const {
    for (int i = 0; i < rows_.size(); ++i) {
        // Null and empty both mean Everyone.
        if (rows_[i].id == id || (rows_[i].id.isEmpty() && id.isEmpty())) {
            return i;
        }
    }
    return -1;
}

int ConversationListModel::unreadTotal() const {
    int total = 0;
    for (const Row& r : rows_) {
        total += r.unread;
    }
    return total;
}

QStringList ConversationListModel::onlineNames() const {
    QStringList names;
    for (const Row& r : rows_) {
        if (r.online) {
            names.append(r.id);
        }
    }
    return names;
}

} // namespace Intercli
