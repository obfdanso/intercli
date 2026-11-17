#include "message_model.h"

#include <QUrl>

namespace Intercli {

namespace {
constexpr qint64 kRunGapSecs = 5 * 60;
constexpr qint64 kTimestampGapSecs = 15 * 60;
}

MessageModel::MessageModel(bool isEveryone, QObject* parent)
    : QAbstractListModel(parent), is_everyone_(isEveryone) {}

int MessageModel::rowCount(const QModelIndex& parent) const {
    return parent.isValid() ? 0 : static_cast<int>(rows_.size());
}

bool MessageModel::continuesRun(int row) const {
    if (row <= 0 || row >= rows_.size()) {
        return false;
    }
    const ChatEntry& prev = rows_.at(row - 1);
    const ChatEntry& cur = rows_.at(row);
    return cur.kind != System && prev.kind == cur.kind && prev.sender == cur.sender &&
           prev.time.secsTo(cur.time) <= kRunGapSecs;
}

bool MessageModel::showsTimestamp(int row) const {
    return row == 0 || rows_.at(row - 1).time.secsTo(rows_.at(row).time) > kTimestampGapSecs;
}

QVariant MessageModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid() || index.row() >= rows_.size()) {
        return {};
    }
    const int row = index.row();
    const ChatEntry& e = rows_.at(row);
    switch (role) {
        case MessageIdRole: return e.id;
        case KindRole: return static_cast<int>(e.kind);
        case SenderRole: return e.sender;
        case Qt::DisplayRole:
        case TextRole: return e.text;
        case TimeRole: return e.time;
        case FirstInRunRole: return !continuesRun(row);
        case LastInRunRole: return !continuesRun(row + 1);
        case ShowSenderRole: return is_everyone_ && e.kind == Incoming && !continuesRun(row);
        case ShowTimestampRole: return showsTimestamp(row);
        case FileRole: return e.file.isEmpty() ? QString() : QUrl::fromLocalFile(e.file).toString();
        default: return {};
    }
}

QHash<int, QByteArray> MessageModel::roleNames() const {
    return {
        {MessageIdRole, "messageId"},
        {KindRole, "kind"},
        {SenderRole, "sender"},
        {TextRole, "text"},
        {TimeRole, "time"},
        {FirstInRunRole, "firstInRun"},
        {LastInRunRole, "lastInRun"},
        {ShowSenderRole, "showSender"},
        {ShowTimestampRole, "showTimestamp"},
        {FileRole, "file"},
    };
}

void MessageModel::append(const ChatEntry& entry) {
    const int row = static_cast<int>(rows_.size());
    beginInsertRows(QModelIndex(), row, row);
    rows_.append(entry);
    endInsertRows();
    if (row > 0 && continuesRun(row)) {
        // The previous row is no longer the last of its run.
        const QModelIndex prev = index(row - 1);
        emit dataChanged(prev, prev, {LastInRunRole});
    }
    emit countChanged();
}

void MessageModel::prepend(const QList<ChatEntry>& olderOldestFirst) {
    if (olderOldestFirst.isEmpty()) {
        return;
    }
    const int n = static_cast<int>(olderOldestFirst.size());
    beginInsertRows(QModelIndex(), 0, n - 1);
    rows_ = olderOldestFirst + rows_;
    endInsertRows();
    if (rows_.size() > n) {
        // The old first row may now continue a run or lose its timestamp.
        const QModelIndex seam = index(n);
        emit dataChanged(seam, seam);
    }
    emit countChanged();
}

void MessageModel::clear() {
    if (rows_.isEmpty()) {
        return;
    }
    beginResetModel();
    rows_.clear();
    endResetModel();
    emit countChanged();
}

int MessageModel::count() const {
    return static_cast<int>(rows_.size());
}

qint64 MessageModel::oldestId() const {
    return rows_.isEmpty() ? 0 : rows_.first().id;
}

const ChatEntry& MessageModel::entryAt(int row) const {
    return rows_.at(row);
}

} // namespace Intercli
