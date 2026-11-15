#include "message_model.h"
#include <QtTest>

using namespace Intercli;

namespace {
QDateTime t(int minutes) {
    return QDateTime(QDate(2026, 11, 15), QTime(9, 0)).addSecs(minutes * 60);
}
ChatEntry in(const QString& who, int minutes, qint64 id = 0) {
    return ChatEntry{id, MessageModel::Incoming, who, QStringLiteral("x"), t(minutes)};
}
ChatEntry out(int minutes) {
    return ChatEntry{0, MessageModel::Outgoing, QStringLiteral("me"), QStringLiteral("y"), t(minutes)};
}
ChatEntry sys(int minutes) {
    return ChatEntry{0, MessageModel::System, QString(), QStringLiteral("alice joined"), t(minutes)};
}
bool flag(const MessageModel& m, int row, int role) {
    return m.data(m.index(row), role).toBool();
}
}

class TestMessageModel : public QObject {
    Q_OBJECT
private slots:
    void runs_get_first_and_last_flags() {
        MessageModel m(true);
        m.append(in("alice", 0));
        m.append(in("alice", 0));
        m.append(in("alice", 1));
        QCOMPARE(flag(m, 0, MessageModel::FirstInRunRole), true);
        QCOMPARE(flag(m, 0, MessageModel::LastInRunRole), false);
        QCOMPARE(flag(m, 1, MessageModel::FirstInRunRole), false);
        QCOMPARE(flag(m, 1, MessageModel::LastInRunRole), false);
        QCOMPARE(flag(m, 2, MessageModel::FirstInRunRole), false);
        QCOMPARE(flag(m, 2, MessageModel::LastInRunRole), true);
    }

    void gap_over_five_minutes_starts_a_run() {
        MessageModel m(true);
        m.append(in("alice", 0));
        m.append(in("alice", 6));
        QCOMPARE(flag(m, 1, MessageModel::FirstInRunRole), true);
        QCOMPARE(flag(m, 0, MessageModel::LastInRunRole), true);
    }

    void different_kind_or_sender_starts_a_run() {
        MessageModel m(true);
        m.append(in("alice", 0));
        m.append(out(0));
        m.append(in("bob", 0));
        QVERIFY(flag(m, 1, MessageModel::FirstInRunRole));
        QVERIFY(flag(m, 2, MessageModel::FirstInRunRole));
    }

    void system_rows_stand_alone() {
        MessageModel m(true);
        m.append(in("alice", 0));
        m.append(sys(0));
        m.append(in("alice", 0));
        QVERIFY(flag(m, 1, MessageModel::FirstInRunRole));
        QVERIFY(flag(m, 1, MessageModel::LastInRunRole));
        QVERIFY(!flag(m, 1, MessageModel::ShowSenderRole));
        QVERIFY(flag(m, 2, MessageModel::FirstInRunRole));
    }

    void sender_shown_only_in_everyone() {
        MessageModel everyone(true);
        everyone.append(in("alice", 0));
        everyone.append(in("alice", 0));
        QVERIFY(flag(everyone, 0, MessageModel::ShowSenderRole));
        QVERIFY(!flag(everyone, 1, MessageModel::ShowSenderRole));

        MessageModel direct(false);
        direct.append(in("alice", 0));
        QVERIFY(!flag(direct, 0, MessageModel::ShowSenderRole));

        everyone.append(out(0));
        QVERIFY(!flag(everyone, 2, MessageModel::ShowSenderRole));
    }

    void timestamps_on_first_row_and_after_fifteen_minutes() {
        MessageModel m(false);
        m.append(in("alice", 0));
        m.append(in("alice", 10));
        m.append(in("alice", 26));
        QVERIFY(flag(m, 0, MessageModel::ShowTimestampRole));
        QVERIFY(!flag(m, 1, MessageModel::ShowTimestampRole));
        QVERIFY(flag(m, 2, MessageModel::ShowTimestampRole));
    }

    void continuing_a_run_updates_the_previous_row() {
        MessageModel m(true);
        m.append(in("alice", 0));
        QSignalSpy changed(&m, &QAbstractItemModel::dataChanged);
        m.append(in("alice", 0));
        QCOMPARE(changed.count(), 1);
        QCOMPARE(changed.at(0).at(0).value<QModelIndex>().row(), 0);
        QVERIFY(!flag(m, 0, MessageModel::LastInRunRole));
    }

    void prepend_keeps_flags_right_across_the_seam() {
        MessageModel m(true);
        m.append(in("alice", 3, 10));
        m.prepend({in("alice", 1, 8), in("alice", 2, 9)});
        QCOMPARE(m.count(), 3);
        QCOMPARE(m.oldestId(), qint64(8));
        QVERIFY(flag(m, 0, MessageModel::FirstInRunRole));
        QVERIFY(!flag(m, 1, MessageModel::LastInRunRole));
        QVERIFY(!flag(m, 2, MessageModel::FirstInRunRole));
        QVERIFY(!flag(m, 2, MessageModel::ShowSenderRole));
        QVERIFY(flag(m, 0, MessageModel::ShowTimestampRole));
        QVERIFY(!flag(m, 2, MessageModel::ShowTimestampRole));
    }

    void clear_empties() {
        MessageModel m(true);
        m.append(in("alice", 0));
        m.clear();
        QCOMPARE(m.count(), 0);
        QCOMPARE(m.oldestId(), qint64(0));
    }
};

QTEST_GUILESS_MAIN(TestMessageModel)
#include "test_message_model.moc"
