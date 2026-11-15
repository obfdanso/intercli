#include "conversation_list_model.h"
#include <QtTest>

using namespace Intercli;

namespace {
QString idAt(const ConversationListModel& m, int row) {
    return m.data(m.index(row), ConversationListModel::ConversationIdRole).toString();
}
QVariant roleAt(const ConversationListModel& m, int row, int role) {
    return m.data(m.index(row), role);
}
QDateTime t(int minutes) {
    return QDateTime(QDate(2026, 11, 15), QTime(9, 0)).addSecs(minutes * 60);
}
}

class TestConversationListModel : public QObject {
    Q_OBJECT
private slots:
    void starts_with_everyone() {
        ConversationListModel m;
        QCOMPARE(m.rowCount(), 1);
        QCOMPARE(idAt(m, 0), QString());
        QCOMPARE(roleAt(m, 0, ConversationListModel::TitleRole).toString(), QStringLiteral("Everyone"));
        QCOMPARE(roleAt(m, 0, ConversationListModel::SectionRole).toString(), QStringLiteral("everyone"));
    }

    void roster_excludes_me() {
        ConversationListModel m;
        m.setRoster({"alice", "bob", "carol"}, "bob");
        QCOMPARE(m.rowCount(), 3);
        QCOMPARE(idAt(m, 0), QString());
        QCOMPARE(idAt(m, 1), QStringLiteral("alice"));
        QCOMPARE(idAt(m, 2), QStringLiteral("carol"));
        QVERIFY(roleAt(m, 1, ConversationListModel::OnlineRole).toBool());
        QCOMPARE(m.onlineCount(), 2);
    }

    void activity_orders_and_counts_unread() {
        ConversationListModel m;
        m.setRoster({"alice", "bob", "carol"}, "bob");
        m.touch("alice", "old", t(1), false);
        m.touch("carol", "hi", t(2), true);
        QCOMPARE(idAt(m, 1), QStringLiteral("carol"));
        QCOMPARE(roleAt(m, 1, ConversationListModel::UnreadRole).toInt(), 1);
        QCOMPARE(roleAt(m, 1, ConversationListModel::PreviewRole).toString(), QStringLiteral("hi"));
        QCOMPARE(m.unreadTotal(), 1);

        m.setOnline("carol", false);
        QCOMPARE(idAt(m, 1), QStringLiteral("alice"));
        QCOMPARE(idAt(m, 2), QStringLiteral("carol"));
        QCOMPARE(roleAt(m, 2, ConversationListModel::SectionRole).toString(), QStringLiteral("offline"));
        QCOMPARE(m.onlineCount(), 1);

        m.markRead("carol");
        QCOMPARE(roleAt(m, 2, ConversationListModel::UnreadRole).toInt(), 0);
    }

    void touch_creates_offline_person() {
        ConversationListModel m;
        m.touch("dave", "hey", t(3), true);
        QCOMPARE(m.rowCount(), 2);
        QCOMPARE(idAt(m, 1), QStringLiteral("dave"));
        QVERIFY(!roleAt(m, 1, ConversationListModel::OnlineRole).toBool());
    }

    void everyone_stays_first() {
        ConversationListModel m;
        m.setRoster({"alice"}, "me");
        m.touch("alice", "x", t(5), false);
        m.touch(QString(), "y", t(1), false);
        QCOMPARE(idAt(m, 0), QString());
        QCOMPARE(m.indexOf("alice"), 1);
    }

    void moves_emit_move_signals() {
        ConversationListModel m;
        m.setRoster({"alice", "carol"}, "me");
        QSignalSpy moved(&m, &QAbstractItemModel::rowsMoved);
        m.touch("carol", "hi", t(9), false);
        QCOMPARE(moved.count(), 1);
        QCOMPARE(idAt(m, 1), QStringLiteral("carol"));
    }

    void clear_leaves_everyone() {
        ConversationListModel m;
        m.setRoster({"alice", "carol"}, "me");
        m.clear();
        QCOMPARE(m.rowCount(), 1);
        QCOMPARE(m.onlineCount(), 0);
    }
};

QTEST_GUILESS_MAIN(TestConversationListModel)
#include "test_conversation_list_model.moc"
