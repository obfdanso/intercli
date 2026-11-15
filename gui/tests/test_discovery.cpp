// Finding chats on the local network: the host's beacon answers queries, the
// joiner's finder lists what answers. Runs on loopback with test ports.

#include "discovery.h"

#include <QHostAddress>
#include <QUdpSocket>
#include <QtTest>

using namespace Intercli;

namespace {

constexpr quint16 kPort = 18081;

ChatAnnouncement announcement(const QString& id = QStringLiteral("chat-1"), int people = 1) {
    ChatAnnouncement a;
    a.chatId = id;
    a.chatName = QStringLiteral("Danso's chat");
    a.hostName = QStringLiteral("Danso");
    a.safetyCode = QStringLiteral("1234 5678 9012 3456 7890");
    a.port = 8082;
    a.people = people;
    return a;
}

int rowOf(const ChatFinder& f, const QString& id) {
    for (int r = 0; r < f.rowCount(); ++r) {
        if (f.data(f.index(r), ChatFinder::ChatIdRole).toString() == id) return r;
    }
    return -1;
}

} // namespace

class TestDiscovery : public QObject {
    Q_OBJECT
private slots:
    void beacon_answers_a_query() {
        ChatBeacon beacon;
        QVERIFY(beacon.start(kPort));
        beacon.setAnnouncement(announcement());

        QUdpSocket asker;
        QVERIFY(asker.bind(QHostAddress::LocalHost, 0));
        asker.writeDatagram(ChatFinder::queryDatagram(), QHostAddress::LocalHost, kPort);
        QTRY_VERIFY(asker.hasPendingDatagrams());
        QByteArray reply(int(asker.pendingDatagramSize()), 0);
        asker.readDatagram(reply.data(), reply.size());
        QVERIFY(reply.startsWith("INTERCLI!2"));
        QVERIFY(reply.contains("chat-1"));
        QVERIFY(reply.contains("Danso's chat"));
    }

    void finder_lists_a_hosted_chat() {
        ChatBeacon beacon;
        QVERIFY(beacon.start(kPort));
        beacon.setAnnouncement(announcement());

        ChatFinder finder;
        finder.setTimingForTests(200, 1000);
        finder.start(kPort);
        QTRY_COMPARE_WITH_TIMEOUT(finder.rowCount(), 1, 3000);
        const QModelIndex i = finder.index(0);
        QCOMPARE(finder.data(i, ChatFinder::ChatIdRole).toString(), QStringLiteral("chat-1"));
        QCOMPARE(finder.data(i, ChatFinder::ChatNameRole).toString(), QStringLiteral("Danso's chat"));
        QCOMPARE(finder.data(i, ChatFinder::HostNameRole).toString(), QStringLiteral("Danso"));
        QCOMPARE(finder.data(i, ChatFinder::PeopleRole).toInt(), 1);
        QCOMPARE(finder.data(i, ChatFinder::PortRole).toInt(), 8082);
        QVERIFY(!finder.data(i, ChatFinder::AddressRole).toString().isEmpty());
        QVERIFY(finder.find(QStringLiteral("chat-1")).has_value());
        QCOMPARE(finder.find(QStringLiteral("chat-1"))->port, quint16(8082));

        // People count changes are picked up.
        beacon.setAnnouncement(announcement(QStringLiteral("chat-1"), 3));
        QTRY_COMPARE_WITH_TIMEOUT(finder.data(finder.index(0), ChatFinder::PeopleRole).toInt(), 3, 3000);

        // When the host stops, the chat disappears after the expiry time.
        beacon.stop();
        QTRY_COMPARE_WITH_TIMEOUT(finder.rowCount(), 0, 4000);
        QVERIFY(!finder.find(QStringLiteral("chat-1")).has_value());
    }

    void replies_from_several_interfaces_are_one_row() {
        ChatFinder finder;
        finder.setTimingForTests(200, 2000);
        finder.start(kPort);
        // (No raw string here: moc misreads the apostrophe inside one.)
        const QByteArray reply = QByteArray("INTERCLI!2") +
            "{\"id\":\"chat-9\",\"name\":\"Kofi chat\",\"host\":\"Kofi\",\"port\":8080,\"people\":2,\"code\":\"1 2 3 4 5\"}";
        finder.injectReplyForTests(reply, QHostAddress(QStringLiteral("192.168.1.20")));
        finder.injectReplyForTests(reply, QHostAddress(QStringLiteral("10.0.0.5")));
        QCOMPARE(finder.rowCount(), 1);
        QCOMPARE(rowOf(finder, QStringLiteral("chat-9")), 0);
    }

    // A reply must never be much bigger than the question, or the beacon could
    // be used to flood someone with traffic they never asked for.
    void short_queries_get_no_reply() {
        ChatBeacon beacon;
        QVERIFY(beacon.start(kPort));
        beacon.setAnnouncement(announcement());
        QUdpSocket asker;
        QVERIFY(asker.bind(QHostAddress::LocalHost, 0));
        asker.writeDatagram(QByteArray("INTERCLI?2"), QHostAddress::LocalHost, kPort);
        QTest::qWait(500);
        QVERIFY(!asker.hasPendingDatagrams());
        QVERIFY(ChatFinder::queryDatagram().size() >= 256);
    }

    void replies_are_rate_limited_per_sender() {
        ChatBeacon beacon;
        QVERIFY(beacon.start(kPort));
        beacon.setAnnouncement(announcement());
        QUdpSocket asker;
        QVERIFY(asker.bind(QHostAddress::LocalHost, 0));
        for (int i = 0; i < 10; ++i) {
            asker.writeDatagram(ChatFinder::queryDatagram(), QHostAddress::LocalHost, kPort);
        }
        QTest::qWait(500);
        int replies = 0;
        while (asker.hasPendingDatagrams()) {
            QByteArray d(int(asker.pendingDatagramSize()), 0);
            asker.readDatagram(d.data(), d.size());
            ++replies;
        }
        QVERIFY2(replies <= 2, qPrintable(QString("got %1 replies to a burst of 10").arg(replies)));
        QVERIFY(replies >= 1);
    }

    // Someone else claiming an already listed chat can't move it to their address.
    void a_listed_chat_keeps_its_first_address() {
        ChatFinder finder;
        finder.setTimingForTests(200, 5000);
        finder.start(kPort);
        const QByteArray reply = QByteArray("INTERCLI!2") +
            "{\"id\":\"chat-5\",\"name\":\"Ama chat\",\"host\":\"Ama\",\"port\":8080,\"people\":2,\"code\":\"1\"}";
        finder.injectReplyForTests(reply, QHostAddress(QStringLiteral("192.168.1.20")));
        finder.injectReplyForTests(reply, QHostAddress(QStringLiteral("192.168.1.66")));
        QCOMPARE(finder.rowCount(), 1);
        QCOMPARE(finder.find(QStringLiteral("chat-5"))->address, QHostAddress(QStringLiteral("192.168.1.20")));
    }

    void the_list_is_bounded() {
        ChatFinder finder;
        finder.setTimingForTests(200, 60000);
        finder.start(kPort);
        // One address can list only a few chats.
        for (int i = 0; i < 20; ++i) {
            const QByteArray r = QByteArray("INTERCLI!2") + "{\"id\":\"one-" + QByteArray::number(i) +
                "\",\"name\":\"x\",\"host\":\"x\",\"port\":8080,\"people\":1,\"code\":\"1\"}";
            finder.injectReplyForTests(r, QHostAddress(QStringLiteral("10.1.1.1")));
        }
        QCOMPARE(finder.rowCount(), 4);
        // And the whole list has a ceiling.
        for (int i = 0; i < 200; ++i) {
            const QByteArray r = QByteArray("INTERCLI!2") + "{\"id\":\"many-" + QByteArray::number(i) +
                "\",\"name\":\"x\",\"host\":\"x\",\"port\":8080,\"people\":1,\"code\":\"1\"}";
            finder.injectReplyForTests(r, QHostAddress(QStringLiteral("10.2.%1.%2").arg(i / 200).arg(i % 200 + 1)));
        }
        QCOMPARE(finder.rowCount(), 64);
    }

    void garbage_is_ignored() {
        ChatFinder finder;
        finder.setTimingForTests(200, 2000);
        finder.start(kPort);
        const QHostAddress from(QStringLiteral("192.168.1.30"));
        finder.injectReplyForTests(QByteArray("hello"), from);
        finder.injectReplyForTests(QByteArray("INTERCLI!1{\"id\":\"old\",\"name\":\"x\",\"host\":\"x\",\"port\":1,\"people\":1}"), from);
        finder.injectReplyForTests(QByteArray("INTERCLI!2not json"), from);
        finder.injectReplyForTests(QByteArray("INTERCLI!2{\"id\":\"\",\"name\":\"x\",\"host\":\"x\",\"port\":1,\"people\":1}"), from);
        finder.injectReplyForTests(QByteArray("INTERCLI!2{\"id\":\"p\",\"name\":\"x\",\"host\":\"x\",\"port\":0,\"people\":1}"), from);
        finder.injectReplyForTests(QByteArray("INTERCLI!2") + QByteArray(2000, 'x'), from);
        QCOMPARE(finder.rowCount(), 0);
    }
};

QTEST_MAIN(TestDiscovery)
#include "test_discovery.moc"
