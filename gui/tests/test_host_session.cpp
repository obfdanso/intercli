// Hosting a chat from the app: server on a free port, beacon, stable chat id,
// room code and identity.

#include "chat_client.h"
#include "discovery.h"
#include "host_session.h"
#include "network_check.h"
#include "secure_server.h"

#include <QFile>
#include <QSettings>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QUdpSocket>
#include <QtTest>

#include <condition_variable>
#include <mutex>
#include <thread>

using namespace Intercli;

namespace {

constexpr quint16 kDiscovery = 18083;

struct Registration {
    std::mutex m;
    std::condition_variable cv;
    std::string result;
    SecureComm::ChatEvents events() {
        SecureComm::ChatEvents ev;
        ev.on_registered = [this](const std::string& n) { set("ok:" + n); };
        ev.on_register_failed = [this](const std::string& r) { set("fail:" + r); };
        return ev;
    }
    void set(const std::string& r) {
        { std::lock_guard<std::mutex> lock(m); result = r; }
        cv.notify_all();
    }
    std::string wait() {
        std::unique_lock<std::mutex> lock(m);
        cv.wait_for(lock, std::chrono::seconds(5), [this] { return !result.empty(); });
        return result;
    }
};

} // namespace

class TestHostSession : public QObject {
    Q_OBJECT
    QTemporaryDir settingsDir;
    QTemporaryDir dataDir;

private slots:
    void initTestCase() {
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settingsDir.path());
    }

    void says_when_it_cannot_be_found() {
        HostSession host(dataDir.path());
        QSignalSpy started(&host, &HostSession::started);
        host.start(QStringLiteral("Danso"), kDiscovery);
        QTRY_COMPARE_WITH_TIMEOUT(started.count(), 1, 5000);
        QVERIFY(host.discoverable());
        host.stop();
        QVERIFY(!host.discoverable());

        // Something else holds the discovery port for itself.
        QUdpSocket blocker;
        QVERIFY(blocker.bind(QHostAddress::AnyIPv4, kDiscovery, QUdpSocket::DontShareAddress));
        host.start(QStringLiteral("Danso"), kDiscovery);
        QTRY_COMPARE_WITH_TIMEOUT(started.count(), 2, 5000);
        QVERIFY(host.running());
        QVERIFY(!host.discoverable());
        host.stop();
    }

    void hosts_on_the_next_free_port() {
        // Something else already has 8080.
        SecureComm::ServerOptions blocker_options;
        blocker_options.port = 8080;
        SecureComm::SecureServer blocker(blocker_options);
        std::string err;
        const bool blocking = blocker.start(&err);

        HostSession host(dataDir.path());
        QSignalSpy started(&host, &HostSession::started);
        host.start(QStringLiteral("Danso"), kDiscovery);
        QTRY_COMPARE_WITH_TIMEOUT(started.count(), 1, 5000);
        QVERIFY(host.running());
        if (blocking) {
            QCOMPARE(host.port(), quint16(8082));
        }
        host.stop();
        QVERIFY(!host.running());
        blocker.stop();
    }

    void chat_id_code_and_identity_are_stable() {
        HostSession first(dataDir.path());
        HostSession second(dataDir.path());
        QVERIFY(!first.chatId().isEmpty());
        QCOMPARE(first.chatId(), second.chatId());
        QCOMPARE(first.roomCode().size(), 6);
        QCOMPARE(first.roomCode(), second.roomCode());
        QCOMPARE(first.identityPublic().size(), 32);
        QCOMPARE(first.identityPublic(), second.identityPublic());
    }

    // A lost identity key means a new chat: people who joined before see a new
    // chat rather than being refused with "identity has changed".
    void a_lost_identity_key_starts_a_new_chat() {
        QTemporaryDir d;
        QString before;
        {
            HostSession first(d.path());
            before = first.chatId();
        }
        QVERIFY(QFile::remove(d.filePath("host.key")));
        HostSession second(d.path());
        QVERIFY(second.chatId() != before);
        QCOMPARE(second.identityPublic().size(), 32);
    }

    void joining_needs_the_room_code() {
        HostSession host(dataDir.path());
        QSignalSpy started(&host, &HostSession::started);
        host.start(QStringLiteral("Danso"), kDiscovery);
        QTRY_COMPARE_WITH_TIMEOUT(started.count(), 1, 5000);
        const uint16_t port = host.port();

        Registration without;
        SecureComm::ChatClient intruder(without.events());
        std::string err;
        QVERIFY(intruder.connect("127.0.0.1", port, &err));
        intruder.request_name("intruder", "");
        QVERIFY(without.wait() == "fail:Wrong room code");

        Registration with;
        SecureComm::ChatClient friendClient(with.events());
        QVERIFY(friendClient.connect("127.0.0.1", port, &err));
        const QByteArray expected = host.identityPublic();
        QVERIFY(friendClient.server_identity() == std::vector<uint8_t>(expected.begin(), expected.end()));
        friendClient.request_name("friend", host.roomCode().toStdString());
        QVERIFY(with.wait() == "ok:friend");
        host.stop();
    }

    void bans_last_until_cleared() {
        HostSession host(dataDir.path());
        host.clearBans();
        QSignalSpy started(&host, &HostSession::started);
        host.start(QStringLiteral("Danso"), kDiscovery);
        QTRY_COMPARE_WITH_TIMEOUT(started.count(), 1, 5000);
        const std::string code = host.roomCode().toStdString();
        std::string err;
        {
            Registration reg;
            SecureComm::ChatClient pest(reg.events());
            QVERIFY(pest.connect("127.0.0.1", host.port(), &err));
            pest.request_name("pest", code);
            QVERIFY(reg.wait() == "ok:pest");
            QVERIFY(host.ban(QStringLiteral("pest")));
        }
        QCOMPARE(host.bannedCount(), 1);
        host.stop();

        // Hosting again, even from a new session, keeps them out.
        HostSession again(dataDir.path());
        QCOMPARE(again.bannedCount(), 1);
        QSignalSpy startedAgain(&again, &HostSession::started);
        again.start(QStringLiteral("Danso"), kDiscovery);
        QTRY_COMPARE_WITH_TIMEOUT(startedAgain.count(), 1, 5000);
        {
            Registration reg;
            SecureComm::ChatClient pest(reg.events());
            QVERIFY(pest.connect("127.0.0.1", again.port(), &err));
            pest.request_name("pest", code);
            QVERIFY(reg.wait().rfind("fail:", 0) == 0);
        }

        // Clearing the bans lets them back in at once.
        again.clearBans();
        QCOMPARE(again.bannedCount(), 0);
        {
            Registration reg;
            SecureComm::ChatClient pest(reg.events());
            QVERIFY(pest.connect("127.0.0.1", again.port(), &err));
            pest.request_name("pest", code);
            QVERIFY(reg.wait() == "ok:pest");
        }
        again.stop();
    }

    void one_ban_can_be_lifted() {
        HostSession host(dataDir.path());
        host.clearBans();
        QSignalSpy started(&host, &HostSession::started);
        host.start(QStringLiteral("Danso"), kDiscovery);
        QTRY_COMPARE_WITH_TIMEOUT(started.count(), 1, 5000);
        const std::string code = host.roomCode().toStdString();
        std::string err;
        const auto join = [&](const std::string& name) {
            Registration reg;
            SecureComm::ChatClient client(reg.events());
            if (!client.connect("127.0.0.1", host.port(), &err)) {
                return std::string("no connection");
            }
            client.request_name(name, code);
            return reg.wait();
        };
        for (const char* name : {"ann", "bob"}) {
            Registration reg;
            SecureComm::ChatClient client(reg.events());
            QVERIFY(client.connect("127.0.0.1", host.port(), &err));
            client.request_name(name, code);
            QVERIFY(reg.wait() == std::string("ok:") + name);
            QVERIFY(host.ban(QString::fromLatin1(name)));
        }
        QCOMPARE(host.bannedNames(), QStringList({"ann", "bob"}));

        QVERIFY(host.unban(QStringLiteral("ann")));
        QVERIFY(!host.unban(QStringLiteral("ann")));
        QCOMPARE(host.bannedNames(), QStringList({"bob"}));
        QVERIFY(join("ann") == "ok:ann");
        QVERIFY(join("bob").rfind("fail:", 0) == 0);
        host.stop();

        HostSession again(dataDir.path());
        QCOMPARE(again.bannedNames(), QStringList({"bob"}));
        again.clearBans();
    }

    void the_chat_shows_up_nearby_with_its_people() {
        HostSession host(dataDir.path());
        host.setPeoplePollForTests(200);
        QSignalSpy started(&host, &HostSession::started);
        host.start(QStringLiteral("Danso"), kDiscovery);
        QTRY_COMPARE_WITH_TIMEOUT(started.count(), 1, 5000);

        ChatFinder finder;
        finder.setTimingForTests(200, 2000);
        finder.start(kDiscovery);
        QTRY_VERIFY_WITH_TIMEOUT(finder.find(host.chatId()).has_value(), 3000);
        auto seen = finder.find(host.chatId());
        QCOMPARE(seen->chatName, QStringLiteral("Danso's chat"));
        QCOMPARE(seen->port, host.port());
        QCOMPARE(seen->people, 0);

        Registration reg;
        SecureComm::ChatClient joiner(reg.events());
        std::string err;
        QVERIFY(joiner.connect("127.0.0.1", host.port(), &err));
        joiner.request_name("ama", host.roomCode().toStdString());
        QVERIFY(reg.wait() == "ok:ama");
        QTRY_COMPARE_WITH_TIMEOUT(finder.find(host.chatId())->people, 1, 3000);
        QTRY_COMPARE_WITH_TIMEOUT(host.people(), 1, 3000);

        host.stop();
        QTRY_VERIFY_WITH_TIMEOUT(!finder.find(host.chatId()).has_value(), 4000);
    }

    void stopping_frees_the_port() {
        HostSession host(dataDir.path());
        QSignalSpy started(&host, &HostSession::started);
        host.start(QStringLiteral("Danso"), kDiscovery);
        QTRY_COMPARE_WITH_TIMEOUT(started.count(), 1, 5000);
        const quint16 port = host.port();
        host.stop();
        SecureComm::ServerOptions o;
        o.port = port;
        SecureComm::SecureServer again(o);
        std::string err;
        QVERIFY2(again.start(&err), err.c_str());
        again.stop();
    }

    void network_check_answers() {
        // Can't control the network here; it must simply answer without hanging.
        const bool isPublic = onPublicNetwork();
        Q_UNUSED(isPublic);
    }
};

QTEST_MAIN(TestHostSession)
#include "test_host_session.moc"
