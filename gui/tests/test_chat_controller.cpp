// Drives ChatController against a real server (started by run_with_server.sh),
// with a plain ChatClient playing "alice" on the other side.

#include "chat_client.h"
#include "chat_controller.h"
#include "conversation_list_model.h"
#include "message_model.h"
#include "history_store.h"
#include "host_session.h"
#include "discovery.h"
#include "../../tests/silent_server.h"

#include <QElapsedTimer>
#include <QSettings>
#include <QTemporaryDir>
#include <QtTest>

#include <atomic>
#include <memory>
#include <mutex>
#include <vector>

using namespace Intercli;

namespace {

constexpr int kWait = 8000;

// A raw client on the other side of the conversation. Its events are only counted.
struct Peer {
    std::mutex mutex;
    std::vector<std::string> received;
    std::unique_ptr<SecureComm::ChatClient> client;

    explicit Peer(const std::string& name) {
        SecureComm::ChatEvents ev;
        ev.on_direct = [this](const std::string& f, const std::string& t) { add("direct:" + f + ":" + t); };
        ev.on_broadcast = [this](const std::string& f, const std::string& t) { add("broadcast:" + f + ":" + t); };
        ev.on_registered = [this](const std::string& n) { add("registered:" + n); };
        ev.on_presence = [this](const std::string& n, bool joined, const std::string&) {
            add("presence:" + n + (joined ? ":joined" : ":left"));
        };
        client = std::make_unique<SecureComm::ChatClient>(ev);
        std::string err;
        if (client->connect("127.0.0.1", SecureComm::DEFAULT_PORT, &err)) {
            client->request_name(name);
        }
    }
    void add(const std::string& s) {
        std::lock_guard<std::mutex> lock(mutex);
        received.push_back(s);
    }
    int count(const std::string& s) {
        std::lock_guard<std::mutex> lock(mutex);
        int n = 0;
        for (const auto& r : received) {
            if (r == s) ++n;
        }
        return n;
    }
    bool has(const std::string& s) {
        std::lock_guard<std::mutex> lock(mutex);
        for (const auto& r : received) {
            if (r == s) return true;
        }
        return false;
    }
};

int rowOf(QAbstractItemModel* m, const QString& id) {
    for (int r = 0; r < m->rowCount(); ++r) {
        if (m->data(m->index(r, 0), ConversationListModel::ConversationIdRole).toString() == id) {
            return r;
        }
    }
    return -1;
}

int unreadOf(QAbstractItemModel* m, const QString& id) {
    const int r = rowOf(m, id);
    return r < 0 ? -1 : m->data(m->index(r, 0), ConversationListModel::UnreadRole).toInt();
}

bool onlineOf(QAbstractItemModel* m, const QString& id) {
    const int r = rowOf(m, id);
    return r >= 0 && m->data(m->index(r, 0), ConversationListModel::OnlineRole).toBool();
}

QString lastText(MessageModel* m) {
    return m->count() == 0 ? QString() : m->entryAt(m->count() - 1).text;
}

int lastKind(MessageModel* m) {
    return m->count() == 0 ? -1 : static_cast<int>(m->entryAt(m->count() - 1).kind);
}

} // namespace

class TestChatController : public QObject {
    Q_OBJECT

    QTemporaryDir settingsDir;
    std::unique_ptr<Peer> alice;
    std::unique_ptr<ChatController> bob;

private slots:
    void initTestCase() {
        // Keep test settings out of the user's real settings.
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settingsDir.path());
        alice = std::make_unique<Peer>("alice");
        QTRY_VERIFY_WITH_TIMEOUT(alice->has("registered:alice"), kWait);
        bob = std::make_unique<ChatController>();
    }

    void signs_in() {
        bob->signIn("127.0.0.1", SecureComm::DEFAULT_PORT, "bob");
        QCOMPARE(bob->state(), ChatController::Connecting);
        QTRY_COMPARE_WITH_TIMEOUT(bob->state(), ChatController::Online, kWait);
        QCOMPARE(bob->myName(), QStringLiteral("bob"));
        QTRY_COMPARE_WITH_TIMEOUT(bob->onlineCount(), 1, kWait);
        QTRY_VERIFY_WITH_TIMEOUT(bob->onlineNames().contains("alice"), kWait);
        QVERIFY(!bob->onlineNames().contains("bob"));
        QCOMPARE(bob->onlineCount(), 1);
    }

    void taken_name_reports_name_error() {
        ChatController other;
        other.signIn("127.0.0.1", SecureComm::DEFAULT_PORT, "bob");
        QTRY_COMPARE_WITH_TIMEOUT(other.state(), ChatController::SignedOut, kWait);
        QVERIFY(other.nameError().contains("taken"));
        QVERIFY(other.connectError().isEmpty());
    }

    void invalid_name_rejected_locally() {
        ChatController other;
        QSignalSpy states(&other, &ChatController::stateChanged);
        other.signIn("127.0.0.1", SecureComm::DEFAULT_PORT, "a b");
        QVERIFY(!other.nameError().isEmpty());
        QCOMPARE(other.state(), ChatController::SignedOut);
        QCOMPARE(states.count(), 0);
        other.clearErrors();
        QVERIFY(other.nameError().isEmpty());
    }

    void bad_port_reports_connect_error() {
        ChatController other;
        QElapsedTimer timer;
        timer.start();
        other.signIn("127.0.0.1", 1, "zed");
        QVERIFY2(timer.elapsed() < 50, "signIn must not block the UI thread");
        QTRY_COMPARE_WITH_TIMEOUT(other.state(), ChatController::SignedOut, 30000);
        QVERIFY(other.connectError().contains("Couldn't reach 127.0.0.1:1"));
        QVERIFY(other.nameError().isEmpty());
    }

    // The error says what actually went wrong, not always "couldn't reach".
    void silent_server_reports_no_answer() {
        SilentServer silent;
        ChatController other;
        other.signIn("127.0.0.1", silent.port(), "quiet");
        QTRY_COMPARE_WITH_TIMEOUT(other.state(), ChatController::SignedOut, 30000);
        QVERIFY2(other.connectError().contains("didn't answer"), qPrintable(other.connectError()));
    }

    void unknown_host_reports_not_found() {
        ChatController other;
        other.signIn("no-such-host.invalid", 8080, "lost");
        QTRY_COMPARE_WITH_TIMEOUT(other.state(), ChatController::SignedOut, 30000);
        QVERIFY2(other.connectError().contains("Couldn't find"), qPrintable(other.connectError()));
    }

    // A server that accepts but never answers: leaving must not freeze the UI.
    void sign_out_during_connect_returns_quickly() {
        SilentServer silent;
        ChatController other;
        other.signIn("127.0.0.1", silent.port(), "slowpoke");
        QTest::qWait(200);
        QCOMPARE(other.state(), ChatController::Connecting);
        QElapsedTimer timer;
        timer.start();
        other.signOut();
        QVERIFY2(timer.elapsed() < 200, qPrintable(QString("signOut took %1 ms").arg(timer.elapsed())));
        QCOMPARE(other.state(), ChatController::SignedOut);
        // A fresh sign-in after that works normally.
        other.signIn("127.0.0.1", SecureComm::DEFAULT_PORT, "slowpoke");
        QTRY_COMPARE_WITH_TIMEOUT(other.state(), ChatController::Online, kWait);
    }

    void closing_during_connect_does_not_hang() {
        SilentServer silent;
        auto other = std::make_unique<ChatController>();
        other->signIn("127.0.0.1", silent.port(), "slowpoke2");
        QTest::qWait(200);
        QElapsedTimer timer;
        timer.start();
        other.reset();
        // Bounded by RSA key generation at most, never by the silent server.
        QVERIFY2(timer.elapsed() < 5000, qPrintable(QString("destruction took %1 ms").arg(timer.elapsed())));
    }

    void direct_and_broadcast_rows() {
        bob->setCurrentConversation(QString());
        alice->client->send_direct("bob", "hi");
        QTRY_COMPARE_WITH_TIMEOUT(unreadOf(bob->conversations(), "alice"), 1, kWait);

        bob->setCurrentConversation("alice");
        QCOMPARE(unreadOf(bob->conversations(), "alice"), 0);
        QCOMPARE(bob->messages()->count(), 1);
        QCOMPARE(lastText(bob->messages()), QStringLiteral("hi"));
        QCOMPARE(lastKind(bob->messages()), int(MessageModel::Incoming));

        QVERIFY(bob->send("yo"));
        QCOMPARE(lastKind(bob->messages()), int(MessageModel::Outgoing));
        QTRY_VERIFY_WITH_TIMEOUT(alice->has("direct:bob:yo"), kWait);

        alice->client->send_broadcast("to all");
        QTRY_COMPARE_WITH_TIMEOUT(unreadOf(bob->conversations(), ""), 1, kWait);
        bob->setCurrentConversation(QString());
        QCOMPARE(lastText(bob->messages()), QStringLiteral("to all"));
        QCOMPARE(bob->messages()->entryAt(bob->messages()->count() - 1).sender, QStringLiteral("alice"));
    }

    void send_rejects_blank_and_too_long() {
        bob->setCurrentConversation(QString());
        QVERIFY(!bob->send("   "));
        QVERIFY(!bob->send(QString(1025, QLatin1Char('a'))));
        QVERIFY(bob->send(QString(1024, QLatin1Char('a'))));
    }

    void notice_goes_to_last_target() {
        bob->setCurrentConversation("ghost");
        QVERIFY(bob->send("x"));
        QTRY_COMPARE_WITH_TIMEOUT(lastText(bob->messages()), QStringLiteral("No such user: ghost"), kWait);
        QCOMPARE(lastKind(bob->messages()), int(MessageModel::System));
    }

    void rotation_updates_session() {
        bob->setCurrentConversation(QString());
        const int before = bob->session().value("sendRotations").toInt();
        const int left = bob->session().value("messagesUntilRotation").toInt();
        for (int i = 0; i < left; ++i) {
            QVERIFY(bob->send(QString("filler %1").arg(i)));
        }
        QTRY_COMPARE_WITH_TIMEOUT(bob->session().value("sendRotations").toInt(), before + 1, kWait);
        QCOMPARE(bob->session().value("messagesUntilRotation").toInt(), 10);
        QVERIFY(bob->session().value("lastSendRotation").toDateTime().isValid());
        QVERIFY(bob->session().value("serverIdentity").toString() != QStringLiteral("Not verified"));
        bob->rotateKey();
        QTRY_COMPARE_WITH_TIMEOUT(bob->session().value("sendRotations").toInt(), before + 2, kWait);
        QTRY_COMPARE_WITH_TIMEOUT(lastText(bob->messages()), QStringLiteral("Your send key rotated"), kWait);
    }

    // --- saved history -------------------------------------------------

    static QString identity(const QString& name) {
        return identityKey("127.0.0.1", SecureComm::DEFAULT_PORT, name);
    }

    void history_unasked_saves_nothing() {
        QTemporaryDir d;
        HistoryStore store(d.filePath("h.db"), QByteArray(32, ''), "hist-unasked");
        QString err;
        QVERIFY(store.open(&err));
        ChatController c(&store);
        QVERIFY(c.historyAvailable());
        c.signIn("127.0.0.1", SecureComm::DEFAULT_PORT, "hzed");
        QTRY_COMPARE_WITH_TIMEOUT(c.state(), ChatController::Online, kWait);
        QCOMPARE(c.historyChoice(), int(HistoryChoice::Unasked));
        alice->client->send_direct("hzed", "not saved");
        QTRY_COMPARE_WITH_TIMEOUT(unreadOf(c.conversations(), "alice"), 1, kWait);
        QCOMPARE(store.totalMessageRowsForTest(), 0);
    }

    void history_save_round_trip() {
        QTemporaryDir d;
        HistoryStore store(d.filePath("h.db"), QByteArray(32, ''), "hist-save");
        QString err;
        QVERIFY(store.open(&err));
        ChatController c(&store);
        c.signIn("127.0.0.1", SecureComm::DEFAULT_PORT, "hsave");
        QTRY_COMPARE_WITH_TIMEOUT(c.state(), ChatController::Online, kWait);
        c.setHistoryChoice(int(HistoryChoice::Save), false);
        QCOMPARE(c.historyChoice(), int(HistoryChoice::Save));
        alice->client->send_direct("hsave", "saved hi");
        QTRY_COMPARE_WITH_TIMEOUT(unreadOf(c.conversations(), "alice"), 1, kWait);
        c.setCurrentConversation("alice");
        QVERIFY(c.send("saved reply"));

        c.signOut();
        QCOMPARE(c.conversations()->rowCount(), 1);
        c.signIn("127.0.0.1", SecureComm::DEFAULT_PORT, "hsave");
        QTRY_COMPARE_WITH_TIMEOUT(c.state(), ChatController::Online, kWait);
        QCOMPARE(c.historyChoice(), int(HistoryChoice::Save));
        QVERIFY(rowOf(c.conversations(), "alice") > 0);
        c.setCurrentConversation("alice");
        QCOMPARE(c.messages()->count(), 2);
        QCOMPARE(c.messages()->entryAt(0).text, QStringLiteral("saved hi"));
        QCOMPARE(c.messages()->entryAt(1).text, QStringLiteral("saved reply"));
        QCOMPARE(int(c.messages()->entryAt(1).kind), int(MessageModel::Outgoing));
        c.signOut();
    }

    void history_dont_save() {
        QTemporaryDir d;
        HistoryStore store(d.filePath("h.db"), QByteArray(32, ''), "hist-none");
        QString err;
        QVERIFY(store.open(&err));
        ChatController c(&store);
        c.signIn("127.0.0.1", SecureComm::DEFAULT_PORT, "hnone");
        QTRY_COMPARE_WITH_TIMEOUT(c.state(), ChatController::Online, kWait);
        c.setHistoryChoice(int(HistoryChoice::DontSave), false);
        alice->client->send_direct("hnone", "ephemeral");
        QTRY_COMPARE_WITH_TIMEOUT(unreadOf(c.conversations(), "alice"), 1, kWait);
        c.setCurrentConversation("alice");
        QVERIFY(c.send("also ephemeral"));
        QCOMPARE(store.totalMessageRowsForTest(), 0);
    }

    void history_turn_off_and_delete() {
        QTemporaryDir d;
        HistoryStore store(d.filePath("h.db"), QByteArray(32, ''), "hist-del");
        QString err;
        QVERIFY(store.open(&err));
        ChatController c(&store);
        c.signIn("127.0.0.1", SecureComm::DEFAULT_PORT, "hdel");
        QTRY_COMPARE_WITH_TIMEOUT(c.state(), ChatController::Online, kWait);
        c.setHistoryChoice(int(HistoryChoice::Save), false);
        c.setCurrentConversation("alice");
        QVERIFY(c.send("soon gone"));
        QVERIFY(store.totalMessageRowsForTest() > 0);
        c.setHistoryChoice(int(HistoryChoice::DontSave), true);
        QCOMPARE(store.loadPage(identity("hdel"), "alice", 50).size(), 0);
        QCOMPARE(store.totalMessageRowsForTest(), 0);
    }

    // --- hosting and joining nearby chats ---------------------------------

    void host_join_code_pin_and_end() {
        constexpr quint16 discovery = 18084;
        QTemporaryDir hostData;
        HostSession hosting(hostData.path());
        ChatController host(nullptr, &hosting, discovery);
        host.hostChat("hana");
        QTRY_COMPARE_WITH_TIMEOUT(host.state(), ChatController::Online, kWait);
        QVERIFY(host.hosting());
        QCOMPARE(host.roomCode().size(), 7);  // XXX-XXX
        QVERIFY(!host.safetyCode().isEmpty());
        QCOMPARE(host.safetyCode(), hosting.safetyCode());
        QVERIFY(host.historyIdentityForTests().startsWith("chat:" + hosting.chatId() + "/"));
        const QString chatId = hosting.chatId();
        const QString code = host.roomCode();

        // Someone else finds it in the list and joins with the code.
        ChatController joiner(nullptr, nullptr, discovery);
        QTRY_VERIFY_WITH_TIMEOUT(joiner.nearby()->find(chatId).has_value(), 6000);
        joiner.joinChat(chatId, code.toLower(), "jojo");
        QTRY_COMPARE_WITH_TIMEOUT(joiner.state(), ChatController::Online, kWait);
        QCOMPARE(joiner.safetyCode(), host.safetyCode());
        QVERIFY(joiner.historyIdentityForTests().startsWith("chat:" + chatId + "/"));
        QCOMPARE(joiner.rememberedCode(chatId), code);
        QTRY_COMPARE_WITH_TIMEOUT(host.peopleInChat(), 2, 6000);
        QVERIFY(host.needsEndChatConfirm());

        // A wrong code says so, next to the code field.
        ChatController guesser(nullptr, nullptr, discovery);
        QTRY_VERIFY_WITH_TIMEOUT(guesser.nearby()->find(chatId).has_value(), 6000);
        guesser.joinChat(chatId, "AAAAAA", "guess");
        QTRY_COMPARE_WITH_TIMEOUT(guesser.state(), ChatController::SignedOut, kWait);
        QCOMPARE(guesser.codeError(), QStringLiteral("Wrong room code"));
        QVERIFY(guesser.nameError().isEmpty());

        // A known chat whose identity changed is refused before anything is sent.
        QSettings().setValue("identities/chat:" + chatId, QString(64, QLatin1Char('a')));
        ChatController wary(nullptr, nullptr, discovery);
        QTRY_VERIFY_WITH_TIMEOUT(wary.nearby()->find(chatId).has_value(), 6000);
        wary.joinChat(chatId, code, "wary");
        QTRY_COMPARE_WITH_TIMEOUT(wary.state(), ChatController::SignedOut, kWait);
        QVERIFY2(wary.connectError().contains("identity has changed"), qPrintable(wary.connectError()));
        QTest::qWait(500);
        QCOMPARE(host.peopleInChat(), 2);
        // The new safety code is shown so it can be compared with the host, and
        // after that the new identity can be trusted.
        QVERIFY(wary.identityChanged());
        QCOMPARE(wary.newSafetyCode(), host.safetyCode());
        wary.trustNewIdentity();
        QTRY_COMPARE_WITH_TIMEOUT(wary.state(), ChatController::Online, kWait);
        QVERIFY(!wary.identityChanged());
        wary.signOut();

        // A first join to a chat whose server proves a different key than the
        // one announced is refused before the code is sent (someone redirected
        // the connection).
        {
            ChatController redirected(nullptr, nullptr, 18085);
            const QByteArray fake = QByteArray("INTERCLI!2") +
                "{\"id\":\"fake-chat\",\"name\":\"Hana chat\",\"host\":\"hana\",\"port\":" +
                QByteArray::number(hosting.port()) + ",\"people\":2,\"code\":\"1\",\"key\":\"" +
                QByteArray(64, 'b') + "\"}";
            redirected.nearby()->injectReplyForTests(fake, QHostAddress::LocalHost);
            redirected.joinChat("fake-chat", code, "victim");
            QTRY_COMPARE_WITH_TIMEOUT(redirected.state(), ChatController::SignedOut, kWait);
            QVERIFY2(redirected.connectError().contains("identity"), qPrintable(redirected.connectError()));
            QTest::qWait(500);
            QCOMPARE(host.peopleInChat(), 2);
        }

        // The joiner drops and comes back: found again by chat id.
        joiner.simulateConnectionLoss();
        QTRY_COMPARE_WITH_TIMEOUT(joiner.state(), ChatController::Disconnected, kWait);
        joiner.reconnect();
        QTRY_COMPARE_WITH_TIMEOUT(joiner.state(), ChatController::Online, kWait);

        // The host ends the chat: the joiner is disconnected.
        host.endChat();
        QCOMPARE(host.state(), ChatController::SignedOut);
        QVERIFY(!host.hosting());
        QTRY_COMPARE_WITH_TIMEOUT(joiner.state(), ChatController::Disconnected, kWait);
    }

    void connection_loss_reconnects() {
        const int everyoneRows = bob->messages()->count();
        bob->simulateConnectionLoss();
        QTRY_COMPARE_WITH_TIMEOUT(bob->state(), ChatController::Disconnected, kWait);
        QVERIFY(!bob->disconnectReason().isEmpty());
        QVERIFY(!bob->send("while offline"));
        // Nobody can be known to be online while we are cut off.
        QCOMPARE(bob->onlineCount(), 0);

        bob->reconnect();
        QTRY_COMPARE_WITH_TIMEOUT(bob->state(), ChatController::Online, kWait);
        QCOMPARE(bob->myName(), QStringLiteral("bob"));
        bob->setCurrentConversation(QString());
        QVERIFY(bob->messages()->count() >= everyoneRows);
        QVERIFY(bob->send("back"));
        QTRY_VERIFY_WITH_TIMEOUT(alice->has("broadcast:bob:back"), kWait);
    }

    // A receive error leaves the socket open; the app must close it so the
    // server stops showing us online while the banner is up.
    void receive_error_closes_the_connection() {
        const int leftBefore = alice->count("presence:bob:left");
        bob->simulateReceiveError();
        QTRY_COMPARE_WITH_TIMEOUT(bob->state(), ChatController::Disconnected, kWait);
        QTRY_COMPARE_WITH_TIMEOUT(alice->count("presence:bob:left"), leftBefore + 1, kWait);
        bob->reconnect();
        QTRY_COMPARE_WITH_TIMEOUT(bob->state(), ChatController::Online, kWait);
    }

    void presence_rows() {
        alice->client->disconnect();
        QTRY_VERIFY_WITH_TIMEOUT(!onlineOf(bob->conversations(), "alice"), kWait);
        bob->setCurrentConversation(QString());
        QTRY_COMPARE_WITH_TIMEOUT(lastText(bob->messages()), QStringLiteral("alice left"), kWait);
        QCOMPARE(lastKind(bob->messages()), int(MessageModel::System));
        QCOMPARE(bob->onlineCount(), 0);
    }

    void sign_out_clears() {
        bob->signOut();
        QCOMPARE(bob->state(), ChatController::SignedOut);
        QCOMPARE(bob->conversations()->rowCount(), 1);
        bob->setCurrentConversation(QString());
        QCOMPARE(bob->messages()->count(), 0);
        QCOMPARE(bob->serverHost(), QStringLiteral("127.0.0.1"));
        QCOMPARE(bob->myName(), QStringLiteral("bob"));
    }

    void cleanupTestCase() {
        bob.reset();
        alice.reset();
    }
};

QTEST_MAIN(TestChatController)
#include "test_chat_controller.moc"
