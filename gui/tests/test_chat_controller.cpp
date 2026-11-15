// Drives ChatController against a real server (started by run_with_server.sh),
// with a plain ChatClient playing "alice" on the other side.

#include "chat_client.h"
#include "chat_controller.h"
#include "conversation_list_model.h"
#include "message_model.h"

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
        QVERIFY(!other.connectError().isEmpty());
        QVERIFY(other.nameError().isEmpty());
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
        QCOMPARE(bob->session().value("serverIdentity").toString(), QStringLiteral("Not verified"));
        bob->rotateKey();
        QTRY_COMPARE_WITH_TIMEOUT(bob->session().value("sendRotations").toInt(), before + 2, kWait);
        QTRY_COMPARE_WITH_TIMEOUT(lastText(bob->messages()), QStringLiteral("Your send key rotated"), kWait);
    }

    void connection_loss_reconnects() {
        const int everyoneRows = bob->messages()->count();
        bob->simulateConnectionLoss();
        QTRY_COMPARE_WITH_TIMEOUT(bob->state(), ChatController::Disconnected, kWait);
        QVERIFY(!bob->disconnectReason().isEmpty());
        QVERIFY(!bob->send("while offline"));

        bob->reconnect();
        QTRY_COMPARE_WITH_TIMEOUT(bob->state(), ChatController::Online, kWait);
        QCOMPARE(bob->myName(), QStringLiteral("bob"));
        bob->setCurrentConversation(QString());
        QVERIFY(bob->messages()->count() >= everyoneRows);
        QVERIFY(bob->send("back"));
        QTRY_VERIFY_WITH_TIMEOUT(alice->has("broadcast:bob:back"), kWait);
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
