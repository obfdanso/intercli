#include "history_store.h"
#include "key_vault.h"
#include "../crypto/crypto_utils.h"

#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>

#include <QDir>
#include <QFile>
#include <QTemporaryDir>
#include <QtTest>

using namespace Intercli;

namespace {

const QString kBob = QStringLiteral("127.0.0.1:8080/bob");
const QString kAlice = QStringLiteral("127.0.0.1:8080/alice");
const QString kOtherServer = QStringLiteral("localhost:9000/bob");

StoredMessage msg(const QString& conversation, const QString& text, int minute = 0) {
    StoredMessage m;
    m.conversation = conversation;
    m.kind = 0;
    m.sender = QStringLiteral("alice");
    m.text = text;
    m.time = QDateTime(QDate(2026, 11, 15), QTime(9, minute));
    return m;
}

int messageRows(const QString& dbPath) {
    // Count rows with a separate connection, so the check doesn't trust the store.
    HistoryStore probe(dbPath, QByteArray(32, 'x'), QStringLiteral("probe"));
    QString err;
    probe.open(&err);
    return probe.totalMessageRowsForTest();
}

QByteArray fileBytes(const QString& path) {
    QFile f(path);
    return f.open(QIODevice::ReadOnly) ? f.readAll() : QByteArray();
}

} // namespace

class TestHistoryStore : public QObject {
    Q_OBJECT

    QTemporaryDir dir;
    QString dbPath() const { return dir.filePath("history.db"); }
    QByteArray key = QByteArray(32, '\x07');

private slots:
    void identity_key_format() {
        QCOMPARE(identityKey("LocalHost", 9000, "bob"), QStringLiteral("localhost:9000/bob"));
    }

    void choice_defaults_to_unasked_and_persists() {
        HistoryStore s(dbPath(), key, "c1");
        QString err;
        QVERIFY2(s.open(&err), qPrintable(err));
        QCOMPARE(s.choice(kBob), HistoryChoice::Unasked);
        s.setChoice(kBob, HistoryChoice::Save);
        QCOMPARE(s.choice(kBob), HistoryChoice::Save);
        QCOMPARE(s.choice(kAlice), HistoryChoice::Unasked);
    }

    void unasked_and_dont_save_write_nothing() {
        QTemporaryDir d;
        const QString path = d.filePath("h.db");
        {
            HistoryStore s(path, key, "c2");
            QString err;
            QVERIFY(s.open(&err));
            QCOMPARE(s.append(kAlice, msg("bob", "x")), qint64(0));
            s.setChoice(kAlice, HistoryChoice::DontSave);
            QCOMPARE(s.append(kAlice, msg("bob", "y")), qint64(0));
        }
        QCOMPARE(messageRows(path), 0);
    }

    void round_trip_and_paging() {
        HistoryStore s(dbPath(), key, "c3");
        QString err;
        QVERIFY(s.open(&err));
        s.setChoice(kBob, HistoryChoice::Save);
        const qint64 a = s.append(kBob, msg("alice", "one", 1));
        const qint64 b = s.append(kBob, msg("alice", "two", 2));
        const qint64 c = s.append(kBob, msg("alice", "three", 3));
        QVERIFY(a > 0 && b > a && c > b);

        const auto newest = s.loadPage(kBob, "alice", 2);
        QCOMPARE(newest.size(), 2);
        QCOMPARE(newest.at(0).text, QStringLiteral("two"));
        QCOMPARE(newest.at(1).text, QStringLiteral("three"));
        QCOMPARE(newest.at(0).id, b);
        QCOMPARE(newest.at(1).time, QDateTime(QDate(2026, 11, 15), QTime(9, 3)));
        QCOMPARE(newest.at(1).sender, QStringLiteral("alice"));

        const auto older = s.loadPage(kBob, "alice", 2, b);
        QCOMPARE(older.size(), 1);
        QCOMPARE(older.at(0).text, QStringLiteral("one"));
    }

    void conversations_summary() {
        HistoryStore s(dbPath(), key, "c4");
        QString err;
        QVERIFY(s.open(&err));
        s.append(kBob, msg("", "to everyone", 5));
        const auto list = s.conversations(kBob);
        QStringList ids;
        for (const auto& c : list) ids << c.conversation;
        QVERIFY(ids.contains("alice"));
        QVERIFY(ids.contains(""));
        for (const auto& c : list) {
            if (c.conversation == "alice") QCOMPARE(c.lastText, QStringLiteral("three"));
        }
    }

    void identities_are_kept_apart() {
        HistoryStore s(dbPath(), key, "c5");
        QString err;
        QVERIFY(s.open(&err));
        s.setChoice(kOtherServer, HistoryChoice::Save);
        s.append(kOtherServer, msg("carol", "elsewhere"));
        QVERIFY(s.loadPage(kAlice, "alice", 50).isEmpty());
        QVERIFY(s.conversations(kAlice).isEmpty());
        QVERIFY(s.loadPage(kBob, "carol", 50).isEmpty());
        QCOMPARE(s.loadPage(kOtherServer, "carol", 50).size(), 1);
    }

    void delete_all_removes_one_identity() {
        HistoryStore s(dbPath(), key, "c6");
        QString err;
        QVERIFY(s.open(&err));
        s.deleteAll(kOtherServer);
        QVERIFY(s.loadPage(kOtherServer, "carol", 50).isEmpty());
        QCOMPARE(s.loadPage(kBob, "alice", 50).size(), 3);
    }

    void text_is_not_readable_in_the_file() {
        {
            HistoryStore s(dbPath(), key, "c7");
            QString err;
            QVERIFY(s.open(&err));
            s.append(kBob, msg("alice", "zebra-secret-123"));
        }
        QByteArray all = fileBytes(dbPath()) + fileBytes(dbPath() + "-wal");
        QVERIFY(!all.contains("zebra-secret-123"));
    }

    void reopen_reads_back_and_wrong_key_is_harmless() {
        {
            HistoryStore s(dbPath(), key, "c8");
            QString err;
            QVERIFY(s.open(&err));
            const auto page = s.loadPage(kBob, "alice", 50);
            QCOMPARE(page.last().text, QStringLiteral("zebra-secret-123"));
        }
        HistoryStore wrong(dbPath(), QByteArray(32, '\x09'), "c9");
        QString err;
        QVERIFY(wrong.open(&err));
        const auto page = wrong.loadPage(kBob, "alice", 50);
        for (const auto& m : page) {
            QVERIFY(m.text != QStringLiteral("zebra-secret-123"));
        }
    }

    void damaged_key_file_is_left_alone() {
        // An unreadable key must never be silently replaced: everything saved
        // under it would be lost. Saving is switched off instead.
        QTemporaryDir d;
        const QString path = d.filePath("history.key");
        {
            QFile f(path);
            QVERIFY(f.open(QIODevice::WriteOnly));
            f.write("not a wrapped key");
        }
        QVERIFY(loadOrCreateHistoryKey(path).isEmpty());
        QCOMPARE(fileBytes(path), QByteArray("not a wrapped key"));
    }

    void delete_leaves_no_names_in_the_file() {
        QTemporaryDir d;
        const QString path = d.filePath("h.db");
        {
            HistoryStore s(path, key, "c10");
            QString err;
            QVERIFY(s.open(&err));
            s.setChoice(kBob, HistoryChoice::Save);
            StoredMessage m = msg("zebrapartner", "x");
            m.sender = QStringLiteral("zebrasender");
            s.append(kBob, m);
            s.deleteAll(kBob);
        }
        const QByteArray all = fileBytes(path) + fileBytes(path + "-wal");
        QVERIFY(!all.contains("zebrapartner"));
        QVERIFY(!all.contains("zebrasender"));
    }

    // A saved row only decrypts under the identity and conversation it was
    // saved for, so rows can't be moved between people's histories.
    void rows_are_bound_to_their_identity() {
        QTemporaryDir d;
        const QString path = d.filePath("bound.db");
        HistoryStore s(path, key, "c11");
        QString err;
        QVERIFY(s.open(&err));
        s.setChoice(kBob, HistoryChoice::Save);
        s.setChoice(kAlice, HistoryChoice::Save);
        const qint64 id = s.append(kBob, msg("carol", "for bob only"));
        QVERIFY(id > 0);
        QSqlQuery q(QSqlDatabase::database("c11"));
        q.prepare("UPDATE messages SET identity = ? WHERE id = ?");
        q.addBindValue(kAlice);
        q.addBindValue(id);
        QVERIFY(q.exec());
        QVERIFY(s.loadPage(kAlice, "carol", 50).isEmpty());

        q.prepare("UPDATE messages SET identity = ?, conversation = ? WHERE id = ?");
        q.addBindValue(kBob);
        q.addBindValue(QStringLiteral("dave"));
        q.addBindValue(id);
        QVERIFY(q.exec());
        QVERIFY(s.loadPage(kBob, "dave", 50).isEmpty());
    }

    // Rows saved before rows were bound (version 1) still load.
    void older_rows_still_load() {
        QTemporaryDir d;
        const QString path = d.filePath("old.db");
        HistoryStore s(path, key, "c12");
        QString err;
        QVERIFY(s.open(&err));
        SecureComm::CryptoManager crypto;
        const std::string text = "saved long ago";
        const std::vector<uint8_t> k(key.begin(), key.end());
        const std::vector<uint8_t> iv = crypto.generate_random_bytes(12);
        std::vector<uint8_t> sealed = crypto.encrypt_aes_gcm(std::vector<uint8_t>(text.begin(), text.end()), k, iv);
        QByteArray blob(reinterpret_cast<const char*>(iv.data()), 12);
        blob.append(reinterpret_cast<const char*>(sealed.data()), static_cast<qsizetype>(sealed.size()));
        QSqlQuery q(QSqlDatabase::database("c12"));
        q.prepare("INSERT INTO messages (identity, conversation, kind, sender, time, blob, v) VALUES (?, ?, 0, ?, ?, ?, 1)");
        q.addBindValue(kBob);
        q.addBindValue(QStringLiteral("carol"));
        q.addBindValue(QStringLiteral("carol"));
        q.addBindValue(QDateTime::currentDateTime().toMSecsSinceEpoch());
        q.addBindValue(blob);
        QVERIFY2(q.exec(), qPrintable(q.lastError().text()));
        const auto page = s.loadPage(kBob, "carol", 50);
        QCOMPARE(page.size(), 1);
        QCOMPARE(page.first().text, QStringLiteral("saved long ago"));
    }

    void key_file_is_stable_and_wrapped() {
        QTemporaryDir d;
        const QString path = d.filePath("history.key");
        const QByteArray k1 = loadOrCreateHistoryKey(path);
        const QByteArray k2 = loadOrCreateHistoryKey(path);
        QCOMPARE(k1.size(), 32);
        QCOMPARE(k1, k2);
#ifdef Q_OS_WIN
        QVERIFY(!fileBytes(path).contains(k1));
#endif
    }
};

QTEST_GUILESS_MAIN(TestHistoryStore)
#include "test_history_store.moc"
