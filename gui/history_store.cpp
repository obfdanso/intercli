#include "history_store.h"
#include "../crypto/crypto_utils.h"

#include <QDir>
#include <QFileInfo>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QVariant>

#include <algorithm>

namespace Intercli {

namespace {

constexpr int kIvSize = 12;

// A null QString binds as SQL NULL; the Everyone conversation must stay "".
QString notNull(const QString& s) {
    return s.isNull() ? QStringLiteral("") : s;
}

// Row format 2 binds a row to its identity and conversation: decrypting it
// anywhere else fails. Format 1 rows (saved before this) have no binding.
constexpr int kBoundRows = 2;

QByteArray rowBinding(const QString& identity, const QString& conversation) {
    QByteArray aad = identity.toUtf8();
    aad.append('\0');
    aad.append(notNull(conversation).toUtf8());
    return aad;
}

} // namespace

QString identityKey(const QString& host, int port, const QString& name) {
    return host.trimmed().toLower() + QLatin1Char(':') + QString::number(port) + QLatin1Char('/') + name;
}

HistoryStore::HistoryStore(const QString& dbPath, const QByteArray& key, const QString& connectionName)
    : path_(dbPath), key_(key), connection_(connectionName),
      crypto_(std::make_unique<SecureComm::CryptoManager>()) {}

HistoryStore::~HistoryStore() {
    if (QSqlDatabase::contains(connection_)) {
        {
            QSqlDatabase db = QSqlDatabase::database(connection_, false);
            db.close();
        }
        QSqlDatabase::removeDatabase(connection_);
    }
}

bool HistoryStore::open(QString* error) {
    if (key_.size() != 32) {
        if (error) *error = QStringLiteral("No usable key for saved messages");
        return false;
    }
    QDir().mkpath(QFileInfo(path_).absolutePath());
    QSqlDatabase db = QSqlDatabase::contains(connection_) ? QSqlDatabase::database(connection_, false)
                                                          : QSqlDatabase::addDatabase("QSQLITE", connection_);
    db.setDatabaseName(path_);
    if (!db.open()) {
        if (error) *error = db.lastError().text();
        return false;
    }
    QSqlQuery q(db);
    const char* statements[] = {
        "PRAGMA journal_mode=WAL",
        // Deleted rows are overwritten, so names and times don't linger in free pages.
        "PRAGMA secure_delete=ON",
        "CREATE TABLE IF NOT EXISTS choices (identity TEXT PRIMARY KEY, choice INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS messages ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " identity TEXT NOT NULL, conversation TEXT NOT NULL, kind INTEGER NOT NULL,"
        " sender TEXT NOT NULL, time INTEGER NOT NULL, blob BLOB NOT NULL)",
        "CREATE INDEX IF NOT EXISTS messages_by_conversation ON messages (identity, conversation, id)",
    };
    for (const char* sql : statements) {
        if (!q.exec(QString::fromLatin1(sql))) {
            if (error) *error = q.lastError().text();
            return false;
        }
    }
    // Databases from before rows were bound get the row format column (old rows are format 1).
    bool hasFormat = false;
    if (q.exec("PRAGMA table_info(messages)")) {
        while (q.next()) {
            hasFormat = hasFormat || q.value(1).toString() == QStringLiteral("v");
        }
    }
    if (!hasFormat && !q.exec("ALTER TABLE messages ADD COLUMN v INTEGER NOT NULL DEFAULT 1")) {
        if (error) *error = q.lastError().text();
        return false;
    }
    open_ = true;
    return true;
}

HistoryChoice HistoryStore::choice(const QString& identity) const {
    if (!open_) return HistoryChoice::Unasked;
    QSqlQuery q(QSqlDatabase::database(connection_));
    q.prepare("SELECT choice FROM choices WHERE identity = ?");
    q.addBindValue(identity);
    if (q.exec() && q.next()) {
        const int v = q.value(0).toInt();
        if (v == 1) return HistoryChoice::Save;
        if (v == 2) return HistoryChoice::DontSave;
    }
    return HistoryChoice::Unasked;
}

void HistoryStore::setChoice(const QString& identity, HistoryChoice choice) {
    if (!open_) return;
    QSqlQuery q(QSqlDatabase::database(connection_));
    q.prepare("INSERT INTO choices (identity, choice) VALUES (?, ?) "
              "ON CONFLICT(identity) DO UPDATE SET choice = excluded.choice");
    q.addBindValue(identity);
    q.addBindValue(static_cast<int>(choice));
    q.exec();
}

QByteArray HistoryStore::encrypt(const QString& text, const QByteArray& aad) const {
    const QByteArray utf8 = text.toUtf8();
    const std::vector<uint8_t> iv = crypto_->generate_random_bytes(kIvSize);
    const std::vector<uint8_t> key(key_.begin(), key_.end());
    const std::vector<uint8_t> plain(utf8.begin(), utf8.end());
    const std::vector<uint8_t> sealed =
        crypto_->encrypt_aes_gcm(plain, key, iv, std::vector<uint8_t>(aad.begin(), aad.end()));
    QByteArray blob(reinterpret_cast<const char*>(iv.data()), static_cast<qsizetype>(iv.size()));
    blob.append(reinterpret_cast<const char*>(sealed.data()), static_cast<qsizetype>(sealed.size()));
    return blob;
}

bool HistoryStore::decrypt(const QByteArray& blob, const QByteArray& aad, QString* text) const {
    if (blob.size() <= kIvSize) {
        return false;
    }
    try {
        const std::vector<uint8_t> iv(blob.begin(), blob.begin() + kIvSize);
        const std::vector<uint8_t> sealed(blob.begin() + kIvSize, blob.end());
        const std::vector<uint8_t> key(key_.begin(), key_.end());
        const std::vector<uint8_t> plain =
            crypto_->decrypt_aes_gcm(sealed, key, iv, std::vector<uint8_t>(aad.begin(), aad.end()));
        *text = QString::fromUtf8(reinterpret_cast<const char*>(plain.data()), static_cast<qsizetype>(plain.size()));
        return true;
    } catch (const std::exception&) {
        return false;  // wrong key or tampered row
    }
}

qint64 HistoryStore::append(const QString& identity, const StoredMessage& message) {
    if (!open_ || choice(identity) != HistoryChoice::Save) {
        return 0;
    }
    QSqlQuery q(QSqlDatabase::database(connection_));
    q.prepare("INSERT INTO messages (identity, conversation, kind, sender, time, blob, v) VALUES (?, ?, ?, ?, ?, ?, ?)");
    q.addBindValue(identity);
    q.addBindValue(notNull(message.conversation));
    q.addBindValue(message.kind);
    q.addBindValue(notNull(message.sender));
    q.addBindValue(message.time.toMSecsSinceEpoch());
    q.addBindValue(encrypt(message.text, rowBinding(identity, message.conversation)));
    q.addBindValue(kBoundRows);
    if (!q.exec()) {
        return 0;
    }
    return q.lastInsertId().toLongLong();
}

QList<StoredMessage> HistoryStore::loadPage(const QString& identity, const QString& conversation, int limit,
                                            qint64 beforeId) const {
    QList<StoredMessage> page;
    if (!open_) return page;
    QSqlQuery q(QSqlDatabase::database(connection_));
    q.prepare("SELECT id, kind, sender, time, blob, v FROM messages "
              "WHERE identity = ? AND conversation = ? AND (? = 0 OR id < ?) "
              "ORDER BY id DESC LIMIT ?");
    q.addBindValue(identity);
    q.addBindValue(notNull(conversation));
    q.addBindValue(beforeId);
    q.addBindValue(beforeId);
    q.addBindValue(limit);
    if (!q.exec()) return page;
    while (q.next()) {
        StoredMessage m;
        const QByteArray aad = q.value(5).toInt() >= kBoundRows ? rowBinding(identity, conversation) : QByteArray();
        if (!decrypt(q.value(4).toByteArray(), aad, &m.text)) {
            continue;
        }
        m.id = q.value(0).toLongLong();
        m.conversation = notNull(conversation);
        m.kind = q.value(1).toInt();
        m.sender = q.value(2).toString();
        m.time = QDateTime::fromMSecsSinceEpoch(q.value(3).toLongLong());
        page.append(m);
    }
    std::reverse(page.begin(), page.end());
    return page;
}

QList<ConversationSummary> HistoryStore::conversations(const QString& identity) const {
    QList<ConversationSummary> list;
    if (!open_) return list;
    QSqlQuery q(QSqlDatabase::database(connection_));
    // The latest chat message (not a join/leave line) of each conversation.
    q.prepare("SELECT m.conversation, m.sender, m.kind, m.time, m.blob, m.v FROM messages m "
              "JOIN (SELECT conversation, MAX(id) AS last FROM messages "
              "      WHERE identity = ? AND kind != 2 GROUP BY conversation) t ON m.id = t.last "
              "ORDER BY m.id DESC");
    q.addBindValue(identity);
    if (!q.exec()) return list;
    while (q.next()) {
        ConversationSummary c;
        c.conversation = notNull(q.value(0).toString());
        c.lastSender = q.value(1).toString();
        c.lastKind = q.value(2).toInt();
        c.lastTime = QDateTime::fromMSecsSinceEpoch(q.value(3).toLongLong());
        const QByteArray aad = q.value(5).toInt() >= kBoundRows ? rowBinding(identity, c.conversation) : QByteArray();
        decrypt(q.value(4).toByteArray(), aad, &c.lastText);
        list.append(c);
    }
    return list;
}

void HistoryStore::deleteAll(const QString& identity) {
    if (!open_) return;
    QSqlQuery q(QSqlDatabase::database(connection_));
    q.prepare("DELETE FROM messages WHERE identity = ?");
    q.addBindValue(identity);
    q.exec();
    // Copy the deletion into the database file and empty the write-ahead log,
    // which would otherwise still hold the old rows.
    q.exec("PRAGMA wal_checkpoint(TRUNCATE)");
}

int HistoryStore::totalMessageRowsForTest() const {
    if (!open_) return -1;
    QSqlQuery q(QSqlDatabase::database(connection_));
    if (q.exec("SELECT COUNT(*) FROM messages") && q.next()) {
        return q.value(0).toInt();
    }
    return -1;
}

} // namespace Intercli
