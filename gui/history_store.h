#pragma once

#include <QByteArray>
#include <QDateTime>
#include <QList>
#include <QString>

#include <memory>

namespace SecureComm {
class CryptoManager;
}

namespace Intercli {

// "host:port/name" with the host lower-cased: one saved history per identity.
QString identityKey(const QString& host, int port, const QString& name);

enum class HistoryChoice { Unasked = 0, Save = 1, DontSave = 2 };

struct StoredMessage {
    qint64 id = 0;
    QString conversation;   // "" is Everyone
    int kind = 0;           // MessageModel::Kind
    QString sender;
    QString text;
    QDateTime time;
};

struct ConversationSummary {
    QString conversation;
    QString lastSender;
    QString lastText;
    QDateTime lastTime;
    int lastKind = 0;
};

// Saved messages in SQLite. Message text is encrypted with AES-256-GCM under the
// key from loadOrCreateHistoryKey; names and times are stored in the clear so
// they can be queried. Nothing is written for an identity unless its choice is Save.
class HistoryStore {
public:
    HistoryStore(const QString& dbPath, const QByteArray& key,
                 const QString& connectionName = QStringLiteral("history"));
    ~HistoryStore();

    HistoryStore(const HistoryStore&) = delete;
    HistoryStore& operator=(const HistoryStore&) = delete;

    bool open(QString* error);

    HistoryChoice choice(const QString& identity) const;
    void setChoice(const QString& identity, HistoryChoice choice);

    // Returns the new row id, or 0 when nothing was saved.
    qint64 append(const QString& identity, const StoredMessage& message);

    // The newest `limit` messages older than beforeId (0 = newest), oldest first.
    // Rows that cannot be decrypted are skipped.
    QList<StoredMessage> loadPage(const QString& identity, const QString& conversation, int limit,
                                  qint64 beforeId = 0) const;

    QList<ConversationSummary> conversations(const QString& identity) const;
    void deleteAll(const QString& identity);

    // Test only: number of message rows across every identity.
    int totalMessageRowsForTest() const;

private:
    QByteArray encrypt(const QString& text) const;
    bool decrypt(const QByteArray& blob, QString* text) const;

    QString path_;
    QByteArray key_;
    QString connection_;
    bool open_ = false;
    std::unique_ptr<SecureComm::CryptoManager> crypto_;
};

} // namespace Intercli
