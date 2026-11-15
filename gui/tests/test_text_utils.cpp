#include "text_utils.h"
#include <QtTest>

using namespace Intercli;

class TestTextUtils : public QObject {
    Q_OBJECT
private slots:
    void utf8_length_counts_bytes() {
        QCOMPARE(utf8Length(QStringLiteral("abc")), 3);
        QCOMPARE(utf8Length(QString::fromUtf8("\xC3\xA9")), 2);          // é
        QCOMPARE(utf8Length(QString::fromUtf8("\xF0\x9F\x91\x8B")), 4);  // 👋
    }

    void truncate_never_splits_a_character() {
        QCOMPARE(truncateToBytes(QString::fromUtf8("a\xC3\xA9"), 2), QStringLiteral("a"));
        const QString base(1023, QLatin1Char('a'));
        QCOMPARE(truncateToBytes(base + QString::fromUtf8("\xF0\x9F\x91\x8B"), 1024), base);
        QCOMPARE(truncateToBytes(QStringLiteral("short"), 1024), QStringLiteral("short"));
    }

    void name_rules_match_the_server() {
        QVERIFY(isValidName(QStringLiteral("bob")));
        QVERIFY(!isValidName(QStringLiteral("a b")));
        QVERIFY(!isValidName(QString()));
        QVERIFY(!isValidName(QString(32, QLatin1Char('x'))));
        QVERIFY(isValidName(QString(31, QLatin1Char('x'))));
        QVERIFY(!isValidName(QString::fromUtf8("caf\xC3\xA9")));
    }

    void avatar_colors_are_stable() {
        QCOMPARE(avatarColors(QStringLiteral("alice")), avatarColors(QStringLiteral("alice")));
        QVERIFY(avatarColors(QStringLiteral("alice")).first.isValid());
    }

    void initials() {
        QCOMPARE(initialFor(QStringLiteral("alice")), QStringLiteral("A"));
        QCOMPARE(initialFor(QString()), QString::fromUtf8("\xE2\x9C\xA6"));  // ✦
    }
};

QTEST_GUILESS_MAIN(TestTextUtils)
#include "test_text_utils.moc"
