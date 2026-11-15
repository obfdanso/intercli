#include "key_vault.h"
#include "../crypto/crypto_utils.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>

#ifdef Q_OS_WIN
#include <windows.h>
#include <dpapi.h>
#endif

namespace Intercli {

namespace {

constexpr int kKeySize = 32;

#ifdef Q_OS_WIN
QByteArray protect(const QByteArray& plain) {
    DATA_BLOB in = {static_cast<DWORD>(plain.size()), reinterpret_cast<BYTE*>(const_cast<char*>(plain.data()))};
    DATA_BLOB out = {};
    if (!CryptProtectData(&in, L"intercli history key", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        return {};
    }
    QByteArray result(reinterpret_cast<const char*>(out.pbData), static_cast<qsizetype>(out.cbData));
    LocalFree(out.pbData);
    return result;
}

QByteArray unprotect(const QByteArray& wrapped) {
    DATA_BLOB in = {static_cast<DWORD>(wrapped.size()), reinterpret_cast<BYTE*>(const_cast<char*>(wrapped.data()))};
    DATA_BLOB out = {};
    if (!CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
        return {};
    }
    QByteArray result(reinterpret_cast<const char*>(out.pbData), static_cast<qsizetype>(out.cbData));
    SecureZeroMemory(out.pbData, out.cbData);
    LocalFree(out.pbData);
    return result;
}
#else
QByteArray protect(const QByteArray& plain) { return plain; }
QByteArray unprotect(const QByteArray& wrapped) { return wrapped; }
#endif

} // namespace

QByteArray loadOrCreateHistoryKey(const QString& keyFilePath) {
    QFile file(keyFilePath);
    if (file.open(QIODevice::ReadOnly)) {
        const QByteArray key = unprotect(file.readAll());
        file.close();
        if (key.size() == kKeySize) {
            return key;
        }
        // Unreadable (another Windows user, or damaged): start a new key. Rows
        // saved under the old one can no longer be read and are skipped.
    }

    SecureComm::CryptoManager crypto;
    const std::vector<uint8_t> raw = crypto.generate_random_bytes(kKeySize);
    const QByteArray key(reinterpret_cast<const char*>(raw.data()), static_cast<qsizetype>(raw.size()));

    QDir().mkpath(QFileInfo(keyFilePath).absolutePath());
    const QByteArray stored = protect(key);
    if (stored.isEmpty()) {
        return key;  // could not wrap it; use it for this run without saving
    }
    // Create the file fresh with owner-only permissions from the start (NewOnly
    // also refuses to follow a planted link), so the key is never readable by others.
    QFile::remove(keyFilePath);
    if (file.open(QIODevice::WriteOnly | QIODevice::NewOnly, QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        if (file.write(stored) != stored.size()) {
            file.close();
            QFile::remove(keyFilePath);
        }
    }
    return key;
}

} // namespace Intercli
