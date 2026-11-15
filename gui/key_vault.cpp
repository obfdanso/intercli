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
    if (!CryptProtectData(&in, L"intercli secret", nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out)) {
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

namespace {

// Reads and unwraps an existing secret file. Empty if it can't be used.
QByteArray readSecret(const QString& path, int size) {
    QFile file(path);
    if (!file.open(QIODevice::ReadOnly)) {
        return {};
    }
    const QByteArray secret = unprotect(file.readAll());
    return secret.size() == size ? secret : QByteArray();
}

} // namespace

QByteArray loadOrCreateHistoryKey(const QString& keyFilePath) {
    return loadOrCreateSecret(keyFilePath, kKeySize);
}

QByteArray loadOrCreateSecret(const QString& keyFilePath, int size) {
    // An existing key is never replaced, even if it can't be read right now
    // (another Windows user, a damaged file): everything saved under it would
    // be lost. The caller switches saving off instead.
    if (QFileInfo::exists(keyFilePath)) {
        return readSecret(keyFilePath, size);
    }

    SecureComm::CryptoManager crypto;
    const std::vector<uint8_t> raw = crypto.generate_random_bytes(static_cast<size_t>(size));
    const QByteArray key(reinterpret_cast<const char*>(raw.data()), static_cast<qsizetype>(raw.size()));
    const QByteArray stored = protect(key);
    if (stored.isEmpty()) {
        return {};  // a key that can't be kept would lose this session's history
    }

    QDir().mkpath(QFileInfo(keyFilePath).absolutePath());
    // Owner-only from the moment it exists; NewOnly also refuses a planted link
    // and loses cleanly to another instance creating the file at the same time.
    QFile file(keyFilePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::NewOnly, QFileDevice::ReadOwner | QFileDevice::WriteOwner)) {
        return readSecret(keyFilePath, size);  // someone else just created it: use theirs
    }
    if (file.write(stored) != stored.size() || !file.flush()) {
        file.close();
        QFile::remove(keyFilePath);
        return {};
    }
    return key;
}

} // namespace Intercli
