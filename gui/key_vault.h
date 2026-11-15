#pragma once

#include <QByteArray>
#include <QString>

namespace Intercli {

// The 32-byte key that encrypts saved message text. Created on first use and
// stored in keyFilePath. On Windows the stored copy is wrapped with DPAPI, so it
// only unwraps for the same Windows user; elsewhere it is stored as-is with
// owner-only permissions.
QByteArray loadOrCreateHistoryKey(const QString& keyFilePath);

} // namespace Intercli
