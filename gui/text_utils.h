#pragma once

#include <QColor>
#include <QPair>
#include <QString>

namespace Intercli {

// Size of the text on the wire, which is what the server's 1024-byte limit counts.
int utf8Length(const QString& text);

// Longest prefix of text that fits in maxBytes of UTF-8 without splitting a character.
QString truncateToBytes(const QString& text, int maxBytes);

// Same rule the server applies (SecureComm::is_valid_name).
bool isValidName(const QString& name);

// Stable gradient (top, bottom) for a person's avatar.
QPair<QColor, QColor> avatarColors(const QString& name);

// Letter shown in an avatar; the Everyone conversation ("") gets a sparkle.
QString initialFor(const QString& name);

} // namespace Intercli
