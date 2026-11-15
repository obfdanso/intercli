#include "text_utils.h"
#include "common.h"

#include <QByteArray>
#include <array>

namespace Intercli {

int utf8Length(const QString& text) {
    return static_cast<int>(text.toUtf8().size());
}

QString truncateToBytes(const QString& text, int maxBytes) {
    int bytes = 0;
    int end = 0;
    while (end < text.size()) {
        const bool pair = text.at(end).isHighSurrogate() && end + 1 < text.size() &&
                          text.at(end + 1).isLowSurrogate();
        const char32_t code = pair ? QChar::surrogateToUcs4(text.at(end), text.at(end + 1))
                                   : text.at(end).unicode();
        const int width = code < 0x80 ? 1 : code < 0x800 ? 2 : code < 0x10000 ? 3 : 4;
        if (bytes + width > maxBytes) {
            break;
        }
        bytes += width;
        end += pair ? 2 : 1;
    }
    return text.left(end);
}

bool isValidName(const QString& name) {
    return SecureComm::is_valid_name(name.toUtf8().toStdString());
}

QPair<QColor, QColor> avatarColors(const QString& name) {
    static const std::array<QPair<QColor, QColor>, 6> pairs = {{
        {QColor("#FF9F0A"), QColor("#FF375F")},  // orange to pink
        {QColor("#64D2FF"), QColor("#0A84FF")},  // cyan to blue
        {QColor("#30D158"), QColor("#0C9F8A")},  // green to teal
        {QColor("#BF5AF2"), QColor("#5E5CE6")},  // purple to indigo
        {QColor("#5E5CE6"), QColor("#0A84FF")},  // indigo to blue
        {QColor("#FFD60A"), QColor("#FF9F0A")},  // yellow to orange
    }};
    if (name.isEmpty()) {
        return pairs[4];
    }
    // FNV-1a, so a name gets the same colour on every run and every machine.
    quint32 hash = 2166136261u;
    for (const char c : name.toUtf8()) {
        hash ^= static_cast<quint8>(c);
        hash *= 16777619u;
    }
    return pairs[hash % pairs.size()];
}

QString initialFor(const QString& name) {
    if (name.isEmpty()) {
        return QString(QChar(0x2726));
    }
    return name.left(1).toUpper();
}

} // namespace Intercli
