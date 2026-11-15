pragma Singleton
import QtQuick

// Palette and metrics for the dark, Apple-style look. Every colour and size
// used by the views comes from here.
QtObject {
    readonly property color window: "#1C1C1E"
    readonly property color sidebar: "#26262A"
    readonly property color panel: "#19191B"
    readonly property color raised: "#2C2C2E"
    readonly property color raised2: "#3A3A3C"
    readonly property color separator: Qt.rgba(1, 1, 1, 0.08)
    readonly property color hover: Qt.rgba(1, 1, 1, 0.05)
    readonly property color fieldFill: Qt.rgba(1, 1, 1, 0.07)
    readonly property color text: "#F5F5F7"
    readonly property color textSecondary: "#A1A1A6"
    readonly property color textTertiary: "#6E6E73"
    readonly property color accent: "#0A84FF"
    readonly property color online: "#30D158"
    readonly property color danger: "#FF453A"
    readonly property color closeHover: "#C42B1C"

    readonly property string fontFamily: Qt.application.font.family
    readonly property string iconFont: "Segoe Fluent Icons"

    readonly property int radiusBubble: 18
    readonly property int radiusCard: 10
    readonly property int titleBarHeight: 32
    readonly property int sidebarWidth: 250
    readonly property int detailsWidth: 240

    readonly property int animFast: 150
    readonly property int animNormal: 220
}
