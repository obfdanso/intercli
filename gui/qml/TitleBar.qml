import QtQuick
import Intercli.Backend

// The custom title bar: app name on the left, caption buttons on the right.
// Everything else in it drags the window (Frame does the hit-testing).
Item {
    id: root
    height: Theme.titleBarHeight

    function reportRects() {
        if (!Frame.customFrame)
            return
        const b = Theme.titleBarHeight
        const right = width
        Frame.setCaptionRects(Qt.rect(0, 0, right - 3 * 46, b),
                              Qt.rect(right - 3 * 46, 0, 46, b),
                              Qt.rect(right - 2 * 46, 0, 46, b),
                              Qt.rect(right - 46, 0, 46, b))
    }
    onWidthChanged: reportRects()
    Component.onCompleted: reportRects()

    Row {
        x: 14
        anchors.verticalCenter: parent.verticalCenter
        spacing: 8
        visible: Frame.customFrame

        Text {
            text: "◆"
            color: Theme.accent
            font.pixelSize: 11
            anchors.verticalCenter: parent.verticalCenter
        }
        Text {
            text: "intercli"
            color: Theme.textSecondary
            font.pixelSize: 12
            anchors.verticalCenter: parent.verticalCenter
        }
    }

    Row {
        anchors.right: parent.right
        anchors.top: parent.top
        visible: Frame.customFrame

        CaptionButton {
            glyph: ""
            onClicked: Frame.minimize()
        }
        CaptionButton {
            glyph: Frame.maximized ? "" : ""
            externalHover: Frame.maxHovered
            externalPressed: Frame.maxPressed
            onClicked: Frame.toggleMaximize()
        }
        CaptionButton {
            glyph: ""
            isClose: true
            onClicked: Frame.close()
        }
    }
}
