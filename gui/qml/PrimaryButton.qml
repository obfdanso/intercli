import QtQuick
import QtQuick.Controls

// Accent-filled button; shows a spinner while busy.
Button {
    id: button
    property bool busy: false
    property string busyText: text

    implicitHeight: 36
    hoverEnabled: true

    contentItem: Item {
        implicitWidth: row.implicitWidth
        implicitHeight: row.implicitHeight
        Row {
            id: row
            spacing: 8
            anchors.centerIn: parent
            Spinner {
                visible: button.busy
                anchors.verticalCenter: parent.verticalCenter
            }
            Text {
                // Peer and server text is shown as typed, never as markup.
                textFormat: Text.PlainText
                text: button.busy ? button.busyText : button.text
                color: "white"
                opacity: button.enabled || button.busy ? 1 : 0.5
                font.pixelSize: 13
                font.weight: Font.DemiBold
                anchors.verticalCenter: parent.verticalCenter
            }
        }
    }

    background: Rectangle {
        radius: 8
        color: !button.enabled && !button.busy ? Qt.rgba(10 / 255, 132 / 255, 1, 0.35)
             : button.down ? Qt.darker(Theme.accent, 1.15)
             : button.hovered ? Qt.lighter(Theme.accent, 1.08) : Theme.accent
        Behavior on color { ColorAnimation { duration: Theme.animFast } }
    }
}
