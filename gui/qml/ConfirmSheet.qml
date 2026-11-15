import QtQuick
import QtQuick.Effects

// A small question over a dimmed window: Cancel or a red confirm button.
Item {
    id: root
    property string title
    property string message
    property string confirmText: "OK"
    signal confirmed()
    signal cancelled()

    function open() { shown = true; keys.forceActiveFocus() }
    property bool shown: false

    Item {
        id: keys
        focus: root.shown
        Keys.onEscapePressed: { root.shown = false; root.cancelled() }
        Keys.onReturnPressed: { root.shown = false; root.confirmed() }
        Keys.onEnterPressed: { root.shown = false; root.confirmed() }
    }

    visible: opacity > 0
    opacity: shown ? 1 : 0
    Behavior on opacity { NumberAnimation { duration: Theme.animNormal; easing.type: Easing.OutCubic } }

    Rectangle {
        anchors.fill: parent
        color: Qt.rgba(0, 0, 0, 0.45)
        MouseArea { anchors.fill: parent }
    }

    Rectangle {
        anchors.centerIn: parent
        width: 340
        height: column.implicitHeight + 44
        radius: 14
        color: Theme.raised
        border.color: Qt.rgba(1, 1, 1, 0.08)
        layer.enabled: true
        layer.effect: MultiEffect {
            shadowEnabled: true
            shadowColor: "black"
            shadowOpacity: 0.6
            shadowBlur: 1.0
            shadowVerticalOffset: 12
        }

        Column {
            id: column
            x: 22
            y: 22
            width: parent.width - 44
            spacing: 8
            Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.title
                color: Theme.text
                font.pixelSize: 16
                font.weight: Font.DemiBold
                wrapMode: Text.Wrap
            }
            Text {
                textFormat: Text.PlainText
                width: parent.width
                text: root.message
                color: Theme.textSecondary
                font.pixelSize: 13
                wrapMode: Text.Wrap
            }
            Item { width: 1; height: 8 }
            Row {
                anchors.right: parent.right
                spacing: 10
                Rectangle {
                    width: cancelText.implicitWidth + 30
                    height: 34
                    radius: 8
                    color: cancelMouse.containsMouse ? Theme.raised2 : Qt.rgba(1, 1, 1, 0.06)
                    Accessible.role: Accessible.Button
                    Accessible.name: "Cancel"
                    Accessible.onPressAction: { root.shown = false; root.cancelled() }
                    Text {
                        id: cancelText
                        textFormat: Text.PlainText
                        anchors.centerIn: parent
                        text: "Cancel"
                        color: Theme.text
                        font.pixelSize: 13
                    }
                    MouseArea {
                        id: cancelMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        onClicked: { root.shown = false; root.cancelled() }
                    }
                }
                Rectangle {
                    width: confirmLabel.implicitWidth + 30
                    height: 34
                    radius: 8
                    color: confirmMouse.containsMouse ? Qt.lighter(Theme.danger, 1.1) : Theme.danger
                    Accessible.role: Accessible.Button
                    Accessible.name: root.confirmText
                    Accessible.onPressAction: { root.shown = false; root.confirmed() }
                    Text {
                        id: confirmLabel
                        textFormat: Text.PlainText
                        anchors.centerIn: parent
                        text: root.confirmText
                        color: "white"
                        font.pixelSize: 13
                        font.weight: Font.DemiBold
                    }
                    MouseArea {
                        id: confirmMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        onClicked: { root.shown = false; root.confirmed() }
                    }
                }
            }
        }
    }
}
