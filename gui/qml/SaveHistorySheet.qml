import QtQuick
import QtQuick.Effects
import Intercli.Backend

// Asked once per name and server: save messages on this computer or not.
Item {
    id: root
    readonly property bool shown: Chat.historyAvailable && Chat.state === Chat.Online && Chat.historyChoice === 0

    visible: opacity > 0
    opacity: shown ? 1 : 0
    Behavior on opacity { NumberAnimation { duration: Theme.animNormal; easing.type: Easing.OutCubic } }

    // Dim everything behind and swallow clicks.
    Rectangle {
        anchors.fill: parent
        color: Qt.rgba(0, 0, 0, 0.45)
        MouseArea { anchors.fill: parent }
    }

    Rectangle {
        id: card
        anchors.centerIn: parent
        anchors.verticalCenterOffset: root.shown ? 0 : 12
        Behavior on anchors.verticalCenterOffset { NumberAnimation { duration: Theme.animNormal; easing.type: Easing.OutCubic } }
        width: 380
        height: content.implicitHeight + 48
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
            id: content
            x: 24
            y: 24
            width: parent.width - 48
            spacing: 0

            Text {
                // Peer and server text is shown as typed, never as markup.
                textFormat: Text.PlainText
                width: parent.width
                text: "Save your messages on this computer?"
                color: Theme.text
                font.pixelSize: 16
                font.weight: Font.DemiBold
                wrapMode: Text.Wrap
            }
            Text {
                // Peer and server text is shown as typed, never as markup.
                textFormat: Text.PlainText
                width: parent.width
                topPadding: 8
                text: "If you save them, your chats with this name on this server come back next time you sign in. They're encrypted with a key tied to your Windows account."
                color: Theme.textSecondary
                font.pixelSize: 13
                wrapMode: Text.Wrap
                lineHeight: 1.15
            }

            Item { width: 1; height: 22 }

            Row {
                anchors.right: parent.right
                spacing: 10

                Rectangle {
                    width: dontText.implicitWidth + 32
                    height: 34
                    radius: 8
                    color: dontMouse.containsMouse ? Theme.raised2 : Qt.rgba(1, 1, 1, 0.06)
                    Accessible.role: Accessible.Button
                    Accessible.name: "Don't Save"
                    Accessible.onPressAction: Chat.setHistoryChoice(2, false)
                    Text {
                        // Peer and server text is shown as typed, never as markup.
                        textFormat: Text.PlainText
                        id: dontText
                        anchors.centerIn: parent
                        text: "Don't Save"
                        color: Theme.text
                        font.pixelSize: 13
                        font.weight: Font.Medium
                    }
                    MouseArea {
                        id: dontMouse
                        anchors.fill: parent
                        hoverEnabled: true
                        onClicked: Chat.setHistoryChoice(2, false)
                    }
                }

                PrimaryButton {
                    text: "Save Messages"
                    implicitWidth: 140
                    height: 34
                    Accessible.name: "Save Messages"
                    onClicked: Chat.setHistoryChoice(1, false)
                }
            }
        }
    }
}
