import QtQuick
import QtQuick.Controls
import Intercli.Backend
import "Format.js" as Format

// Right column: who you're talking to and the live state of your session.
Rectangle {
    id: panel
    readonly property string peer: Chat.currentConversation
    readonly property bool everyone: peer === ""
    readonly property bool peerOnline: Chat.onlineNames.indexOf(peer) >= 0
    property int tick: 0   // bumps every 30 s so relative times refresh
    property bool confirmStop: false   // asking whether to delete what is saved

    color: Theme.panel

    Rectangle {
        width: 1
        height: parent.height
        color: Theme.separator
    }

    Timer {
        interval: 30000
        repeat: true
        running: panel.visible
        onTriggered: panel.tick++
    }

    component Row2: Item {
        property string label
        property string value
        property bool last: false
        width: parent ? parent.width : 0
        height: 34
        Text {
            // Peer and server text is shown as typed, never as markup.
            textFormat: Text.PlainText
            x: 12
            anchors.verticalCenter: parent.verticalCenter
            text: parent.label
            color: Theme.textSecondary
            font.pixelSize: 12
        }
        Text {
            // Peer and server text is shown as typed, never as markup.
            textFormat: Text.PlainText
            anchors.right: parent.right
            anchors.rightMargin: 12
            anchors.verticalCenter: parent.verticalCenter
            text: parent.value
            color: Theme.text
            font.pixelSize: 12
        }
        Rectangle {
            visible: !parent.last
            x: 12
            anchors.bottom: parent.bottom
            width: parent.width - 12
            height: 1
            color: Theme.separator
        }
    }

    Flickable {
        anchors.fill: parent
        anchors.topMargin: Theme.titleBarHeight
        anchors.bottomMargin: signOut.height + 12
        contentHeight: content.implicitHeight + 24
        clip: true
        boundsBehavior: Flickable.StopAtBounds

        Column {
            id: content
            x: 16
            y: 24
            width: panel.width - 32
            spacing: 0

            Avatar {
                anchors.horizontalCenter: parent.horizontalCenter
                size: 64
                name: panel.peer
            }
            Text {
                // Peer and server text is shown as typed, never as markup.
                textFormat: Text.PlainText
                anchors.horizontalCenter: parent.horizontalCenter
                topPadding: 10
                text: panel.everyone ? "Everyone" : panel.peer
                color: Theme.text
                font.pixelSize: 16
                font.weight: Font.DemiBold
            }
            Text {
                // Peer and server text is shown as typed, never as markup.
                textFormat: Text.PlainText
                anchors.horizontalCenter: parent.horizontalCenter
                topPadding: 3
                text: panel.everyone ? (Chat.onlineCount + 1) + " online"
                    : panel.peerOnline ? "● Online" : "Offline"
                color: !panel.everyone && panel.peerOnline ? Theme.online : Theme.textTertiary
                font.pixelSize: 12
            }

            // Everyone: who is online right now.
            Column {
                visible: panel.everyone
                width: parent.width
                topPadding: 16
                spacing: 6
                Repeater {
                    model: [Chat.myName].concat(Chat.onlineNames)
                    delegate: Item {
                        required property string modelData
                        required property int index
                        width: content.width
                        height: 26
                        Avatar {
                            id: a
                            size: 22
                            name: parent.modelData
                            anchors.verticalCenter: parent.verticalCenter
                        }
                        Text {
                            // Peer and server text is shown as typed, never as markup.
                            textFormat: Text.PlainText
                            anchors.left: a.right
                            anchors.leftMargin: 8
                            anchors.verticalCenter: parent.verticalCenter
                            text: parent.modelData + (parent.index === 0 ? " (you)" : "")
                            color: Theme.text
                            font.pixelSize: 12
                        }
                    }
                }
            }

            Text {
                // Peer and server text is shown as typed, never as markup.
                textFormat: Text.PlainText
                topPadding: 22
                bottomPadding: 6
                leftPadding: 4
                text: "SESSION"
                color: Theme.textTertiary
                font.pixelSize: 11
                font.weight: Font.DemiBold
                font.letterSpacing: 0.3
            }
            Rectangle {
                width: parent.width
                height: rows.implicitHeight
                radius: Theme.radiusCard
                color: Theme.raised
                Column {
                    id: rows
                    width: parent.width
                    Row2 { label: "Cipher"; value: Chat.session.cipher }
                    Row2 { label: "Key exchange"; value: "Diffie-Hellman" }
                    Row2 { label: "Server identity"; value: Chat.session.serverIdentity }
                    Row2 {
                        label: "Send key rotated"
                        value: { panel.tick; return Format.relative(Chat.session.lastSendRotation) }
                    }
                    Row2 {
                        label: "Next rotation"
                        value: "in " + Chat.session.messagesUntilRotation + " messages"
                        last: true
                    }
                }
            }

            Item { width: 1; height: 10 }
            Rectangle {
                width: parent.width
                height: 34
                radius: Theme.radiusCard
                color: rotateMouse.pressed ? Qt.darker(Theme.raised, 1.1)
                     : rotateMouse.containsMouse ? Theme.raised2 : Theme.raised
                opacity: Chat.state === Chat.Online ? 1 : 0.5
                Accessible.role: Accessible.Button
                Accessible.name: "Rotate Key Now"
                Accessible.onPressAction: Chat.rotateKey()
                Text {
                    // Peer and server text is shown as typed, never as markup.
                    textFormat: Text.PlainText
                    anchors.centerIn: parent
                    text: "Rotate Key Now"
                    color: Theme.accent
                    font.pixelSize: 13
                    font.weight: Font.Medium
                }
                MouseArea {
                    id: rotateMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    enabled: Chat.state === Chat.Online
                    onClicked: Chat.rotateKey()
                }
            }

            // Saved messages: the switch, and the follow-up question when it is turned off.
            Item { width: 1; height: Chat.historyAvailable ? 10 : 0 }
            Rectangle {
                visible: Chat.historyAvailable
                width: parent.width
                height: saveRow.height + (panel.confirmStop ? confirm.height : 0)
                radius: Theme.radiusCard
                color: Theme.raised
                clip: true

                Item {
                    id: saveRow
                    width: parent.width
                    height: 44
                    Text {
                        // Peer and server text is shown as typed, never as markup.
                        textFormat: Text.PlainText
                        x: 12
                        anchors.verticalCenter: parent.verticalCenter
                        width: parent.width - 70
                        text: "Save messages on this computer"
                        color: Theme.text
                        font.pixelSize: 12
                        wrapMode: Text.Wrap
                    }
                    Toggle {
                        anchors.right: parent.right
                        anchors.rightMargin: 12
                        anchors.verticalCenter: parent.verticalCenter
                        name: "Save messages on this computer"
                        checked: Chat.historyChoice === 1
                        onToggled: {
                            if (checked)
                                panel.confirmStop = true
                            else
                                Chat.setHistoryChoice(1, false)
                        }
                    }
                }

                Column {
                    id: confirm
                    visible: panel.confirmStop
                    anchors.top: saveRow.bottom
                    width: parent.width
                    padding: 12
                    topPadding: 0
                    spacing: 8
                    Text {
                        // Peer and server text is shown as typed, never as markup.
                        textFormat: Text.PlainText
                        width: parent.width - 24
                        text: "Delete messages already saved?"
                        color: Theme.textSecondary
                        font.pixelSize: 12
                        wrapMode: Text.Wrap
                    }
                    Column {
                        spacing: 6
                        Rectangle {
                            width: confirm.width - 24
                            height: 28
                            radius: 7
                            color: keepMouse.containsMouse ? Theme.raised2 : Qt.rgba(1, 1, 1, 0.06)
                            Accessible.role: Accessible.Button
                            Accessible.name: "Keep"
                            Accessible.onPressAction: { Chat.setHistoryChoice(2, false); panel.confirmStop = false }
                            Text { id: keepText; anchors.centerIn: parent; text: "Keep"; color: Theme.text; font.pixelSize: 12 }
                            MouseArea {
                                id: keepMouse
                                anchors.fill: parent
                                hoverEnabled: true
                                onClicked: { Chat.setHistoryChoice(2, false); panel.confirmStop = false }
                            }
                        }
                        Rectangle {
                            width: confirm.width - 24
                            height: 28
                            radius: 7
                            color: delMouse.containsMouse ? Qt.rgba(1, 69 / 255, 58 / 255, 0.25) : Qt.rgba(1, 69 / 255, 58 / 255, 0.15)
                            Accessible.role: Accessible.Button
                            Accessible.name: "Delete Saved Messages"
                            Accessible.onPressAction: { Chat.setHistoryChoice(2, true); panel.confirmStop = false }
                            Text { id: delText; anchors.centerIn: parent; text: "Delete Saved Messages"; color: Theme.danger; font.pixelSize: 12 }
                            MouseArea {
                                id: delMouse
                                anchors.fill: parent
                                hoverEnabled: true
                                onClicked: { Chat.setHistoryChoice(2, true); panel.confirmStop = false }
                            }
                        }
                    }
                }
            }

            Text {
                // Peer and server text is shown as typed, never as markup.
                textFormat: Text.PlainText
                width: parent.width
                topPadding: 12
                leftPadding: 4
                rightPadding: 4
                wrapMode: Text.Wrap
                text: "Encrypted between you and the server. The server's identity isn't checked, and it can read relayed messages."
                color: Theme.textTertiary
                font.pixelSize: 11
                lineHeight: 1.15
            }
        }
    }

    Rectangle {
        id: signOut
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 14
        anchors.horizontalCenter: parent.horizontalCenter
        width: parent.width - 32
        height: 34
        radius: Theme.radiusCard
        color: signOutMouse.containsMouse ? Theme.raised : "transparent"
        Accessible.role: Accessible.Button
        Accessible.name: "Sign Out"
        Accessible.onPressAction: Chat.signOut()
        Text {
            // Peer and server text is shown as typed, never as markup.
            textFormat: Text.PlainText
            anchors.centerIn: parent
            text: "Sign Out"
            color: Theme.danger
            font.pixelSize: 13
            font.weight: Font.Medium
        }
        MouseArea {
            id: signOutMouse
            anchors.fill: parent
            hoverEnabled: true
            onClicked: Chat.signOut()
        }
    }
}
