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
            x: 12
            anchors.verticalCenter: parent.verticalCenter
            text: parent.label
            color: Theme.textSecondary
            font.pixelSize: 12
        }
        Text {
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
                anchors.horizontalCenter: parent.horizontalCenter
                topPadding: 10
                text: panel.everyone ? "Everyone" : panel.peer
                color: Theme.text
                font.pixelSize: 16
                font.weight: Font.DemiBold
            }
            Text {
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

            Text {
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
