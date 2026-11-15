import QtQuick
import QtQuick.Controls
import QtCore
import Intercli.Backend

// Main window: sidebar, the open conversation and (toggleable) details panel.
Item {
    id: root
    readonly property bool everyone: Chat.currentConversation === ""
    readonly property string peer: Chat.currentConversation

    Settings {
        id: prefs
        category: "view"
        property bool detailsOpen: true
    }

    Sidebar {
        id: sidebar
        width: Theme.sidebarWidth
        anchors.top: parent.top
        anchors.bottom: parent.bottom
    }

    Item {
        id: details
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        anchors.right: parent.right
        width: prefs.detailsOpen ? Theme.detailsWidth : 0
        clip: true
        Behavior on width { NumberAnimation { duration: Theme.animNormal; easing.type: Easing.OutCubic } }

        DetailsPanel {
            anchors.top: parent.top
            anchors.bottom: parent.bottom
            anchors.left: parent.left
            width: Theme.detailsWidth
            visible: parent.width > 0
        }
    }

    Rectangle {
        id: pane
        anchors.left: sidebar.right
        anchors.right: details.left
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        color: Theme.window

        // Header sits under the title bar strip.
        Item {
            id: header
            anchors.top: parent.top
            anchors.topMargin: Theme.titleBarHeight
            anchors.left: parent.left
            anchors.right: parent.right
            height: 52

            Avatar {
                id: headerAvatar
                x: 18
                anchors.verticalCenter: parent.verticalCenter
                size: 30
                name: root.peer
            }
            Column {
                anchors.left: headerAvatar.right
                anchors.leftMargin: 10
                anchors.verticalCenter: parent.verticalCenter
                Text {
                    text: root.everyone ? "Everyone" : root.peer
                    color: Theme.text
                    font.pixelSize: 14
                    font.weight: Font.DemiBold
                }
                Text {
                    text: root.everyone ? (Chat.onlineCount + 1) + " online" : "Direct message"
                    color: Theme.textTertiary
                    font.pixelSize: 11
                }
            }

            Rectangle {
                id: infoButton
                anchors.right: parent.right
                anchors.rightMargin: 14
                anchors.verticalCenter: parent.verticalCenter
                width: 28
                height: 28
                radius: 6
                color: infoMouse.containsMouse ? Theme.hover : "transparent"
                Accessible.role: Accessible.Button
                Accessible.name: "Details"
                Accessible.onPressAction: prefs.detailsOpen = !prefs.detailsOpen
                Text {
                    anchors.centerIn: parent
                    text: ""
                    font.family: Theme.iconFont
                    font.pixelSize: 15
                    color: prefs.detailsOpen ? Theme.accent : Theme.textSecondary
                }
                MouseArea {
                    id: infoMouse
                    anchors.fill: parent
                    hoverEnabled: true
                    onClicked: prefs.detailsOpen = !prefs.detailsOpen
                }
            }

            Rectangle {
                anchors.bottom: parent.bottom
                width: parent.width
                height: 1
                color: Theme.separator
            }
        }

        DisconnectedBanner {
            id: banner
            anchors.top: header.bottom
            anchors.left: parent.left
            anchors.right: parent.right
        }

        MessageList {
            id: messages
            anchors.top: banner.bottom
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: composer.top
        }

        Composer {
            id: composer
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            placeholder: root.everyone ? "Message everyone" : "Message " + root.peer
        }
    }

    Connections {
        target: Chat
        function onCurrentConversationChanged() { composer.focusInput() }
    }
    Component.onCompleted: composer.focusInput()
}
