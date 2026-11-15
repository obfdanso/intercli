import QtQuick
import Intercli.Backend
import "Format.js" as Format

// One sidebar row: avatar, name, time, last message preview and unread marker.
Item {
    id: row
    required property string conversationId
    required property string title
    required property bool online
    required property string preview
    required property var lastActivity
    required property int unread

    readonly property bool selected: Chat.currentConversation === conversationId
    signal activated()

    width: ListView.view ? ListView.view.width : 0
    height: 56

    Accessible.role: Accessible.Button
    Accessible.name: title
    Accessible.onPressAction: row.activated()

    Rectangle {
        anchors.fill: parent
        anchors.leftMargin: 8
        anchors.rightMargin: 8
        anchors.topMargin: 1
        anchors.bottomMargin: 1
        radius: 10
        color: row.selected ? Theme.accent : mouse.containsMouse ? Theme.hover : "transparent"
        Behavior on color { ColorAnimation { duration: Theme.animFast } }

        Avatar {
            id: avatar
            x: 10
            anchors.verticalCenter: parent.verticalCenter
            name: row.conversationId
            showOnline: row.online
            ringColor: row.selected ? Theme.accent : Theme.sidebar
        }

        Item {
            anchors.left: avatar.right
            anchors.leftMargin: 10
            anchors.right: parent.right
            anchors.rightMargin: 10
            anchors.verticalCenter: parent.verticalCenter
            height: 36

            Text {
                // Peer and server text is shown as typed, never as markup.
                textFormat: Text.PlainText
                id: nameText
                anchors.left: parent.left
                anchors.right: timeText.left
                anchors.rightMargin: 6
                anchors.top: parent.top
                text: row.title
                color: Theme.text
                font.pixelSize: 13
                font.weight: Font.DemiBold
                elide: Text.ElideRight
            }
            Text {
                // Peer and server text is shown as typed, never as markup.
                textFormat: Text.PlainText
                id: timeText
                anchors.right: parent.right
                anchors.baseline: nameText.baseline
                text: Format.rowTime(row.lastActivity)
                color: row.selected ? Qt.rgba(1, 1, 1, 0.8) : Theme.textTertiary
                font.pixelSize: 11
            }
            Text {
                // Peer and server text is shown as typed, never as markup.
                textFormat: Text.PlainText
                anchors.left: parent.left
                anchors.right: badge.visible ? badge.left : parent.right
                anchors.rightMargin: badge.visible ? 6 : 0
                anchors.bottom: parent.bottom
                text: row.preview.length > 0 ? row.preview.replace(/\n/g, " ")
                    : (row.conversationId === "" ? "Message everyone online" : (row.online ? "Online" : "Offline"))
                color: row.selected ? Qt.rgba(1, 1, 1, 0.8) : Theme.textSecondary
                font.pixelSize: 12
                elide: Text.ElideRight
            }
            Rectangle {
                id: badge
                visible: row.unread > 0 && !row.selected
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.bottomMargin: 2
                height: row.unread > 1 ? 16 : 9
                width: row.unread > 1 ? Math.max(16, countText.implicitWidth + 9) : 9
                radius: height / 2
                color: Theme.accent
                Text {
                    // Peer and server text is shown as typed, never as markup.
                    textFormat: Text.PlainText
                    id: countText
                    visible: row.unread > 1
                    anchors.centerIn: parent
                    text: row.unread > 99 ? "99+" : String(row.unread)
                    color: "white"
                    font.pixelSize: 10
                    font.weight: Font.DemiBold
                }
            }
        }

        MouseArea {
            id: mouse
            anchors.fill: parent
            hoverEnabled: true
            onClicked: row.activated()
        }
    }
}
