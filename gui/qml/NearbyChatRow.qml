import QtQuick
import Intercli.Backend

// One chat in the "Chats nearby" list.
Item {
    id: row
    required property string chatId
    required property string chatName
    required property string hostName
    required property int people
    property bool selected: false
    property bool keyboardFocus: false
    signal picked()

    width: ListView.view ? ListView.view.width : 0
    height: 52

    Accessible.role: Accessible.Button
    Accessible.name: chatName + ", " + (people === 1 ? "1 person" : people + " people")
    Accessible.selected: selected
    Accessible.selectable: true
    Accessible.onPressAction: row.picked()

    Rectangle {
        anchors.fill: parent
        anchors.topMargin: 2
        anchors.bottomMargin: 2
        radius: 10
        color: row.selected ? Qt.rgba(10 / 255, 132 / 255, 1, 0.18) : mouse.containsMouse ? Theme.hover : "transparent"
        border.width: row.selected || row.keyboardFocus ? 1 : 0
        border.color: row.keyboardFocus && !row.selected ? Qt.rgba(1, 1, 1, 0.6) : Theme.accent
        Behavior on color { ColorAnimation { duration: Theme.animFast } }

        Avatar {
            id: avatar
            x: 10
            size: 32
            anchors.verticalCenter: parent.verticalCenter
            name: row.hostName
        }
        Column {
            anchors.left: avatar.right
            anchors.leftMargin: 10
            anchors.right: lock.left
            anchors.rightMargin: 8
            anchors.verticalCenter: parent.verticalCenter
            Text {
                textFormat: Text.PlainText
                width: parent.width
                text: row.chatName
                color: Theme.text
                font.pixelSize: 13
                font.weight: Font.DemiBold
                elide: Text.ElideRight
            }
            Text {
                textFormat: Text.PlainText
                text: row.people === 1 ? "1 person" : row.people + " people"
                color: Theme.textSecondary
                font.pixelSize: 11
            }
        }
        Text {
            id: lock
            textFormat: Text.PlainText
            anchors.right: parent.right
            anchors.rightMargin: 12
            anchors.verticalCenter: parent.verticalCenter
            text: ""
            font.family: Theme.iconFont
            font.pixelSize: 13
            color: Theme.textTertiary
        }
        MouseArea {
            id: mouse
            anchors.fill: parent
            hoverEnabled: true
            onClicked: row.picked()
        }
    }
}
