import QtQuick
import Intercli.Backend

// Gradient circle with the person's initial; the Everyone conversation ("")
// gets a sparkle. Optional green dot for people who are online.
Item {
    id: root
    property string name
    property int size: 36
    property bool showOnline: false
    property color ringColor: Theme.sidebar

    readonly property var colors: Chat.avatarColors(name)

    width: size
    height: size

    Rectangle {
        anchors.fill: parent
        radius: width / 2
        gradient: Gradient {
            GradientStop { position: 0; color: root.colors[0] }
            GradientStop { position: 1; color: root.colors[1] }
        }
    }

    Text {
        anchors.centerIn: parent
        text: Chat.initialFor(root.name)
        color: "white"
        font.pixelSize: Math.round(root.size * 0.4)
        font.weight: Font.DemiBold
    }

    Rectangle {
        visible: root.showOnline
        width: Math.max(10, Math.round(root.size * 0.3))
        height: width
        radius: width / 2
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.rightMargin: -1
        anchors.bottomMargin: -1
        color: Theme.online
        border.width: 2
        border.color: root.ringColor
    }
}
