import QtQuick
import Intercli.Backend

// Shown under the chat header while the connection is down.
Rectangle {
    id: banner
    readonly property bool shown: Chat.state === Chat.Disconnected || Chat.state === Chat.Reconnecting
    readonly property bool reconnecting: Chat.state === Chat.Reconnecting

    height: shown ? 44 : 0
    visible: height > 0
    clip: true
    color: Qt.rgba(1, 69 / 255, 58 / 255, 0.12)

    function act() {
        if (Chat.needsSignIn)
            Chat.signOut()
        else
            Chat.reconnect()
    }
    Behavior on height { NumberAnimation { duration: Theme.animNormal; easing.type: Easing.OutCubic } }

    Text {
        anchors.left: parent.left
        anchors.leftMargin: 18
        anchors.right: action.left
        anchors.rightMargin: 12
        anchors.verticalCenter: parent.verticalCenter
        text: banner.reconnecting ? "Reconnecting…"
            : (Chat.disconnectReason.length > 0 ? Chat.disconnectReason : "Disconnected from server")
        color: Theme.text
        font.pixelSize: 13
        elide: Text.ElideRight
    }

    Rectangle {
        id: action
        anchors.right: parent.right
        anchors.rightMargin: 14
        anchors.verticalCenter: parent.verticalCenter
        height: 28
        width: actionRow.implicitWidth + 24
        radius: 7
        color: actionMouse.containsMouse ? Qt.lighter(Theme.accent, 1.08) : Theme.accent
        opacity: banner.reconnecting ? 0.7 : 1
        Accessible.role: Accessible.Button
        Accessible.name: actionText.text
        Accessible.onPressAction: banner.act()

        Row {
            id: actionRow
            anchors.centerIn: parent
            spacing: 6
            Spinner {
                visible: banner.reconnecting
                anchors.verticalCenter: parent.verticalCenter
                implicitWidth: 12
                implicitHeight: 12
            }
            Text {
                id: actionText
                text: Chat.needsSignIn ? "Sign in again" : "Reconnect"
                color: "white"
                font.pixelSize: 12
                font.weight: Font.DemiBold
                anchors.verticalCenter: parent.verticalCenter
            }
        }
        MouseArea {
            id: actionMouse
            anchors.fill: parent
            hoverEnabled: true
            enabled: !banner.reconnecting
            onClicked: banner.act()
        }
    }
}
