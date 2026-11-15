import QtQuick
import QtQuick.Controls
import Intercli.Backend

ApplicationWindow {
    id: window
    width: 1100
    height: 700
    minimumWidth: 820
    minimumHeight: 520
    visible: true
    title: "intercli"
    color: Theme.window
    flags: Frame.customFrame ? (Qt.Window | Qt.FramelessWindowHint) : Qt.Window

    readonly property bool signedIn: Chat.state !== Chat.SignedOut && Chat.state !== Chat.Connecting

    Binding {
        target: Chat
        property: "windowActive"
        value: window.active
    }

    SignInView {
        anchors.fill: parent
        opacity: window.signedIn ? 0 : 1
        visible: opacity > 0
        Behavior on opacity { NumberAnimation { duration: Theme.animNormal; easing.type: Easing.OutCubic } }
    }

    Loader {
        anchors.fill: parent
        active: window.signedIn
        source: "ChatView.qml"
        opacity: window.signedIn ? 1 : 0
        Behavior on opacity { NumberAnimation { duration: Theme.animNormal; easing.type: Easing.OutCubic } }
    }

    TitleBar {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        z: 100
    }
}
