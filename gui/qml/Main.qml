import QtQuick
import QtQuick.Controls
import Intercli.Backend

ApplicationWindow {
    id: window
    width: 1100
    height: 700
    visible: true
    title: "intercli"
    color: Theme.window
    flags: Frame.customFrame ? (Qt.Window | Qt.FramelessWindowHint) : Qt.Window

    readonly property bool signedIn: Chat.state !== Chat.SignedOut && Chat.state !== Chat.Connecting

    // Small sign-in window first (like joining a meeting); the full window
    // opens once signed in, and shrinks back on sign out.
    onSignedInChanged: signedIn ? Frame.enterFull() : Frame.enterCompact()

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

    SaveHistorySheet {
        anchors.fill: parent
        z: 50
    }

    TitleBar {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        z: 100
    }
}
