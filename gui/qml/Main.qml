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

    // Signing out or closing while hosting with others in the chat ends it for
    // them too, so ask first.
    property bool closeAfterEnding: false
    function requestSignOut() {
        if (Chat.needsEndChatConfirm()) {
            endChatSheet.open()
        } else {
            Chat.endChat()
        }
    }
    onClosing: (close) => {
        if (!window.closeAfterEnding && Chat.needsEndChatConfirm()) {
            close.accepted = false
            window.closeAfterEnding = true
            endChatSheet.open()
        }
    }

    Loader {
        id: chatLoader
        anchors.fill: parent
        active: window.signedIn
        source: "ChatView.qml"
        Connections {
            target: chatLoader.item
            ignoreUnknownSignals: true
            function onSignOutRequested() { window.requestSignOut() }
        }
        opacity: window.signedIn ? 1 : 0
        Behavior on opacity { NumberAnimation { duration: Theme.animNormal; easing.type: Easing.OutCubic } }
    }

    SaveHistorySheet {
        anchors.fill: parent
        z: 50
    }

    ConfirmSheet {
        id: endChatSheet
        anchors.fill: parent
        z: 60
        title: "End your chat?"
        message: (Chat.peopleInChat - 1) === 1 ? "1 person will be disconnected."
                 : (Chat.peopleInChat - 1) + " people will be disconnected."
        confirmText: "End Chat"
        onConfirmed: {
            Chat.endChat()
            if (window.closeAfterEnding)
                window.close()
        }
        onCancelled: window.closeAfterEnding = false
    }

    TitleBar {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        z: 100
    }
}
