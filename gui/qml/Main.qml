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

    Binding {
        target: Chat
        property: "windowActive"
        value: window.active
    }

    // Placeholder until the views arrive: a sidebar-coloured strip like the mockup.
    Rectangle {
        width: Theme.sidebarWidth
        height: parent.height
        color: Theme.sidebar
    }

    TitleBar {
        anchors.top: parent.top
        anchors.left: parent.left
        anchors.right: parent.right
        z: 100
    }
}
