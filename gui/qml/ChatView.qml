import QtQuick
import Intercli.Backend

// Placeholder until the main window views are built.
Item {
    Rectangle {
        width: Theme.sidebarWidth
        height: parent.height
        color: Theme.sidebar
    }
    Text {
        anchors.centerIn: parent
        text: "Signed in as " + Chat.myName
        color: Theme.textSecondary
    }
}
