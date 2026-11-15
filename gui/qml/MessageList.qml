import QtQuick
import QtQuick.Controls
import Intercli.Backend

// The conversation. Sits at the bottom when short, follows new messages while
// the reader is at the end, and offers a "New messages" pill when they are not.
Item {
    id: root
    property bool stick: true
    property bool unseen: false
    signal reachedTop()

    clip: true

    ListView {
        id: view
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.leftMargin: 18
        anchors.rightMargin: 18
        // Shorter than the pane while there are few messages, so they hug the bottom.
        height: Math.min(parent.height, contentHeight + topMargin + bottomMargin)
        topMargin: 12
        bottomMargin: 6
        boundsBehavior: Flickable.StopAtBounds
        model: Chat.messages
        reuseItems: false
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        delegate: MessageBubble {}

        add: Transition {
            NumberAnimation { property: "opacity"; from: 0; to: 1; duration: 180; easing.type: Easing.OutCubic }
            NumberAnimation { property: "y"; from: ViewTransition.destination.y + 8; duration: 180; easing.type: Easing.OutCubic }
        }

        onCountChanged: {
            if (root.stick)
                Qt.callLater(view.positionViewAtEnd)
            else
                root.unseen = true
        }
        onMovementEnded: {
            root.stick = view.atYEnd
            if (root.stick)
                root.unseen = false
            if (view.atYBeginning)
                root.reachedTop()
        }
        onModelChanged: {
            root.stick = true
            root.unseen = false
            Qt.callLater(view.positionViewAtEnd)
        }
        onHeightChanged: if (root.stick) Qt.callLater(view.positionViewAtEnd)
    }

    Rectangle {
        visible: root.unseen && !root.stick
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 10
        width: pillText.implicitWidth + 24
        height: 28
        radius: 14
        color: Theme.accent
        Text {
            id: pillText
            anchors.centerIn: parent
            text: "New messages ↓"
            color: "white"
            font.pixelSize: 12
            font.weight: Font.DemiBold
        }
        MouseArea {
            anchors.fill: parent
            onClicked: {
                view.positionViewAtEnd()
                root.stick = true
                root.unseen = false
            }
        }
    }
}
