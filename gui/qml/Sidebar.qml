import QtQuick
import QtQuick.Controls
import Intercli.Backend

// Left column: search, Everyone, then people online and offline.
Rectangle {
    id: sidebar
    color: Theme.sidebar

    Rectangle {
        anchors.right: parent.right
        width: 1
        height: parent.height
        color: Theme.separator
    }

    AppTextField {
        id: search
        anchors.top: parent.top
        anchors.topMargin: Theme.titleBarHeight + 8
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.leftMargin: 12
        anchors.rightMargin: 12
        implicitHeight: 30
        leftPadding: 30
        font.pixelSize: 13
        placeholderText: "Search"
        Accessible.name: "Search"
        onTextChanged: Chat.setSearch(text)

        Text {
            // Peer and server text is shown as typed, never as markup.
            textFormat: Text.PlainText
            x: 10
            anchors.verticalCenter: parent.verticalCenter
            text: ""
            font.family: Theme.iconFont
            font.pixelSize: 12
            color: Theme.textTertiary
        }
    }

    ListView {
        id: list
        anchors.top: search.bottom
        anchors.topMargin: 10
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        model: Chat.conversations
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        section.property: "section"
        section.criteria: ViewSection.FullString
        section.delegate: Item {
            required property string section
            width: ListView.view.width
            height: section === "everyone" ? 0 : 28
            visible: section !== "everyone"
            Text {
                // Peer and server text is shown as typed, never as markup.
                textFormat: Text.PlainText
                x: 18
                anchors.bottom: parent.bottom
                anchors.bottomMargin: 6
                text: parent.section === "online" ? "ONLINE — " + Chat.onlineCount : "OFFLINE"
                color: Theme.textTertiary
                font.pixelSize: 11
                font.weight: Font.DemiBold
                font.letterSpacing: 0.3
            }
        }

        delegate: ConversationRow {
            onActivated: Chat.currentConversation = conversationId
        }

        move: Transition { NumberAnimation { properties: "y"; duration: Theme.animNormal; easing.type: Easing.OutCubic } }
        displaced: Transition { NumberAnimation { properties: "y"; duration: Theme.animNormal; easing.type: Easing.OutCubic } }
    }
}
