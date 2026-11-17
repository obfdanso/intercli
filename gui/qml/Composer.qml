import QtQuick
import QtQuick.Controls
import Intercli.Backend

// Message box: Enter sends, Shift+Enter adds a line, grows to five lines, and
// counts bytes near the limit for a message (a little lower for direct ones).
Item {
    id: root
    property string placeholder: "Message"
    readonly property int bytes: Chat.utf8Length(input.text)
    readonly property bool tooLong: bytes > Chat.textLimit
    readonly property bool canSend: Chat.state === Chat.Online && input.text.trim().length > 0 && !tooLong

    implicitHeight: field.height + 24

    function send() {
        if (!canSend)
            return
        if (Chat.send(input.text))
            input.clear()
    }

    function focusInput() { input.forceActiveFocus() }

    Rectangle {
        id: field
        anchors.left: parent.left
        anchors.right: sendButton.left
        anchors.leftMargin: 16
        anchors.rightMargin: 10
        anchors.bottom: parent.bottom
        anchors.bottomMargin: 14
        height: Math.min(input.implicitHeight, 5 * 18 + 16)
        radius: 18
        color: "transparent"
        border.width: 1
        border.color: root.tooLong ? Theme.danger
                    : input.activeFocus ? Qt.rgba(1, 1, 1, 0.22) : Qt.rgba(1, 1, 1, 0.14)
        opacity: Chat.state === Chat.Online ? 1 : 0.5

        ScrollView {
            anchors.fill: parent
            ScrollBar.horizontal.policy: ScrollBar.AlwaysOff

            TextArea {
                id: input
                enabled: Chat.state === Chat.Online
                placeholderText: root.placeholder
                placeholderTextColor: Theme.textTertiary
                color: Theme.text
                selectionColor: Theme.accent
                selectedTextColor: "white"
                wrapMode: TextEdit.Wrap
                font.pixelSize: 14
                leftPadding: 14
                rightPadding: counter.visible ? counter.width + 18 : 14
                topPadding: 8
                bottomPadding: 8
                background: null
                Accessible.name: "Message"

                Keys.onPressed: (event) => {
                    if (event.key === Qt.Key_Return || event.key === Qt.Key_Enter) {
                        if (event.modifiers & Qt.ShiftModifier)
                            return
                        event.accepted = true
                        root.send()
                    }
                }
            }
        }

        Text {
            // Peer and server text is shown as typed, never as markup.
            textFormat: Text.PlainText
            id: counter
            visible: root.bytes > 900
            anchors.right: parent.right
            anchors.rightMargin: 12
            anchors.bottom: parent.bottom
            anchors.bottomMargin: 9
            text: root.bytes + "/" + Chat.textLimit
            color: root.tooLong ? Theme.danger : Theme.textTertiary
            font.pixelSize: 11
        }
    }

    Rectangle {
        id: sendButton
        anchors.right: parent.right
        anchors.rightMargin: 16
        anchors.verticalCenter: field.bottom
        anchors.verticalCenterOffset: -18
        width: 28
        height: 28
        radius: 14
        color: Theme.accent
        opacity: root.canSend ? 1 : 0.35
        Behavior on opacity { NumberAnimation { duration: Theme.animFast } }
        Accessible.role: Accessible.Button
        Accessible.name: "Send"
        Accessible.onPressAction: root.send()

        Text {
            // Peer and server text is shown as typed, never as markup.
            textFormat: Text.PlainText
            anchors.centerIn: parent
            text: "↑"
            color: "white"
            font.pixelSize: 16
            font.weight: Font.Bold
        }
        MouseArea {
            anchors.fill: parent
            enabled: root.canSend
            cursorShape: Qt.PointingHandCursor
            onClicked: root.send()
        }
    }
}
