import QtQuick
import Intercli.Backend
import "Format.js" as Format

// One message row: optional time separator and sender label, then either a
// bubble (incoming left, outgoing right) or a centred system line.
Item {
    id: root
    required property int kind          // 0 incoming, 1 outgoing, 2 system
    required property string sender
    required property string text
    required property string file       // a file URL when the message is a file on this PC
    readonly property bool picture: /\.(png|jpe?g|gif|bmp|webp)$/i.test(file)
    required property var time
    required property bool firstInRun
    required property bool lastInRun
    required property bool showSender
    required property bool showTimestamp

    readonly property real maxBubbleWidth: Math.max(160, width * 0.62)

    width: ListView.view ? ListView.view.width : 0
    height: column.implicitHeight + (lastInRun ? 8 : 3)

    Column {
        id: column
        width: parent.width
        spacing: 0

        Text {
            // Peer and server text is shown as typed, never as markup.
            textFormat: Text.PlainText
            visible: root.showTimestamp
            width: parent.width
            topPadding: 8
            bottomPadding: 10
            horizontalAlignment: Text.AlignHCenter
            text: Format.separator(root.time)
            color: Theme.textTertiary
            font.pixelSize: 11
            font.weight: Font.Medium
        }

        Text {
            // Peer and server text is shown as typed, never as markup.
            textFormat: Text.PlainText
            visible: root.showSender
            leftPadding: 14
            bottomPadding: 3
            text: root.sender
            color: Theme.textTertiary
            font.pixelSize: 11
        }

        Text {
            // Peer and server text is shown as typed, never as markup.
            textFormat: Text.PlainText
            visible: root.kind === 2
            width: parent.width
            topPadding: 6
            bottomPadding: 6
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.Wrap
            text: root.text
            color: Theme.textTertiary
            font.pixelSize: 11
        }

        Item {
            visible: root.kind !== 2
            width: parent.width
            height: bubble.height

            Rectangle {
                id: bubble
                x: root.kind === 1 ? parent.width - width : 0
                width: Math.max(Math.min(body.implicitWidth, root.maxBubbleWidth - 24), preview.width) + 24
                height: body.y + body.height + 7
                radius: Theme.radiusBubble
                color: root.kind === 1 ? Theme.accent : Theme.raised2

                // The tail: one squared-off corner on the last bubble of a run.
                Rectangle {
                    visible: root.lastInRun
                    width: Theme.radiusBubble
                    height: Theme.radiusBubble
                    anchors.bottom: parent.bottom
                    anchors.left: root.kind === 1 ? undefined : parent.left
                    anchors.right: root.kind === 1 ? parent.right : undefined
                    color: parent.color
                    radius: 5
                    z: -1
                }
                Rectangle {
                    visible: root.lastInRun
                    width: Theme.radiusBubble
                    height: Theme.radiusBubble
                    anchors.bottom: parent.bottom
                    anchors.left: root.kind === 1 ? undefined : parent.left
                    anchors.right: root.kind === 1 ? parent.right : undefined
                    anchors.bottomMargin: 5
                    anchors.leftMargin: root.kind === 1 ? 0 : 5
                    anchors.rightMargin: root.kind === 1 ? 5 : 0
                    color: parent.color
                }

                // A picture is shown; any file opens in its usual program when clicked.
                Image {
                    id: preview
                    visible: root.picture
                    x: 12
                    y: 7
                    source: root.picture ? root.file : ""
                    asynchronous: true
                    cache: false
                    sourceSize.width: 480
                    fillMode: Image.PreserveAspectFit
                    width: !root.picture ? 0 : Math.min(240, root.maxBubbleWidth - 24)
                    height: !root.picture ? 0
                          : status === Image.Ready ? width * implicitHeight / Math.max(1, implicitWidth) : 120
                }
                MouseArea {
                    visible: root.file.length > 0
                    anchors.fill: root.picture ? preview : body
                    cursorShape: Qt.PointingHandCursor
                    Accessible.role: Accessible.Button
                    Accessible.name: "Open file"
                    onClicked: Qt.openUrlExternally(root.file)
                    z: 1
                }
                TextEdit {
                    id: body
                    x: 12
                    y: 7 + (root.picture ? preview.height + 6 : 0)
                    width: Math.min(implicitWidth, root.maxBubbleWidth - 24)
                    readOnly: true
                    selectByMouse: true
                    textFormat: TextEdit.PlainText
                    wrapMode: TextEdit.Wrap
                    text: root.text
                    color: root.kind === 1 ? "white" : Theme.text
                    selectionColor: root.kind === 1 ? Qt.rgba(1, 1, 1, 0.35) : Theme.accent
                    selectedTextColor: "white"
                    font.pixelSize: 14
                }
            }
        }
    }
}
