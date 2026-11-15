import QtQuick

// One Windows 11 caption button (46 x 32). The maximise button's hover and
// pressed looks come from Frame, because Windows owns the mouse over it.
Item {
    id: root
    property string glyph
    property bool isClose: false
    property bool externalHover: false
    property bool externalPressed: false
    signal clicked()

    readonly property bool hovered: mouse.containsMouse || externalHover
    readonly property bool pressed: mouse.pressed || externalPressed

    width: 46
    height: Theme.titleBarHeight

    Rectangle {
        anchors.fill: parent
        color: root.isClose
               ? (root.pressed ? Qt.darker(Theme.closeHover, 1.15) : root.hovered ? Theme.closeHover : "transparent")
               : (root.pressed ? Qt.rgba(1, 1, 1, 0.05) : root.hovered ? Qt.rgba(1, 1, 1, 0.08) : "transparent")
        Behavior on color { ColorAnimation { duration: Theme.animFast } }
    }

    Text {
        anchors.centerIn: parent
        text: root.glyph
        font.family: Theme.iconFont
        font.pixelSize: 10
        color: root.isClose && root.hovered ? "white" : "#E4E4E7"
        renderType: Text.NativeRendering
    }

    MouseArea {
        id: mouse
        anchors.fill: parent
        hoverEnabled: true
        onClicked: root.clicked()
    }
}
