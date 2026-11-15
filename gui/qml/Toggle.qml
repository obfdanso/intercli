import QtQuick

// iOS-style switch.
Rectangle {
    id: root
    property bool checked: false
    property string name
    signal toggled()

    width: 38
    height: 22
    radius: 11
    color: checked ? Theme.online : Qt.rgba(1, 1, 1, 0.16)
    Behavior on color { ColorAnimation { duration: Theme.animFast } }

    Accessible.role: Accessible.CheckBox
    Accessible.name: name
    Accessible.checkable: true
    Accessible.checked: checked
    Accessible.onToggleAction: root.toggled()
    Accessible.onPressAction: root.toggled()

    Rectangle {
        width: 18
        height: 18
        radius: 9
        y: 2
        x: root.checked ? root.width - width - 2 : 2
        color: "white"
        Behavior on x { NumberAnimation { duration: Theme.animFast; easing.type: Easing.OutCubic } }
    }

    MouseArea {
        anchors.fill: parent
        cursorShape: Qt.PointingHandCursor
        onClicked: root.toggled()
    }
}
