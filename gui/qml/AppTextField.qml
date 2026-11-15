import QtQuick
import QtQuick.Controls

// Rounded dark text field with an accent focus ring.
TextField {
    id: field
    property bool invalid: false

    implicitHeight: 36
    leftPadding: 12
    rightPadding: 12
    color: Theme.text
    placeholderTextColor: Theme.textTertiary
    selectionColor: Theme.accent
    selectedTextColor: "white"
    font.pixelSize: 13
    verticalAlignment: TextInput.AlignVCenter

    background: Rectangle {
        radius: 8
        color: Theme.fieldFill
        border.width: field.activeFocus || field.invalid ? 2 : 1
        border.color: field.invalid ? Theme.danger
                    : field.activeFocus ? Theme.accent : Qt.rgba(1, 1, 1, 0.10)
        Behavior on border.color { ColorAnimation { duration: Theme.animFast } }
    }
}
