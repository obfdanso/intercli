import QtQuick
import QtQuick.Controls

ApplicationWindow {
    id: window
    width: 1100
    height: 700
    minimumWidth: 820
    minimumHeight: 520
    visible: true
    title: "intercli"
    color: Theme.window

    Text {
        anchors.centerIn: parent
        text: "intercli"
        color: Theme.text
        font.pixelSize: 24
        font.weight: Font.DemiBold
    }
}
