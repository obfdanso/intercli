import QtQuick
import QtQuick.Controls
import QtQuick.Effects
import QtQuick.Layouts
import Intercli.Backend

// Centred sign-in card: server, port and name.
Item {
    id: root
    readonly property bool connecting: Chat.state === Chat.Connecting
    readonly property bool nameOk: Chat.isValidName(nameField.text)
    readonly property bool portOk: /^\d+$/.test(portField.text) && Number(portField.text) >= 1
                                   && Number(portField.text) <= 65535
    readonly property bool canSubmit: !connecting && nameOk && portOk && hostField.text.trim().length > 0

    function submit() {
        if (canSubmit)
            Chat.signIn(hostField.text, Number(portField.text), nameField.text)
    }

    Rectangle {
        id: card
        anchors.centerIn: parent
        width: 360
        height: column.implicitHeight + 64
        radius: 14
        color: Theme.raised
        border.color: Qt.rgba(1, 1, 1, 0.06)

        // Soft shadow under the card.
        layer.enabled: true
        layer.effect: MultiEffect {
            shadowEnabled: true
            shadowColor: "black"
            shadowOpacity: 0.55
            shadowBlur: 1.0
            shadowVerticalOffset: 10
        }

        ColumnLayout {
            id: column
            anchors.fill: parent
            anchors.margins: 32
            spacing: 0

            Row {
                Layout.alignment: Qt.AlignHCenter
                spacing: 10
                Text {
                    text: "◆"
                    color: Theme.accent
                    font.pixelSize: 20
                    anchors.verticalCenter: parent.verticalCenter
                }
                Text {
                    text: "intercli"
                    color: Theme.text
                    font.pixelSize: 24
                    font.weight: Font.DemiBold
                    anchors.verticalCenter: parent.verticalCenter
                }
            }
            Text {
                Layout.alignment: Qt.AlignHCenter
                Layout.topMargin: 6
                text: "Encrypted chat"
                color: Theme.textSecondary
                font.pixelSize: 13
            }

            Text {
                Layout.topMargin: 28
                text: "Server"
                color: Theme.textSecondary
                font.pixelSize: 12
                font.weight: Font.Medium
            }
            RowLayout {
                Layout.topMargin: 6
                Layout.fillWidth: true
                spacing: 8
                AppTextField {
                    id: hostField
                    Accessible.name: "Server address"
                    Layout.fillWidth: true
                    text: Chat.serverHost
                    placeholderText: "127.0.0.1"
                    enabled: !root.connecting
                    invalid: Chat.connectError.length > 0
                    onAccepted: root.submit()
                    onTextEdited: Chat.clearErrors()
                    KeyNavigation.tab: portField
                }
                AppTextField {
                    id: portField
                    Accessible.name: "Port"
                    Layout.preferredWidth: 84
                    text: String(Chat.serverPort)
                    placeholderText: "8080"
                    enabled: !root.connecting
                    invalid: Chat.connectError.length > 0 || (text.length > 0 && !root.portOk)
                    inputMethodHints: Qt.ImhDigitsOnly
                    validator: RegularExpressionValidator { regularExpression: /\d{0,5}/ }
                    onAccepted: root.submit()
                    onTextEdited: Chat.clearErrors()
                    KeyNavigation.tab: nameField
                }
            }
            Text {
                Layout.topMargin: 6
                Layout.fillWidth: true
                visible: Chat.connectError.length > 0
                text: Chat.connectError
                color: Theme.danger
                font.pixelSize: 12
                wrapMode: Text.Wrap
            }

            Text {
                Layout.topMargin: 16
                text: "Your name"
                color: Theme.textSecondary
                font.pixelSize: 12
                font.weight: Font.Medium
            }
            AppTextField {
                id: nameField
                Accessible.name: "Your name"
                Layout.topMargin: 6
                Layout.fillWidth: true
                text: Chat.myName
                placeholderText: "e.g. alice"
                enabled: !root.connecting
                invalid: Chat.nameError.length > 0 || (text.length > 0 && !root.nameOk)
                maximumLength: 31
                onAccepted: root.submit()
                onTextEdited: Chat.clearErrors()
                KeyNavigation.tab: connectButton
                Component.onCompleted: forceActiveFocus()
            }
            Text {
                Layout.topMargin: 6
                Layout.fillWidth: true
                visible: text.length > 0
                text: Chat.nameError.length > 0 ? Chat.nameError
                    : (nameField.text.length > 0 && !root.nameOk) ? "1-31 characters, no spaces" : ""
                color: Chat.nameError.length > 0 ? Theme.danger : Theme.textTertiary
                font.pixelSize: 12
                wrapMode: Text.Wrap
            }

            PrimaryButton {
                id: connectButton
                Layout.topMargin: 24
                Layout.fillWidth: true
                text: "Connect"
                busyText: "Securing connection…"
                busy: root.connecting
                enabled: root.canSubmit
                onClicked: root.submit()
            }
        }
    }
}
