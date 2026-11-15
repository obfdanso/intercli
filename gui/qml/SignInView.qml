import QtQuick
import QtQuick.Controls
import QtQuick.Effects
import QtQuick.Layouts
import Intercli.Backend

// The sign-in window: your name, the chats on this network, join one with its
// room code, host your own, or join by address.
Item {
    id: root
    readonly property bool connecting: Chat.state === Chat.Connecting || (Chat.hosting && Chat.state === Chat.SignedOut)
    readonly property bool nameOk: Chat.isValidName(nameField.text)
    property string selectedChat: ""
    property bool byAddress: false
    property string hint: ""
    readonly property bool portOk: /^\d+$/.test(portField.text) && Number(portField.text) >= 1
                                   && Number(portField.text) <= 65535

    function join() {
        if (connecting || !nameOk)
            return
        hint = ""
        if (!byAddress && selectedChat.length === 0) {
            hint = nearbyList.count > 0 ? "Pick a chat below (arrow keys and Enter), or host your own."
                                        : "No chats found yet. Host your own, or join by address."
            return
        }
        if (byAddress) {
            if (portOk && hostField.text.trim().length > 0)
                Chat.signIn(hostField.text, Number(portField.text), nameField.text, addressCodeField.text)
        } else if (selectedChat.length > 0) {
            Chat.joinChat(selectedChat, codeField.text, nameField.text)
        }
    }

    function pick(chatId) {
        selectedChat = chatId
        Chat.clearErrors()
        codeField.text = Chat.rememberedCode(chatId)
        codeField.forceActiveFocus()
    }

    Component.onCompleted: Chat.refreshNetworkCheck()

    // In the small sign-in window the form is the whole window (no card
    // drawn inside it); the card look is kept for a large window.
    Rectangle {
        id: card
        readonly property bool plain: root.width < 600
        anchors.centerIn: parent
        anchors.verticalCenterOffset: plain ? Theme.titleBarHeight / 2 : 0
        width: 360
        height: Math.min(column.implicitHeight + 48, root.height - Theme.titleBarHeight - 8)
        radius: 14
        color: plain ? "transparent" : Theme.raised
        border.color: plain ? "transparent" : Qt.rgba(1, 1, 1, 0.06)
        layer.enabled: !plain
        layer.effect: MultiEffect {
            shadowEnabled: true
            shadowColor: "black"
            shadowOpacity: 0.55
            shadowBlur: 1.0
            shadowVerticalOffset: 10
        }

        Flickable {
            anchors.fill: parent
            anchors.margins: 24
            contentHeight: column.implicitHeight
            clip: true
            boundsBehavior: Flickable.StopAtBounds

            ColumnLayout {
                id: column
                width: parent.width
                spacing: 0

                Row {
                    Layout.alignment: Qt.AlignHCenter
                    spacing: 10
                    Text {
                        textFormat: Text.PlainText
                        text: "◆"
                        color: Theme.accent
                        font.pixelSize: 18
                        anchors.verticalCenter: parent.verticalCenter
                    }
                    Text {
                        textFormat: Text.PlainText
                        text: "intercli"
                        color: Theme.text
                        font.pixelSize: 22
                        font.weight: Font.DemiBold
                        anchors.verticalCenter: parent.verticalCenter
                    }
                }

                Label2 { text: "Your name"; Layout.topMargin: 18 }
                AppTextField {
                    id: nameField
                    Layout.topMargin: 6
                    Layout.fillWidth: true
                    Accessible.name: "Your name"
                    text: Chat.myName
                    placeholderText: "e.g. alice"
                    enabled: !root.connecting
                    invalid: Chat.nameError.length > 0 || (text.length > 0 && !root.nameOk)
                    maximumLength: 31
                    onTextEdited: Chat.clearErrors()
                    onAccepted: root.join()
                    Component.onCompleted: if (text.length === 0) forceActiveFocus()
                }
                ErrorText {
                    text: Chat.nameError.length > 0 ? Chat.nameError
                        : (nameField.text.length > 0 && !root.nameOk) ? "1-31 characters, no spaces" : root.hint
                    color: Chat.nameError.length > 0 ? Theme.danger : Theme.textTertiary
                }

                // --- Chats nearby -------------------------------------------
                ColumnLayout {
                    visible: !root.byAddress
                    Layout.fillWidth: true
                    spacing: 0

                    Label2 { text: "CHATS NEARBY"; Layout.topMargin: 16; font.letterSpacing: 0.3 }
                    Rectangle {
                        Layout.topMargin: 6
                        Layout.fillWidth: true
                        Layout.preferredHeight: Math.max(64, Math.min(3, nearbyList.count) * 52 + 8)
                        radius: 10
                        color: Theme.fieldFill

                        ListView {
                            id: nearbyList
                            anchors.fill: parent
                            anchors.margins: 4
                            clip: true
                            model: Chat.nearby
                            activeFocusOnTab: true
                            keyNavigationEnabled: true
                            Accessible.role: Accessible.List
                            Accessible.name: "Chats nearby"
                            delegate: NearbyChatRow {
                                selected: root.selectedChat === chatId
                                keyboardFocus: nearbyList.activeFocus && ListView.isCurrentItem
                                onPicked: root.pick(chatId)
                            }
                            Keys.onReturnPressed: if (currentItem) root.pick(currentItem.chatId)
                            Keys.onEnterPressed: if (currentItem) root.pick(currentItem.chatId)
                            Keys.onSpacePressed: if (currentItem) root.pick(currentItem.chatId)
                        }
                        Column {
                            visible: nearbyList.count === 0
                            anchors.centerIn: parent
                            width: parent.width - 24
                            spacing: 4
                            Row {
                                anchors.horizontalCenter: parent.horizontalCenter
                                spacing: 8
                                Spinner {
                                    color: Theme.textSecondary
                                    anchors.verticalCenter: parent.verticalCenter
                                    implicitWidth: 12
                                    implicitHeight: 12
                                }
                                Text {
                                    textFormat: Text.PlainText
                                    text: "Looking for chats on this network…"
                                    color: Theme.textSecondary
                                    font.pixelSize: 12
                                }
                            }
                            Text {
                                textFormat: Text.PlainText
                                width: parent.width
                                horizontalAlignment: Text.AlignHCenter
                                wrapMode: Text.Wrap
                                text: "Everyone needs to be on the same Wi-Fi or hotspot."
                                color: Theme.textTertiary
                                font.pixelSize: 11
                            }
                        }
                    }

                    ColumnLayout {
                        visible: root.selectedChat.length > 0
                        Layout.fillWidth: true
                        spacing: 0
                        Label2 { text: "Room code"; Layout.topMargin: 12 }
                        AppTextField {
                            id: codeField
                            Layout.topMargin: 6
                            Layout.fillWidth: true
                            Accessible.name: "Room code"
                            placeholderText: "XXX-XXX"
                            font.capitalization: Font.AllUppercase
                            enabled: !root.connecting
                            invalid: Chat.codeError.length > 0
                            maximumLength: 9
                            onTextEdited: Chat.clearErrors()
                            onAccepted: root.join()
                        }
                        ErrorText { text: Chat.codeError }
                        PrimaryButton {
                            Layout.topMargin: 12
                            Layout.fillWidth: true
                            text: "Join"
                            busyText: "Securing connection…"
                            busy: root.connecting && !Chat.hosting
                            enabled: !root.connecting && root.nameOk && codeField.text.trim().length > 0
                            Accessible.name: "Join"
                            onClicked: root.join()
                        }
                    }
                    ErrorText { text: root.byAddress ? "" : Chat.connectError }

                    // --- or host your own ----------------------------------
                    RowLayout {
                        Layout.topMargin: 16
                        Layout.fillWidth: true
                        spacing: 10
                        Rectangle { Layout.fillWidth: true; height: 1; color: Theme.separator }
                        Text { textFormat: Text.PlainText; text: "or"; color: Theme.textTertiary; font.pixelSize: 11 }
                        Rectangle { Layout.fillWidth: true; height: 1; color: Theme.separator }
                    }
                    PrimaryButton {
                        Layout.topMargin: 14
                        Layout.fillWidth: true
                        visible: Chat.hostingAvailable
                        text: "Host a chat"
                        busyText: "Starting your chat…"
                        busy: Chat.hosting && root.connecting
                        enabled: !root.connecting && root.nameOk
                        Accessible.name: "Host a chat"
                        onClicked: Chat.hostChat(nameField.text)
                    }
                    ErrorText { text: Chat.hostError }
                    Text {
                        textFormat: Text.PlainText
                        visible: Chat.publicNetwork
                        Layout.topMargin: 8
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        text: "This network is set to Public in Windows, so others won't be able to join. "
                              + "Switch it to Private in Settings > Network & internet."
                        color: "#FFD60A"
                        font.pixelSize: 11
                    }
                    Text {
                        textFormat: Text.PlainText
                        visible: Chat.firewallNoteNeeded && Chat.hostingAvailable
                        Layout.topMargin: 8
                        Layout.fillWidth: true
                        wrapMode: Text.Wrap
                        text: "Windows may ask to let intercli through the firewall. Choose Allow so others can join."
                        color: Theme.textTertiary
                        font.pixelSize: 11
                    }
                }

                // --- Join by address ----------------------------------------
                ColumnLayout {
                    visible: root.byAddress
                    Layout.fillWidth: true
                    spacing: 0
                    Label2 { text: "Server"; Layout.topMargin: 16 }
                    RowLayout {
                        Layout.topMargin: 6
                        Layout.fillWidth: true
                        spacing: 8
                        AppTextField {
                            id: hostField
                            Layout.fillWidth: true
                            Accessible.name: "Server address"
                            text: Chat.serverHost
                            placeholderText: "192.168.1.20"
                            enabled: !root.connecting
                            invalid: Chat.connectError.length > 0
                            onTextEdited: Chat.clearErrors()
                            onAccepted: root.join()
                        }
                        AppTextField {
                            id: portField
                            Layout.preferredWidth: 84
                            Accessible.name: "Port"
                            text: String(Chat.serverPort)
                            placeholderText: "8080"
                            enabled: !root.connecting
                            invalid: Chat.connectError.length > 0 || (text.length > 0 && !root.portOk)
                            validator: RegularExpressionValidator { regularExpression: /\d{0,5}/ }
                            onTextEdited: Chat.clearErrors()
                            onAccepted: root.join()
                        }
                    }
                    ErrorText { text: root.byAddress ? Chat.connectError : "" }
                    Label2 { text: "Room code (if the chat has one)"; Layout.topMargin: 12 }
                    AppTextField {
                        id: addressCodeField
                        Layout.topMargin: 6
                        Layout.fillWidth: true
                        Accessible.name: "Room code for address"
                        placeholderText: "XXX-XXX"
                        font.capitalization: Font.AllUppercase
                        enabled: !root.connecting
                        invalid: Chat.codeError.length > 0
                        onTextEdited: Chat.clearErrors()
                        onAccepted: root.join()
                    }
                    ErrorText { text: root.byAddress ? Chat.codeError : "" }
                    PrimaryButton {
                        Layout.topMargin: 16
                        Layout.fillWidth: true
                        text: "Connect"
                        busyText: "Securing connection…"
                        busy: root.connecting
                        enabled: !root.connecting && root.nameOk && root.portOk && hostField.text.trim().length > 0
                        Accessible.name: "Connect"
                        onClicked: root.join()
                    }
                }

                Text {
                    id: addressLink
                    textFormat: Text.PlainText
                    Layout.topMargin: 14
                    Layout.alignment: Qt.AlignHCenter
                    text: root.byAddress ? "Back to chats nearby" : "Join by address"
                    color: Theme.accent
                    font.pixelSize: 12
                    font.underline: activeFocus
                    activeFocusOnTab: true
                    Keys.onReturnPressed: { root.byAddress = !root.byAddress; Chat.clearErrors() }
                    Keys.onSpacePressed: { root.byAddress = !root.byAddress; Chat.clearErrors() }
                    Accessible.role: Accessible.Link
                    Accessible.name: text
                    Accessible.onPressAction: { root.byAddress = !root.byAddress; Chat.clearErrors() }
                    MouseArea {
                        anchors.fill: parent
                        cursorShape: Qt.PointingHandCursor
                        onClicked: { root.byAddress = !root.byAddress; Chat.clearErrors() }
                    }
                }
            }
        }
    }

    component Label2: Text {
        textFormat: Text.PlainText
        color: Theme.textSecondary
        font.pixelSize: 12
        font.weight: Font.Medium
    }

    component ErrorText: Text {
        textFormat: Text.PlainText
        Layout.topMargin: 6
        Layout.fillWidth: true
        visible: text.length > 0
        color: Theme.danger
        font.pixelSize: 12
        wrapMode: Text.Wrap
    }
}
