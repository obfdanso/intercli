import QtQuick

// Small spinning arc.
Item {
    id: root
    property color color: "white"
    implicitWidth: 14
    implicitHeight: 14

    Canvas {
        anchors.fill: parent
        onPaint: {
            const ctx = getContext("2d")
            ctx.reset()
            ctx.lineWidth = 2
            ctx.lineCap = "round"
            ctx.strokeStyle = root.color
            ctx.beginPath()
            ctx.arc(width / 2, height / 2, width / 2 - 1.5, 0, Math.PI * 1.4)
            ctx.stroke()
        }
        RotationAnimator on rotation {
            from: 0
            to: 360
            duration: 800
            loops: Animation.Infinite
            running: root.visible
        }
    }
}
