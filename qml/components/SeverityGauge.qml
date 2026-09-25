import QtQuick
import QtQuick.Layouts

Item {
    id: root

    property int total: 0
    property int high: 0
    property int medium: 0

    BrandTheme { id: theme }

    readonly property real highShare: total > 0 ? high / total : 0
    readonly property int percent: Math.round(highShare * 100)
    readonly property string stateLabel: high === 0 ? "NORMAL" : (highShare >= 0.35 ? "CRITICAL" : "ELEVATED")
    readonly property color stateColor: high === 0 ? theme.primary : (highShare >= 0.35 ? theme.danger : theme.warning)

    Canvas {
        id: gauge
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.top
        width: Math.min(parent.width, 260)
        height: 140

        onPaint: {
            var ctx = getContext("2d")
            ctx.clearRect(0, 0, width, height)

            var cx = width / 2
            var cy = height - 18
            var radius = Math.min(width * 0.38, height * 0.78)

            ctx.lineCap = "round"
            ctx.lineWidth = 13
            ctx.strokeStyle = "#173247"
            ctx.beginPath()
            ctx.arc(cx, cy, radius, Math.PI, 2 * Math.PI, false)
            ctx.stroke()

            ctx.strokeStyle = root.stateColor
            ctx.shadowColor = root.stateColor
            ctx.shadowBlur = 10
            ctx.beginPath()
            ctx.arc(cx, cy, radius, Math.PI, Math.PI + (Math.PI * root.highShare), false)
            ctx.stroke()
            ctx.shadowBlur = 0
        }

        Connections {
            target: root

            function onTotalChanged() {
                gauge.requestPaint()
            }

            function onHighChanged() {
                gauge.requestPaint()
            }
        }
    }

    ColumnLayout {
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.top: parent.top
        anchors.topMargin: 70
        spacing: 3

        Text {
            Layout.alignment: Qt.AlignHCenter
            text: root.percent + "%"
            color: root.stateColor
            font.pixelSize: 28
            font.bold: true
        }

        Text {
            Layout.alignment: Qt.AlignHCenter
            text: "HIGH-SEVERITY SHARE"
            color: theme.textMuted
            font.pixelSize: 10
            font.bold: true
            font.letterSpacing: 0.45
        }
    }

    RowLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        spacing: 10

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2

            Text {
                Layout.alignment: Qt.AlignHCenter
                text: root.high
                color: theme.textPrimary
                font.pixelSize: 16
                font.bold: true
            }

            Text {
                Layout.alignment: Qt.AlignHCenter
                text: "HIGH"
                color: theme.textMuted
                font.pixelSize: 10
                font.bold: true
            }
        }

        Rectangle {
            Layout.preferredWidth: 1
            Layout.preferredHeight: 30
            color: theme.border
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 2

            Text {
                Layout.alignment: Qt.AlignHCenter
                text: root.medium
                color: theme.textPrimary
                font.pixelSize: 16
                font.bold: true
            }

            Text {
                Layout.alignment: Qt.AlignHCenter
                text: "MEDIUM"
                color: theme.textMuted
                font.pixelSize: 10
                font.bold: true
            }
        }

        Rectangle {
            Layout.preferredWidth: 1
            Layout.preferredHeight: 30
            color: theme.border
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.preferredHeight: 30
            radius: 9
            color: Qt.rgba(root.stateColor.r, root.stateColor.g, root.stateColor.b, 0.10)
            border.width: 1
            border.color: Qt.rgba(root.stateColor.r, root.stateColor.g, root.stateColor.b, 0.35)

            Text {
                anchors.centerIn: parent
                text: root.stateLabel
                color: root.stateColor
                font.pixelSize: 10
                font.bold: true
            }
        }
    }
}
