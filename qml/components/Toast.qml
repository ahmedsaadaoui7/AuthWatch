import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    property string message: ""
    property string kind: "info"
    property bool showing: false

    BrandTheme { id: theme }
    readonly property color accent: kind === "danger" ? theme.danger : (kind === "success" ? theme.success : theme.primary)

    function show(text, type) {
        root.message = text
        root.kind = type || "info"
        root.showing = true
        hideTimer.restart()
    }

    width: Math.min(520, parent ? parent.width - 40 : 520)
    height: 58
    radius: 12
    color: "#0B1A27"
    border.width: 1
    border.color: Qt.rgba(accent.r, accent.g, accent.b, 0.55)
    opacity: showing ? 1 : 0
    visible: opacity > 0

    Behavior on opacity { NumberAnimation { duration: 160 } }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 14
        anchors.rightMargin: 14
        spacing: 10
        Rectangle { Layout.preferredWidth: 8; Layout.preferredHeight: 8; radius: 4; color: root.accent }
        Text { Layout.fillWidth: true; text: root.message; color: theme.textPrimary; font.pixelSize: 12; wrapMode: Text.WordWrap }
    }

    Timer { id: hideTimer; interval: 3400; onTriggered: root.showing = false }
}
