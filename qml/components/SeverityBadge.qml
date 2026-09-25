import QtQuick

Rectangle {
    id: root
    property string severity: "low"

    BrandTheme { id: theme }

    readonly property string normalized: String(root.severity || "low").toLowerCase()
    readonly property color badgeColor: normalized === "high" ? theme.danger : (normalized === "medium" ? theme.warning : (normalized === "low" ? theme.info : theme.textMuted))

    implicitWidth: label.implicitWidth + 20
    implicitHeight: 28
    radius: 8
    color: Qt.rgba(badgeColor.r, badgeColor.g, badgeColor.b, 0.11)
    border.width: 1
    border.color: Qt.rgba(badgeColor.r, badgeColor.g, badgeColor.b, 0.42)

    Text {
        id: label
        anchors.centerIn: parent
        text: root.normalized.toUpperCase()
        color: root.badgeColor
        font.pixelSize: 10
        font.bold: true
        font.letterSpacing: 0.35
    }
}
