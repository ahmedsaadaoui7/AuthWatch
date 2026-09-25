import QtQuick

Rectangle {
    id: root
    property string status: "new"

    BrandTheme { id: theme }

    readonly property string normalized: String(root.status || "new").toLowerCase()
    readonly property color badgeColor: normalized === "closed" ? theme.textMuted : (normalized === "investigating" ? theme.warning : (normalized === "reviewed" ? theme.success : (normalized === "escalated" ? theme.danger : theme.primary)))

    implicitWidth: label.implicitWidth + 20
    implicitHeight: 28
    radius: 8
    color: Qt.rgba(badgeColor.r, badgeColor.g, badgeColor.b, 0.10)
    border.width: 1
    border.color: Qt.rgba(badgeColor.r, badgeColor.g, badgeColor.b, 0.34)

    Text {
        id: label
        anchors.centerIn: parent
        text: root.normalized.replace("_", " ").toUpperCase()
        color: root.badgeColor
        font.pixelSize: 10
        font.bold: true
    }
}
