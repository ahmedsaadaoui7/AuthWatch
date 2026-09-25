import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    property string code: "--"
    property string label: "METRIC"
    property var value: 0
    property string helper: ""
    property color accentColor: "#24D6E7"
    property color valueColor: "#F2F7FB"
    property bool critical: false

    BrandTheme { id: theme }

    Layout.fillWidth: true
    Layout.preferredHeight: 134
    radius: theme.radiusLarge
    color: root.critical && Number(root.value) > 0 ? "#15141D" : theme.surface
    border.width: 1
    border.color: root.critical && Number(root.value) > 0 ? theme.dangerBorder : theme.border

    ColumnLayout {
        anchors.fill: parent
        anchors.leftMargin: 18
        anchors.rightMargin: 18
        anchors.topMargin: 16
        anchors.bottomMargin: 16
        spacing: 6

        RowLayout {
            Layout.fillWidth: true
            spacing: 8

            Rectangle {
                Layout.preferredWidth: 7
                Layout.preferredHeight: 7
                radius: 4
                color: root.accentColor
                opacity: 0.9
            }

            Text {
                text: root.label
                color: theme.textMuted
                font.pixelSize: 11
                font.bold: true
                font.letterSpacing: 0.5
            }

            Item { Layout.fillWidth: true }

            Rectangle {
                Layout.preferredWidth: 32
                Layout.preferredHeight: 24
                radius: 7
                color: Qt.rgba(root.accentColor.r, root.accentColor.g, root.accentColor.b, 0.10)
                border.width: 1
                border.color: Qt.rgba(root.accentColor.r, root.accentColor.g, root.accentColor.b, 0.28)
                Text {
                    anchors.centerIn: parent
                    text: root.code
                    color: root.accentColor
                    font.pixelSize: 10
                    font.bold: true
                }
            }
        }

        Text {
            text: root.value
            color: root.valueColor
            font.pixelSize: 34
            font.bold: true
        }

        Text {
            Layout.fillWidth: true
            text: root.helper
            color: theme.textSecondary
            font.pixelSize: 11
            elide: Text.ElideRight
        }
    }
}
