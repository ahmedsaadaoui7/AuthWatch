import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    property string title: ""
    property string subtitle: "Affected entities"
    property var items: []
    property string code: "EN"

    BrandTheme { id: theme }

    radius: theme.radiusLarge
    color: theme.surface
    border.width: 1
    border.color: theme.border

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 18
        spacing: 11

        RowLayout {
            Layout.fillWidth: true
            spacing: 10
            Rectangle {
                Layout.preferredWidth: 34
                Layout.preferredHeight: 34
                radius: 9
                color: "#0D2B38"
                border.width: 1
                border.color: "#1E5667"
                Text { anchors.centerIn: parent; text: root.code; color: theme.primary; font.pixelSize: 10; font.bold: true }
            }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: 2
                Text { Layout.fillWidth: true; text: root.title; color: theme.textPrimary; font.pixelSize: 13; font.bold: true; elide: Text.ElideRight }
                Text { Layout.fillWidth: true; text: root.subtitle; color: theme.textMuted; font.pixelSize: 11; elide: Text.ElideRight }
            }
        }

        Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: theme.border }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 5
            Repeater {
                model: root.items ? root.items.slice(0, 4) : []
                delegate: RowLayout {
                    required property var modelData
                    Layout.fillWidth: true
                    Layout.preferredHeight: 30
                    spacing: 8
                    Text { Layout.fillWidth: true; text: modelData.value; color: theme.textSecondary; font.pixelSize: 11; elide: Text.ElideRight }
                    Rectangle { Layout.preferredWidth: 38; Layout.preferredHeight: 24; radius: 7; color: "#0D2431"; border.width: 1; border.color: theme.border; Text { anchors.centerIn: parent; text: modelData.count; color: theme.primaryBright; font.pixelSize: 10; font.bold: true } }
                }
            }
            Item { Layout.fillWidth: true; Layout.fillHeight: true; visible: !root.items || root.items.length === 0; Text { anchors.centerIn: parent; text: "No entity data"; color: theme.textDim; font.pixelSize: 11 } }
        }
    }
}
