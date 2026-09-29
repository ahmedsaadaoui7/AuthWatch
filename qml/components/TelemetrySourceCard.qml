import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    signal browseRequested()
    signal clearRequested()
    property string code: "TL"
    property string title: "Telemetry"
    property string subtitle: ""
    property string selectedPath: ""

    BrandTheme { id: theme }
    readonly property bool selected: root.selectedPath !== ""

    radius: theme.radiusLarge
    color: root.selected ? "#0B202C" : theme.surface
    border.width: 1
    border.color: root.selected ? theme.primaryMuted : theme.border

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 18
        spacing: 10

        RowLayout {
            Layout.fillWidth: true
            spacing: 12

            Rectangle {
                Layout.preferredWidth: 44
                Layout.preferredHeight: 44
                radius: 12
                color: root.selected ? "#103542" : "#0C1D2A"
                border.width: 1
                border.color: root.selected ? "#2A6F7D" : theme.border
                Text { anchors.centerIn: parent; text: root.code; color: root.selected ? theme.primaryBright : theme.textMuted; font.pixelSize: 12; font.bold: true }
            }

            ColumnLayout {
                Layout.fillWidth: true
                spacing: 3
                Text { Layout.fillWidth: true; text: root.title; color: theme.textPrimary; font.pixelSize: 14; font.bold: true; elide: Text.ElideRight }
                Text { Layout.fillWidth: true; text: root.subtitle; color: theme.textMuted; font.pixelSize: 11; wrapMode: Text.WordWrap }
            }

            Rectangle {
                Layout.preferredWidth: statusText.implicitWidth + 16
                Layout.preferredHeight: 26
                radius: 8
                color: root.selected ? "#0D3B39" : "#101D28"
                border.width: 1
                border.color: root.selected ? "#1B7168" : theme.border
                Text { id: statusText; anchors.centerIn: parent; text: root.selected ? "SELECTED" : "OPTIONAL"; color: root.selected ? theme.success : theme.textMuted; font.pixelSize: 10; font.bold: true }
            }
        }

        Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: theme.border }

        Text {
            Layout.fillWidth: true
            text: root.selected ? root.selectedPath.replace("file://", "") : "No file selected"
            color: root.selected ? theme.textSecondary : theme.textDim
            font.pixelSize: 11
            elide: Text.ElideMiddle
        }

        Item { Layout.fillHeight: true }

        RowLayout {
            Layout.fillWidth: true
            spacing: 8
            SecondaryButton { text: root.selected ? "Replace file" : "Choose file"; onClicked: root.browseRequested() }
            SecondaryButton { visible: root.selected; text: "Clear"; onClicked: root.clearRequested() }
            Item { Layout.fillWidth: true }
        }
    }
}
