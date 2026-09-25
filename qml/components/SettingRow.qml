import QtQuick
import QtQuick.Layouts

Item {
    id: root
    property string title: "Setting"
    property string description: ""
    property int controlColumnWidth: 190
    default property alias control: controlHost.data

    BrandTheme { id: theme }

    implicitHeight: Math.max(74, textColumn.implicitHeight + 18)
    Layout.fillWidth: true
    Layout.preferredHeight: implicitHeight

    RowLayout {
        anchors.fill: parent
        anchors.topMargin: 3
        anchors.bottomMargin: 3
        spacing: 20

        ColumnLayout {
            id: textColumn
            Layout.fillWidth: true
            Layout.alignment: Qt.AlignVCenter
            spacing: 4

            Text {
                Layout.fillWidth: true
                text: root.title
                color: theme.textPrimary
                font.pixelSize: 13
                font.bold: true
                wrapMode: Text.WordWrap
            }

            Text {
                Layout.fillWidth: true
                visible: root.description !== ""
                text: root.description
                color: theme.textMuted
                font.pixelSize: 11
                wrapMode: Text.WordWrap
                lineHeight: 1.1
            }
        }

        RowLayout {
            id: controlHost
            Layout.preferredWidth: root.controlColumnWidth
            Layout.minimumWidth: root.controlColumnWidth
            Layout.maximumWidth: root.controlColumnWidth
            Layout.alignment: Qt.AlignRight | Qt.AlignVCenter
            layoutDirection: Qt.RightToLeft
            spacing: 8
        }
    }
}
