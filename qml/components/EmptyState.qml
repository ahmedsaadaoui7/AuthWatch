import QtQuick
import QtQuick.Layouts

Item {
    id: root
    property string title: "Nothing here yet"
    property string message: ""
    property string code: "AW"

    BrandTheme { id: theme }

    ColumnLayout {
        anchors.centerIn: parent
        width: Math.min(parent.width - 30, 460)
        spacing: 9

        Rectangle {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: 54
            Layout.preferredHeight: 54
            radius: 27
            color: "#0D2532"
            border.width: 1
            border.color: "#1F5264"
            Text { anchors.centerIn: parent; text: root.code; color: theme.primary; font.pixelSize: 12; font.bold: true }
        }

        Text {
            Layout.fillWidth: true
            text: root.title
            color: theme.textPrimary
            font.pixelSize: 15
            font.bold: true
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
        }

        Text {
            Layout.fillWidth: true
            text: root.message
            color: theme.textMuted
            font.pixelSize: 12
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.WordWrap
        }
    }
}
