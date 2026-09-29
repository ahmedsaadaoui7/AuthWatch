import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    signal clicked()
    property string text: "Action"
    property string leadingText: ""

    BrandTheme { id: theme }

    implicitWidth: buttonRow.implicitWidth + 30
    implicitHeight: 40
    radius: 9
    color: !root.enabled ? "#0D2A32" : (mouseArea.containsMouse ? theme.primaryBright : theme.primary)
    border.width: 1
    border.color: !root.enabled ? "#17404A" : theme.primaryBright
    opacity: root.enabled ? 1.0 : 0.55

    RowLayout {
        id: buttonRow
        anchors.centerIn: parent
        spacing: 8

        Text {
            visible: root.leadingText !== ""
            text: root.leadingText
            color: "#031117"
            font.pixelSize: 12
            font.bold: true
        }

        Text {
            text: root.text
            color: "#031117"
            font.pixelSize: 13
            font.bold: true
        }
    }

    MouseArea {
        id: mouseArea
        anchors.fill: parent
        hoverEnabled: true
        enabled: root.enabled
        cursorShape: root.enabled ? Qt.PointingHandCursor : Qt.ArrowCursor
        onClicked: root.clicked()
    }
}
