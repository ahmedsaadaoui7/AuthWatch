import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    signal clicked()
    property string text: "Dashboard"
    property string shortCode: "DB"
    property bool active: false

    BrandTheme { id: theme }

    Layout.fillWidth: true
    Layout.preferredHeight: 46
    radius: 10
    color: root.active ? "#0D2734" : (mouseArea.containsMouse ? "#0A1E2B" : "transparent")
    border.width: root.active ? 1 : 0
    border.color: root.active ? "#1B5B6B" : "transparent"

    Rectangle {
        visible: root.active
        anchors.left: parent.left
        anchors.verticalCenter: parent.verticalCenter
        width: 3
        height: 24
        radius: 2
        color: theme.primary
    }

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 12
        anchors.rightMargin: 12
        spacing: 12

        Rectangle {
            Layout.preferredWidth: 28
            Layout.preferredHeight: 28
            radius: 8
            color: root.active ? "#123848" : "#0C1B28"
            border.width: 1
            border.color: root.active ? "#27677A" : "#173247"

            Text {
                anchors.centerIn: parent
                text: root.shortCode
                color: root.active ? theme.primaryBright : theme.textMuted
                font.pixelSize: 10
                font.bold: true
            }
        }

        Text {
            Layout.fillWidth: true
            text: root.text
            color: root.active ? theme.textPrimary : theme.textSecondary
            font.pixelSize: 13
            font.bold: root.active
        }

        Text {
            visible: root.active
            text: "›"
            color: theme.primary
            font.pixelSize: 20
        }
    }

    MouseArea {
        id: mouseArea
        anchors.fill: parent
        hoverEnabled: true
        cursorShape: Qt.PointingHandCursor
        onClicked: root.clicked()
    }
}
