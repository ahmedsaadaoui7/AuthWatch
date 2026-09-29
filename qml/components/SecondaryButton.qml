import QtQuick

Rectangle {
    id: root
    signal clicked()
    property string text: "Action"

    BrandTheme { id: theme }

    implicitWidth: label.implicitWidth + 28
    implicitHeight: 40
    radius: 9
    color: mouseArea.containsMouse && root.enabled ? theme.surfaceHover : theme.surfaceRaised
    border.width: 1
    border.color: mouseArea.containsMouse && root.enabled ? theme.borderStrong : theme.border
    opacity: root.enabled ? 1.0 : 0.5

    Text {
        id: label
        anchors.centerIn: parent
        text: root.text
        color: theme.textSecondary
        font.pixelSize: 13
        font.bold: true
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
