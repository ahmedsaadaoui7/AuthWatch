import QtQuick

Item {
    id: root
    property bool checked: false
    signal toggled(bool value)

    BrandTheme { id: theme }

    implicitWidth: 48
    implicitHeight: 28

    Rectangle {
        anchors.fill: parent
        radius: height / 2
        color: root.checked ? "#0E5461" : "#172532"
        border.width: 1
        border.color: root.checked ? theme.primaryMuted : theme.border
    }

    Rectangle {
        width: 20
        height: 20
        radius: 10
        y: 4
        x: root.checked ? parent.width - width - 4 : 4
        color: root.checked ? theme.primaryBright : theme.textMuted
        Behavior on x { NumberAnimation { duration: 120 } }
    }

    MouseArea {
        anchors.fill: parent
        cursorShape: Qt.PointingHandCursor
        onClicked: {
            root.checked = !root.checked
            root.toggled(root.checked)
        }
    }
}
