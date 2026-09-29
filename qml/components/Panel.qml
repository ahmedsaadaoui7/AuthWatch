import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    property string title: ""
    property string subtitle: ""
    property bool showHeader: title !== "" || subtitle !== ""
    property color accentColor: "transparent"
    default property alias content: body.data

    BrandTheme { id: theme }

    implicitWidth: 320
    implicitHeight: Math.max(
        120,
        40 + body.implicitHeight + (root.showHeader ? headerBlock.implicitHeight + 29 : 0)
    )

    radius: theme.radiusLarge
    color: theme.surface
    border.width: 1
    border.color: theme.border

    // A short accent marker is less visually noisy than a full-height colored rail.
    Rectangle {
        visible: root.accentColor !== "transparent"
        width: 46
        height: 3
        anchors.left: parent.left
        anchors.leftMargin: 20
        anchors.top: parent.top
        anchors.topMargin: 1
        radius: 2
        color: root.accentColor
        opacity: 0.95
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: 20
        spacing: 14

        ColumnLayout {
            id: headerBlock
            visible: root.showHeader
            Layout.fillWidth: true
            spacing: 4

            Text {
                Layout.fillWidth: true
                text: root.title
                color: theme.textPrimary
                font.pixelSize: 14
                font.bold: true
                elide: Text.ElideRight
            }

            Text {
                Layout.fillWidth: true
                visible: root.subtitle !== ""
                text: root.subtitle
                color: theme.textMuted
                font.pixelSize: 12
                wrapMode: Text.WordWrap
            }
        }

        Item {
            visible: root.showHeader
            Layout.fillWidth: true
            Layout.preferredHeight: 1
            Rectangle { anchors.fill: parent; color: theme.border; opacity: 0.75 }
        }

        ColumnLayout {
            id: body
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 12
        }
    }
}
