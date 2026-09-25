import QtQuick
import QtQuick.Controls

ComboBox {
    id: root
    BrandTheme { id: theme }

    implicitWidth: 180
    implicitHeight: 38
    leftPadding: 12
    rightPadding: 30
    font.pixelSize: 12

    contentItem: Text {
        leftPadding: 0
        text: root.displayText
        color: theme.textPrimary
        verticalAlignment: Text.AlignVCenter
        elide: Text.ElideRight
        font.pixelSize: 12
    }

    background: Rectangle {
        radius: 9
        color: theme.surfaceRaised
        border.width: 1
        border.color: root.activeFocus ? theme.primaryMuted : theme.border
    }

    indicator: Text {
        x: root.width - width - 11
        anchors.verticalCenter: parent.verticalCenter
        text: "⌄"
        color: theme.textMuted
        font.pixelSize: 16
    }

    popup: Popup {
        y: root.height + 4
        width: root.width
        implicitHeight: Math.min(contentItem.implicitHeight + 8, 240)
        padding: 4
        background: Rectangle { radius: 9; color: "#0A1825"; border.width: 1; border.color: "#21465C" }
        contentItem: ListView {
            clip: true
            implicitHeight: contentHeight
            model: root.popup.visible ? root.delegateModel : null
            currentIndex: root.highlightedIndex
        }
    }

    delegate: ItemDelegate {
        width: root.width - 8
        height: 34
        contentItem: Text { text: modelData; color: highlighted ? theme.primaryBright : theme.textSecondary; font.pixelSize: 12; verticalAlignment: Text.AlignVCenter }
        background: Rectangle { radius: 7; color: highlighted ? "#102B38" : "transparent" }
    }
}
