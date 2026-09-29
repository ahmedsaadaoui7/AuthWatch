import QtQuick
import QtQuick.Controls

TextField {
    id: root
    BrandTheme { id: theme }

    implicitHeight: 40
    leftPadding: 14
    rightPadding: 14
    color: theme.textPrimary
    placeholderTextColor: theme.textDim
    selectionColor: theme.primaryMuted
    selectedTextColor: theme.textPrimary
    font.pixelSize: 12

    background: Rectangle {
        radius: 9
        color: theme.surfaceRaised
        border.width: 1
        border.color: root.activeFocus ? theme.primaryMuted : theme.border
    }
}
