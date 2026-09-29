import QtQuick
import QtQuick.Layouts

Rectangle {
    id: root
    signal actionClicked()
    property int count: 0
    property string title: "High-severity findings require analyst attention"
    property string message: "Review priority findings and escalate confirmed activity into a case."
    property string actionText: "Review findings"

    BrandTheme { id: theme }

    Layout.fillWidth: true
    Layout.preferredHeight: 88
    radius: 14
    color: "#17141D"
    border.width: 1
    border.color: theme.dangerBorder

    RowLayout {
        anchors.fill: parent
        anchors.leftMargin: 18
        anchors.rightMargin: 16
        spacing: 14

        Rectangle {
            Layout.preferredWidth: 44
            Layout.preferredHeight: 44
            radius: 22
            color: theme.dangerSoft
            border.width: 1
            border.color: theme.dangerBorder
            Text {
                anchors.centerIn: parent
                text: "!"
                color: theme.danger
                font.pixelSize: 22
                font.bold: true
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 4

            RowLayout {
                Layout.fillWidth: true
                spacing: 10

                Text {
                    Layout.fillWidth: true
                    text: root.title
                    color: theme.textPrimary
                    font.pixelSize: 14
                    font.bold: true
                    elide: Text.ElideRight
                }

                Rectangle {
                    Layout.preferredWidth: countLabel.implicitWidth + 18
                    Layout.preferredHeight: 26
                    radius: 8
                    color: theme.dangerSoft
                    border.width: 1
                    border.color: theme.dangerBorder
                    Text {
                        id: countLabel
                        anchors.centerIn: parent
                        text: root.count + " HIGH"
                        color: theme.danger
                        font.pixelSize: 10
                        font.bold: true
                    }
                }
            }

            Text {
                Layout.fillWidth: true
                text: root.message
                color: theme.textSecondary
                font.pixelSize: 12
                elide: Text.ElideRight
            }
        }

        SecondaryButton {
            text: root.actionText
            onClicked: root.actionClicked()
        }
    }
}
