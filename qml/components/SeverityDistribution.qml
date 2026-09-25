import QtQuick
import QtQuick.Layouts

Item {
    id: root

    property var counts: ({})

    BrandTheme { id: theme }

    function countFor(key) {
        return (!counts || counts[key] === undefined || counts[key] === null)
            ? 0
            : Number(counts[key])
    }

    readonly property int highCount: countFor("high")
    readonly property int mediumCount: countFor("medium")
    readonly property int lowCount: countFor("low")
    readonly property int maximumCount: Math.max(highCount, mediumCount, lowCount, 1)
    readonly property int totalCount: highCount + mediumCount + lowCount

    ColumnLayout {
        anchors.fill: parent
        spacing: 14

        RowLayout {
            Layout.fillWidth: true

            Text {
                text: root.totalCount
                color: theme.textPrimary
                font.pixelSize: 30
                font.bold: true
            }

            Text {
                text: "total findings"
                color: theme.textMuted
                font.pixelSize: 11
            }

            Item { Layout.fillWidth: true }
        }

        Repeater {
            model: [
                { label: "HIGH", count: root.highCount, color: theme.danger },
                { label: "MEDIUM", count: root.mediumCount, color: theme.warning },
                { label: "LOW", count: root.lowCount, color: theme.info }
            ]

            delegate: ColumnLayout {
                required property var modelData

                Layout.fillWidth: true
                spacing: 6

                RowLayout {
                    Layout.fillWidth: true

                    Text {
                        text: modelData.label
                        color: modelData.color
                        font.pixelSize: 10
                        font.bold: true
                    }

                    Item { Layout.fillWidth: true }

                    Text {
                        text: modelData.count
                        color: theme.textSecondary
                        font.pixelSize: 11
                        font.bold: true
                    }
                }

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 8
                    radius: 4
                    color: "#132838"

                    Rectangle {
                        width: parent.width * (Number(modelData.count) / root.maximumCount)
                        height: parent.height
                        radius: parent.radius
                        color: modelData.color

                        Behavior on width {
                            NumberAnimation {
                                duration: 220
                                easing.type: Easing.OutCubic
                            }
                        }
                    }
                }
            }
        }
    }
}
