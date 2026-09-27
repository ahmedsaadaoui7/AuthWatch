import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Item {
    id: root

    property var points: []

    BrandTheme {
        id: theme
    }

    function pointCount() {
        return points ? points.length : 0
    }

    function formatTime(value) {
        if (!value)
            return "--:--:--"

        var date = new Date(value)

        if (isNaN(date.getTime()))
            return String(value)

        return Qt.formatDateTime(date, "HH:mm:ss")
    }

    function formatEventType(value) {
        if (!value)
            return "Security event"

        var text = String(value).replace(/_/g, " ")

        return text.charAt(0).toUpperCase()
                + text.slice(1)
    }

    function buildContext(event) {
        if (!event)
            return ""

        var parts = []

        if (event.username)
            parts.push("User: " + event.username)

        if (event.source_ip)
            parts.push("Source IP: " + event.source_ip)

        if (event.host)
            parts.push("Host: " + event.host)

        if (event.result)
            parts.push("Result: " + event.result)

        return parts.join("  ·  ")
    }

    ListView {
        id: eventList

        anchors.fill: parent
        anchors.margins: 4

        visible: root.pointCount() > 0

        clip: true
        spacing: 0

        model: root.points || []

        ScrollBar.vertical: ScrollBar {
            policy: ScrollBar.AsNeeded
        }

        delegate: Item {
            required property var modelData
            required property int index

            width: eventList.width
            height: 74

            RowLayout {
                anchors.fill: parent
                spacing: 12

                Text {
                    Layout.preferredWidth: 72

                    text: root.formatTime(
                        modelData.timestamp
                    )

                    color: theme.textSecondary

                    font.pixelSize: 11
                    font.bold: true
                }

                Item {
                    Layout.preferredWidth: 24
                    Layout.fillHeight: true

                    Rectangle {
                        width: 1

                        anchors.horizontalCenter:
                            parent.horizontalCenter
                        anchors.top: parent.top
                        anchors.bottom: parent.bottom

                        color: theme.borderStrong
                    }

                    Rectangle {
                        width: 11
                        height: 11

                        radius: 6

                        anchors.centerIn: parent

                        color: modelData.result === "failure"
                               ? theme.danger
                               : theme.primary

                        border.width: 2
                        border.color: theme.background
                    }
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 4

                    Text {
                        Layout.fillWidth: true

                        text: root.formatEventType(
                            modelData.event_type
                        )

                        color: theme.textPrimary

                        font.pixelSize: 12
                        font.bold: true

                        elide: Text.ElideRight
                    }

                    Text {
                        Layout.fillWidth: true

                        text: root.buildContext(
                            modelData
                        )

                        color: theme.textSecondary
                        font.pixelSize: 10

                        elide: Text.ElideRight
                    }

                    Text {
                        Layout.fillWidth: true

                        text: modelData.source
                              ? String(modelData.source)
                              : ""

                        color: theme.textMuted
                        font.pixelSize: 9

                        elide: Text.ElideRight
                    }
                }
            }

            Rectangle {
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.bottom: parent.bottom
                anchors.leftMargin: 108

                height: 1
                color: theme.border
            }
        }
    }

    EmptyState {
        anchors.fill: parent

        visible: root.pointCount() === 0

        title: "Timeline not available yet"
        message: "Investigation events will appear here after analysis."
        code: "EV"
    }
}
