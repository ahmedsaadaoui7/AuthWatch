import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: root

    property var viewModel: null
    property string query: ""

    readonly property var investigationsModel:
        root.viewModel
        ? root.viewModel.investigations
        : []

    readonly property var selectedInvestigation:
        root.viewModel && root.viewModel.hasSelection
        ? root.viewModel.selectedInvestigation
        : null

    signal analyzeRequested()
    signal exportRequested(var investigation)

    Component.onCompleted: {
        if (root.viewModel) {
            root.viewModel.loadInvestigations()
        }
    }

    BrandTheme {
        id: theme
    }

    function matches(item) {
        if (!item)
            return false

        var q = root.query.toLowerCase()

        return q === ""
                || String(item.name || "").toLowerCase().indexOf(q) >= 0
                || String(item.public_id || "").toLowerCase().indexOf(q) >= 0
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.leftMargin: 24
        anchors.rightMargin: 24

        spacing: 16

        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: 104

            RowLayout {
                anchors.fill: parent
                spacing: 16

                ColumnLayout {
                    Layout.fillWidth: true
                    spacing: 6

                    Text {
                        text: "Investigations"
                        color: theme.textPrimary

                        font.pixelSize: 28
                        font.bold: true
                    }

                    Text {
                        text: "Review completed analyses, timelines, affected entities, and investigation context."
                        color: theme.textSecondary

                        font.pixelSize: 13
                    }
                }

                PrimaryButton {
                    text: "New investigation"

                    onClicked: root.analyzeRequested()
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true

            spacing: 14

            Panel {
                Layout.preferredWidth: 410
                Layout.fillHeight: true

                title: "Investigation Library"
                subtitle: "Completed and in-progress AuthWatch investigations"

                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    spacing: 8

                    SearchField {
                        Layout.fillWidth: true

                        placeholderText: "Search investigation name or ID"

                        onTextChanged: root.query = text
                    }

                    Repeater {
                        model: root.investigationsModel || []

                        delegate: Rectangle {
                            required property var modelData

                            property bool accepted:
                                root.matches(modelData)

                            property bool isSelected:
                                root.selectedInvestigation
                                && root.selectedInvestigation.id === modelData.id

                            Layout.fillWidth: true
                            Layout.preferredHeight: accepted ? 72 : 0

                            visible: accepted

                            radius: 10

                            color: isSelected
                                   ? "#102C3B"
                                   : (
                                         investigationMouse.containsMouse
                                         ? "#102230"
                                         : "transparent"
                                     )

                            border.width: isSelected ? 1 : 0
                            border.color: theme.primaryMuted

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 10
                                anchors.rightMargin: 10

                                spacing: 10

                                Rectangle {
                                    Layout.preferredWidth: 42
                                    Layout.preferredHeight: 42

                                    radius: 11

                                    color: "#0D2B38"

                                    border.width: 1
                                    border.color: "#1E5667"

                                    Text {
                                        anchors.centerIn: parent

                                        text: "IN"
                                        color: theme.primary

                                        font.pixelSize: 11
                                        font.bold: true
                                    }
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 4

                                    Text {
                                        Layout.fillWidth: true

                                        text: modelData.name || "Investigation"
                                        color: theme.textPrimary

                                        font.pixelSize: 12
                                        font.bold: true

                                        elide: Text.ElideRight
                                    }

                                    Text {
                                        Layout.fillWidth: true

                                        text: (modelData.public_id || "")
                                              + (
                                                    modelData.finding_count !== undefined
                                                    ? ("  ·  " + modelData.finding_count + " findings")
                                                    : ""
                                                )

                                        color: theme.textMuted

                                        font.pixelSize: 10

                                        elide: Text.ElideRight
                                    }
                                }

                                StatusBadge {
                                    status: modelData.status || "open"
                                }
                            }

                            MouseArea {
                                id: investigationMouse

                                anchors.fill: parent

                                hoverEnabled: true
                                cursorShape: Qt.PointingHandCursor

                                onClicked: {
                                    if (root.viewModel) {
                                        root.viewModel.selectInvestigation(
                                            modelData.id
                                        )
                                    }
                                }
                            }
                        }
                    }

                    EmptyState {
                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        visible: !root.investigationsModel
                                 || root.investigationsModel.length === 0

                        title: "No investigations yet"
                        message: "Run telemetry analysis to create the first AuthWatch investigation."
                        code: "IN"
                    }
                }
            }

            ColumnLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true

                spacing: 14

                Panel {
                    Layout.fillWidth: true

                    Layout.preferredHeight: 230

                    title: root.selectedInvestigation
                           ? (root.selectedInvestigation.name || "Investigation")
                           : "Investigation Overview"

                    subtitle: root.selectedInvestigation
                              ? (root.selectedInvestigation.public_id || "")
                              : "Select an investigation to review its operational summary"

                    EmptyState {
                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        visible: root.selectedInvestigation === null

                        title: "No investigation selected"
                        message: "Choose an investigation from the library to inspect findings, timeline, telemetry sources, and affected entities."
                        code: "i"
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        visible: root.selectedInvestigation !== null

                        spacing: 12

                        MetricCard {
                            code: "EV"
                            label: "EVENTS"

                            value: root.selectedInvestigation
                                   ? (root.selectedInvestigation.event_count || 0)
                                   : 0

                            helper: "Normalized events"
                            accentColor: theme.primary
                        }

                        MetricCard {
                            code: "FD"
                            label: "FINDINGS"

                            value: root.selectedInvestigation
                                   ? (root.selectedInvestigation.finding_count || 0)
                                   : 0

                            helper: "Detection + correlation"
                            accentColor: theme.primary
                        }

                        MetricCard {
                            code: "HI"
                            label: "HIGH SEVERITY"

                            value: root.selectedInvestigation
                                   ? (root.selectedInvestigation.high_severity_count || 0)
                                   : 0

                            helper: "Priority findings"

                            accentColor: theme.danger
                            valueColor: theme.danger
                        }
                    }
                }

                Panel {
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    title: "Investigation Timeline"
                    subtitle: "Chronological security activity and finding context"

                    EmptyState {
                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        visible: root.selectedInvestigation === null

                        title: "Timeline waiting for an investigation"
                        message: "AuthWatch will show the event sequence here once an investigation is selected."
                        code: "TL"
                    }

                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        visible: root.selectedInvestigation !== null

                        spacing: 10

                        TimelineChart {
                            Layout.fillWidth: true
                            Layout.fillHeight: true

                            points: root.selectedInvestigation
                                    && root.selectedInvestigation.timeline
                                    ? root.selectedInvestigation.timeline
                                    : []
                        }

                        RowLayout {
                            Layout.fillWidth: true

                            Item {
                                Layout.fillWidth: true
                            }

                            SecondaryButton {
                                text: "Export investigation"

                                onClicked: root.exportRequested(
                                               root.selectedInvestigation
                                           )
                            }
                        }
                    }
                }
            }
        }

        Item {
            Layout.preferredHeight: 20
        }
    }
}
