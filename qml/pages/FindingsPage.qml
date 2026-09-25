import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: root
    property var viewModel
    property string selectedSeverity: "all"
    property var selectedFinding: null
    signal openAnalyzeRequested()
    signal markReviewedRequested(var finding)
    signal escalateRequested(var finding)

    BrandTheme { id: theme }

    readonly property var findingsModel: root.viewModel ? root.viewModel.recentHighFindings : []
    readonly property int highCount: root.viewModel ? root.viewModel.highFindings : 0

    function matches(item) {
        if (!item) return false
        var q = searchField.text.toLowerCase()
        var queryMatch = q === "" || String(item.title || "").toLowerCase().indexOf(q) >= 0 || String(item.rule_id || "").toLowerCase().indexOf(q) >= 0
        var severityMatch = selectedSeverity === "all" || String(item.severity || "").toLowerCase() === selectedSeverity
        return queryMatch && severityMatch
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
                    Text { text: "Findings Queue"; color: theme.textPrimary; font.pixelSize: 28; font.bold: true }
                    Text { text: "Search, triage, review, and escalate AuthWatch detections and correlations."; color: theme.textSecondary; font.pixelSize: 13 }
                }
                PrimaryButton { text: "Analyze telemetry"; onClicked: root.openAnalyzeRequested() }
            }
        }

        AlertBanner {
            visible: root.highCount > 0
            count: root.highCount
            actionText: "Show high findings"
            onActionClicked: root.selectedSeverity = "high"
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.preferredHeight: 44
            spacing: 10

            SearchField { id: searchField; Layout.fillWidth: true; Layout.maximumWidth: 440; placeholderText: "Search finding title or rule ID" }

            Repeater {
                model: ["all", "high", "medium", "low"]
                delegate: Rectangle {
                    required property string modelData
                    Layout.preferredWidth: filterLabel.implicitWidth + 24
                    Layout.preferredHeight: 38
                    radius: 9
                    color: root.selectedSeverity === modelData ? "#0E3140" : theme.surfaceRaised
                    border.width: 1
                    border.color: root.selectedSeverity === modelData ? theme.primaryMuted : theme.border
                    Text { id: filterLabel; anchors.centerIn: parent; text: modelData.toUpperCase(); color: root.selectedSeverity === modelData ? theme.primaryBright : theme.textSecondary; font.pixelSize: 11; font.bold: true }
                    MouseArea { anchors.fill: parent; cursorShape: Qt.PointingHandCursor; onClicked: root.selectedSeverity = modelData }
                }
            }

            Item { Layout.fillWidth: true }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 14

            Panel {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredWidth: 2.1
                title: "Findings"
                subtitle: "Analyst review queue"

                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    spacing: 5

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 30
                        Text { Layout.fillWidth: true; text: "FINDING"; color: theme.textMuted; font.pixelSize: 10; font.bold: true }
                        Text { Layout.preferredWidth: 130; text: "RULE"; color: theme.textMuted; font.pixelSize: 10; font.bold: true }
                        Text { Layout.preferredWidth: 88; text: "SEVERITY"; color: theme.textMuted; font.pixelSize: 10; font.bold: true }
                        Text { Layout.preferredWidth: 98; text: "STATUS"; color: theme.textMuted; font.pixelSize: 10; font.bold: true }
                    }

                    Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: theme.border }

                    Repeater {
                        model: root.findingsModel
                        delegate: Rectangle {
                            required property var modelData
                            property bool accepted: root.matches(modelData)
                            Layout.fillWidth: true
                            Layout.preferredHeight: accepted ? 64 : 0
                            visible: accepted
                            radius: 10
                            color: root.selectedFinding === modelData ? "#102C3B" : (findingMouse.containsMouse ? "#102230" : "transparent")
                            border.width: root.selectedFinding === modelData ? 1 : 0
                            border.color: theme.primaryMuted

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 10
                                anchors.rightMargin: 10
                                spacing: 10
                                Rectangle { Layout.preferredWidth: 4; Layout.preferredHeight: 34; radius: 2; color: String(modelData.severity).toLowerCase() === "high" ? theme.danger : (String(modelData.severity).toLowerCase() === "medium" ? theme.warning : theme.info) }
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 4
                                    Text { Layout.fillWidth: true; text: modelData.title; color: theme.textPrimary; font.pixelSize: 12; font.bold: true; elide: Text.ElideRight }
                                    Text { Layout.fillWidth: true; text: modelData.investigation_id ? ("Investigation #" + modelData.investigation_id) : "AuthWatch finding"; color: theme.textMuted; font.pixelSize: 10; elide: Text.ElideRight }
                                }
                                Text { Layout.preferredWidth: 130; text: modelData.rule_id; color: theme.textSecondary; font.pixelSize: 11; elide: Text.ElideRight }
                                SeverityBadge { Layout.preferredWidth: 88; severity: modelData.severity }
                                StatusBadge { Layout.preferredWidth: 98; status: modelData.status }
                            }

                            MouseArea { id: findingMouse; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: root.selectedFinding = modelData }
                        }
                    }

                    EmptyState {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        visible: !root.findingsModel || root.findingsModel.length === 0
                        title: "No findings available"
                        message: "Analyze telemetry to populate the findings queue."
                        code: "FD"
                    }
                }
            }

            Panel {
                Layout.preferredWidth: 390
                Layout.fillHeight: true
                title: "Finding Details"
                subtitle: "Evidence and analyst actions"
                accentColor: root.selectedFinding && String(root.selectedFinding.severity).toLowerCase() === "high" ? theme.danger : "transparent"

                EmptyState {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    visible: root.selectedFinding === null
                    title: "Select a finding"
                    message: "Choose a row from the queue to inspect severity, status, rule context, and analyst actions."
                    code: "i"
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    visible: root.selectedFinding !== null
                    spacing: 12

                    Text { Layout.fillWidth: true; text: root.selectedFinding ? root.selectedFinding.title : ""; color: theme.textPrimary; font.pixelSize: 17; font.bold: true; wrapMode: Text.WordWrap }
                    RowLayout {
                        spacing: 8

                        SeverityBadge {
                            severity: root.selectedFinding ? root.selectedFinding.severity : "low"
                        }

                        StatusBadge {
                            status: root.selectedFinding ? root.selectedFinding.status : "new"
                        }
                    }

                    Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: theme.border }

                    GridLayout {
                        Layout.fillWidth: true
                        columns: 2
                        rowSpacing: 9
                        columnSpacing: 14
                        Text { text: "Rule ID"; color: theme.textMuted; font.pixelSize: 11 }
                        Text { text: root.selectedFinding ? root.selectedFinding.rule_id : ""; color: theme.textSecondary; font.pixelSize: 11; font.bold: true }
                        Text { text: "Investigation"; color: theme.textMuted; font.pixelSize: 11 }
                        Text { text: root.selectedFinding ? root.selectedFinding.investigation_id : ""; color: theme.textSecondary; font.pixelSize: 11 }
                        Text { text: "First seen"; color: theme.textMuted; font.pixelSize: 11 }
                        Text { text: root.selectedFinding && root.selectedFinding.first_seen ? root.selectedFinding.first_seen : "Not available"; color: theme.textSecondary; font.pixelSize: 11; elide: Text.ElideRight }
                        Text { text: "Last seen"; color: theme.textMuted; font.pixelSize: 11 }
                        Text { text: root.selectedFinding && root.selectedFinding.last_seen ? root.selectedFinding.last_seen : "Not available"; color: theme.textSecondary; font.pixelSize: 11; elide: Text.ElideRight }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 88
                        radius: 10
                        color: String(root.selectedFinding ? root.selectedFinding.severity : "").toLowerCase() === "high" ? "#1B141C" : "#091925"
                        border.width: 1
                        border.color: String(root.selectedFinding ? root.selectedFinding.severity : "").toLowerCase() === "high" ? theme.dangerBorder : theme.border
                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 12
                            spacing: 4
                            Text { text: String(root.selectedFinding ? root.selectedFinding.severity : "").toLowerCase() === "high" ? "PRIORITY REVIEW" : "ANALYST REVIEW"; color: String(root.selectedFinding ? root.selectedFinding.severity : "").toLowerCase() === "high" ? theme.danger : theme.primary; font.pixelSize: 10; font.bold: true }
                            Text { Layout.fillWidth: true; text: "Review supporting telemetry before changing finding status or escalating into a case."; color: theme.textSecondary; font.pixelSize: 11; wrapMode: Text.WordWrap }
                        }
                    }

                    Item { Layout.fillHeight: true }

                    RowLayout {
                        Layout.fillWidth: true
                        spacing: 8
                        SecondaryButton { Layout.fillWidth: true; text: "Mark reviewed"; onClicked: root.markReviewedRequested(root.selectedFinding) }
                        PrimaryButton { Layout.fillWidth: true; text: "Escalate to case"; onClicked: root.escalateRequested(root.selectedFinding) }
                    }
                }
            }
        }

        Item { Layout.preferredHeight: 20 }
    }
}
