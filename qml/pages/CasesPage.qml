import QtQuick
import QtQuick.Layouts
import "../components"

Item {
    id: root
    property var viewModel
    property var selectedCase: null
    property string query: ""
    signal openFindingWorkflowRequested()

    BrandTheme { id: theme }

    readonly property var casesModel: root.viewModel ? root.viewModel.activeCases : []

    function matches(item) {
        if (!item) return false
        var q = root.query.toLowerCase()
        return q === "" || String(item.title || "").toLowerCase().indexOf(q) >= 0 || String(item.public_id || "").toLowerCase().indexOf(q) >= 0
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
                    Text { text: "Cases"; color: theme.textPrimary; font.pixelSize: 28; font.bold: true }
                    Text { text: "Manage escalated findings, analyst workflow, notes, priority, status, and resolution."; color: theme.textSecondary; font.pixelSize: 13 }
                }
                SecondaryButton { text: "Create from finding"; onClicked: root.openFindingWorkflowRequested() }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 14
            MetricCard { code: "AC"; label: "ACTIVE CASES"; value: root.viewModel ? root.viewModel.openCases : 0; helper: "Open and investigating"; accentColor: theme.primary }
            MetricCard { code: "HP"; label: "HIGH PRIORITY"; value: 0; helper: "Priority classification"; accentColor: theme.danger; valueColor: theme.danger }
            MetricCard { code: "CL"; label: "CLOSED"; value: 0; helper: "Resolved cases"; accentColor: theme.success }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 14

            Panel {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredWidth: 1.7
                title: "Case Queue"
                subtitle: "Active SOC cases created from escalated findings"

                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    spacing: 8

                    SearchField {
                        Layout.fillWidth: true
                        placeholderText: "Search case title or ID"
                        onTextChanged: root.query = text
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 28
                        visible: root.casesModel && root.casesModel.length > 0
                        Text { Layout.fillWidth: true; text: "CASE"; color: theme.textMuted; font.pixelSize: 10; font.bold: true }
                        Text { Layout.preferredWidth: 110; text: "PRIORITY"; color: theme.textMuted; font.pixelSize: 10; font.bold: true }
                        Text { Layout.preferredWidth: 110; text: "STATUS"; color: theme.textMuted; font.pixelSize: 10; font.bold: true }
                    }

                    Repeater {
                        model: root.casesModel || []
                        delegate: Rectangle {
                            required property var modelData
                            property bool accepted: root.matches(modelData)
                            Layout.fillWidth: true
                            Layout.preferredHeight: accepted ? 68 : 0
                            visible: accepted
                            radius: 10
                            color: root.selectedCase === modelData ? "#102C3B" : (caseMouse.containsMouse ? "#102230" : "transparent")
                            border.width: root.selectedCase === modelData ? 1 : 0
                            border.color: theme.primaryMuted

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 10
                                anchors.rightMargin: 10
                                spacing: 10
                                Rectangle { Layout.preferredWidth: 4; Layout.preferredHeight: 36; radius: 2; color: String(modelData.priority || "low").toLowerCase() === "high" ? theme.danger : (String(modelData.priority || "low").toLowerCase() === "medium" ? theme.warning : theme.primary) }
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 4
                                    Text { Layout.fillWidth: true; text: modelData.title; color: theme.textPrimary; font.pixelSize: 12; font.bold: true; elide: Text.ElideRight }
                                    Text { text: modelData.public_id; color: theme.textMuted; font.pixelSize: 10 }
                                }
                                SeverityBadge { Layout.preferredWidth: 110; severity: modelData.priority || "low" }
                                StatusBadge { Layout.preferredWidth: 110; status: modelData.status }
                            }

                            MouseArea { id: caseMouse; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: root.selectedCase = modelData }
                        }
                    }

                    EmptyState {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        visible: !root.casesModel || root.casesModel.length === 0
                        title: "No active cases"
                        message: "Escalate a finding to start a tracked analyst case."
                        code: "CS"
                    }
                }
            }

            Panel {
                Layout.preferredWidth: 430
                Layout.fillHeight: true
                title: root.selectedCase ? "Case Details" : "Case Workspace"
                subtitle: "Case context, workflow, and evidence"
                accentColor: root.selectedCase && String(root.selectedCase.priority || "").toLowerCase() === "high" ? theme.danger : "transparent"

                EmptyState {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    visible: root.selectedCase === null
                    title: "Select a case"
                    message: "Choose an active case to inspect priority, status, case identity, and analyst workflow."
                    code: "i"
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    visible: root.selectedCase !== null
                    spacing: 12

                    Text { Layout.fillWidth: true; text: root.selectedCase ? root.selectedCase.title : ""; color: theme.textPrimary; font.pixelSize: 17; font.bold: true; wrapMode: Text.WordWrap }
                    Text { text: root.selectedCase ? root.selectedCase.public_id : ""; color: theme.primary; font.pixelSize: 11; font.bold: true }
                    RowLayout {
                        spacing: 8

                        SeverityBadge {
                            severity: root.selectedCase ? (root.selectedCase.priority || "low") : "low"
                        }

                        StatusBadge {
                            status: root.selectedCase ? root.selectedCase.status : "open"
                        }
                    }

                    Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: theme.border }

                    GridLayout {
                        Layout.fillWidth: true
                        columns: 2
                        rowSpacing: 10
                        columnSpacing: 14
                        Text { text: "Created"; color: theme.textMuted; font.pixelSize: 11 }
                        Text { text: root.selectedCase && root.selectedCase.created_at ? root.selectedCase.created_at : "Not available"; color: theme.textSecondary; font.pixelSize: 11; elide: Text.ElideRight }
                        Text { text: "Workflow state"; color: theme.textMuted; font.pixelSize: 11 }
                        Text { text: root.selectedCase ? String(root.selectedCase.status).toUpperCase() : ""; color: theme.textSecondary; font.pixelSize: 11; font.bold: true }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 104
                        radius: 10
                        color: "#091925"
                        border.width: 1
                        border.color: theme.border
                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 12
                            spacing: 5
                            Text { text: "CASE WORKFLOW"; color: theme.primary; font.pixelSize: 10; font.bold: true }
                            Text { Layout.fillWidth: true; text: "Linked findings, analyst notes, activity history, evidence, resolution, close, and reopen actions will use this workspace."; color: theme.textSecondary; font.pixelSize: 11; wrapMode: Text.WordWrap }
                        }
                    }

                    Item { Layout.fillHeight: true }
                }
            }
        }

        Item { Layout.preferredHeight: 20 }
    }
}
