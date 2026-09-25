import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: root
    property var viewModel
    signal openAnalyzeRequested()
    signal openFindingsRequested()
    signal openCasesRequested()

    BrandTheme { id: theme }

    readonly property int totalFindings: root.viewModel ? root.viewModel.totalFindings : 0
    readonly property int highFindings: root.viewModel ? root.viewModel.highFindings : 0
    readonly property int mediumFindings: root.viewModel ? root.viewModel.mediumFindings : 0
    readonly property int activeCases: root.viewModel ? root.viewModel.openCases : 0

    ScrollView {
        id: scroll
        anchors.fill: parent
        clip: true
        contentWidth: availableWidth

        ColumnLayout {
            width: Math.max(1040, scroll.availableWidth - 48)
            x: 24
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
                        Text { text: "Security Operations Dashboard"; color: theme.textPrimary; font.pixelSize: 28; font.bold: true }
                        Text { text: "Live operational view of AuthWatch findings, affected entities, and analyst workload."; color: theme.textSecondary; font.pixelSize: 13 }
                    }

                    SecondaryButton { text: "Refresh"; onClicked: if (root.viewModel) root.viewModel.loadDashboard() }
                    PrimaryButton { text: "Analyze telemetry"; onClicked: root.openAnalyzeRequested() }
                }
            }

            AlertBanner {
                visible: root.highFindings > 0
                count: root.highFindings
                onActionClicked: root.openFindingsRequested()
            }

            RowLayout {
                Layout.fillWidth: true
                spacing: 14

                MetricCard { code: "FD"; label: "TOTAL FINDINGS"; value: root.totalFindings; helper: "Detections and correlations"; accentColor: theme.primary; valueColor: theme.textPrimary }
                MetricCard { code: "HI"; label: "HIGH SEVERITY"; value: root.highFindings; helper: "Priority analyst review"; accentColor: theme.danger; valueColor: root.highFindings > 0 ? theme.danger : theme.textPrimary; critical: true }
                MetricCard { code: "CS"; label: "ACTIVE CASES"; value: root.activeCases; helper: "Open and investigating"; accentColor: theme.primary; valueColor: theme.textPrimary }
                MetricCard { code: "MD"; label: "MEDIUM FINDINGS"; value: root.mediumFindings; helper: "Contextual review queue"; accentColor: theme.warning; valueColor: theme.textPrimary }
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.preferredHeight: 320
                spacing: 14

                Panel {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    Layout.preferredWidth: 2.25
                    title: "Finding Activity"
                    subtitle: "First-seen findings grouped by day"
                    ActivityChart { Layout.fillWidth: true; Layout.fillHeight: true; points: root.viewModel ? root.viewModel.findingsOverTime : [] }
                }

                Panel {
                    Layout.preferredWidth: 330
                    Layout.fillHeight: true
                    title: "Severity Exposure"
                    subtitle: "How much of the current finding set is high severity"
                    SeverityGauge { Layout.fillWidth: true; Layout.fillHeight: true; total: root.totalFindings; high: root.highFindings; medium: root.mediumFindings }
                }
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.preferredHeight: 218
                spacing: 14

                EntityRankCard { Layout.fillWidth: true; Layout.fillHeight: true; code: "US"; title: "Top Affected Users"; subtitle: "Users referenced by findings"; items: root.viewModel ? root.viewModel.topUsers : [] }
                EntityRankCard { Layout.fillWidth: true; Layout.fillHeight: true; code: "HS"; title: "Top Affected Hosts"; subtitle: "Hosts referenced by findings"; items: root.viewModel ? root.viewModel.topHosts : [] }
                EntityRankCard { Layout.fillWidth: true; Layout.fillHeight: true; code: "IP"; title: "Top Source IPs"; subtitle: "Source addresses in findings"; items: root.viewModel ? root.viewModel.topSourceIps : [] }
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.preferredHeight: 314
                spacing: 14

                Panel {
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    Layout.preferredWidth: 2.15
                    title: "Recent High-Severity Findings"
                    subtitle: "Priority detections requiring analyst attention"
                    accentColor: root.highFindings > 0 ? theme.danger : "transparent"

                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        spacing: 6

                        RowLayout {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 28
                            visible: root.viewModel && root.viewModel.recentHighFindings.length > 0
                            Text { Layout.fillWidth: true; text: "FINDING"; color: theme.textMuted; font.pixelSize: 10; font.bold: true }
                            Text { Layout.preferredWidth: 130; text: "RULE ID"; color: theme.textMuted; font.pixelSize: 10; font.bold: true }
                            Text { Layout.preferredWidth: 96; text: "STATUS"; color: theme.textMuted; font.pixelSize: 10; font.bold: true }
                        }

                        Repeater {
                            model: root.viewModel ? root.viewModel.recentHighFindings.slice(0, 4) : []
                            delegate: Rectangle {
                                required property var modelData
                                Layout.fillWidth: true
                                Layout.preferredHeight: 50
                                radius: 9
                                color: findingMouse.containsMouse ? "#132333" : "#0A1723"
                                border.width: 1
                                border.color: findingMouse.containsMouse ? theme.dangerBorder : theme.border

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: 12
                                    anchors.rightMargin: 10
                                    spacing: 10
                                    Rectangle { Layout.preferredWidth: 4; Layout.preferredHeight: 26; radius: 2; color: theme.danger }
                                    Text { Layout.fillWidth: true; text: modelData.title; color: theme.textPrimary; font.pixelSize: 12; font.bold: true; elide: Text.ElideRight }
                                    Text { Layout.preferredWidth: 130; text: modelData.rule_id; color: theme.textSecondary; font.pixelSize: 11; elide: Text.ElideRight }
                                    StatusBadge { Layout.preferredWidth: 96; status: modelData.status }
                                }
                                MouseArea { id: findingMouse; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: root.openFindingsRequested() }
                            }
                        }

                        EmptyState {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            visible: !root.viewModel || root.viewModel.recentHighFindings.length === 0
                            title: "No high-severity findings"
                            message: "Priority findings will appear here after telemetry analysis."
                            code: "OK"
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            visible: root.viewModel && root.viewModel.recentHighFindings.length > 0
                            Item { Layout.fillWidth: true }
                            SecondaryButton { text: "Open findings queue"; onClicked: root.openFindingsRequested() }
                        }
                    }
                }

                Panel {
                    Layout.preferredWidth: 360
                    Layout.fillHeight: true
                    title: "Active Cases"
                    subtitle: "Open analyst investigations and escalations"

                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.fillHeight: true
                        spacing: 7

                        Repeater {
                            model: root.viewModel ? root.viewModel.activeCases.slice(0, 4) : []
                            delegate: Rectangle {
                                required property var modelData
                                Layout.fillWidth: true
                                Layout.preferredHeight: 54
                                radius: 9
                                color: caseMouse.containsMouse ? "#102332" : "#0A1723"
                                border.width: 1
                                border.color: caseMouse.containsMouse ? theme.borderStrong : theme.border

                                RowLayout {
                                    anchors.fill: parent
                                    anchors.leftMargin: 12
                                    anchors.rightMargin: 10
                                    spacing: 9
                                    ColumnLayout {
                                        Layout.fillWidth: true
                                        spacing: 3
                                        Text { Layout.fillWidth: true; text: modelData.title; color: theme.textPrimary; font.pixelSize: 12; font.bold: true; elide: Text.ElideRight }
                                        Text { text: modelData.public_id; color: theme.textMuted; font.pixelSize: 10 }
                                    }
                                    StatusBadge { status: modelData.status }
                                }
                                MouseArea { id: caseMouse; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: root.openCasesRequested() }
                            }
                        }

                        EmptyState {
                            Layout.fillWidth: true
                            Layout.fillHeight: true
                            visible: !root.viewModel || root.viewModel.activeCases.length === 0
                            title: "No active cases"
                            message: "Escalated findings will appear here as active SOC cases."
                            code: "CS"
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            visible: root.viewModel && root.viewModel.activeCases.length > 0
                            Item { Layout.fillWidth: true }
                            SecondaryButton { text: "Open cases"; onClicked: root.openCasesRequested() }
                        }
                    }
                }
            }

            Item { Layout.preferredHeight: 24 }
        }
    }
}
