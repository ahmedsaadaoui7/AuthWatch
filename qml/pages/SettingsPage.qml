import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: root

    property int selectedSection: 0
    property string interfaceDensity: "Comfortable"
    property string uiScale: "100%"
    property bool animationsEnabled: true
    property string defaultSeverity: "All severities"
    property bool openCompletedInvestigation: true
    property bool confirmLargeAnalysis: true
    property bool highSeverityVisualAlerts: true
    property bool alertSound: false
    property bool stickyHighAlerts: true

    readonly property var categories: [
        { label: "Appearance", code: "UI" },
        { label: "Analysis", code: "AN" },
        { label: "Alerts", code: "AL" },
        { label: "Data & Privacy", code: "DB" },
        { label: "About", code: "AW" }
    ]

    BrandTheme { id: theme }

    ColumnLayout {
        anchors.fill: parent
        anchors.leftMargin: 24
        anchors.rightMargin: 24
        spacing: 16

        Item {
            Layout.fillWidth: true
            Layout.preferredHeight: 104
            ColumnLayout {
                anchors.verticalCenter: parent.verticalCenter
                spacing: 6
                Text { text: "Settings"; color: theme.textPrimary; font.pixelSize: 28; font.bold: true }
                Text { text: "Configure the AuthWatch desktop experience, analysis behavior, alerts, and local data preferences."; color: theme.textSecondary; font.pixelSize: 13 }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 14

            Rectangle {
                Layout.preferredWidth: 230
                Layout.fillHeight: true
                radius: 16
                color: theme.surface
                border.width: 1
                border.color: theme.border

                ColumnLayout {
                    anchors.fill: parent
                    anchors.margins: 12
                    spacing: 6

                    Text { Layout.fillWidth: true; Layout.leftMargin: 8; Layout.topMargin: 4; Layout.bottomMargin: 6; text: "SETTINGS"; color: theme.textMuted; font.pixelSize: 10; font.bold: true; font.letterSpacing: 0.6 }

                    Repeater {
                        model: root.categories
                        delegate: Rectangle {
                            required property var modelData
                            required property int index
                            Layout.fillWidth: true
                            Layout.preferredHeight: 46
                            radius: 10
                            color: root.selectedSection === index ? "#0E2B38" : (categoryMouse.containsMouse ? "#0D202D" : "transparent")
                            border.width: root.selectedSection === index ? 1 : 0
                            border.color: root.selectedSection === index ? "#1D6071" : "transparent"

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 10
                                anchors.rightMargin: 10
                                spacing: 10
                                Rectangle {
                                    Layout.preferredWidth: 28
                                    Layout.preferredHeight: 28
                                    radius: 8
                                    color: root.selectedSection === index ? "#123B49" : "#0B1B28"
                                    border.width: 1
                                    border.color: root.selectedSection === index ? "#286A7A" : theme.border
                                    Text { anchors.centerIn: parent; text: modelData.code; color: root.selectedSection === index ? theme.primaryBright : theme.textMuted; font.pixelSize: 10; font.bold: true }
                                }
                                Text { Layout.fillWidth: true; text: modelData.label; color: root.selectedSection === index ? theme.textPrimary : theme.textSecondary; font.pixelSize: 12; font.bold: root.selectedSection === index }
                            }

                            MouseArea { id: categoryMouse; anchors.fill: parent; hoverEnabled: true; cursorShape: Qt.PointingHandCursor; onClicked: root.selectedSection = index }
                        }
                    }

                    Item { Layout.fillHeight: true }

                    Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 94
                        radius: 12
                        color: "#091925"
                        border.width: 1
                        border.color: theme.border
                        ColumnLayout {
                            anchors.fill: parent
                            anchors.margins: 12
                            spacing: 4
                            RowLayout {
                                spacing: 8

                                LogoMark { preferredSize: 28 }

                                Text {
                                    text: "AuthWatch V4"
                                    color: theme.textPrimary
                                    font.pixelSize: 12
                                    font.bold: true
                                }
                            }
                            Text { text: "Local SOC desktop"; color: theme.textMuted; font.pixelSize: 10 }
                            Text { text: "V3 detection engine"; color: theme.textDim; font.pixelSize: 10 }
                        }
                    }
                }
            }

            StackLayout {
                Layout.fillWidth: true
                Layout.fillHeight: true
                currentIndex: root.selectedSection

                ScrollView {
                    id: appearanceScroll
                    clip: true
                    contentWidth: availableWidth
                    ColumnLayout {
                        width: Math.max(0, appearanceScroll.availableWidth - 2)
                        spacing: 14

                        Panel {
                            Layout.fillWidth: true
                            Layout.preferredHeight: Math.ceil(implicitHeight)
                            title: "Appearance"
                            subtitle: "Choose how the AuthWatch desktop interface is presented"

                            SettingRow {
                                title: "Interface density"
                                description: "Comfortable spacing improves readability; compact mode fits more analyst rows on screen."
                                BrandComboBox {
                                    model: ["Comfortable", "Compact"]
                                    currentIndex: root.interfaceDensity === "Compact" ? 1 : 0
                                    onActivated: root.interfaceDensity = currentText
                                }
                            }
                            Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: theme.border }
                            SettingRow {
                                title: "Interface scale"
                                description: "Increase interface size on high-DPI displays or when you prefer larger controls."
                                BrandComboBox {
                                    model: ["100%", "110%", "125%"]
                                    currentIndex: root.uiScale === "125%" ? 2 : (root.uiScale === "110%" ? 1 : 0)
                                    onActivated: root.uiScale = currentText
                                }
                            }
                            Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: theme.border }
                            SettingRow {
                                title: "Subtle interface animations"
                                description: "Use short transitions for navigation, switches, and status changes."
                                BrandSwitch { checked: root.animationsEnabled; onToggled: root.animationsEnabled = value }
                            }
                        }

                        Panel {
                            Layout.fillWidth: true
                            Layout.preferredHeight: Math.ceil(implicitHeight)
                            title: "Brand & Theme"
                            subtitle: "AuthWatch uses the Authentication Radar identity across the desktop application"

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 16
                                Rectangle {
                                    Layout.preferredWidth: 82
                                    Layout.preferredHeight: 82
                                    radius: 18
                                    color: "#07131F"
                                    border.width: 1
                                    border.color: theme.borderStrong
                                    LogoMark { anchors.centerIn: parent; preferredSize: 70 }
                                }
                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 5
                                    Text { text: "Authentication Radar"; color: theme.textPrimary; font.pixelSize: 16; font.bold: true }
                                    Text { Layout.fillWidth: true; text: "Deep navy, cyan/teal, and cool white form the primary identity. Red is reserved for high-severity security states."; color: theme.textSecondary; font.pixelSize: 11; wrapMode: Text.WordWrap }
                                }
                            }
                        }

                        Item { Layout.preferredHeight: 20 }
                    }
                }

                ScrollView {
                    id: analysisScroll
                    clip: true
                    contentWidth: availableWidth
                    ColumnLayout {
                        width: Math.max(0, analysisScroll.availableWidth - 2)
                        spacing: 14

                        Panel {
                            Layout.fillWidth: true
                            Layout.preferredHeight: Math.ceil(implicitHeight)
                            title: "Analysis Behavior"
                            subtitle: "Preferences used when starting and completing investigations"

                            SettingRow {
                                title: "Default findings severity view"
                                description: "Choose which severity group the Findings page should emphasize first."
                                BrandComboBox {
                                    model: ["All severities", "High", "Medium", "Low"]
                                    currentIndex: Math.max(0, model.indexOf(root.defaultSeverity))
                                    onActivated: root.defaultSeverity = currentText
                                }
                            }
                            Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: theme.border }
                            SettingRow {
                                title: "Open completed investigation automatically"
                                description: "Move directly to investigation details after a successful analysis run."
                                BrandSwitch { checked: root.openCompletedInvestigation; onToggled: root.openCompletedInvestigation = value }
                            }
                            Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: theme.border }
                            SettingRow {
                                title: "Confirm large analysis requests"
                                description: "Ask for confirmation before processing very large telemetry sources."
                                BrandSwitch { checked: root.confirmLargeAnalysis; onToggled: root.confirmLargeAnalysis = value }
                            }
                        }

                        Panel {
                            Layout.fillWidth: true
                            Layout.preferredHeight: Math.ceil(implicitHeight)
                            title: "Analysis Engine"
                            subtitle: "Current runtime foundation"
                            SettingRow { title: "Detection and correlation engine"; description: "AuthWatch V3 — Endpoint Telemetry & Event Correlation"; Rectangle { implicitWidth: 82; implicitHeight: 28; radius: 8; color: theme.successSoft; border.width: 1; border.color: "#1D6752"; Text { anchors.centerIn: parent; text: "ACTIVE"; color: theme.success; font.pixelSize: 10; font.bold: true } } }
                        }

                        Item { Layout.preferredHeight: 20 }
                    }
                }

                ScrollView {
                    id: alertsScroll
                    clip: true
                    contentWidth: availableWidth
                    ColumnLayout {
                        width: Math.max(0, alertsScroll.availableWidth - 2)
                        spacing: 14

                        Panel {
                            Layout.fillWidth: true
                            Layout.preferredHeight: Math.ceil(implicitHeight)
                            title: "Analyst Alerts"
                            subtitle: "Control how AuthWatch presents urgent security states"
                            accentColor: theme.danger

                            SettingRow {
                                title: "High-severity visual alerts"
                                description: "Show a prominent red attention banner when high-severity findings exist."
                                BrandSwitch { checked: root.highSeverityVisualAlerts; onToggled: root.highSeverityVisualAlerts = value }
                            }
                            Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: theme.border }
                            SettingRow {
                                title: "Local alert sound"
                                description: "Play a local notification sound when new high-severity findings are surfaced."
                                BrandSwitch { checked: root.alertSound; onToggled: root.alertSound = value }
                            }
                            Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: theme.border }
                            SettingRow {
                                title: "Keep urgent banner visible"
                                description: "Do not dismiss the high-severity banner until the analyst reviews the queue."
                                BrandSwitch { checked: root.stickyHighAlerts; onToggled: root.stickyHighAlerts = value }
                            }
                        }

                        Panel {
                            Layout.fillWidth: true
                            Layout.preferredHeight: Math.ceil(implicitHeight)
                            title: "High-Severity Alert Preview"
                            subtitle: "Preview only — this is not a live security finding"
                            AlertBanner {
                                Layout.fillWidth: true
                                count: 3
                                title: "High-severity findings require analyst attention"
                                message: "Urgent findings use a dedicated red state while the AuthWatch brand remains cyan and navy."
                                actionText: "Review findings"
                            }
                        }

                        Item { Layout.preferredHeight: 20 }
                    }
                }

                ScrollView {
                    id: dataScroll
                    clip: true
                    contentWidth: availableWidth
                    ColumnLayout {
                        width: Math.max(0, dataScroll.availableWidth - 2)
                        spacing: 14

                        Panel {
                            Layout.fillWidth: true
                            Layout.preferredHeight: Math.ceil(implicitHeight)
                            title: "Local Data & Privacy"
                            subtitle: "AuthWatch V4 is designed for local SOC operation"

                            SettingRow {
                                title: "Runtime database"
                                description: "Stored in the operating-system application-data directory."
                                Rectangle { implicitWidth: 110; implicitHeight: 28; radius: 8; color: "#0D2B38"; border.width: 1; border.color: theme.borderStrong; Text { anchors.centerIn: parent; text: "LOCAL SQLITE"; color: theme.primary; font.pixelSize: 10; font.bold: true } }
                            }
                            Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: theme.border }
                            SettingRow {
                                title: "Telemetry retention"
                                description: "Normalized events required to reconstruct investigations are stored locally."
                                Rectangle { implicitWidth: 86; implicitHeight: 28; radius: 8; color: theme.successSoft; border.width: 1; border.color: "#1D6752"; Text { anchors.centerIn: parent; text: "ENABLED"; color: theme.success; font.pixelSize: 10; font.bold: true } }
                            }
                            Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: theme.border }
                            SettingRow {
                                title: "Original telemetry files"
                                description: "Original source files are not automatically duplicated for permanent V4 retention."
                                Rectangle { implicitWidth: 118; implicitHeight: 28; radius: 8; color: "#0F2530"; border.width: 1; border.color: theme.border; Text { anchors.centerIn: parent; text: "NO DUPLICATION"; color: theme.textSecondary; font.pixelSize: 10; font.bold: true } }
                            }
                            Rectangle { Layout.fillWidth: true; Layout.preferredHeight: 1; color: theme.border }
                            SettingRow {
                                title: "Cloud dependency"
                                description: "No cloud service is required for the V4 local desktop workflow."
                                Rectangle { implicitWidth: 74; implicitHeight: 28; radius: 8; color: theme.successSoft; border.width: 1; border.color: "#1D6752"; Text { anchors.centerIn: parent; text: "NONE"; color: theme.success; font.pixelSize: 10; font.bold: true } }
                            }
                        }

                        Panel {
                            Layout.fillWidth: true
                            Layout.preferredHeight: Math.ceil(implicitHeight)
                            title: "Database Location"
                            subtitle: "Typical Linux location"
                            Rectangle {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 48
                                radius: 9
                                color: "#081722"
                                border.width: 1
                                border.color: theme.border
                                Text { anchors.fill: parent; anchors.leftMargin: 12; anchors.rightMargin: 12; verticalAlignment: Text.AlignVCenter; text: "~/.local/share/AuthWatch/authwatch.db"; color: theme.textSecondary; font.pixelSize: 12; font.family: "monospace"; elide: Text.ElideMiddle }
                            }
                        }

                        Item { Layout.preferredHeight: 20 }
                    }
                }

                ScrollView {
                    id: aboutScroll
                    clip: true
                    contentWidth: availableWidth
                    ColumnLayout {
                        width: Math.max(0, aboutScroll.availableWidth - 2)
                        spacing: 14

                        Panel {
                            Layout.fillWidth: true
                            Layout.preferredHeight: Math.ceil(implicitHeight)
                            title: "About AuthWatch"
                            subtitle: "Authentication Threat Detection & SOC Investigation Platform"

                            RowLayout {
                                Layout.fillWidth: true
                                spacing: 22

                                Rectangle {
                                    Layout.preferredWidth: 118
                                    Layout.preferredHeight: 118
                                    radius: 26
                                    color: "#07131F"
                                    border.width: 1
                                    border.color: theme.borderStrong
                                    LogoMark { anchors.centerIn: parent; preferredSize: 102 }
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 6
                                    Text { text: "AUTHWATCH"; color: theme.textPrimary; font.pixelSize: 24; font.bold: true; font.letterSpacing: 1.0 }
                                    Text { text: "SECURITY OPERATIONS"; color: theme.primary; font.pixelSize: 11; font.bold: true; font.letterSpacing: 1.4 }
                                    Text { text: "V4 — Local SOC Dashboard & Case Management"; color: theme.textSecondary; font.pixelSize: 13 }
                                    Text { Layout.fillWidth: true; text: "Engine foundation: AuthWatch V3 — Endpoint Telemetry & Event Correlation"; color: theme.textMuted; font.pixelSize: 11; wrapMode: Text.WordWrap }
                                }
                            }
                        }

                        Panel {
                            Layout.fillWidth: true
                            Layout.preferredHeight: Math.ceil(implicitHeight)
                            title: "Technology"
                            subtitle: "Desktop and persistence stack"

                            GridLayout {
                                Layout.fillWidth: true
                                columns: 2
                                rowSpacing: 10
                                columnSpacing: 20
                                Text { text: "Desktop UI"; color: theme.textMuted; font.pixelSize: 11 }
                                Text { text: "PySide6 · Qt Quick / QML"; color: theme.textSecondary; font.pixelSize: 12; font.bold: true }
                                Text { text: "Persistence"; color: theme.textMuted; font.pixelSize: 11 }
                                Text { text: "SQLite · SQLAlchemy · Alembic"; color: theme.textSecondary; font.pixelSize: 12; font.bold: true }
                                Text { text: "Runtime"; color: theme.textMuted; font.pixelSize: 11 }
                                Text { text: "Python"; color: theme.textSecondary; font.pixelSize: 12; font.bold: true }
                                Text { text: "Brand identity"; color: theme.textMuted; font.pixelSize: 11 }
                                Text { text: "Authentication Radar"; color: theme.primary; font.pixelSize: 12; font.bold: true }
                            }
                        }

                        Item { Layout.preferredHeight: 20 }
                    }
                }
            }
        }

        Item { Layout.preferredHeight: 20 }
    }
}
