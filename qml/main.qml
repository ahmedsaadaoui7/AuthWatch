import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "components"
import "pages"

ApplicationWindow {
    id: root

    width: 1600
    height: 960
    minimumWidth: 1240
    minimumHeight: 760

    visible: true
    title: "AuthWatch — Security Operations"
    color: "#06111D"

    property int currentPage: 0
    property date currentDateTime: new Date()

    readonly property var applicationSettings:
        settingsViewModel
        ? settingsViewModel.settings
        : ({})

    readonly property string findingsDefaultSeverity: {
        var value = root.applicationSettings[
            "default_severity"
        ]

        if (value === "High")
            return "high"

        if (value === "Medium")
            return "medium"

        if (value === "Low")
            return "low"

        return "all"
    }

    readonly property bool openCompletedInvestigation:
        root.applicationSettings[
            "open_completed_investigation"
        ] !== undefined
        ? Boolean(
              root.applicationSettings[
                  "open_completed_investigation"
              ]
          )
        : true

    readonly property bool highSeverityVisualAlerts:
        root.applicationSettings[
            "high_severity_visual_alerts"
        ] !== undefined
        ? Boolean(
              root.applicationSettings[
                  "high_severity_visual_alerts"
              ]
          )
        : true

    BrandTheme {
        id: theme
    }

    readonly property var navigationItems: [
        { label: "Dashboard", code: "DB" },
        { label: "Analyze", code: "AN" },
        { label: "Findings", code: "FD" },
        { label: "Investigations", code: "IN" },
        { label: "Cases", code: "CS" },
        { label: "Settings", code: "ST" }
    ]

    function navigate(index) {
        currentPage = index

        if (index === 0 && dashboardViewModel) {
            dashboardViewModel.loadDashboard()
        }

        if (index === 2 && findingViewModel) {
            findingViewModel.loadFindings()
            findingsPage.applyDefaultSeverity()
        }

        if (index === 3 && investigationViewModel) {
            investigationViewModel.loadInvestigations()
        }

        if (index === 4 && caseViewModel) {
            caseViewModel.loadCases()
        }

        if (index === 5 && settingsViewModel) {
            settingsViewModel.loadSettings()
        }
    }

    Component.onCompleted: {
        if (dashboardViewModel) {
            dashboardViewModel.loadDashboard()
        }

        if (investigationViewModel) {
            investigationViewModel.loadInvestigations()
        }

        if (settingsViewModel) {
            settingsViewModel.loadSettings()
        }
    }

    Timer {
        interval: 1000
        running: true
        repeat: true

        onTriggered: root.currentDateTime = new Date()
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0

        Rectangle {
            Layout.preferredWidth: 270
            Layout.fillHeight: true

            color: theme.sidebar

            border.width: 1
            border.color: theme.border

            ColumnLayout {
                anchors.fill: parent

                anchors.leftMargin: 14
                anchors.rightMargin: 14
                anchors.topMargin: 14
                anchors.bottomMargin: 14

                spacing: 8

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 82

                    radius: 14
                    color: "#081A27"

                    border.width: 1
                    border.color: theme.border

                    RowLayout {
                        anchors.fill: parent

                        anchors.leftMargin: 12
                        anchors.rightMargin: 12

                        spacing: 12

                        Rectangle {
                            Layout.preferredWidth: 54
                            Layout.preferredHeight: 54

                            radius: 14
                            color: "#06131F"

                            border.width: 1
                            border.color: theme.borderStrong

                            LogoMark {
                                anchors.centerIn: parent
                                preferredSize: 48
                            }
                        }

                        ColumnLayout {
                            Layout.fillWidth: true
                            spacing: 3

                            Text {
                                text: "AUTHWATCH"
                                color: theme.textPrimary

                                font.pixelSize: 16
                                font.bold: true
                                font.letterSpacing: 0.8
                            }

                            Text {
                                text: "SECURITY OPERATIONS"
                                color: theme.primary

                                font.pixelSize: 10
                                font.bold: true
                                font.letterSpacing: 0.9
                            }

                            Text {
                                text: "LOCAL SOC · V4"
                                color: theme.textMuted

                                font.pixelSize: 10
                            }
                        }
                    }
                }

                Text {
                    Layout.fillWidth: true
                    Layout.leftMargin: 8
                    Layout.topMargin: 8
                    Layout.bottomMargin: 2

                    text: "OPERATIONS"
                    color: theme.textMuted

                    font.pixelSize: 10
                    font.bold: true
                    font.letterSpacing: 0.8
                }

                Repeater {
                    model: root.navigationItems

                    delegate: SidebarItem {
                        required property var modelData
                        required property int index

                        text: modelData.label
                        shortCode: modelData.code

                        active: root.currentPage === index

                        onClicked: root.navigate(index)
                    }
                }

                Item {
                    Layout.fillHeight: true
                }

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 102

                    radius: 12
                    color: "#081A27"

                    border.width: 1
                    border.color: theme.border

                    ColumnLayout {
                        anchors.fill: parent
                        anchors.margins: 12

                        spacing: 6

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8

                            Rectangle {
                                Layout.preferredWidth: 8
                                Layout.preferredHeight: 8

                                radius: 4
                                color: theme.success
                            }

                            Text {
                                text: "SYSTEM ACTIVE"
                                color: theme.success

                                font.pixelSize: 10
                                font.bold: true
                                font.letterSpacing: 0.4
                            }

                            Item {
                                Layout.fillWidth: true
                            }
                        }

                        Text {
                            text: "Local SQLite database"
                            color: theme.textSecondary
                            font.pixelSize: 11
                        }

                        Text {
                            text: "AuthWatch V3 engine"
                            color: theme.textMuted
                            font.pixelSize: 11
                        }

                        Text {
                            text: "Offline-first workflow"
                            color: theme.textMuted
                            font.pixelSize: 11
                        }
                    }
                }

                Text {
                    Layout.fillWidth: true
                    Layout.leftMargin: 6

                    text: "AuthWatch V4 · Local build"
                    color: theme.textDim

                    font.pixelSize: 10
                }
            }
        }

        Rectangle {
            Layout.fillWidth: true
            Layout.fillHeight: true

            color: theme.background

            ColumnLayout {
                anchors.fill: parent
                spacing: 0

                Rectangle {
                    Layout.fillWidth: true
                    Layout.preferredHeight: 60

                    color: theme.topbar

                    border.width: 1
                    border.color: theme.border

                    RowLayout {
                        anchors.fill: parent

                        anchors.leftMargin: 22
                        anchors.rightMargin: 22

                        spacing: 12

                        Text {
                            text: root.navigationItems[root.currentPage].label
                            color: theme.textPrimary

                            font.pixelSize: 14
                            font.bold: true
                        }

                        Text {
                            text: "·"
                            color: theme.textDim
                            font.pixelSize: 14
                        }

                        Text {
                            text: "AUTHENTICATION RADAR"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                            font.letterSpacing: 0.7
                        }

                        Item {
                            Layout.fillWidth: true
                        }

                        Rectangle {
                            Layout.preferredWidth: 112
                            Layout.preferredHeight: 32

                            radius: 9
                            color: "#0C2529"

                            border.width: 1
                            border.color: "#1A5D5F"

                            RowLayout {
                                anchors.centerIn: parent
                                spacing: 6

                                Rectangle {
                                    Layout.preferredWidth: 7
                                    Layout.preferredHeight: 7

                                    radius: 4
                                    color: theme.success
                                }

                                Text {
                                    text: "LOCAL MODE"
                                    color: theme.success

                                    font.pixelSize: 10
                                    font.bold: true
                                }
                            }
                        }

                        Rectangle {
                            Layout.preferredWidth: 108
                            Layout.preferredHeight: 32

                            radius: 9
                            color: "#0C2130"

                            border.width: 1
                            border.color: theme.borderStrong

                            RowLayout {
                                anchors.centerIn: parent
                                spacing: 6

                                Rectangle {
                                    Layout.preferredWidth: 7
                                    Layout.preferredHeight: 7

                                    radius: 4
                                    color: theme.primary
                                }

                                Text {
                                    text: "V3 ENGINE"
                                    color: theme.primaryBright

                                    font.pixelSize: 10
                                    font.bold: true
                                }
                            }
                        }

                        Text {
                            text: Qt.formatDateTime(
                                      root.currentDateTime,
                                      "ddd, dd MMM · HH:mm:ss"
                                  )

                            color: theme.textSecondary
                            font.pixelSize: 11
                        }
                    }
                }

                StackLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    currentIndex: root.currentPage

                    DashboardPage {
                        viewModel: dashboardViewModel

                        onOpenAnalyzeRequested:
                            root.navigate(1)

                        onOpenFindingsRequested:
                            root.navigate(2)

                        onOpenCasesRequested:
                            root.navigate(4)
                    }

                    AnalyzePage {
                        onAnalysisRequested: function(payload) {
                            analysisViewModel.startAnalysis(
                                payload
                            )
                        }
                    }

                    FindingsPage {
                        id: findingsPage

                        viewModel: findingViewModel
                        defaultSeverity:
                            root.findingsDefaultSeverity
                        highSeverityVisualAlerts:
                            root.highSeverityVisualAlerts

                        onOpenAnalyzeRequested:
                            root.navigate(1)

                        onEscalateRequested: function(finding) {
                            if (!finding || !caseViewModel)
                                return

                            caseViewModel.createFromFinding(
                                finding.id,
                                finding.title,
                                finding.severity
                            )
                        }
                    }

                    InvestigationsPage {
                        viewModel: investigationViewModel

                        onAnalyzeRequested:
                            root.navigate(1)
                    }

                    CasesPage {
                        viewModel: caseViewModel

                        onOpenFindingWorkflowRequested:
                            root.navigate(2)
                    }

                    SettingsPage {
                        viewModel: settingsViewModel
                    }
                }
            }

            Toast {
                id: globalToast

                anchors.right: parent.right
                anchors.rightMargin: 22

                anchors.bottom: parent.bottom
                anchors.bottomMargin: 22

                z: 100
            }

            Connections {
                target: analysisViewModel

                function onErrorChanged() {
                    if (
                        analysisViewModel.errorMessage !== ""
                    ) {
                        globalToast.show(
                            analysisViewModel.errorMessage,
                            "error"
                        )
                    }
                }

                function onAnalysisCompleted() {
                    globalToast.show(
                        analysisViewModel.statusMessage,
                        "success"
                    )

                    dashboardViewModel.loadDashboard()

                    findingViewModel.loadFindings()

                    investigationViewModel.loadInvestigations()

                    if (
                        root.openCompletedInvestigation
                        && investigationViewModel.investigations
                        && investigationViewModel.investigations.length > 0
                    ) {
                        var newestInvestigation = null

                        for (
                            var index = 0;
                            index < investigationViewModel.investigations.length;
                            ++index
                        ) {
                            var candidate =
                                investigationViewModel.investigations[index]

                            if (
                                newestInvestigation === null
                                || Number(candidate.id)
                                   > Number(newestInvestigation.id)
                            ) {
                                newestInvestigation = candidate
                            }
                        }

                        if (newestInvestigation !== null) {
                            root.navigate(3)

                            investigationViewModel.selectInvestigation(
                                newestInvestigation.id
                            )
                        }
                    }
                }
            }

            Connections {
                target: investigationViewModel

                function onErrorChanged() {
                    if (
                        investigationViewModel.errorMessage !== ""
                    ) {
                        globalToast.show(
                            investigationViewModel.errorMessage,
                            "error"
                        )
                    }
                }

                function onExportCompleted(outputPath) {
                    globalToast.show(
                        "Investigation exported successfully.",
                        "success"
                    )
                }
            }

            Connections {
                target: findingViewModel

                function onErrorChanged() {
                    if (
                        findingViewModel.errorMessage !== ""
                    ) {
                        globalToast.show(
                            findingViewModel.errorMessage,
                            "error"
                        )
                    }
                }

                function onFindingUpdated() {
                    globalToast.show(
                        "Finding marked as reviewed.",
                        "success"
                    )

                    dashboardViewModel.loadDashboard()
                }
            }

            Connections {
                target: caseViewModel

                function onErrorChanged() {
                    if (
                        caseViewModel.errorMessage !== ""
                    ) {
                        globalToast.show(
                            caseViewModel.errorMessage,
                            "error"
                        )
                    }
                }

                function onCaseCreated(caseId) {
                    globalToast.show(
                        "Finding escalated to a new case.",
                        "success"
                    )

                    findingViewModel.loadFindings()
                    dashboardViewModel.loadDashboard()

                    root.navigate(4)
                    caseViewModel.selectCase(caseId)
                }

                function onCaseActionCompleted(message) {
                    globalToast.show(
                        message,
                        "success"
                    )

                    findingViewModel.loadFindings()
                    dashboardViewModel.loadDashboard()
                }
            }

            Connections {
                target: settingsViewModel

                function onErrorChanged() {
                    if (
                        settingsViewModel.errorMessage !== ""
                    ) {
                        globalToast.show(
                            settingsViewModel.errorMessage,
                            "error"
                        )
                    }
                }

                function onSettingSaved(key) {
                    globalToast.show(
                        "Setting saved locally.",
                        "success"
                    )
                }
            }
        }
    }
}
