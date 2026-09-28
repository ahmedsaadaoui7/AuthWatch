import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import QtQuick.Layouts
import "../components"

Item {
    id: root

    property var viewModel: null

    property string windowsPath: ""
    property string sysmonPath: ""
    property string linuxPath: ""
    property string authwatchPath: ""
    property string linuxYear: new Date().getFullYear().toString()
    property string linuxUtcOffset: "+00:00"
    property string investigationName: ""

    signal analysisRequested(var payload)

    BrandTheme { id: theme }

    readonly property bool hasTelemetry:
        windowsPath !== "" ||
        sysmonPath !== "" ||
        linuxPath !== "" ||
        authwatchPath !== ""

    readonly property bool analysisRunning:
        root.viewModel
        ? root.viewModel.running
        : false

    readonly property string analysisStatus:
        root.viewModel
        ? root.viewModel.statusMessage
        : ""

    readonly property int selectedSourceCount:
        (windowsPath !== "" ? 1 : 0) +
        (sysmonPath !== "" ? 1 : 0) +
        (linuxPath !== "" ? 1 : 0) +
        (authwatchPath !== "" ? 1 : 0)

    function urlText(urlValue) {
        return urlValue ? urlValue.toString() : ""
    }

    FileDialog {
        id: windowsDialog
        title: "Select Windows Security telemetry"
        onAccepted: root.windowsPath = root.urlText(selectedFile)
    }

    FileDialog {
        id: sysmonDialog
        title: "Select Sysmon telemetry"
        onAccepted: root.sysmonPath = root.urlText(selectedFile)
    }

    FileDialog {
        id: linuxDialog
        title: "Select Linux authentication log"
        onAccepted: root.linuxPath = root.urlText(selectedFile)
    }

    FileDialog {
        id: authwatchDialog
        title: "Select AuthWatch CSV or JSON"
        onAccepted: root.authwatchPath = root.urlText(selectedFile)
    }

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

                        Text {
                            text: "Analyze Telemetry"
                            color: theme.textPrimary
                            font.pixelSize: 28
                            font.bold: true
                        }

                        Text {
                            text: "Create a new AuthWatch investigation from local endpoint and authentication telemetry."
                            color: theme.textSecondary
                            font.pixelSize: 13
                        }
                    }

                    Rectangle {
                        Layout.preferredWidth: 124
                        Layout.preferredHeight: 36

                        radius: 10
                        color: root.hasTelemetry ? "#0F2A2D" : "#0D1B27"

                        border.width: 1
                        border.color: root.hasTelemetry
                                      ? "#1B626B"
                                      : theme.border

                        Text {
                            anchors.centerIn: parent

                            text: root.selectedSourceCount
                                  + " SOURCE"
                                  + (root.selectedSourceCount === 1 ? "" : "S")

                            color: root.hasTelemetry
                                   ? theme.primaryBright
                                   : theme.textMuted

                            font.pixelSize: 11
                            font.bold: true
                        }
                    }
                }
            }

            Rectangle {
                Layout.fillWidth: true
                Layout.preferredHeight: 74

                radius: 14
                color: theme.surface

                border.width: 1
                border.color: theme.border

                RowLayout {
                    anchors.fill: parent
                    anchors.leftMargin: 22
                    anchors.rightMargin: 22

                    spacing: 16

                    Repeater {
                        model: [
                            {
                                number: "1",
                                title: "Select telemetry",
                                active: true
                            },
                            {
                                number: "2",
                                title: "Configure context",
                                active: root.hasTelemetry
                            },
                            {
                                number: "3",
                                title: "Run investigation",
                                active: root.hasTelemetry
                            }
                        ]

                        delegate: RowLayout {
                            required property var modelData

                            Layout.fillWidth: true
                            spacing: 10

                            Rectangle {
                                Layout.preferredWidth: 32
                                Layout.preferredHeight: 32

                                radius: 16

                                color: modelData.active
                                       ? "#0E4250"
                                       : "#10202C"

                                border.width: 1
                                border.color: modelData.active
                                              ? theme.primaryMuted
                                              : theme.border

                                Text {
                                    anchors.centerIn: parent

                                    text: modelData.number

                                    color: modelData.active
                                           ? theme.primaryBright
                                           : theme.textMuted

                                    font.pixelSize: 12
                                    font.bold: true
                                }
                            }

                            Text {
                                text: modelData.title

                                color: modelData.active
                                       ? theme.textPrimary
                                       : theme.textMuted

                                font.pixelSize: 12
                                font.bold: true
                            }

                            Item {
                                Layout.fillWidth: true
                            }
                        }
                    }
                }
            }

            RowLayout {
                Layout.fillWidth: true
                Layout.preferredHeight: 520

                spacing: 14

                GridLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    columns: 2
                    rowSpacing: 14
                    columnSpacing: 14

                    TelemetrySourceCard {
                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        code: "WS"
                        title: "Windows Security"
                        subtitle: "EVTX logon and authentication events"
                        selectedPath: root.windowsPath

                        onBrowseRequested: windowsDialog.open()
                        onClearRequested: root.windowsPath = ""
                    }

                    TelemetrySourceCard {
                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        code: "SM"
                        title: "Sysmon"
                        subtitle: "Process, network, DNS, file, and registry telemetry"
                        selectedPath: root.sysmonPath

                        onBrowseRequested: sysmonDialog.open()
                        onClearRequested: root.sysmonPath = ""
                    }

                    TelemetrySourceCard {
                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        code: "LA"
                        title: "Linux Authentication"
                        subtitle: "SSH, sudo, and local session activity"
                        selectedPath: root.linuxPath

                        onBrowseRequested: linuxDialog.open()
                        onClearRequested: root.linuxPath = ""
                    }

                    TelemetrySourceCard {
                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        code: "AW"
                        title: "AuthWatch CSV / JSON"
                        subtitle: "Authentication dataset compatibility input"
                        selectedPath: root.authwatchPath

                        onBrowseRequested: authwatchDialog.open()
                        onClearRequested: root.authwatchPath = ""
                    }
                }

                Panel {
                    Layout.preferredWidth: 390
                    Layout.fillHeight: true

                    title: "Investigation Configuration"
                    subtitle: "Context applied to the analysis run"

                    ColumnLayout {
                        Layout.fillWidth: true
                        spacing: 7

                        Text {
                            text: "INVESTIGATION NAME"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                            font.letterSpacing: 0.4
                        }

                        TextField {
                            id: nameField

                            Layout.fillWidth: true
                            Layout.preferredHeight: 40

                            placeholderText: "Example: Finance workstation review"
                            text: root.investigationName

                            color: theme.textPrimary
                            placeholderTextColor: theme.textDim

                            font.pixelSize: 12

                            leftPadding: 12
                            rightPadding: 12

                            background: Rectangle {
                                radius: 9
                                color: theme.surfaceRaised

                                border.width: 1
                                border.color: nameField.activeFocus
                                              ? theme.primaryMuted
                                              : theme.border
                            }

                            onTextChanged: root.investigationName = text
                        }

                        Text {
                            text: "LINUX YEAR"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                            font.letterSpacing: 0.4
                        }

                        TextField {
                            id: yearField

                            Layout.fillWidth: true
                            Layout.preferredHeight: 40

                            text: root.linuxYear
                            color: theme.textPrimary

                            font.pixelSize: 12
                            inputMethodHints: Qt.ImhDigitsOnly

                            leftPadding: 12

                            background: Rectangle {
                                radius: 9
                                color: theme.surfaceRaised

                                border.width: 1
                                border.color: yearField.activeFocus
                                              ? theme.primaryMuted
                                              : theme.border
                            }

                            onTextChanged: root.linuxYear = text
                        }

                        Text {
                            text: "LINUX UTC OFFSET"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                            font.letterSpacing: 0.4
                        }

                        TextField {
                            id: offsetField

                            Layout.fillWidth: true
                            Layout.preferredHeight: 40

                            text: root.linuxUtcOffset
                            color: theme.textPrimary

                            font.pixelSize: 12
                            leftPadding: 12

                            background: Rectangle {
                                radius: 9
                                color: theme.surfaceRaised

                                border.width: 1
                                border.color: offsetField.activeFocus
                                              ? theme.primaryMuted
                                              : theme.border
                            }

                            onTextChanged: root.linuxUtcOffset = text
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 1

                            color: theme.border
                        }

                        Text {
                            text: "ANALYSIS PIPELINE"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                            font.letterSpacing: 0.4
                        }

                        Repeater {
                            model: [
                                "Validate selected telemetry",
                                "Calculate source metadata and SHA-256",
                                "Execute the AuthWatch V3 engine",
                                "Persist events, findings, and evidence",
                                "Open the completed investigation"
                            ]

                            delegate: RowLayout {
                                required property string modelData

                                Layout.fillWidth: true
                                spacing: 9

                                Rectangle {
                                    Layout.preferredWidth: 7
                                    Layout.preferredHeight: 7

                                    radius: 4
                                    color: theme.primary
                                }

                                Text {
                                    Layout.fillWidth: true

                                    text: modelData
                                    color: theme.textSecondary

                                    font.pixelSize: 11
                                    wrapMode: Text.WordWrap
                                }
                            }
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 64

                            radius: 10
                            color: "#091925"

                            border.width: 1
                            border.color: theme.border

                            ColumnLayout {
                                anchors.fill: parent
                                anchors.margins: 12

                                spacing: 4

                                Text {
                                    text: "LOCAL ANALYSIS"
                                    color: theme.primary

                                    font.pixelSize: 10
                                    font.bold: true
                                }

                                Text {
                                    Layout.fillWidth: true

                                    text: "Telemetry stays on this workstation. Original files are not permanently duplicated by V4."

                                    color: theme.textMuted
                                    font.pixelSize: 11

                                    wrapMode: Text.WordWrap
                                }
                            }
                        }
                    }
                }
            }

            Panel {
                Layout.fillWidth: true
                Layout.preferredHeight: 138

                title: root.analysisRunning
                       ? "Analysis Running"
                       : (
                             root.hasTelemetry
                             ? "Ready to Analyze"
                             : "Select Telemetry to Continue"
                         )

                subtitle: root.analysisRunning
                          ? "AuthWatch is processing the selected telemetry locally"
                          : (
                                root.hasTelemetry
                                ? (
                                      root.selectedSourceCount
                                      + " source"
                                      + (root.selectedSourceCount === 1 ? "" : "s")
                                      + " selected for this investigation"
                                  )
                                : "Choose at least one telemetry source above"
                            )

                accentColor: root.analysisRunning
                             ? theme.success
                             : (
                                   root.hasTelemetry
                                   ? theme.primary
                                   : "transparent"
                               )

                RowLayout {
                    Layout.fillWidth: true
                    spacing: 14

                    ColumnLayout {
                        Layout.fillWidth: true
                        Layout.alignment: Qt.AlignVCenter

                        spacing: 4

                        Text {
                            Layout.fillWidth: true

                            text: root.analysisRunning
                                  ? "Telemetry analysis is in progress."
                                  : (
                                        root.hasTelemetry
                                        ? "The analysis request is ready."
                                        : "No telemetry source has been selected."
                                    )

                            color: theme.textPrimary

                            font.pixelSize: 13
                            font.bold: true

                            wrapMode: Text.WordWrap
                        }

                        Text {
                            Layout.fillWidth: true

                            text: root.analysisRunning
                                  ? (
                                        root.analysisStatus !== ""
                                        ? root.analysisStatus
                                        : "Running the AuthWatch V3 detection and correlation engine."
                                    )
                                  : (
                                        root.hasTelemetry
                                        ? "Review the configuration, then start the local analysis workflow."
                                        : "Windows Security, Sysmon, Linux authentication, and AuthWatch CSV/JSON are supported by this V4 workflow."
                                    )

                            color: theme.textMuted
                            font.pixelSize: 11

                            wrapMode: Text.WordWrap
                        }
                    }

                    PrimaryButton {
                        Layout.alignment: Qt.AlignVCenter | Qt.AlignRight
                        Layout.preferredWidth: 140

                        text: root.analysisRunning
                              ? "Analyzing..."
                              : "Run analysis"

                        enabled:
                            root.hasTelemetry
                            && !root.analysisRunning

                        onClicked: root.analysisRequested({
                            investigation_name: root.investigationName,
                            windows_security: root.windowsPath,
                            sysmon: root.sysmonPath,
                            linux_auth: root.linuxPath,
                            authwatch_log: root.authwatchPath,
                            linux_year: root.linuxYear,
                            linux_utc_offset: root.linuxUtcOffset
                        })
                    }
                }
            }

            Item {
                Layout.preferredHeight: 24
            }
        }
    }
}
