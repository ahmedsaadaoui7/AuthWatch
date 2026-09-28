import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: root

    property var viewModel: null
    property string selectedSeverity: "all"

    readonly property var findingsModel:
        root.viewModel
        ? root.viewModel.findings
        : []

    readonly property var selectedFinding:
        root.viewModel && root.viewModel.hasSelection
        ? root.viewModel.selectedFinding
        : null

    readonly property int highCount:
        root.viewModel
        ? root.viewModel.highCount
        : 0

    signal openAnalyzeRequested()
    signal escalateRequested(var finding)

    BrandTheme {
        id: theme
    }

    Component.onCompleted: {
        if (root.viewModel) {
            root.viewModel.loadFindings()
        }
    }

    function matches(item) {
        if (!item)
            return false

        var q = searchField.text.toLowerCase()

        var queryMatch =
                q === ""
                || String(item.title || "")
                    .toLowerCase()
                    .indexOf(q) >= 0
                || String(item.rule_id || "")
                    .toLowerCase()
                    .indexOf(q) >= 0

        var severityMatch =
                selectedSeverity === "all"
                || String(item.severity || "")
                    .toLowerCase() === selectedSeverity

        return queryMatch && severityMatch
    }

    function prettyEventType(value) {
        if (!value)
            return "Security event"

        var text = String(value).replace(/_/g, " ")

        return text.charAt(0).toUpperCase()
                + text.slice(1)
    }

    function displayTimestamp(value) {
        if (!value)
            return "Unknown time"

        return String(value).replace("T", " ")
    }

    function eventContext(event) {
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
                        text: "Findings Queue"
                        color: theme.textPrimary

                        font.pixelSize: 28
                        font.bold: true
                    }

                    Text {
                        text: "Search, triage, review, and escalate AuthWatch detections and correlations."
                        color: theme.textSecondary

                        font.pixelSize: 13
                    }
                }

                PrimaryButton {
                    text: "Analyze telemetry"

                    onClicked:
                        root.openAnalyzeRequested()
                }
            }
        }

        AlertBanner {
            visible: root.highCount > 0

            count: root.highCount
            actionText: "Show high findings"

            onActionClicked:
                root.selectedSeverity = "high"
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.preferredHeight: 44

            spacing: 10

            SearchField {
                id: searchField

                Layout.fillWidth: true
                Layout.maximumWidth: 440

                placeholderText:
                    "Search finding title or rule ID"
            }

            Repeater {
                model: [
                    "all",
                    "high",
                    "medium",
                    "low"
                ]

                delegate: Rectangle {
                    required property string modelData

                    Layout.preferredWidth:
                        filterLabel.implicitWidth + 24

                    Layout.preferredHeight: 38

                    radius: 9

                    color:
                        root.selectedSeverity === modelData
                        ? "#0E3140"
                        : theme.surfaceRaised

                    border.width: 1

                    border.color:
                        root.selectedSeverity === modelData
                        ? theme.primaryMuted
                        : theme.border

                    Text {
                        id: filterLabel

                        anchors.centerIn: parent

                        text: modelData.toUpperCase()

                        color:
                            root.selectedSeverity === modelData
                            ? theme.primaryBright
                            : theme.textSecondary

                        font.pixelSize: 11
                        font.bold: true
                    }

                    MouseArea {
                        anchors.fill: parent

                        cursorShape: Qt.PointingHandCursor

                        onClicked:
                            root.selectedSeverity =
                                modelData
                    }
                }
            }

            Item {
                Layout.fillWidth: true
            }
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

                        Text {
                            Layout.fillWidth: true

                            text: "FINDING"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                        }

                        Text {
                            Layout.preferredWidth: 130

                            text: "RULE"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                        }

                        Text {
                            Layout.preferredWidth: 88

                            text: "SEVERITY"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                        }

                        Text {
                            Layout.preferredWidth: 98

                            text: "STATUS"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                        }
                    }

                    Rectangle {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 1

                        color: theme.border
                    }

                    Repeater {
                        model: root.findingsModel || []

                        delegate: Rectangle {
                            required property var modelData

                            property bool accepted:
                                root.matches(modelData)

                            property bool isSelected:
                                root.selectedFinding
                                && root.selectedFinding.id
                                   === modelData.id

                            Layout.fillWidth: true
                            Layout.preferredHeight:
                                accepted ? 64 : 0

                            visible: accepted

                            radius: 10

                            color:
                                isSelected
                                ? "#102C3B"
                                : (
                                      findingMouse.containsMouse
                                      ? "#102230"
                                      : "transparent"
                                  )

                            border.width:
                                isSelected ? 1 : 0

                            border.color:
                                theme.primaryMuted

                            RowLayout {
                                anchors.fill: parent
                                anchors.leftMargin: 10
                                anchors.rightMargin: 10

                                spacing: 10

                                Rectangle {
                                    Layout.preferredWidth: 4
                                    Layout.preferredHeight: 34

                                    radius: 2

                                    color:
                                        String(
                                            modelData.severity
                                        ).toLowerCase() === "high"
                                        ? theme.danger
                                        : (
                                              String(
                                                  modelData.severity
                                              ).toLowerCase()
                                              === "medium"
                                              ? theme.warning
                                              : theme.info
                                          )
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 4

                                    Text {
                                        Layout.fillWidth: true

                                        text:
                                            modelData.title
                                            || "Finding"

                                        color: theme.textPrimary

                                        font.pixelSize: 12
                                        font.bold: true

                                        elide: Text.ElideRight
                                    }

                                    Text {
                                        Layout.fillWidth: true

                                        text:
                                            modelData.investigation_id
                                            ? (
                                                  "Investigation #"
                                                  + modelData.investigation_id
                                              )
                                            : "AuthWatch finding"

                                        color: theme.textMuted
                                        font.pixelSize: 10

                                        elide: Text.ElideRight
                                    }
                                }

                                Text {
                                    Layout.preferredWidth: 130

                                    text:
                                        modelData.rule_id
                                        || ""

                                    color: theme.textSecondary
                                    font.pixelSize: 11

                                    elide: Text.ElideRight
                                }

                                SeverityBadge {
                                    Layout.preferredWidth: 88

                                    severity:
                                        modelData.severity
                                        || "low"
                                }

                                StatusBadge {
                                    Layout.preferredWidth: 98

                                    status:
                                        modelData.status
                                        || "new"
                                }
                            }

                            MouseArea {
                                id: findingMouse

                                anchors.fill: parent

                                hoverEnabled: true
                                cursorShape:
                                    Qt.PointingHandCursor

                                onClicked: {
                                    if (root.viewModel) {
                                        root.viewModel.selectFinding(
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

                        visible:
                            !root.findingsModel
                            || root.findingsModel.length === 0

                        title: "No findings available"

                        message:
                            "Analyze telemetry to populate the findings queue."

                        code: "FD"
                    }
                }
            }

            Panel {
                Layout.preferredWidth: 420
                Layout.fillHeight: true

                title: "Finding Details"
                subtitle: "Evidence and analyst actions"

                accentColor:
                    root.selectedFinding
                    && String(
                        root.selectedFinding.severity
                    ).toLowerCase() === "high"
                    ? theme.danger
                    : "transparent"

                EmptyState {
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    visible:
                        root.selectedFinding === null

                    title: "Select a finding"

                    message:
                        "Choose a row from the queue to inspect severity, status, rule context, evidence, and analyst actions."

                    code: "i"
                }

                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    visible:
                        root.selectedFinding !== null

                    spacing: 10

                    ScrollView {
                        id: detailsScroll

                        Layout.fillWidth: true
                        Layout.fillHeight: true

                        clip: true
                        contentWidth: availableWidth

                        ColumnLayout {
                            width: detailsScroll.availableWidth

                            spacing: 12

                            Text {
                                Layout.fillWidth: true

                                text:
                                    root.selectedFinding
                                    ? root.selectedFinding.title
                                    : ""

                                color: theme.textPrimary

                                font.pixelSize: 17
                                font.bold: true

                                wrapMode: Text.WordWrap
                            }

                            RowLayout {
                                spacing: 8

                                SeverityBadge {
                                    severity:
                                        root.selectedFinding
                                        ? root.selectedFinding.severity
                                        : "low"
                                }

                                StatusBadge {
                                    status:
                                        root.selectedFinding
                                        ? root.selectedFinding.status
                                        : "new"
                                }
                            }

                            Rectangle {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 1

                                color: theme.border
                            }

                            GridLayout {
                                Layout.fillWidth: true

                                columns: 2

                                rowSpacing: 9
                                columnSpacing: 14

                                Text {
                                    text: "Rule ID"
                                    color: theme.textMuted
                                    font.pixelSize: 11
                                }

                                Text {
                                    text:
                                        root.selectedFinding
                                        ? root.selectedFinding.rule_id
                                        : ""

                                    color: theme.textSecondary

                                    font.pixelSize: 11
                                    font.bold: true
                                }

                                Text {
                                    text: "Investigation"
                                    color: theme.textMuted
                                    font.pixelSize: 11
                                }

                                Text {
                                    text:
                                        root.selectedFinding
                                        ? root.selectedFinding.investigation_id
                                        : ""

                                    color: theme.textSecondary
                                    font.pixelSize: 11
                                }

                                Text {
                                    text: "First seen"
                                    color: theme.textMuted
                                    font.pixelSize: 11
                                }

                                Text {
                                    Layout.fillWidth: true

                                    text:
                                        root.selectedFinding
                                        && root.selectedFinding.first_seen
                                        ? root.selectedFinding.first_seen
                                        : "Not available"

                                    color: theme.textSecondary

                                    font.pixelSize: 11
                                    elide: Text.ElideRight
                                }

                                Text {
                                    text: "Last seen"
                                    color: theme.textMuted
                                    font.pixelSize: 11
                                }

                                Text {
                                    Layout.fillWidth: true

                                    text:
                                        root.selectedFinding
                                        && root.selectedFinding.last_seen
                                        ? root.selectedFinding.last_seen
                                        : "Not available"

                                    color: theme.textSecondary

                                    font.pixelSize: 11
                                    elide: Text.ElideRight
                                }
                            }

                            Rectangle {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 88

                                radius: 10

                                color:
                                    String(
                                        root.selectedFinding
                                        ? root.selectedFinding.severity
                                        : ""
                                    ).toLowerCase() === "high"
                                    ? "#1B141C"
                                    : "#091925"

                                border.width: 1

                                border.color:
                                    String(
                                        root.selectedFinding
                                        ? root.selectedFinding.severity
                                        : ""
                                    ).toLowerCase() === "high"
                                    ? theme.dangerBorder
                                    : theme.border

                                ColumnLayout {
                                    anchors.fill: parent
                                    anchors.margins: 12

                                    spacing: 4

                                    Text {
                                        text:
                                            String(
                                                root.selectedFinding
                                                ? root.selectedFinding.severity
                                                : ""
                                            ).toLowerCase() === "high"
                                            ? "PRIORITY REVIEW"
                                            : "ANALYST REVIEW"

                                        color:
                                            String(
                                                root.selectedFinding
                                                ? root.selectedFinding.severity
                                                : ""
                                            ).toLowerCase() === "high"
                                            ? theme.danger
                                            : theme.primary

                                        font.pixelSize: 10
                                        font.bold: true
                                    }

                                    Text {
                                        Layout.fillWidth: true

                                        text:
                                            root.selectedFinding
                                            && root.selectedFinding.summary
                                            ? root.selectedFinding.summary
                                            : "Review supporting telemetry before changing finding status or escalating into a case."

                                        color: theme.textSecondary

                                        font.pixelSize: 11
                                        wrapMode: Text.WordWrap
                                    }
                                }
                            }

                            Rectangle {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 1

                                color: theme.border
                            }

                            Text {
                                Layout.fillWidth: true

                                text: "SUPPORTING EVIDENCE"
                                color: theme.textMuted

                                font.pixelSize: 10
                                font.bold: true
                                font.letterSpacing: 0.6
                            }

                            Repeater {
                                model:
                                    root.selectedFinding
                                    && root.selectedFinding.evidence
                                    ? root.selectedFinding.evidence
                                    : []

                                delegate: Rectangle {
                                    required property var modelData

                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 72

                                    radius: 8
                                    color: "#081A27"

                                    border.width: 1
                                    border.color: theme.border

                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.margins: 9

                                        spacing: 9

                                        Rectangle {
                                            Layout.preferredWidth: 7
                                            Layout.preferredHeight: 7

                                            radius: 4

                                            color:
                                                String(
                                                    modelData.result
                                                    || ""
                                                ).toLowerCase() === "failure"
                                                ? theme.danger
                                                : theme.primary
                                        }

                                        ColumnLayout {
                                            Layout.fillWidth: true
                                            spacing: 3

                                            RowLayout {
                                                Layout.fillWidth: true

                                                Text {
                                                    Layout.fillWidth: true

                                                    text:
                                                        root.prettyEventType(
                                                            modelData.event_type
                                                        )

                                                    color: theme.textPrimary

                                                    font.pixelSize: 11
                                                    font.bold: true

                                                    elide: Text.ElideRight
                                                }

                                                Text {
                                                    text:
                                                        modelData.source
                                                        || ""

                                                    color: theme.textMuted
                                                    font.pixelSize: 9
                                                }
                                            }

                                            Text {
                                                Layout.fillWidth: true

                                                text:
                                                    root.eventContext(
                                                        modelData
                                                    )

                                                color: theme.textSecondary
                                                font.pixelSize: 10

                                                elide: Text.ElideRight
                                            }

                                            Text {
                                                Layout.fillWidth: true

                                                text:
                                                    root.displayTimestamp(
                                                        modelData.timestamp
                                                    )

                                                color: theme.textMuted
                                                font.pixelSize: 9

                                                elide: Text.ElideRight
                                            }
                                        }
                                    }
                                }
                            }

                            Text {
                                Layout.fillWidth: true

                                visible:
                                    !root.selectedFinding
                                    || !root.selectedFinding.evidence
                                    || root.selectedFinding.evidence.length === 0

                                text:
                                    "No supporting events are linked to this finding."

                                color: theme.textMuted
                                font.pixelSize: 10
                            }

                            Rectangle {
                                Layout.fillWidth: true
                                Layout.preferredHeight: 1

                                color: theme.border
                            }

                            Text {
                                Layout.fillWidth: true

                                text: "RELATED FINDINGS"
                                color: theme.textMuted

                                font.pixelSize: 10
                                font.bold: true
                                font.letterSpacing: 0.6
                            }

                            Repeater {
                                model:
                                    root.selectedFinding
                                    && root.selectedFinding.related_findings
                                    ? root.selectedFinding.related_findings
                                    : []

                                delegate: Rectangle {
                                    required property var modelData

                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 66

                                    radius: 8
                                    color: "#081A27"

                                    border.width: 1
                                    border.color: theme.border

                                    RowLayout {
                                        anchors.fill: parent
                                        anchors.leftMargin: 10
                                        anchors.rightMargin: 10

                                        spacing: 8

                                        ColumnLayout {
                                            Layout.fillWidth: true

                                            spacing: 3

                                            Text {
                                                Layout.fillWidth: true

                                                text:
                                                    modelData.title
                                                    || "Related finding"

                                                color: theme.textPrimary

                                                font.pixelSize: 11
                                                font.bold: true

                                                elide: Text.ElideRight
                                            }

                                            Text {
                                                Layout.fillWidth: true

                                                text:
                                                    modelData.rule_id
                                                    || ""

                                                color: theme.textMuted
                                                font.pixelSize: 10

                                                elide: Text.ElideRight
                                            }
                                        }

                                        SeverityBadge {
                                            severity:
                                                modelData.severity
                                                || "low"
                                        }

                                        StatusBadge {
                                            status:
                                                modelData.status
                                                || "new"
                                        }
                                    }
                                }
                            }

                            Text {
                                Layout.fillWidth: true

                                visible:
                                    !root.selectedFinding
                                    || !root.selectedFinding.related_findings
                                    || root.selectedFinding.related_findings.length === 0

                                text:
                                    "No other findings are related to this investigation."

                                color: theme.textMuted
                                font.pixelSize: 10
                            }
                        }
                    }

                    RowLayout {
                        Layout.fillWidth: true

                        spacing: 8

                        SecondaryButton {
                            Layout.fillWidth: true

                            text:
                                !root.selectedFinding
                                ? "Mark reviewed"
                                : (
                                      String(
                                          root.selectedFinding.status
                                      ).toLowerCase() === "new"
                                      ? "Mark reviewed"
                                      : (
                                            String(
                                                root.selectedFinding.status
                                            ).toLowerCase() === "reviewed"
                                            ? "Reviewed"
                                            : "Escalated"
                                        )
                                  )

                            enabled:
                                root.selectedFinding
                                && String(
                                    root.selectedFinding.status
                                ).toLowerCase() === "new"

                            onClicked: {
                                if (
                                    root.viewModel
                                    && root.selectedFinding
                                ) {
                                    root.viewModel.markReviewed(
                                        root.selectedFinding.id
                                    )
                                }
                            }
                        }

                        PrimaryButton {
                            Layout.fillWidth: true

                            text:
                                root.selectedFinding
                                && String(
                                    root.selectedFinding.status
                                ).toLowerCase() === "escalated"
                                ? "Escalated to case"
                                : "Escalate to case"

                            enabled:
                                root.selectedFinding
                                && String(
                                    root.selectedFinding.status
                                ).toLowerCase() !== "escalated"

                            onClicked:
                                root.escalateRequested(
                                    root.selectedFinding
                                )
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
