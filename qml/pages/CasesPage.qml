import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import "../components"

Item {
    id: root

    property var viewModel: null
    property string query: ""

    readonly property var casesModel:
        root.viewModel
        ? root.viewModel.cases
        : []

    readonly property var selectedCase:
        root.viewModel && root.viewModel.hasSelection
        ? root.viewModel.selectedCase
        : null

    signal openFindingWorkflowRequested()

    BrandTheme {
        id: theme
    }

    Component.onCompleted: {
        if (root.viewModel) {
            root.viewModel.loadCases()
        }
    }

    function matches(item) {
        if (!item)
            return false

        var q = root.query.toLowerCase()

        return q === ""
                || String(item.title || "")
                    .toLowerCase()
                    .indexOf(q) >= 0
                || String(item.public_id || "")
                    .toLowerCase()
                    .indexOf(q) >= 0
    }

    function displayTimestamp(value) {
        if (!value)
            return "Not available"

        return String(value).replace("T", " ")
    }

    function resolutionLabel(value) {
        var labels = {
            "true_positive": "True positive",
            "false_positive": "False positive",
            "benign_activity": "Benign activity",
            "other": "Other"
        }

        return labels[value] || value || "Not set"
    }

    function priorityColor(priority) {
        var value = String(priority || "").toLowerCase()

        if (value === "high")
            return theme.danger

        if (value === "medium")
            return theme.warning

        return theme.primary
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
                        text: "Cases"
                        color: theme.textPrimary

                        font.pixelSize: 28
                        font.bold: true
                    }

                    Text {
                        text: "Manage escalated findings, analyst notes, workflow state, priority, and resolution."
                        color: theme.textSecondary

                        font.pixelSize: 13
                    }
                }

                SecondaryButton {
                    text: "Create from finding"

                    onClicked:
                        root.openFindingWorkflowRequested()
                }
            }
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: 14

            MetricCard {
                code: "AC"
                label: "ACTIVE CASES"
                value: root.viewModel
                       ? root.viewModel.activeCount
                       : 0
                helper: "Open and investigating"
                accentColor: theme.primary
            }

            MetricCard {
                code: "HP"
                label: "HIGH PRIORITY"
                value: root.viewModel
                       ? root.viewModel.highPriorityCount
                       : 0
                helper: "Active high-priority cases"
                accentColor: theme.danger
                valueColor: theme.danger
            }

            MetricCard {
                code: "CL"
                label: "CLOSED"
                value: root.viewModel
                       ? root.viewModel.closedCount
                       : 0
                helper: "Resolved cases"
                accentColor: theme.success
            }
        }

        RowLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true

            spacing: 14

            Panel {
                Layout.fillWidth: true
                Layout.fillHeight: true
                Layout.preferredWidth: 1.55

                title: "Case Queue"
                subtitle: "All tracked SOC cases"

                ColumnLayout {
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    spacing: 8

                    SearchField {
                        Layout.fillWidth: true

                        placeholderText:
                            "Search case title or ID"

                        onTextChanged:
                            root.query = text
                    }

                    RowLayout {
                        Layout.fillWidth: true
                        Layout.preferredHeight: 28

                        visible:
                            root.casesModel
                            && root.casesModel.length > 0

                        Text {
                            Layout.fillWidth: true

                            text: "CASE"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                        }

                        Text {
                            Layout.preferredWidth: 110

                            text: "PRIORITY"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                        }

                        Text {
                            Layout.preferredWidth: 110

                            text: "STATUS"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                        }
                    }

                    Repeater {
                        model: root.casesModel || []

                        delegate: Rectangle {
                            required property var modelData

                            property bool accepted:
                                root.matches(modelData)

                            property bool isSelected:
                                root.selectedCase
                                && root.selectedCase.id
                                   === modelData.id

                            Layout.fillWidth: true
                            Layout.preferredHeight:
                                accepted ? 70 : 0

                            visible: accepted

                            radius: 10

                            color:
                                isSelected
                                ? "#102C3B"
                                : (
                                      caseMouse.containsMouse
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
                                    Layout.preferredHeight: 38

                                    radius: 2

                                    color:
                                        root.priorityColor(
                                            modelData.priority
                                        )
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 4

                                    Text {
                                        Layout.fillWidth: true

                                        text:
                                            modelData.title
                                            || "Case"

                                        color: theme.textPrimary

                                        font.pixelSize: 12
                                        font.bold: true

                                        elide: Text.ElideRight
                                    }

                                    Text {
                                        text:
                                            modelData.public_id
                                            || ""

                                        color: theme.textMuted
                                        font.pixelSize: 10
                                    }
                                }

                                SeverityBadge {
                                    Layout.preferredWidth: 110

                                    severity:
                                        modelData.priority
                                        || "low"
                                }

                                StatusBadge {
                                    Layout.preferredWidth: 110

                                    status:
                                        modelData.status
                                        || "open"
                                }
                            }

                            MouseArea {
                                id: caseMouse

                                anchors.fill: parent

                                hoverEnabled: true
                                cursorShape:
                                    Qt.PointingHandCursor

                                onClicked: {
                                    if (root.viewModel) {
                                        root.viewModel.selectCase(
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
                            !root.casesModel
                            || root.casesModel.length === 0

                        title: "No cases yet"

                        message:
                            "Escalate a finding to create the first tracked analyst case."

                        code: "CS"
                    }
                }
            }

            Panel {
                Layout.preferredWidth: 520
                Layout.fillHeight: true

                title: "Case Workspace"
                subtitle: "Context, workflow, notes, and history"

                accentColor:
                    root.selectedCase
                    && String(
                        root.selectedCase.priority
                    ).toLowerCase() === "high"
                    ? theme.danger
                    : "transparent"

                EmptyState {
                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    visible:
                        root.selectedCase === null

                    title: "Select a case"

                    message:
                        "Choose a case to inspect linked findings, change workflow state, add notes, and manage resolution."

                    code: "i"
                }

                ScrollView {
                    id: caseScroll

                    Layout.fillWidth: true
                    Layout.fillHeight: true

                    visible:
                        root.selectedCase !== null

                    clip: true
                    contentWidth: availableWidth

                    ColumnLayout {
                        width: caseScroll.availableWidth

                        spacing: 12

                        Text {
                            Layout.fillWidth: true

                            text:
                                root.selectedCase
                                ? root.selectedCase.title
                                : ""

                            color: theme.textPrimary

                            font.pixelSize: 18
                            font.bold: true

                            wrapMode: Text.WordWrap
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8

                            Text {
                                text:
                                    root.selectedCase
                                    ? root.selectedCase.public_id
                                    : ""

                                color: theme.primaryBright

                                font.pixelSize: 11
                                font.bold: true
                            }

                            Item {
                                Layout.fillWidth: true
                            }

                            SeverityBadge {
                                severity:
                                    root.selectedCase
                                    ? root.selectedCase.priority
                                    : "low"
                            }

                            StatusBadge {
                                status:
                                    root.selectedCase
                                    ? root.selectedCase.status
                                    : "open"
                            }
                        }

                        GridLayout {
                            Layout.fillWidth: true

                            columns: 2
                            rowSpacing: 8
                            columnSpacing: 12

                            Text {
                                text: "Created"
                                color: theme.textMuted
                                font.pixelSize: 11
                            }

                            Text {
                                Layout.fillWidth: true

                                text:
                                    root.selectedCase
                                    ? root.displayTimestamp(
                                          root.selectedCase.created_at
                                      )
                                    : ""

                                color: theme.textSecondary
                                font.pixelSize: 11

                                elide: Text.ElideRight
                            }

                            Text {
                                visible:
                                    root.selectedCase
                                    && root.selectedCase.status
                                       === "closed"

                                text: "Closed"
                                color: theme.textMuted
                                font.pixelSize: 11
                            }

                            Text {
                                Layout.fillWidth: true

                                visible:
                                    root.selectedCase
                                    && root.selectedCase.status
                                       === "closed"

                                text:
                                    root.selectedCase
                                    ? root.displayTimestamp(
                                          root.selectedCase.closed_at
                                      )
                                    : ""

                                color: theme.textSecondary
                                font.pixelSize: 11

                                elide: Text.ElideRight
                            }
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 1
                            color: theme.border
                        }

                        Text {
                            text: "PRIORITY"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                            font.letterSpacing: 0.6
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8

                            Repeater {
                                model: [
                                    "high",
                                    "medium",
                                    "low"
                                ]

                                delegate: Rectangle {
                                    required property string modelData

                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 36

                                    radius: 8

                                    color:
                                        root.selectedCase
                                        && root.selectedCase.priority
                                           === modelData
                                        ? "#102C3B"
                                        : "#081A27"

                                    border.width: 1

                                    border.color:
                                        root.selectedCase
                                        && root.selectedCase.priority
                                           === modelData
                                        ? root.priorityColor(
                                              modelData
                                          )
                                        : theme.border

                                    Text {
                                        anchors.centerIn: parent

                                        text:
                                            modelData.toUpperCase()

                                        color:
                                            root.selectedCase
                                            && root.selectedCase.priority
                                               === modelData
                                            ? root.priorityColor(
                                                  modelData
                                              )
                                            : theme.textSecondary

                                        font.pixelSize: 10
                                        font.bold: true
                                    }

                                    MouseArea {
                                        anchors.fill: parent

                                        enabled:
                                            root.selectedCase
                                            && root.selectedCase.status
                                               !== "closed"
                                            && root.selectedCase.priority
                                               !== modelData

                                        cursorShape:
                                            enabled
                                            ? Qt.PointingHandCursor
                                            : Qt.ArrowCursor

                                        onClicked: {
                                            root.viewModel.changePriority(
                                                root.selectedCase.id,
                                                modelData
                                            )
                                        }
                                    }
                                }
                            }
                        }

                        Text {
                            text: "WORKFLOW STATUS"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                            font.letterSpacing: 0.6
                        }

                        RowLayout {
                            Layout.fillWidth: true
                            spacing: 8

                            visible:
                                root.selectedCase
                                && root.selectedCase.status
                                   !== "closed"

                            Repeater {
                                model: [
                                    "open",
                                    "investigating"
                                ]

                                delegate: Rectangle {
                                    required property string modelData

                                    Layout.fillWidth: true
                                    Layout.preferredHeight: 36

                                    radius: 8

                                    color:
                                        root.selectedCase
                                        && root.selectedCase.status
                                           === modelData
                                        ? "#102C3B"
                                        : "#081A27"

                                    border.width: 1

                                    border.color:
                                        root.selectedCase
                                        && root.selectedCase.status
                                           === modelData
                                        ? theme.primaryMuted
                                        : theme.border

                                    Text {
                                        anchors.centerIn: parent

                                        text:
                                            modelData.toUpperCase()

                                        color:
                                            root.selectedCase
                                            && root.selectedCase.status
                                               === modelData
                                            ? theme.primaryBright
                                            : theme.textSecondary

                                        font.pixelSize: 10
                                        font.bold: true
                                    }

                                    MouseArea {
                                        anchors.fill: parent

                                        enabled:
                                            root.selectedCase
                                            && root.selectedCase.status
                                               !== modelData

                                        cursorShape:
                                            enabled
                                            ? Qt.PointingHandCursor
                                            : Qt.ArrowCursor

                                        onClicked: {
                                            root.viewModel.changeStatus(
                                                root.selectedCase.id,
                                                modelData
                                            )
                                        }
                                    }
                                }
                            }
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 1
                            color: theme.border
                        }

                        Text {
                            text: "LINKED FINDINGS"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                            font.letterSpacing: 0.6
                        }

                        Repeater {
                            model:
                                root.selectedCase
                                && root.selectedCase.findings
                                ? root.selectedCase.findings
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
                                                || "Finding"

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
                                            || "escalated"
                                    }
                                }
                            }
                        }

                        Text {
                            visible:
                                !root.selectedCase
                                || !root.selectedCase.findings
                                || root.selectedCase.findings.length
                                   === 0

                            text:
                                "No findings are linked to this case."

                            color: theme.textMuted
                            font.pixelSize: 10
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 1
                            color: theme.border
                        }

                        Text {
                            text: "ANALYST NOTES"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                            font.letterSpacing: 0.6
                        }

                        Repeater {
                            model:
                                root.selectedCase
                                && root.selectedCase.notes
                                ? root.selectedCase.notes
                                : []

                            delegate: Rectangle {
                                required property var modelData

                                Layout.fillWidth: true
                                Layout.preferredHeight:
                                    noteContent.implicitHeight + 42

                                radius: 8
                                color: "#081A27"

                                border.width: 1
                                border.color: theme.border

                                ColumnLayout {
                                    anchors.fill: parent
                                    anchors.margins: 10

                                    spacing: 4

                                    Text {
                                        Layout.fillWidth: true

                                        text:
                                            root.displayTimestamp(
                                                modelData.created_at
                                            )

                                        color: theme.textMuted
                                        font.pixelSize: 9
                                    }

                                    Text {
                                        id: noteContent

                                        Layout.fillWidth: true

                                        text:
                                            modelData.content
                                            || ""

                                        color: theme.textSecondary
                                        font.pixelSize: 11

                                        wrapMode: Text.WordWrap
                                    }
                                }
                            }
                        }

                        TextArea {
                            id: noteInput

                            Layout.fillWidth: true
                            Layout.preferredHeight: 78

                            visible:
                                root.selectedCase
                                && root.selectedCase.status
                                   !== "closed"

                            placeholderText:
                                "Add analyst note..."

                            color: theme.textPrimary
                            placeholderTextColor: theme.textMuted

                            font.pixelSize: 11
                            wrapMode: TextEdit.Wrap

                            background: Rectangle {
                                radius: 8
                                color: "#071823"

                                border.width: 1
                                border.color: theme.border
                            }
                        }

                        SecondaryButton {
                            Layout.fillWidth: true

                            visible:
                                root.selectedCase
                                && root.selectedCase.status
                                   !== "closed"

                            text: "Add note"

                            enabled:
                                noteInput.text.trim() !== ""

                            onClicked: {
                                root.viewModel.addNote(
                                    root.selectedCase.id,
                                    noteInput.text
                                )

                                noteInput.text = ""
                            }
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 1
                            color: theme.border
                        }

                        Text {
                            text: "ACTIVITY HISTORY"
                            color: theme.textMuted

                            font.pixelSize: 10
                            font.bold: true
                            font.letterSpacing: 0.6
                        }

                        Repeater {
                            model:
                                root.selectedCase
                                && root.selectedCase.history
                                ? root.selectedCase.history
                                : []

                            delegate: RowLayout {
                                required property var modelData

                                Layout.fillWidth: true
                                spacing: 8

                                Rectangle {
                                    Layout.preferredWidth: 7
                                    Layout.preferredHeight: 7

                                    radius: 4
                                    color: theme.primary
                                }

                                ColumnLayout {
                                    Layout.fillWidth: true
                                    spacing: 2

                                    Text {
                                        Layout.fillWidth: true

                                        text:
                                            modelData.description
                                            || "Case activity"

                                        color: theme.textSecondary
                                        font.pixelSize: 10

                                        wrapMode: Text.WordWrap
                                    }

                                    Text {
                                        Layout.fillWidth: true

                                        text:
                                            root.displayTimestamp(
                                                modelData.created_at
                                            )

                                        color: theme.textMuted
                                        font.pixelSize: 9
                                    }
                                }
                            }
                        }

                        Rectangle {
                            Layout.fillWidth: true
                            Layout.preferredHeight: 1
                            color: theme.border
                        }

                        ColumnLayout {
                            Layout.fillWidth: true

                            visible:
                                root.selectedCase
                                && root.selectedCase.status
                                   === "closed"

                            spacing: 8

                            Text {
                                text: "RESOLUTION"
                                color: theme.textMuted

                                font.pixelSize: 10
                                font.bold: true
                                font.letterSpacing: 0.6
                            }

                            Rectangle {
                                Layout.fillWidth: true
                                Layout.preferredHeight:
                                    closedNote.implicitHeight + 70

                                radius: 9
                                color: "#0A1D24"

                                border.width: 1
                                border.color: theme.border

                                ColumnLayout {
                                    anchors.fill: parent
                                    anchors.margins: 10

                                    spacing: 5

                                    Text {
                                        text:
                                            root.selectedCase
                                            ? root.resolutionLabel(
                                                  root.selectedCase.resolution
                                              )
                                            : ""

                                        color: theme.success

                                        font.pixelSize: 11
                                        font.bold: true
                                    }

                                    Text {
                                        id: closedNote

                                        Layout.fillWidth: true

                                        text:
                                            root.selectedCase
                                            ? root.selectedCase.closing_note
                                              || ""
                                            : ""

                                        color: theme.textSecondary
                                        font.pixelSize: 11

                                        wrapMode: Text.WordWrap
                                    }
                                }
                            }

                            PrimaryButton {
                                Layout.fillWidth: true

                                text: "Reopen case"

                                onClicked: {
                                    root.viewModel.reopenCase(
                                        root.selectedCase.id
                                    )
                                }
                            }
                        }

                        ColumnLayout {
                            Layout.fillWidth: true

                            visible:
                                root.selectedCase
                                && root.selectedCase.status
                                   !== "closed"

                            spacing: 8

                            Text {
                                text: "CLOSE CASE"
                                color: theme.textMuted

                                font.pixelSize: 10
                                font.bold: true
                                font.letterSpacing: 0.6
                            }

                            ComboBox {
                                id: resolutionInput

                                Layout.fillWidth: true
                                Layout.preferredHeight: 38

                                model: [
                                    "true_positive",
                                    "false_positive",
                                    "benign_activity",
                                    "other"
                                ]

                                contentItem: Text {
                                    text:
                                        root.resolutionLabel(
                                            resolutionInput.currentText
                                        )

                                    color: theme.textPrimary
                                    font.pixelSize: 11

                                    verticalAlignment:
                                        Text.AlignVCenter

                                    elide: Text.ElideRight
                                }

                                background: Rectangle {
                                    radius: 8
                                    color: "#071823"

                                    border.width: 1
                                    border.color: theme.border
                                }
                            }

                            TextArea {
                                id: closingNoteInput

                                Layout.fillWidth: true
                                Layout.preferredHeight: 84

                                placeholderText:
                                    "Closing note required..."

                                color: theme.textPrimary
                                placeholderTextColor:
                                    theme.textMuted

                                font.pixelSize: 11
                                wrapMode: TextEdit.Wrap

                                background: Rectangle {
                                    radius: 8
                                    color: "#071823"

                                    border.width: 1
                                    border.color: theme.border
                                }
                            }

                            PrimaryButton {
                                Layout.fillWidth: true

                                text: "Close case"

                                enabled:
                                    closingNoteInput.text.trim()
                                    !== ""

                                onClicked: {
                                    root.viewModel.closeCase(
                                        root.selectedCase.id,
                                        resolutionInput.currentText,
                                        closingNoteInput.text
                                    )

                                    closingNoteInput.text = ""
                                }
                            }
                        }

                        Item {
                            Layout.preferredHeight: 8
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
