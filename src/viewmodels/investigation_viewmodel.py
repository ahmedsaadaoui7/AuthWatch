from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import (
    QObject,
    Property,
    QUrl,
    Signal,
    Slot,
)

from src.services.investigation_service import (
    InvestigationService,
)


class InvestigationViewModel(QObject):
    investigationsChanged = Signal()
    selectionChanged = Signal()
    loadingChanged = Signal()
    errorChanged = Signal()

    exportCompleted = Signal(str)

    def __init__(
        self,
        service: InvestigationService,
        parent: QObject | None = None,
    ):
        super().__init__(parent)

        self._service = service

        self._investigations = []
        self._selected_investigation = {}

        self._loading = False
        self._error_message = ""

    @Property(
        "QVariantList",
        notify=investigationsChanged,
    )
    def investigations(self) -> list:
        return self._investigations

    @Property(
        "QVariantMap",
        notify=selectionChanged,
    )
    def selectedInvestigation(self) -> dict:
        return self._selected_investigation

    @Property(
        bool,
        notify=selectionChanged,
    )
    def hasSelection(self) -> bool:
        return bool(
            self._selected_investigation
        )

    @Property(
        bool,
        notify=loadingChanged,
    )
    def loading(self) -> bool:
        return self._loading

    @Property(
        str,
        notify=errorChanged,
    )
    def errorMessage(self) -> str:
        return self._error_message

    @staticmethod
    def _format_datetime(value):
        if value is None:
            return None

        return value.isoformat()

    @classmethod
    def _serialize_investigation(
        cls,
        investigation,
    ) -> dict:
        return {
            "id": investigation.id,
            "public_id": investigation.public_id,
            "name": investigation.name,
            "status": investigation.status,
            "created_at": cls._format_datetime(
                investigation.created_at
            ),
            "completed_at": cls._format_datetime(
                investigation.completed_at
            ),
            "event_count": investigation.event_count,
            "finding_count": investigation.finding_count,
            "high_severity_count": (
                investigation.high_severity_count
            ),
        }

    @classmethod
    def _serialize_event(
        cls,
        event,
    ) -> dict:
        return {
            "id": event.id,
            "timestamp": cls._format_datetime(
                event.timestamp
            ),
            "source": event.source,
            "event_id": event.event_id,
            "event_type": event.event_type,
            "host": event.host,
            "username": event.username,
            "session_id": event.session_id,
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "process_name": event.process_name,
            "process_id": event.process_id,
            "process_guid": event.process_guid,
            "parent_process_name": (
                event.parent_process_name
            ),
            "command_line": event.command_line,
            "result": event.result,
            "details": event.details or {},
        }

    @classmethod
    def _serialize_finding(
        cls,
        finding,
    ) -> dict:
        return {
            "id": finding.id,
            "finding_type": finding.finding_type,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity,
            "status": finding.status,
            "first_seen": cls._format_datetime(
                finding.first_seen
            ),
            "last_seen": cls._format_datetime(
                finding.last_seen
            ),
            "summary": finding.summary,
            "details": finding.details or {},
            "mitre": finding.mitre,
        }

    @classmethod
    def _serialize_case(
        cls,
        case,
    ) -> dict:
        return {
            "id": case.id,
            "public_id": case.public_id,
            "title": case.title,
            "priority": case.priority,
            "status": case.status,
            "resolution": case.resolution,
            "created_at": cls._format_datetime(
                case.created_at
            ),
            "closed_at": cls._format_datetime(
                case.closed_at
            ),
        }

    def _set_loading(
        self,
        value: bool,
    ) -> None:
        if self._loading == value:
            return

        self._loading = value
        self.loadingChanged.emit()

    def _set_error(
        self,
        message: str,
    ) -> None:
        if self._error_message == message:
            return

        self._error_message = message
        self.errorChanged.emit()

    @Slot()
    def loadInvestigations(self) -> None:
        if self._loading:
            return

        self._set_loading(True)
        self._set_error("")

        try:
            investigations = (
                self._service.list_investigations()
            )

            self._investigations = [
                self._serialize_investigation(
                    investigation
                )
                for investigation
                in investigations
            ]

            self.investigationsChanged.emit()

        except Exception as error:
            self._set_error(str(error))

        finally:
            self._set_loading(False)

    @Slot(int)
    def selectInvestigation(
        self,
        investigation_id: int,
    ) -> None:
        if self._loading:
            return

        self._set_loading(True)
        self._set_error("")

        try:
            investigation = (
                self._service.get_investigation(
                    investigation_id
                )
            )

            timeline = (
                self._service.load_timeline(
                    investigation_id=(
                        investigation_id
                    )
                )
            )

            affected_entities = (
                self._service.load_affected_entities(
                    investigation_id=(
                        investigation_id
                    )
                )
            )

            findings = (
                self._service.load_findings(
                    investigation_id=(
                        investigation_id
                    )
                )
            )

            related_cases = (
                self._service.load_related_cases(
                    investigation_id=(
                        investigation_id
                    )
                )
            )

            selected = (
                self._serialize_investigation(
                    investigation
                )
            )

            selected["timeline"] = [
                self._serialize_event(event)
                for event in timeline
            ]

            selected["affected_entities"] = (
                affected_entities
            )

            selected["findings"] = [
                self._serialize_finding(finding)
                for finding in findings
            ]

            selected["related_cases"] = [
                self._serialize_case(case)
                for case in related_cases
            ]

            self._selected_investigation = (
                selected
            )

            self.selectionChanged.emit()

        except Exception as error:
            self._set_error(str(error))

        finally:
            self._set_loading(False)

    @Slot()
    def clearSelection(self) -> None:
        if not self._selected_investigation:
            return

        self._selected_investigation = {}
        self.selectionChanged.emit()

    @staticmethod
    def _normalize_output_path(value: str) -> str:
        text = str(value or "").strip()

        if not text:
            raise ValueError(
                "Export path is required."
            )

        url = QUrl(text)

        if url.isLocalFile():
            return url.toLocalFile()

        return text

    @Slot(int, str)
    def exportInvestigation(
        self,
        investigation_id: int,
        output_path: str,
    ) -> None:
        self._set_error("")

        try:
            normalized_path = (
                self._normalize_output_path(
                    output_path
                )
            )

            path = Path(normalized_path)

            suffix = path.suffix.lower()

            if suffix == ".json":
                export_format = "json"

            elif suffix in {".md", ".markdown"}:
                export_format = "markdown"

            else:
                raise ValueError(
                    "Export file must use .json or .md."
                )

            result_path = (
                self._service.export_investigation(
                    investigation_id=investigation_id,
                    export_format=export_format,
                    output_path=path,
                )
            )

            self.exportCompleted.emit(
                str(result_path)
            )

        except Exception as error:
            self._set_error(str(error))
