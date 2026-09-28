from __future__ import annotations

from PySide6.QtCore import (
    QObject,
    Property,
    Signal,
    Slot,
)

from src.services.finding_service import FindingService


class FindingViewModel(QObject):
    findingsChanged = Signal()
    selectionChanged = Signal()
    loadingChanged = Signal()
    errorChanged = Signal()
    findingUpdated = Signal()

    def __init__(
        self,
        service: FindingService,
        parent: QObject | None = None,
    ):
        super().__init__(parent)

        self._service = service

        self._findings = []
        self._selected_finding = {}

        self._loading = False
        self._error_message = ""

    @Property(
        "QVariantList",
        notify=findingsChanged,
    )
    def findings(self) -> list:
        return self._findings

    @Property(
        int,
        notify=findingsChanged,
    )
    def highCount(self) -> int:
        return sum(
            1
            for finding in self._findings
            if str(
                finding.get(
                    "severity",
                    "",
                )
            ).lower() == "high"
        )

    @Property(
        "QVariantMap",
        notify=selectionChanged,
    )
    def selectedFinding(self) -> dict:
        return self._selected_finding

    @Property(
        bool,
        notify=selectionChanged,
    )
    def hasSelection(self) -> bool:
        return bool(
            self._selected_finding
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
    def _serialize_finding(
        cls,
        finding,
    ) -> dict:
        return {
            "id": finding.id,
            "investigation_id": (
                finding.investigation_id
            ),
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
            "source_ip": event.source_ip,
            "destination_ip": event.destination_ip,
            "process_name": event.process_name,
            "command_line": event.command_line,
            "result": event.result,
            "details": event.details or {},
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
    def loadFindings(self) -> None:
        if self._loading:
            return

        self._set_loading(True)
        self._set_error("")

        try:
            findings = (
                self._service.list_findings()
            )

            self._findings = [
                self._serialize_finding(
                    finding
                )
                for finding in findings
            ]

            self.findingsChanged.emit()

        except Exception as error:
            self._set_error(str(error))

        finally:
            self._set_loading(False)

    @Slot(int)
    def selectFinding(
        self,
        finding_id: int,
    ) -> None:
        if self._loading:
            return

        self._set_loading(True)
        self._set_error("")

        try:
            finding = self._service.get_finding(
                finding_id
            )

            evidence = (
                self._service
                .load_supporting_evidence(
                    finding_id=finding_id
                )
            )

            related = (
                self._service
                .load_related_findings(
                    finding_id=finding_id
                )
            )

            selected = self._serialize_finding(
                finding
            )

            selected["evidence"] = [
                self._serialize_event(event)
                for event in evidence
            ]

            selected["related_findings"] = [
                self._serialize_finding(item)
                for item in related
            ]

            self._selected_finding = selected
            self.selectionChanged.emit()

        except Exception as error:
            self._set_error(str(error))

        finally:
            self._set_loading(False)

    @Slot()
    def clearSelection(self) -> None:
        if not self._selected_finding:
            return

        self._selected_finding = {}
        self.selectionChanged.emit()

    @Slot(int)
    def markReviewed(
        self,
        finding_id: int,
    ) -> None:
        self._set_error("")

        try:
            finding = self._service.mark_reviewed(
                finding_id=finding_id
            )

            self._service.session.commit()

            updated = self._serialize_finding(
                finding
            )

            self.loadFindings()

            if (
                self._selected_finding
                and self._selected_finding.get("id")
                == finding_id
            ):
                self.selectFinding(finding_id)

            self.findingUpdated.emit()

        except Exception as error:
            self._service.session.rollback()
            self._set_error(str(error))
