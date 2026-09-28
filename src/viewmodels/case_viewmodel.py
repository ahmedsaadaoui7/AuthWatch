from __future__ import annotations

from PySide6.QtCore import (
    QObject,
    Property,
    Signal,
    Slot,
)

from src.services.case_service import CaseService


class CaseViewModel(QObject):
    casesChanged = Signal()
    selectionChanged = Signal()
    loadingChanged = Signal()
    errorChanged = Signal()
    caseCreated = Signal(int)
    caseActionCompleted = Signal(str)

    def __init__(
        self,
        service: CaseService,
        parent: QObject | None = None,
    ):
        super().__init__(parent)

        self._service = service
        self._cases = []
        self._selected_case = {}
        self._loading = False
        self._error_message = ""

    @Property(
        "QVariantList",
        notify=casesChanged,
    )
    def cases(self) -> list:
        return self._cases

    @Property(
        int,
        notify=casesChanged,
    )
    def activeCount(self) -> int:
        return sum(
            1
            for case in self._cases
            if str(case.get("status", "")).lower()
            in {"open", "investigating"}
        )

    @Property(
        int,
        notify=casesChanged,
    )
    def highPriorityCount(self) -> int:
        return sum(
            1
            for case in self._cases
            if str(case.get("priority", "")).lower()
            == "high"
            and str(case.get("status", "")).lower()
            != "closed"
        )

    @Property(
        int,
        notify=casesChanged,
    )
    def closedCount(self) -> int:
        return sum(
            1
            for case in self._cases
            if str(case.get("status", "")).lower()
            == "closed"
        )

    @Property(
        "QVariantMap",
        notify=selectionChanged,
    )
    def selectedCase(self) -> dict:
        return self._selected_case

    @Property(
        bool,
        notify=selectionChanged,
    )
    def hasSelection(self) -> bool:
        return bool(self._selected_case)

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
    def _serialize_case_summary(
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
            "closing_note": case.closing_note,
            "created_at": cls._format_datetime(
                case.created_at
            ),
            "closed_at": cls._format_datetime(
                case.closed_at
            ),
        }

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
        }

    @classmethod
    def _serialize_note(
        cls,
        note,
    ) -> dict:
        return {
            "id": note.id,
            "content": note.content,
            "created_at": cls._format_datetime(
                note.created_at
            ),
        }

    @classmethod
    def _serialize_activity(
        cls,
        activity,
    ) -> dict:
        return {
            "id": activity.id,
            "activity_type": activity.activity_type,
            "description": activity.description,
            "details": activity.details or {},
            "created_at": cls._format_datetime(
                activity.created_at
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

    def _refresh_case(
        self,
        case_id: int,
    ) -> None:
        self.loadCases()
        self.selectCase(case_id)

    @Slot()
    def loadCases(self) -> None:
        if self._loading:
            return

        self._set_loading(True)
        self._set_error("")

        try:
            cases = self._service.list_cases()

            self._cases = [
                self._serialize_case_summary(case)
                for case in cases
            ]

            self.casesChanged.emit()

        except Exception as error:
            self._set_error(str(error))

        finally:
            self._set_loading(False)

    @Slot(int)
    def selectCase(
        self,
        case_id: int,
    ) -> None:
        if self._loading:
            return

        self._set_loading(True)
        self._set_error("")

        try:
            case = self._service.get_case(
                case_id
            )

            findings = (
                self._service.load_linked_findings(
                    case_id=case_id
                )
            )

            notes = self._service.load_notes(
                case_id=case_id
            )

            history = self._service.load_history(
                case_id=case_id
            )

            selected = self._serialize_case_summary(
                case
            )

            selected["findings"] = [
                self._serialize_finding(finding)
                for finding in findings
            ]

            selected["notes"] = [
                self._serialize_note(note)
                for note in notes
            ]

            selected["history"] = [
                self._serialize_activity(activity)
                for activity in history
            ]

            self._selected_case = selected
            self.selectionChanged.emit()

        except Exception as error:
            self._selected_case = {}
            self.selectionChanged.emit()
            self._set_error(str(error))

        finally:
            self._set_loading(False)

    @Slot()
    def clearSelection(self) -> None:
        if not self._selected_case:
            return

        self._selected_case = {}
        self.selectionChanged.emit()

    @Slot(int, str, str)
    def createFromFinding(
        self,
        finding_id: int,
        title: str,
        priority: str,
    ) -> None:
        self._set_error("")

        try:
            case = (
                self._service.create_case_from_finding(
                    finding_id=finding_id,
                    title=title,
                    priority=priority,
                )
            )

            self._service.session.commit()

            case_id = case.id

            self.caseCreated.emit(case_id)

        except Exception as error:
            self._service.session.rollback()
            self._set_error(str(error))

    @Slot(int, str)
    def addNote(
        self,
        case_id: int,
        content: str,
    ) -> None:
        self._set_error("")

        try:
            self._service.add_note(
                case_id=case_id,
                content=content,
            )

            self._service.session.commit()
            self._refresh_case(case_id)

            self.caseActionCompleted.emit(
                "Analyst note added."
            )

        except Exception as error:
            self._service.session.rollback()
            self._set_error(str(error))

    @Slot(int, str)
    def changePriority(
        self,
        case_id: int,
        priority: str,
    ) -> None:
        self._set_error("")

        try:
            self._service.change_priority(
                case_id=case_id,
                priority=priority,
            )

            self._service.session.commit()
            self._refresh_case(case_id)

            self.caseActionCompleted.emit(
                "Case priority updated."
            )

        except Exception as error:
            self._service.session.rollback()
            self._set_error(str(error))

    @Slot(int, str)
    def changeStatus(
        self,
        case_id: int,
        status: str,
    ) -> None:
        self._set_error("")

        try:
            self._service.change_status(
                case_id=case_id,
                status=status,
            )

            self._service.session.commit()
            self._refresh_case(case_id)

            self.caseActionCompleted.emit(
                "Case status updated."
            )

        except Exception as error:
            self._service.session.rollback()
            self._set_error(str(error))

    @Slot(int, str, str)
    def closeCase(
        self,
        case_id: int,
        resolution: str,
        closing_note: str,
    ) -> None:
        self._set_error("")

        try:
            self._service.close_case(
                case_id=case_id,
                resolution=resolution,
                closing_note=closing_note,
            )

            self._service.session.commit()
            self._refresh_case(case_id)

            self.caseActionCompleted.emit(
                "Case closed."
            )

        except Exception as error:
            self._service.session.rollback()
            self._set_error(str(error))

    @Slot(int)
    def reopenCase(
        self,
        case_id: int,
    ) -> None:
        self._set_error("")

        try:
            self._service.reopen_case(
                case_id=case_id
            )

            self._service.session.commit()
            self._refresh_case(case_id)

            self.caseActionCompleted.emit(
                "Case reopened."
            )

        except Exception as error:
            self._service.session.rollback()
            self._set_error(str(error))
