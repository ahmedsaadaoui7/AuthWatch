from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from PySide6.QtCore import (
    QObject,
    Property,
    QThread,
    QUrl,
    Signal,
    Slot,
)

from src.services.analysis_service import AnalysisService


class _AnalysisWorker(QObject):
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(
        self,
        session_factory,
        analysis_arguments: dict[str, Any],
        service_factory=AnalysisService,
    ):
        super().__init__()

        self._session_factory = session_factory
        self._analysis_arguments = analysis_arguments
        self._service_factory = service_factory

    @staticmethod
    def _serialize_investigation(investigation) -> dict:
        return {
            "id": investigation.id,
            "public_id": investigation.public_id,
            "name": investigation.name,
            "status": investigation.status,
            "event_count": investigation.event_count,
            "finding_count": investigation.finding_count,
            "high_severity_count": (
                investigation.high_severity_count
            ),
            "created_at": (
                investigation.created_at.isoformat()
                if investigation.created_at
                else None
            ),
            "completed_at": (
                investigation.completed_at.isoformat()
                if investigation.completed_at
                else None
            ),
        }

    @Slot()
    def run(self) -> None:
        session = None

        try:
            # The worker creates its own SQLAlchemy session.
            # The GUI-thread session is never shared here.
            session = self._session_factory()

            service = self._service_factory(session)

            investigation = service.analyze_and_store(
                **self._analysis_arguments
            )

            # AnalysisService intentionally flushes but does not
            # commit. The workflow boundary owns the commit.
            session.commit()

            serialized = self._serialize_investigation(
                investigation
            )

            self.succeeded.emit(serialized)

        except Exception as error:
            if session is not None:
                session.rollback()

            self.failed.emit(str(error))

        finally:
            if session is not None:
                session.close()

            self.finished.emit()


class AnalysisViewModel(QObject):
    runningChanged = Signal()
    statusChanged = Signal()
    errorChanged = Signal()
    completedInvestigationChanged = Signal()

    analysisCompleted = Signal()

    def __init__(
        self,
        session_factory,
        parent: QObject | None = None,
    ):
        super().__init__(parent)

        self._session_factory = session_factory

        self._running = False
        self._status_message = ""
        self._error_message = ""
        self._completed_investigation = {}

        self._thread: QThread | None = None
        self._worker: _AnalysisWorker | None = None

    @Property(bool, notify=runningChanged)
    def running(self) -> bool:
        return self._running

    @Property(str, notify=statusChanged)
    def statusMessage(self) -> str:
        return self._status_message

    @Property(str, notify=errorChanged)
    def errorMessage(self) -> str:
        return self._error_message

    @Property(
        "QVariantMap",
        notify=completedInvestigationChanged,
    )
    def completedInvestigation(self) -> dict:
        return self._completed_investigation

    def _set_running(self, value: bool) -> None:
        if self._running == value:
            return

        self._running = value
        self.runningChanged.emit()

    def _set_status(self, message: str) -> None:
        if self._status_message == message:
            return

        self._status_message = message
        self.statusChanged.emit()

    def _set_error(self, message: str) -> None:
        if self._error_message == message:
            return

        self._error_message = message
        self.errorChanged.emit()

    @staticmethod
    def _normalize_file_path(
        value: str | None,
    ) -> str | None:
        if value is None:
            return None

        text = str(value).strip()

        if not text:
            return None

        url = QUrl(text)

        if url.isLocalFile():
            local_path = url.toLocalFile()

            if local_path:
                return local_path

        return text

    @classmethod
    def _normalize_payload(
        cls,
        payload: Mapping,
    ) -> dict[str, Any]:
        if not isinstance(payload, Mapping):
            raise ValueError(
                "Analysis request must be a valid object."
            )

        name = str(
            payload.get("investigation_name") or ""
        ).strip()

        if not name:
            raise ValueError(
                "Investigation name is required."
            )

        linux_year_value = str(
            payload.get("linux_year") or ""
        ).strip()

        linux_year = None

        if linux_year_value:
            try:
                linux_year = int(linux_year_value)
            except ValueError as error:
                raise ValueError(
                    "Linux year must be a valid number."
                ) from error

        linux_utc_offset = str(
            payload.get("linux_utc_offset") or ""
        ).strip()

        if not linux_utc_offset:
            linux_utc_offset = None

        analysis_arguments = {
            "name": name,
            "log_file": cls._normalize_file_path(
                payload.get("authwatch_log")
            ),
            "windows_security": (
                cls._normalize_file_path(
                    payload.get("windows_security")
                )
            ),
            "sysmon": cls._normalize_file_path(
                payload.get("sysmon")
            ),
            "linux_auth": cls._normalize_file_path(
                payload.get("linux_auth")
            ),
            "linux_year": linux_year,
            "linux_utc_offset": linux_utc_offset,
        }

        telemetry_fields = (
            "log_file",
            "windows_security",
            "sysmon",
            "linux_auth",
        )

        if not any(
            analysis_arguments[field]
            for field in telemetry_fields
        ):
            raise ValueError(
                "At least one telemetry input is required."
            )

        return analysis_arguments

    @Slot("QVariantMap")
    def startAnalysis(self, payload) -> None:
        if self._running:
            return

        try:
            analysis_arguments = (
                self._normalize_payload(payload)
            )

        except Exception as error:
            self._set_error(str(error))
            self._set_status("Analysis could not start.")
            return

        self._set_error("")
        self._set_status("Analyzing telemetry...")

        self._completed_investigation = {}
        self.completedInvestigationChanged.emit()

        self._set_running(True)

        self._thread = QThread(self)

        self._worker = _AnalysisWorker(
            self._session_factory,
            analysis_arguments,
        )

        self._worker.moveToThread(
            self._thread
        )

        self._thread.started.connect(
            self._worker.run
        )

        self._worker.succeeded.connect(
            self._handle_success
        )

        self._worker.failed.connect(
            self._handle_failure
        )

        self._worker.finished.connect(
            self._thread.quit
        )

        self._worker.finished.connect(
            self._worker.deleteLater
        )

        self._thread.finished.connect(
            self._handle_thread_finished
        )

        self._thread.start()

    @Slot(object)
    def _handle_success(
        self,
        investigation: dict,
    ) -> None:
        self._completed_investigation = dict(
            investigation
        )

        self.completedInvestigationChanged.emit()

        public_id = (
            self._completed_investigation.get(
                "public_id"
            )
            or "investigation"
        )

        self._set_error("")

        self._set_status(
            f"Analysis completed successfully: "
            f"{public_id}"
        )

        self.analysisCompleted.emit()

    @Slot(str)
    def _handle_failure(
        self,
        message: str,
    ) -> None:
        self._set_error(message)

        self._set_status(
            "Analysis failed."
        )

    @Slot()
    def _handle_thread_finished(self) -> None:
        self._set_running(False)

        thread = self._thread

        self._worker = None
        self._thread = None

        if thread is not None:
            thread.deleteLater()
