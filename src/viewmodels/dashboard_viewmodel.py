from __future__ import annotations

from PySide6.QtCore import (
    QObject,
    Property,
    Signal,
    Slot,
)

from src.services.dashboard_service import (
    DashboardService,
)


class DashboardViewModel(QObject):
    dashboardChanged = Signal()
    loadingChanged = Signal()
    errorChanged = Signal()

    def __init__(
        self,
        service: DashboardService,
        parent: QObject | None = None,
    ):
        super().__init__(parent)

        self._service = service

        self._loading = False
        self._error_message = ""

        self._metrics = {
            "total_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "open_cases": 0,
        }

        self._findings_by_severity = {}
        self._findings_over_time = []

        self._top_users = []
        self._top_hosts = []
        self._top_source_ips = []

        self._recent_high_findings = []
        self._active_cases = []

    @Property(bool, notify=loadingChanged)
    def loading(self) -> bool:
        return self._loading

    @Property(str, notify=errorChanged)
    def errorMessage(self) -> str:
        return self._error_message

    @Property(int, notify=dashboardChanged)
    def totalFindings(self) -> int:
        return self._metrics["total_findings"]

    @Property(int, notify=dashboardChanged)
    def highFindings(self) -> int:
        return self._metrics["high_findings"]

    @Property(int, notify=dashboardChanged)
    def mediumFindings(self) -> int:
        return self._metrics["medium_findings"]

    @Property(int, notify=dashboardChanged)
    def openCases(self) -> int:
        return self._metrics["open_cases"]

    @Property(
        "QVariantMap",
        notify=dashboardChanged,
    )
    def findingsBySeverity(self) -> dict:
        return self._findings_by_severity

    @Property(
        "QVariantList",
        notify=dashboardChanged,
    )
    def findingsOverTime(self) -> list:
        return self._findings_over_time

    @Property(
        "QVariantList",
        notify=dashboardChanged,
    )
    def topUsers(self) -> list:
        return self._top_users

    @Property(
        "QVariantList",
        notify=dashboardChanged,
    )
    def topHosts(self) -> list:
        return self._top_hosts

    @Property(
        "QVariantList",
        notify=dashboardChanged,
    )
    def topSourceIps(self) -> list:
        return self._top_source_ips

    @Property(
        "QVariantList",
        notify=dashboardChanged,
    )
    def recentHighFindings(self) -> list:
        return self._recent_high_findings

    @Property(
        "QVariantList",
        notify=dashboardChanged,
    )
    def activeCases(self) -> list:
        return self._active_cases

    @staticmethod
    def _serialize_finding(finding) -> dict:
        return {
            "id": finding.id,
            "investigation_id": (
                finding.investigation_id
            ),
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity,
            "status": finding.status,
            "first_seen": (
                finding.first_seen.isoformat()
                if finding.first_seen
                else None
            ),
            "last_seen": (
                finding.last_seen.isoformat()
                if finding.last_seen
                else None
            ),
        }

    @staticmethod
    def _serialize_case(case) -> dict:
        return {
            "id": case.id,
            "public_id": case.public_id,
            "title": case.title,
            "priority": case.priority,
            "status": case.status,
            "created_at": (
                case.created_at.isoformat()
                if case.created_at
                else None
            ),
        }

    @Slot()
    def loadDashboard(self) -> None:
        if self._loading:
            return

        self._loading = True
        self.loadingChanged.emit()

        self._error_message = ""
        self.errorChanged.emit()

        try:
            snapshot = (
                self._service.load_dashboard()
            )

            self._metrics = snapshot["metrics"]

            self._findings_by_severity = (
                snapshot["findings_by_severity"]
            )

            self._findings_over_time = (
                snapshot["findings_over_time"]
            )

            self._top_users = snapshot["top_users"]
            self._top_hosts = snapshot["top_hosts"]

            self._top_source_ips = (
                snapshot["top_source_ips"]
            )

            self._recent_high_findings = [
                self._serialize_finding(finding)
                for finding
                in snapshot[
                    "recent_high_findings"
                ]
            ]

            self._active_cases = [
                self._serialize_case(case)
                for case
                in snapshot["active_cases"]
            ]

            self.dashboardChanged.emit()

        except Exception as error:
            self._error_message = str(error)
            self.errorChanged.emit()

        finally:
            self._loading = False
            self.loadingChanged.emit()
