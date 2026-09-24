from datetime import datetime

from src.repositories.dashboard_repository import (
    DashboardRepository,
)


class DashboardService:
    def __init__(self, session):
        self.repository = DashboardRepository(
            session
        )

    def load_dashboard(
        self,
        *,
        top_limit: int = 5,
        operational_limit: int = 5,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict:
        return {
            "metrics": (
                self.repository
                .get_primary_metrics()
            ),
            "findings_by_severity": (
                self.repository
                .get_findings_by_severity()
            ),
            "findings_over_time": (
                self.repository
                .get_findings_over_time(
                    start_time=start_time,
                    end_time=end_time,
                )
            ),
            "top_users": (
                self.repository.get_top_users(
                    limit=top_limit
                )
            ),
            "top_hosts": (
                self.repository.get_top_hosts(
                    limit=top_limit
                )
            ),
            "top_source_ips": (
                self.repository
                .get_top_source_ips(
                    limit=top_limit
                )
            ),
            "recent_high_findings": (
                self.repository
                .get_recent_high_findings(
                    limit=operational_limit
                )
            ),
            "active_cases": (
                self.repository.get_active_cases(
                    limit=operational_limit
                )
            ),
        }
