from datetime import datetime, timezone

from src.models import Case, Finding
from src.viewmodels.dashboard_viewmodel import (
    DashboardViewModel,
)


class FakeDashboardService:
    def load_dashboard(self):
        finding = Finding(
            id=10,
            investigation_id=20,
            finding_type="detection",
            rule_id="AUTH-BF-001",
            title="Potential Brute-Force Activity",
            severity="high",
            status="new",
            summary="Potential Brute-Force Activity",
            details={},
            first_seen=datetime(
                2026, 9, 24, 20, 0,
                tzinfo=timezone.utc,
            ),
            last_seen=datetime(
                2026, 9, 24, 20, 5,
                tzinfo=timezone.utc,
            ),
        )

        case = Case(
            id=30,
            public_id="AW-0030",
            title="Authentication Investigation",
            priority="high",
            status="investigating",
            created_at=datetime(
                2026, 9, 24, 20, 10,
                tzinfo=timezone.utc,
            ),
        )

        return {
            "metrics": {
                "total_findings": 12,
                "high_findings": 4,
                "medium_findings": 6,
                "open_cases": 3,
            },
            "findings_by_severity": {
                "high": 4,
                "medium": 6,
                "low": 2,
            },
            "findings_over_time": [
                {
                    "date": "2026-09-24",
                    "count": 12,
                }
            ],
            "top_users": [
                {
                    "value": "admin",
                    "count": 5,
                }
            ],
            "top_hosts": [
                {
                    "value": "WIN-01",
                    "count": 4,
                }
            ],
            "top_source_ips": [
                {
                    "value": "10.0.0.8",
                    "count": 3,
                }
            ],
            "recent_high_findings": [
                finding
            ],
            "active_cases": [
                case
            ],
        }


def test_dashboard_viewmodel_loads_dashboard():
    viewmodel = DashboardViewModel(
        FakeDashboardService()
    )

    viewmodel.loadDashboard()

    assert viewmodel.loading is False
    assert viewmodel.errorMessage == ""

    assert viewmodel.totalFindings == 12
    assert viewmodel.highFindings == 4
    assert viewmodel.mediumFindings == 6
    assert viewmodel.openCases == 3

    assert viewmodel.findingsBySeverity == {
        "high": 4,
        "medium": 6,
        "low": 2,
    }

    assert viewmodel.topUsers == [
        {
            "value": "admin",
            "count": 5,
        }
    ]

    assert (
        viewmodel.recentHighFindings[0][
            "rule_id"
        ]
        == "AUTH-BF-001"
    )

    assert (
        viewmodel.activeCases[0]["public_id"]
        == "AW-0030"
    )


class FailingDashboardService:
    def load_dashboard(self):
        raise RuntimeError(
            "Dashboard database unavailable"
        )


def test_dashboard_viewmodel_exposes_error_state():
    viewmodel = DashboardViewModel(
        FailingDashboardService()
    )

    viewmodel.loadDashboard()

    assert viewmodel.loading is False

    assert (
        viewmodel.errorMessage
        == "Dashboard database unavailable"
    )
