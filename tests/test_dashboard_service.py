from src.database import (
    create_database_engine,
    create_session_factory,
)
from src.models.base import Base
from src.services.dashboard_service import (
    DashboardService,
)


def test_dashboard_service_returns_empty_snapshot(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        service = DashboardService(session)

        dashboard = service.load_dashboard()

        assert dashboard["metrics"] == {
            "total_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "open_cases": 0,
        }

        assert (
            dashboard["findings_by_severity"]
            == {}
        )

        assert (
            dashboard["findings_over_time"]
            == []
        )

        assert dashboard["top_users"] == []
        assert dashboard["top_hosts"] == []
        assert dashboard["top_source_ips"] == []

        assert (
            dashboard["recent_high_findings"]
            == []
        )

        assert dashboard["active_cases"] == []
