from src.database import (
    create_database_engine,
    create_session_factory,
)

from src.models.base import Base

from src.models import (
    Case,
    Finding,
    Investigation,
)

from datetime import datetime, timezone

from src.repositories.dashboard_repository import (
    DashboardRepository,
)


def test_dashboard_repository_returns_zero_metrics(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        repository = DashboardRepository(session)

        metrics = repository.get_primary_metrics()

        assert metrics == {
            "total_findings": 0,
            "high_findings": 0,
            "medium_findings": 0,
            "open_cases": 0,
        }


def test_dashboard_repository_returns_primary_metrics(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0500",
        name="Dashboard Test",
        status="complete",
    )

    investigation.findings.extend(
        [
            Finding(
                finding_type="detection",
                rule_id="TEST-001",
                title="High Finding One",
                severity="high",
                status="new",
                summary="High Finding One",
                details={},
            ),
            Finding(
                finding_type="detection",
                rule_id="TEST-002",
                title="High Finding Two",
                severity="high",
                status="new",
                summary="High Finding Two",
                details={},
            ),
            Finding(
                finding_type="detection",
                rule_id="TEST-003",
                title="Medium Finding",
                severity="medium",
                status="new",
                summary="Medium Finding",
                details={},
            ),
            Finding(
                finding_type="detection",
                rule_id="TEST-004",
                title="Low Finding",
                severity="low",
                status="new",
                summary="Low Finding",
                details={},
            ),
        ]
    )

    cases = [
        Case(
            public_id="AW-0500",
            title="Open Case",
            priority="high",
            status="open",
        ),
        Case(
            public_id="AW-0501",
            title="Investigating Case",
            priority="medium",
            status="investigating",
        ),
        Case(
            public_id="AW-0502",
            title="Closed Case",
            priority="low",
            status="closed",
        ),
    ]

    with SessionLocal() as session:
        session.add(investigation)
        session.add_all(cases)
        session.commit()

        repository = DashboardRepository(session)

        metrics = repository.get_primary_metrics()

        assert metrics == {
            "total_findings": 4,
            "high_findings": 2,
            "medium_findings": 1,
            "open_cases": 2,
        }


def test_dashboard_repository_groups_findings_by_severity(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0501",
        name="Severity Dashboard Test",
        status="complete",
    )

    investigation.findings.extend(
        [
            Finding(
                finding_type="detection",
                rule_id="TEST-010",
                title="High One",
                severity="high",
                status="new",
                summary="High One",
                details={},
            ),
            Finding(
                finding_type="detection",
                rule_id="TEST-011",
                title="High Two",
                severity="high",
                status="new",
                summary="High Two",
                details={},
            ),
            Finding(
                finding_type="detection",
                rule_id="TEST-012",
                title="Medium",
                severity="medium",
                status="new",
                summary="Medium",
                details={},
            ),
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

        repository = DashboardRepository(session)

        severity_counts = (
            repository.get_findings_by_severity()
        )

        assert severity_counts == {
            "high": 2,
            "medium": 1,
        }


def test_dashboard_repository_returns_top_affected_entities(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0502",
        name="Affected Entities Test",
        status="complete",
    )

    investigation.findings.extend(
        [
            Finding(
                finding_type="detection",
                rule_id="TEST-020",
                title="Finding One",
                severity="high",
                status="new",
                summary="Finding One",
                details={
                    "username": "admin",
                    "host": "WIN-01",
                    "source_ip": "10.0.0.8",
                },
            ),
            Finding(
                finding_type="detection",
                rule_id="TEST-021",
                title="Finding Two",
                severity="medium",
                status="new",
                summary="Finding Two",
                details={
                    "usernames": [
                        "admin",
                        "alice",
                    ],
                    "host": "WIN-01",
                    "source_ips": [
                        "10.0.0.8",
                        "10.0.0.9",
                    ],
                },
            ),
            Finding(
                finding_type="correlation",
                rule_id="TEST-022",
                title="Finding Three",
                severity="medium",
                status="new",
                summary="Finding Three",
                details={
                    "username": "alice",
                    "host": "WIN-02",
                    "source_ip": "10.0.0.9",
                },
            ),
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

        repository = DashboardRepository(session)

        assert repository.get_top_users(
            limit=5
        ) == [
            {
                "value": "admin",
                "count": 2,
            },
            {
                "value": "alice",
                "count": 2,
            },
        ]

        assert repository.get_top_hosts(
            limit=5
        ) == [
            {
                "value": "WIN-01",
                "count": 2,
            },
            {
                "value": "WIN-02",
                "count": 1,
            },
        ]

        assert repository.get_top_source_ips(
            limit=5
        ) == [
            {
                "value": "10.0.0.8",
                "count": 2,
            },
            {
                "value": "10.0.0.9",
                "count": 2,
            },
        ]


def test_dashboard_repository_returns_operational_sections(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0503",
        name="Operational Dashboard Test",
        status="complete",
    )

    investigation.findings.extend(
        [
            Finding(
                finding_type="detection",
                rule_id="TEST-030",
                title="Older High",
                severity="high",
                status="new",
                summary="Older High",
                details={},
                first_seen=datetime(
                    2026, 9, 20, 10, 0,
                    tzinfo=timezone.utc,
                ),
                last_seen=datetime(
                    2026, 9, 20, 10, 5,
                    tzinfo=timezone.utc,
                ),
            ),
            Finding(
                finding_type="detection",
                rule_id="TEST-031",
                title="Recent High",
                severity="high",
                status="new",
                summary="Recent High",
                details={},
                first_seen=datetime(
                    2026, 9, 22, 10, 0,
                    tzinfo=timezone.utc,
                ),
                last_seen=datetime(
                    2026, 9, 22, 10, 5,
                    tzinfo=timezone.utc,
                ),
            ),
        ]
    )

    cases = [
        Case(
            public_id="AW-0510",
            title="Active Open Case",
            priority="high",
            status="open",
        ),
        Case(
            public_id="AW-0511",
            title="Active Investigation",
            priority="medium",
            status="investigating",
        ),
        Case(
            public_id="AW-0512",
            title="Closed Case",
            priority="low",
            status="closed",
        ),
    ]

    with SessionLocal() as session:
        session.add(investigation)
        session.add_all(cases)
        session.commit()

        repository = DashboardRepository(session)

        recent = (
            repository.get_recent_high_findings(
                limit=5
            )
        )

        active_cases = (
            repository.get_active_cases(
                limit=5
            )
        )

        assert [
            finding.title
            for finding in recent
        ] == [
            "Recent High",
            "Older High",
        ]

        assert {
            case.public_id
            for case in active_cases
        } == {
            "AW-0510",
            "AW-0511",
        }


def test_dashboard_repository_groups_findings_over_time(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0504",
        name="Timeline Dashboard Test",
        status="complete",
    )

    for index, first_seen in enumerate(
        [
            datetime(
                2026, 9, 20, 10, 0,
                tzinfo=timezone.utc,
            ),
            datetime(
                2026, 9, 20, 11, 0,
                tzinfo=timezone.utc,
            ),
            datetime(
                2026, 9, 21, 12, 0,
                tzinfo=timezone.utc,
            ),
        ]
    ):
        investigation.findings.append(
            Finding(
                finding_type="detection",
                rule_id=f"TIME-{index}",
                title=f"Timeline Finding {index}",
                severity="medium",
                status="new",
                summary=(
                    f"Timeline Finding {index}"
                ),
                details={},
                first_seen=first_seen,
                last_seen=first_seen,
            )
        )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

        repository = DashboardRepository(session)

        values = (
            repository.get_findings_over_time()
        )

        assert values == [
            {
                "date": "2026-09-20",
                "count": 2,
            },
            {
                "date": "2026-09-21",
                "count": 1,
            },
        ]
