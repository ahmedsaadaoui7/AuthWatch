from sqlalchemy import select

from src.database import (
    create_database_engine,
    create_session_factory,
)

from datetime import datetime, timezone

from src.models.base import Base
from src.models.case import Case
from src.models.case_activity import CaseActivity
from src.models.case_finding import CaseFinding
from src.models.case_note import CaseNote
from src.models.event import Event
from src.models.finding import Finding
from src.models.finding_event import FindingEvent
from src.models.investigation import Investigation
from src.models.telemetry_source import TelemetrySource
from src.repositories.finding_repository import FindingRepository


def test_finding_repository_get_by_id_returns_finding(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0007",
        name="Authentication Investigation",
        status="complete",
    )

    finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    investigation.findings.append(finding)

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

        finding_id = finding.id

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored = repository.get_by_id(finding_id)

        assert stored is not None
        assert stored.rule_id == "AUTH-BF-001"
        assert stored.title == "Potential Brute-Force Activity"
        assert stored.severity == "high"
        assert stored.status == "new"


def test_finding_repository_get_by_id_returns_none_when_missing(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored = repository.get_by_id(999)

        assert stored is None


def test_finding_repository_list_all_returns_findings(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0008",
        name="Authentication Investigation",
        status="complete",
    )

    first_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    second_finding = Finding(
        finding_type="correlation",
        rule_id="CORR-AUTH-EXEC-001",
        title="Authentication to Process Activity",
        severity="medium",
        status="reviewed",
        summary="Authentication followed by process activity.",
        details={},
    )

    investigation.findings.append(first_finding)
    investigation.findings.append(second_finding)

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored_findings = repository.list_all()

        assert len(stored_findings) == 2
        assert stored_findings[0].rule_id == "AUTH-BF-001"
        assert stored_findings[1].rule_id == "CORR-AUTH-EXEC-001"


def test_finding_repository_list_all_returns_empty_list_when_no_findings(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored_findings = repository.list_all()

        assert stored_findings == []


def test_finding_repository_list_by_status_returns_matching_findings(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0009",
        name="Authentication Investigation",
        status="complete",
    )

    new_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    reviewed_finding = Finding(
        finding_type="correlation",
        rule_id="CORR-AUTH-EXEC-001",
        title="Authentication to Process Activity",
        severity="medium",
        status="reviewed",
        summary="Authentication followed by process activity.",
        details={},
    )

    investigation.findings.append(new_finding)
    investigation.findings.append(reviewed_finding)

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored_findings = repository.list_by_status("reviewed")

        assert len(stored_findings) == 1
        assert stored_findings[0].rule_id == "CORR-AUTH-EXEC-001"
        assert stored_findings[0].status == "reviewed"



def test_finding_repository_add_stores_finding(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0010",
        name="Authentication Investigation",
        status="complete",
    )

    finding = Finding(
        investigation=investigation,
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    with SessionLocal() as session:
        repository = FindingRepository(session)

        repository.add(finding)

        session.commit()

        finding_id = finding.id

    with SessionLocal() as session:
        stored = session.get(Finding, finding_id)

        assert stored is not None
        assert stored.rule_id == "AUTH-BF-001"
        assert stored.severity == "high"


def test_finding_repository_add_does_not_commit_automatically(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0011",
        name="Authentication Investigation",
        status="complete",
    )

    finding = Finding(
        investigation=investigation,
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    with SessionLocal() as session:
        repository = FindingRepository(session)

        repository.add(finding)

        session.rollback()

    with SessionLocal() as session:
        stored = session.execute(
            select(Finding).where(
                Finding.rule_id == "AUTH-BF-001"
            )
        ).scalar_one_or_none()

        assert stored is None


def test_finding_repository_list_by_severity_returns_matching_findings(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0012",
        name="Authentication Investigation",
        status="complete",
    )

    high_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    medium_finding = Finding(
        finding_type="correlation",
        rule_id="CORR-AUTH-EXEC-001",
        title="Authentication to Process Activity",
        severity="medium",
        status="new",
        summary="Authentication followed by process activity.",
        details={},
    )

    investigation.findings.append(high_finding)
    investigation.findings.append(medium_finding)

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored_findings = repository.list_by_severity("high")

        assert len(stored_findings) == 1
        assert stored_findings[0].rule_id == "AUTH-BF-001"
        assert stored_findings[0].severity == "high"


def test_finding_repository_list_filtered_combines_filters(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0013",
        name="Authentication Investigation",
        status="complete",
    )

    high_new = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    high_reviewed = Finding(
        finding_type="detection",
        rule_id="AUTH-PS-001",
        title="Potential Password Spray Activity",
        severity="high",
        status="reviewed",
        summary="Password spray activity detected.",
        details={},
    )

    medium_new = Finding(
        finding_type="correlation",
        rule_id="CORR-AUTH-EXEC-001",
        title="Authentication to Process Activity",
        severity="medium",
        status="new",
        summary="Authentication followed by process activity.",
        details={},
    )

    investigation.findings.extend(
        [
            high_new,
            high_reviewed,
            medium_new,
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored_findings = repository.list_filtered(
            status="new",
            severity="high",
        )

        assert len(stored_findings) == 1
        assert stored_findings[0].rule_id == "AUTH-BF-001"


def test_finding_repository_list_filtered_filters_by_type(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0014",
        name="Authentication Investigation",
        status="complete",
    )

    detection = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    correlation = Finding(
        finding_type="correlation",
        rule_id="CORR-AUTH-EXEC-001",
        title="Authentication to Process Activity",
        severity="high",
        status="new",
        summary="Authentication followed by process activity.",
        details={},
    )

    investigation.findings.extend(
        [
            detection,
            correlation,
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored_findings = repository.list_filtered(
            finding_type="correlation",
        )

        assert len(stored_findings) == 1
        assert (
            stored_findings[0].rule_id
            == "CORR-AUTH-EXEC-001"
        )
        assert stored_findings[0].finding_type == "correlation"


def test_finding_repository_list_filtered_filters_by_rule_id(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0015",
        name="Authentication Investigation",
        status="complete",
    )

    brute_force = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    password_spray = Finding(
        finding_type="detection",
        rule_id="AUTH-PS-001",
        title="Potential Password Spray Activity",
        severity="high",
        status="new",
        summary="Password spray activity detected.",
        details={},
    )

    investigation.findings.extend(
        [
            brute_force,
            password_spray,
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored_findings = repository.list_filtered(
            rule_id="AUTH-PS-001",
        )

        assert len(stored_findings) == 1
        assert stored_findings[0].rule_id == "AUTH-PS-001"


def test_finding_repository_list_filtered_filters_by_investigation(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    first_investigation = Investigation(
        public_id="INV-2026-0016",
        name="First Investigation",
        status="complete",
    )

    second_investigation = Investigation(
        public_id="INV-2026-0017",
        name="Second Investigation",
        status="complete",
    )

    first_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    second_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-PS-001",
        title="Potential Password Spray Activity",
        severity="high",
        status="new",
        summary="Password spray activity detected.",
        details={},
    )

    first_investigation.findings.append(first_finding)
    second_investigation.findings.append(second_finding)

    with SessionLocal() as session:
        session.add(first_investigation)
        session.add(second_investigation)
        session.commit()

        first_investigation_id = first_investigation.id

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored_findings = repository.list_filtered(
            investigation_id=first_investigation_id,
        )

        assert len(stored_findings) == 1
        assert stored_findings[0].rule_id == "AUTH-BF-001"


def test_finding_repository_list_filtered_filters_by_username(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0018",
        name="Authentication Investigation",
        status="complete",
    )

    telemetry_source = TelemetrySource(
        filename="auth.log",
        source_type="linux_auth",
        file_size=1024,
        sha256="a" * 64,
        original_path="/var/log/auth.log",
    )

    admin_event = Event(
        timestamp=datetime(
            2026,
            9,
            21,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        source="linux_auth",
        event_type="authentication_failure",
        username="admin",
    )

    user_event = Event(
        timestamp=datetime(
            2026,
            9,
            21,
            10,
            1,
            tzinfo=timezone.utc,
        ),
        source="linux_auth",
        event_type="authentication_failure",
        username="user",
    )

    telemetry_source.events.extend(
        [
            admin_event,
            user_event,
        ]
    )

    investigation.telemetry_sources.append(
        telemetry_source
    )

    investigation.events.extend(
        [
            admin_event,
            user_event,
        ]
    )

    admin_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    user_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-SF-001",
        title="Successful Login After Failures",
        severity="medium",
        status="new",
        summary="Successful login followed failures.",
        details={},
    )

    admin_finding.finding_events.append(
        FindingEvent(event=admin_event)
    )

    user_finding.finding_events.append(
        FindingEvent(event=user_event)
    )

    investigation.findings.extend(
        [
            admin_finding,
            user_finding,
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored_findings = repository.list_filtered(
            username="admin",
        )

        assert len(stored_findings) == 1
        assert stored_findings[0].rule_id == "AUTH-BF-001"


def test_finding_repository_list_filtered_filters_by_host(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0019",
        name="Endpoint Investigation",
        status="complete",
    )

    telemetry_source = TelemetrySource(
        filename="sysmon.json",
        source_type="sysmon",
        file_size=2048,
        sha256="b" * 64,
        original_path="/data/sysmon.json",
    )

    first_event = Event(
        timestamp=datetime(
            2026,
            9,
            21,
            11,
            0,
            tzinfo=timezone.utc,
        ),
        source="sysmon",
        event_type="process_creation",
        host="WIN-01",
    )

    second_event = Event(
        timestamp=datetime(
            2026,
            9,
            21,
            11,
            1,
            tzinfo=timezone.utc,
        ),
        source="sysmon",
        event_type="process_creation",
        host="WIN-02",
    )

    telemetry_source.events.extend(
        [
            first_event,
            second_event,
        ]
    )

    investigation.telemetry_sources.append(
        telemetry_source
    )

    investigation.events.extend(
        [
            first_event,
            second_event,
        ]
    )

    first_finding = Finding(
        finding_type="correlation",
        rule_id="CORR-PROC-NET-001",
        title="Process to Network Activity",
        severity="high",
        status="new",
        summary="Process followed by network activity.",
        details={},
    )

    second_finding = Finding(
        finding_type="correlation",
        rule_id="CORR-PROC-DNS-001",
        title="Process to DNS Activity",
        severity="medium",
        status="new",
        summary="Process followed by DNS activity.",
        details={},
    )

    first_finding.finding_events.append(
        FindingEvent(event=first_event)
    )

    second_finding.finding_events.append(
        FindingEvent(event=second_event)
    )

    investigation.findings.extend(
        [
            first_finding,
            second_finding,
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored_findings = repository.list_filtered(
            host="WIN-01",
        )

        assert len(stored_findings) == 1
        assert stored_findings[0].rule_id == "CORR-PROC-NET-001"


def test_finding_repository_list_filtered_filters_by_source_ip(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0020",
        name="Network Investigation",
        status="complete",
    )

    telemetry_source = TelemetrySource(
        filename="auth.log",
        source_type="linux_auth",
        file_size=1024,
        sha256="c" * 64,
        original_path="/var/log/auth.log",
    )

    first_event = Event(
        timestamp=datetime(
            2026,
            9,
            21,
            12,
            0,
            tzinfo=timezone.utc,
        ),
        source="linux_auth",
        event_type="authentication_failure",
        source_ip="10.0.0.8",
    )

    second_event = Event(
        timestamp=datetime(
            2026,
            9,
            21,
            12,
            1,
            tzinfo=timezone.utc,
        ),
        source="linux_auth",
        event_type="authentication_failure",
        source_ip="10.0.0.9",
    )

    telemetry_source.events.extend(
        [
            first_event,
            second_event,
        ]
    )

    investigation.telemetry_sources.append(
        telemetry_source
    )

    investigation.events.extend(
        [
            first_event,
            second_event,
        ]
    )

    first_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    second_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-PS-001",
        title="Potential Password Spray Activity",
        severity="high",
        status="new",
        summary="Password spray activity detected.",
        details={},
    )

    first_finding.finding_events.append(
        FindingEvent(event=first_event)
    )

    second_finding.finding_events.append(
        FindingEvent(event=second_event)
    )

    investigation.findings.extend(
        [
            first_finding,
            second_finding,
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored_findings = repository.list_filtered(
            source_ip="10.0.0.8",
        )

        assert len(stored_findings) == 1
        assert stored_findings[0].rule_id == "AUTH-BF-001"


def test_finding_repository_list_filtered_filters_by_telemetry_source(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0021",
        name="Multi-Source Investigation",
        status="complete",
    )

    auth_source = TelemetrySource(
        filename="auth.log",
        source_type="linux_auth",
        file_size=1024,
        sha256="d" * 64,
        original_path="/var/log/auth.log",
    )

    sysmon_source = TelemetrySource(
        filename="sysmon.json",
        source_type="sysmon",
        file_size=2048,
        sha256="e" * 64,
        original_path="/data/sysmon.json",
    )

    auth_event = Event(
        timestamp=datetime(
            2026,
            9,
            21,
            13,
            0,
            tzinfo=timezone.utc,
        ),
        source="linux_auth",
        event_type="authentication_failure",
        username="admin",
    )

    sysmon_event = Event(
        timestamp=datetime(
            2026,
            9,
            21,
            13,
            1,
            tzinfo=timezone.utc,
        ),
        source="sysmon",
        event_type="process_creation",
        host="WIN-01",
    )

    auth_source.events.append(auth_event)
    sysmon_source.events.append(sysmon_event)

    investigation.telemetry_sources.extend(
        [
            auth_source,
            sysmon_source,
        ]
    )

    investigation.events.extend(
        [
            auth_event,
            sysmon_event,
        ]
    )

    auth_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    sysmon_finding = Finding(
        finding_type="correlation",
        rule_id="CORR-PROC-NET-001",
        title="Process to Network Activity",
        severity="high",
        status="new",
        summary="Process followed by network activity.",
        details={},
    )

    auth_finding.finding_events.append(
        FindingEvent(event=auth_event)
    )

    sysmon_finding.finding_events.append(
        FindingEvent(event=sysmon_event)
    )

    investigation.findings.extend(
        [
            auth_finding,
            sysmon_finding,
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

        auth_source_id = auth_source.id

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored_findings = repository.list_filtered(
            telemetry_source_id=auth_source_id,
        )

        assert len(stored_findings) == 1
        assert stored_findings[0].rule_id == "AUTH-BF-001"


def test_finding_repository_list_filtered_filters_by_time_overlap(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0022",
        name="Time Filter Investigation",
        status="complete",
    )

    overlapping_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        first_seen=datetime(
            2026,
            9,
            21,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        last_seen=datetime(
            2026,
            9,
            21,
            10,
            15,
            tzinfo=timezone.utc,
        ),
        summary="Repeated authentication failures detected.",
        details={},
    )

    earlier_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-PS-001",
        title="Potential Password Spray Activity",
        severity="high",
        status="new",
        first_seen=datetime(
            2026,
            9,
            21,
            9,
            0,
            tzinfo=timezone.utc,
        ),
        last_seen=datetime(
            2026,
            9,
            21,
            9,
            30,
            tzinfo=timezone.utc,
        ),
        summary="Password spray activity detected.",
        details={},
    )

    investigation.findings.extend(
        [
            overlapping_finding,
            earlier_finding,
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored_findings = repository.list_filtered(
            start_time=datetime(
                2026,
                9,
                21,
                10,
                10,
                tzinfo=timezone.utc,
            ),
            end_time=datetime(
                2026,
                9,
                21,
                10,
                20,
                tzinfo=timezone.utc,
            ),
        )

        assert len(stored_findings) == 1
        assert stored_findings[0].rule_id == "AUTH-BF-001"


def test_finding_repository_list_filtered_searches_finding_text(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0023",
        name="Search Investigation",
        status="complete",
    )

    brute_force = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    password_spray = Finding(
        finding_type="detection",
        rule_id="AUTH-PS-001",
        title="Potential Password Spray Activity",
        severity="high",
        status="new",
        summary="Multiple accounts received authentication failures.",
        details={},
    )

    correlation = Finding(
        finding_type="correlation",
        rule_id="CORR-AUTH-EXEC-001",
        title="Authentication to Process Activity",
        severity="medium",
        status="new",
        summary="PowerShell execution followed authentication activity.",
        details={},
    )

    investigation.findings.extend(
        [
            brute_force,
            password_spray,
            correlation,
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        repository = FindingRepository(session)

        title_results = repository.list_filtered(
            search="brute",
        )

        rule_results = repository.list_filtered(
            search="AUTH-PS",
        )

        summary_results = repository.list_filtered(
            search="powershell",
        )

        assert len(title_results) == 1
        assert title_results[0].rule_id == "AUTH-BF-001"

        assert len(rule_results) == 1
        assert rule_results[0].rule_id == "AUTH-PS-001"

        assert len(summary_results) == 1
        assert (
            summary_results[0].rule_id
            == "CORR-AUTH-EXEC-001"
        )


def test_finding_repository_list_filtered_uses_default_soc_sorting(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0024",
        name="Sorting Investigation",
        status="complete",
    )

    medium_recent = Finding(
        finding_type="detection",
        rule_id="AUTH-SF-001",
        title="Successful Login After Failures",
        severity="medium",
        status="new",
        first_seen=datetime(
            2026, 9, 21, 12, 0,
            tzinfo=timezone.utc,
        ),
        last_seen=datetime(
            2026, 9, 21, 12, 30,
            tzinfo=timezone.utc,
        ),
        summary="Recent medium-severity finding.",
        details={},
    )

    high_older = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        first_seen=datetime(
            2026, 9, 21, 10, 0,
            tzinfo=timezone.utc,
        ),
        last_seen=datetime(
            2026, 9, 21, 10, 30,
            tzinfo=timezone.utc,
        ),
        summary="Older high-severity finding.",
        details={},
    )

    high_recent = Finding(
        finding_type="detection",
        rule_id="AUTH-PS-001",
        title="Potential Password Spray Activity",
        severity="high",
        status="new",
        first_seen=datetime(
            2026, 9, 21, 11, 0,
            tzinfo=timezone.utc,
        ),
        last_seen=datetime(
            2026, 9, 21, 11, 30,
            tzinfo=timezone.utc,
        ),
        summary="Recent high-severity finding.",
        details={},
    )

    investigation.findings.extend(
        [
            medium_recent,
            high_older,
            high_recent,
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        repository = FindingRepository(session)

        stored_findings = repository.list_filtered()

        assert [
            finding.rule_id
            for finding in stored_findings
        ] == [
            "AUTH-PS-001",
            "AUTH-BF-001",
            "AUTH-SF-001",
        ]
