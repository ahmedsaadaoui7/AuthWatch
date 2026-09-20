from sqlalchemy import select

from src.database import (
    create_database_engine,
    create_session_factory,
)
from src.models.base import Base
from src.models.investigation import Investigation
from src.models.telemetry_source import TelemetrySource

from datetime import datetime, timezone

from src.models.event import Event
from src.models.finding import Finding
from src.models.finding_event import FindingEvent
from src.models.case import Case
from src.models.case_finding import CaseFinding


def test_investigation_can_be_stored_and_loaded(tmp_path):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0001",
        name="Windows Workstation Investigation",
        status="complete",
        event_count=120,
        finding_count=4,
        high_severity_count=1,
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        stored = session.execute(
            select(Investigation).where(
                Investigation.public_id
                == "INV-2026-0001"
            )
        ).scalar_one()

        assert stored.name == (
            "Windows Workstation Investigation"
        )
        assert stored.status == "complete"
        assert stored.event_count == 120
        assert stored.finding_count == 4
        assert stored.high_severity_count == 1


def test_telemetry_source_belongs_to_investigation(tmp_path):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0002",
        name="Endpoint Telemetry Investigation",
        status="complete",
    )

    telemetry_source = TelemetrySource(
        filename="Security.evtx",
        source_type="windows_security",
        file_size=5242880,
        sha256="a" * 64,
        original_path="/evidence/Security.evtx",
    )

    investigation.telemetry_sources.append(
        telemetry_source
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        stored = session.execute(
            select(Investigation).where(
                Investigation.public_id
                == "INV-2026-0002"
            )
        ).scalar_one()

        assert len(stored.telemetry_sources) == 1

        source = stored.telemetry_sources[0]

        assert source.filename == "Security.evtx"
        assert source.source_type == "windows_security"
        assert source.file_size == 5242880
        assert source.sha256 == "a" * 64
        assert source.original_path == (
            "/evidence/Security.evtx"
        )


def test_event_belongs_to_investigation_and_telemetry_source(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0003",
        name="Windows Endpoint Investigation",
        status="complete",
    )

    telemetry_source = TelemetrySource(
        filename="Security.evtx",
        source_type="windows_security",
        file_size=5242880,
        sha256="b" * 64,
        original_path="/evidence/Security.evtx",
    )

    event = Event(
        timestamp=datetime(
            2026,
            9,
            18,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        source="windows_security",
        event_id="4624",
        event_type="authentication_success",
        host="WIN-CLIENT01",
        username="alice",
        session_id="0x1234",
        source_ip="10.0.0.50",
        result="success",
        details={
            "logon_type": "3",
        },
    )

    telemetry_source.events.append(event)

    investigation.telemetry_sources.append(
        telemetry_source
    )

    investigation.events.append(event)

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        stored = session.execute(
            select(Investigation).where(
                Investigation.public_id
                == "INV-2026-0003"
            )
        ).scalar_one()

        assert len(stored.events) == 1

        stored_event = stored.events[0]

        assert stored_event.event_id == "4624"
        assert stored_event.event_type == (
            "authentication_success"
        )
        assert stored_event.username == "alice"
        assert stored_event.source_ip == "10.0.0.50"
        assert stored_event.details["logon_type"] == "3"

        assert stored_event.telemetry_source.filename == (
            "Security.evtx"
        )


def test_findings_belong_to_investigation(tmp_path):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0004",
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
        details={
            "username": "admin",
            "source_ip": "10.0.0.50",
        },
    )

    correlation = Finding(
        finding_type="correlation",
        rule_id="CORR-AUTH-EXEC-001",
        title="Authentication to Process Activity",
        severity="medium",
        status="new",
        summary=(
            "Authentication activity was followed "
            "by process execution."
        ),
        details={
            "host": "WIN-CLIENT01",
        },
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
        stored = session.execute(
            select(Investigation).where(
                Investigation.public_id
                == "INV-2026-0004"
            )
        ).scalar_one()

        assert len(stored.findings) == 2

        finding_types = {
            finding.finding_type
            for finding in stored.findings
        }

        assert finding_types == {
            "detection",
            "correlation",
        }


def test_finding_can_link_to_supporting_event(tmp_path):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0005",
        name="Brute Force Investigation",
        status="complete",
    )

    telemetry_source = TelemetrySource(
        filename="Security.evtx",
        source_type="windows_security",
        file_size=5242880,
        sha256="c" * 64,
        original_path="/evidence/Security.evtx",
    )

    event = Event(
        timestamp=datetime(
            2026,
            9,
            19,
            8,
            0,
            tzinfo=timezone.utc,
        ),
        source="windows_security",
        event_id="4625",
        event_type="authentication_failure",
        host="WIN-CLIENT01",
        username="admin",
        source_ip="10.0.0.50",
        result="failure",
        details={},
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

    telemetry_source.events.append(event)
    investigation.telemetry_sources.append(
        telemetry_source
    )
    investigation.events.append(event)
    investigation.findings.append(finding)

    finding_event = FindingEvent(
        event=event,
    )

    finding.finding_events.append(
        finding_event
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        stored_finding = session.execute(
            select(Finding).where(
                Finding.rule_id == "AUTH-BF-001"
            )
        ).scalar_one()

        assert len(stored_finding.finding_events) == 1

        linked_event = (
            stored_finding.finding_events[0].event
        )

        assert linked_event.event_id == "4625"
        assert linked_event.username == "admin"
        assert linked_event.source_ip == "10.0.0.50"


def test_case_can_be_stored_and_loaded(tmp_path):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    case = Case(
        public_id="AW-0001",
        title="Investigate repeated admin login failures",
        priority="high",
        status="open",
    )

    with SessionLocal() as session:
        session.add(case)
        session.commit()

    with SessionLocal() as session:
        stored = session.execute(
            select(Case).where(
                Case.public_id == "AW-0001"
            )
        ).scalar_one()

        assert stored.title == (
            "Investigate repeated admin login failures"
        )
        assert stored.priority == "high"
        assert stored.status == "open"
        assert stored.resolution is None
        assert stored.closing_note is None
        assert stored.closed_at is None


def test_case_can_link_to_finding(tmp_path):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0006",
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

    case = Case(
        public_id="AW-0002",
        title="Investigate brute-force activity",
        priority="high",
        status="open",
    )

    case_finding = CaseFinding(
        finding=finding,
    )

    case.case_findings.append(case_finding)

    with SessionLocal() as session:
        session.add(investigation)
        session.add(case)
        session.commit()

    with SessionLocal() as session:
        stored_case = session.execute(
            select(Case).where(
                Case.public_id == "AW-0002"
            )
        ).scalar_one()

        assert len(stored_case.case_findings) == 1

        linked_finding = stored_case.case_findings[0].finding

        assert linked_finding.rule_id == "AUTH-BF-001"
        assert linked_finding.severity == "high"
