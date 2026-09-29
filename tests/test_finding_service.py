import pytest

from src.database import (
    create_database_engine,
    create_session_factory,
)
from src.models.base import Base
from datetime import datetime, timezone

from src.models.application_setting import ApplicationSetting
from src.models.case import Case
from src.models.case_activity import CaseActivity
from src.models.case_finding import CaseFinding
from src.models.case_note import CaseNote
from src.models.event import Event
from src.models.finding import Finding
from src.models.finding_event import FindingEvent
from src.models.investigation import Investigation
from src.models.telemetry_source import TelemetrySource

from src.services.finding_service import FindingService
from src.services.case_service import CaseService


def test_finding_service_gets_finding(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0300",
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
        service = FindingService(session)

        stored = service.get_finding(
            finding_id
        )

        assert stored.rule_id == "AUTH-BF-001"


def test_finding_service_rejects_missing_finding(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        service = FindingService(session)

        with pytest.raises(
            ValueError,
            match="Finding not found.",
        ):
            service.get_finding(999)


def test_finding_service_lists_filtered_findings(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0301",
        name="Finding Queue Investigation",
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

    medium_reviewed = Finding(
        finding_type="detection",
        rule_id="AUTH-SF-001",
        title="Successful Login After Failures",
        severity="medium",
        status="reviewed",
        summary="Successful authentication followed failures.",
        details={},
    )

    investigation.findings.extend(
        [
            high_new,
            medium_reviewed,
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        service = FindingService(session)

        stored = service.list_findings(
            severity="high",
            status="new",
        )

        assert len(stored) == 1
        assert stored[0].rule_id == "AUTH-BF-001"


def test_finding_service_marks_finding_reviewed(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0302",
        name="Review Investigation",
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
        service = FindingService(session)

        service.mark_reviewed(
            finding_id=finding_id,
        )

        session.commit()

    with SessionLocal() as session:
        stored = session.get(
            Finding,
            finding_id,
        )

        assert stored is not None
        assert stored.status == "reviewed"


def test_finding_service_escalates_finding_to_case(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0303",
        name="Escalation Investigation",
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
        case_service = CaseService(session)

        case = case_service.create_case(
            title="Suspicious Admin Activity",
            priority="high",
        )

        case_id = case.id

        finding_service = FindingService(session)

        finding_service.mark_escalated(
            finding_id=finding_id,
            case_id=case_id,
        )

        session.commit()

    with SessionLocal() as session:
        stored_finding = session.get(
            Finding,
            finding_id,
        )

        stored_case = session.get(
            Case,
            case_id,
        )

        assert stored_finding is not None
        assert stored_case is not None

        assert stored_finding.status == "escalated"

        assert len(stored_case.case_findings) == 1

        assert (
            stored_case.case_findings[0].finding_id
            == finding_id
        )

        assert (
            stored_case.activities[-1].activity_type
            == "finding_added"
        )


def test_finding_service_loads_supporting_evidence(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0304",
        name="Evidence Investigation",
        status="complete",
    )

    telemetry_source = TelemetrySource(
        filename="auth.log",
        source_type="linux_auth",
        file_size=1024,
        sha256="f" * 64,
        original_path="/var/log/auth.log",
    )

    first_event = Event(
        timestamp=datetime(
            2026,
            9,
            22,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        source="linux_auth",
        event_type="authentication_failure",
        username="admin",
        source_ip="10.0.0.8",
    )

    second_event = Event(
        timestamp=datetime(
            2026,
            9,
            22,
            10,
            1,
            tzinfo=timezone.utc,
        ),
        source="linux_auth",
        event_type="authentication_failure",
        username="admin",
        source_ip="10.0.0.8",
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

    finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    finding.finding_events.extend(
        [
            FindingEvent(event=first_event),
            FindingEvent(event=second_event),
        ]
    )

    investigation.findings.append(finding)

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

        finding_id = finding.id

    with SessionLocal() as session:
        service = FindingService(session)

        evidence = service.load_supporting_evidence(
            finding_id=finding_id,
        )

        assert len(evidence) == 2

        assert evidence[0].timestamp < evidence[1].timestamp

        assert evidence[0].username == "admin"
        assert evidence[1].username == "admin"


def test_finding_service_loads_related_findings(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    first_investigation = Investigation(
        public_id="INV-2026-0305",
        name="Related Findings Investigation",
        status="complete",
    )

    second_investigation = Investigation(
        public_id="INV-2026-0306",
        name="Different Investigation",
        status="complete",
    )

    primary_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    related_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-SF-001",
        title="Successful Login After Failures",
        severity="medium",
        status="new",
        summary="Successful login followed failures.",
        details={},
    )

    unrelated_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-PS-001",
        title="Potential Password Spray Activity",
        severity="high",
        status="new",
        summary="Password spray activity detected.",
        details={},
    )

    first_investigation.findings.extend(
        [
            primary_finding,
            related_finding,
        ]
    )

    second_investigation.findings.append(
        unrelated_finding
    )

    with SessionLocal() as session:
        session.add_all(
            [
                first_investigation,
                second_investigation,
            ]
        )
        session.commit()

        primary_finding_id = primary_finding.id

    with SessionLocal() as session:
        service = FindingService(session)

        related = service.load_related_findings(
            finding_id=primary_finding_id,
        )

        assert len(related) == 1
        assert related[0].rule_id == "AUTH-SF-001"
