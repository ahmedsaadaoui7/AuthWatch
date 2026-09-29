import json
import pytest

from src.database import (
    create_database_engine,
    create_session_factory,
)
from src.models.base import Base

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

from src.services.investigation_service import (
    InvestigationService,
)

from datetime import datetime, timezone


def test_investigation_service_gets_investigation(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0400",
        name="Authentication Investigation",
        status="complete",
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

        investigation_id = investigation.id

    with SessionLocal() as session:
        service = InvestigationService(session)

        stored = service.get_investigation(
            investigation_id
        )

        assert (
            stored.public_id
            == "INV-2026-0400"
        )


def test_investigation_service_rejects_missing_investigation(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        service = InvestigationService(session)

        with pytest.raises(
            ValueError,
            match="Investigation not found.",
        ):
            service.get_investigation(999)



def test_investigation_service_lists_filtered_investigations(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    complete_auth = Investigation(
        public_id="INV-2026-0401",
        name="Authentication Investigation",
        status="complete",
    )

    running_auth = Investigation(
        public_id="INV-2026-0402",
        name="Authentication Review",
        status="running",
    )

    complete_endpoint = Investigation(
        public_id="INV-2026-0403",
        name="Endpoint Investigation",
        status="complete",
    )

    with SessionLocal() as session:
        session.add_all(
            [
                complete_auth,
                running_auth,
                complete_endpoint,
            ]
        )
        session.commit()

    with SessionLocal() as session:
        service = InvestigationService(session)

        stored = service.list_investigations(
            search="authentication",
            status="complete",
        )

        assert len(stored) == 1
        assert (
            stored[0].public_id
            == "INV-2026-0401"
        )


def test_investigation_service_loads_timeline_in_order(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0404",
        name="Timeline Investigation",
        status="complete",
    )

    telemetry_source = TelemetrySource(
        filename="events.json",
        source_type="sysmon",
        file_size=2048,
        sha256="a" * 64,
        original_path="/data/events.json",
    )

    later_event = Event(
        timestamp=datetime(
            2026, 9, 22, 10, 2,
            tzinfo=timezone.utc,
        ),
        source="sysmon",
        event_type="process_creation",
        host="WIN-01",
        process_name="powershell.exe",
    )

    earlier_event = Event(
        timestamp=datetime(
            2026, 9, 22, 10, 0,
            tzinfo=timezone.utc,
        ),
        source="windows_security",
        event_type="authentication_success",
        host="WIN-01",
        username="admin",
    )

    telemetry_source.events.extend(
        [
            later_event,
            earlier_event,
        ]
    )

    investigation.telemetry_sources.append(
        telemetry_source
    )

    investigation.events.extend(
        [
            later_event,
            earlier_event,
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

        investigation_id = investigation.id

    with SessionLocal() as session:
        service = InvestigationService(session)

        timeline = service.load_timeline(
            investigation_id=investigation_id,
        )

        assert len(timeline) == 2

        assert (
            timeline[0].event_type
            == "authentication_success"
        )

        assert (
            timeline[1].event_type
            == "process_creation"
        )


def test_investigation_service_loads_affected_entities(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0405",
        name="Affected Entities Investigation",
        status="complete",
    )

    telemetry_source = TelemetrySource(
        filename="events.json",
        source_type="sysmon",
        file_size=2048,
        sha256="b" * 64,
        original_path="/data/events.json",
    )

    first_event = Event(
        timestamp=datetime(
            2026, 9, 22, 10, 0,
            tzinfo=timezone.utc,
        ),
        source="windows_security",
        event_type="authentication_failure",
        host="WIN-01",
        username="admin",
        source_ip="10.0.0.8",
    )

    second_event = Event(
        timestamp=datetime(
            2026, 9, 22, 10, 1,
            tzinfo=timezone.utc,
        ),
        source="windows_security",
        event_type="authentication_failure",
        host="WIN-01",
        username="admin",
        source_ip="10.0.0.8",
    )

    third_event = Event(
        timestamp=datetime(
            2026, 9, 22, 10, 2,
            tzinfo=timezone.utc,
        ),
        source="windows_security",
        event_type="authentication_success",
        host="WIN-02",
        username="john",
        source_ip="10.0.0.9",
    )

    telemetry_source.events.extend(
        [
            first_event,
            second_event,
            third_event,
        ]
    )

    investigation.telemetry_sources.append(
        telemetry_source
    )

    investigation.events.extend(
        [
            first_event,
            second_event,
            third_event,
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

        investigation_id = investigation.id

    with SessionLocal() as session:
        service = InvestigationService(session)

        entities = service.load_affected_entities(
            investigation_id=investigation_id,
        )

        assert entities == {
            "users": [
                "admin",
                "john",
            ],
            "hosts": [
                "WIN-01",
                "WIN-02",
            ],
            "source_ips": [
                "10.0.0.8",
                "10.0.0.9",
            ],
        }


def test_investigation_service_loads_findings(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0406",
        name="Findings Investigation",
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
        severity="high",
        status="new",
        summary="Authentication followed by process activity.",
        details={},
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

        investigation_id = investigation.id

    with SessionLocal() as session:
        service = InvestigationService(session)

        findings = service.load_findings(
            investigation_id=investigation_id,
        )

        assert len(findings) == 2

        assert [
            finding.rule_id
            for finding in findings
        ] == [
            "AUTH-BF-001",
            "CORR-AUTH-EXEC-001",
        ]


def test_investigation_service_loads_related_cases(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0407",
        name="Related Cases Investigation",
        status="complete",
    )

    first_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="escalated",
        summary="Repeated authentication failures detected.",
        details={},
    )

    second_finding = Finding(
        finding_type="detection",
        rule_id="AUTH-SF-001",
        title="Successful Login After Failures",
        severity="medium",
        status="escalated",
        summary="Successful login followed failures.",
        details={},
    )

    investigation.findings.extend(
        [
            first_finding,
            second_finding,
        ]
    )

    case = Case(
        public_id="AW-0100",
        title="Suspicious Authentication Activity",
        priority="high",
        status="open",
    )

    case.case_findings.extend(
        [
            CaseFinding(finding=first_finding),
            CaseFinding(finding=second_finding),
        ]
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.add(case)
        session.commit()

        investigation_id = investigation.id

    with SessionLocal() as session:
        service = InvestigationService(session)

        cases = service.load_related_cases(
            investigation_id=investigation_id,
        )

        assert len(cases) == 1
        assert cases[0].public_id == "AW-0100"


def test_investigation_service_exports_json_report(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0408",
        name="Export Investigation",
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
            "source_ip": "10.0.0.8",
        },
        first_seen=datetime(
            2026, 9, 22, 10, 0,
            tzinfo=timezone.utc,
        ),
        last_seen=datetime(
            2026, 9, 22, 10, 5,
            tzinfo=timezone.utc,
        ),
    )

    investigation.findings.append(detection)

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

        investigation_id = investigation.id

    output_path = tmp_path / "investigation.json"

    with SessionLocal() as session:
        service = InvestigationService(session)

        result_path = service.export_investigation(
            investigation_id=investigation_id,
            export_format="json",
            output_path=output_path,
        )

    report = json.loads(
        result_path.read_text(encoding="utf-8")
    )

    assert report["detection_summary"]["total"] == 1
    assert report["detection_summary"]["high"] == 1

    assert (
        report["detections"][0]["rule_id"]
        == "AUTH-BF-001"
    )

    assert report["affected_entities"]["users"] == [
        "admin"
    ]

    assert report["affected_entities"]["ip_addresses"] == [
        "10.0.0.8"
    ]


def test_investigation_service_exports_correlation_with_timeline(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0409",
        name="Correlation Export Investigation",
        status="complete",
    )

    telemetry_source = TelemetrySource(
        filename="events.json",
        source_type="sysmon",
        file_size=2048,
        sha256="c" * 64,
        original_path="/data/events.json",
    )

    auth_event = Event(
        timestamp=datetime(
            2026, 9, 22, 10, 0,
            tzinfo=timezone.utc,
        ),
        source="windows_security",
        event_type="authentication_success",
        host="WIN-01",
        username="admin",
        source_ip="10.0.0.8",
    )

    process_event = Event(
        timestamp=datetime(
            2026, 9, 22, 10, 2,
            tzinfo=timezone.utc,
        ),
        source="sysmon",
        event_type="process_creation",
        host="WIN-01",
        username="admin",
        process_name="powershell.exe",
    )

    telemetry_source.events.extend(
        [
            auth_event,
            process_event,
        ]
    )

    investigation.telemetry_sources.append(
        telemetry_source
    )

    investigation.events.extend(
        [
            auth_event,
            process_event,
        ]
    )

    correlation = Finding(
        finding_type="correlation",
        rule_id="CORR-AUTH-EXEC-001",
        title="Authentication to Process Activity",
        severity="high",
        status="new",
        first_seen=auth_event.timestamp,
        last_seen=process_event.timestamp,
        summary=(
            "Authentication was followed by "
            "process execution."
        ),
        details={
            "username": "admin",
            "host": "WIN-01",
        },
    )

    correlation.finding_events.extend(
        [
            FindingEvent(event=auth_event),
            FindingEvent(event=process_event),
        ]
    )

    investigation.findings.append(correlation)

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

        investigation_id = investigation.id

    output_path = tmp_path / "correlation_report.json"

    with SessionLocal() as session:
        service = InvestigationService(session)

        result_path = service.export_investigation(
            investigation_id=investigation_id,
            export_format="json",
            output_path=output_path,
        )

    report = json.loads(
        result_path.read_text(encoding="utf-8")
    )

    assert report["correlation_summary"]["total"] == 1
    assert report["correlation_summary"]["high"] == 1

    assert (
        report["correlations"][0]["correlation_id"]
        == "CORR-AUTH-EXEC-001"
    )

    assert len(
        report["correlations"][0]["related_events"]
    ) == 2

    assert len(report["timeline"]) == 2

    assert (
        report["timeline"][0]["event_type"]
        == "authentication_success"
    )

    assert (
        report["timeline"][1]["event_type"]
        == "process_creation"
    )


def test_investigation_service_exports_markdown_report(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0410",
        name="Markdown Export Investigation",
        status="complete",
    )

    finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        first_seen=datetime(
            2026, 9, 22, 11, 0,
            tzinfo=timezone.utc,
        ),
        last_seen=datetime(
            2026, 9, 22, 11, 5,
            tzinfo=timezone.utc,
        ),
        summary="Repeated authentication failures detected.",
        details={
            "username": "admin",
            "source_ip": "10.0.0.8",
        },
    )

    investigation.findings.append(finding)

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

        investigation_id = investigation.id

    output_path = tmp_path / "investigation.md"

    with SessionLocal() as session:
        service = InvestigationService(session)

        result_path = service.export_investigation(
            investigation_id=investigation_id,
            export_format="markdown",
            output_path=output_path,
        )

    content = result_path.read_text(
        encoding="utf-8"
    )

    assert result_path == output_path
    assert "AUTH-BF-001" in content
    assert "Potential Brute-Force Activity" in content
    assert "admin" in content
    assert "10.0.0.8" in content
