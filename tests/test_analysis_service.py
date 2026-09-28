import hashlib

import pytest
from sqlalchemy import select

from src.services.analysis_service import AnalysisService

from src.analysis_engine import (
    AnalysisRequest,
    AnalysisResult,
)

from src.database import (
    create_database_engine,
    create_session_factory,
)

from src.models.base import Base
from src.models import Investigation

def test_analysis_service_builds_telemetry_metadata(
    tmp_path,
):
    telemetry_file = tmp_path / "security.evtx"
    telemetry_file.write_bytes(b"authwatch telemetry")

    metadata = AnalysisService._build_telemetry_metadata(
        windows_security=str(telemetry_file),
    )

    expected_hash = hashlib.sha256(
        b"authwatch telemetry"
    ).hexdigest()

    assert len(metadata) == 1

    source = metadata[0]

    assert source["request_field"] == "windows_security"
    assert source["filename"] == "security.evtx"
    assert source["source_type"] == "windows_security"
    assert source["file_size"] == len(
        b"authwatch telemetry"
    )
    assert source["sha256"] == expected_hash
    assert source["original_path"] == str(
        telemetry_file.resolve()
    )


def test_analysis_service_supports_all_telemetry_types(
    tmp_path,
):
    auth_log = tmp_path / "auth.csv"
    windows = tmp_path / "security.evtx"
    sysmon = tmp_path / "sysmon.evtx"
    linux = tmp_path / "auth.log"

    for path in (
        auth_log,
        windows,
        sysmon,
        linux,
    ):
        path.write_text(
            "test",
            encoding="utf-8",
        )

    metadata = AnalysisService._build_telemetry_metadata(
        log_file=str(auth_log),
        windows_security=str(windows),
        sysmon=str(sysmon),
        linux_auth=str(linux),
    )

    source_types = {
        item["source_type"]
        for item in metadata
    }

    assert source_types == {
        "auth_log",
        "windows_security",
        "sysmon",
        "linux_auth",
    }


def test_analysis_service_requires_telemetry_input():
    with pytest.raises(
        ValueError,
        match="At least one telemetry input is required",
    ):
        AnalysisService._build_telemetry_metadata()


def test_analysis_service_builds_analysis_request(
    tmp_path,
):
    windows = tmp_path / "security.evtx"
    sysmon = tmp_path / "sysmon.evtx"

    windows.write_text(
        "windows telemetry",
        encoding="utf-8",
    )

    sysmon.write_text(
        "sysmon telemetry",
        encoding="utf-8",
    )

    request = AnalysisService.build_analysis_request(
        windows_security=str(windows),
        sysmon=str(sysmon),
        linux_year=2026,
        linux_utc_offset="+01:00",
        disabled_accounts="disabled.txt",
        detection_config="detection.json",
        correlation_config="correlation.json",
    )

    assert request.windows_security == str(windows)
    assert request.sysmon == str(sysmon)

    assert request.log_file is None
    assert request.linux_auth is None

    assert request.linux_year == 2026
    assert request.linux_utc_offset == "+01:00"

    assert request.disabled_accounts == "disabled.txt"
    assert request.detection_config == "detection.json"
    assert request.correlation_config == "correlation.json"


def test_analysis_service_rejects_missing_telemetry_file(
    tmp_path,
):
    missing_file = tmp_path / "missing.evtx"

    with pytest.raises(
        ValueError,
        match="Selected telemetry file does not exist",
    ):
        AnalysisService.build_analysis_request(
            sysmon=str(missing_file),
        )


def test_analysis_service_executes_v3_engine(
    monkeypatch,
):
    request = AnalysisRequest(
        sysmon="sysmon.evtx",
    )

    expected_result = AnalysisResult(
        events=[
            {
                "timestamp": "2026-09-22T10:00:00Z",
                "source": "sysmon",
                "event_type": "process_creation",
            }
        ],
        detections=[
            {
                "rule_id": "TEST-001",
            }
        ],
        correlations=[],
        v3_mode=True,
    )

    received = {}

    def fake_run_analysis(received_request):
        received["request"] = received_request
        return expected_result

    monkeypatch.setattr(
        "src.services.analysis_service.run_analysis",
        fake_run_analysis,
    )

    result = AnalysisService.execute_analysis(
        request
    )

    assert received["request"] is request
    assert result is expected_result
    assert result.v3_mode is True
    assert len(result.events) == 1
    assert len(result.detections) == 1


def test_analysis_service_persists_investigation_and_events(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    sysmon_file = tmp_path / "sysmon.evtx"
    auth_file = tmp_path / "auth.csv"

    sysmon_file.write_bytes(
        b"sysmon telemetry"
    )

    auth_file.write_bytes(
        b"auth telemetry"
    )

    metadata = (
        AnalysisService._build_telemetry_metadata(
            log_file=str(auth_file),
            sysmon=str(sysmon_file),
        )
    )

    sysmon_event = {
        "timestamp": "2026-09-23T08:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "host": "WIN-01",
        "username": "admin",
        "process_name": "powershell.exe",
        "details": {
            "integrity_level": "High",
        },
    }

    legacy_event = {
        "timestamp": "2026-09-23T08:01:00",
        "username": "admin",
        "source_ip": "10.0.0.8",
        "result": "failure",
    }

    result = AnalysisResult(
        events=[
            sysmon_event,
            legacy_event,
        ],
        detections=[
            {
                "rule_id": "AUTH-BF-001",
                "severity": "high",
            }
        ],
        correlations=[],
        v3_mode=True,
    )

    with SessionLocal() as session:
        service = AnalysisService(session)

        investigation, event_map = (
            service._persist_investigation_events(
                name="Test Investigation",
                result=result,
                telemetry_metadata=metadata,
            )
        )

        assert investigation.public_id.startswith(
            "INV-2026-"
        )

        assert investigation.status == "complete"
        assert investigation.event_count == 2
        assert investigation.finding_count == 1
        assert investigation.high_severity_count == 1

        assert len(
            investigation.telemetry_sources
        ) == 2

        assert len(investigation.events) == 2

        assert (
            event_map[id(sysmon_event)]
            .event_type
            == "process_creation"
        )

        assert (
            event_map[id(legacy_event)]
            .event_type
            == "authentication_failure"
        )

        assert (
            event_map[id(legacy_event)].source
            == "auth_log"
        )

        session.commit()


def test_analysis_service_persists_findings_and_evidence(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    sysmon_file = tmp_path / "sysmon.evtx"

    sysmon_file.write_bytes(
        b"sysmon telemetry"
    )

    metadata = (
        AnalysisService._build_telemetry_metadata(
            sysmon=str(sysmon_file),
        )
    )

    process_event = {
        "timestamp": "2026-09-23T08:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "host": "WIN-01",
        "username": "admin",
        "process_name": "powershell.exe",
        "process_guid": "{PROCESS-1}",
        "details": {},
    }

    network_event = {
        "timestamp": "2026-09-23T08:00:20Z",
        "source": "sysmon",
        "event_type": "network_connection",
        "host": "WIN-01",
        "username": "admin",
        "process_name": "powershell.exe",
        "process_guid": "{PROCESS-1}",
        "destination_ip": "10.0.0.50",
        "details": {
            "destination_port": "443",
        },
    }

    result = AnalysisResult(
        events=[
            process_event,
            network_event,
        ],
        detections=[
            {
                "rule_id": "AUTH-BF-001",
                "title": (
                    "Potential Brute-Force Activity"
                ),
                "severity": "high",
                "first_seen": (
                    "2026-09-23T07:55:00Z"
                ),
                "last_seen": (
                    "2026-09-23T08:00:00Z"
                ),
                "details": {
                    "username": "admin",
                },
                "mitre": None,
            }
        ],
        correlations=[
            {
                "correlation_id": (
                    "CORR-PROC-NET-001"
                ),
                "title": (
                    "Process to Network Activity"
                ),
                "severity": "medium",
                "first_seen": (
                    process_event["timestamp"]
                ),
                "last_seen": (
                    network_event["timestamp"]
                ),
                "details": {
                    "host": "WIN-01",
                    "process_name": (
                        "powershell.exe"
                    ),
                },
                "related_events": [
                    process_event,
                    network_event,
                ],
                "mitre": None,
            }
        ],
        v3_mode=True,
    )

    with SessionLocal() as session:
        service = AnalysisService(session)

        investigation, event_map = (
            service._persist_investigation_events(
                name="Finding Persistence Test",
                result=result,
                telemetry_metadata=metadata,
            )
        )

        findings = service._persist_findings(
            investigation=investigation,
            result=result,
            event_map=event_map,
        )

        assert len(findings) == 2
        assert len(investigation.findings) == 2

        detection = findings[0]

        assert detection.finding_type == "detection"
        assert detection.rule_id == "AUTH-BF-001"

        assert (
            detection.summary
            == "Potential Brute-Force Activity"
        )

        correlation = findings[1]

        assert (
            correlation.finding_type
            == "correlation"
        )

        assert (
            correlation.rule_id
            == "CORR-PROC-NET-001"
        )

        assert len(
            correlation.finding_events
        ) == 2

        assert (
            correlation.finding_events[0].event
            is event_map[id(process_event)]
        )

        assert (
            correlation.finding_events[1].event
            is event_map[id(network_event)]
        )

        session.commit()


def test_analysis_service_analyzes_and_stores_investigation(
    tmp_path,
    monkeypatch,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    sysmon_file = tmp_path / "sysmon.evtx"

    sysmon_file.write_bytes(
        b"real telemetry bytes"
    )

    process_event = {
        "timestamp": "2026-09-23T08:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "host": "WIN-01",
        "username": "admin",
        "process_name": "powershell.exe",
        "process_guid": "{PROCESS-1}",
        "details": {},
    }

    network_event = {
        "timestamp": "2026-09-23T08:00:20Z",
        "source": "sysmon",
        "event_type": "network_connection",
        "host": "WIN-01",
        "username": "admin",
        "process_name": "powershell.exe",
        "process_guid": "{PROCESS-1}",
        "destination_ip": "10.0.0.50",
        "details": {
            "destination_port": "443",
        },
    }

    result = AnalysisResult(
        events=[
            process_event,
            network_event,
        ],
        detections=[
            {
                "rule_id": "AUTH-BF-001",
                "title": (
                    "Potential Brute-Force Activity"
                ),
                "severity": "high",
                "first_seen": (
                    "2026-09-23T07:55:00Z"
                ),
                "last_seen": (
                    "2026-09-23T08:00:00Z"
                ),
                "details": {
                    "username": "admin",
                },
                "mitre": None,
            }
        ],
        correlations=[
            {
                "correlation_id": (
                    "CORR-PROC-NET-001"
                ),
                "title": (
                    "Process to Network Activity"
                ),
                "severity": "medium",
                "first_seen": (
                    process_event["timestamp"]
                ),
                "last_seen": (
                    network_event["timestamp"]
                ),
                "details": {
                    "host": "WIN-01",
                },
                "related_events": [
                    process_event,
                    network_event,
                ],
                "mitre": None,
            }
        ],
        v3_mode=True,
    )

    def fake_execute_analysis(request):
        assert request.sysmon == str(
            sysmon_file
        )

        return result

    monkeypatch.setattr(
        AnalysisService,
        "execute_analysis",
        staticmethod(fake_execute_analysis),
    )

    with SessionLocal() as session:
        service = AnalysisService(session)

        investigation = (
            service.analyze_and_store(
                name="Complete Analysis Test",
                sysmon=str(sysmon_file),
            )
        )

        assert investigation.status == "complete"

        assert investigation.event_count == 2
        assert investigation.finding_count == 2
        assert investigation.high_severity_count == 1

        assert len(
            investigation.telemetry_sources
        ) == 1

        assert len(investigation.events) == 2
        assert len(investigation.findings) == 2

        correlation = next(
            finding
            for finding in investigation.findings
            if finding.finding_type
            == "correlation"
        )

        assert len(
            correlation.finding_events
        ) == 2

        session.commit()


def test_analysis_service_rolls_back_partial_analysis(
    tmp_path,
    monkeypatch,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    sysmon_file = tmp_path / "sysmon.evtx"
    sysmon_file.write_bytes(b"telemetry")

    persisted_event = {
        "timestamp": "2026-09-23T08:00:00Z",
        "source": "sysmon",
        "event_type": "process_creation",
        "host": "WIN-01",
        "details": {},
    }

    orphan_event = {
        "timestamp": "2026-09-23T08:00:20Z",
        "source": "sysmon",
        "event_type": "network_connection",
        "host": "WIN-01",
        "details": {},
    }

    result = AnalysisResult(
        events=[
            persisted_event,
        ],
        detections=[],
        correlations=[
            {
                "correlation_id": "CORR-TEST-001",
                "title": "Broken Correlation",
                "severity": "medium",
                "first_seen": (
                    persisted_event["timestamp"]
                ),
                "last_seen": (
                    orphan_event["timestamp"]
                ),
                "details": {},
                "related_events": [
                    persisted_event,
                    orphan_event,
                ],
                "mitre": None,
            }
        ],
        v3_mode=True,
    )

    monkeypatch.setattr(
        AnalysisService,
        "execute_analysis",
        staticmethod(lambda request: result),
    )

    with SessionLocal() as session:
        service = AnalysisService(session)

        with pytest.raises(
            ValueError,
            match=(
                "Correlation references an event "
                "that was not persisted"
            ),
        ):
            service.analyze_and_store(
                name="Rollback Test",
                sysmon=str(sysmon_file),
            )

        investigations = session.scalars(
            select(Investigation)
        ).all()

        assert investigations == []


def test_analysis_service_links_detection_supporting_events(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    auth_file = tmp_path / "auth.csv"

    auth_file.write_bytes(
        b"auth telemetry"
    )

    metadata = (
        AnalysisService._build_telemetry_metadata(
            log_file=str(auth_file),
        )
    )

    event_times = [
        "2026-08-08T09:00:00",
        "2026-08-08T09:00:12",
        "2026-08-08T09:00:24",
        "2026-08-08T09:00:36",
        "2026-08-08T09:00:48",
    ]

    events = [
        {
            "timestamp": timestamp,
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        }
        for timestamp in event_times
    ]

    result = AnalysisResult(
        events=events,
        detections=[
            {
                "rule_id": "AUTH-BF-001",
                "title": (
                    "Potential Brute-Force Activity"
                ),
                "severity": "high",
                "first_seen": (
                    "2026-08-08T09:00:00"
                ),
                "last_seen": (
                    "2026-08-08T09:00:48"
                ),
                "details": {
                    "source_ip": "10.0.0.50",
                    "username": "admin",
                    "failed_attempts": 5,
                },
                "mitre": None,
            }
        ],
        correlations=[],
        v3_mode=True,
    )

    with SessionLocal() as session:
        service = AnalysisService(session)

        investigation, event_map = (
            service._persist_investigation_events(
                name="Detection Evidence Test",
                result=result,
                telemetry_metadata=metadata,
            )
        )

        findings = service._persist_findings(
            investigation=investigation,
            result=result,
            event_map=event_map,
        )

        session.flush()

        assert len(findings) == 1

        finding = findings[0]

        assert finding.rule_id == "AUTH-BF-001"

        assert len(
            finding.finding_events
        ) == 5

        linked_events = [
            link.event
            for link in finding.finding_events
        ]

        assert [
            event.username
            for event in linked_events
        ] == [
            "admin",
            "admin",
            "admin",
            "admin",
            "admin",
        ]

        assert [
            event.source_ip
            for event in linked_events
        ] == [
            "10.0.0.50",
            "10.0.0.50",
            "10.0.0.50",
            "10.0.0.50",
            "10.0.0.50",
        ]
