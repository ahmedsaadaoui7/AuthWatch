import src.analysis_engine as analysis_engine

from src.analysis_engine import (
    AnalysisRequest,
    AnalysisResult,
    run_analysis,
)


def test_analysis_request_defaults():
    request = AnalysisRequest()

    assert request.log_file is None
    assert request.windows_security is None
    assert request.sysmon is None
    assert request.linux_auth is None
    assert request.linux_year is None
    assert request.linux_utc_offset is None
    assert request.disabled_accounts is None
    assert request.detection_config is None
    assert request.correlation_config is None


def test_analysis_result_defaults():
    result = AnalysisResult()

    assert result.events == []
    assert result.detections == []
    assert result.correlations == []
    assert result.v3_mode is False


def test_run_analysis_detects_v2_brute_force():
    request = AnalysisRequest(
        log_file="data/brute_force_auth_log.csv"
    )

    result = run_analysis(request)

    assert result.v3_mode is False
    assert any(
        detection["rule_id"] == "AUTH-BF-001"
        for detection in result.detections
    )
    assert result.correlations == []


def test_run_analysis_processes_windows_security(monkeypatch):
    raw_event = {"raw": "windows-event"}

    normalized_event = {
        "timestamp": "2026-09-18T10:00:00Z",
        "source": "windows_security",
        "event_id": "4624",
        "event_type": "authentication_success",
        "host": "WIN-CLIENT01",
        "username": "alice",
        "session_id": "0x1234",
        "source_ip": "10.0.0.50",
        "destination_ip": None,
        "process_name": None,
        "process_id": None,
        "process_guid": None,
        "parent_process_name": None,
        "command_line": None,
        "result": "success",
        "details": {},
    }

    monkeypatch.setattr(
        analysis_engine,
        "load_windows_security_events",
        lambda path: [raw_event],
    )

    monkeypatch.setattr(
        analysis_engine,
        "normalize_windows_security_event",
        lambda event: normalized_event,
    )

    monkeypatch.setattr(
        analysis_engine,
        "run_detection_engine",
        lambda events, disabled_accounts=None, config=None: [],
    )

    request = AnalysisRequest(
        windows_security="Security.evtx"
    )

    result = run_analysis(request)

    assert result.v3_mode is True
    assert result.events == [normalized_event]
    assert result.detections == []


def test_run_analysis_processes_sysmon(monkeypatch):
    raw_event = {"raw": "sysmon-event"}

    normalized_event = {
        "timestamp": "2026-09-18T10:01:00Z",
        "source": "sysmon",
        "event_id": "1",
        "event_type": "process_creation",
        "host": "WIN-CLIENT01",
        "username": "alice",
        "session_id": "0x1234",
        "source_ip": None,
        "destination_ip": None,
        "process_name": "powershell.exe",
        "process_id": "4820",
        "process_guid": "{ABC-123}",
        "parent_process_name": "explorer.exe",
        "command_line": "powershell.exe",
        "result": None,
        "details": {},
    }

    monkeypatch.setattr(
        analysis_engine,
        "load_sysmon_events",
        lambda path: [raw_event],
    )

    monkeypatch.setattr(
        analysis_engine,
        "normalize_sysmon_event",
        lambda event: normalized_event,
    )

    monkeypatch.setattr(
        analysis_engine,
        "run_detection_engine",
        lambda events, disabled_accounts=None, config=None: [],
    )

    request = AnalysisRequest(
        sysmon="Sysmon.evtx"
    )

    result = run_analysis(request)

    assert result.v3_mode is True
    assert result.events == [normalized_event]
    assert result.detections == []


def test_run_analysis_processes_linux_auth(monkeypatch):
    raw_event = {"raw": "linux-auth-event"}

    normalized_event = {
        "timestamp": "2026-09-18T19:00:00Z",
        "source": "linux_auth",
        "event_id": None,
        "event_type": "authentication_success",
        "host": "kali",
        "username": "alice",
        "session_id": None,
        "source_ip": "10.0.0.120",
        "destination_ip": None,
        "process_name": None,
        "process_id": None,
        "process_guid": None,
        "parent_process_name": None,
        "command_line": None,
        "result": "success",
        "details": {},
    }

    monkeypatch.setattr(
        analysis_engine,
        "load_linux_auth_events",
        lambda path: [raw_event],
    )

    monkeypatch.setattr(
        analysis_engine,
        "normalize_linux_auth_event",
        lambda event, year, utc_offset: normalized_event,
    )

    monkeypatch.setattr(
        analysis_engine,
        "run_detection_engine",
        lambda events, disabled_accounts=None, config=None: [],
    )

    request = AnalysisRequest(
        linux_auth="auth.log",
        linux_year=2026,
        linux_utc_offset="+01:00",
    )

    result = run_analysis(request)

    assert result.v3_mode is True
    assert result.events == [normalized_event]
    assert result.detections == []


def test_run_analysis_applies_correlation_timeline_and_mitre(
    monkeypatch,
):
    raw_event = {"raw": "windows-event"}

    normalized_event = {
        "timestamp": "2026-09-18T10:00:00Z",
        "source": "windows_security",
        "event_id": "4624",
        "event_type": "authentication_success",
        "host": "WIN-CLIENT01",
        "username": "alice",
        "session_id": "0x1234",
        "source_ip": "10.0.0.50",
        "destination_ip": None,
        "process_name": None,
        "process_id": None,
        "process_guid": None,
        "parent_process_name": None,
        "command_line": None,
        "result": "success",
        "details": {},
    }

    detection = {
        "rule_id": "AUTH-BF-001",
        "title": "Potential Brute-Force Activity",
        "severity": "high",
        "first_seen": "2026-09-18T10:00:00Z",
        "last_seen": "2026-09-18T10:00:00Z",
        "details": {},
    }

    correlation = {
        "correlation_id": "CORR-AUTH-EXEC-001",
        "title": "Authentication to Process Activity",
        "severity": "medium",
        "first_seen": "2026-09-18T10:00:00Z",
        "last_seen": "2026-09-18T10:00:20Z",
        "details": {},
    }

    monkeypatch.setattr(
        analysis_engine,
        "load_windows_security_events",
        lambda path: [raw_event],
    )

    monkeypatch.setattr(
        analysis_engine,
        "normalize_windows_security_event",
        lambda event: normalized_event,
    )

    monkeypatch.setattr(
        analysis_engine,
        "run_detection_engine",
        lambda events, disabled_accounts=None, config=None: [
            detection
        ],
    )

    monkeypatch.setattr(
        analysis_engine,
        "run_correlation_engine",
        lambda events, config=None: [correlation],
    )

    monkeypatch.setattr(
        analysis_engine,
        "attach_timelines_to_correlations",
        lambda correlations: [
            {
                **correlations[0],
                "timeline": ["event-1", "event-2"],
            }
        ],
    )

    def fake_attach_mitre_mappings(items):
        return [
            {
                **item,
                "mitre_processed": True,
            }
            for item in items
        ]

    monkeypatch.setattr(
        analysis_engine,
        "attach_mitre_mappings",
        fake_attach_mitre_mappings,
    )

    request = AnalysisRequest(
        windows_security="Security.evtx"
    )

    result = run_analysis(request)

    assert result.v3_mode is True

    assert result.detections[0]["mitre_processed"] is True

    assert result.correlations[0]["timeline"] == [
        "event-1",
        "event-2",
    ]

    assert result.correlations[0]["mitre_processed"] is True
