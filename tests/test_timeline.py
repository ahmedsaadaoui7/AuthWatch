import pytest
from src.timeline import (
    attach_timeline_to_correlation,
    attach_timelines_to_correlations,
    build_correlation_timeline,
    build_timeline,
    build_timeline_description,
    build_timeline_entry,
    sort_events_chronologically,
)


def test_sort_events_chronologically():
    events = [
        {
            "timestamp": "2026-08-30T14:00:40Z",
            "event_type": "network_connection",
        },
        {
            "timestamp": "2026-08-30T14:00:00Z",
            "event_type": "process_creation",
        },
        {
            "timestamp": "2026-08-30T14:00:30Z",
            "event_type": "dns_query",
        },
    ]

    sorted_events = sort_events_chronologically(events)

    assert sorted_events[0]["event_type"] == "process_creation"
    assert sorted_events[1]["event_type"] == "dns_query"
    assert sorted_events[2]["event_type"] == "network_connection"


def test_build_explicit_credentials_description():
    event = {
        "event_type": "explicit_credentials",
        "username": "hawk",
        "host": "WIN-PC01",
    }

    description = build_timeline_description(event)

    assert description == (
        "hawk used explicit credentials on WIN-PC01"
    )


def test_build_timeline_entry_preserves_investigation_fields():
    event = {
        "timestamp": "2026-08-30T14:00:00Z",
        "source": "sysmon",
        "event_id": "1",
        "event_type": "process_creation",
        "host": "WIN-PC01",
        "username": "hawk",
        "source_ip": None,
        "destination_ip": None,
        "process_name": "powershell.exe",
        "process_id": "5000",
        "process_guid": "{PROC-001}",
        "command_line": "powershell.exe -NoProfile",
        "details": {},
    }

    entry = build_timeline_entry(event)

    assert entry["timestamp"] == "2026-08-30T14:00:00Z"
    assert entry["source"] == "sysmon"
    assert entry["event_id"] == "1"
    assert entry["event_type"] == "process_creation"
    assert entry["host"] == "WIN-PC01"
    assert entry["username"] == "hawk"
    assert entry["process_name"] == "powershell.exe"
    assert entry["process_id"] == "5000"
    assert entry["process_guid"] == "{PROC-001}"
    assert entry["command_line"] == "powershell.exe -NoProfile"
    assert entry["description"] == (
        "powershell.exe was started by hawk on WIN-PC01"
    )
    assert entry["source_event"] is event


def test_build_process_creation_description():
    event = {
        "event_type": "process_creation",
        "host": "WIN-PC01",
        "username": "hawk",
        "process_name": "powershell.exe",
    }

    description = build_timeline_description(event)

    assert description == (
        "powershell.exe was started by hawk on WIN-PC01"
    )


def test_build_network_connection_description():
    event = {
        "event_type": "network_connection",
        "process_name": "powershell.exe",
        "destination_ip": "10.0.0.50",
        "details": {
            "destination_port": "443",
        },
    }

    description = build_timeline_description(event)

    assert description == (
        "powershell.exe connected to 10.0.0.50:443"
    )


def test_build_dns_query_description():
    event = {
        "event_type": "dns_query",
        "process_name": "powershell.exe",
        "details": {
            "query_name": "example.com",
        },
    }

    description = build_timeline_description(event)

    assert description == (
        "powershell.exe queried DNS for example.com"
    )


def test_build_authentication_success_description():
    event = {
        "event_type": "authentication_success",
        "username": "hawk",
        "host": "WIN-PC01",
        "source_ip": "192.168.1.50",
    }

    description = build_timeline_description(event)

    assert description == (
        "hawk successfully authenticated to "
        "WIN-PC01 from 192.168.1.50"
    )


def test_build_authentication_failure_description():
    event = {
        "event_type": "authentication_failure",
        "username": "admin",
        "host": "WIN-PC01",
        "source_ip": "10.0.0.8",
    }

    description = build_timeline_description(event)

    assert description == (
        "Failed authentication for admin to "
        "WIN-PC01 from 10.0.0.8"
    )


def test_build_privileged_logon_description():
    event = {
        "event_type": "privileged_logon",
        "username": "Administrator",
        "host": "WIN-PC01",
    }

    description = build_timeline_description(event)

    assert description == (
        "Administrator received special logon privileges "
        "on WIN-PC01"
    )


def test_build_sudo_execution_description():
    event = {
        "event_type": "sudo_execution",
        "username": "hawk",
        "command_line": "/usr/bin/systemctl restart ssh",
        "details": {
            "target_user": "root",
        },
    }

    description = build_timeline_description(event)

    assert description == (
        "hawk executed sudo as root: "
        "/usr/bin/systemctl restart ssh"
    )


def test_build_session_opened_description():
    event = {
        "event_type": "session_activity",
        "host": "server01",
        "username": "hawk",
        "details": {
            "session_action": "opened",
        },
    }

    description = build_timeline_description(event)

    assert description == (
        "Session for hawk was opened on server01"
    )


def test_build_session_closed_description():
    event = {
        "event_type": "session_activity",
        "host": "server01",
        "username": "hawk",
        "details": {
            "session_action": "closed",
        },
    }

    description = build_timeline_description(event)

    assert description == (
        "Session for hawk was closed on server01"
    )


def test_build_timeline_creates_chronological_investigation_story():
    events = [
        {
            "timestamp": "2026-08-30T14:00:40Z",
            "source": "sysmon",
            "event_id": "3",
            "event_type": "network_connection",
            "host": "WIN-PC01",
            "username": "hawk",
            "process_name": "powershell.exe",
            "destination_ip": "10.0.0.50",
            "details": {
                "destination_port": "443",
            },
        },
        {
            "timestamp": "2026-08-30T14:00:00Z",
            "source": "sysmon",
            "event_id": "1",
            "event_type": "process_creation",
            "host": "WIN-PC01",
            "username": "hawk",
            "process_name": "powershell.exe",
            "process_id": "5000",
            "process_guid": "{PROC-001}",
            "command_line": "powershell.exe -NoProfile",
            "details": {},
        },
        {
            "timestamp": "2026-08-30T14:00:30Z",
            "source": "sysmon",
            "event_id": "22",
            "event_type": "dns_query",
            "host": "WIN-PC01",
            "username": "hawk",
            "process_name": "powershell.exe",
            "details": {
                "query_name": "example.com",
            },
        },
    ]

    timeline = build_timeline(events)

    assert len(timeline) == 3

    assert timeline[0]["event_type"] == "process_creation"
    assert timeline[1]["event_type"] == "dns_query"
    assert timeline[2]["event_type"] == "network_connection"

    assert timeline[0]["description"] == (
        "powershell.exe was started by hawk on WIN-PC01"
    )
    assert timeline[1]["description"] == (
        "powershell.exe queried DNS for example.com"
    )
    assert timeline[2]["description"] == (
        "powershell.exe connected to 10.0.0.50:443"
    )


def test_build_correlation_timeline():
    process_event = {
        "timestamp": "2026-08-30T14:00:00Z",
        "source": "sysmon",
        "event_id": "1",
        "event_type": "process_creation",
        "host": "WIN-PC01",
        "username": "hawk",
        "process_name": "powershell.exe",
        "process_guid": "{PROC-001}",
        "details": {},
    }

    network_event = {
        "timestamp": "2026-08-30T14:00:40Z",
        "source": "sysmon",
        "event_id": "3",
        "event_type": "network_connection",
        "host": "WIN-PC01",
        "username": "hawk",
        "process_name": "powershell.exe",
        "process_guid": "{PROC-001}",
        "destination_ip": "10.0.0.50",
        "details": {
            "destination_port": "443",
        },
    }

    correlation = {
        "correlation_id": "CORR-PROC-NET-001",
        "related_events": [
            network_event,
            process_event,
        ],
    }

    timeline = build_correlation_timeline(correlation)

    assert len(timeline) == 2
    assert timeline[0]["event_type"] == "process_creation"
    assert timeline[1]["event_type"] == "network_connection"

    assert timeline[0]["source_event"] is process_event
    assert timeline[1]["source_event"] is network_event


def test_attach_timeline_to_correlation():
    process_event = {
        "timestamp": "2026-08-30T14:00:00Z",
        "source": "sysmon",
        "event_id": "1",
        "event_type": "process_creation",
        "host": "WIN-PC01",
        "username": "hawk",
        "process_name": "powershell.exe",
        "process_guid": "{PROC-001}",
        "details": {},
    }

    network_event = {
        "timestamp": "2026-08-30T14:00:40Z",
        "source": "sysmon",
        "event_id": "3",
        "event_type": "network_connection",
        "host": "WIN-PC01",
        "username": "hawk",
        "process_name": "powershell.exe",
        "process_guid": "{PROC-001}",
        "destination_ip": "10.0.0.50",
        "details": {
            "destination_port": "443",
        },
    }

    correlation = {
        "correlation_id": "CORR-PROC-NET-001",
        "title": "Process to Network Activity",
        "related_events": [
            network_event,
            process_event,
        ],
    }

    result = attach_timeline_to_correlation(correlation)

    assert result["correlation_id"] == "CORR-PROC-NET-001"
    assert len(result["timeline"]) == 2

    assert result["timeline"][0]["event_type"] == "process_creation"
    assert result["timeline"][1]["event_type"] == "network_connection"

    assert "timeline" not in correlation


def test_attach_timelines_to_correlations():
    process_event = {
        "timestamp": "2026-08-30T14:00:00Z",
        "source": "sysmon",
        "event_id": "1",
        "event_type": "process_creation",
        "host": "WIN-PC01",
        "username": "hawk",
        "process_name": "powershell.exe",
        "details": {},
    }

    network_event = {
        "timestamp": "2026-08-30T14:00:40Z",
        "source": "sysmon",
        "event_id": "3",
        "event_type": "network_connection",
        "host": "WIN-PC01",
        "username": "hawk",
        "process_name": "powershell.exe",
        "destination_ip": "10.0.0.50",
        "details": {
            "destination_port": "443",
        },
    }

    dns_event = {
        "timestamp": "2026-08-30T14:00:30Z",
        "source": "sysmon",
        "event_id": "22",
        "event_type": "dns_query",
        "host": "WIN-PC01",
        "username": "hawk",
        "process_name": "powershell.exe",
        "details": {
            "query_name": "example.com",
        },
    }

    correlations = [
        {
            "correlation_id": "CORR-PROC-NET-001",
            "related_events": [
                network_event,
                process_event,
            ],
        },
        {
            "correlation_id": "CORR-PROC-DNS-001",
            "related_events": [
                dns_event,
                process_event,
            ],
        },
    ]

    results = attach_timelines_to_correlations(correlations)

    assert len(results) == 2

    assert results[0]["correlation_id"] == "CORR-PROC-NET-001"
    assert len(results[0]["timeline"]) == 2
    assert results[0]["timeline"][0]["event_type"] == "process_creation"
    assert results[0]["timeline"][1]["event_type"] == "network_connection"

    assert results[1]["correlation_id"] == "CORR-PROC-DNS-001"
    assert len(results[1]["timeline"]) == 2
    assert results[1]["timeline"][0]["event_type"] == "process_creation"
    assert results[1]["timeline"][1]["event_type"] == "dns_query"


def test_build_file_creation_description():
    event = {
        "event_type": "file_creation",
        "process_name": "powershell.exe",
        "details": {
            "target_filename": r"C:\Temp\payload.exe",
        },
    }

    description = build_timeline_description(event)

    assert description == (
        r"powershell.exe created file C:\Temp\payload.exe"
    )


def test_build_registry_modification_description():
    event = {
        "event_type": "registry_modification",
        "process_name": "powershell.exe",
        "details": {
            "target_object": r"HKCU\Software\Example",
        },
    }

    description = build_timeline_description(event)

    assert description == (
        r"powershell.exe modified registry object "
        r"HKCU\Software\Example"
    )


def test_timeline_rejects_missing_timestamp():
    events = [
        {
            "event_type": "process_creation",
            "process_name": "powershell.exe",
        },
    ]

    with pytest.raises(
        ValueError,
        match="missing timestamp",
    ):
        sort_events_chronologically(events)


def test_timeline_rejects_invalid_timestamp():
    events = [
        {
            "timestamp": "not-a-timestamp",
            "event_type": "process_creation",
        },
    ]

    with pytest.raises(
        ValueError,
        match="Invalid timeline event timestamp",
    ):
        sort_events_chronologically(events)
