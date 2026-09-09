import pytest
from src.normalizer import (
    normalize_linux_auth_event,
    normalize_linux_timestamp,
    normalize_sysmon_event,
    normalize_windows_security_event,
)


def test_normalize_windows_successful_logon():
    event = {
        "event_id": "4624",
        "timestamp": "2026-08-29T16:00:00.000000Z",
        "host": "WIN-PC01",
        "username": "hawk",
        "source_ip": "192.168.1.20",
        "logon_type": "10",
        "logon_id": "0x12345",
        "authentication_package": "Negotiate",
    }

    normalized = normalize_windows_security_event(event)

    assert normalized["source"] == "windows_security"
    assert normalized["event_id"] == "4624"
    assert normalized["event_type"] == "authentication_success"
    assert normalized["username"] == "hawk"
    assert normalized["session_id"] == "0x12345"
    assert normalized["source_ip"] == "192.168.1.20"
    assert normalized["result"] == "success"
    assert normalized["details"]["logon_type"] == "10"


def test_normalize_windows_failed_logon():
    event = {
        "event_id": "4625",
        "timestamp": "2026-08-29T16:05:00.000000Z",
        "host": "WIN-PC01",
        "username": "admin",
        "source_ip": "10.0.0.8",
        "logon_type": "3",
        "failure_reason": "Unknown user name or bad password",
        "status": "0xC000006D",
        "sub_status": "0xC000006A",
    }

    normalized = normalize_windows_security_event(event)

    assert normalized["source"] == "windows_security"
    assert normalized["event_id"] == "4625"
    assert normalized["event_type"] == "authentication_failure"
    assert normalized["username"] == "admin"
    assert normalized["source_ip"] == "10.0.0.8"
    assert normalized["result"] == "failure"
    assert (
        normalized["details"]["failure_reason"]
        == "Unknown user name or bad password"
    )


def test_normalize_windows_explicit_credentials():
    event = {
        "event_id": "4648",
        "timestamp": "2026-08-29T16:10:00.000000Z",
        "host": "WIN-PC01",
        "username": "administrator",
        "source_username": "hawk",
        "source_ip": "192.168.1.20",
        "target_server": "SERVER01",
        "process_name": "C:\\Windows\\System32\\runas.exe",
        "logon_id": "0x12345",
    }

    normalized = normalize_windows_security_event(event)

    assert normalized["event_type"] == "explicit_credentials"
    assert normalized["username"] == "administrator"
    assert normalized["session_id"] == "0x12345"
    assert normalized["process_name"] == "C:\\Windows\\System32\\runas.exe"
    assert normalized["result"] is None
    assert normalized["details"]["source_username"] == "hawk"
    assert normalized["details"]["target_server"] == "SERVER01"


def test_normalize_windows_privileged_logon():
    event = {
        "event_id": "4672",
        "timestamp": "2026-08-29T16:15:00.000000Z",
        "host": "WIN-PC01",
        "username": "administrator",
        "logon_id": "0x12345",
        "privileges": (
            "SeDebugPrivilege "
            "SeBackupPrivilege "
            "SeRestorePrivilege"
        ),
    }

    normalized = normalize_windows_security_event(event)

    assert normalized["event_type"] == "privileged_logon"
    assert normalized["username"] == "administrator"
    assert normalized["session_id"] == "0x12345"
    assert normalized["result"] is None
    assert (
        normalized["details"]["privileges"]
        == "SeDebugPrivilege SeBackupPrivilege SeRestorePrivilege"
    )


def test_normalize_sysmon_process_creation():
    event = {
        "event_id": "1",
        "timestamp": "2026-08-29T16:25:00.000000Z",
        "host": "WIN-PC01",
        "username": "WIN-PC01\\hawk",
        "logon_id": "0x12345",
        "process_guid": "{ABC-123}",
        "process_id": "4568",
        "process_name": "powershell.exe",
        "command_line": "powershell.exe -NoProfile",
        "parent_process_name": "explorer.exe",
        "integrity_level": "High",
        "hashes": "SHA256=abc123",
    }

    normalized = normalize_sysmon_event(event)

    assert normalized["source"] == "sysmon"
    assert normalized["event_type"] == "process_creation"
    assert normalized["session_id"] == "0x12345"
    assert normalized["process_guid"] == "{ABC-123}"
    assert normalized["process_name"] == "powershell.exe"
    assert normalized["command_line"] == "powershell.exe -NoProfile"
    assert normalized["details"]["integrity_level"] == "High"


def test_normalize_sysmon_network_connection():
    event = {
        "event_id": "3",
        "timestamp": "2026-08-29T16:30:00.000000Z",
        "host": "WIN-PC01",
        "username": "WIN-PC01\\hawk",
        "process_guid": "{ABC-123}",
        "process_id": "4568",
        "process_name": "powershell.exe",
        "protocol": "tcp",
        "source_ip": "192.168.1.10",
        "source_port": "50123",
        "destination_ip": "10.0.0.50",
        "destination_port": "443",
    }

    normalized = normalize_sysmon_event(event)

    assert normalized["event_type"] == "network_connection"
    assert normalized["process_guid"] == "{ABC-123}"
    assert normalized["source_ip"] == "192.168.1.10"
    assert normalized["destination_ip"] == "10.0.0.50"
    assert normalized["details"]["protocol"] == "tcp"
    assert normalized["details"]["destination_port"] == "443"


def test_normalize_sysmon_file_creation():
    event = {
        "event_id": "11",
        "timestamp": "2026-08-29T16:35:00.000000Z",
        "host": "WIN-PC01",
        "username": "WIN-PC01\\hawk",
        "process_guid": "{ABC-123}",
        "process_id": "4568",
        "process_name": "powershell.exe",
        "target_filename": "C:\\Users\\hawk\\Downloads\\script.ps1",
        "creation_utc_time": "2026-08-29T16:35:00.000000Z",
    }

    normalized = normalize_sysmon_event(event)

    assert normalized["event_type"] == "file_creation"
    assert normalized["process_guid"] == "{ABC-123}"
    assert (
        normalized["details"]["target_filename"]
        == "C:\\Users\\hawk\\Downloads\\script.ps1"
    )


def test_normalize_sysmon_registry_modification():
    event = {
        "event_id": "13",
        "timestamp": "2026-08-29T16:40:00.000000Z",
        "host": "WIN-PC01",
        "username": "WIN-PC01\\hawk",
        "process_guid": "{ABC-123}",
        "process_id": "4568",
        "process_name": "powershell.exe",
        "target_object": "HKCU\\Software\\Example\\Setting",
        "details": "NewValue",
    }

    normalized = normalize_sysmon_event(event)

    assert normalized["event_type"] == "registry_modification"
    assert normalized["process_guid"] == "{ABC-123}"
    assert (
        normalized["details"]["target_object"]
        == "HKCU\\Software\\Example\\Setting"
    )
    assert normalized["details"]["registry_details"] == "NewValue"


def test_normalize_sysmon_dns_query():
    event = {
        "event_id": "22",
        "timestamp": "2026-08-29T16:45:00.000000Z",
        "host": "WIN-PC01",
        "username": "WIN-PC01\\hawk",
        "process_guid": "{ABC-123}",
        "process_id": "4568",
        "process_name": "powershell.exe",
        "query_name": "example.com",
        "query_status": "0",
        "query_results": "10.0.0.50",
    }

    normalized = normalize_sysmon_event(event)

    assert normalized["event_type"] == "dns_query"
    assert normalized["process_guid"] == "{ABC-123}"
    assert normalized["details"]["query_name"] == "example.com"
    assert normalized["details"]["query_status"] == "0"
    assert normalized["details"]["query_results"] == "10.0.0.50"


def test_normalize_linux_authentication_success():
    event = {
        "event_type": "authentication_success",
        "timestamp": "Aug 29 17:00:00",
        "host": "server01",
        "service": "sshd",
        "process_id": "4002",
        "username": "hawk",
        "source_ip": "192.168.1.20",
        "source_port": "50002",
        "authentication_method": "password",
        "protocol": "ssh2",
        "result": "success",
    }

    normalized = normalize_linux_auth_event(
        event,
        year=2026,
        utc_offset="+01:00",
    )

    assert normalized["source"] == "linux_auth"
    assert normalized["event_type"] == "authentication_success"
    assert normalized["username"] == "hawk"
    assert normalized["source_ip"] == "192.168.1.20"
    assert normalized["result"] == "success"
    assert normalized["details"]["service"] == "sshd"
    assert normalized["details"]["authentication_method"] == "password"


def test_normalize_linux_authentication_failure():
    event = {
        "event_type": "authentication_failure",
        "timestamp": "Aug 29 17:15:00",
        "host": "server01",
        "service": "sshd",
        "process_id": "4200",
        "username": "administrator",
        "source_ip": "10.0.0.8",
        "source_port": "51000",
        "authentication_method": "password",
        "protocol": "ssh2",
        "invalid_user": True,
        "result": "failure",
    }

    normalized = normalize_linux_auth_event(
        event,
        year=2026,
        utc_offset="+01:00",
    )

    assert normalized["event_type"] == "authentication_failure"
    assert normalized["username"] == "administrator"
    assert normalized["source_ip"] == "10.0.0.8"
    assert normalized["result"] == "failure"
    assert normalized["details"]["invalid_user"] is True


def test_normalize_linux_sudo_execution():
    event = {
        "event_type": "sudo_execution",
        "timestamp": "Aug 29 17:05:00",
        "host": "server01",
        "service": "sudo",
        "process_id": "4100",
        "username": "hawk",
        "target_user": "root",
        "tty": "pts/0",
        "working_directory": "/home/hawk",
        "command": "/usr/bin/systemctl restart ssh",
        "result": "success",
    }

    normalized = normalize_linux_auth_event(
        event,
        year=2026,
        utc_offset="+01:00",
    )

    assert normalized["event_type"] == "sudo_execution"
    assert normalized["username"] == "hawk"
    assert normalized["command_line"] == "/usr/bin/systemctl restart ssh"
    assert normalized["result"] == "success"
    assert normalized["details"]["target_user"] == "root"


def test_normalize_linux_session_open():
    event = {
        "event_type": "session_activity",
        "session_action": "opened",
        "timestamp": "Aug 29 17:10:00",
        "host": "server01",
        "service": "sshd",
        "process_id": "4002",
        "username": "hawk",
        "user_id": "1000",
        "opened_by_uid": "0",
    }

    normalized = normalize_linux_auth_event(
        event,
        year=2026,
        utc_offset="+01:00",
    )
    assert normalized["event_type"] == "session_activity"
    assert normalized["username"] == "hawk"
    assert normalized["details"]["session_action"] == "opened"
    assert normalized["details"]["service"] == "sshd"


def test_normalize_linux_session_close():
    event = {
        "event_type": "session_activity",
        "session_action": "closed",
        "timestamp": "Aug 29 17:20:00",
        "host": "server01",
        "service": "sshd",
        "process_id": "4002",
        "username": "hawk",
    }

    normalized = normalize_linux_auth_event(
        event,
        year=2026,
        utc_offset="+01:00",
    )
    assert normalized["event_type"] == "session_activity"
    assert normalized["details"]["session_action"] == "closed"
    assert normalized["details"]["service"] == "sshd"


def test_unsupported_windows_event_raises_error():
    event = {
        "event_id": "9999",
        "timestamp": "2026-08-29T17:30:00Z",
    }

    with pytest.raises(ValueError):
        normalize_windows_security_event(event)


def test_unsupported_sysmon_event_raises_error():
    event = {
        "event_id": "9999",
        "timestamp": "2026-08-29T17:30:00Z",
    }

    with pytest.raises(ValueError):
        normalize_sysmon_event(event)


def test_unsupported_linux_event_raises_error():
    event = {
        "event_type": "unknown_linux_event",
        "timestamp": "Aug 29 17:30:00",
    }

    with pytest.raises(ValueError):
        normalize_linux_auth_event(
            event,
            year=2026,
            utc_offset="+01:00",
        )


def test_invalid_linux_timestamp_raises_error():
    with pytest.raises(ValueError):
        normalize_linux_timestamp(
            "not-a-timestamp",
            year=2026,
            utc_offset="+01:00",
        )


def test_invalid_linux_utc_offset_raises_error():
    with pytest.raises(ValueError):
        normalize_linux_timestamp(
            "Aug 29 17:00:00",
            year=2026,
            utc_offset="invalid",
        )
