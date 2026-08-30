from src.correlation import (
    correlate_process_to_network,
    correlate_process_to_dns,
    correlate_authentication_to_process,
    correlate_privileged_logon_to_process,
    correlate_ssh_to_sudo,
    run_correlation_engine,
)


def test_process_to_network_correlation():
    events = [
        {
            "timestamp": "2026-08-30T14:00:00Z",
            "event_type": "process_creation",
            "host": "WIN-PC01",
            "username": "hawk",
            "process_guid": "{PROC-001}",
            "process_id": "5000",
            "process_name": "powershell.exe",
            "details": {},
        },
        {
            "timestamp": "2026-08-30T14:00:20Z",
            "event_type": "network_connection",
            "host": "WIN-PC01",
            "username": "hawk",
            "process_guid": "{PROC-001}",
            "process_id": "5000",
            "process_name": "powershell.exe",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.50",
            "details": {
                "destination_port": "443",
            },
        },
    ]

    correlations = correlate_process_to_network(events)

    assert len(correlations) == 1
    assert correlations[0]["correlation_id"] == "CORR-PROC-NET-001"
    assert correlations[0]["details"]["process_guid"] == "{PROC-001}"
    assert correlations[0]["details"]["destination_ip"] == "10.0.0.50"
    assert correlations[0]["details"]["destination_port"] == "443"


def test_process_to_network_different_process_guid_does_not_correlate():
    events = [
        {
            "timestamp": "2026-08-30T14:00:00Z",
            "event_type": "process_creation",
            "host": "WIN-PC01",
            "process_guid": "{PROC-001}",
            "process_name": "powershell.exe",
        },
        {
            "timestamp": "2026-08-30T14:00:20Z",
            "event_type": "network_connection",
            "host": "WIN-PC01",
            "process_guid": "{PROC-999}",
            "process_name": "powershell.exe",
            "destination_ip": "10.0.0.50",
        },
    ]

    correlations = correlate_process_to_network(events)

    assert correlations == []


def test_process_to_network_different_host_does_not_correlate():
    events = [
        {
            "timestamp": "2026-08-30T14:00:00Z",
            "event_type": "process_creation",
            "host": "WIN-PC01",
            "process_guid": "{PROC-001}",
        },
        {
            "timestamp": "2026-08-30T14:00:20Z",
            "event_type": "network_connection",
            "host": "WIN-PC02",
            "process_guid": "{PROC-001}",
        },
    ]

    correlations = correlate_process_to_network(events)

    assert correlations == []


def test_process_to_network_outside_time_window_does_not_correlate():
    events = [
        {
            "timestamp": "2026-08-30T14:00:00Z",
            "event_type": "process_creation",
            "host": "WIN-PC01",
            "process_guid": "{PROC-001}",
        },
        {
            "timestamp": "2026-08-30T14:06:00Z",
            "event_type": "network_connection",
            "host": "WIN-PC01",
            "process_guid": "{PROC-001}",
        },
    ]

    correlations = correlate_process_to_network(
        events,
        window_seconds=300,
    )

    assert correlations == []


def test_process_to_dns_correlation():
    events = [
        {
            "timestamp": "2026-08-30T15:00:00Z",
            "event_type": "process_creation",
            "host": "WIN-PC01",
            "username": "hawk",
            "process_guid": "{PROC-DNS-001}",
            "process_name": "powershell.exe",
        },
        {
            "timestamp": "2026-08-30T15:00:15Z",
            "event_type": "dns_query",
            "host": "WIN-PC01",
            "username": "hawk",
            "process_guid": "{PROC-DNS-001}",
            "process_name": "powershell.exe",
            "details": {
                "query_name": "example.com",
                "query_status": "0",
                "query_results": "10.0.0.50",
            },
        },
    ]

    correlations = correlate_process_to_dns(events)

    assert len(correlations) == 1
    assert correlations[0]["correlation_id"] == "CORR-PROC-DNS-001"
    assert correlations[0]["details"]["process_guid"] == "{PROC-DNS-001}"
    assert correlations[0]["details"]["query_name"] == "example.com"
    assert correlations[0]["details"]["query_results"] == "10.0.0.50"


def test_process_to_dns_different_process_guid_does_not_correlate():
    events = [
        {
            "timestamp": "2026-08-30T15:00:00Z",
            "event_type": "process_creation",
            "host": "WIN-PC01",
            "process_guid": "{PROC-001}",
        },
        {
            "timestamp": "2026-08-30T15:00:15Z",
            "event_type": "dns_query",
            "host": "WIN-PC01",
            "process_guid": "{PROC-999}",
            "details": {
                "query_name": "example.com",
            },
        },
    ]

    correlations = correlate_process_to_dns(events)

    assert correlations == []


def test_authentication_to_process_correlation():
    events = [
        {
            "timestamp": "2026-08-30T15:10:00Z",
            "event_type": "authentication_success",
            "host": "WIN-PC01",
            "username": "hawk",
            "session_id": "0x12345",
            "source_ip": "192.168.1.50",
        },
        {
            "timestamp": "2026-08-30T15:10:20Z",
            "event_type": "process_creation",
            "host": "WIN-PC01",
            "username": "WIN-PC01\\hawk",
            "session_id": "0x12345",
            "process_guid": "{PROC-001}",
            "process_id": "5000",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -NoProfile",
        },
    ]

    correlations = correlate_authentication_to_process(events)

    assert len(correlations) == 1
    assert correlations[0]["correlation_id"] == "CORR-AUTH-EXEC-001"
    assert correlations[0]["details"]["session_id"] == "0x12345"
    assert correlations[0]["details"]["source_ip"] == "192.168.1.50"
    assert correlations[0]["details"]["process_name"] == "powershell.exe"


def test_authentication_to_process_different_session_does_not_correlate():
    events = [
        {
            "timestamp": "2026-08-30T15:10:00Z",
            "event_type": "authentication_success",
            "host": "WIN-PC01",
            "username": "hawk",
            "session_id": "0x111",
        },
        {
            "timestamp": "2026-08-30T15:10:20Z",
            "event_type": "process_creation",
            "host": "WIN-PC01",
            "username": "hawk",
            "session_id": "0x999",
            "process_name": "powershell.exe",
        },
    ]

    correlations = correlate_authentication_to_process(events)

    assert correlations == []



def test_privileged_logon_to_process_correlation():
    events = [
        {
            "timestamp": "2026-08-30T15:20:00Z",
            "event_type": "privileged_logon",
            "host": "WIN-PC01",
            "username": "Administrator",
            "session_id": "0x999",
        },
        {
            "timestamp": "2026-08-30T15:20:20Z",
            "event_type": "process_creation",
            "host": "WIN-PC01",
            "username": "WIN-PC01\\Administrator",
            "session_id": "0x999",
            "process_guid": "{PROC-ADMIN-001}",
            "process_id": "6000",
            "process_name": "cmd.exe",
            "command_line": "cmd.exe /c whoami",
        },
    ]

    correlations = correlate_privileged_logon_to_process(events)

    assert len(correlations) == 1
    assert correlations[0]["correlation_id"] == "CORR-PRIV-EXEC-001"
    assert correlations[0]["details"]["session_id"] == "0x999"
    assert correlations[0]["details"]["process_name"] == "cmd.exe"
    assert correlations[0]["details"]["process_guid"] == "{PROC-ADMIN-001}"


def test_privileged_logon_to_process_different_session_does_not_correlate():
    events = [
        {
            "timestamp": "2026-08-30T15:20:00Z",
            "event_type": "privileged_logon",
            "host": "WIN-PC01",
            "username": "Administrator",
            "session_id": "0x111",
        },
        {
            "timestamp": "2026-08-30T15:20:20Z",
            "event_type": "process_creation",
            "host": "WIN-PC01",
            "username": "Administrator",
            "session_id": "0x999",
            "process_name": "cmd.exe",
        },
    ]

    correlations = correlate_privileged_logon_to_process(events)

    assert correlations == []


def test_ssh_to_sudo_uses_most_recent_valid_login():
    events = [
        {
            "timestamp": "2026-08-30T15:00:00Z",
            "source": "linux_auth",
            "event_type": "authentication_success",
            "host": "server01",
            "username": "hawk",
            "source_ip": "192.168.1.40",
            "details": {
                "service": "sshd",
            },
        },
        {
            "timestamp": "2026-08-30T15:28:00Z",
            "source": "linux_auth",
            "event_type": "authentication_success",
            "host": "server01",
            "username": "hawk",
            "source_ip": "192.168.1.50",
            "details": {
                "service": "sshd",
            },
        },
        {
            "timestamp": "2026-08-30T15:30:00Z",
            "source": "linux_auth",
            "event_type": "sudo_execution",
            "host": "server01",
            "username": "hawk",
            "command_line": "/usr/bin/systemctl restart ssh",
            "details": {
                "target_user": "root",
            },
        },
    ]

    correlations = correlate_ssh_to_sudo(events)

    assert len(correlations) == 1
    assert correlations[0]["correlation_id"] == "CORR-SSH-SUDO-001"
    assert correlations[0]["first_seen"] == "2026-08-30T15:28:00Z"
    assert correlations[0]["details"]["source_ip"] == "192.168.1.50"
    assert correlations[0]["details"]["target_user"] == "root"


def test_ssh_to_sudo_different_username_does_not_correlate():
    events = [
        {
            "timestamp": "2026-08-30T15:28:00Z",
            "source": "linux_auth",
            "event_type": "authentication_success",
            "host": "server01",
            "username": "hawk",
            "source_ip": "192.168.1.50",
            "details": {
                "service": "sshd",
            },
        },
        {
            "timestamp": "2026-08-30T15:30:00Z",
            "source": "linux_auth",
            "event_type": "sudo_execution",
            "host": "server01",
            "username": "admin",
            "command_line": "/usr/bin/id",
            "details": {
                "target_user": "root",
            },
        },
    ]

    correlations = correlate_ssh_to_sudo(events)

    assert correlations == []


def test_ssh_to_sudo_outside_time_window_does_not_correlate():
    events = [
        {
            "timestamp": "2026-08-30T15:00:00Z",
            "source": "linux_auth",
            "event_type": "authentication_success",
            "host": "server01",
            "username": "hawk",
            "source_ip": "192.168.1.50",
            "details": {
                "service": "sshd",
            },
        },
        {
            "timestamp": "2026-08-30T15:06:00Z",
            "source": "linux_auth",
            "event_type": "sudo_execution",
            "host": "server01",
            "username": "hawk",
            "command_line": "/usr/bin/id",
            "details": {
                "target_user": "root",
            },
        },
    ]

    correlations = correlate_ssh_to_sudo(
        events,
        window_seconds=300,
    )

    assert correlations == []


def test_non_ssh_login_to_sudo_does_not_correlate():
    events = [
        {
            "timestamp": "2026-08-30T15:28:00Z",
            "source": "linux_auth",
            "event_type": "authentication_success",
            "host": "server01",
            "username": "hawk",
            "source_ip": "192.168.1.50",
            "details": {
                "service": "login",
            },
        },
        {
            "timestamp": "2026-08-30T15:30:00Z",
            "source": "linux_auth",
            "event_type": "sudo_execution",
            "host": "server01",
            "username": "hawk",
            "command_line": "/usr/bin/id",
            "details": {
                "target_user": "root",
            },
        },
    ]

    correlations = correlate_ssh_to_sudo(events)

    assert correlations == []


def test_run_correlation_engine_runs_all_correlators():
    events = [
        {
            "timestamp": "2026-08-30T16:00:00Z",
            "source": "windows_security",
            "event_type": "authentication_success",
            "host": "WIN-PC01",
            "username": "hawk",
            "session_id": "0x12345",
            "source_ip": "192.168.1.50",
        },
        {
            "timestamp": "2026-08-30T16:00:05Z",
            "source": "windows_security",
            "event_type": "privileged_logon",
            "host": "WIN-PC01",
            "username": "hawk",
            "session_id": "0x12345",
        },
        {
            "timestamp": "2026-08-30T16:00:20Z",
            "source": "sysmon",
            "event_type": "process_creation",
            "host": "WIN-PC01",
            "username": "hawk",
            "session_id": "0x12345",
            "process_guid": "{PROC-001}",
            "process_name": "powershell.exe",
        },
        {
            "timestamp": "2026-08-30T16:00:30Z",
            "source": "sysmon",
            "event_type": "dns_query",
            "host": "WIN-PC01",
            "process_guid": "{PROC-001}",
            "process_name": "powershell.exe",
            "details": {
                "query_name": "example.com",
            },
        },
        {
            "timestamp": "2026-08-30T16:00:40Z",
            "source": "sysmon",
            "event_type": "network_connection",
            "host": "WIN-PC01",
            "process_guid": "{PROC-001}",
            "process_name": "powershell.exe",
            "destination_ip": "10.0.0.50",
            "details": {
                "destination_port": "443",
            },
        },
        {
            "timestamp": "2026-08-30T17:00:00Z",
            "source": "linux_auth",
            "event_type": "authentication_success",
            "host": "server01",
            "username": "hawk",
            "source_ip": "192.168.1.60",
            "details": {
                "service": "sshd",
            },
        },
        {
            "timestamp": "2026-08-30T17:02:00Z",
            "source": "linux_auth",
            "event_type": "sudo_execution",
            "host": "server01",
            "username": "hawk",
            "command_line": "/usr/bin/id",
            "details": {
                "target_user": "root",
            },
        },
    ]

    correlations = run_correlation_engine(events)

    correlation_ids = {
        correlation["correlation_id"]
        for correlation in correlations
    }

    assert len(correlations) == 5
    assert correlation_ids == {
        "CORR-PROC-NET-001",
        "CORR-PROC-DNS-001",
        "CORR-AUTH-EXEC-001",
        "CORR-PRIV-EXEC-001",
        "CORR-SSH-SUDO-001",
    }


def test_run_correlation_engine_applies_custom_rule_config():
    events = [
        {
            "timestamp": "2026-08-30T16:00:00Z",
            "event_type": "process_creation",
            "host": "WIN-PC01",
            "process_guid": "{PROC-001}",
            "process_name": "powershell.exe",
        },
        {
            "timestamp": "2026-08-30T16:06:00Z",
            "event_type": "network_connection",
            "host": "WIN-PC01",
            "process_guid": "{PROC-001}",
            "process_name": "powershell.exe",
            "destination_ip": "10.0.0.50",
        },
    ]

    config = {
        "CORR-PROC-NET-001": {
            "window_seconds": 600,
        },
    }

    correlations = run_correlation_engine(
        events,
        config=config,
    )

    assert len(correlations) == 1
    assert correlations[0]["correlation_id"] == "CORR-PROC-NET-001"
