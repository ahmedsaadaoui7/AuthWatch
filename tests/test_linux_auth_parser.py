import pytest

from src.parsers.linux_auth import (
    load_linux_auth_events,
    parse_linux_auth_event,
)


def test_failed_ssh_login():
    line = (
        "Aug 29 11:40:00 server01 sshd[4001]: "
        "Failed password for hawk from 192.168.1.50 port 50001 ssh2"
    )

    event = parse_linux_auth_event(line)

    assert event["event_type"] == "authentication_failure"
    assert event["username"] == "hawk"
    assert event["source_ip"] == "192.168.1.50"
    assert event["invalid_user"] is False
    assert event["result"] == "failure"


def test_failed_ssh_invalid_user():
    line = (
        "Aug 29 11:40:00 server01 sshd[4001]: "
        "Failed password for invalid user attacker "
        "from 10.0.0.8 port 50001 ssh2"
    )

    event = parse_linux_auth_event(line)

    assert event["username"] == "attacker"
    assert event["invalid_user"] is True


def test_successful_ssh_password():
    line = (
        "Aug 29 11:41:00 server01 sshd[4002]: "
        "Accepted password for hawk "
        "from 192.168.1.20 port 50002 ssh2"
    )

    event = parse_linux_auth_event(line)

    assert event["event_type"] == "authentication_success"
    assert event["username"] == "hawk"
    assert event["authentication_method"] == "password"
    assert event["result"] == "success"


def test_successful_ssh_publickey():
    line = (
        "Aug 29 11:41:00 server01 sshd[4002]: "
        "Accepted publickey for john "
        "from 192.168.1.30 port 50003 ssh2"
    )

    event = parse_linux_auth_event(line)

    assert event["username"] == "john"
    assert event["authentication_method"] == "publickey"


def test_sudo_command():
    line = (
        "Aug 29 11:42:00 server01 sudo: hawk : "
        "TTY=pts/0 ; PWD=/home/hawk ; "
        "USER=root ; COMMAND=/usr/bin/id"
    )

    event = parse_linux_auth_event(line)

    assert event["event_type"] == "sudo_execution"
    assert event["username"] == "hawk"
    assert event["target_user"] == "root"
    assert event["command"] == "/usr/bin/id"


def test_ssh_session_open():
    line = (
        "Aug 29 11:43:00 server01 sshd[4002]: "
        "pam_unix(sshd:session): session opened "
        "for user hawk(uid=1000) by (uid=0)"
    )

    event = parse_linux_auth_event(line)

    assert event["event_type"] == "session_activity"
    assert event["session_action"] == "opened"
    assert event["username"] == "hawk"
    assert event["user_id"] == "1000"


def test_ssh_session_close():
    line = (
        "Aug 29 11:50:00 server01 sshd[4002]: "
        "pam_unix(sshd:session): session closed for user hawk"
    )

    event = parse_linux_auth_event(line)

    assert event["event_type"] == "session_activity"
    assert event["session_action"] == "closed"
    assert event["username"] == "hawk"


def test_unsupported_log_returns_none():
    line = (
        "Aug 29 11:55:00 server01 "
        "kernel: unrelated example message"
    )

    assert parse_linux_auth_event(line) is None


def test_load_linux_auth_events(tmp_path):
    log_file = tmp_path / "auth.log"

    log_file.write_text(
        "Aug 29 11:40:00 server01 sshd[4001]: "
        "Failed password for hawk from 192.168.1.50 "
        "port 50001 ssh2\n"
        "Aug 29 11:41:00 server01 sshd[4002]: "
        "Accepted password for hawk from 192.168.1.20 "
        "port 50002 ssh2\n"
        "Aug 29 11:55:00 server01 "
        "kernel: unrelated example message\n",
        encoding="utf-8",
    )

    events = load_linux_auth_events(log_file)

    assert len(events) == 2
    assert events[0]["event_type"] == "authentication_failure"
    assert events[1]["event_type"] == "authentication_success"


def test_missing_log_file_raises_error(tmp_path):
    missing_file = tmp_path / "missing.log"

    with pytest.raises(FileNotFoundError):
        load_linux_auth_events(missing_file)
