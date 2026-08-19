from src.detector import (
    detect_brute_force,
    detect_disabled_account_attempts,
    detect_many_ips_one_account,
    detect_one_ip_many_accounts,
    detect_password_spray,
    detect_success_after_failures,
    run_detection_engine,
)
from src.parser import load_auth_events


def test_detect_brute_force():
    events = load_auth_events("data/brute_force_auth_log.csv")

    alerts = detect_brute_force(events)

    assert alerts[0]["rule_id"] == "AUTH-BF-001"
    assert alerts[0]["title"] == "Potential Brute-Force Activity"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["first_seen"] == "2026-08-08T09:00:00"
    assert alerts[0]["last_seen"] == "2026-08-08T09:00:48"
    assert len(alerts) == 1
    assert alerts[0]["details"]["source_ip"] == "10.0.0.50"
    assert alerts[0]["details"]["username"] == "admin"
    assert alerts[0]["details"]["failed_attempts"] == 5


def test_normal_activity_does_not_trigger_alert():
    events = load_auth_events("data/normal_auth_log.csv")

    alerts = detect_brute_force(events)

    assert alerts == []


def test_failures_outside_time_window_do_not_trigger_alert():
    events = [
        {
            "timestamp": "2026-08-08T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:00:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:00:40",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:01:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:01:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_different_users_are_not_combined():
    events = [
        {
            "timestamp": "2026-08-08T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:00:10",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:00:20",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:00:30",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:00:40",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_different_source_ips_are_not_combined():
    events = [
        {
            "timestamp": "2026-08-08T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:00:10",
            "username": "admin",
            "source_ip": "10.0.0.60",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:00:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:00:30",
            "username": "admin",
            "source_ip": "10.0.0.60",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:00:40",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    alerts = detect_brute_force(events)

    assert alerts == []


def test_failures_exactly_at_window_boundary_trigger_alert():
    events = [
        {
            "timestamp": "2026-08-08T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:00:15",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:00:30",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:00:45",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-08T09:01:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    alerts = detect_brute_force(events)

    assert len(alerts) == 1

def test_detect_password_spray():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:10",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:20",
            "username": "charlie",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:30",
            "username": "david",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:40",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    alerts = detect_password_spray(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-PS-001"
    assert alerts[0]["title"] == "Potential Password Spraying Activity"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["details"]["source_ip"] == "10.0.0.50"
    assert alerts[0]["details"]["unique_accounts"] == 5

def test_password_spray_requires_unique_accounts():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:10",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:30",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:40",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    alerts = detect_password_spray(events)

    assert alerts == []

def test_password_spray_different_source_ips_are_not_combined():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:10",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:20",
            "username": "charlie",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:30",
            "username": "david",
            "source_ip": "10.0.0.60",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:40",
            "username": "admin",
            "source_ip": "10.0.0.60",
            "result": "failure",
        },
    ]

    alerts = detect_password_spray(events)

    assert alerts == []

def test_password_spray_attempts_outside_time_window_do_not_trigger():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:20",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:40",
            "username": "charlie",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:01:00",
            "username": "david",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:01:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    alerts = detect_password_spray(events)

    assert alerts == []

def test_password_spray_exactly_at_window_boundary_triggers():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:15",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:30",
            "username": "charlie",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:45",
            "username": "david",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:01:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    alerts = detect_password_spray(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-PS-001"
    assert alerts[0]["details"]["unique_accounts"] == 5

def test_password_spray_successful_logins_do_not_count():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:10",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:20",
            "username": "charlie",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:30",
            "username": "david",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:40",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = detect_password_spray(events)

    assert alerts == []

def test_detection_engine_runs_multiple_rules():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:10",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:30",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:40",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:01:00",
            "username": "alice",
            "source_ip": "10.0.0.60",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:01:10",
            "username": "bob",
            "source_ip": "10.0.0.60",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:01:20",
            "username": "charlie",
            "source_ip": "10.0.0.60",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:01:30",
            "username": "david",
            "source_ip": "10.0.0.60",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:01:40",
            "username": "eve",
            "source_ip": "10.0.0.60",
            "result": "failure",
        },
    ]

    alerts = run_detection_engine(events)

    rule_ids = {alert["rule_id"] for alert in alerts}

    assert {"AUTH-BF-001", "AUTH-PS-001"}.issubset(rule_ids)

def test_detect_success_after_failures():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:10",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:30",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = detect_success_after_failures(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-SF-001"
    assert alerts[0]["title"] == "Successful Login After Repeated Failures"
    assert alerts[0]["severity"] == "high"
    assert alerts[0]["details"]["source_ip"] == "10.0.0.50"
    assert alerts[0]["details"]["username"] == "admin"
    assert alerts[0]["details"]["failed_attempts"] == 3

def test_success_after_failures_requires_threshold():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:10",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []

def test_success_after_failures_different_usernames_are_not_combined():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:10",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:30",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []


def test_success_after_failures_different_source_ips_are_not_combined():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:10",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:30",
            "username": "admin",
            "source_ip": "10.0.0.60",
            "result": "success",
        },
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []


def test_success_after_failures_outside_time_window_do_not_trigger():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:40",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:01:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []

def test_success_after_failures_exactly_at_window_boundary_triggers():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:40",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:01:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = detect_success_after_failures(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-SF-001"

def test_success_without_previous_failures_does_not_trigger():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []

def test_success_clears_previous_failure_window():
    events = [
        {
            "timestamp": "2026-08-14T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:10",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-14T09:00:30",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-14T09:00:40",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = detect_success_after_failures(events)

    assert alerts == []

def test_detection_engine_runs_success_after_failures_rule():
    events = [
        {
            "timestamp": "2026-08-15T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-15T09:00:10",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-15T09:00:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-15T09:00:30",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = run_detection_engine(events)

    rule_ids = {alert["rule_id"] for alert in alerts}

    assert "AUTH-SF-001" in rule_ids


def test_detect_disabled_account_attempt():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "old_admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    disabled_accounts = {"old_admin"}

    alerts = detect_disabled_account_attempts(
        events,
        disabled_accounts,
    )

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-DA-001"
    assert alerts[0]["title"] == "Authentication Attempt Against Disabled Account"
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["details"]["source_ip"] == "10.0.0.50"
    assert alerts[0]["details"]["username"] == "old_admin"
    assert alerts[0]["details"]["result"] == "failure"


def test_active_account_does_not_trigger_disabled_account_alert():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    disabled_accounts = {"old_admin"}

    alerts = detect_disabled_account_attempts(
        events,
        disabled_accounts,
    )

    assert alerts == []


def test_empty_disabled_account_list_does_not_trigger():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "old_admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    disabled_accounts = set()

    alerts = detect_disabled_account_attempts(
        events,
        disabled_accounts,
    )

    assert alerts == []


def test_successful_login_to_disabled_account_triggers_alert():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "old_admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    disabled_accounts = {"old_admin"}

    alerts = detect_disabled_account_attempts(
        events,
        disabled_accounts,
    )

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-DA-001"
    assert alerts[0]["details"]["result"] == "success"


def test_multiple_disabled_accounts_are_detected():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "old_admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-17T09:00:10",
            "username": "terminated_user",
            "source_ip": "10.0.0.60",
            "result": "failure",
        },
    ]

    disabled_accounts = {
        "old_admin",
        "terminated_user",
    }

    alerts = detect_disabled_account_attempts(
        events,
        disabled_accounts,
    )

    assert len(alerts) == 2
    assert alerts[0]["details"]["username"] == "old_admin"
    assert alerts[1]["details"]["username"] == "terminated_user"


def test_disabled_and_active_accounts_are_separated():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "old_admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-17T09:00:10",
            "username": "alice",
            "source_ip": "10.0.0.60",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-17T09:00:20",
            "username": "terminated_user",
            "source_ip": "10.0.0.70",
            "result": "success",
        },
    ]

    disabled_accounts = {
        "old_admin",
        "terminated_user",
    }

    alerts = detect_disabled_account_attempts(
        events,
        disabled_accounts,
    )

    assert len(alerts) == 2

    usernames = {
        alert["details"]["username"]
        for alert in alerts
    }

    assert usernames == {
        "old_admin",
        "terminated_user",
    }


def test_detection_engine_runs_disabled_account_rule():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "old_admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    disabled_accounts = {"old_admin"}

    alerts = run_detection_engine(
        events,
        disabled_accounts=disabled_accounts,
    )

    rule_ids = {alert["rule_id"] for alert in alerts}

    assert "AUTH-DA-001" in rule_ids


def test_detect_one_ip_many_accounts():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:01:00",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-17T09:02:00",
            "username": "charlie",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:03:00",
            "username": "david",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-17T09:04:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = detect_one_ip_many_accounts(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-MA-001"
    assert alerts[0]["title"] == "One Source IP Accessing Multiple Accounts"
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["details"]["source_ip"] == "10.0.0.50"
    assert alerts[0]["details"]["unique_accounts"] == 5


def test_one_ip_many_accounts_requires_threshold():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:01:00",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-17T09:02:00",
            "username": "charlie",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:03:00",
            "username": "david",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    alerts = detect_one_ip_many_accounts(events)

    assert alerts == []


def test_one_ip_many_accounts_requires_unique_accounts():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-17T09:01:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:02:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-17T09:03:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:04:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    alerts = detect_one_ip_many_accounts(events)

    assert alerts == []


def test_one_ip_many_accounts_different_source_ips_are_not_combined():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:01:00",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-17T09:02:00",
            "username": "charlie",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:03:00",
            "username": "david",
            "source_ip": "10.0.0.60",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-17T09:04:00",
            "username": "admin",
            "source_ip": "10.0.0.60",
            "result": "success",
        },
    ]

    alerts = detect_one_ip_many_accounts(events)

    assert alerts == []


def test_one_ip_many_accounts_outside_time_window_do_not_trigger():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:02:00",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-17T09:04:00",
            "username": "charlie",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:06:00",
            "username": "david",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-17T09:08:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = detect_one_ip_many_accounts(events)

    assert alerts == []


def test_one_ip_many_accounts_exactly_at_window_boundary_triggers():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:01:00",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-17T09:02:00",
            "username": "charlie",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:03:00",
            "username": "david",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-17T09:05:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = detect_one_ip_many_accounts(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-MA-001"


def test_one_ip_many_accounts_successful_logins_count():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:01:00",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:02:00",
            "username": "charlie",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:03:00",
            "username": "david",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:04:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = detect_one_ip_many_accounts(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-MA-001"
    assert alerts[0]["details"]["unique_accounts"] == 5


def test_detection_engine_runs_one_ip_many_accounts_rule():
    events = [
        {
            "timestamp": "2026-08-17T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:01:00",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:02:00",
            "username": "charlie",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:03:00",
            "username": "david",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
        {
            "timestamp": "2026-08-17T09:04:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = run_detection_engine(events)

    rule_ids = {alert["rule_id"] for alert in alerts}

    assert "AUTH-MA-001" in rule_ids


def test_detect_many_ips_one_account():
    events = [
        {
            "timestamp": "2026-08-19T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.10",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:01:00",
            "username": "admin",
            "source_ip": "10.0.0.20",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:02:00",
            "username": "admin",
            "source_ip": "10.0.0.30",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:03:00",
            "username": "admin",
            "source_ip": "10.0.0.40",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:04:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    alerts = detect_many_ips_one_account(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-MI-001"
    assert alerts[0]["title"] == "One Account Accessed From Multiple Source IPs"
    assert alerts[0]["severity"] == "medium"
    assert alerts[0]["details"]["username"] == "admin"
    assert alerts[0]["details"]["unique_source_ips"] == 5


def test_many_ips_one_account_requires_threshold():
    events = [
        {
            "timestamp": "2026-08-19T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.10",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:01:00",
            "username": "admin",
            "source_ip": "10.0.0.20",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:02:00",
            "username": "admin",
            "source_ip": "10.0.0.30",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:03:00",
            "username": "admin",
            "source_ip": "10.0.0.40",
            "result": "success",
        },
    ]

    alerts = detect_many_ips_one_account(events)

    assert alerts == []


def test_many_ips_one_account_requires_unique_source_ips():
    events = [
        {
            "timestamp": "2026-08-19T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.10",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:01:00",
            "username": "admin",
            "source_ip": "10.0.0.10",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:02:00",
            "username": "admin",
            "source_ip": "10.0.0.10",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:03:00",
            "username": "admin",
            "source_ip": "10.0.0.10",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:04:00",
            "username": "admin",
            "source_ip": "10.0.0.10",
            "result": "failure",
        },
    ]

    alerts = detect_many_ips_one_account(events)

    assert alerts == []


def test_many_ips_one_account_different_usernames_are_not_combined():
    events = [
        {
            "timestamp": "2026-08-19T09:00:00",
            "username": "alice",
            "source_ip": "10.0.0.10",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:01:00",
            "username": "alice",
            "source_ip": "10.0.0.20",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:02:00",
            "username": "alice",
            "source_ip": "10.0.0.30",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:03:00",
            "username": "bob",
            "source_ip": "10.0.0.40",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:04:00",
            "username": "bob",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    alerts = detect_many_ips_one_account(events)

    assert alerts == []


def test_many_ips_one_account_outside_time_window_do_not_trigger():
    events = [
        {
            "timestamp": "2026-08-19T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.10",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:02:00",
            "username": "admin",
            "source_ip": "10.0.0.20",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:04:00",
            "username": "admin",
            "source_ip": "10.0.0.30",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:06:00",
            "username": "admin",
            "source_ip": "10.0.0.40",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:08:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    alerts = detect_many_ips_one_account(events)

    assert alerts == []


def test_many_ips_one_account_exactly_at_window_boundary_triggers():
    events = [
        {
            "timestamp": "2026-08-19T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.10",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:01:00",
            "username": "admin",
            "source_ip": "10.0.0.20",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:02:00",
            "username": "admin",
            "source_ip": "10.0.0.30",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:03:00",
            "username": "admin",
            "source_ip": "10.0.0.40",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:05:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    alerts = detect_many_ips_one_account(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-MI-001"


def test_many_ips_one_account_successful_logins_count():
    events = [
        {
            "timestamp": "2026-08-19T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.10",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:01:00",
            "username": "admin",
            "source_ip": "10.0.0.20",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:02:00",
            "username": "admin",
            "source_ip": "10.0.0.30",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:03:00",
            "username": "admin",
            "source_ip": "10.0.0.40",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:04:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = detect_many_ips_one_account(events)

    assert len(alerts) == 1
    assert alerts[0]["rule_id"] == "AUTH-MI-001"
    assert alerts[0]["details"]["unique_source_ips"] == 5


def test_detection_engine_runs_many_ips_one_account_rule():
    events = [
        {
            "timestamp": "2026-08-19T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.10",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:01:00",
            "username": "admin",
            "source_ip": "10.0.0.20",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:02:00",
            "username": "admin",
            "source_ip": "10.0.0.30",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:03:00",
            "username": "admin",
            "source_ip": "10.0.0.40",
            "result": "success",
        },
        {
            "timestamp": "2026-08-19T09:04:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "success",
        },
    ]

    alerts = run_detection_engine(events)

    rule_ids = {alert["rule_id"] for alert in alerts}

    assert "AUTH-MI-001" in rule_ids


def test_detection_engine_uses_custom_brute_force_config():
    events = [
        {
            "timestamp": "2026-08-19T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:00:10",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:00:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    config = {
        "AUTH-BF-001": {
            "threshold": 3,
        }
    }

    alerts = run_detection_engine(
        events,
        config=config,
    )

    rule_ids = {alert["rule_id"] for alert in alerts}

    assert "AUTH-BF-001" in rule_ids


def test_detection_engine_uses_custom_brute_force_window():
    events = [
        {
            "timestamp": "2026-08-19T09:00:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:00:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:00:40",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:01:00",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
        {
            "timestamp": "2026-08-19T09:01:20",
            "username": "admin",
            "source_ip": "10.0.0.50",
            "result": "failure",
        },
    ]

    config = {
        "AUTH-BF-001": {
            "window_seconds": 120,
        }
    }

    alerts = run_detection_engine(
        events,
        config=config,
    )

    rule_ids = {alert["rule_id"] for alert in alerts}

    assert "AUTH-BF-001" in rule_ids
