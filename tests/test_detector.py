from src.detector import (
    detect_brute_force,
    detect_password_spray,
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

    assert len(alerts) == 2
    assert rule_ids == {"AUTH-BF-001", "AUTH-PS-001"}
