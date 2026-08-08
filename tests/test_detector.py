from src.detector import detect_brute_force
from src.parser import load_auth_events


def test_detect_brute_force():
    events = load_auth_events("data/brute_force_auth_log.csv")

    alerts = detect_brute_force(events)

    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "10.0.0.50"
    assert alerts[0]["username"] == "admin"
    assert alerts[0]["failed_attempts"] == 5


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
