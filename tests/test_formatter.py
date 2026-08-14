from src.formatter import format_alert_details


def test_format_brute_force_details():
    details = {
        "source_ip": "10.0.0.50",
        "username": "admin",
        "failed_attempts": 5,
    }

    lines = format_alert_details(details)

    assert lines == [
        "Source IP: 10.0.0.50",
        "Username: admin",
        "Failed attempts: 5",
    ]


def test_format_password_spray_details():
    details = {
        "source_ip": "10.0.0.50",
        "unique_accounts": 5,
        "usernames": ["admin", "alice", "bob", "charlie", "david"],
    }

    lines = format_alert_details(details)

    assert lines == [
        "Source IP: 10.0.0.50",
        "Unique accounts: 5",
        "Usernames: admin, alice, bob, charlie, david",
    ]
