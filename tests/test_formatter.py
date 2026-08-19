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


def test_format_many_ips_one_account_details():
    details = {
        "username": "admin",
        "unique_source_ips": 5,
        "source_ips": [
            "10.0.0.10",
            "10.0.0.20",
            "10.0.0.30",
            "10.0.0.40",
            "10.0.0.50",
        ],
    }

    lines = format_alert_details(details)

    assert "Username: admin" in lines
    assert "Unique source IPs: 5" in lines
    assert (
        "Source IPs: 10.0.0.10, 10.0.0.20, 10.0.0.30, "
        "10.0.0.40, 10.0.0.50"
        in lines
    )
