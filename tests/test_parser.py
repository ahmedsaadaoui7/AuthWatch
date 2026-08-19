import pytest

from src.parser import load_auth_events, load_disabled_accounts


def test_load_auth_events():
    events = load_auth_events("data/normal_auth_log.csv")

    assert len(events) == 4
    assert events[0]["username"] == "alice"
    assert events[0]["source_ip"] == "192.168.1.20"
    assert events[0]["result"] == "success"


def test_missing_required_field(tmp_path):
    invalid_file = tmp_path / "invalid_auth_log.csv"

    invalid_file.write_text(
        "timestamp,username,result\n"
        "2026-08-08T08:00:00,alice,success\n"
    )

    with pytest.raises(ValueError):
        load_auth_events(invalid_file)


def test_empty_required_value_is_rejected(tmp_path):
    invalid_file = tmp_path / "empty_value.csv"

    invalid_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-08T09:00:00,,10.0.0.50,failure\n"
    )

    with pytest.raises(
        ValueError,
        match="required field 'username' must be a non-empty string",
    ):
        load_auth_events(invalid_file)


def test_invalid_result_is_rejected(tmp_path):
    invalid_file = tmp_path / "invalid_result.csv"

    invalid_file.write_text(
        "timestamp,username,source_ip,result\n"
        "2026-08-08T09:00:00,admin,10.0.0.50,unknown\n"
    )

    with pytest.raises(ValueError, match="invalid authentication result"):
        load_auth_events(invalid_file)


def test_invalid_timestamp_is_rejected(tmp_path):
    invalid_file = tmp_path / "invalid_timestamp.csv"

    invalid_file.write_text(
        "timestamp,username,source_ip,result\n"
        "not-a-timestamp,admin,10.0.0.50,failure\n"
    )

    with pytest.raises(ValueError, match="invalid timestamp"):
        load_auth_events(invalid_file)


def test_load_disabled_accounts(tmp_path):
    input_file = tmp_path / "disabled_accounts.txt"

    input_file.write_text(
        "old_admin\n"
        "terminated_user\n",
        encoding="utf-8",
    )

    disabled_accounts = load_disabled_accounts(input_file)

    assert disabled_accounts == {
        "old_admin",
        "terminated_user",
    }


def test_load_disabled_accounts_ignores_blank_lines(tmp_path):
    input_file = tmp_path / "disabled_accounts.txt"

    input_file.write_text(
        "old_admin\n"
        "\n"
        "terminated_user\n"
        "   \n",
        encoding="utf-8",
    )

    disabled_accounts = load_disabled_accounts(input_file)

    assert disabled_accounts == {
        "old_admin",
        "terminated_user",
    }


def test_load_disabled_accounts_removes_duplicates(tmp_path):
    input_file = tmp_path / "disabled_accounts.txt"

    input_file.write_text(
        "old_admin\n"
        "old_admin\n"
        "terminated_user\n",
        encoding="utf-8",
    )

    disabled_accounts = load_disabled_accounts(input_file)

    assert disabled_accounts == {
        "old_admin",
        "terminated_user",
    }


def test_load_auth_events_from_json(tmp_path):
    input_file = tmp_path / "auth.json"

    input_file.write_text(
        """
[
    {
        "timestamp": "2026-08-19T09:00:00",
        "username": "admin",
        "source_ip": "10.0.0.50",
        "result": "failure"
    },
    {
        "timestamp": "2026-08-19T09:00:10",
        "username": "admin",
        "source_ip": "10.0.0.50",
        "result": "success"
    }
]
""",
        encoding="utf-8",
    )

    events = load_auth_events(input_file)

    assert len(events) == 2
    assert events[0]["username"] == "admin"
    assert events[0]["source_ip"] == "10.0.0.50"
    assert events[0]["result"] == "failure"
    assert events[1]["result"] == "success"


def test_json_auth_log_requires_list(tmp_path):
    input_file = tmp_path / "auth.json"

    input_file.write_text(
        """
{
    "timestamp": "2026-08-19T09:00:00",
    "username": "admin",
    "source_ip": "10.0.0.50",
    "result": "failure"
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="JSON authentication log must be a list"):
        load_auth_events(input_file)


def test_json_auth_log_requires_object_events(tmp_path):
    input_file = tmp_path / "auth.json"

    input_file.write_text(
        """
[
    "not-an-event"
]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="JSON authentication event must be an object"):
        load_auth_events(input_file)


def test_json_auth_log_uses_event_validation(tmp_path):
    input_file = tmp_path / "auth.json"

    input_file.write_text(
        """
[
    {
        "timestamp": "2026-08-19T09:00:00",
        "username": "admin",
        "result": "failure"
    }
]
""",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="required field 'source_ip' must be a non-empty string",
    ):
        load_auth_events(input_file)


def test_json_auth_log_rejects_non_string_field(tmp_path):
    input_file = tmp_path / "auth.json"

    input_file.write_text(
        """
[
    {
        "timestamp": "2026-08-19T09:00:00",
        "username": 123,
        "source_ip": "10.0.0.50",
        "result": "failure"
    }
]
""",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="required field 'username' must be a non-empty string",
    ):
        load_auth_events(input_file)


def test_load_auth_events_rejects_unsupported_format(tmp_path):
    input_file = tmp_path / "auth.txt"

    input_file.write_text(
        "unsupported log format",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Unsupported authentication log format",
    ):
        load_auth_events(input_file)
