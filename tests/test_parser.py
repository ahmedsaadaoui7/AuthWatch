import pytest

from src.parser import load_auth_events


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
