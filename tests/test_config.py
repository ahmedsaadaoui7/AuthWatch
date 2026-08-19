import pytest

from src.config import (
    DEFAULT_DETECTION_CONFIG,
    load_detection_config,
)


def test_default_detection_config():
    assert DEFAULT_DETECTION_CONFIG["AUTH-BF-001"] == {
        "threshold": 5,
        "window_seconds": 60,
    }
    assert DEFAULT_DETECTION_CONFIG["AUTH-PS-001"] == {
        "threshold": 5,
        "window_seconds": 60,
    }
    assert DEFAULT_DETECTION_CONFIG["AUTH-SF-001"] == {
        "threshold": 3,
        "window_seconds": 60,
    }
    assert DEFAULT_DETECTION_CONFIG["AUTH-MA-001"] == {
        "threshold": 5,
        "window_seconds": 300,
    }
    assert DEFAULT_DETECTION_CONFIG["AUTH-MI-001"] == {
        "threshold": 5,
        "window_seconds": 300,
    }


def test_load_detection_config(tmp_path):
    config_file = tmp_path / "config.json"

    config_file.write_text(
        """
{
    "AUTH-BF-001": {
        "threshold": 3,
        "window_seconds": 120
    }
}
""",
        encoding="utf-8",
    )

    config = load_detection_config(config_file)

    assert config == {
        "AUTH-BF-001": {
            "threshold": 3,
            "window_seconds": 120,
        }
    }


def test_load_detection_config_rejects_unknown_rule(tmp_path):
    config_file = tmp_path / "config.json"

    config_file.write_text(
        """
{
    "AUTH-UNKNOWN-001": {
        "threshold": 3
    }
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unknown rule ID"):
        load_detection_config(config_file)


def test_load_detection_config_rejects_unknown_setting(tmp_path):
    config_file = tmp_path / "config.json"

    config_file.write_text(
        """
{
    "AUTH-BF-001": {
        "threshhold": 3
    }
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unknown setting"):
        load_detection_config(config_file)


def test_load_detection_config_rejects_non_positive_value(tmp_path):
    config_file = tmp_path / "config.json"

    config_file.write_text(
        """
{
    "AUTH-BF-001": {
        "threshold": 0
    }
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="positive integer"):
        load_detection_config(config_file)


def test_load_detection_config_rejects_wrong_value_type(tmp_path):
    config_file = tmp_path / "config.json"

    config_file.write_text(
        """
{
    "AUTH-BF-001": {
        "threshold": "3"
    }
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="positive integer"):
        load_detection_config(config_file)


def test_load_detection_config_rejects_non_object_rule_config(tmp_path):
    config_file = tmp_path / "config.json"

    config_file.write_text(
        """
{
    "AUTH-BF-001": 3
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must be an object"):
        load_detection_config(config_file)


def test_load_detection_config_rejects_non_object_config(tmp_path):
    config_file = tmp_path / "config.json"

    config_file.write_text(
        """
[
    "AUTH-BF-001"
]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must be an object"):
        load_detection_config(config_file)
