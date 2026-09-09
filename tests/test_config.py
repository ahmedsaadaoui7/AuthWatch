import pytest

from src.config import (
    DEFAULT_DETECTION_CONFIG,
    DEFAULT_CORRELATION_CONFIG,
    load_detection_config,
    load_correlation_config,
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


def test_default_correlation_config():
    assert DEFAULT_CORRELATION_CONFIG["CORR-PROC-NET-001"] == {
        "window_seconds": 300,
    }
    assert DEFAULT_CORRELATION_CONFIG["CORR-PROC-DNS-001"] == {
        "window_seconds": 300,
    }
    assert DEFAULT_CORRELATION_CONFIG["CORR-AUTH-EXEC-001"] == {
        "window_seconds": 300,
    }
    assert DEFAULT_CORRELATION_CONFIG["CORR-PRIV-EXEC-001"] == {
        "window_seconds": 300,
    }
    assert DEFAULT_CORRELATION_CONFIG["CORR-SSH-SUDO-001"] == {
        "window_seconds": 300,
    }


def test_load_correlation_config(tmp_path):
    config_file = tmp_path / "correlation_config.json"

    config_file.write_text(
        """
{
    "CORR-SSH-SUDO-001": {
        "window_seconds": 600
    }
}
""",
        encoding="utf-8",
    )

    config = load_correlation_config(config_file)

    assert config == {
        "CORR-SSH-SUDO-001": {
            "window_seconds": 600,
        }
    }


def test_load_correlation_config_rejects_unknown_rule(tmp_path):
    config_file = tmp_path / "correlation_config.json"

    config_file.write_text(
        """
{
    "CORR-UNKNOWN-001": {
        "window_seconds": 300
    }
}
""",
        encoding="utf-8",
    )

    with pytest.raises(
        ValueError,
        match="Unknown correlation rule ID",
    ):
        load_correlation_config(config_file)


def test_load_correlation_config_rejects_unknown_setting(tmp_path):
    config_file = tmp_path / "correlation_config.json"

    config_file.write_text(
        """
{
    "CORR-PROC-NET-001": {
        "window": 300
    }
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unknown setting"):
        load_correlation_config(config_file)


def test_load_correlation_config_rejects_non_positive_value(tmp_path):
    config_file = tmp_path / "correlation_config.json"

    config_file.write_text(
        """
{
    "CORR-PROC-NET-001": {
        "window_seconds": 0
    }
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="positive integer"):
        load_correlation_config(config_file)


def test_load_correlation_config_rejects_wrong_value_type(tmp_path):
    config_file = tmp_path / "correlation_config.json"

    config_file.write_text(
        """
{
    "CORR-PROC-NET-001": {
        "window_seconds": "300"
    }
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="positive integer"):
        load_correlation_config(config_file)


def test_load_correlation_config_rejects_non_object_rule_config(tmp_path):
    config_file = tmp_path / "correlation_config.json"

    config_file.write_text(
        """
{
    "CORR-PROC-NET-001": 300
}
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must be an object"):
        load_correlation_config(config_file)


def test_load_correlation_config_rejects_non_object_config(tmp_path):
    config_file = tmp_path / "correlation_config.json"

    config_file.write_text(
        """
[
    "CORR-PROC-NET-001"
]
""",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must be an object"):
        load_correlation_config(config_file)
