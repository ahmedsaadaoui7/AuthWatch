import json


DEFAULT_DETECTION_CONFIG = {
    "AUTH-BF-001": {
        "threshold": 5,
        "window_seconds": 60,
    },
    "AUTH-PS-001": {
        "threshold": 5,
        "window_seconds": 60,
    },
    "AUTH-SF-001": {
        "threshold": 3,
        "window_seconds": 60,
    },
    "AUTH-MA-001": {
        "threshold": 5,
        "window_seconds": 300,
    },
    "AUTH-MI-001": {
        "threshold": 5,
        "window_seconds": 300,
    },
}


DEFAULT_CORRELATION_CONFIG = {
    "CORR-PROC-NET-001": {
        "window_seconds": 300,
    },
    "CORR-PROC-DNS-001": {
        "window_seconds": 300,
    },
    "CORR-AUTH-EXEC-001": {
        "window_seconds": 300,
    },
    "CORR-PRIV-EXEC-001": {
        "window_seconds": 300,
    },
    "CORR-SSH-SUDO-001": {
        "window_seconds": 300,
    },
}


def load_detection_config(file_path):
    with open(file_path, encoding="utf-8") as config_file:
        config = json.load(config_file)

    if not isinstance(config, dict):
        raise ValueError(
            "Detection configuration must be an object"
        )

    for rule_id, rule_config in config.items():
        if rule_id not in DEFAULT_DETECTION_CONFIG:
            raise ValueError(f"Unknown rule ID: {rule_id}")

        if not isinstance(rule_config, dict):
            raise ValueError(
                f"Configuration for {rule_id} must be an object"
            )

        valid_settings = DEFAULT_DETECTION_CONFIG[rule_id]

        for setting in rule_config:
            if setting not in valid_settings:
                raise ValueError(
                    f"Unknown setting for {rule_id}: {setting}"
                )

            value = rule_config[setting]

            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
            ):
                raise ValueError(
                    f"{setting} for {rule_id} must be a positive integer"
                )

    return config


def load_correlation_config(file_path):
    with open(file_path, encoding="utf-8") as config_file:
        config = json.load(config_file)

    if not isinstance(config, dict):
        raise ValueError(
            "Correlation configuration must be an object"
        )

    for rule_id, rule_config in config.items():
        if rule_id not in DEFAULT_CORRELATION_CONFIG:
            raise ValueError(
                f"Unknown correlation rule ID: {rule_id}"
            )

        if not isinstance(rule_config, dict):
            raise ValueError(
                f"Configuration for {rule_id} must be an object"
            )

        valid_settings = DEFAULT_CORRELATION_CONFIG[rule_id]

        for setting in rule_config:
            if setting not in valid_settings:
                raise ValueError(
                    f"Unknown setting for {rule_id}: {setting}"
                )

            value = rule_config[setting]

            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value <= 0
            ):
                raise ValueError(
                    f"{setting} for {rule_id} must be a positive integer"
                )

    return config
