from pathlib import Path

from PySide6.QtCore import QStandardPaths


APP_DIRECTORY_NAME = "AuthWatch"


def _get_base_data_location() -> Path:
    location = QStandardPaths.writableLocation(
        QStandardPaths.StandardLocation.GenericDataLocation
    )

    if not location:
        raise RuntimeError(
            "Unable to determine the application-data directory."
        )

    return Path(location)


def get_app_data_directory() -> Path:
    app_data_directory = (
        _get_base_data_location()
        / APP_DIRECTORY_NAME
    )

    app_data_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return app_data_directory


def get_database_path() -> Path:
    return (
        get_app_data_directory()
        / "authwatch.db"
    )


def get_log_directory() -> Path:
    log_directory = (
        get_app_data_directory()
        / "logs"
    )

    log_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return log_directory
