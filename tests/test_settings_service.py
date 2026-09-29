import pytest

from src.database import (
    create_database_engine,
    create_session_factory,
)
from src.models.application_setting import ApplicationSetting
from src.models.base import Base
from src.services.settings_service import SettingsService


def _build_service(tmp_path):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )
    Base.metadata.create_all(engine)
    SessionLocal = create_session_factory(engine)
    session = SessionLocal()

    return session, SettingsService(session)


def test_settings_service_returns_defaults(tmp_path):
    session, service = _build_service(tmp_path)

    try:
        settings = service.load_settings()

        assert settings == {
            "default_severity": "All severities",
            "open_completed_investigation": True,
            "high_severity_visual_alerts": True,
        }
    finally:
        session.close()


def test_settings_service_overlays_persisted_values(tmp_path):
    session, service = _build_service(tmp_path)

    try:
        service.set_setting(
            key="default_severity",
            value="High",
        )
        service.set_setting(
            key="high_severity_visual_alerts",
            value=False,
        )
        session.commit()

        settings = service.load_settings()

        assert settings["default_severity"] == "High"
        assert settings["high_severity_visual_alerts"] is False
        assert settings["open_completed_investigation"] is True
    finally:
        session.close()


def test_settings_service_rejects_unknown_key(tmp_path):
    session, service = _build_service(tmp_path)

    try:
        with pytest.raises(
            ValueError,
            match="Unknown application setting",
        ):
            service.set_setting(
                key="unsupported_setting",
                value=True,
            )
    finally:
        session.close()


def test_settings_service_validates_choice_value(tmp_path):
    session, service = _build_service(tmp_path)

    try:
        with pytest.raises(
            ValueError,
            match="Invalid application setting value",
        ):
            service.set_setting(
                key="default_severity",
                value="Critical",
            )
    finally:
        session.close()


def test_settings_service_ignores_invalid_stored_value(tmp_path):
    session, service = _build_service(tmp_path)

    try:
        session.add(
            ApplicationSetting(
                key="default_severity",
                value="Critical",
            )
        )
        session.commit()

        settings = service.load_settings()

        assert (
            settings["default_severity"]
            == "All severities"
        )
    finally:
        session.close()
