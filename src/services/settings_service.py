from __future__ import annotations

from sqlalchemy.orm import Session

from src.models.application_setting import ApplicationSetting
from src.repositories.application_setting_repository import (
    ApplicationSettingRepository,
)


class SettingsService:
    DEFAULTS = {
        "default_severity": "All severities",
        "open_completed_investigation": True,
        "high_severity_visual_alerts": True,
    }

    _CHOICES = {
        "default_severity": {
            "All severities",
            "High",
            "Medium",
            "Low",
        },
    }

    _BOOLEAN_KEYS = {
        "open_completed_investigation",
        "high_severity_visual_alerts",
    }

    def __init__(self, session: Session):
        self.session = session
        self.repository = ApplicationSettingRepository(
            session
        )

    @classmethod
    def default_settings(cls) -> dict:
        return dict(cls.DEFAULTS)

    def load_settings(self) -> dict:
        settings = self.default_settings()

        for stored in self.repository.list_all():
            if stored.key not in self.DEFAULTS:
                continue

            try:
                self._validate(
                    key=stored.key,
                    value=stored.value,
                )
            except ValueError:
                continue

            settings[stored.key] = stored.value

        return settings

    def set_setting(
        self,
        *,
        key: str,
        value: object,
    ) -> ApplicationSetting:
        self._validate(
            key=key,
            value=value,
        )

        return self.repository.set_value(
            key=key,
            value=value,
        )

    def _validate(
        self,
        *,
        key: str,
        value: object,
    ) -> None:
        if key not in self.DEFAULTS:
            raise ValueError(
                "Unknown application setting."
            )

        if key in self._BOOLEAN_KEYS:
            if type(value) is not bool:
                raise ValueError(
                    "Setting requires a boolean value."
                )
            return

        allowed_values = self._CHOICES.get(key)

        if (
            allowed_values is not None
            and value not in allowed_values
        ):
            raise ValueError(
                "Invalid application setting value."
            )
