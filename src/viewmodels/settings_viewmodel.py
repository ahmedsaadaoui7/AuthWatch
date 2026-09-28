from __future__ import annotations

from PySide6.QtCore import (
    QObject,
    Property,
    Signal,
    Slot,
)

from src.services.settings_service import SettingsService


class SettingsViewModel(QObject):
    settingsChanged = Signal()
    loadingChanged = Signal()
    errorChanged = Signal()
    settingSaved = Signal(str)

    def __init__(
        self,
        service: SettingsService,
        parent: QObject | None = None,
    ):
        super().__init__(parent)

        self._service = service
        self._settings = service.default_settings()
        self._loading = False
        self._error_message = ""

    @Property(
        "QVariantMap",
        notify=settingsChanged,
    )
    def settings(self) -> dict:
        return self._settings

    @Property(bool, notify=loadingChanged)
    def loading(self) -> bool:
        return self._loading

    @Property(str, notify=errorChanged)
    def errorMessage(self) -> str:
        return self._error_message

    def _set_error(self, message: str) -> None:
        if self._error_message == message:
            return

        self._error_message = message
        self.errorChanged.emit()

    @Slot()
    def loadSettings(self) -> None:
        if self._loading:
            return

        self._loading = True
        self.loadingChanged.emit()
        self._set_error("")

        try:
            self._settings = (
                self._service.load_settings()
            )
            self.settingsChanged.emit()

        except Exception as error:
            self._set_error(str(error))

        finally:
            self._loading = False
            self.loadingChanged.emit()

    @Slot(str, "QVariant")
    def setSetting(
        self,
        key: str,
        value: object,
    ) -> None:
        self._set_error("")

        try:
            self._service.set_setting(
                key=key,
                value=value,
            )

            self._service.session.commit()

            self._settings = (
                self._service.load_settings()
            )

            self.settingsChanged.emit()
            self.settingSaved.emit(key)

        except Exception as error:
            self._service.session.rollback()
            self._set_error(str(error))
