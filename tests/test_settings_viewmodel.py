from src.viewmodels.settings_viewmodel import SettingsViewModel


class _FakeSession:
    def __init__(self):
        self.commits = 0
        self.rollbacks = 0

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


class _SettingsService:
    def __init__(self):
        self.session = _FakeSession()
        self.values = {
            "default_severity": "All severities",
            "open_completed_investigation": True,
            "high_severity_visual_alerts": True,
        }

    def default_settings(self):
        return dict(self.values)

    def load_settings(self):
        return dict(self.values)

    def set_setting(self, *, key, value):
        self.values[key] = value


def test_settings_viewmodel_loads_settings():
    service = _SettingsService()
    service.values["default_severity"] = "Medium"

    viewmodel = SettingsViewModel(service)
    viewmodel.loadSettings()

    assert viewmodel.loading is False
    assert viewmodel.errorMessage == ""
    assert viewmodel.settings["default_severity"] == "Medium"


def test_settings_viewmodel_saves_and_commits_setting():
    service = _SettingsService()
    viewmodel = SettingsViewModel(service)

    saved = []
    viewmodel.settingSaved.connect(
        lambda key: saved.append(key)
    )

    viewmodel.setSetting(
        "high_severity_visual_alerts",
        False,
    )

    assert service.session.commits == 1
    assert service.session.rollbacks == 0
    assert (
        viewmodel.settings[
            "high_severity_visual_alerts"
        ]
        is False
    )
    assert saved == [
        "high_severity_visual_alerts"
    ]


def test_settings_viewmodel_rolls_back_on_failure():
    class FailingService(_SettingsService):
        def set_setting(self, *, key, value):
            raise RuntimeError(
                "Unable to save setting"
            )

    service = FailingService()
    viewmodel = SettingsViewModel(service)

    viewmodel.setSetting(
        "default_severity",
        "High",
    )

    assert service.session.commits == 0
    assert service.session.rollbacks == 1
    assert (
        viewmodel.errorMessage
        == "Unable to save setting"
    )
