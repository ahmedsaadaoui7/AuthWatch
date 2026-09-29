from datetime import datetime, timezone
from types import SimpleNamespace

import pytest
from PySide6.QtCore import QUrl

from src.viewmodels.analysis_viewmodel import (
    AnalysisViewModel,
    _AnalysisWorker,
)


def test_analysis_viewmodel_normalizes_qml_payload(
    tmp_path,
):
    windows_file = tmp_path / "security.evtx"

    windows_url = QUrl.fromLocalFile(
        str(windows_file)
    ).toString()

    payload = {
        "investigation_name": "Finance Review",
        "windows_security": windows_url,
        "sysmon": "",
        "linux_auth": "",
        "authwatch_log": "",
        "linux_year": "2026",
        "linux_utc_offset": "+01:00",
    }

    arguments = (
        AnalysisViewModel._normalize_payload(
            payload
        )
    )

    assert arguments == {
        "name": "Finance Review",
        "log_file": None,
        "windows_security": str(windows_file),
        "sysmon": None,
        "linux_auth": None,
        "linux_year": 2026,
        "linux_utc_offset": "+01:00",
    }


def test_analysis_viewmodel_maps_authwatch_log_to_log_file(
    tmp_path,
):
    auth_file = tmp_path / "auth.csv"

    payload = {
        "investigation_name": "Authentication Review",
        "authwatch_log": str(auth_file),
    }

    arguments = (
        AnalysisViewModel._normalize_payload(
            payload
        )
    )

    assert arguments["name"] == (
        "Authentication Review"
    )

    assert arguments["log_file"] == str(
        auth_file
    )

    assert arguments["windows_security"] is None
    assert arguments["sysmon"] is None
    assert arguments["linux_auth"] is None


def test_analysis_viewmodel_requires_investigation_name():
    payload = {
        "investigation_name": "",
        "sysmon": "/tmp/sysmon.evtx",
    }

    with pytest.raises(
        ValueError,
        match="Investigation name is required",
    ):
        AnalysisViewModel._normalize_payload(
            payload
        )


def test_analysis_viewmodel_requires_telemetry():
    payload = {
        "investigation_name": "Empty Review",
        "windows_security": "",
        "sysmon": "",
        "linux_auth": "",
        "authwatch_log": "",
    }

    with pytest.raises(
        ValueError,
        match="At least one telemetry input is required",
    ):
        AnalysisViewModel._normalize_payload(
            payload
        )


def test_analysis_viewmodel_rejects_invalid_linux_year():
    payload = {
        "investigation_name": "Linux Review",
        "linux_auth": "/tmp/auth.log",
        "linux_year": "not-a-year",
    }

    with pytest.raises(
        ValueError,
        match="Linux year must be a valid number",
    ):
        AnalysisViewModel._normalize_payload(
            payload
        )


def test_analysis_viewmodel_exposes_validation_error():
    viewmodel = AnalysisViewModel(
        session_factory=lambda: None,
    )

    viewmodel.startAnalysis(
        {
            "investigation_name": "No Sources",
        }
    )

    assert viewmodel.running is False

    assert viewmodel.errorMessage == (
        "At least one telemetry input is required."
    )

    assert viewmodel.statusMessage == (
        "Analysis could not start."
    )


def test_analysis_worker_commits_successful_analysis():
    class FakeSession:
        def __init__(self):
            self.committed = False
            self.rolled_back = False
            self.closed = False

        def commit(self):
            self.committed = True

        def rollback(self):
            self.rolled_back = True

        def close(self):
            self.closed = True

    session = FakeSession()

    received_arguments = {}

    completed_at = datetime(
        2026,
        9,
        26,
        12,
        0,
        tzinfo=timezone.utc,
    )

    investigation = SimpleNamespace(
        id=7,
        public_id="INV-2026-0007",
        name="Worker Test",
        status="complete",
        event_count=125,
        finding_count=8,
        high_severity_count=2,
        created_at=completed_at,
        completed_at=completed_at,
    )

    class FakeAnalysisService:
        def __init__(self, received_session):
            assert received_session is session

        def analyze_and_store(self, **arguments):
            received_arguments.update(
                arguments
            )

            return investigation

    worker = _AnalysisWorker(
        session_factory=lambda: session,
        analysis_arguments={
            "name": "Worker Test",
            "sysmon": "/tmp/sysmon.evtx",
        },
        service_factory=FakeAnalysisService,
    )

    successes = []
    failures = []
    finished = []

    worker.succeeded.connect(
        successes.append
    )

    worker.failed.connect(
        failures.append
    )

    worker.finished.connect(
        lambda: finished.append(True)
    )

    worker.run()

    assert received_arguments == {
        "name": "Worker Test",
        "sysmon": "/tmp/sysmon.evtx",
    }

    assert session.committed is True
    assert session.rolled_back is False
    assert session.closed is True

    assert failures == []
    assert finished == [True]

    assert len(successes) == 1

    serialized = successes[0]

    assert serialized["id"] == 7
    assert serialized["public_id"] == (
        "INV-2026-0007"
    )
    assert serialized["name"] == "Worker Test"
    assert serialized["status"] == "complete"
    assert serialized["event_count"] == 125
    assert serialized["finding_count"] == 8
    assert serialized["high_severity_count"] == 2

    assert serialized["created_at"] == (
        completed_at.isoformat()
    )

    assert serialized["completed_at"] == (
        completed_at.isoformat()
    )


def test_analysis_worker_rolls_back_failed_analysis():
    class FakeSession:
        def __init__(self):
            self.committed = False
            self.rolled_back = False
            self.closed = False

        def commit(self):
            self.committed = True

        def rollback(self):
            self.rolled_back = True

        def close(self):
            self.closed = True

    session = FakeSession()

    class FailingAnalysisService:
        def __init__(self, received_session):
            assert received_session is session

        def analyze_and_store(self, **arguments):
            raise RuntimeError(
                "V3 analysis failed"
            )

    worker = _AnalysisWorker(
        session_factory=lambda: session,
        analysis_arguments={
            "name": "Failure Test",
            "sysmon": "/tmp/sysmon.evtx",
        },
        service_factory=FailingAnalysisService,
    )

    successes = []
    failures = []
    finished = []

    worker.succeeded.connect(
        successes.append
    )

    worker.failed.connect(
        failures.append
    )

    worker.finished.connect(
        lambda: finished.append(True)
    )

    worker.run()

    assert successes == []

    assert failures == [
        "V3 analysis failed"
    ]

    assert finished == [True]

    assert session.committed is False
    assert session.rolled_back is True
    assert session.closed is True



def test_analysis_viewmodel_shutdown_waits_for_running_thread():
    class FakeThread:
        def __init__(self):
            self.quit_called = False
            self.wait_called = False

        def isRunning(self):
            return True

        def quit(self):
            self.quit_called = True

        def wait(self):
            self.wait_called = True
            return True

    viewmodel = AnalysisViewModel(
        session_factory=lambda: None,
    )

    thread = FakeThread()

    viewmodel._thread = thread
    viewmodel._worker = object()

    viewmodel.shutdown()

    assert thread.quit_called is True
    assert thread.wait_called is True
    assert viewmodel._thread is None
    assert viewmodel._worker is None
