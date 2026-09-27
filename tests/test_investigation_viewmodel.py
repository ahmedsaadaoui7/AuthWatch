from datetime import datetime, timezone
from types import SimpleNamespace

from src.viewmodels.investigation_viewmodel import (
    InvestigationViewModel,
)


def _make_investigation():
    completed_at = datetime(
        2026,
        9,
        27,
        12,
        0,
        tzinfo=timezone.utc,
    )

    return SimpleNamespace(
        id=1,
        public_id="INV-2026-0001",
        name="Brute Force GUI Test",
        status="complete",
        created_at=completed_at,
        completed_at=completed_at,
        event_count=5,
        finding_count=1,
        high_severity_count=1,
    )


def test_investigation_viewmodel_loads_investigations():
    investigation = _make_investigation()

    class FakeService:
        def list_investigations(self):
            return [investigation]

    viewmodel = InvestigationViewModel(
        FakeService()
    )

    viewmodel.loadInvestigations()

    assert viewmodel.loading is False
    assert viewmodel.errorMessage == ""

    assert len(viewmodel.investigations) == 1

    item = viewmodel.investigations[0]

    assert item["id"] == 1
    assert item["public_id"] == "INV-2026-0001"
    assert item["name"] == "Brute Force GUI Test"
    assert item["status"] == "complete"
    assert item["event_count"] == 5
    assert item["finding_count"] == 1
    assert item["high_severity_count"] == 1


def test_investigation_viewmodel_load_error():
    class FailingService:
        def list_investigations(self):
            raise RuntimeError(
                "Database unavailable"
            )

    viewmodel = InvestigationViewModel(
        FailingService()
    )

    viewmodel.loadInvestigations()

    assert viewmodel.loading is False

    assert viewmodel.errorMessage == (
        "Database unavailable"
    )


def test_investigation_viewmodel_selects_investigation():
    investigation = _make_investigation()

    event = SimpleNamespace(
        id=10,
        timestamp=datetime(
            2026,
            9,
            27,
            11,
            30,
            tzinfo=timezone.utc,
        ),
        source="auth_log",
        event_id=None,
        event_type="authentication_failure",
        host=None,
        username="admin",
        session_id=None,
        source_ip="10.0.0.50",
        destination_ip=None,
        process_name=None,
        process_id=None,
        process_guid=None,
        parent_process_name=None,
        command_line=None,
        result="failure",
        details={},
    )

    finding = SimpleNamespace(
        id=20,
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        first_seen=datetime(
            2026,
            9,
            27,
            11,
            30,
            tzinfo=timezone.utc,
        ),
        last_seen=datetime(
            2026,
            9,
            27,
            11,
            34,
            tzinfo=timezone.utc,
        ),
        summary="Potential Brute-Force Activity",
        details={
            "username": "admin",
        },
        mitre=None,
    )

    case = SimpleNamespace(
        id=30,
        public_id="AW-0030",
        title="Brute Force Review",
        priority="high",
        status="open",
        resolution=None,
        created_at=datetime(
            2026,
            9,
            27,
            12,
            0,
            tzinfo=timezone.utc,
        ),
        closed_at=None,
    )

    class FakeService:
        def get_investigation(
            self,
            investigation_id,
        ):
            assert investigation_id == 1
            return investigation

        def load_timeline(
            self,
            *,
            investigation_id,
        ):
            assert investigation_id == 1
            return [event]

        def load_affected_entities(
            self,
            *,
            investigation_id,
        ):
            assert investigation_id == 1

            return {
                "users": ["admin"],
                "hosts": [],
                "source_ips": ["10.0.0.50"],
            }

        def load_findings(
            self,
            *,
            investigation_id,
        ):
            assert investigation_id == 1
            return [finding]

        def load_related_cases(
            self,
            *,
            investigation_id,
        ):
            assert investigation_id == 1
            return [case]

    viewmodel = InvestigationViewModel(
        FakeService()
    )

    viewmodel.selectInvestigation(1)

    assert viewmodel.loading is False
    assert viewmodel.errorMessage == ""
    assert viewmodel.hasSelection is True

    selected = viewmodel.selectedInvestigation

    assert selected["id"] == 1
    assert selected["public_id"] == (
        "INV-2026-0001"
    )

    assert selected["event_count"] == 5
    assert selected["finding_count"] == 1
    assert selected["high_severity_count"] == 1

    assert len(selected["timeline"]) == 1

    assert (
        selected["timeline"][0]["username"]
        == "admin"
    )

    assert (
        selected["timeline"][0]["source_ip"]
        == "10.0.0.50"
    )

    assert selected["affected_entities"] == {
        "users": ["admin"],
        "hosts": [],
        "source_ips": ["10.0.0.50"],
    }

    assert len(selected["findings"]) == 1

    assert (
        selected["findings"][0]["rule_id"]
        == "AUTH-BF-001"
    )

    assert (
        selected["findings"][0]["severity"]
        == "high"
    )

    assert len(
        selected["related_cases"]
    ) == 1

    assert (
        selected["related_cases"][0]["public_id"]
        == "AW-0030"
    )


def test_investigation_viewmodel_selection_error():
    class FailingService:
        def get_investigation(
            self,
            investigation_id,
        ):
            raise ValueError(
                "Investigation not found."
            )

    viewmodel = InvestigationViewModel(
        FailingService()
    )

    viewmodel.selectInvestigation(99)

    assert viewmodel.loading is False

    assert viewmodel.errorMessage == (
        "Investigation not found."
    )

    assert viewmodel.hasSelection is False


def test_investigation_viewmodel_clears_selection():
    investigation = _make_investigation()

    class FakeService:
        def get_investigation(
            self,
            investigation_id,
        ):
            return investigation

        def load_timeline(
            self,
            *,
            investigation_id,
        ):
            return []

        def load_affected_entities(
            self,
            *,
            investigation_id,
        ):
            return {
                "users": [],
                "hosts": [],
                "source_ips": [],
            }

        def load_findings(
            self,
            *,
            investigation_id,
        ):
            return []

        def load_related_cases(
            self,
            *,
            investigation_id,
        ):
            return []

    viewmodel = InvestigationViewModel(
        FakeService()
    )

    viewmodel.selectInvestigation(1)

    assert viewmodel.hasSelection is True

    viewmodel.clearSelection()

    assert viewmodel.hasSelection is False
    assert viewmodel.selectedInvestigation == {}
