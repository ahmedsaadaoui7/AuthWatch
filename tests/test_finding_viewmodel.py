from datetime import datetime, timezone
from types import SimpleNamespace

from src.viewmodels.finding_viewmodel import FindingViewModel


def _make_finding(
    *,
    finding_id=1,
    severity="high",
    status="new",
):
    return SimpleNamespace(
        id=finding_id,
        investigation_id=1,
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity=severity,
        status=status,
        first_seen=datetime(
            2026,
            8,
            8,
            9,
            0,
            tzinfo=timezone.utc,
        ),
        last_seen=datetime(
            2026,
            8,
            8,
            9,
            0,
            48,
            tzinfo=timezone.utc,
        ),
        summary="Repeated authentication failures detected.",
        details={
            "username": "admin",
            "source_ip": "10.0.0.50",
            "failed_attempts": 5,
        },
        mitre={
            "technique_id": "T1110",
            "technique_name": "Brute Force",
        },
    )


def _make_event():
    return SimpleNamespace(
        id=10,
        timestamp=datetime(
            2026,
            8,
            8,
            9,
            0,
            tzinfo=timezone.utc,
        ),
        source="auth_log",
        event_id=None,
        event_type="authentication_failure",
        host=None,
        username="admin",
        source_ip="10.0.0.50",
        destination_ip=None,
        process_name=None,
        command_line=None,
        result="failure",
        details={},
    )


def test_finding_viewmodel_loads_findings():
    high = _make_finding(
        finding_id=1,
        severity="high",
    )

    medium = _make_finding(
        finding_id=2,
        severity="medium",
    )

    class FakeService:
        def list_findings(self):
            return [high, medium]

    viewmodel = FindingViewModel(
        FakeService()
    )

    viewmodel.loadFindings()

    assert viewmodel.loading is False
    assert viewmodel.errorMessage == ""

    assert len(viewmodel.findings) == 2
    assert viewmodel.highCount == 1

    assert viewmodel.findings[0]["id"] == 1
    assert (
        viewmodel.findings[0]["rule_id"]
        == "AUTH-BF-001"
    )

    assert (
        viewmodel.findings[0]["severity"]
        == "high"
    )

    assert (
        viewmodel.findings[1]["severity"]
        == "medium"
    )


def test_finding_viewmodel_load_error():
    class FailingService:
        def list_findings(self):
            raise RuntimeError(
                "Database unavailable"
            )

    viewmodel = FindingViewModel(
        FailingService()
    )

    viewmodel.loadFindings()

    assert viewmodel.loading is False

    assert viewmodel.errorMessage == (
        "Database unavailable"
    )


def test_finding_viewmodel_selects_finding():
    finding = _make_finding()
    event = _make_event()

    related = _make_finding(
        finding_id=2,
        severity="medium",
    )

    related.rule_id = "AUTH-SF-001"
    related.title = "Successful Login After Failures"

    class FakeService:
        def get_finding(
            self,
            finding_id,
        ):
            assert finding_id == 1
            return finding

        def load_supporting_evidence(
            self,
            *,
            finding_id,
        ):
            assert finding_id == 1
            return [event]

        def load_related_findings(
            self,
            *,
            finding_id,
        ):
            assert finding_id == 1
            return [related]

    viewmodel = FindingViewModel(
        FakeService()
    )

    viewmodel.selectFinding(1)

    assert viewmodel.loading is False
    assert viewmodel.errorMessage == ""
    assert viewmodel.hasSelection is True

    selected = viewmodel.selectedFinding

    assert selected["id"] == 1

    assert (
        selected["rule_id"]
        == "AUTH-BF-001"
    )

    assert selected["severity"] == "high"

    assert len(selected["evidence"]) == 1

    assert (
        selected["evidence"][0]["username"]
        == "admin"
    )

    assert (
        selected["evidence"][0]["source_ip"]
        == "10.0.0.50"
    )

    assert (
        selected["evidence"][0]["event_type"]
        == "authentication_failure"
    )

    assert len(
        selected["related_findings"]
    ) == 1

    assert (
        selected["related_findings"][0]["rule_id"]
        == "AUTH-SF-001"
    )


def test_finding_viewmodel_selection_error():
    class FailingService:
        def get_finding(
            self,
            finding_id,
        ):
            raise ValueError(
                "Finding not found."
            )

    viewmodel = FindingViewModel(
        FailingService()
    )

    viewmodel.selectFinding(999)

    assert viewmodel.loading is False

    assert viewmodel.errorMessage == (
        "Finding not found."
    )

    assert viewmodel.hasSelection is False


def test_finding_viewmodel_clears_selection():
    finding = _make_finding()

    class FakeService:
        def get_finding(
            self,
            finding_id,
        ):
            return finding

        def load_supporting_evidence(
            self,
            *,
            finding_id,
        ):
            return []

        def load_related_findings(
            self,
            *,
            finding_id,
        ):
            return []

    viewmodel = FindingViewModel(
        FakeService()
    )

    viewmodel.selectFinding(1)

    assert viewmodel.hasSelection is True

    viewmodel.clearSelection()

    assert viewmodel.hasSelection is False
    assert viewmodel.selectedFinding == {}


def test_finding_viewmodel_marks_reviewed_and_commits():
    finding = _make_finding()

    class FakeSession:
        def __init__(self):
            self.committed = False
            self.rolled_back = False

        def commit(self):
            self.committed = True

        def rollback(self):
            self.rolled_back = True

    class FakeService:
        def __init__(self):
            self.session = FakeSession()

        def mark_reviewed(
            self,
            *,
            finding_id,
        ):
            assert finding_id == 1

            finding.status = "reviewed"

            return finding

        def list_findings(self):
            return [finding]

    service = FakeService()

    viewmodel = FindingViewModel(
        service
    )

    updates = []

    viewmodel.findingUpdated.connect(
        lambda: updates.append(True)
    )

    viewmodel.markReviewed(1)

    assert service.session.committed is True
    assert service.session.rolled_back is False

    assert viewmodel.errorMessage == ""

    assert len(viewmodel.findings) == 1

    assert (
        viewmodel.findings[0]["status"]
        == "reviewed"
    )

    assert updates == [True]


def test_finding_viewmodel_review_failure_rolls_back():
    class FakeSession:
        def __init__(self):
            self.committed = False
            self.rolled_back = False

        def commit(self):
            self.committed = True

        def rollback(self):
            self.rolled_back = True

    class FailingService:
        def __init__(self):
            self.session = FakeSession()

        def mark_reviewed(
            self,
            *,
            finding_id,
        ):
            raise RuntimeError(
                "Review failed"
            )

    service = FailingService()

    viewmodel = FindingViewModel(
        service
    )

    viewmodel.markReviewed(1)

    assert service.session.committed is False
    assert service.session.rolled_back is True

    assert viewmodel.errorMessage == (
        "Review failed"
    )
