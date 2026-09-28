from datetime import datetime, timezone
from types import SimpleNamespace

from src.viewmodels.case_viewmodel import CaseViewModel


def _make_case(
    *,
    case_id=1,
    public_id="AW-0001",
    priority="high",
    status="open",
):
    return SimpleNamespace(
        id=case_id,
        public_id=public_id,
        title="Potential Brute-Force Activity",
        priority=priority,
        status=status,
        resolution=(
            "true_positive"
            if status == "closed"
            else None
        ),
        closing_note=(
            "Confirmed malicious activity."
            if status == "closed"
            else None
        ),
        created_at=datetime(
            2026,
            9,
            28,
            20,
            0,
            tzinfo=timezone.utc,
        ),
        closed_at=(
            datetime(
                2026,
                9,
                28,
                21,
                0,
                tzinfo=timezone.utc,
            )
            if status == "closed"
            else None
        ),
    )


def _make_finding():
    return SimpleNamespace(
        id=10,
        investigation_id=1,
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="escalated",
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
    )


def _make_note():
    return SimpleNamespace(
        id=20,
        content="Reviewed source IP and authentication timeline.",
        created_at=datetime(
            2026,
            9,
            28,
            20,
            10,
            tzinfo=timezone.utc,
        ),
    )


def _make_activity():
    return SimpleNamespace(
        id=30,
        activity_type="case_created",
        description="Case AW-0001 created.",
        details={
            "priority": "high",
            "status": "open",
        },
        created_at=datetime(
            2026,
            9,
            28,
            20,
            0,
            tzinfo=timezone.utc,
        ),
    )


class _FakeSession:
    def __init__(self):
        self.commits = 0
        self.rollbacks = 0

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


class _MutationService:
    def __init__(self):
        self.session = _FakeSession()
        self.case = _make_case()
        self.calls = []

    def list_cases(self):
        return [self.case]

    def get_case(self, case_id):
        assert case_id == self.case.id
        return self.case

    def load_linked_findings(self, *, case_id):
        return [_make_finding()]

    def load_notes(self, *, case_id):
        return [_make_note()]

    def load_history(self, *, case_id):
        return [_make_activity()]

    def add_note(self, *, case_id, content):
        self.calls.append(("note", case_id, content))

    def change_priority(self, *, case_id, priority):
        self.calls.append(("priority", case_id, priority))
        self.case.priority = priority
        return self.case

    def change_status(self, *, case_id, status):
        self.calls.append(("status", case_id, status))
        self.case.status = status
        return self.case

    def close_case(
        self,
        *,
        case_id,
        resolution,
        closing_note,
    ):
        self.calls.append(
            (
                "close",
                case_id,
                resolution,
                closing_note,
            )
        )
        self.case.status = "closed"
        self.case.resolution = resolution
        self.case.closing_note = closing_note
        self.case.closed_at = datetime.now(
            timezone.utc
        )
        return self.case

    def reopen_case(self, *, case_id):
        self.calls.append(("reopen", case_id))
        self.case.status = "open"
        self.case.resolution = None
        self.case.closing_note = None
        self.case.closed_at = None
        return self.case


def test_case_viewmodel_loads_cases_and_metrics():
    high = _make_case(
        case_id=1,
        public_id="AW-0001",
        priority="high",
        status="open",
    )

    medium = _make_case(
        case_id=2,
        public_id="AW-0002",
        priority="medium",
        status="investigating",
    )

    closed = _make_case(
        case_id=3,
        public_id="AW-0003",
        priority="high",
        status="closed",
    )

    class FakeService:
        def list_cases(self):
            return [high, medium, closed]

    viewmodel = CaseViewModel(
        FakeService()
    )

    viewmodel.loadCases()

    assert viewmodel.loading is False
    assert viewmodel.errorMessage == ""
    assert len(viewmodel.cases) == 3
    assert viewmodel.activeCount == 2
    assert viewmodel.highPriorityCount == 1
    assert viewmodel.closedCount == 1
    assert viewmodel.cases[0]["public_id"] == "AW-0001"


def test_case_viewmodel_load_error():
    class FailingService:
        def list_cases(self):
            raise RuntimeError("Database unavailable")

    viewmodel = CaseViewModel(
        FailingService()
    )

    viewmodel.loadCases()

    assert viewmodel.loading is False
    assert viewmodel.errorMessage == "Database unavailable"


def test_case_viewmodel_selects_full_case_workspace():
    case = _make_case()
    finding = _make_finding()
    note = _make_note()
    activity = _make_activity()

    class FakeService:
        def get_case(self, case_id):
            assert case_id == 1
            return case

        def load_linked_findings(self, *, case_id):
            return [finding]

        def load_notes(self, *, case_id):
            return [note]

        def load_history(self, *, case_id):
            return [activity]

    viewmodel = CaseViewModel(
        FakeService()
    )

    viewmodel.selectCase(1)

    selected = viewmodel.selectedCase

    assert viewmodel.hasSelection is True
    assert selected["public_id"] == "AW-0001"
    assert selected["priority"] == "high"
    assert selected["findings"][0]["rule_id"] == "AUTH-BF-001"
    assert selected["notes"][0]["content"].startswith("Reviewed")
    assert selected["history"][0]["activity_type"] == "case_created"


def test_case_viewmodel_creates_case_from_finding_and_commits():
    case = _make_case(
        case_id=7,
        public_id="AW-0007",
    )

    class FakeService:
        def __init__(self):
            self.session = _FakeSession()

        def create_case_from_finding(
            self,
            *,
            finding_id,
            title,
            priority,
        ):
            assert finding_id == 10
            assert title == "Potential Brute-Force Activity"
            assert priority == "high"
            return case

    service = FakeService()
    viewmodel = CaseViewModel(service)

    created = []
    viewmodel.caseCreated.connect(
        lambda case_id: created.append(case_id)
    )

    viewmodel.createFromFinding(
        10,
        "Potential Brute-Force Activity",
        "high",
    )

    assert service.session.commits == 1
    assert service.session.rollbacks == 0
    assert viewmodel.errorMessage == ""
    assert created == [7]


def test_case_viewmodel_create_failure_rolls_back():
    class FailingService:
        def __init__(self):
            self.session = _FakeSession()

        def create_case_from_finding(self, **kwargs):
            raise RuntimeError("Case creation failed")

    service = FailingService()
    viewmodel = CaseViewModel(service)

    viewmodel.createFromFinding(
        10,
        "Potential Brute-Force Activity",
        "high",
    )

    assert service.session.commits == 0
    assert service.session.rollbacks == 1
    assert viewmodel.errorMessage == "Case creation failed"


def test_case_viewmodel_adds_note_and_refreshes():
    service = _MutationService()
    viewmodel = CaseViewModel(service)

    messages = []
    viewmodel.caseActionCompleted.connect(
        lambda message: messages.append(message)
    )

    viewmodel.addNote(
        1,
        "Investigated authentication timeline.",
    )

    assert service.session.commits == 1
    assert service.calls == [
        (
            "note",
            1,
            "Investigated authentication timeline.",
        )
    ]
    assert viewmodel.hasSelection is True
    assert messages == ["Analyst note added."]


def test_case_viewmodel_changes_priority_and_status():
    service = _MutationService()
    viewmodel = CaseViewModel(service)

    viewmodel.changePriority(1, "medium")
    viewmodel.changeStatus(1, "investigating")

    assert service.session.commits == 2
    assert ("priority", 1, "medium") in service.calls
    assert ("status", 1, "investigating") in service.calls
    assert viewmodel.selectedCase["priority"] == "medium"
    assert viewmodel.selectedCase["status"] == "investigating"


def test_case_viewmodel_closes_and_reopens_case():
    service = _MutationService()
    viewmodel = CaseViewModel(service)

    messages = []
    viewmodel.caseActionCompleted.connect(
        lambda message: messages.append(message)
    )

    viewmodel.closeCase(
        1,
        "true_positive",
        "Confirmed malicious activity.",
    )

    assert viewmodel.selectedCase["status"] == "closed"
    assert (
        viewmodel.selectedCase["resolution"]
        == "true_positive"
    )

    viewmodel.reopenCase(1)

    assert viewmodel.selectedCase["status"] == "open"
    assert viewmodel.selectedCase["resolution"] is None
    assert service.session.commits == 2
    assert messages == [
        "Case closed.",
        "Case reopened.",
    ]
