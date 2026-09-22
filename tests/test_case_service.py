import pytest

from src.database import (
    create_database_engine,
    create_session_factory,
)

from sqlalchemy import select
from src.models.base import Base

from src.models.application_setting import ApplicationSetting
from src.models.case import Case
from src.models.case_activity import CaseActivity
from src.models.case_finding import CaseFinding
from src.models.case_note import CaseNote
from src.models.event import Event
from src.models.finding import Finding
from src.models.finding_event import FindingEvent
from src.models.investigation import Investigation
from src.models.telemetry_source import TelemetrySource

from src.services.case_service import CaseService


def test_case_service_creates_case_with_public_id_and_activity(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        service = CaseService(session)

        case = service.create_case(
            title="Suspicious Admin Activity",
            priority="high",
        )

        session.commit()

        case_id = case.id

    with SessionLocal() as session:
        stored = session.get(Case, case_id)

        assert stored is not None
        assert stored.public_id == "AW-0001"
        assert stored.title == "Suspicious Admin Activity"
        assert stored.priority == "high"
        assert stored.status == "open"

        assert len(stored.activities) == 1

        assert (
            stored.activities[0].activity_type
            == "case_created"
        )


def test_case_service_create_case_does_not_auto_commit(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        service = CaseService(session)

        service.create_case(
            title="Rollback Case",
            priority="high",
        )

        session.rollback()

    with SessionLocal() as session:
        stored = session.get(Case, 1)

        assert stored is None


def test_case_service_links_finding_and_marks_it_escalated(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0200",
        name="Authentication Investigation",
        status="complete",
    )

    finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    investigation.findings.append(finding)

    with SessionLocal() as session:
        session.add(investigation)
        session.flush()

        finding_id = finding.id

        service = CaseService(session)

        case = service.create_case(
            title="Suspicious Admin Activity",
            priority="high",
        )

        case_id = case.id

        service.link_finding(
            case_id=case_id,
            finding_id=finding_id,
        )

        session.commit()

    with SessionLocal() as session:
        stored_case = session.get(Case, case_id)
        stored_finding = session.get(
            Finding,
            finding_id,
        )

        assert stored_case is not None
        assert stored_finding is not None

        assert len(stored_case.case_findings) == 1

        assert (
            stored_case.case_findings[0].finding_id
            == finding_id
        )

        assert stored_finding.status == "escalated"

        assert len(stored_case.activities) == 2

        assert (
            stored_case.activities[1].activity_type
            == "finding_added"
        )


def test_case_service_link_finding_rolls_back_all_changes(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0201",
        name="Rollback Investigation",
        status="complete",
    )

    finding = Finding(
        finding_type="detection",
        rule_id="AUTH-BF-001",
        title="Potential Brute-Force Activity",
        severity="high",
        status="new",
        summary="Repeated authentication failures detected.",
        details={},
    )

    investigation.findings.append(finding)

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

        finding_id = finding.id

    with SessionLocal() as session:
        service = CaseService(session)

        case = service.create_case(
            title="Rollback Case",
            priority="high",
        )

        service.link_finding(
            case_id=case.id,
            finding_id=finding_id,
        )

        session.rollback()

    with SessionLocal() as session:
        stored_finding = session.get(
            Finding,
            finding_id,
        )

        case_links = session.execute(
            select(CaseFinding)
        ).scalars().all()

        activities = session.execute(
            select(CaseActivity)
        ).scalars().all()

        cases = session.execute(
            select(Case)
        ).scalars().all()

        assert stored_finding is not None
        assert stored_finding.status == "new"

        assert case_links == []
        assert activities == []
        assert cases == []


def test_case_service_adds_analyst_note_and_activity(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        service = CaseService(session)

        case = service.create_case(
            title="Suspicious Admin Activity",
            priority="high",
        )

        case_id = case.id

        service.add_note(
            case_id=case_id,
            content=(
                "Observed repeated admin login "
                "failures from 10.0.0.8."
            ),
        )

        session.commit()

    with SessionLocal() as session:
        stored_case = session.get(Case, case_id)

        assert stored_case is not None

        assert len(stored_case.notes) == 1
        assert (
            stored_case.notes[0].content
            == (
                "Observed repeated admin login "
                "failures from 10.0.0.8."
            )
        )

        assert len(stored_case.activities) == 2

        assert (
            stored_case.activities[1].activity_type
            == "note_added"
        )


def test_case_service_changes_priority_and_records_activity(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        service = CaseService(session)

        case = service.create_case(
            title="Suspicious Admin Activity",
            priority="medium",
        )

        case_id = case.id

        service.change_priority(
            case_id=case_id,
            priority="high",
        )

        session.commit()

    with SessionLocal() as session:
        stored_case = session.get(Case, case_id)

        assert stored_case is not None
        assert stored_case.priority == "high"

        assert len(stored_case.activities) == 2

        activity = stored_case.activities[1]

        assert activity.activity_type == "priority_changed"
        assert activity.details == {
            "previous_priority": "medium",
            "new_priority": "high",
        }


def test_case_service_changes_status_and_records_activity(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        service = CaseService(session)

        case = service.create_case(
            title="Suspicious Admin Activity",
            priority="high",
        )

        case_id = case.id

        service.change_status(
            case_id=case_id,
            status="investigating",
        )

        session.commit()

    with SessionLocal() as session:
        stored_case = session.get(Case, case_id)

        assert stored_case is not None
        assert stored_case.status == "investigating"

        assert len(stored_case.activities) == 2

        activity = stored_case.activities[1]

        assert activity.activity_type == "status_changed"

        assert activity.details == {
            "previous_status": "open",
            "new_status": "investigating",
        }


def test_case_service_closes_case_with_resolution_and_note(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        service = CaseService(session)

        case = service.create_case(
            title="Suspicious Admin Activity",
            priority="high",
        )

        case_id = case.id

        service.change_status(
            case_id=case_id,
            status="investigating",
        )

        service.close_case(
            case_id=case_id,
            resolution="true_positive",
            closing_note=(
                "Confirmed malicious authentication "
                "activity."
            ),
        )

        session.commit()

    with SessionLocal() as session:
        stored_case = session.get(Case, case_id)

        assert stored_case is not None
        assert stored_case.status == "closed"
        assert stored_case.resolution == "true_positive"
        assert (
            stored_case.closing_note
            == (
                "Confirmed malicious authentication "
                "activity."
            )
        )
        assert stored_case.closed_at is not None

        assert len(stored_case.activities) == 3

        activity = stored_case.activities[2]

        assert activity.activity_type == "case_closed"
        assert activity.details["resolution"] == (
            "true_positive"
        )


def test_case_service_rejects_invalid_resolution(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        service = CaseService(session)

        case = service.create_case(
            title="Suspicious Admin Activity",
            priority="high",
        )

        with pytest.raises(
            ValueError,
            match="Invalid case resolution.",
        ):
            service.close_case(
                case_id=case.id,
                resolution="unknown",
                closing_note="Investigation complete.",
            )

        assert case.status == "open"
        assert case.resolution is None
        assert case.closed_at is None
        assert len(case.activities) == 1


def test_case_service_requires_closing_note(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        service = CaseService(session)

        case = service.create_case(
            title="Suspicious Admin Activity",
            priority="high",
        )

        with pytest.raises(
            ValueError,
            match="Closing note is required.",
        ):
            service.close_case(
                case_id=case.id,
                resolution="true_positive",
                closing_note="   ",
            )

        assert case.status == "open"
        assert case.resolution is None
        assert case.closed_at is None
        assert len(case.activities) == 1


def test_case_service_reopens_closed_case_and_preserves_history(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        service = CaseService(session)

        case = service.create_case(
            title="Suspicious Admin Activity",
            priority="high",
        )

        case_id = case.id

        service.close_case(
            case_id=case_id,
            resolution="true_positive",
            closing_note="Confirmed malicious activity.",
        )

        service.reopen_case(
            case_id=case_id,
        )

        session.commit()

    with SessionLocal() as session:
        stored_case = session.get(Case, case_id)

        assert stored_case is not None

        assert stored_case.status == "open"
        assert stored_case.resolution is None
        assert stored_case.closing_note is None
        assert stored_case.closed_at is None

        assert len(stored_case.activities) == 3

        assert (
            stored_case.activities[0].activity_type
            == "case_created"
        )

        assert (
            stored_case.activities[1].activity_type
            == "case_closed"
        )

        reopened_activity = stored_case.activities[2]

        assert (
            reopened_activity.activity_type
            == "case_reopened"
        )

        assert (
            reopened_activity.details[
                "previous_resolution"
            ]
            == "true_positive"
        )

        assert (
            reopened_activity.details[
                "previous_closing_note"
            ]
            == "Confirmed malicious activity."
        )


def test_case_service_rejects_reopening_non_closed_case(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        service = CaseService(session)

        case = service.create_case(
            title="Suspicious Admin Activity",
            priority="high",
        )

        with pytest.raises(
            ValueError,
            match="Only closed cases can be reopened.",
        ):
            service.reopen_case(
                case_id=case.id,
            )

        assert case.status == "open"
        assert len(case.activities) == 1


def test_case_service_loads_case_history_in_order(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        service = CaseService(session)

        case = service.create_case(
            title="Suspicious Admin Activity",
            priority="medium",
        )

        case_id = case.id

        service.change_priority(
            case_id=case_id,
            priority="high",
        )

        service.change_status(
            case_id=case_id,
            status="investigating",
        )

        session.commit()

    with SessionLocal() as session:
        service = CaseService(session)

        history = service.load_history(
            case_id=case_id,
        )

        assert [
            activity.activity_type
            for activity in history
        ] == [
            "case_created",
            "priority_changed",
            "status_changed",
        ]
