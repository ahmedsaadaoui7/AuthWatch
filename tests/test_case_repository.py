from sqlalchemy import select

from src.database import (
    create_database_engine,
    create_session_factory,
)
from src.models.base import Base
from src.models.case import Case

# Load the remaining persistence models so SQLAlchemy
# knows about all model relationships.
from src.models.case_activity import CaseActivity
from src.models.case_finding import CaseFinding
from src.models.case_note import CaseNote
from src.models.event import Event
from src.models.finding import Finding
from src.models.finding_event import FindingEvent
from src.models.investigation import Investigation
from src.models.telemetry_source import TelemetrySource

from src.repositories.case_repository import CaseRepository


def test_case_repository_get_by_id_returns_case(tmp_path):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    case = Case(
        public_id="AW-0001",
        title="Investigate repeated admin login failures",
        priority="high",
        status="open",
    )

    with SessionLocal() as session:
        session.add(case)
        session.commit()

        case_id = case.id

    with SessionLocal() as session:
        repository = CaseRepository(session)

        stored = repository.get_by_id(case_id)

        assert stored is not None
        assert stored.public_id == "AW-0001"
        assert stored.title == (
            "Investigate repeated admin login failures"
        )
        assert stored.priority == "high"
        assert stored.status == "open"


def test_case_repository_get_by_id_returns_none_when_missing(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        repository = CaseRepository(session)

        stored = repository.get_by_id(999)

        assert stored is None


def test_case_repository_get_by_public_id_returns_case(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    case = Case(
        public_id="AW-0002",
        title="Investigate suspicious authentication",
        priority="high",
        status="open",
    )

    with SessionLocal() as session:
        session.add(case)
        session.commit()

    with SessionLocal() as session:
        repository = CaseRepository(session)

        stored = repository.get_by_public_id("AW-0002")

        assert stored is not None
        assert stored.public_id == "AW-0002"
        assert stored.title == (
            "Investigate suspicious authentication"
        )


def test_case_repository_get_by_public_id_returns_none_when_missing(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        repository = CaseRepository(session)

        stored = repository.get_by_public_id("AW-9999")

        assert stored is None


def test_case_repository_list_all_returns_cases(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    first_case = Case(
        public_id="AW-0003",
        title="Investigate authentication failures",
        priority="high",
        status="open",
    )

    second_case = Case(
        public_id="AW-0004",
        title="Investigate suspicious PowerShell",
        priority="medium",
        status="investigating",
    )

    with SessionLocal() as session:
        session.add(first_case)
        session.add(second_case)
        session.commit()

    with SessionLocal() as session:
        repository = CaseRepository(session)

        stored_cases = repository.list_all()

        assert len(stored_cases) == 2
        assert stored_cases[0].public_id == "AW-0003"
        assert stored_cases[1].public_id == "AW-0004"


def test_case_repository_list_all_returns_empty_list_when_no_cases(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        repository = CaseRepository(session)

        stored_cases = repository.list_all()

        assert stored_cases == []


def test_case_repository_list_by_status_returns_matching_cases(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    open_case = Case(
        public_id="AW-0005",
        title="Investigate authentication failures",
        priority="high",
        status="open",
    )

    closed_case = Case(
        public_id="AW-0006",
        title="Resolved authentication investigation",
        priority="medium",
        status="closed",
    )

    investigating_case = Case(
        public_id="AW-0007",
        title="Investigate suspicious execution",
        priority="high",
        status="investigating",
    )

    with SessionLocal() as session:
        session.add(open_case)
        session.add(closed_case)
        session.add(investigating_case)
        session.commit()

    with SessionLocal() as session:
        repository = CaseRepository(session)

        stored_cases = repository.list_by_status("open")

        assert len(stored_cases) == 1
        assert stored_cases[0].public_id == "AW-0005"
        assert stored_cases[0].status == "open"


def test_case_repository_add_stores_case(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    case = Case(
        public_id="AW-0008",
        title="Investigate suspicious authentication",
        priority="high",
        status="open",
    )

    with SessionLocal() as session:
        repository = CaseRepository(session)

        repository.add(case)

        session.commit()

    with SessionLocal() as session:
        stored = session.get(Case, case.id)

        assert stored is not None
        assert stored.public_id == "AW-0008"
        assert stored.title == (
            "Investigate suspicious authentication"
        )


def test_case_repository_add_does_not_commit_automatically(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    case = Case(
        public_id="AW-0009",
        title="Investigate suspicious login activity",
        priority="medium",
        status="open",
    )

    with SessionLocal() as session:
        repository = CaseRepository(session)

        repository.add(case)

        session.rollback()

    with SessionLocal() as session:
        stored = session.execute(
            select(Case).where(
                Case.public_id == "AW-0009"
            )
        ).scalar_one_or_none()

        assert stored is None
