from src.database import (
    create_database_engine,
    create_session_factory,
)
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

from src.repositories.investigation_repository import (
    InvestigationRepository,
)


def test_investigation_repository_get_by_id_returns_investigation(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0100",
        name="Authentication Investigation",
        status="complete",
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

        investigation_id = investigation.id

    with SessionLocal() as session:
        repository = InvestigationRepository(session)

        stored = repository.get_by_id(
            investigation_id
        )

        assert stored is not None
        assert stored.public_id == "INV-2026-0100"


def test_investigation_repository_get_by_id_returns_none_when_missing(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        repository = InvestigationRepository(session)

        stored = repository.get_by_id(999)

        assert stored is None


def test_investigation_repository_get_by_public_id_returns_investigation(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0101",
        name="Endpoint Investigation",
        status="complete",
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        repository = InvestigationRepository(session)

        stored = repository.get_by_public_id(
            "INV-2026-0101"
        )

        assert stored is not None
        assert stored.name == "Endpoint Investigation"


def test_investigation_repository_get_by_public_id_returns_none_when_missing(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        repository = InvestigationRepository(session)

        stored = repository.get_by_public_id(
            "INV-DOES-NOT-EXIST"
        )

        assert stored is None


def test_investigation_repository_list_all_returns_investigations(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    first = Investigation(
        public_id="INV-2026-0102",
        name="First Investigation",
        status="complete",
    )

    second = Investigation(
        public_id="INV-2026-0103",
        name="Second Investigation",
        status="complete",
    )

    with SessionLocal() as session:
        session.add_all([first, second])
        session.commit()

    with SessionLocal() as session:
        repository = InvestigationRepository(session)

        stored = repository.list_all()

        assert len(stored) == 2
        assert stored[0].public_id == "INV-2026-0102"
        assert stored[1].public_id == "INV-2026-0103"


def test_investigation_repository_list_all_returns_empty_list(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        repository = InvestigationRepository(session)

        stored = repository.list_all()

        assert stored == []


def test_investigation_repository_add_stores_investigation(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0104",
        name="Added Investigation",
        status="complete",
    )

    with SessionLocal() as session:
        repository = InvestigationRepository(session)

        repository.add(investigation)
        session.commit()

    with SessionLocal() as session:
        repository = InvestigationRepository(session)

        stored = repository.get_by_public_id(
            "INV-2026-0104"
        )

        assert stored is not None
        assert stored.name == "Added Investigation"


def test_investigation_repository_add_does_not_auto_commit(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0105",
        name="Rollback Investigation",
        status="complete",
    )

    with SessionLocal() as session:
        repository = InvestigationRepository(session)

        repository.add(investigation)
        session.rollback()

    with SessionLocal() as session:
        repository = InvestigationRepository(session)

        stored = repository.get_by_public_id(
            "INV-2026-0105"
        )

        assert stored is None


def test_investigation_repository_list_by_status_filters_investigations(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    complete = Investigation(
        public_id="INV-2026-0106",
        name="Completed Investigation",
        status="complete",
    )

    running = Investigation(
        public_id="INV-2026-0107",
        name="Running Investigation",
        status="running",
    )

    with SessionLocal() as session:
        session.add_all(
            [
                complete,
                running,
            ]
        )
        session.commit()

    with SessionLocal() as session:
        repository = InvestigationRepository(session)

        stored = repository.list_by_status(
            "complete"
        )

        assert len(stored) == 1
        assert stored[0].public_id == "INV-2026-0106"


def test_investigation_repository_searches_name_and_public_id(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    authentication = Investigation(
        public_id="INV-2026-0108",
        name="Authentication Investigation",
        status="complete",
    )

    endpoint = Investigation(
        public_id="INV-2026-0109",
        name="Endpoint Investigation",
        status="complete",
    )

    with SessionLocal() as session:
        session.add_all(
            [
                authentication,
                endpoint,
            ]
        )
        session.commit()

    with SessionLocal() as session:
        repository = InvestigationRepository(session)

        name_results = repository.search(
            "authentication"
        )

        public_id_results = repository.search(
            "0109"
        )

        assert len(name_results) == 1
        assert (
            name_results[0].public_id
            == "INV-2026-0108"
        )

        assert len(public_id_results) == 1
        assert (
            public_id_results[0].public_id
            == "INV-2026-0109"
        )


def test_investigation_repository_list_filtered_combines_search_and_status(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    complete_auth = Investigation(
        public_id="INV-2026-0110",
        name="Authentication Investigation",
        status="complete",
    )

    running_auth = Investigation(
        public_id="INV-2026-0111",
        name="Authentication Review",
        status="running",
    )

    complete_endpoint = Investigation(
        public_id="INV-2026-0112",
        name="Endpoint Investigation",
        status="complete",
    )

    with SessionLocal() as session:
        session.add_all(
            [
                complete_auth,
                running_auth,
                complete_endpoint,
            ]
        )
        session.commit()

    with SessionLocal() as session:
        repository = InvestigationRepository(session)

        stored = repository.list_filtered(
            search="authentication",
            status="complete",
        )

        assert len(stored) == 1
        assert stored[0].public_id == "INV-2026-0110"
