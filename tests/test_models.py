from sqlalchemy import select

from src.database import (
    create_database_engine,
    create_session_factory,
)
from src.models.base import Base
from src.models.investigation import Investigation


def test_investigation_can_be_stored_and_loaded(tmp_path):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0001",
        name="Windows Workstation Investigation",
        status="complete",
        event_count=120,
        finding_count=4,
        high_severity_count=1,
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        stored = session.execute(
            select(Investigation).where(
                Investigation.public_id
                == "INV-2026-0001"
            )
        ).scalar_one()

        assert stored.name == (
            "Windows Workstation Investigation"
        )
        assert stored.status == "complete"
        assert stored.event_count == 120
        assert stored.finding_count == 4
        assert stored.high_severity_count == 1
