from sqlalchemy import select

from src.database import (
    create_database_engine,
    create_session_factory,
)
from src.models.base import Base
from src.models.investigation import Investigation
from src.models.telemetry_source import TelemetrySource


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


def test_telemetry_source_belongs_to_investigation(tmp_path):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0002",
        name="Endpoint Telemetry Investigation",
        status="complete",
    )

    telemetry_source = TelemetrySource(
        filename="Security.evtx",
        source_type="windows_security",
        file_size=5242880,
        sha256="a" * 64,
        original_path="/evidence/Security.evtx",
    )

    investigation.telemetry_sources.append(
        telemetry_source
    )

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        stored = session.execute(
            select(Investigation).where(
                Investigation.public_id
                == "INV-2026-0002"
            )
        ).scalar_one()

        assert len(stored.telemetry_sources) == 1

        source = stored.telemetry_sources[0]

        assert source.filename == "Security.evtx"
        assert source.source_type == "windows_security"
        assert source.file_size == 5242880
        assert source.sha256 == "a" * 64
        assert source.original_path == (
            "/evidence/Security.evtx"
        )
