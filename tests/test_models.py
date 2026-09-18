from sqlalchemy import select

from src.database import (
    create_database_engine,
    create_session_factory,
)
from src.models.base import Base
from src.models.investigation import Investigation
from src.models.telemetry_source import TelemetrySource

from datetime import datetime, timezone

from src.models.event import Event

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


def test_event_belongs_to_investigation_and_telemetry_source(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    Base.metadata.create_all(engine)

    SessionLocal = create_session_factory(engine)

    investigation = Investigation(
        public_id="INV-2026-0003",
        name="Windows Endpoint Investigation",
        status="complete",
    )

    telemetry_source = TelemetrySource(
        filename="Security.evtx",
        source_type="windows_security",
        file_size=5242880,
        sha256="b" * 64,
        original_path="/evidence/Security.evtx",
    )

    event = Event(
        timestamp=datetime(
            2026,
            9,
            18,
            10,
            0,
            tzinfo=timezone.utc,
        ),
        source="windows_security",
        event_id="4624",
        event_type="authentication_success",
        host="WIN-CLIENT01",
        username="alice",
        session_id="0x1234",
        source_ip="10.0.0.50",
        result="success",
        details={
            "logon_type": "3",
        },
    )

    telemetry_source.events.append(event)

    investigation.telemetry_sources.append(
        telemetry_source
    )

    investigation.events.append(event)

    with SessionLocal() as session:
        session.add(investigation)
        session.commit()

    with SessionLocal() as session:
        stored = session.execute(
            select(Investigation).where(
                Investigation.public_id
                == "INV-2026-0003"
            )
        ).scalar_one()

        assert len(stored.events) == 1

        stored_event = stored.events[0]

        assert stored_event.event_id == "4624"
        assert stored_event.event_type == (
            "authentication_success"
        )
        assert stored_event.username == "alice"
        assert stored_event.source_ip == "10.0.0.50"
        assert stored_event.details["logon_type"] == "3"

        assert stored_event.telemetry_source.filename == (
            "Security.evtx"
        )
