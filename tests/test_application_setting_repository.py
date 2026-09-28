from src.database import (
    create_database_engine,
    create_session_factory,
)
from src.models.base import Base
from src.repositories.application_setting_repository import (
    ApplicationSettingRepository,
)


def test_application_setting_repository_sets_and_reads_value(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )
    Base.metadata.create_all(engine)
    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        repository = ApplicationSettingRepository(
            session
        )

        repository.set_value(
            key="default_severity",
            value="High",
        )
        session.commit()

    with SessionLocal() as session:
        repository = ApplicationSettingRepository(
            session
        )

        setting = repository.get_by_key(
            "default_severity"
        )

        assert setting is not None
        assert setting.value == "High"


def test_application_setting_repository_updates_existing_value(
    tmp_path,
):
    engine = create_database_engine(
        tmp_path / "authwatch.db"
    )
    Base.metadata.create_all(engine)
    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        repository = ApplicationSettingRepository(
            session
        )

        repository.set_value(
            key="high_severity_visual_alerts",
            value=True,
        )
        repository.set_value(
            key="high_severity_visual_alerts",
            value=False,
        )
        session.commit()

        settings = repository.list_all()

        assert len(settings) == 1
        assert settings[0].value is False
