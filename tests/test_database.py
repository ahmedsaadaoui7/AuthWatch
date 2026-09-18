from sqlalchemy import text

from src.database import (
    create_database_engine,
    create_session_factory,
)


def test_create_database_engine_connects_to_sqlite(tmp_path):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)

    with engine.connect() as connection:
        result = connection.execute(
            text("SELECT 1")
        ).scalar_one()

    assert result == 1
    assert database_path.exists()


def test_create_database_engine_creates_parent_directory(
    tmp_path,
):
    database_path = (
        tmp_path
        / "AuthWatch"
        / "data"
        / "authwatch.db"
    )

    engine = create_database_engine(database_path)

    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))

    assert database_path.parent.exists()
    assert database_path.exists()


def test_create_session_factory_opens_database_session(
    tmp_path,
):
    database_path = tmp_path / "authwatch.db"

    engine = create_database_engine(database_path)
    SessionLocal = create_session_factory(engine)

    with SessionLocal() as session:
        result = session.execute(
            text("SELECT 1")
        ).scalar_one()

    assert result == 1
