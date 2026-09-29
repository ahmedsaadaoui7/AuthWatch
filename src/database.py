from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.engine import URL
from sqlalchemy.orm import sessionmaker


def create_database_engine(database_path):
    database_path = Path(database_path)

    database_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    database_url = URL.create(
        "sqlite",
        database=str(database_path),
    )

    return create_engine(database_url)


def create_session_factory(engine):
    return sessionmaker(
        bind=engine,
        autoflush=False,
        expire_on_commit=False,
    )
