from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config

from src.app_paths import get_database_path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
MIGRATIONS_DIRECTORY = PROJECT_ROOT / "migrations"


def _build_alembic_config(
    database_path: Path,
) -> Config:
    config = Config()

    config.set_main_option(
        "script_location",
        str(MIGRATIONS_DIRECTORY),
    )

    config.attributes["database_path"] = (
        database_path
    )

    return config


def upgrade_database(
    database_path: Path | None = None,
) -> Path:
    if database_path is None:
        database_path = get_database_path()

    database_path = Path(database_path)

    database_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    config = _build_alembic_config(
        database_path
    )

    command.upgrade(
        config,
        "head",
    )

    return database_path
