import sqlite3

from src.database_migrations import (
    upgrade_database,
)


EXPECTED_TABLES = {
    "alembic_version",
    "application_settings",
    "case_activities",
    "case_findings",
    "case_notes",
    "cases",
    "events",
    "finding_events",
    "findings",
    "investigations",
    "telemetry_sources",
}


def test_upgrade_database_creates_v4_schema(
    tmp_path,
):
    database_path = (
        tmp_path
        / "runtime"
        / "authwatch.db"
    )

    result = upgrade_database(
        database_path
    )

    assert result == database_path
    assert database_path.exists()

    connection = sqlite3.connect(
        database_path
    )

    try:
        tables = {
            row[0]
            for row in connection.execute(
                """
                SELECT name
                FROM sqlite_master
                WHERE type = 'table'
                """
            )
        }

        assert EXPECTED_TABLES <= tables

        revision = connection.execute(
            """
            SELECT version_num
            FROM alembic_version
            """
        ).fetchone()

        assert revision is not None
        assert revision[0] == "37e623554387"

    finally:
        connection.close()


def test_upgrade_database_is_idempotent(
    tmp_path,
):
    database_path = (
        tmp_path
        / "authwatch.db"
    )

    upgrade_database(database_path)
    upgrade_database(database_path)

    connection = sqlite3.connect(
        database_path
    )

    try:
        revisions = connection.execute(
            """
            SELECT version_num
            FROM alembic_version
            """
        ).fetchall()

        assert revisions == [
            ("37e623554387",)
        ]

    finally:
        connection.close()
