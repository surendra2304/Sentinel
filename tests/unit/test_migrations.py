from alembic.config import Config
from sqlalchemy import create_engine, text

from alembic import command


def test_alembic_upgrade_downgrade_sqlite(tmp_path):
    db_file = tmp_path / "test_migration.db"
    sqlite_url = f"sqlite:///{db_file}"

    # Setup temporary alembic config pointing to SQLite for migration test
    alembic_cfg = Config("alembic.ini")
    alembic_cfg.set_main_option("sqlalchemy.url", sqlite_url)

    # Test upgrade to head
    command.upgrade(alembic_cfg, "head")

    # Verify tables exist in SQLite
    engine = create_engine(sqlite_url)
    with engine.connect() as conn:
        result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table';"))
        tables = {row[0] for row in result.fetchall()}

        expected_tables = {
            "sentinel_targets",
            "sentinel_targetsets",
            "sentinel_targetset_targets",
            "sentinel_scopes",
            "sentinel_policies",
            "sentinel_tasks",
            "sentinel_action_requests",
            "sentinel_action_results",
            "sentinel_evidence",
            "sentinel_findings",
            "sentinel_risks",
            "sentinel_events",
            "sentinel_audit_logs",
            "alembic_version",
        }
        for table in expected_tables:
            assert table in tables, f"Expected table {table} not found in database!"

    # Test downgrade to base
    command.downgrade(alembic_cfg, "base")

    # Verify tables dropped
    with engine.connect() as conn:
        result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='table';"))
        tables = {row[0] for row in result.fetchall()}
        for table in expected_tables - {"alembic_version"}:
            assert table not in tables, f"Table {table} was not dropped on downgrade!"
