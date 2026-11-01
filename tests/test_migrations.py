import sqlite3

from vane.storage.sqlite_store import SQLiteStore


def test_schema_v1_database_is_upgraded_by_forward_migration(tmp_path):
    path = tmp_path / "migration.sqlite3"
    store = SQLiteStore(path)
    db = sqlite3.connect(path)
    db.execute("DROP INDEX IF EXISTS idx_events_project_type_sequence")
    db.execute("DELETE FROM schema_migrations WHERE version = 2")
    db.commit()
    db.close()

    upgraded = SQLiteStore(path)
    assert upgraded.schema_version() == 2
    db = sqlite3.connect(path)
    index = db.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
        ("idx_events_project_type_sequence",),
    ).fetchone()
    db.close()
    assert index is not None


def test_migration_schema_is_forward_only(tmp_path):
    path = tmp_path / "future.sqlite3"
    store = SQLiteStore(path)
    db = sqlite3.connect(path)
    db.execute("INSERT INTO schema_migrations(version, applied_at) VALUES(99, 'future')")
    db.commit()
    db.close()
    import pytest
    with pytest.raises(RuntimeError):
        SQLiteStore(path)
