"""Forward-only, transactional SQLite schema migrations."""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


@dataclass(frozen=True, slots=True)
class Migration:
    version: int
    name: str
    apply: Callable[[sqlite3.Connection], None]


def _initial_schema(db: sqlite3.Connection) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS projects (
        project_id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL,
        created_at TEXT NOT NULL)""")
    db.execute("""CREATE TABLE IF NOT EXISTS domain_records (
        project_id TEXT NOT NULL, record_type TEXT NOT NULL, record_id TEXT NOT NULL,
        revision INTEGER NOT NULL, record_json TEXT NOT NULL, updated_at TEXT NOT NULL,
        PRIMARY KEY(project_id, record_type, record_id))""")
    db.execute("""CREATE TABLE IF NOT EXISTS events (
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT NOT NULL UNIQUE, project_id TEXT NOT NULL,
        event_type TEXT NOT NULL, actor TEXT NOT NULL,
        occurred_at TEXT NOT NULL, payload_json TEXT NOT NULL,
        previous_digest TEXT, digest TEXT NOT NULL)""")
    db.execute("""CREATE INDEX IF NOT EXISTS idx_events_project_sequence
        ON events(project_id, sequence)""")
    db.execute("""CREATE INDEX IF NOT EXISTS idx_records_project_type
        ON domain_records(project_id, record_type)""")


def _add_event_lookup_index(db: sqlite3.Connection) -> None:
    db.execute("""CREATE INDEX IF NOT EXISTS idx_events_project_type_sequence
        ON events(project_id, event_type, sequence)""")


MIGRATIONS = (
    Migration(1, "initial_domain_store", _initial_schema),
    Migration(2, "event_type_lookup_index", _add_event_lookup_index),
)


def apply_migrations(db: sqlite3.Connection) -> int:
    """Apply every missing contiguous migration inside the caller's transaction."""
    db.execute("""CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)""")
    row = db.execute("SELECT MAX(version) AS version FROM schema_migrations").fetchone()
    current = int(row["version"] or 0)
    if current > MIGRATIONS[-1].version:
        raise RuntimeError("Database schema is newer than this VANE build.")
    for migration in MIGRATIONS:
        if migration.version <= current:
            continue
        if migration.version != current + 1:
            raise RuntimeError(f"Missing migration after schema version {current}.")
        migration.apply(db)
        db.execute("INSERT INTO schema_migrations(version, applied_at) VALUES(?, ?)",
                   (migration.version, datetime.now(timezone.utc).isoformat()))
        current = migration.version
    return current
