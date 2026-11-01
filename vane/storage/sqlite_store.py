"""SQLite persistence with explicit transactions and immutable event records."""
from __future__ import annotations
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

class SQLiteStore:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS projects (
                    project_id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_id TEXT NOT NULL UNIQUE, project_id TEXT NOT NULL,
                    event_type TEXT NOT NULL, actor TEXT NOT NULL,
                    occurred_at TEXT NOT NULL, payload_json TEXT NOT NULL,
                    previous_digest TEXT, digest TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_project_sequence
                    ON events(project_id, sequence);
            """)

    def append_event(self, *, event_id: str, project_id: str, event_type: str,
                     actor: str, payload: dict[str, Any], digest: str,
                     previous_digest: str | None = None) -> int:
        occurred = datetime.now(timezone.utc).isoformat()
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            cursor = db.execute("""INSERT INTO events
                (event_id, project_id, event_type, actor, occurred_at, payload_json,
                 previous_digest, digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (event_id, project_id, event_type, actor, occurred, encoded,
                 previous_digest, digest))
            return int(cursor.lastrowid)

    def list_events(self, project_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1 or limit > 10000:
            raise ValueError("limit must be between 1 and 10000")
        with self._connect() as db:
            rows = db.execute("""SELECT * FROM events WHERE project_id=?
                ORDER BY sequence LIMIT ?""", (project_id, limit)).fetchall()
        return [dict(row) for row in rows]
