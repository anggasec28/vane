"""SQLite persistence with serialized, hash-linked event appends."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from vane.evidence.provenance import chain_digest


class SQLiteStore:
    """Small SQLite store. Each append obtains a write lock before reading chain head."""

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
        db = self._connect()
        try:
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
        finally:
            db.close()

    def append_chained_event(self, *, project_id: str, event_type: str,
                             actor: str, payload: dict[str, Any],
                             event_id: str | None = None) -> int:
        """Atomically read the project head, calculate digest, and append the event."""
        identifier = event_id or str(uuid4())
        occurred = datetime.now(timezone.utc).isoformat()
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, default=str)
        event_payload = {
            "event_id": identifier, "project_id": project_id,
            "event_type": event_type, "actor": actor,
            "occurred_at": occurred, "payload": payload,
        }
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT digest FROM events WHERE project_id=? ORDER BY sequence DESC LIMIT 1",
                (project_id,),
            ).fetchone()
            previous = str(row["digest"]) if row else None
            digest = chain_digest(previous, event_payload)
            cursor = db.execute(
                """INSERT INTO events
                (event_id, project_id, event_type, actor, occurred_at, payload_json,
                 previous_digest, digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (identifier, project_id, event_type, actor, occurred, encoded, previous, digest),
            )
            sequence = int(cursor.lastrowid)
            db.commit()
            return sequence
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def list_events(self, project_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        if limit < 1 or limit > 10000:
            raise ValueError("limit must be between 1 and 10000")
        db = self._connect()
        try:
            rows = db.execute(
                "SELECT * FROM events WHERE project_id=? ORDER BY sequence LIMIT ?",
                (project_id, limit),
            ).fetchall()
        finally:
            db.close()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item.pop("payload_json"))
            result.append(item)
        return result

    def verify_project_chain(self, project_id: str) -> bool:
        from vane.evidence.chain import verify_event_chain
        return verify_event_chain(self.list_events(project_id, limit=10000)).valid
