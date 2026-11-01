"""SQLite persistence with atomic domain-record and hash-linked event writes."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from vane.evidence.provenance import chain_digest
from vane.storage.migrations import apply_migrations


def _json_default(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, set):
        return sorted(value)
    if hasattr(value, "value"):
        return value.value
    raise TypeError(f"Unsupported JSON value: {type(value).__name__}")


class SQLiteStore:
    """SQLite store with serialized writers and atomic event-linked record updates."""

    ALLOWED_RECORD_TYPES = {"project", "authorization", "mission", "asset", "evidence", "finding", "approval", "worker_task", "worker_assignment", "case_work_item", "case_timeline_event", "threat_intel", "remediation_action", "report_bundle", "lifecycle_review"}

    def __init__(self, path: str | Path, *, read_only: bool = False) -> None:
        self.path = str(path)
        self.read_only = read_only
        if read_only:
            if not Path(self.path).is_file():
                raise FileNotFoundError(self.path)
        else:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            self._initialize()

    def _connect(self) -> sqlite3.Connection:
        if self.read_only:
            uri = Path(self.path).resolve().as_uri() + "?mode=ro"
            connection = sqlite3.connect(uri, uri=True, timeout=10, isolation_level=None)
        else:
            connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        if not self.read_only:
            connection.execute("PRAGMA journal_mode = WAL")
        return connection

    def _initialize(self) -> None:
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            apply_migrations(db)
            db.commit()
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def schema_version(self) -> int:
        db = self._connect()
        try:
            row = db.execute("SELECT MAX(version) AS version FROM schema_migrations").fetchone()
            return int(row["version"] or 0)
        finally:
            db.close()

    def _append_event_locked(self, db: sqlite3.Connection, *, project_id: str,
                             event_type: str, actor: str, payload: dict[str, Any]) -> int:
        identifier = str(uuid4())
        occurred = datetime.now(timezone.utc).isoformat()
        row = db.execute(
            "SELECT digest FROM events WHERE project_id=? ORDER BY sequence DESC LIMIT 1",
            (project_id,),
        ).fetchone()
        previous = str(row["digest"]) if row else None
        event_payload = {"event_id": identifier, "project_id": project_id,
            "event_type": event_type, "actor": actor, "occurred_at": occurred,
            "payload": payload}
        digest = chain_digest(previous, event_payload)
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, default=_json_default)
        cursor = db.execute(
            """INSERT INTO events
            (event_id, project_id, event_type, actor, occurred_at, payload_json,
             previous_digest, digest) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (identifier, project_id, event_type, actor, occurred, encoded, previous, digest),
        )
        return int(cursor.lastrowid)

    def save_record(self, *, project_id: str, record_type: str, record_id: str,
                    record: dict[str, Any], actor: str) -> int:
        """Persist one versioned record and its hash-linked event atomically."""
        return self.save_records_atomic([{
            "project_id": project_id, "record_type": record_type, "record_id": record_id,
            "record": record, "actor": actor,
        }])[0]

    def save_records_atomic(self, records: list[dict[str, Any]]) -> list[int]:
        """Persist several records and their audit events in one SQLite transaction."""
        if self.read_only:
            raise PermissionError("SQLite store is read-only.")
        if not records:
            return []
        prepared: list[tuple[dict[str, Any], str, str]] = []
        for item in records:
            if item["record_type"] not in self.ALLOWED_RECORD_TYPES:
                raise ValueError(f"Unsupported record type: {item['record_type']}")
            if not all((item["project_id"], item["record_id"], item["actor"])):
                raise ValueError("project_id, record_id, and actor are required.")
            encoded = json.dumps(item["record"], sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=False, default=_json_default)
            digest = __import__("hashlib").sha256(encoded.encode("utf-8")).hexdigest()
            prepared.append((item, encoded, digest))
        db = self._connect()
        revisions: list[int] = []
        try:
            db.execute("BEGIN IMMEDIATE")
            for item, encoded, digest in prepared:
                project_id = item["project_id"]
                record_type = item["record_type"]
                record_id = item["record_id"]
                record = item["record"]
                if record_type == "project":
                    db.execute(
                        """INSERT INTO projects(project_id,name,owner,created_at) VALUES(?,?,?,?)
                        ON CONFLICT(project_id) DO UPDATE SET name=excluded.name, owner=excluded.owner""",
                        (project_id, record["name"], record["owner"], record["created_at"]),
                    )
                else:
                    exists = db.execute("SELECT 1 FROM projects WHERE project_id=?",
                                        (project_id,)).fetchone()
                    if exists is None:
                        raise ValueError(f"Project does not exist: {project_id}")
                row = db.execute(
                    """SELECT revision FROM domain_records
                    WHERE project_id=? AND record_type=? AND record_id=?""",
                    (project_id, record_type, record_id),
                ).fetchone()
                revision = int(row["revision"]) + 1 if row else 1
                db.execute(
                    """INSERT INTO domain_records
                    (project_id,record_type,record_id,revision,record_json,updated_at)
                    VALUES(?,?,?,?,?,?)
                    ON CONFLICT(project_id,record_type,record_id) DO UPDATE SET
                      revision=excluded.revision, record_json=excluded.record_json,
                      updated_at=excluded.updated_at""",
                    (project_id, record_type, record_id, revision, encoded,
                     datetime.now(timezone.utc).isoformat()),
                )
                self._append_event_locked(db, project_id=project_id,
                    event_type=f"{record_type}.saved", actor=item["actor"],
                    payload={"record_type": record_type, "record_id": record_id,
                             "revision": revision, "record_digest": digest})
                revisions.append(revision)
            db.commit()
            return revisions
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    def get_record(self, *, project_id: str, record_type: str,
                   record_id: str) -> tuple[dict[str, Any], int] | None:
        db = self._connect()
        try:
            row = db.execute(
                """SELECT record_json,revision FROM domain_records
                WHERE project_id=? AND record_type=? AND record_id=?""",
                (project_id, record_type, record_id),
            ).fetchone()
        finally:
            db.close()
        if row is None:
            return None
        return json.loads(row["record_json"]), int(row["revision"])

    def list_records(self, *, project_id: str, record_type: str) -> list[dict[str, Any]]:
        db = self._connect()
        try:
            rows = db.execute(
                """SELECT record_json FROM domain_records
                WHERE project_id=? AND record_type=? ORDER BY record_id""",
                (project_id, record_type),
            ).fetchall()
        finally:
            db.close()
        return [json.loads(row["record_json"]) for row in rows]

    def append_chained_event(self, *, project_id: str, event_type: str,
                             actor: str, payload: dict[str, Any],
                             event_id: str | None = None,
                             expected_previous_digest: str | None = None,
                             enforce_expected_head: bool = False) -> int:
        """Append an immutable event, optionally using compare-and-swap on the chain head."""
        if self.read_only:
            raise PermissionError("SQLite store is read-only.")
        identifier = event_id or str(uuid4())
        occurred = datetime.now(timezone.utc).isoformat()
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False, default=_json_default)
        event_payload = {"event_id": identifier, "project_id": project_id,
            "event_type": event_type, "actor": actor, "occurred_at": occurred,
            "payload": payload}
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT digest FROM events WHERE project_id=? ORDER BY sequence DESC LIMIT 1",
                (project_id,),
            ).fetchone()
            previous = str(row["digest"]) if row else None
            if enforce_expected_head and previous != expected_previous_digest:
                raise ValueError("Event-chain head changed; refresh before appending.")
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

    def list_events(self, project_id: str, *, limit: int | None = 100) -> list[dict[str, Any]]:
        if limit is not None and (limit < 1 or limit > 10000):
            raise ValueError("limit must be between 1 and 10000, or None for all events")
        db = self._connect()
        try:
            if limit is None:
                rows = db.execute(
                    "SELECT * FROM events WHERE project_id=? ORDER BY sequence",
                    (project_id,),
                ).fetchall()
            else:
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
        return verify_event_chain(self.list_events(project_id, limit=None)).valid

    def verify_domain_records(self, project_id: str) -> bool:
        """Compare current domain rows to their latest event-record digests."""
        events = self.list_events(project_id, limit=None)
        latest: dict[tuple[str, str], tuple[int, str]] = {}
        for event in events:
            payload = event["payload"]
            if not event["event_type"].endswith(".saved"):
                continue
            key = (str(payload.get("record_type", "")), str(payload.get("record_id", "")))
            latest[key] = (int(payload.get("revision", 0)), str(payload.get("record_digest", "")))
        db = self._connect()
        try:
            rows = db.execute(
                "SELECT record_type,record_id,revision,record_json FROM domain_records WHERE project_id=?",
                (project_id,),
            ).fetchall()
        finally:
            db.close()
        current: dict[tuple[str, str], tuple[int, str]] = {}
        import hashlib
        for row in rows:
            key = (str(row["record_type"]), str(row["record_id"]))
            digest = hashlib.sha256(str(row["record_json"]).encode("utf-8")).hexdigest()
            current[key] = (int(row["revision"]), digest)
        return current == latest

    def verify_project_integrity(self, project_id: str) -> bool:
        """Verify event chain continuity and current domain rows against recorded digests."""
        return self.verify_project_chain(project_id) and self.verify_domain_records(project_id)

    def list_projects(self) -> list[dict[str, str]]:
        db = self._connect()
        try:
            rows = db.execute(
                "SELECT project_id,name,owner,created_at FROM projects ORDER BY created_at,project_id"
            ).fetchall()
        finally:
            db.close()
        return [dict(row) for row in rows]
