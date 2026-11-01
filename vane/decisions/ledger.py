"""Append-only, evidence-linked Central Decision Ledger.

The central ledger event chain is the authoritative history. This module stores complete
decision snapshots in immutable events and uses event-head compare-and-swap so
concurrent writers cannot silently fork or overwrite the ledger.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

from vane.storage.sqlite_store import SQLiteStore
from vane.validation.schema_contracts import validate_document


class DecisionStatus(StrEnum):
    VALID = "VALID"
    REVALIDATION_REQUIRED = "REVALIDATION_REQUIRED"
    SUSPENDED = "SUSPENDED"
    SUPERSEDED = "SUPERSEDED"
    UNRESOLVED = "UNRESOLVED"


_ALLOWED_TRANSITIONS: dict[DecisionStatus, set[DecisionStatus]] = {
    DecisionStatus.VALID: {
        DecisionStatus.REVALIDATION_REQUIRED, DecisionStatus.SUSPENDED,
        DecisionStatus.SUPERSEDED,
    },
    DecisionStatus.REVALIDATION_REQUIRED: {
        DecisionStatus.VALID, DecisionStatus.SUSPENDED,
        DecisionStatus.SUPERSEDED, DecisionStatus.UNRESOLVED,
    },
    DecisionStatus.SUSPENDED: {
        DecisionStatus.VALID, DecisionStatus.REVALIDATION_REQUIRED,
        DecisionStatus.SUPERSEDED, DecisionStatus.UNRESOLVED,
    },
    DecisionStatus.UNRESOLVED: {
        DecisionStatus.VALID, DecisionStatus.SUSPENDED,
        DecisionStatus.SUPERSEDED,
    },
    DecisionStatus.SUPERSEDED: set(),
}


@dataclass(frozen=True, slots=True)
class DecisionSnapshot:
    decision_id: str
    project_id: str
    revision: int
    status: DecisionStatus
    title: str
    rationale: str
    actor: str
    authority_reference: str
    trigger: str
    occurred_at: datetime
    evidence_references: tuple[str, ...] = ()
    dependency_decision_ids: tuple[str, ...] = ()
    policy_version: str = "1"
    superseded_by_decision_id: str | None = None
    superseded_by_revision: int | None = None
    uncertainty: str = ""


def _validate_snapshot(snapshot: DecisionSnapshot) -> None:
    required = (
        snapshot.decision_id, snapshot.project_id, snapshot.title,
        snapshot.rationale, snapshot.actor, snapshot.authority_reference,
        snapshot.trigger, snapshot.policy_version,
    )
    if any(not value.strip() for value in required):
        raise ValueError("Decision identity, rationale, authority, trigger, and policy are required.")
    if snapshot.revision < 1:
        raise ValueError("Decision revision must be positive.")
    if snapshot.status == DecisionStatus.SUPERSEDED:
        if not snapshot.superseded_by_decision_id or snapshot.superseded_by_revision is None:
            raise ValueError("A superseding decision must identify the prior decision and revision.")
    if snapshot.decision_id in snapshot.dependency_decision_ids:
        raise ValueError("A decision cannot depend on itself.")
    if len(set(snapshot.evidence_references)) != len(snapshot.evidence_references):
        raise ValueError("Evidence references must be unique.")


def _serialize(snapshot: DecisionSnapshot) -> dict[str, Any]:
    value = asdict(snapshot)
    value["status"] = snapshot.status.value
    value["occurred_at"] = snapshot.occurred_at.astimezone(timezone.utc).isoformat()
    value["evidence_references"] = list(snapshot.evidence_references)
    value["dependency_decision_ids"] = list(snapshot.dependency_decision_ids)
    return value


def _deserialize(value: dict[str, Any]) -> DecisionSnapshot:
    return DecisionSnapshot(
        decision_id=value["decision_id"], project_id=value["project_id"],
        revision=int(value["revision"]), status=DecisionStatus(value["status"]),
        title=value["title"], rationale=value["rationale"], actor=value["actor"],
        authority_reference=value["authority_reference"], trigger=value["trigger"],
        occurred_at=datetime.fromisoformat(value["occurred_at"]),
        evidence_references=tuple(value.get("evidence_references", [])),
        dependency_decision_ids=tuple(value.get("dependency_decision_ids", [])),
        policy_version=value.get("policy_version", "1"),
        superseded_by_decision_id=value.get("superseded_by_decision_id"),
        superseded_by_revision=value.get("superseded_by_revision"),
        uncertainty=value.get("uncertainty", ""),
    )


class DecisionLedger:
    """One central authoritative event chain with project-scoped decision views."""

    EVENT_TYPE = "decision.snapshot"
    LEDGER_PROJECT_ID = "__central_decision_ledger__"

    def __init__(self, store: SQLiteStore) -> None:
        self.store = store
        if store.get_record(project_id=self.LEDGER_PROJECT_ID, record_type="project",
                            record_id=self.LEDGER_PROJECT_ID) is None:
            store.save_record(
                project_id=self.LEDGER_PROJECT_ID, record_type="project",
                record_id=self.LEDGER_PROJECT_ID, actor="vane-ledger",
                record={
                    "project_id": self.LEDGER_PROJECT_ID,
                    "name": "VANE Central Decision Ledger", "owner": "VANE",
                    "created_at": datetime.now(timezone.utc).isoformat(),
                },
            )

    def _events(self, project_id: str | None = None) -> list[dict[str, Any]]:
        events = [event for event in self.store.list_events(self.LEDGER_PROJECT_ID, limit=None)
                  if event["event_type"] == self.EVENT_TYPE]
        if project_id is not None:
            events = [event for event in events
                      if event["payload"]["snapshot"]["project_id"] == project_id]
        return events

    def _head_digest(self) -> str | None:
        events = self.store.list_events(self.LEDGER_PROJECT_ID, limit=None)
        return str(events[-1]["digest"]) if events else None

    def list_decisions(self, project_id: str) -> tuple[DecisionSnapshot, ...]:
        latest: dict[str, DecisionSnapshot] = {}
        for event in self._events(project_id):
            snapshot = _deserialize(event["payload"]["snapshot"])
            current = latest.get(snapshot.decision_id)
            if current is None or snapshot.revision > current.revision:
                latest[snapshot.decision_id] = snapshot
        return tuple(sorted(latest.values(), key=lambda item: item.decision_id))

    def list_all_decisions(self) -> tuple[DecisionSnapshot, ...]:
        latest: dict[tuple[str, str], DecisionSnapshot] = {}
        for event in self._events():
            snapshot = _deserialize(event["payload"]["snapshot"])
            key = (snapshot.project_id, snapshot.decision_id)
            current = latest.get(key)
            if current is None or snapshot.revision > current.revision:
                latest[key] = snapshot
        return tuple(sorted(latest.values(), key=lambda item: (item.project_id, item.decision_id)))

    def get(self, project_id: str, decision_id: str) -> DecisionSnapshot:
        for snapshot in self.list_decisions(project_id):
            if snapshot.decision_id == decision_id:
                return snapshot
        raise KeyError(decision_id)

    def create(
        self, *, project_id: str, title: str, rationale: str, actor: str,
        authority_reference: str, trigger: str,
        evidence_references: tuple[str, ...] = (),
        dependency_decision_ids: tuple[str, ...] = (),
        policy_version: str = "1", uncertainty: str = "",
        decision_id: str | None = None,
    ) -> DecisionSnapshot:
        identifier = decision_id or str(uuid4())
        if any(item.decision_id == identifier for item in self.list_decisions(project_id)):
            raise ValueError(f"Decision already exists: {identifier}")
        snapshot = DecisionSnapshot(
            decision_id=identifier, project_id=project_id, revision=1,
            status=DecisionStatus.UNRESOLVED, title=title, rationale=rationale,
            actor=actor, authority_reference=authority_reference, trigger=trigger,
            occurred_at=datetime.now(timezone.utc),
            evidence_references=evidence_references,
            dependency_decision_ids=dependency_decision_ids,
            policy_version=policy_version, uncertainty=uncertainty,
        )
        return self._append(snapshot, expected_revision=0)

    def transition(
        self, *, project_id: str, decision_id: str,
        expected_revision: int, target: DecisionStatus,
        actor: str, authority_reference: str, trigger: str, rationale: str,
        evidence_references: tuple[str, ...] | None = None,
        policy_version: str | None = None, uncertainty: str | None = None,
        superseded_by_decision_id: str | None = None,
        superseded_by_revision: int | None = None,
    ) -> DecisionSnapshot:
        current = self.get(project_id, decision_id)
        if current.revision != expected_revision:
            raise ValueError("Decision revision changed; refresh before transition.")
        if target not in _ALLOWED_TRANSITIONS[current.status]:
            raise ValueError(f"Invalid decision transition: {current.status.value} -> {target.value}")
        snapshot = DecisionSnapshot(
            decision_id=current.decision_id, project_id=current.project_id,
            revision=current.revision + 1, status=target, title=current.title,
            rationale=rationale, actor=actor, authority_reference=authority_reference,
            trigger=trigger, occurred_at=datetime.now(timezone.utc),
            evidence_references=(evidence_references if evidence_references is not None
                                 else current.evidence_references),
            dependency_decision_ids=current.dependency_decision_ids,
            policy_version=policy_version or current.policy_version,
            superseded_by_decision_id=superseded_by_decision_id,
            superseded_by_revision=superseded_by_revision, uncertainty=(
                current.uncertainty if uncertainty is None else uncertainty),
        )
        return self._append(snapshot, expected_revision=current.revision)

    def _append(self, snapshot: DecisionSnapshot, *, expected_revision: int) -> DecisionSnapshot:
        _validate_snapshot(snapshot)
        latest = {item.decision_id: item for item in self.list_decisions(snapshot.project_id)}
        for dependency_id in snapshot.dependency_decision_ids:
            if dependency_id not in latest:
                raise ValueError(f"Dependency decision does not exist in this project: {dependency_id}")
            if latest[dependency_id].status == DecisionStatus.SUPERSEDED:
                raise ValueError(f"Dependency decision is superseded: {dependency_id}")
        if snapshot.status == DecisionStatus.SUPERSEDED:
            target_id = snapshot.superseded_by_decision_id
            if target_id == snapshot.decision_id:
                raise ValueError("A decision cannot supersede itself.")
            target = latest.get(target_id or "")
            if target is None:
                raise ValueError("Superseding decision must exist in the same project.")
            if target.revision != snapshot.superseded_by_revision:
                raise ValueError("Superseding decision revision does not match the current ledger.")
            if target.status == DecisionStatus.SUPERSEDED:
                raise ValueError("A superseded decision cannot supersede another decision.")
        events = self._events(snapshot.project_id)
        current = next((item for item in reversed(events)
                        if item["payload"]["snapshot"]["decision_id"] == snapshot.decision_id), None)
        actual_revision = int(current["payload"]["snapshot"]["revision"]) if current else 0
        if actual_revision != expected_revision:
            raise ValueError("Decision revision changed; refresh before appending.")
        head = self._head_digest()
        self.store.append_chained_event(
            project_id=self.LEDGER_PROJECT_ID, event_type=self.EVENT_TYPE,
            actor=snapshot.actor,
            payload={"snapshot": _serialize(snapshot),
                     "previous_decision_revision": expected_revision,
                     "authority_reference": snapshot.authority_reference,
                     "policy_version": snapshot.policy_version},
            expected_previous_digest=head, enforce_expected_head=True,
        )
        return snapshot
