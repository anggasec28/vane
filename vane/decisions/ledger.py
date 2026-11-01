"""Append-only, evidence-linked Central Decision Ledger.

The project event chain is the authoritative history. This module stores complete
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
    supersedes_decision_id: str | None = None
    supersedes_revision: int | None = None
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
        if not snapshot.supersedes_decision_id or snapshot.supersedes_revision is None:
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
        supersedes_decision_id=value.get("supersedes_decision_id"),
        supersedes_revision=value.get("supersedes_revision"),
        uncertainty=value.get("uncertainty", ""),
    )


class DecisionLedger:
    """Project-scoped authoritative ledger with immutable event history."""

    EVENT_TYPE = "decision.snapshot"

    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def _events(self, project_id: str) -> list[dict[str, Any]]:
        return [event for event in self.store.list_events(project_id, limit=None)
                if event["event_type"] == self.EVENT_TYPE]

    def _head_digest(self, project_id: str) -> str | None:
        events = self.store.list_events(project_id, limit=None)
        return str(events[-1]["digest"]) if events else None

    def list_decisions(self, project_id: str) -> tuple[DecisionSnapshot, ...]:
        latest: dict[str, DecisionSnapshot] = {}
        for event in self._events(project_id):
            snapshot = _deserialize(event["payload"]["snapshot"])
            current = latest.get(snapshot.decision_id)
            if current is None or snapshot.revision > current.revision:
                latest[snapshot.decision_id] = snapshot
        return tuple(sorted(latest.values(), key=lambda item: item.decision_id))

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
        supersedes_decision_id: str | None = None,
        supersedes_revision: int | None = None,
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
            supersedes_decision_id=supersedes_decision_id,
            supersedes_revision=supersedes_revision, uncertainty=(
                current.uncertainty if uncertainty is None else uncertainty),
        )
        return self._append(snapshot, expected_revision=current.revision)

    def _append(self, snapshot: DecisionSnapshot, *, expected_revision: int) -> DecisionSnapshot:
        _validate_snapshot(snapshot)
        events = self._events(snapshot.project_id)
        current = next((item for item in reversed(events)
                        if item["payload"]["snapshot"]["decision_id"] == snapshot.decision_id), None)
        actual_revision = int(current["payload"]["snapshot"]["revision"]) if current else 0
        if actual_revision != expected_revision:
            raise ValueError("Decision revision changed; refresh before appending.")
        head = self._head_digest(snapshot.project_id)
        self.store.append_chained_event(
            project_id=snapshot.project_id, event_type=self.EVENT_TYPE,
            actor=snapshot.actor,
            payload={"snapshot": _serialize(snapshot),
                     "previous_decision_revision": expected_revision,
                     "authority_reference": snapshot.authority_reference,
                     "policy_version": snapshot.policy_version},
            expected_previous_digest=head, enforce_expected_head=True,
        )
        return snapshot
