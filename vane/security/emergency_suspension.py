"""Master-only, signed emergency suspension control with fail-closed reads."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from vane.crypto.approval_verifier import Ed25519ApprovalVerifier
from vane.security.approval import Approval, ApprovalVerifier
from vane.security.digests import approval_signing_payload
from vane.storage.sqlite_store import SQLiteStore


class SuspensionStatus(StrEnum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"


@dataclass(frozen=True, slots=True)
class SuspensionSnapshot:
    status: SuspensionStatus
    revision: int
    master_principal: str
    reason: str
    authority_reference: str
    trigger: str
    occurred_at: datetime
    approval_id: str


def suspension_approval_digest(*, operation: SuspensionStatus, expected_revision: int,
                               master_principal: str, reason: str,
                               authority_reference: str, trigger: str) -> str:
    payload = {
        "domain": "VANE_MASTER_EMERGENCY_SUSPENSION_V1",
        "operation": operation.value,
        "expected_revision": expected_revision,
        "master_principal": master_principal,
        "reason": reason,
        "authority_reference": authority_reference,
        "trigger": trigger,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class MasterEmergencySuspension:
    """Global control ledger. Only an explicitly configured Master key may suspend/release."""

    PROJECT_ID = "__vane_emergency_control__"
    EVENT_TYPE = "emergency_suspension.transition"

    def __init__(self, store: SQLiteStore, *, master_principal: str,
                 master_key_ids: set[str], verifier: ApprovalVerifier) -> None:
        if not master_principal.strip() or not master_key_ids:
            raise ValueError("Master principal and at least one Master signing key ID are required.")
        if any(not item.strip() for item in master_key_ids):
            raise ValueError("Master key IDs must be non-empty.")
        self.store = store
        self.master_principal = master_principal
        self.master_key_ids = frozenset(master_key_ids)
        self.verifier = verifier

    def _events(self) -> list[dict[str, Any]]:
        if not self.store.verify_project_chain(self.PROJECT_ID):
            raise RuntimeError("Emergency control event chain integrity failed; fail closed.")
        events = self.store.list_events(self.PROJECT_ID, limit=None)
        if any(item["event_type"] != self.EVENT_TYPE for item in events):
            raise RuntimeError("Unexpected event in emergency control chain; fail closed.")
        return events

    def current(self) -> SuspensionSnapshot | None:
        events = self._events()
        transitions = [item for item in events if item["event_type"] == self.EVENT_TYPE]
        if not transitions:
            return None
        previous_status = SuspensionStatus.ACTIVE
        previous_revision = 0
        latest: SuspensionSnapshot | None = None
        for event in transitions:
            payload = event["payload"]
            raw = payload["snapshot"]
            approval_raw = payload["approval"]
            snapshot = SuspensionSnapshot(
                status=SuspensionStatus(raw["status"]), revision=int(raw["revision"]),
                master_principal=str(raw["master_principal"]), reason=str(raw["reason"]),
                authority_reference=str(raw["authority_reference"]), trigger=str(raw["trigger"]),
                occurred_at=datetime.fromisoformat(raw["occurred_at"]),
                approval_id=str(raw["approval_id"]),
            )
            approval = Approval(
                approval_id=str(approval_raw["approval_id"]),
                approver=str(approval_raw["approver"]),
                subject_digest=str(approval_raw["subject_digest"]),
                decision=str(approval_raw["decision"]),
                decided_at=datetime.fromisoformat(approval_raw["decided_at"]),
                key_id=str(approval_raw["key_id"]),
                signature=str(approval_raw["signature"]),
                expires_at=datetime.fromisoformat(approval_raw["expires_at"])
                    if approval_raw.get("expires_at") else None,
                rationale=str(approval_raw.get("rationale", "")),
            )
            expected_digest = suspension_approval_digest(
                operation=snapshot.status, expected_revision=previous_revision,
                master_principal=self.master_principal, reason=snapshot.reason,
                authority_reference=snapshot.authority_reference, trigger=snapshot.trigger,
            )
            if (snapshot.master_principal != self.master_principal
                    or snapshot.revision != previous_revision + 1
                    or snapshot.status == previous_status
                    or event["actor"] != self.master_principal
                    or approval.approval_id != snapshot.approval_id
                    or approval.approver != self.master_principal
                    or approval.key_id not in self.master_key_ids
                    or not approval.is_valid_for(expected_digest, snapshot.occurred_at)
                    or not self.verifier.verify(approval)):
                raise RuntimeError("Emergency control authorization history invalid; fail closed.")
            latest = snapshot
            previous_status = snapshot.status
            previous_revision = snapshot.revision
        return latest

    def is_suspended(self) -> bool:
        snapshot = self.current()
        return snapshot is not None and snapshot.status == SuspensionStatus.SUSPENDED

    def _transition(self, operation: SuspensionStatus, *, expected_revision: int,
                    reason: str, authority_reference: str, trigger: str,
                    approval: Approval, now: datetime | None = None) -> SuspensionSnapshot:
        if not all(value.strip() for value in (reason, authority_reference, trigger)):
            raise ValueError("Reason, authority reference, and trigger are required.")
        current = self.current()
        actual_revision = current.revision if current else 0
        current_status = current.status if current else SuspensionStatus.ACTIVE
        if actual_revision != expected_revision:
            raise ValueError("Emergency control revision changed; refresh before transition.")
        if operation == current_status:
            raise ValueError(f"Emergency control is already {operation.value}.")
        if approval.approver != self.master_principal or approval.key_id not in self.master_key_ids:
            raise PermissionError("Emergency suspension requires an approval from the configured Master identity.")
        digest = suspension_approval_digest(
            operation=operation, expected_revision=expected_revision,
            master_principal=self.master_principal, reason=reason,
            authority_reference=authority_reference, trigger=trigger,
        )
        if (not approval.is_valid_for(digest, now)
                or not self.verifier.verify(approval)):
            raise PermissionError("Master emergency-control signature is invalid or expired.")
        occurred_at = now or datetime.now(timezone.utc)
        snapshot = SuspensionSnapshot(
            status=operation, revision=actual_revision + 1,
            master_principal=self.master_principal, reason=reason,
            authority_reference=authority_reference, trigger=trigger,
            occurred_at=occurred_at, approval_id=approval.approval_id,
        )
        events = self.store.list_events(self.PROJECT_ID, limit=None)
        head = str(events[-1]["digest"]) if events else None
        payload = {
            "snapshot": {
                "status": snapshot.status.value, "revision": snapshot.revision,
                "master_principal": snapshot.master_principal, "reason": snapshot.reason,
                "authority_reference": snapshot.authority_reference, "trigger": snapshot.trigger,
                "occurred_at": snapshot.occurred_at.isoformat(),
                "approval_id": snapshot.approval_id,
            },
            "approval_digest": digest,
            "approval": {
                "approval_id": approval.approval_id, "approver": approval.approver,
                "subject_digest": approval.subject_digest, "decision": approval.decision,
                "decided_at": approval.decided_at.isoformat(), "key_id": approval.key_id,
                "signature": approval.signature,
                "expires_at": approval.expires_at.isoformat() if approval.expires_at else None,
                "rationale": approval.rationale,
            },
            "approval_signing_payload_sha256": hashlib.sha256(
                approval_signing_payload(approval)).hexdigest(),
        }
        self.store.append_chained_event(
            project_id=self.PROJECT_ID, event_type=self.EVENT_TYPE,
            actor=self.master_principal, payload=payload,
            expected_previous_digest=head, enforce_expected_head=True,
        )
        return snapshot

    def suspend(self, *, expected_revision: int, reason: str,
                authority_reference: str, trigger: str,
                approval: Approval, now: datetime | None = None) -> SuspensionSnapshot:
        return self._transition(
            SuspensionStatus.SUSPENDED, expected_revision=expected_revision,
            reason=reason, authority_reference=authority_reference, trigger=trigger,
            approval=approval, now=now,
        )

    def release(self, *, expected_revision: int, reason: str,
                authority_reference: str, trigger: str,
                approval: Approval, now: datetime | None = None) -> SuspensionSnapshot:
        current = self.current()
        if current is None or current.status != SuspensionStatus.SUSPENDED:
            raise ValueError("Emergency control is not suspended.")
        return self._transition(
            SuspensionStatus.ACTIVE, expected_revision=expected_revision,
            reason=reason, authority_reference=authority_reference, trigger=trigger,
            approval=approval, now=now,
        )
