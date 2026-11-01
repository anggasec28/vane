"""Approval records and trusted verifier interface.

Approval records are data. They become trusted only after an injected verifier validates
their Ed25519 signature against a configured public key.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

@dataclass(frozen=True, slots=True)
class Approval:
    approval_id: str
    approver: str
    subject_digest: str
    decision: str
    decided_at: datetime
    key_id: str
    signature: str
    expires_at: datetime | None = None
    rationale: str = ""

    def is_valid_for(self, subject_digest: str, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        return (bool(self.approval_id and self.approver and self.subject_digest
                     and self.key_id and self.signature)
                and self.decision == "APPROVE"
                and self.subject_digest == subject_digest
                and self.decided_at <= current
                and (self.expires_at is None or current < self.expires_at))

class ApprovalVerifier(Protocol):
    def verify(self, approval: Approval) -> bool: ...
