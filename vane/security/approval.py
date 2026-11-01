"""Explicit human approval records issued by a trusted host authority."""
from dataclasses import dataclass
from datetime import datetime, timezone

@dataclass(frozen=True, slots=True)
class Approval:
    approval_id: str
    approver: str
    subject_digest: str
    decision: str
    decided_at: datetime
    expires_at: datetime | None = None
    rationale: str = ""

    def is_valid_for(self, subject_digest: str, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        return (bool(self.approval_id and self.approver and self.subject_digest)
                and self.decision == "APPROVE"
                and self.subject_digest == subject_digest
                and self.decided_at <= current
                and (self.expires_at is None or current < self.expires_at))
