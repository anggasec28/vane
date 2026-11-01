"""Explicit human approval records."""
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
        return self.decision == "APPROVE" and self.subject_digest == subject_digest and (
            self.expires_at is None or current < self.expires_at)
