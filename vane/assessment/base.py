"""Shared assessment contracts; adapters must be explicitly configured."""
from dataclasses import dataclass
from typing import Protocol
from vane.models import AuthorizationEnvelope, EvidenceRecord

@dataclass(frozen=True, slots=True)
class ObservationRequest:
    locator: str
    method: str
    purpose: str
    authorization: AuthorizationEnvelope

@dataclass(frozen=True, slots=True)
class ObservationResult:
    success: bool
    summary: str
    evidence: EvidenceRecord | None = None
    blocked_reason: str | None = None

class ObservationAdapter(Protocol):
    def observe(self, request: ObservationRequest) -> ObservationResult: ...
