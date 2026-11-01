"""Typed domain models shared by the engine.

The models deliberately avoid implicit authorization. Constructing an Asset, Mission,
or EvidenceRecord never grants permission to interact with it.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any
from uuid import uuid4

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

class MissionStatus(StrEnum):
    DRAFT = "DRAFT"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    AUTHORIZED = "AUTHORIZED"
    RUNNING = "RUNNING"
    BLOCKED = "BLOCKED"
    EVIDENCE_REVIEW = "EVIDENCE_REVIEW"
    COMPLETED = "COMPLETED"
    CLOSED = "CLOSED"
    REJECTED = "REJECTED"

class AssetDisposition(StrEnum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    NOT_INSPECTED = "NOT_INSPECTED"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"

class EvidenceStatus(StrEnum):
    OBSERVED = "OBSERVED"
    DERIVED = "DERIVED"
    CORROBORATED = "CORROBORATED"
    DISPUTED = "DISPUTED"
    INSUFFICIENT = "INSUFFICIENT"

class FindingStatus(StrEnum):
    DRAFT = "DRAFT"
    TRIAGED = "TRIAGED"
    VALIDATED = "VALIDATED"
    ACCEPTED = "ACCEPTED"
    DISPUTED = "DISPUTED"
    CLOSED = "CLOSED"

@dataclass(frozen=True, slots=True)
class ScopeRule:
    kind: str
    value: str
    include_subdomains: bool = False
    ports: tuple[int, ...] = ()
    notes: str = ""

@dataclass(frozen=True, slots=True)
class AuthorizationEnvelope:
    envelope_id: str
    principal: str
    project_id: str
    rules: tuple[ScopeRule, ...]
    allowed_methods: tuple[str, ...]
    prohibited_methods: tuple[str, ...] = ()
    starts_at: datetime | None = None
    expires_at: datetime | None = None
    approval_id: str | None = None
    revoked: bool = False

    def is_time_valid(self, now: datetime | None = None) -> bool:
        current = now or utc_now()
        if self.revoked or not self.approval_id:
            return False
        if self.starts_at is None or self.expires_at is None:
            return False
        if self.starts_at >= self.expires_at:
            return False
        return self.starts_at <= current < self.expires_at

@dataclass(slots=True)
class Asset:
    asset_id: str
    locator: str
    asset_type: str
    disposition: AssetDisposition = AssetDisposition.UNKNOWN
    discovered_from: str | None = None
    notes: str = ""

@dataclass(slots=True)
class EvidenceRecord:
    evidence_id: str
    project_id: str
    mission_id: str
    kind: str
    source: str
    observed_at: datetime
    content_digest: str
    status: EvidenceStatus = EvidenceStatus.OBSERVED
    authorization_id: str | None = None
    collection_method: str = "manual"
    limitations: list[str] = field(default_factory=list)
    parent_evidence_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass(slots=True)
class Finding:
    finding_id: str
    project_id: str
    title: str
    description: str
    severity: str
    status: FindingStatus = FindingStatus.DRAFT
    evidence_ids: list[str] = field(default_factory=list)
    affected_assets: list[str] = field(default_factory=list)
    root_cause: str | None = None
    confidence: str = "unknown"
    remediation: str = ""
    created_at: datetime = field(default_factory=utc_now)

@dataclass(slots=True)
class Mission:
    mission_id: str
    project_id: str
    objective: str
    status: MissionStatus = MissionStatus.DRAFT
    authorization_id: str | None = None
    required_evidence: set[str] = field(default_factory=set)
    completed_evidence: set[str] = field(default_factory=set)
    blockers: list[str] = field(default_factory=list)
    history: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def create(cls, project_id: str, objective: str) -> "Mission":
        return cls(mission_id=str(uuid4()), project_id=project_id, objective=objective)
