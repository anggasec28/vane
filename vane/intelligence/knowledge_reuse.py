"""Fail-closed cross-mission knowledge reuse gate.

Reusable knowledge is a lead, never target-specific evidence or authorization.
This module evaluates metadata and references only; it never transfers raw project data.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import StrEnum

from vane.lifecycle.policy import DataClass


class KnowledgeForm(StrEnum):
    PUBLIC = "PUBLIC"
    SANITIZED_GENERALIZED = "SANITIZED_GENERALIZED"
    RAW_PROJECT_DATA = "RAW_PROJECT_DATA"


class KnowledgeReuseStatus(StrEnum):
    ALLOW_AS_LEAD = "ALLOW_AS_LEAD"
    DENY = "DENY"


@dataclass(frozen=True, slots=True)
class KnowledgeCandidate:
    knowledge_id: str
    source_project_id: str
    target_project_id: str
    data_class: DataClass
    form: KnowledgeForm
    provenance_reference: str
    ownership_reference: str
    quality_review_reference: str
    reuse_authorization_reference: str
    applicability_reference: str
    sanitized_record_reference: str | None = None
    sanitization_method: str | None = None
    sanitization_reviewer: str | None = None
    expires_at: datetime | None = None
    revoked: bool = False


@dataclass(frozen=True, slots=True)
class KnowledgeReuseDecision:
    status: KnowledgeReuseStatus
    knowledge_id: str
    source_project_id: str
    target_project_id: str
    reasons: tuple[str, ...]
    authoritative_evidence: bool = False
    grants_authorization: bool = False


def evaluate_knowledge_reuse(candidate: KnowledgeCandidate, *,
                             now: datetime | None = None) -> KnowledgeReuseDecision:
    """Allow only public or explicitly sanitized/generalized knowledge with all gates met."""
    current = now or datetime.now(timezone.utc)
    reasons: list[str] = []
    if not candidate.knowledge_id.strip():
        reasons.append("Knowledge identity is missing.")
    if not candidate.source_project_id.strip() or not candidate.target_project_id.strip():
        reasons.append("Source and target project identities are required.")
    if candidate.source_project_id == candidate.target_project_id:
        reasons.append("Cross-mission reuse requires distinct source and target projects.")
    if candidate.revoked:
        reasons.append("Knowledge reuse has been revoked.")
    if candidate.expires_at is not None and candidate.expires_at <= current:
        reasons.append("Knowledge reuse authorization or applicability has expired.")
    required = (
        candidate.provenance_reference, candidate.ownership_reference,
        candidate.quality_review_reference, candidate.reuse_authorization_reference,
        candidate.applicability_reference,
    )
    if any(not isinstance(value, str) or not value.strip() for value in required):
        reasons.append("Provenance, ownership, quality, authorization, and applicability references are mandatory.")
    if candidate.form == KnowledgeForm.PUBLIC:
        if candidate.data_class != DataClass.PUBLIC:
            reasons.append("PUBLIC form requires PUBLIC data classification.")
    elif candidate.form == KnowledgeForm.SANITIZED_GENERALIZED:
        if candidate.data_class != DataClass.INTERNAL:
            reasons.append("Sanitized generalized reuse is limited to INTERNAL source material.")
        if not all(isinstance(value, str) and value.strip() for value in (
            candidate.sanitized_record_reference, candidate.sanitization_method,
            candidate.sanitization_reviewer,
        )):
            reasons.append("Sanitized reuse requires a reviewed sanitization record, method, and reviewer.")
    else:
        reasons.append("Raw project data is never reusable across mission boundaries.")
    if candidate.data_class in {
        DataClass.CONFIDENTIAL, DataClass.SECRET, DataClass.EVIDENCE, DataClass.UNKNOWN,
    }:
        reasons.append(f"{candidate.data_class.value} data cannot be reused across project boundaries.")
    status = KnowledgeReuseStatus.DENY if reasons else KnowledgeReuseStatus.ALLOW_AS_LEAD
    return KnowledgeReuseDecision(
        status=status, knowledge_id=candidate.knowledge_id,
        source_project_id=candidate.source_project_id,
        target_project_id=candidate.target_project_id,
        reasons=tuple(reasons or [
            "All reuse gates passed. Treat this material only as a contextual lead; collect target-specific evidence."
        ]),
    )
