"""Hierarchical evidence-weighted arbitration without majority voting or numeric scores."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Iterable


class ArbitrationStatus(StrEnum):
    RESOLVED = "RESOLVED"
    UNRESOLVED = "UNRESOLVED"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True, slots=True)
class EvidenceQuality:
    evidence_id: str
    independence_group: str
    provenance: int
    integrity: int
    independence: int
    reproducibility: int
    freshness: int
    relevance: int

    def __post_init__(self) -> None:
        if (not isinstance(self.evidence_id, str) or not self.evidence_id.strip()
                or not isinstance(self.independence_group, str) or not self.independence_group.strip()):
            raise ValueError("Evidence ID and independence group are required.")
        for name in ("provenance", "integrity", "independence",
                     "reproducibility", "freshness", "relevance"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 3:
                raise ValueError(f"{name} must be an integer from 0 to 3.")

    def dominates(self, other: "EvidenceQuality") -> bool:
        """Strict Pareto dominance; no arbitrary weights or compensating scores."""
        left = (self.provenance, self.integrity, self.independence,
                self.reproducibility, self.freshness, self.relevance)
        right = (other.provenance, other.integrity, other.independence,
                 other.reproducibility, other.freshness, other.relevance)
        return all(a >= b for a, b in zip(left, right)) and any(
            a > b for a, b in zip(left, right)
        )


@dataclass(frozen=True, slots=True)
class ClaimAssessment:
    claim_id: str
    supporting_evidence: tuple[EvidenceQuality, ...]
    contradicting_evidence: tuple[EvidenceQuality, ...] = ()
    scope_valid: bool = True
    policy_valid: bool = True
    authority_valid: bool = True
    mission_priority: int = 0
    impact: int = 0
    specialist_competence: int = 0

    def __post_init__(self) -> None:
        if not isinstance(self.claim_id, str) or not self.claim_id.strip():
            raise ValueError("claim_id is required.")
        for name in ("mission_priority", "impact", "specialist_competence"):
            value = getattr(self, name)
            if type(value) is not int or not 0 <= value <= 3:
                raise ValueError(f"{name} must be an integer from 0 to 3.")
        ids = [item.evidence_id for item in
               (*self.supporting_evidence, *self.contradicting_evidence)]
        if len(ids) != len(set(ids)):
            raise ValueError("Evidence IDs must be unique within a claim assessment.")


@dataclass(frozen=True, slots=True)
class ArbitrationResult:
    status: ArbitrationStatus
    selected_claim_id: str | None
    considered_claim_ids: tuple[str, ...]
    excluded_claim_ids: tuple[str, ...]
    rationale: tuple[str, ...]


def _unique_dominant(items: Iterable[EvidenceQuality]) -> EvidenceQuality | None:
    values = tuple(items)
    if not values:
        return None
    winners = [
        candidate for candidate in values
        if all(candidate == other or candidate.dominates(other) for other in values)
    ]
    return winners[0] if len(winners) == 1 else None


def arbitrate_claims(claims: Iterable[ClaimAssessment]) -> ArbitrationResult:
    """Resolve only when one admissible claim has unambiguous dominant evidence.

    Scope, policy, and authority are hard gates. Mission priority, impact, and
    specialist competence are recorded context, never substitutes for evidence.
    Incomparable evidence, ties, common-source contradictions, or unsupported
    claims remain UNRESOLVED.
    """
    items = tuple(claims)
    if not items:
        return ArbitrationResult(ArbitrationStatus.UNRESOLVED, None, (), (),
                                ("No claims were supplied.",))
    ids = [item.claim_id for item in items]
    if len(ids) != len(set(ids)):
        raise ValueError("Claim IDs must be unique.")

    excluded = tuple(sorted(item.claim_id for item in items
        if not (item.scope_valid and item.policy_valid and item.authority_valid)))
    admissible = tuple(item for item in items
        if item.scope_valid and item.policy_valid and item.authority_valid)
    if not admissible:
        return ArbitrationResult(
            ArbitrationStatus.BLOCKED, None, tuple(sorted(ids)), excluded,
            ("Every candidate failed a scope, policy, or authority gate.",),
        )

    profiles: dict[str, EvidenceQuality] = {}
    reasons: list[str] = []
    for item in admissible:
        if not item.supporting_evidence:
            reasons.append(f"{item.claim_id}: no supporting evidence.")
            continue
        support = _unique_dominant(item.supporting_evidence)
        if support is None:
            reasons.append(f"{item.claim_id}: supporting evidence is tied or incomparable.")
            continue
        unresolved_contradictions = [
            contradiction for contradiction in item.contradicting_evidence
            if (contradiction.independence_group == support.independence_group
                or not support.dominates(contradiction))
        ]
        if unresolved_contradictions:
            reasons.append(
                f"{item.claim_id}: material contradictory evidence is not independently "
                "and strictly outweighed."
            )
            continue
        profiles[item.claim_id] = support

    if reasons or not profiles:
        return ArbitrationResult(
            ArbitrationStatus.UNRESOLVED, None, tuple(sorted(ids)), excluded,
            tuple(reasons or ["No claim has a defensible dominant evidence profile."]),
        )

    winners = []
    for claim_id, quality in profiles.items():
        competitors = [(other_id, other_quality) for other_id, other_quality in profiles.items()
                       if other_id != claim_id]
        if all(quality.independence_group != other_quality.independence_group
               and quality.dominates(other_quality)
               for _, other_quality in competitors):
            winners.append(claim_id)
    if len(winners) != 1:
        return ArbitrationResult(
            ArbitrationStatus.UNRESOLVED, None, tuple(sorted(ids)), excluded,
            ("No unique claim strictly dominates all competing evidence profiles; "
             "preserve competing hypotheses and obtain further authorized evidence.",),
        )
    return ArbitrationResult(
        ArbitrationStatus.RESOLVED, winners[0], tuple(sorted(ids)), excluded,
        ("One admissible claim has a unique, strictly dominant evidence profile; "
         "no unresolved material contradiction remains.",),
    )
