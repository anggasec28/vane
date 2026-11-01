import pytest

from vane.decisions.arbitration import (
    ArbitrationStatus, ClaimAssessment, EvidenceQuality, arbitrate_claims,
)


def quality(evidence_id, group, values):
    return EvidenceQuality(evidence_id, group, *values)


def test_arbitration_resolves_only_unique_dominant_evidence():
    strong = quality("e1", "source-a", (3, 3, 3, 3, 3, 3))
    weaker = quality("e2", "source-b", (2, 2, 2, 2, 2, 2))
    result = arbitrate_claims((
        ClaimAssessment("claim-a", (strong,)),
        ClaimAssessment("claim-b", (weaker,)),
    ))
    assert result.status == ArbitrationStatus.RESOLVED
    assert result.selected_claim_id == "claim-a"


def test_arbitration_preserves_incomparable_evidence_without_weighted_vote():
    provenance_heavy = quality("e1", "source-a", (3, 3, 1, 2, 2, 3))
    independence_heavy = quality("e2", "source-b", (2, 3, 3, 3, 2, 2))
    result = arbitrate_claims((
        ClaimAssessment("claim-a", (provenance_heavy,)),
        ClaimAssessment("claim-b", (independence_heavy,)),
    ))
    assert result.status == ArbitrationStatus.UNRESOLVED
    assert result.selected_claim_id is None


def test_arbitration_blocks_candidates_outside_authority_gates():
    result = arbitrate_claims((
        ClaimAssessment("claim-a", (quality("e1", "s1", (3, 3, 3, 3, 3, 3)),),
                        scope_valid=False),
    ))
    assert result.status == ArbitrationStatus.BLOCKED
    assert result.excluded_claim_ids == ("claim-a",)


def test_arbitration_does_not_hide_material_contradiction():
    support = quality("e1", "source-a", (3, 3, 3, 3, 3, 3))
    contradiction = quality("e2", "source-a", (1, 3, 3, 2, 2, 3))
    result = arbitrate_claims((
        ClaimAssessment("claim-a", (support,), (contradiction,)),
    ))
    assert result.status == ArbitrationStatus.UNRESOLVED


def test_evidence_quality_rejects_out_of_range_values_and_duplicate_claim_ids():
    with pytest.raises(ValueError):
        quality("e1", "s1", (4, 3, 3, 3, 3, 3))
    evidence = quality("e1", "s1", (3, 3, 3, 3, 3, 3))
    with pytest.raises(ValueError, match="unique"):
        arbitrate_claims((
            ClaimAssessment("same", (evidence,)),
            ClaimAssessment("same", (quality("e2", "s2", (2, 2, 2, 2, 2, 2)),)),
        ))

def test_arbitration_rejects_boolean_quality_and_priority_values():
    with pytest.raises(ValueError, match="integer"):
        quality("e1", "s1", (True, 3, 3, 3, 3, 3))
    evidence = quality("e1", "s1", (3, 3, 3, 3, 3, 3))
    with pytest.raises(ValueError, match="integer"):
        ClaimAssessment("claim-a", (evidence,), mission_priority=True)
