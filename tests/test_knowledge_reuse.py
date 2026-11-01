from datetime import datetime, timedelta, timezone

import pytest

from vane.intelligence.knowledge_reuse import (
    KnowledgeCandidate, KnowledgeForm, KnowledgeReuseStatus, evaluate_knowledge_reuse,
)
from vane.lifecycle.policy import DataClass


def candidate(**overrides):
    values = {
        "knowledge_id": "knowledge-1",
        "source_project_id": "project-a",
        "target_project_id": "project-b",
        "data_class": DataClass.INTERNAL,
        "form": KnowledgeForm.SANITIZED_GENERALIZED,
        "provenance_reference": "prov-1",
        "ownership_reference": "owner-review-1",
        "quality_review_reference": "quality-review-1",
        "reuse_authorization_reference": "master-approval-1",
        "applicability_reference": "applicability-review-1",
        "sanitized_record_reference": "sanitized-1",
        "sanitization_method": "remove-identifiers-generalize-patterns",
        "sanitization_reviewer": "independent-reviewer",
    }
    values.update(overrides)
    return KnowledgeCandidate(**values)


def test_sanitized_internal_knowledge_is_allowed_only_as_non_authoritative_lead():
    result = evaluate_knowledge_reuse(candidate())
    assert result.status == KnowledgeReuseStatus.ALLOW_AS_LEAD
    assert result.authoritative_evidence is False
    assert result.grants_authorization is False


def test_public_knowledge_requires_public_classification():
    result = evaluate_knowledge_reuse(candidate(
        data_class=DataClass.PUBLIC, form=KnowledgeForm.PUBLIC,
        sanitized_record_reference=None, sanitization_method=None,
        sanitization_reviewer=None,
    ))
    assert result.status == KnowledgeReuseStatus.ALLOW_AS_LEAD


@pytest.mark.parametrize("data_class", [
    DataClass.CONFIDENTIAL, DataClass.SECRET, DataClass.EVIDENCE, DataClass.UNKNOWN,
])
def test_restricted_or_unknown_data_is_never_reusable(data_class):
    result = evaluate_knowledge_reuse(candidate(data_class=data_class))
    assert result.status == KnowledgeReuseStatus.DENY


def test_raw_project_data_and_missing_sanitization_are_denied():
    assert evaluate_knowledge_reuse(candidate(form=KnowledgeForm.RAW_PROJECT_DATA)).status == KnowledgeReuseStatus.DENY
    assert evaluate_knowledge_reuse(candidate(sanitization_reviewer=None)).status == KnowledgeReuseStatus.DENY


def test_missing_ownership_provenance_authorization_or_applicability_is_denied():
    for field in ("provenance_reference", "ownership_reference",
                  "quality_review_reference", "reuse_authorization_reference",
                  "applicability_reference"):
        assert evaluate_knowledge_reuse(candidate(**{field: ""})).status == KnowledgeReuseStatus.DENY


def test_revoked_expired_and_same_project_knowledge_is_denied():
    now = datetime.now(timezone.utc)
    assert evaluate_knowledge_reuse(candidate(revoked=True), now=now).status == KnowledgeReuseStatus.DENY
    assert evaluate_knowledge_reuse(candidate(expires_at=now - timedelta(seconds=1)), now=now).status == KnowledgeReuseStatus.DENY
    assert evaluate_knowledge_reuse(candidate(target_project_id="project-a"), now=now).status == KnowledgeReuseStatus.DENY
