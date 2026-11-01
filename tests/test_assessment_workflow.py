from datetime import datetime, timedelta, timezone

import pytest

from vane.assessment.workflow import build_assessment_workflow, workflow_plan_payload
from vane.errors import AuthorizationError
from vane.models import Asset, AssetDisposition, AuthorizationEnvelope, ScopeRule


def envelope(methods=("http_metadata",)):
    now = datetime.now(timezone.utc)
    return AuthorizationEnvelope(
        "auth-1", "master", "project-1",
        (ScopeRule("hostname", "example.com", include_subdomains=True),),
        methods, starts_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1), approval_id="approval-1",
    )


def test_builds_eleven_phase_plan_without_execution():
    assets = [Asset("a1", "https://example.com", "web", AssetDisposition.IN_SCOPE)]
    steps = build_assessment_workflow(envelope(), assets, platform="web2")
    payload = workflow_plan_payload(steps)
    assert len(steps) == 11
    assert steps[0].phase == "MISSION_COMPREHENSION"
    assert steps[-1].phase == "REPORTING_KNOWLEDGE"
    assert payload["execution_performed"] is False
    assert payload["target_requests_performed"] is False
    assert steps[6].execution_mode == "REQUIRES_APPROVED_ADAPTER"
    assert steps[6].asset_ids == ("a1",)


def test_rejects_expired_or_unapproved_envelope():
    auth = envelope()
    expired = AuthorizationEnvelope(
        auth.envelope_id, auth.principal, auth.project_id, auth.rules,
        auth.allowed_methods, starts_at=datetime.now(timezone.utc) - timedelta(days=2),
        expires_at=datetime.now(timezone.utc) - timedelta(days=1), approval_id=auth.approval_id,
    )
    with pytest.raises(AuthorizationError):
        build_assessment_workflow(expired, [
            Asset("a1", "https://example.com", "web", AssetDisposition.IN_SCOPE)
        ])


def test_rejects_out_of_scope_asset_marked_in_scope():
    with pytest.raises(AuthorizationError):
        build_assessment_workflow(envelope(), [
            Asset("a1", "https://outside.test", "web", AssetDisposition.IN_SCOPE)
        ])


def test_requires_at_least_one_explicitly_in_scope_asset():
    with pytest.raises(AuthorizationError):
        build_assessment_workflow(envelope(), [
            Asset("a1", "https://example.com", "web", AssetDisposition.UNKNOWN)
        ])


def test_rejects_unknown_platform():
    with pytest.raises(ValueError):
        build_assessment_workflow(envelope(), [
            Asset("a1", "https://example.com", "web", AssetDisposition.IN_SCOPE)
        ], platform="ftp")
