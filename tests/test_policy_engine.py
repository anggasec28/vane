from datetime import datetime, timedelta, timezone
from vane.models import AuthorizationEnvelope, ScopeRule
from vane.security.approval import Approval
from vane.security.digests import capability_action_digest
from vane.security.policy_engine import PolicyEngine

def test_capability_requires_approval_bound_to_exact_action():
    envelope = AuthorizationEnvelope("a1", "master", "p1",
        (ScopeRule("hostname", "example.com"),), ("http_metadata",),
        starts_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1), approval_id="ap1")
    engine = PolicyEngine()
    denied = engine.evaluate(envelope=envelope, locator="https://example.com",
        method="http_metadata", requires_human_approval=True)
    assert not denied.allowed
    approval = Approval("ap1", "master",
        capability_action_digest(envelope, "https://example.com", "http_metadata"),
        "APPROVE", datetime.now(timezone.utc))
    allowed = engine.evaluate(envelope=envelope, locator="https://example.com",
        method="http_metadata", requires_human_approval=True, approval=approval)
    assert allowed.allowed
    wrong_action = engine.evaluate(envelope=envelope, locator="https://example.com",
        method="http_metadata", requires_human_approval=True,
        approval=Approval("ap1", "master", "0" * 64, "APPROVE", datetime.now(timezone.utc)))
    assert not wrong_action.allowed
