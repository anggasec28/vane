from datetime import datetime, timedelta, timezone
from vane.models import AuthorizationEnvelope, ScopeRule
from vane.security.approval import Approval
from vane.security.digests import authorization_digest, capability_action_digest
from vane.security.policy_engine import PolicyEngine

class TestVerifier:
    def verify(self, approval):
        return approval.signature == "test-signature"

def test_capability_requires_mission_approval_and_action_approval_for_high_risk():
    now = datetime.now(timezone.utc)
    envelope = AuthorizationEnvelope("a1", "master", "p1",
        (ScopeRule("hostname", "example.com"),),
        ("http_metadata", "active_scan"),
        starts_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1), approval_id="mission-ap1")
    engine = PolicyEngine(TestVerifier())
    mission_approval = Approval("mission-ap1", "master", authorization_digest(envelope),
        "APPROVE", now, "key-1", "test-signature", envelope.expires_at)
    denied = engine.evaluate(envelope=envelope, locator="https://example.com",
        method="http_metadata")
    assert not denied.allowed
    read_allowed = engine.evaluate(envelope=envelope, locator="https://example.com",
        method="http_metadata", mission_approval=mission_approval)
    assert read_allowed.allowed
    active_denied = engine.evaluate(envelope=envelope, locator="https://example.com",
        method="active_scan", mission_approval=mission_approval)
    assert not active_denied.allowed
    action_approval = Approval("action-ap1", "master",
        capability_action_digest(envelope, "https://example.com", "active_scan"),
        "APPROVE", now, "key-1", "test-signature", envelope.expires_at)
    active_allowed = engine.evaluate(envelope=envelope, locator="https://example.com",
        method="active_scan", mission_approval=mission_approval,
        action_approval=action_approval)
    assert active_allowed.allowed
    wrong_action = Approval("action-ap2", "master", "0" * 64, "APPROVE",
        now, "key-1", "test-signature", envelope.expires_at)
    denied_wrong_action = engine.evaluate(envelope=envelope, locator="https://example.com",
        method="active_scan", mission_approval=mission_approval,
        action_approval=wrong_action)
    assert not denied_wrong_action.allowed
