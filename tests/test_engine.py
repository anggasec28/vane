from datetime import datetime, timedelta, timezone
from vane.engine import VaneEngine
from vane.models import AuthorizationEnvelope, ScopeRule, MissionStatus
from vane.security.approval import Approval
from vane.security.digests import authorization_digest
from vane.security.enforcement import SecurityEnforcer
from vane.security.policy_engine import PolicyEngine

class TestVerifier:
    def verify(self, approval):
        return approval.signature == "test-signature"

def test_engine_requires_explicit_mission_submission_and_bound_signed_approval():
    engine = VaneEngine(enforcer=SecurityEnforcer(PolicyEngine(TestVerifier())))
    engine.register_project("p1", "Assessment", "master")
    mission = engine.create_mission("p1", "Review approved web surface")
    assert mission.status == MissionStatus.DRAFT
    engine.submit_mission(mission)
    envelope = AuthorizationEnvelope("a1", "master", "p1",
        (ScopeRule("hostname", "example.com"),), ("http_metadata",),
        starts_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1), approval_id="approval-1")
    approval = Approval("approval-1", "master", authorization_digest(envelope), "APPROVE",
                        datetime.now(timezone.utc), "master-key-1", "test-signature",
                        envelope.expires_at)
    engine.authorize_mission(mission, envelope, approval)
    assert mission.status == MissionStatus.AUTHORIZED
