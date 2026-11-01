from datetime import datetime, timedelta, timezone
from vane.engine import VaneEngine
from vane.models import AuthorizationEnvelope, EvidenceRecord, MissionStatus, ScopeRule
from vane.security.approval import Approval
from vane.security.digests import authorization_digest, mission_closure_digest
from vane.security.enforcement import SecurityEnforcer
from vane.security.policy_engine import PolicyEngine

class TestVerifier:
    def verify(self, approval):
        return approval.signature == "ok"

def test_evidence_drives_mission_completion():
    engine = VaneEngine(enforcer=SecurityEnforcer(PolicyEngine(TestVerifier())))
    engine.register_project("p1", "Project", "master")
    mission = engine.create_mission("p1", "Map authorized surface")
    mission.required_evidence = {"surface_map"}
    engine.submit_mission(mission)
    now = datetime.now(timezone.utc)
    envelope = AuthorizationEnvelope("auth1", "master", "p1",
        (ScopeRule("hostname", "example.com"),), ("http_metadata",),
        starts_at=now - timedelta(minutes=1), expires_at=now + timedelta(hours=1),
        approval_id="approval1")
    approval = Approval("approval1", "master", authorization_digest(envelope),
        "APPROVE", now, "master-key", "ok", envelope.expires_at)
    engine.authorize_mission(mission, envelope, approval)
    engine.start_mission(mission)
    import pytest
    from vane.errors import PolicyViolation
    outside = EvidenceRecord("e-out", "p1", mission.mission_id, "http_observation",
        "operator", now, "b" * 64, authorization_id="auth1",
        collection_method="http_metadata",
        metadata={"locator":"https://outside.test","method":"http_metadata"})
    with pytest.raises(PolicyViolation):
        engine.attach_evidence(mission, outside)
    evidence = EvidenceRecord("e1", "p1", mission.mission_id, "http_observation",
        "operator", now, "a" * 64, authorization_id="auth1",
        collection_method="http_metadata",
        metadata={"satisfies":["surface_map"],"locator":"https://example.com",
                  "method":"http_metadata"})
    engine.attach_evidence(mission, evidence)
    engine.request_evidence_review(mission)
    engine.complete_mission(mission)
    assert mission.status == MissionStatus.COMPLETED
    closure = Approval("closure1", "master", mission_closure_digest(mission),
        "APPROVE", datetime.now(timezone.utc), "master-key", "ok", envelope.expires_at)
    engine.close_mission(mission, envelope, closure)
    assert mission.status == MissionStatus.CLOSED

def test_mission_cannot_complete_with_missing_evidence():
    engine = VaneEngine()
    engine.register_project("p1", "Project", "master")
    mission = engine.create_mission("p1", "Map authorized surface")
    mission.required_evidence = {"surface_map"}
    mission.status = MissionStatus.EVIDENCE_REVIEW
    import pytest
    from vane.errors import PolicyViolation
    with pytest.raises(PolicyViolation):
        engine.complete_mission(mission)

def test_high_risk_evidence_requires_exact_action_approval():
    from vane.security.digests import capability_action_digest
    engine = VaneEngine(enforcer=SecurityEnforcer(PolicyEngine(TestVerifier())))
    engine.register_project("p3", "High Risk Project", "master")
    mission = engine.create_mission("p3", "Validate approved high-risk method")
    engine.submit_mission(mission)
    now = datetime.now(timezone.utc)
    envelope = AuthorizationEnvelope("auth3", "master", "p3",
        (ScopeRule("hostname", "example.com"),), ("http_metadata", "active_scan"),
        starts_at=now - timedelta(minutes=1), expires_at=now + timedelta(hours=1),
        approval_id="mission-ap3")
    mission_approval = Approval("mission-ap3", "master", authorization_digest(envelope),
        "APPROVE", now, "master-key", "ok", envelope.expires_at)
    engine.authorize_mission(mission, envelope, mission_approval)
    engine.start_mission(mission)
    denied = engine.authorize_observation(envelope, "https://example.com", "active_scan",
        mission_approval=mission_approval)
    assert not denied.allowed
    action_approval = Approval("action-ap3", "master",
        capability_action_digest(envelope, "https://example.com", "active_scan"),
        "APPROVE", now, "master-key", "ok", envelope.expires_at)
    allowed = engine.authorize_observation(envelope, "https://example.com", "active_scan",
        mission_approval=mission_approval, action_approval=action_approval)
    assert allowed.allowed
    evidence = EvidenceRecord("e3", "p3", mission.mission_id, "active_scan_observation",
        "operator", now, "c" * 64, authorization_id="auth3",
        collection_method="active_scan",
        metadata={"locator":"https://example.com","method":"active_scan",
                  "action_approval_id":"action-ap3"})
    engine.attach_evidence(mission, evidence)
