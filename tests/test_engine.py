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

def test_mission_authorization_and_approval_persist_together(tmp_path):
    from vane.storage.repository import SQLiteRepository
    from vane.storage.sqlite_store import SQLiteStore
    repository = SQLiteRepository(SQLiteStore(tmp_path / "vane.sqlite3"))
    engine = VaneEngine(enforcer=SecurityEnforcer(PolicyEngine(TestVerifier())),
                        repository=repository)
    engine.register_project("p2", "Persistent Project", "master")
    mission = engine.create_mission("p2", "Review approved surface")
    engine.submit_mission(mission)
    now = datetime.now(timezone.utc)
    envelope = AuthorizationEnvelope("a2", "master", "p2",
        (ScopeRule("hostname", "example.org"),), ("http_metadata",),
        starts_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1), approval_id="approval-2")
    approval = Approval("approval-2", "master", authorization_digest(envelope), "APPROVE",
        now, "master-key-1", "test-signature", envelope.expires_at)
    engine.authorize_mission(mission, envelope, approval)
    persisted = repository.get_mission("p2", mission.mission_id)
    assert persisted.status == MissionStatus.AUTHORIZED
    assert repository.get_approval("p2", "approval-2").subject_digest == authorization_digest(envelope)
    assert repository.get_authorization("p2", "a2").envelope_id == "a2"
    assert repository.store.verify_project_integrity("p2")
    restarted = VaneEngine(repository=repository)
    assert restarted.get_mission("p2", mission.mission_id).status == MissionStatus.AUTHORIZED

def test_evidence_attachment_after_restart_reloads_signed_authorization(tmp_path):
    from vane.storage.repository import SQLiteRepository
    from vane.storage.sqlite_store import SQLiteStore
    repository = SQLiteRepository(SQLiteStore(tmp_path / "resume.sqlite3"))
    engine = VaneEngine(enforcer=SecurityEnforcer(PolicyEngine(TestVerifier())),
                        repository=repository)
    engine.register_project("p3", "Resume Project", "master")
    mission = engine.create_mission("p3", "Observe approved host")
    engine.submit_mission(mission)
    now = datetime.now(timezone.utc)
    envelope = AuthorizationEnvelope("a3", "master", "p3",
        (ScopeRule("hostname", "example.net"),), ("http_metadata",),
        starts_at=now - timedelta(minutes=1), expires_at=now + timedelta(hours=1),
        approval_id="approval-3")
    approval = Approval("approval-3", "master", authorization_digest(envelope),
        "APPROVE", now, "master-key-1", "test-signature", envelope.expires_at)
    engine.authorize_mission(mission, envelope, approval)
    engine.start_mission(mission)
    restarted = VaneEngine(enforcer=SecurityEnforcer(PolicyEngine(TestVerifier())),
                           repository=repository)
    resumed_mission = restarted.get_mission("p3", mission.mission_id)
    evidence = EvidenceRecord("e3", "p3", mission.mission_id, "http_observation",
        "operator", now, "d" * 64, authorization_id="a3",
        collection_method="http_metadata",
        metadata={"locator":"https://example.net","method":"http_metadata"})
    restarted.attach_evidence(resumed_mission, evidence)
    assert repository.get_evidence("p3", "e3").authorization_id == "a3"
