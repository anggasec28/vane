from datetime import datetime, timedelta, timezone
from vane.engine import VaneEngine
from vane.models import AuthorizationEnvelope, ScopeRule, MissionStatus

def test_engine_requires_explicit_mission_submission_and_authorization():
    engine = VaneEngine()
    engine.register_project("p1", "Assessment", "master")
    mission = engine.create_mission("p1", "Review approved web surface")
    assert mission.status == MissionStatus.DRAFT
    engine.submit_mission(mission)
    envelope = AuthorizationEnvelope("a1", "master", "p1",
        (ScopeRule("hostname", "example.com"),), ("http_metadata",),
        starts_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1), approval_id="approval-1")
    engine.authorize_mission(mission, envelope)
    assert mission.status == MissionStatus.AUTHORIZED
