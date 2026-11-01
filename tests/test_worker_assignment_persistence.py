from datetime import datetime, timedelta, timezone

from vane.engine import VaneEngine
from vane.models import Asset, AuthorizationEnvelope, MissionStatus, ScopeRule
from vane.security.approval import Approval
from vane.security.digests import authorization_digest
from vane.security.enforcement import SecurityEnforcer
from vane.security.policy_engine import PolicyEngine
from vane.storage.repository import SQLiteRepository
from vane.storage.sqlite_store import SQLiteStore
from vane.workers.contracts import WorkerTask
from vane.workers.orchestrator import WorkerTaskStatus


class TestVerifier:
    def verify(self, approval):
        return approval.signature == "valid"


def test_worker_assignment_survives_engine_restart(tmp_path):
    repository = SQLiteRepository(SQLiteStore(tmp_path / "worker.sqlite3"))
    enforcer = SecurityEnforcer(PolicyEngine(TestVerifier()))
    engine = VaneEngine(enforcer=enforcer, repository=repository)
    engine.register_project("p1", "Project", "master")
    mission = engine.create_mission("p1", "Map supplied authorized asset")
    engine.submit_mission(mission)
    now = datetime.now(timezone.utc)
    envelope = AuthorizationEnvelope("auth1", "master", "p1",
        (ScopeRule("hostname", "example.com"),), ("http_metadata",),
        starts_at=now - timedelta(minutes=1),
        expires_at=now + timedelta(hours=1), approval_id="approval1")
    approval = Approval("approval1", "master", authorization_digest(envelope),
        "APPROVE", now, "key1", "valid", envelope.expires_at)
    engine.authorize_mission(mission, envelope, approval)
    asset = Asset("asset1", "https://example.com", "hostname")
    engine.save_asset(envelope, asset)
    task = WorkerTask("task1", mission.mission_id, "asset-surface-mapper",
        "Normalize supplied asset", ("http_metadata",), ("asset1",),
        now + timedelta(minutes=30), "approval1")
    engine.delegate_worker(task, mission, envelope, {"asset1": asset})

    restarted = VaneEngine(enforcer=enforcer, repository=repository)
    completed = restarted.complete_worker_task("task1", {
        "task_id": "task1", "worker_profile": "asset-surface-mapper",
        "asset_ids": ["asset1"], "methods": ["http_metadata"],
        "output": {
            "type": "asset_mapping_result", "assets": [], "source_links": [],
            "dispositions": [], "unresolved_items": [], "limitations": [],
        },
    })
    assert completed.status == WorkerTaskStatus.COMPLETED
    persisted = repository.get_worker_assignment("p1", "task1")
    assert persisted.status == WorkerTaskStatus.COMPLETED
