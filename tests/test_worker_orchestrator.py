from datetime import datetime, timedelta, timezone
import pytest
from vane.models import Asset, AssetDisposition, AuthorizationEnvelope, Mission, MissionStatus, ScopeRule
from vane.workers.contracts import WorkerTask
from vane.workers.orchestrator import WorkerOrchestrator, WorkerTaskStatus

def setup():
    now = datetime.now(timezone.utc)
    envelope = AuthorizationEnvelope("a1", "master", "p1",
        (ScopeRule("hostname", "example.com"),), ("http_metadata",),
        starts_at=now - timedelta(minutes=1), expires_at=now + timedelta(hours=1),
        approval_id="ap1")
    mission = Mission("m1", "p1", "review", status=MissionStatus.AUTHORIZED,
                      authorization_id="a1")
    asset = Asset("asset-1", "https://example.com", "hostname", AssetDisposition.IN_SCOPE)
    task = WorkerTask("t1", "m1", "web-worker", "passive review",
        ("http_metadata",), ("asset-1",), now + timedelta(minutes=30), "ap1")
    return envelope, mission, asset, task

def test_worker_delegation_is_bounded_and_result_is_checked():
    envelope, mission, asset, task = setup()
    orchestrator = WorkerOrchestrator()
    assignment = orchestrator.delegate(task, mission, envelope, {"asset-1": asset})
    assert assignment.status == WorkerTaskStatus.DELEGATED
    completed = orchestrator.complete("t1", {"task_id":"t1", "worker_profile":"web-worker",
        "asset_ids":["asset-1"], "methods":["http_metadata"],
        "output":{"type":"web_worker_result"}})
    assert completed.status == WorkerTaskStatus.COMPLETED

def test_worker_cannot_expand_parent_method_authority():
    envelope, mission, asset, task = setup()
    invalid = WorkerTask(task.task_id, task.parent_mission_id, task.worker_profile,
        task.objective, ("active_scan",), task.allowed_asset_ids, task.deadline, task.approval_id)
    with pytest.raises(PermissionError):
        WorkerOrchestrator().delegate(invalid, mission, envelope, {"asset-1": asset})
