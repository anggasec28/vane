from datetime import datetime, timedelta, timezone
import pytest
from vane.workers.contracts import WorkerTask, validate_worker_result

def task():
    return WorkerTask("t1", "m1", "web-worker", "review", ("http_metadata",),
        ("asset-1",), datetime.now(timezone.utc) + timedelta(hours=1), "approval-1")

def test_worker_cannot_return_unassigned_asset():
    with pytest.raises(PermissionError):
        validate_worker_result({"task_id": "t1", "worker_profile": "web-worker",
            "asset_ids": ["asset-2"]}, task())
