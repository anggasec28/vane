from datetime import datetime, timedelta, timezone

import pytest

from vane.workers.catalog import default_specialist_registry
from vane.workers.contracts import WorkerTask, validate_worker_result


def task(**overrides):
    values = {
        "task_id": "t1",
        "parent_mission_id": "m1",
        "worker_profile": "web2-assessment-analyst",
        "objective": "Review supplied in-scope web assets",
        "allowed_methods": ("http_metadata",),
        "allowed_asset_ids": ("asset-1",),
        "deadline": datetime.now(timezone.utc) + timedelta(hours=1),
        "approval_id": "approval-1",
    }
    values.update(overrides)
    return WorkerTask(**values)


def valid_result(**overrides):
    result = {
        "task_id": "t1",
        "worker_profile": "web2-assessment-analyst",
        "asset_ids": ["asset-1"],
        "methods": ["HTTP_METADATA"],
        "output": {
            "type": "web2_assessment_result",
            "scope_basis": "signed envelope",
            "attack_surface_model": {},
            "observations": [],
            "hypotheses": [],
            "evidence_gaps": [],
            "limitations": [],
        },
    }
    result.update(overrides)
    return result


def test_worker_cannot_return_unassigned_asset():
    with pytest.raises(PermissionError, match="outside delegated task"):
        validate_worker_result(valid_result(asset_ids=["asset-2"]), task())


def test_worker_result_must_match_identity_and_declared_methods():
    with pytest.raises(ValueError, match="identity"):
        validate_worker_result(valid_result(worker_profile="other"), task())
    with pytest.raises(PermissionError, match="outside delegated authority"):
        validate_worker_result(valid_result(methods=["exploit_validation"]), task())


def test_worker_result_requires_typed_output_and_valid_lists():
    with pytest.raises(ValueError, match="typed output"):
        validate_worker_result(valid_result(output=None), task())
    with pytest.raises(ValueError, match="methods must be a list"):
        validate_worker_result(valid_result(methods="http_metadata"), task())


def test_worker_task_rejects_naive_deadline_empty_and_duplicate_authority():
    with pytest.raises(ValueError, match="timezone-aware"):
        task(deadline=datetime(2030, 1, 1))
    with pytest.raises(ValueError, match="allowed_methods"):
        task(allowed_methods=())
    with pytest.raises(ValueError, match="duplicates"):
        task(allowed_asset_ids=("asset-1", "ASSET-1"))


def test_worker_result_must_satisfy_registered_specialist_output_contract():
    result = valid_result()
    result["output"] = {"type": "web2_assessment_result"}
    with pytest.raises(Exception, match="missing fields"):
        default_specialist_registry().validate_output(task().worker_profile, result["output"])
