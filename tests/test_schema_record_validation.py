from datetime import datetime, timezone

import pytest

from vane.errors import PolicyViolation
from vane.validation.schema_contracts import validate_all_schemas, validate_domain_record


def test_repository_schemas_are_meta_valid():
    assert len(validate_all_schemas()) == 17


def test_typed_project_record_passes_schema():
    validate_domain_record("project", {
        "project_id": "p1", "name": "Project", "owner": "master",
        "created_at": datetime.now(timezone.utc),
    })


def test_mission_history_is_excluded_from_public_schema_contract():
    validate_domain_record("mission", {
        "mission_id": "m1", "project_id": "p1", "objective": "review",
        "status": "DRAFT", "authorization_id": None,
        "required_evidence": set(), "completed_evidence": set(),
        "blockers": [], "history": [{"event": "created"}],
    })


def test_invalid_project_record_is_rejected():
    with pytest.raises(PolicyViolation):
        validate_domain_record("project", {"project_id": "p1"})



def test_every_persisted_record_type_has_a_canonical_schema():
    from vane.storage.sqlite_store import SQLiteStore
    from vane.validation.schema_contracts import SCHEMA_BY_RECORD_TYPE

    assert set(SCHEMA_BY_RECORD_TYPE) == SQLiteStore.ALLOWED_RECORD_TYPES


def test_worker_assignment_schema_validates_nested_task_and_history():
    validate_domain_record("worker_assignment", {
        "task": {
            "task_id": "t1", "parent_mission_id": "m1",
            "worker_profile": "asset-surface-mapper", "objective": "Map supplied asset",
            "allowed_methods": ["http_metadata"], "allowed_asset_ids": ["asset-1"],
            "deadline": "2030-01-01T00:00:00+00:00", "approval_id": "approval-1",
        },
        "status": "DELEGATED", "result": None,
        "history": [{"event": "DELEGATED", "worker": "asset-surface-mapper"}],
    })


def test_case_and_lifecycle_records_are_schema_checked():
    validate_domain_record("case_work_item", {
        "item_id": "w1", "project_id": "p1", "mission_id": "m1",
        "title": "Review", "owner": "master", "due_at": "2030-01-01T00:00:00+00:00",
        "dependencies": [], "status": "OPEN", "escalation_level": 0,
    })
    validate_domain_record("lifecycle_review", {
        "review_id": "r1", "project_id": "p1", "record_id": "e1",
        "data_class": "UNKNOWN", "project_active": False, "disputed": False,
        "legal_or_contractual_hold": False, "ownership_known": False,
        "retention_expired": True, "action": "PRESERVE",
        "rationale": "Ownership unknown", "actor": "master",
        "reviewed_at": "2030-01-01T00:00:00+00:00", "approval_reference": None,
    })
