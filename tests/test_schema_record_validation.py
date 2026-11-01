from datetime import datetime, timezone

import pytest

from vane.errors import PolicyViolation
from vane.validation.schema_contracts import validate_all_schemas, validate_domain_record


def test_repository_schemas_are_meta_valid():
    assert len(validate_all_schemas()) == 9


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
