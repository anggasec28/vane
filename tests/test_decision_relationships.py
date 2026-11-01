from datetime import datetime, timezone

import pytest

from vane.decisions.ledger import DecisionLedger, DecisionStatus
from vane.decisions.relationships import DecisionRelationshipIndex, RelationshipType
from vane.storage.sqlite_store import SQLiteStore


def make_project(store, project_id):
    store.save_record(
        project_id=project_id, record_type="project", record_id=project_id, actor="master",
        record={"project_id": project_id, "name": project_id, "owner": "master",
                "created_at": datetime.now(timezone.utc).isoformat()},
    )


def test_relationship_index_rebuilds_dependencies_supersession_and_shared_evidence(tmp_path):
    store = SQLiteStore(tmp_path / "relationships.sqlite3")
    make_project(store, "p1")
    ledger = DecisionLedger(store)
    ledger.create(project_id="p1", decision_id="d1", title="Base", rationale="R",
                  actor="vane", authority_reference="master-1", trigger="intake",
                  evidence_references=("ev-shared",))
    ledger.create(project_id="p1", decision_id="d2", title="Dependent", rationale="R",
                  actor="vane", authority_reference="master-2", trigger="intake",
                  dependency_decision_ids=("d1",), evidence_references=("ev-shared",))
    ledger.create(project_id="p1", decision_id="d3", title="Replacement", rationale="R",
                  actor="vane", authority_reference="master-3", trigger="intake")
    ledger.transition(project_id="p1", decision_id="d2", expected_revision=1,
                      target=DecisionStatus.SUSPENDED, actor="master",
                      authority_reference="master-3a", trigger="dependency-change",
                      rationale="Suspend dependent decision pending revalidation.")
    ledger.transition(project_id="p1", decision_id="d1", expected_revision=1,
                      target=DecisionStatus.SUPERSEDED, actor="master",
                      authority_reference="master-4", trigger="replace", rationale="R",
                      superseded_by_decision_id="d3", superseded_by_revision=1)
    index = DecisionRelationshipIndex.rebuild(ledger, "p1")
    pairs = {(r.source_decision_id, r.target_decision_id, r.relationship)
             for r in index.relationships}
    assert ("d2", "d1", RelationshipType.DEPENDS_ON) in pairs
    assert ("d1", "d3", RelationshipType.SUPERSEDES) in pairs
    assert ("d1", "d2", RelationshipType.SHARES_EVIDENCE) in pairs
    assert index.related("d3", depth=2) == ("d1", "d2")


def test_relationship_index_is_project_scoped_and_depth_bounded(tmp_path):
    store = SQLiteStore(tmp_path / "relationships-scope.sqlite3")
    make_project(store, "p1")
    make_project(store, "p2")
    ledger = DecisionLedger(store)
    for project_id in ("p1", "p2"):
        ledger.create(project_id=project_id, decision_id="same", title="D", rationale="R",
                      actor="vane", authority_reference="master", trigger="intake")
    index = DecisionRelationshipIndex.rebuild(ledger, "p1")
    assert index.snapshot("same").project_id == "p1"
    with pytest.raises(ValueError, match="depth"):
        index.related("same", depth=4)
    with pytest.raises(KeyError):
        index.snapshot("not-present")
