from datetime import datetime, timezone
from vane.models import EvidenceRecord, Finding, Mission
from vane.projects.registry import Project
from vane.storage.repository import SQLiteRepository
from vane.storage.sqlite_store import SQLiteStore

def test_typed_repository_persists_domain_records_and_audit_chain(tmp_path):
    store = SQLiteStore(tmp_path / "data" / "vane.sqlite3")
    assert store.schema_version() == 2
    repository = SQLiteRepository(store)
    project = Project("p1", "Test Project", "master")
    repository.save_project(project)
    mission = Mission.create("p1", "Review approved surface")
    repository.save_mission(mission)
    loaded = repository.get_mission("p1", mission.mission_id)
    assert loaded.objective == mission.objective
    assert loaded.status == mission.status
    evidence = EvidenceRecord("e1", "p1", mission.mission_id, "http", "operator",
        datetime.now(timezone.utc), "a" * 64, authorization_id="auth-1")
    repository.save_evidence(evidence)
    assert repository.get_evidence("p1", "e1").content_digest == "a" * 64
    finding = Finding("f1", "p1", "Test finding", "Description", "low",
                      evidence_ids=["e1"])
    repository.save_finding(finding)
    assert repository.get_finding("p1", "f1").evidence_ids == ["e1"]
    assert store.verify_project_chain("p1")
    assert store.verify_project_integrity("p1")
    import sqlite3
    db = sqlite3.connect(store.path)
    db.execute("UPDATE domain_records SET record_json='{}' WHERE record_type='mission'")
    db.commit()
    db.close()
    assert store.verify_project_chain("p1")
    assert not store.verify_project_integrity("p1")

def test_read_only_store_verifies_without_allowing_mutation(tmp_path):
    import pytest
    path = tmp_path / "readonly.sqlite3"
    store = SQLiteStore(path)
    store.save_record(project_id="p1", record_type="project", record_id="p1",
        record={"name": "P", "owner": "master", "created_at": datetime.now(timezone.utc).isoformat()},
        actor="master")
    readonly = SQLiteStore(path, read_only=True)
    assert readonly.verify_project_integrity("p1")
    with pytest.raises(PermissionError):
        readonly.append_chained_event(project_id="p1", event_type="forbidden",
                                      actor="test", payload={})

def test_multi_record_write_rolls_back_as_one_transaction(tmp_path):
    import pytest
    store = SQLiteStore(tmp_path / "atomic.sqlite3")
    repository = SQLiteRepository(store)
    repository.save_project(Project("p1", "P1", "master"))
    records = [
        {"project_id":"p1", "record_type":"mission", "record_id":"m1",
         "record":{"mission_id":"m1"}, "actor":"master"},
        {"project_id":"missing", "record_type":"mission", "record_id":"m2",
         "record":{"mission_id":"m2"}, "actor":"master"},
    ]
    with pytest.raises(ValueError):
        store.save_records_atomic(records)
    assert store.get_record(project_id="p1", record_type="mission", record_id="m1") is None
    assert store.verify_project_integrity("p1")
