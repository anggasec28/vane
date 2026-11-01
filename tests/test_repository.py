from datetime import datetime, timezone
from vane.models import EvidenceRecord, Finding, Mission
from vane.projects.registry import Project
from vane.storage.repository import SQLiteRepository
from vane.storage.sqlite_store import SQLiteStore

def test_typed_repository_persists_domain_records_and_audit_chain(tmp_path):
    store = SQLiteStore(tmp_path / "data" / "vane.sqlite3")
    assert store.schema_version() == 1
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
