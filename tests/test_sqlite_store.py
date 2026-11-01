from vane.storage.sqlite_store import SQLiteStore

def test_sqlite_event_chain_is_verified(tmp_path):
    store = SQLiteStore(tmp_path / "vane.sqlite3")
    store.append_chained_event(project_id="p1", event_type="mission.created",
                               actor="master", payload={"mission_id": "m1"})
    store.append_chained_event(project_id="p1", event_type="mission.approved",
                               actor="master", payload={"mission_id": "m1"})
    assert store.verify_project_chain("p1")
    events = store.list_events("p1")
    assert len(events) == 2
    assert events[1]["previous_digest"] == events[0]["digest"]
