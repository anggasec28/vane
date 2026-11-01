from datetime import datetime, timezone

import pytest

from vane.decisions.ledger import DecisionLedger, DecisionStatus
from vane.storage.sqlite_store import SQLiteStore


def _project(store):
    store.save_record(
        project_id="p1", record_type="project", record_id="p1", actor="master",
        record={"project_id": "p1", "name": "Project", "owner": "master",
                "created_at": datetime.now(timezone.utc).isoformat()},
    )


def test_decision_ledger_preserves_immutable_transition_history(tmp_path):
    store = SQLiteStore(tmp_path / "decisions.sqlite3")
    _project(store)
    ledger = DecisionLedger(store)
    first = ledger.create(
        project_id="p1", decision_id="d1", title="Scope interpretation",
        rationale="Evidence is incomplete.", actor="vane",
        authority_reference="master-approval-17", trigger="mission-intake",
        evidence_references=("ev-1",), uncertainty="Ownership requires confirmation",
    )
    assert first.status == DecisionStatus.UNRESOLVED

    second = ledger.transition(
        project_id="p1", decision_id="d1", expected_revision=1,
        target=DecisionStatus.VALID, actor="master",
        authority_reference="master-approval-18", trigger="new-evidence",
        rationale="The scope owner confirmed the asset.", evidence_references=("ev-1", "ev-2"),
        uncertainty="",
    )
    assert second.revision == 2
    assert ledger.get("p1", "d1") == second

    history = [event for event in store.list_events("p1", limit=None)
               if event["event_type"] == DecisionLedger.EVENT_TYPE]
    assert len(history) == 2
    assert history[0]["payload"]["snapshot"]["status"] == "UNRESOLVED"
    assert history[1]["payload"]["snapshot"]["status"] == "VALID"
    assert store.verify_project_integrity("p1")


def test_decision_ledger_rejects_stale_revision_and_invalid_transition(tmp_path):
    store = SQLiteStore(tmp_path / "decisions.sqlite3")
    _project(store)
    ledger = DecisionLedger(store)
    ledger.create(project_id="p1", decision_id="d1", title="D", rationale="R",
                  actor="vane", authority_reference="master-1", trigger="intake")
    with pytest.raises(ValueError, match="Invalid decision transition"):
        ledger.transition(project_id="p1", decision_id="d1", expected_revision=1,
                          target=DecisionStatus.REVALIDATION_REQUIRED, actor="master",
                          authority_reference="master-2", trigger="recheck", rationale="R")
    with pytest.raises(ValueError, match="revision changed"):
        ledger.transition(project_id="p1", decision_id="d1", expected_revision=0,
                          target=DecisionStatus.VALID, actor="master",
                          authority_reference="master-2", trigger="evidence", rationale="R")


def test_decision_ledger_requires_authority_and_supersession_link(tmp_path):
    store = SQLiteStore(tmp_path / "decisions.sqlite3")
    _project(store)
    ledger = DecisionLedger(store)
    with pytest.raises(ValueError, match="authority"):
        ledger.create(project_id="p1", decision_id="d1", title="D", rationale="R",
                      actor="vane", authority_reference="", trigger="intake")
    created = ledger.create(project_id="p1", decision_id="d1", title="D", rationale="R",
                            actor="vane", authority_reference="master-1", trigger="intake")
    with pytest.raises(ValueError, match="superseding decision"):
        ledger.transition(project_id="p1", decision_id="d1", expected_revision=1,
                          target=DecisionStatus.SUPERSEDED, actor="master",
                          authority_reference="master-2", trigger="replace", rationale="R")

def test_event_append_compare_and_swap_rejects_stale_chain_head(tmp_path):
    store = SQLiteStore(tmp_path / "cas.sqlite3")
    _project(store)
    store.append_chained_event(project_id="p1", event_type="baseline", actor="master",
                               payload={"version": 1})
    with pytest.raises(ValueError, match="head changed"):
        store.append_chained_event(
            project_id="p1", event_type="decision.snapshot", actor="vane",
            payload={"snapshot": {}}, expected_previous_digest=None,
            enforce_expected_head=True,
        )
    current_head = store.list_events("p1", limit=None)[-1]["digest"]
    store.append_chained_event(
        project_id="p1", event_type="decision.snapshot", actor="vane",
        payload={"snapshot": {}}, expected_previous_digest=current_head,
        enforce_expected_head=True,
    )
    assert store.verify_project_chain("p1")

def test_decisions_from_multiple_projects_share_one_authoritative_ledger(tmp_path):
    store = SQLiteStore(tmp_path / "central-ledger.sqlite3")
    _project(store)
    store.save_record(
        project_id="p2", record_type="project", record_id="p2", actor="master",
        record={"project_id": "p2", "name": "Project 2", "owner": "master",
                "created_at": datetime.now(timezone.utc).isoformat()},
    )
    ledger = DecisionLedger(store)
    ledger.create(project_id="p1", decision_id="same-id", title="P1 decision",
                  rationale="P1 rationale", actor="vane",
                  authority_reference="master-p1", trigger="intake")
    ledger.create(project_id="p2", decision_id="same-id", title="P2 decision",
                  rationale="P2 rationale", actor="vane",
                  authority_reference="master-p2", trigger="intake")
    assert ledger.get("p1", "same-id").title == "P1 decision"
    assert ledger.get("p2", "same-id").title == "P2 decision"
    assert len(ledger.list_all_decisions()) == 2
    assert store.verify_project_integrity(DecisionLedger.LEDGER_PROJECT_ID)
