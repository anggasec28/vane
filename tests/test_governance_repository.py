from datetime import datetime, timedelta, timezone

from vane.findings.remediation import RemediationAction
from vane.intelligence.threat_intel import IntelConfidence, ThreatIntelRecord
from vane.models import Finding, FindingStatus
from vane.projects.case_ops import CaseTimelineEvent, CaseWorkItem
from vane.storage.governance_repository import GovernanceRepository
from vane.storage.sqlite_store import SQLiteStore


def test_case_records_and_global_intel_persist(tmp_path):
    store = SQLiteStore(tmp_path / "governance.sqlite3")
    store.save_record(project_id="p1", record_type="project", record_id="p1",
        actor="master", record={"project_id":"p1","name":"Project","owner":"master",
                                "created_at":datetime.now(timezone.utc).isoformat()})
    repo = GovernanceRepository(store)
    due = datetime.now(timezone.utc) + timedelta(days=2)
    item = CaseWorkItem("w1", "p1", "m1", "Review evidence", "analyst", due)
    repo.save_work_item(item)
    assert repo.list_work_items("p1")[0].item_id == "w1"

    event = CaseTimelineEvent("ev1", "p1", "m1", "NOTE", "master",
        datetime.now(timezone.utc), "Review opened")
    repo.save_timeline_event(event)
    assert repo.list_timeline_events("p1", "m1")[0].summary == "Review opened"

    now = datetime.now(timezone.utc)
    intel = ThreatIntelRecord("ti1", "feed1", "https://feed.invalid/advisory",
        "Advisory", "Supplied advisory summary", now - timedelta(days=1), now,
        now + timedelta(days=10), ("CVE-2099-0001",), (), (),
        IntelConfidence.HIGH, ("web",))
    repo.save_threat_intel(intel)
    assert repo.list_threat_intel()[0].intel_id == "ti1"


def test_remediation_and_report_records_persist(tmp_path):
    store = SQLiteStore(tmp_path / "governance2.sqlite3")
    store.save_record(project_id="p1", record_type="project", record_id="p1",
        actor="master", record={"project_id":"p1","name":"Project","owner":"master",
                                "created_at":datetime.now(timezone.utc).isoformat()})
    repo = GovernanceRepository(store)
    finding = Finding("f1", "p1", "Finding", "Description", "high",
                      status=FindingStatus.ACCEPTED)
    action = RemediationAction("r1", "f1", "Fix", "Apply the approved fix", "owner",
        "high", (), ("Verify the control",))
    repo.save_remediation_action("p1", action, {"f1": finding})
    assert repo.list_remediation_actions("p1")[0].action_id == "r1"
