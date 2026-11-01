from datetime import datetime, timedelta, timezone

from vane.intelligence.threat_intel import IntelConfidence, ThreatIntelRecord
from vane.storage.governance_repository import GovernanceRepository
from vane.storage.repository import SQLiteRepository
from vane.storage.sqlite_store import SQLiteStore


def test_internal_intelligence_ledger_is_not_a_user_project(tmp_path):
    store = SQLiteStore(tmp_path / "projects.sqlite3")
    governance = GovernanceRepository(store)
    now = datetime.now(timezone.utc)
    governance.save_threat_intel(ThreatIntelRecord(
        "intel-1", "feed", "https://feed.invalid/item", "Advisory", "Summary",
        now - timedelta(days=1), now, None, ("CVE-2099-0001",), (), (),
        IntelConfidence.MEDIUM,
    ))
    assert SQLiteRepository(store).list_projects() == []
