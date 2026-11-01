from datetime import datetime, timezone

from vane.lifecycle.policy import DataClass, LifecycleAction, LifecycleContext
from vane.lifecycle.review import create_lifecycle_review
from vane.storage.governance_repository import GovernanceRepository
from vane.storage.sqlite_store import SQLiteStore


def test_unknown_ownership_is_preserved_and_audited(tmp_path):
    store = SQLiteStore(tmp_path / "lifecycle.sqlite3")
    store.save_record(project_id="p1", record_type="project", record_id="p1",
        actor="master", record={"project_id":"p1","name":"P","owner":"master",
                                "created_at":datetime.now(timezone.utc).isoformat()})
    repo = GovernanceRepository(store)
    review = create_lifecycle_review(
        review_id="lr1", project_id="p1", record_id="evidence-1",
        context=LifecycleContext(DataClass.UNKNOWN, False, ownership_known=False,
                                 retention_expired=True),
        rationale="Ownership is not established.", actor="master")
    assert review.action == LifecycleAction.PRESERVE
    repo.save_lifecycle_review(review)
    assert repo.list_lifecycle_reviews("p1")[0].action == LifecycleAction.PRESERVE


def test_expired_data_only_becomes_pending_disposal_review():
    review = create_lifecycle_review(
        review_id="lr2", project_id="p1", record_id="record-2",
        context=LifecycleContext(DataClass.INTERNAL, False, ownership_known=True,
                                 retention_expired=True),
        rationale="Retention window elapsed; approval still required.", actor="master")
    assert review.action == LifecycleAction.DISPOSE_PENDING_APPROVAL
    assert review.approval_reference is None
