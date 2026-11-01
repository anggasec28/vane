from datetime import datetime, timedelta, timezone

from vane.projects.case_ops import (
    CaseWorkItem, SLAState, WorkItemStatus, evaluate_case_sla,
)


def test_case_sla_evaluates_overdue_without_mutating_item():
    now = datetime.now(timezone.utc)
    item = CaseWorkItem("w1", "p1", "m1", "Task", "owner",
        now - timedelta(hours=2), status=WorkItemStatus.IN_PROGRESS)
    result = evaluate_case_sla(item, now=now)
    assert result.state == SLAState.OVERDUE
    assert result.escalation_recommended is True
    assert result.suggested_escalation_level == 1
    assert item.status == WorkItemStatus.IN_PROGRESS


def test_completed_case_is_not_escalated():
    now = datetime.now(timezone.utc)
    item = CaseWorkItem("w2", "p1", "m1", "Done", "owner", now,
        status=WorkItemStatus.DONE, escalation_level=3)
    result = evaluate_case_sla(item, now=now)
    assert result.state == SLAState.COMPLETE
    assert result.escalation_recommended is False
    assert result.suggested_escalation_level == 3
