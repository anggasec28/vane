"""Case work-item and timeline contracts for project operations."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from typing import Iterable

from vane.errors import PolicyViolation


class WorkItemStatus(StrEnum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    DONE = "DONE"
    CANCELLED = "CANCELLED"


@dataclass(frozen=True, slots=True)
class CaseWorkItem:
    item_id: str
    project_id: str
    mission_id: str
    title: str
    owner: str
    due_at: datetime
    dependencies: tuple[str, ...] = ()
    status: WorkItemStatus = WorkItemStatus.OPEN
    escalation_level: int = 0


@dataclass(frozen=True, slots=True)
class CaseTimelineEvent:
    event_id: str
    project_id: str
    mission_id: str
    event_type: str
    actor: str
    occurred_at: datetime
    summary: str
    references: tuple[str, ...] = ()


def validate_work_items(items: Iterable[CaseWorkItem]) -> None:
    records = tuple(items)
    by_id = {item.item_id: item for item in records}
    if len(by_id) != len(records):
        raise PolicyViolation("Case work-item IDs must be unique.")
    for item in records:
        if not all((item.item_id, item.project_id, item.mission_id,
                    item.title.strip(), item.owner.strip())):
            raise PolicyViolation("Case work item is missing required identity or ownership.")
        if item.due_at.tzinfo is None or item.due_at.utcoffset() is None:
            raise PolicyViolation("Case work-item due_at must be timezone-aware.")
        if item.escalation_level < 0:
            raise PolicyViolation("Escalation level cannot be negative.")
        if item.item_id in item.dependencies:
            raise PolicyViolation("A work item cannot depend on itself.")
        missing = set(item.dependencies) - by_id.keys()
        if missing:
            raise PolicyViolation("Unknown work-item dependencies: " + ", ".join(sorted(missing)))
    graph = {item.item_id: set(item.dependencies) for item in records}
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(item_id: str) -> None:
        if item_id in visiting:
            raise PolicyViolation("Case work-item dependency cycle detected.")
        if item_id in visited:
            return
        visiting.add(item_id)
        for dependency in graph[item_id]:
            visit(dependency)
        visiting.remove(item_id)
        visited.add(item_id)

    for item_id in graph:
        visit(item_id)


def validate_timeline_event(event: CaseTimelineEvent) -> None:
    if not all((event.event_id, event.project_id, event.mission_id,
                event.event_type, event.actor, event.summary.strip())):
        raise PolicyViolation("Case timeline event is missing required fields.")
    if event.occurred_at.tzinfo is None or event.occurred_at.utcoffset() is None:
        raise PolicyViolation("Case timeline timestamp must be timezone-aware.")
    if event.occurred_at > datetime.now(timezone.utc):
        raise PolicyViolation("Case timeline event cannot be future-dated.")


class SLAState(StrEnum):
    ON_TRACK = "ON_TRACK"
    DUE_SOON = "DUE_SOON"
    OVERDUE = "OVERDUE"
    BLOCKED = "BLOCKED"
    COMPLETE = "COMPLETE"


@dataclass(frozen=True, slots=True)
class CaseSLAResult:
    item_id: str
    state: SLAState
    seconds_to_due: int | None
    escalation_recommended: bool
    suggested_escalation_level: int


def evaluate_case_sla(item: CaseWorkItem, *, now: datetime | None = None,
                      warning_window: timedelta = timedelta(hours=24)) -> CaseSLAResult:
    """Evaluate SLA state without scheduling, mutating, or auto-escalating a case."""
    current = now or datetime.now(timezone.utc)
    if current.tzinfo is None or current.utcoffset() is None:
        raise PolicyViolation("SLA evaluation time must be timezone-aware.")
    if item.due_at.tzinfo is None or item.due_at.utcoffset() is None:
        raise PolicyViolation("Case due_at must be timezone-aware.")
    if warning_window < timedelta(0):
        raise ValueError("warning_window cannot be negative.")
    if item.status in {WorkItemStatus.DONE, WorkItemStatus.CANCELLED}:
        return CaseSLAResult(item.item_id, SLAState.COMPLETE, None, False, item.escalation_level)
    if item.status == WorkItemStatus.BLOCKED:
        return CaseSLAResult(item.item_id, SLAState.BLOCKED, None, True, item.escalation_level + 1)
    remaining = item.due_at - current
    seconds = int(remaining.total_seconds())
    if seconds < 0:
        return CaseSLAResult(item.item_id, SLAState.OVERDUE, seconds, True,
                             item.escalation_level + 1)
    if remaining <= warning_window:
        return CaseSLAResult(item.item_id, SLAState.DUE_SOON, seconds, False,
                             item.escalation_level)
    return CaseSLAResult(item.item_id, SLAState.ON_TRACK, seconds, False,
                         item.escalation_level)
