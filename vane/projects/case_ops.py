"""Case work-item and timeline contracts for project operations."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
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
