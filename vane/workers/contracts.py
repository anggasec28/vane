"""Bounded worker task contracts. Workers inherit, never expand, parent authority."""
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

@dataclass(frozen=True, slots=True)
class WorkerTask:
    task_id: str
    parent_mission_id: str
    worker_profile: str
    objective: str
    allowed_methods: tuple[str, ...]
    allowed_asset_ids: tuple[str, ...]
    deadline: datetime
    approval_id: str

    def is_valid(self, now: datetime | None = None) -> bool:
        return (bool(self.task_id and self.parent_mission_id and self.approval_id)
                and bool(self.allowed_methods) and bool(self.allowed_asset_ids)
                and (now or datetime.now(timezone.utc)) < self.deadline)

def validate_worker_result(result: dict[str, Any], task: WorkerTask) -> None:
    if not task.is_valid():
        raise PermissionError("Worker task is expired or incomplete.")
    if result.get("task_id") != task.task_id:
        raise ValueError("Worker result does not match delegated task.")
    if result.get("worker_profile") != task.worker_profile:
        raise ValueError("Worker identity mismatch.")
    if set(result.get("asset_ids", [])) - set(task.allowed_asset_ids):
        raise PermissionError("Worker result references assets outside delegated task.")
