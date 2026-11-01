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

    def __post_init__(self) -> None:
        for name in ("task_id", "parent_mission_id", "worker_profile", "objective", "approval_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string.")
        if not isinstance(self.deadline, datetime) or self.deadline.tzinfo is None or self.deadline.utcoffset() is None:
            raise ValueError("Worker deadline must be timezone-aware.")
        for name in ("allowed_methods", "allowed_asset_ids"):
            values = getattr(self, name)
            if not isinstance(values, tuple) or not values:
                raise ValueError(f"{name} must be a non-empty tuple.")
            if any(not isinstance(item, str) or not item.strip() for item in values):
                raise ValueError(f"{name} must contain only non-empty strings.")
            if len({item.casefold() for item in values}) != len(values):
                raise ValueError(f"{name} must not contain duplicates.")

    def is_valid(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(timezone.utc)
        if current.tzinfo is None or current.utcoffset() is None:
            raise ValueError("Worker validation time must be timezone-aware.")
        return current < self.deadline


def validate_worker_result(result: dict[str, Any], task: WorkerTask) -> None:
    """Validate identity, asset/method confinement, and presence of a typed specialist output."""
    if not isinstance(result, dict):
        raise TypeError("Worker result must be an object.")
    if not task.is_valid():
        raise PermissionError("Worker task is expired.")
    if result.get("task_id") != task.task_id:
        raise ValueError("Worker result does not match delegated task.")
    if result.get("worker_profile") != task.worker_profile:
        raise ValueError("Worker identity mismatch.")
    asset_ids = result.get("asset_ids")
    if (not isinstance(asset_ids, list)
            or any(not isinstance(item, str) or not item for item in asset_ids)):
        raise ValueError("Worker result asset_ids must be a list of non-empty strings.")
    if set(asset_ids) - set(task.allowed_asset_ids):
        raise PermissionError("Worker result references assets outside delegated task.")
    methods = result.get("methods")
    if (not isinstance(methods, list)
            or any(not isinstance(item, str) or not item for item in methods)):
        raise ValueError("Worker result methods must be a list of non-empty strings.")
    allowed = {item.casefold() for item in task.allowed_methods}
    if {item.casefold() for item in methods} - allowed:
        raise PermissionError("Worker result reports methods outside delegated authority.")
    output = result.get("output")
    if not isinstance(output, dict):
        raise ValueError("Worker result requires a typed output object.")
