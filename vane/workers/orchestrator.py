"""Bounded worker delegation lifecycle; Hermes sessions are managed externally."""
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from vane.models import Asset, AssetDisposition, AuthorizationEnvelope, Mission, MissionStatus
from vane.security.authorization import asset_is_in_scope
from vane.security.policy_engine import HIGH_RISK_METHODS
from vane.workers.contracts import WorkerTask, validate_worker_result
from vane.workers.registry import SpecialistRegistry


class WorkerTaskStatus(StrEnum):
    DELEGATED = "DELEGATED"
    COMPLETED = "COMPLETED"
    REVOKED = "REVOKED"
    REJECTED = "REJECTED"


@dataclass(slots=True)
class WorkerAssignment:
    task: WorkerTask
    status: WorkerTaskStatus = WorkerTaskStatus.DELEGATED
    result: dict[str, Any] | None = None
    history: list[dict[str, str]] = field(default_factory=list)


class WorkerOrchestrator:
    def __init__(self, registry: SpecialistRegistry | None = None) -> None:
        self._assignments: dict[str, WorkerAssignment] = {}
        self.registry = registry

    def delegate(self, task: WorkerTask, mission: Mission,
                 envelope: AuthorizationEnvelope, assets: dict[str, Asset]) -> WorkerAssignment:
        if mission.status not in {MissionStatus.AUTHORIZED, MissionStatus.RUNNING}:
            raise PermissionError("Parent mission is not in an executable state.")
        if mission.authorization_id != envelope.envelope_id or not envelope.is_time_valid():
            raise PermissionError("Worker delegation is not bound to the active parent authorization.")
        if task.parent_mission_id != mission.mission_id or task.approval_id != envelope.approval_id:
            raise PermissionError("Worker task parent or approval reference mismatch.")
        if not task.is_valid() or task.deadline > envelope.expires_at:
            raise PermissionError("Worker task is expired or outlives the parent authorization.")
        if self.registry is not None:
            self.registry.get(task.worker_profile)
        allowed_methods = {method.lower() for method in envelope.allowed_methods}
        if not {method.lower() for method in task.allowed_methods}.issubset(allowed_methods):
            raise PermissionError("Worker task methods exceed parent authorization.")
        if {method.lower() for method in task.allowed_methods} & HIGH_RISK_METHODS:
            raise PermissionError("High-risk worker methods require a separately approved delegation path.")
        if not task.allowed_asset_ids:
            raise PermissionError("Worker task must have a finite asset allowlist.")
        for asset_id in task.allowed_asset_ids:
            asset = assets.get(asset_id)
            if (asset is None or asset.disposition != AssetDisposition.IN_SCOPE
                    or not asset_is_in_scope(asset.locator, envelope.rules)):
                raise PermissionError(f"Worker asset is not explicitly in scope: {asset_id}")
        if task.task_id in self._assignments:
            raise ValueError(f"Worker task already exists: {task.task_id}")
        assignment = WorkerAssignment(task)
        assignment.history.append({"event": "DELEGATED", "worker": task.worker_profile})
        self._assignments[task.task_id] = assignment
        return assignment

    def restore(self, assignment: WorkerAssignment, *, replace: bool = False) -> WorkerAssignment:
        task_id = assignment.task.task_id
        existing = self._assignments.get(task_id)
        if existing is not None and existing != assignment and not replace:
            raise ValueError(f"Conflicting worker assignment already loaded: {task_id}")
        self._assignments[task_id] = assignment
        return assignment

    def get(self, task_id: str) -> WorkerAssignment:
        return self._assignments[task_id]

    def complete(self, task_id: str, result: dict[str, Any]) -> WorkerAssignment:
        assignment = self._assignments[task_id]
        if assignment.status != WorkerTaskStatus.DELEGATED:
            raise ValueError("Only a delegated task can be completed.")
        validate_worker_result(result, assignment.task)
        if set(result.get("methods", [])) - set(assignment.task.allowed_methods):
            raise PermissionError("Worker result reports methods outside delegated authority.")
        if self.registry is not None and "output" in result:
            self.registry.validate_output(assignment.task.worker_profile, result["output"])
        assignment.result = dict(result)
        assignment.status = WorkerTaskStatus.COMPLETED
        assignment.history.append({"event": "COMPLETED", "worker": assignment.task.worker_profile})
        return assignment

    def revoke(self, task_id: str, *, actor: str, reason: str) -> WorkerAssignment:
        assignment = self._assignments[task_id]
        if assignment.status != WorkerTaskStatus.DELEGATED:
            raise ValueError("Only a delegated task can be revoked.")
        assignment.status = WorkerTaskStatus.REVOKED
        assignment.history.append({"event": "REVOKED", "worker": actor, "reason": reason})
        return assignment
