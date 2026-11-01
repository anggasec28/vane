"""Typed domain repositories backed by SQLiteStore."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any

from vane.models import (
    Asset, EvidenceRecord, EvidenceStatus, Finding, FindingStatus, Mission, MissionStatus,
)
from vane.security.approval import Approval
from vane.workers.contracts import WorkerTask
from vane.projects.registry import Project
from vane.storage.sqlite_store import SQLiteStore
from vane.evidence.manager import validate_evidence
from vane.findings.governance import validate_finding
from copy import deepcopy


class SQLiteRepository:
    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def save_project(self, project: Project, *, actor: str = "master") -> int:
        record = {"project_id": project.project_id, "name": project.name,
                  "owner": project.owner, "created_at": project.created_at.isoformat()}
        return self.store.save_record(project_id=project.project_id, record_type="project",
            record_id=project.project_id, record=record, actor=actor)

    def get_project(self, project_id: str) -> Project:
        result = self.store.get_record(project_id=project_id, record_type="project",
                                       record_id=project_id)
        if result is None:
            raise KeyError(project_id)
        record, _ = result
        return Project(record["project_id"], record["name"], record["owner"],
                       datetime.fromisoformat(record["created_at"]))

    def save_authorized_mission(self, mission: Mission, approval: Approval,
                                *, actor: str = "master") -> tuple[int, int]:
        mission_record = asdict(mission)
        mission_record["status"] = mission.status.value
        mission_record["required_evidence"] = sorted(mission.required_evidence)
        mission_record["completed_evidence"] = sorted(mission.completed_evidence)
        approval_record = asdict(approval)
        revisions = self.store.save_records_atomic([
            {"project_id": mission.project_id, "record_type": "approval",
             "record_id": approval.approval_id, "record": approval_record, "actor": actor},
            {"project_id": mission.project_id, "record_type": "mission",
             "record_id": mission.mission_id, "record": mission_record, "actor": actor},
        ])
        return revisions[0], revisions[1]

    def save_closed_mission(self, mission: Mission, approval: Approval,
                            *, actor: str = "master") -> tuple[int, int]:
        mission_record = asdict(mission)
        mission_record["status"] = mission.status.value
        mission_record["required_evidence"] = sorted(mission.required_evidence)
        mission_record["completed_evidence"] = sorted(mission.completed_evidence)
        approval_record = asdict(approval)
        revisions = self.store.save_records_atomic([
            {"project_id": mission.project_id, "record_type": "approval",
             "record_id": approval.approval_id, "record": approval_record, "actor": actor},
            {"project_id": mission.project_id, "record_type": "mission",
             "record_id": mission.mission_id, "record": mission_record, "actor": actor},
        ])
        return revisions[0], revisions[1]

    def save_mission(self, mission: Mission, *, actor: str = "master") -> int:
        record = asdict(mission)
        record["status"] = mission.status.value
        record["required_evidence"] = sorted(mission.required_evidence)
        record["completed_evidence"] = sorted(mission.completed_evidence)
        return self.store.save_record(project_id=mission.project_id, record_type="mission",
            record_id=mission.mission_id, record=record, actor=actor)

    def get_mission(self, project_id: str, mission_id: str) -> Mission:
        result = self.store.get_record(project_id=project_id, record_type="mission",
                                       record_id=mission_id)
        if result is None:
            raise KeyError(mission_id)
        record, _ = result
        return Mission(
            mission_id=record["mission_id"], project_id=record["project_id"],
            objective=record["objective"], status=MissionStatus(record["status"]),
            authorization_id=record.get("authorization_id"),
            required_evidence=set(record.get("required_evidence", [])),
            completed_evidence=set(record.get("completed_evidence", [])),
            blockers=list(record.get("blockers", [])), history=list(record.get("history", [])),
        )

    def list_missions(self, project_id: str) -> list[Mission]:
        records = self.store.list_records(project_id=project_id, record_type="mission")
        return [Mission(
            mission_id=r["mission_id"], project_id=r["project_id"], objective=r["objective"],
            status=MissionStatus(r["status"]), authorization_id=r.get("authorization_id"),
            required_evidence=set(r.get("required_evidence", [])),
            completed_evidence=set(r.get("completed_evidence", [])),
            blockers=list(r.get("blockers", [])), history=list(r.get("history", [])),
        ) for r in records]

    def save_evidence(self, evidence: EvidenceRecord, *, actor: str = "collector") -> int:
        validate_evidence(evidence)
        record = asdict(evidence)
        record["status"] = evidence.status.value
        return self.store.save_record(project_id=evidence.project_id, record_type="evidence",
            record_id=evidence.evidence_id, record=record, actor=actor)

    def save_finding(self, finding: Finding, *, actor: str = "analyst") -> int:
        if finding.status in {FindingStatus.VALIDATED, FindingStatus.ACCEPTED}:
            evidence: dict[str, EvidenceRecord] = {}
            for evidence_id in finding.evidence_ids:
                try:
                    evidence[evidence_id] = self.get_evidence(finding.project_id, evidence_id)
                except KeyError:
                    continue
            validate_finding(deepcopy(finding), evidence)
        record = asdict(finding)
        record["status"] = finding.status.value
        return self.store.save_record(project_id=finding.project_id, record_type="finding",
            record_id=finding.finding_id, record=record, actor=actor)

    def get_evidence(self, project_id: str, evidence_id: str) -> EvidenceRecord:
        result = self.store.get_record(project_id=project_id, record_type="evidence",
                                       record_id=evidence_id)
        if result is None:
            raise KeyError(evidence_id)
        record, _ = result
        record["observed_at"] = datetime.fromisoformat(record["observed_at"])
        record["status"] = EvidenceStatus(record["status"])
        return EvidenceRecord(**record)

    def list_evidence(self, project_id: str) -> list[EvidenceRecord]:
        records = self.store.list_records(project_id=project_id, record_type="evidence")
        result: list[EvidenceRecord] = []
        for record in records:
            record["observed_at"] = datetime.fromisoformat(record["observed_at"])
            record["status"] = EvidenceStatus(record["status"])
            result.append(EvidenceRecord(**record))
        return result

    def get_finding(self, project_id: str, finding_id: str) -> Finding:
        result = self.store.get_record(project_id=project_id, record_type="finding",
                                       record_id=finding_id)
        if result is None:
            raise KeyError(finding_id)
        record, _ = result
        record["created_at"] = datetime.fromisoformat(record["created_at"])
        record["status"] = FindingStatus(record["status"])
        return Finding(**record)

    def list_findings(self, project_id: str) -> list[Finding]:
        records = self.store.list_records(project_id=project_id, record_type="finding")
        result: list[Finding] = []
        for record in records:
            record["created_at"] = datetime.fromisoformat(record["created_at"])
            record["status"] = FindingStatus(record["status"])
            result.append(Finding(**record))
        return result

    def save_asset(self, project_id: str, asset: Asset, *, actor: str = "mapper") -> int:
        record = asdict(asset)
        record["disposition"] = asset.disposition.value
        return self.store.save_record(project_id=project_id, record_type="asset",
            record_id=asset.asset_id, record=record, actor=actor)

    def save_approval(self, project_id: str, approval: Approval, *, actor: str = "master") -> int:
        record = asdict(approval)
        return self.store.save_record(project_id=project_id, record_type="approval",
            record_id=approval.approval_id, record=record, actor=actor)

    def get_asset(self, project_id: str, asset_id: str) -> Asset:
        result = self.store.get_record(project_id=project_id, record_type="asset",
                                       record_id=asset_id)
        if result is None:
            raise KeyError(asset_id)
        record, _ = result
        from vane.models import AssetDisposition
        record["disposition"] = AssetDisposition(record["disposition"])
        return Asset(**record)

    def get_approval(self, project_id: str, approval_id: str) -> Approval:
        result = self.store.get_record(project_id=project_id, record_type="approval",
                                       record_id=approval_id)
        if result is None:
            raise KeyError(approval_id)
        record, _ = result
        record["decided_at"] = datetime.fromisoformat(record["decided_at"])
        if record.get("expires_at"):
            record["expires_at"] = datetime.fromisoformat(record["expires_at"])
        return Approval(**record)

    def save_worker_task(self, project_id: str, task: WorkerTask,
                         *, actor: str = "master") -> int:
        record = asdict(task)
        return self.store.save_record(project_id=project_id, record_type="worker_task",
            record_id=task.task_id, record=record, actor=actor)

    def get_worker_task(self, project_id: str, task_id: str) -> WorkerTask:
        result = self.store.get_record(project_id=project_id, record_type="worker_task",
                                       record_id=task_id)
        if result is None:
            raise KeyError(task_id)
        record, _ = result
        record["deadline"] = datetime.fromisoformat(record["deadline"])
        record["allowed_methods"] = tuple(record["allowed_methods"])
        record["allowed_asset_ids"] = tuple(record["allowed_asset_ids"])
        return WorkerTask(**record)

    def list_assets(self, project_id: str) -> list[Asset]:
        records = self.store.list_records(project_id=project_id, record_type="asset")
        from vane.models import AssetDisposition
        return [Asset(
            asset_id=record["asset_id"], locator=record["locator"],
            asset_type=record["asset_type"],
            disposition=AssetDisposition(record["disposition"]),
            discovered_from=record.get("discovered_from"), notes=record.get("notes", ""),
        ) for record in records]
