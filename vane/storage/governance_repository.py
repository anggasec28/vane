"""Durable repositories for case operations, remediation, threat intel, and reports."""
from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any

from vane.findings.remediation import (
    RemediationAction, RemediationStatus, validate_remediation, validate_remediation_graph,
)
from vane.findings.reporting import ReportBundle
from vane.intelligence.threat_intel import (
    IntelConfidence, ThreatIntelRecord, validate_intel,
)
from vane.models import Finding
from vane.projects.case_ops import (
    CaseTimelineEvent, CaseWorkItem, WorkItemStatus,
    validate_timeline_event, validate_work_items,
)
from vane.storage.sqlite_store import SQLiteStore


class GovernanceRepository:
    """Persist governance records in the same project-scoped event chain as core records."""

    def __init__(self, store: SQLiteStore) -> None:
        self.store = store

    def save_work_item(self, item: CaseWorkItem, *, actor: str = "master") -> int:
        existing = [row for row in self.list_work_items(item.project_id)
                    if row.item_id != item.item_id]
        validate_work_items([*existing, item])
        record = asdict(item)
        record["status"] = item.status.value
        return self.store.save_record(project_id=item.project_id,
            record_type="case_work_item", record_id=item.item_id, record=record, actor=actor)

    def list_work_items(self, project_id: str) -> list[CaseWorkItem]:
        rows = self.store.list_records(project_id=project_id, record_type="case_work_item")
        return [CaseWorkItem(
            item_id=row["item_id"], project_id=row["project_id"], mission_id=row["mission_id"],
            title=row["title"], owner=row["owner"], due_at=datetime.fromisoformat(row["due_at"]),
            dependencies=tuple(row.get("dependencies", [])),
            status=WorkItemStatus(row.get("status", "OPEN")),
            escalation_level=int(row.get("escalation_level", 0)),
        ) for row in rows]

    def save_timeline_event(self, event: CaseTimelineEvent, *, actor: str = "system") -> int:
        validate_timeline_event(event)
        record = asdict(event)
        return self.store.save_record(project_id=event.project_id,
            record_type="case_timeline_event", record_id=event.event_id, record=record, actor=actor)

    def list_timeline_events(self, project_id: str, mission_id: str | None = None) -> list[CaseTimelineEvent]:
        rows = self.store.list_records(project_id=project_id, record_type="case_timeline_event")
        events = [CaseTimelineEvent(
            event_id=row["event_id"], project_id=row["project_id"], mission_id=row["mission_id"],
            event_type=row["event_type"], actor=row["actor"],
            occurred_at=datetime.fromisoformat(row["occurred_at"]),
            summary=row["summary"], references=tuple(row.get("references", [])),
        ) for row in rows if mission_id is None or row["mission_id"] == mission_id]
        return sorted(events, key=lambda item: (item.occurred_at, item.event_id))

    def save_threat_intel(self, record: ThreatIntelRecord, *, actor: str = "intel-ingest") -> int:
        validate_intel(record)
        item = asdict(record)
        item["confidence"] = record.confidence.value
        return self.store.save_record(project_id="__global_intelligence__",
            record_type="threat_intel", record_id=record.intel_id, record=item, actor=actor)

    def list_threat_intel(self) -> list[ThreatIntelRecord]:
        rows = self.store.list_records(project_id="__global_intelligence__", record_type="threat_intel")
        return [ThreatIntelRecord(
            intel_id=row["intel_id"], source_id=row["source_id"], source_uri=row["source_uri"],
            title=row["title"], summary=row["summary"],
            published_at=datetime.fromisoformat(row["published_at"]),
            observed_at=datetime.fromisoformat(row["observed_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row.get("expires_at") else None,
            indicators=tuple(row.get("indicators", [])),
            affected_products=tuple(row.get("affected_products", [])),
            affected_versions=tuple(row.get("affected_versions", [])),
            confidence=IntelConfidence(row["confidence"]), tags=tuple(row.get("tags", [])),
        ) for row in rows]

    def save_remediation_action(self, project_id: str, action: RemediationAction,
                                findings: dict[str, Finding], *,
                                actor: str = "remediation-advisor") -> int:
        existing = [row for row in self.list_remediation_actions(project_id)
                    if row.action_id != action.action_id]
        actions = [*existing, action]
        validate_remediation_graph(actions)
        validate_remediation(action, findings, {row.action_id for row in actions})
        record = asdict(action)
        record["status"] = action.status.value
        return self.store.save_record(project_id=project_id,
            record_type="remediation_action", record_id=action.action_id, record=record, actor=actor)

    def list_remediation_actions(self, project_id: str) -> list[RemediationAction]:
        rows = self.store.list_records(project_id=project_id, record_type="remediation_action")
        return [RemediationAction(
            action_id=row["action_id"], finding_id=row["finding_id"], title=row["title"],
            description=row["description"], owner=row["owner"], priority=row["priority"],
            dependencies=tuple(row.get("dependencies", [])),
            verification_criteria=tuple(row.get("verification_criteria", [])),
            status=RemediationStatus(row.get("status", "PROPOSED")),
            verification_evidence_ids=tuple(row.get("verification_evidence_ids", [])),
        ) for row in rows]

    def save_report(self, bundle: ReportBundle, *, actor: str = "reporter") -> int:
        project_id = str(bundle.mission["project_id"])
        record: dict[str, Any] = asdict(bundle)
        return self.store.save_record(project_id=project_id,
            record_type="report_bundle", record_id=bundle.report_id, record=record, actor=actor)
