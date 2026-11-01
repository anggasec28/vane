"""Deterministic, evidence-linked assessment report assembly."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from vane.models import EvidenceRecord, Finding, Mission
from vane.errors import PolicyViolation


@dataclass(frozen=True, slots=True)
class ReportBundle:
    report_id: str
    generated_at: str
    executive_summary: str
    mission: dict[str, Any]
    findings: tuple[dict[str, Any], ...]
    evidence_index: tuple[dict[str, Any], ...]
    limitations: tuple[str, ...]
    unresolved_blockers: tuple[str, ...]


def build_report(mission: Mission, findings: list[Finding],
                 evidence: dict[str, EvidenceRecord], *,
                 report_id: str, limitations: tuple[str, ...] = ()) -> ReportBundle:
    if not report_id.strip():
        raise ValueError("report_id is required.")
    for finding in findings:
        if finding.project_id != mission.project_id:
            raise PolicyViolation("Report cannot combine findings from another project.")
        for evidence_id in finding.evidence_ids:
            record = evidence.get(evidence_id)
            if record is not None and (
                record.project_id != mission.project_id or record.mission_id != mission.mission_id
            ):
                raise PolicyViolation("Report evidence reference belongs to another project or mission.")
    report_findings: list[dict[str, Any]] = []
    referenced: set[str] = set()
    for finding in sorted(findings, key=lambda item: (item.severity.lower(), item.finding_id)):
        links = []
        for evidence_id in finding.evidence_ids:
            record = evidence.get(evidence_id)
            if record is None:
                links.append({"evidence_id": evidence_id, "state": "MISSING"})
                continue
            referenced.add(evidence_id)
            links.append({
                "evidence_id": evidence_id,
                "state": record.status.value,
                "kind": record.kind,
                "observed_at": record.observed_at.isoformat(),
                "digest": record.content_digest,
                "source": record.source,
                "limitations": list(record.limitations),
            })
        report_findings.append({
            "finding_id": finding.finding_id,
            "title": finding.title,
            "description": finding.description,
            "severity": finding.severity,
            "status": finding.status.value,
            "confidence": finding.confidence,
            "root_cause": finding.root_cause,
            "affected_assets": list(finding.affected_assets),
            "remediation": finding.remediation,
            "evidence": links,
        })
    counts: dict[str, int] = {}
    for finding in findings:
        key = finding.severity.lower()
        counts[key] = counts.get(key, 0) + 1
    summary = (
        f"Mission {mission.mission_id} contains {len(findings)} finding(s); "
        f"{len(referenced)} evidence record(s) are referenced. "
        f"Severity distribution: {counts or {'none': 0}}. "
        f"Mission state: {mission.status.value}."
    )
    evidence_index = tuple({
        "evidence_id": item.evidence_id,
        "kind": item.kind,
        "status": item.status.value,
        "observed_at": item.observed_at.isoformat(),
        "digest": item.content_digest,
        "source": item.source,
        "limitations": tuple(item.limitations),
    } for item in sorted(evidence.values(), key=lambda row: row.evidence_id))
    return ReportBundle(
        report_id=report_id,
        generated_at=datetime.now(timezone.utc).isoformat(),
        executive_summary=summary,
        mission={
            "mission_id": mission.mission_id,
            "project_id": mission.project_id,
            "objective": mission.objective,
            "status": mission.status.value,
            "required_evidence": sorted(mission.required_evidence),
            "completed_evidence": sorted(mission.completed_evidence),
        },
        findings=tuple(report_findings),
        evidence_index=evidence_index,
        limitations=tuple(limitations),
        unresolved_blockers=tuple(mission.blockers),
    )


def render_markdown(bundle: ReportBundle) -> str:
    """Render a portable Markdown view without embedding raw evidence payloads."""
    lines = [
        "# VANE Assessment Report", "",
        f"Report ID: {bundle.report_id}",
        f"Generated: {bundle.generated_at}", "",
        "## Executive Summary", "", bundle.executive_summary, "",
        "## Mission", "",
        f"- Project: {bundle.mission['project_id']}",
        f"- Mission: {bundle.mission['mission_id']}",
        f"- Objective: {bundle.mission['objective']}",
        f"- State: {bundle.mission['status']}", "",
        "## Findings", "",
    ]
    if not bundle.findings:
        lines.append("No findings were recorded.")
    for item in bundle.findings:
        lines.extend([
            f"### [{item['severity'].upper()}] {item['title']}", "",
            item["description"], "",
            f"- Finding ID: {item['finding_id']}",
            f"- Status: {item['status']}",
            f"- Confidence: {item['confidence']}",
            f"- Affected assets: {', '.join(item['affected_assets']) or 'Not specified'}",
            "- Evidence:",
        ])
        for link in item["evidence"]:
            lines.append(f"  - {link['evidence_id']}: {link['state']}")
        lines.append("")
    lines.extend(["## Limitations", ""])
    lines.extend([f"- {item}" for item in bundle.limitations] or ["- None recorded."])
    lines.extend(["", "## Unresolved Blockers", ""])
    lines.extend([f"- {item}" for item in bundle.unresolved_blockers] or ["- None recorded."])
    return "\\n".join(lines) + "\\n"
