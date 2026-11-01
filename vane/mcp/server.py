"""Local VANE MCP server exposing durable governance and mission workflow operations.

No network scanning, exploitation, transaction submission, key operations, or target mutation
is exposed by this server. Hermes connects over stdio after the Python extra is installed.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Any

from mcp.server.fastmcp import FastMCP

from vane import __version__
from vane.assessment.asset_mapping import classify_discovered_asset
from vane.assessment.web2 import plan_web2_surface_review
from vane.assessment.web3 import plan_contract_review
from vane.evidence.chain import verify_event_chain
from vane.decisions.ledger import DecisionStatus
from vane.evidence.manager import validate_evidence
from vane.findings.governance import validate_finding
from vane.findings.reporting import render_markdown
from vane.findings.remediation import RemediationAction, RemediationStatus
from vane.intelligence.threat_intel import IntelConfidence, ThreatIntelRecord
from vane.projects.case_ops import CaseTimelineEvent, CaseWorkItem, WorkItemStatus
from vane.lifecycle.policy import DataClass, LifecycleContext
from vane.findings.remediation import RemediationAction, RemediationStatus
from vane.lifecycle.policy import DataClass, LifecycleContext, decide_lifecycle
from vane.models import (
    Asset, AssetDisposition, EvidenceRecord, EvidenceStatus, Finding, FindingStatus, Mission, MissionStatus,
)
from vane.recovery.planner import plan_recovery
from vane.security.authorization import require_authorized
from vane.security.approval import Approval
from vane.security.digests import authorization_digest, capability_action_digest, mission_closure_digest
from vane.crypto.approval_verifier import Ed25519ApprovalVerifier
from vane.crypto.keyring import load_public_keyring
from vane.security.serialization import authorization_from_dict
from vane.validation.independent import validate_mission_closure
from vane.storage.sqlite_store import SQLiteStore

server = FastMCP("vane-engine")

_ENGINE = None

def _get_engine():
    global _ENGINE
    if _ENGINE is None:
        from vane.bootstrap import create_engine
        _ENGINE = create_engine()
    return _ENGINE


def _mission_payload(mission: Mission) -> dict[str, Any]:
    return {"mission_id": mission.mission_id, "project_id": mission.project_id,
        "objective": mission.objective, "status": mission.status.value,
        "authorization_id": mission.authorization_id,
        "required_evidence": sorted(mission.required_evidence),
        "completed_evidence": sorted(mission.completed_evidence),
        "blockers": list(mission.blockers), "history": list(mission.history)}


def _decision_payload(snapshot) -> dict[str, Any]:
    return {
        "decision_id": snapshot.decision_id, "project_id": snapshot.project_id,
        "revision": snapshot.revision, "status": snapshot.status.value,
        "title": snapshot.title, "rationale": snapshot.rationale,
        "actor": snapshot.actor, "authority_reference": snapshot.authority_reference,
        "trigger": snapshot.trigger, "occurred_at": snapshot.occurred_at.isoformat(),
        "evidence_references": list(snapshot.evidence_references),
        "dependency_decision_ids": list(snapshot.dependency_decision_ids),
        "policy_version": snapshot.policy_version,
        "superseded_by_decision_id": snapshot.superseded_by_decision_id,
        "superseded_by_revision": snapshot.superseded_by_revision,
        "uncertainty": snapshot.uncertainty,
    }




def _evidence_from_dict(item: dict[str, Any]) -> EvidenceRecord:
    observed = datetime.fromisoformat(str(item["observed_at"]).replace("Z", "+00:00"))
    return EvidenceRecord(
        evidence_id=str(item["evidence_id"]), project_id=str(item["project_id"]),
        mission_id=str(item["mission_id"]), kind=str(item["kind"]),
        source=str(item["source"]), observed_at=observed,
        content_digest=str(item["content_digest"]),
        status=EvidenceStatus(item.get("status", "OBSERVED")),
        authorization_id=item.get("authorization_id"),
        collection_method=str(item.get("collection_method", "manual")),
        limitations=list(item.get("limitations", [])),
        parent_evidence_ids=list(item.get("parent_evidence_ids", [])),
        metadata=dict(item.get("metadata", {})),
    )


@server.tool()
def vane_status() -> dict[str, Any]:
    """Return VANE engine version and safe capability status."""
    return {"name": "VANE", "version": __version__, "runtime": "Hermes Agent",
            "default_policy": "deny", "live_scanning_enabled": False,
            "transaction_submission_enabled": False, "signing_keys_in_engine": False}


@server.tool()
def vane_scope_check(envelope_json: str, locator: str, method: str) -> dict[str, Any]:
    """Check whether an exact asset and method are covered by an authorization envelope."""
    try:
        envelope = authorization_from_dict(json.loads(envelope_json))
        require_authorized(envelope, locator, method)
        return {"scope_covered": True, "decision": "SCOPE_COVERED_NOT_EXECUTION_AUTHORIZATION",
                "envelope_id": envelope.envelope_id, "locator": locator, "method": method,
                "execution_authorized": False}
    except Exception as exc:
        return {"scope_covered": False, "decision": "SCOPE_DENIED", "reason": str(exc),
                "locator": locator, "method": method, "execution_authorized": False}


def _approval_from_dict(item: dict[str, Any]) -> Approval:
    decided = datetime.fromisoformat(str(item["decided_at"]).replace("Z", "+00:00"))
    expiry = item.get("expires_at")
    expires_at = datetime.fromisoformat(str(expiry).replace("Z", "+00:00")) if expiry else None
    return Approval(str(item["approval_id"]), str(item["approver"]),
        str(item["subject_digest"]), str(item["decision"]), decided,
        str(item["key_id"]), str(item["signature"]), expires_at,
        str(item.get("rationale", "")))


def _verify_approval(envelope_json: str, approval_json: str, expected_digest: str,
                     expected_approval_id: str | None,
                     enforce_envelope_expiry: bool = True) -> dict[str, Any]:
    try:
        envelope = authorization_from_dict(json.loads(envelope_json))
        approval = _approval_from_dict(json.loads(approval_json))
        keyring_path = os.environ.get("VANE_APPROVAL_KEYRING", "config/approval-public-keys.json")
        verifier = Ed25519ApprovalVerifier(load_public_keyring(keyring_path))
        valid = ((expected_approval_id is None or approval.approval_id == expected_approval_id)
                 and approval.expires_at is not None
                 and (not enforce_envelope_expiry or approval.expires_at <= envelope.expires_at)
                 and approval.is_valid_for(expected_digest) and verifier.verify(approval))
        return {"signature_valid": valid, "approval_id": approval.approval_id,
                "key_id": approval.key_id}
    except Exception as exc:
        return {"signature_valid": False, "reason": str(exc)}


@server.tool()
def vane_verify_mission_approval(envelope_json: str, approval_json: str) -> dict[str, Any]:
    """Verify the Ed25519 approval bound to the exact authorization envelope."""
    envelope = authorization_from_dict(json.loads(envelope_json))
    if not envelope.is_time_valid():
        return {"mission_approval_verified": False, "execution_authorized": False,
                "reason": "Authorization envelope is expired, revoked, or missing a finite validity window."}
    result = _verify_approval(envelope_json, approval_json, authorization_digest(envelope),
                              envelope.approval_id)
    result["mission_approval_verified"] = result.pop("signature_valid", False)
    result["execution_authorized"] = False
    return result


@server.tool()
def vane_verify_action_approval(envelope_json: str, approval_json: str,
                                locator: str, method: str) -> dict[str, Any]:
    """Verify the Ed25519 approval bound to one exact asset and method."""
    envelope = authorization_from_dict(json.loads(envelope_json))
    require_authorized(envelope, locator, method)
    digest = capability_action_digest(envelope, locator, method)
    result = _verify_approval(envelope_json, approval_json, digest, None)
    result["action_approval_verified"] = result.pop("signature_valid", False)
    result.update({"locator": locator, "method": method, "execution_authorized": False})
    return result




@server.tool()
def vane_save_asset(asset_json: str, envelope_json: str) -> dict[str, Any]:
    """Classify and persist a supplied asset against the current authorization envelope."""
    engine = _get_engine()
    envelope = authorization_from_dict(json.loads(envelope_json))
    item = json.loads(asset_json)
    asset = Asset(str(item["asset_id"]), str(item["locator"]),
        str(item.get("asset_type", "hostname")),
        AssetDisposition(item.get("disposition", "UNKNOWN")),
        item.get("discovered_from"), str(item.get("notes", "")))
    classify_discovered_asset(asset, envelope)
    engine.save_asset(envelope, asset)
    return {"asset_id": asset.asset_id, "locator": asset.locator,
            "disposition": asset.disposition.value, "notes": asset.notes}


@server.tool()
def vane_list_assets(project_id: str) -> list[dict[str, Any]]:
    """List the durable asset inventory for a project."""
    engine = _get_engine()
    assets = (engine.repository.list_assets(project_id) if engine.repository is not None
              else list(engine.get_project(project_id).assets.values()))
    return [{"asset_id": a.asset_id, "locator": a.locator, "asset_type": a.asset_type,
             "disposition": a.disposition.value, "discovered_from": a.discovered_from,
             "notes": a.notes} for a in assets]


@server.tool()
def vane_list_evidence(project_id: str) -> list[dict[str, Any]]:
    """List durable evidence records for a project."""
    engine = _get_engine()
    records = (engine.repository.list_evidence(project_id) if engine.repository is not None
               else list(engine.get_project(project_id).evidence.values()))
    return [{"evidence_id": r.evidence_id, "project_id": r.project_id,
        "mission_id": r.mission_id, "kind": r.kind, "source": r.source,
        "observed_at": r.observed_at.isoformat(), "content_digest": r.content_digest,
        "status": r.status.value, "authorization_id": r.authorization_id,
        "collection_method": r.collection_method, "limitations": r.limitations,
        "parent_evidence_ids": r.parent_evidence_ids, "metadata": r.metadata} for r in records]


@server.tool()
def vane_save_finding(finding_json: str) -> dict[str, Any]:
    """Persist a draft or evidence-validated finding in its project."""
    engine = _get_engine()
    item = json.loads(finding_json)
    finding = Finding(
        finding_id=str(item["finding_id"]), project_id=str(item["project_id"]),
        title=str(item["title"]), description=str(item["description"]),
        severity=str(item["severity"]), status=FindingStatus(item.get("status", "DRAFT")),
        evidence_ids=list(item.get("evidence_ids", [])),
        affected_assets=list(item.get("affected_assets", [])),
        root_cause=item.get("root_cause"), confidence=str(item.get("confidence", "unknown")),
        remediation=str(item.get("remediation", "")),
    )
    engine.save_finding(finding)
    return {"finding_id": finding.finding_id, "status": finding.status.value,
            "evidence_ids": finding.evidence_ids}


@server.tool()
def vane_list_findings(project_id: str) -> list[dict[str, Any]]:
    """List durable findings for a project."""
    engine = _get_engine()
    records = (engine.repository.list_findings(project_id) if engine.repository is not None
               else list(engine.get_project(project_id).findings.values()))
    return [{"finding_id": f.finding_id, "project_id": f.project_id, "title": f.title,
        "description": f.description, "severity": f.severity, "status": f.status.value,
        "evidence_ids": f.evidence_ids, "affected_assets": f.affected_assets,
        "root_cause": f.root_cause, "confidence": f.confidence,
        "remediation": f.remediation, "created_at": f.created_at.isoformat()} for f in records]


@server.tool()
def vane_list_projects() -> list[dict[str, Any]]:
    """List durable VANE project records."""
    engine = _get_engine()
    projects = (engine.repository.list_projects() if engine.repository is not None
                else [engine.projects.get(pid) for pid in engine.projects.list_ids()])
    return [{"project_id":p.project_id,"name":p.name,"owner":p.owner,
             "created_at":p.created_at.isoformat()} for p in projects]


@server.tool()
def vane_create_decision(project_id: str, title: str, rationale: str, actor: str,
                         authority_reference: str, trigger: str,
                         evidence_references_json: str = "[]",
                         dependency_decision_ids_json: str = "[]",
                         policy_version: str = "1", uncertainty: str = "",
                         decision_id: str = "") -> dict[str, Any]:
    """Create an UNRESOLVED decision snapshot in the authoritative append-only ledger."""
    evidence_refs = json.loads(evidence_references_json)
    dependencies = json.loads(dependency_decision_ids_json)
    if not isinstance(evidence_refs, list) or not all(isinstance(x, str) and x for x in evidence_refs):
        raise ValueError("evidence_references_json must be a JSON array of non-empty strings.")
    if not isinstance(dependencies, list) or not all(isinstance(x, str) and x for x in dependencies):
        raise ValueError("dependency_decision_ids_json must be a JSON array of non-empty strings.")
    snapshot = _get_engine().create_decision(
        project_id=project_id, title=title, rationale=rationale, actor=actor,
        authority_reference=authority_reference, trigger=trigger,
        evidence_references=tuple(evidence_refs), dependency_decision_ids=tuple(dependencies),
        policy_version=policy_version, uncertainty=uncertainty, decision_id=decision_id or None,
    )
    return _decision_payload(snapshot)


@server.tool()
def vane_get_decision(project_id: str, decision_id: str) -> dict[str, Any]:
    """Retrieve the latest immutable decision snapshot for a project decision ID."""
    ledger = _get_engine().decision_ledger
    if ledger is None:
        raise RuntimeError("Durable Central Decision Ledger is not configured.")
    return _decision_payload(ledger.get(project_id, decision_id))


@server.tool()
def vane_list_decisions(project_id: str) -> list[dict[str, Any]]:
    """List latest decision snapshots for a project; full history remains in the event chain."""
    ledger = _get_engine().decision_ledger
    if ledger is None:
        raise RuntimeError("Durable Central Decision Ledger is not configured.")
    return [_decision_payload(item) for item in ledger.list_decisions(project_id)]


@server.tool()
def vane_transition_decision(project_id: str, decision_id: str, expected_revision: int,
                             target_status: str, actor: str, authority_reference: str,
                             trigger: str, rationale: str,
                             evidence_references_json: str = "",
                             policy_version: str = "", uncertainty: str = "",
                             superseded_by_decision_id: str = "",
                             superseded_by_revision: int = 0) -> dict[str, Any]:
    """Append a governed decision-state transition with revision and event-head checks."""
    evidence_refs = None
    if evidence_references_json:
        evidence_refs = json.loads(evidence_references_json)
        if not isinstance(evidence_refs, list) or not all(isinstance(x, str) and x for x in evidence_refs):
            raise ValueError("evidence_references_json must be a JSON array of non-empty strings.")
    snapshot = _get_engine().transition_decision(
        project_id=project_id, decision_id=decision_id, expected_revision=expected_revision,
        target=DecisionStatus(target_status), actor=actor,
        authority_reference=authority_reference, trigger=trigger, rationale=rationale,
        evidence_references=tuple(evidence_refs) if evidence_refs is not None else None,
        policy_version=policy_version or None, uncertainty=uncertainty if uncertainty else None,
        superseded_by_decision_id=superseded_by_decision_id or None,
        superseded_by_revision=superseded_by_revision or None,
    )
    return _decision_payload(snapshot)


@server.tool()
def vane_create_project(project_id: str, name: str, owner: str) -> dict[str, Any]:
    """Create a durable project record. This does not authorize an assessment."""
    project = _get_engine().register_project(project_id, name, owner)
    return {"created": True, "project_id": project.project_id, "name": project.name}


@server.tool()
def vane_create_mission(project_id: str, objective: str,
                        required_evidence_json: str = "[]") -> dict[str, Any]:
    """Create a draft mission with explicit evidence objectives."""
    engine = _get_engine()
    required = json.loads(required_evidence_json)
    if not isinstance(required, list) or not all(isinstance(item, str) and item for item in required):
        raise ValueError("required_evidence_json must be a JSON array of non-empty strings.")
    mission = engine.create_mission(project_id, objective, set(required))
    return _mission_payload(mission)


@server.tool()
def vane_get_mission(project_id: str, mission_id: str) -> dict[str, Any]:
    """Retrieve the current durable mission state."""
    return _mission_payload(_get_engine().get_mission(project_id, mission_id))


@server.tool()
def vane_list_missions(project_id: str) -> list[dict[str, Any]]:
    """List durable missions for a project."""
    engine = _get_engine()
    if engine.repository is None:
        return [_mission_payload(m) for m in engine.get_project(project_id).missions.values()]
    return [_mission_payload(m) for m in engine.repository.list_missions(project_id)]


@server.tool()
def vane_submit_mission(project_id: str, mission_id: str) -> dict[str, Any]:
    """Move a draft mission to the explicit approval queue."""
    engine = _get_engine()
    return _mission_payload(engine.submit_mission(engine.get_mission(project_id, mission_id)))


@server.tool()
def vane_authorize_mission(project_id: str, mission_id: str, envelope_json: str,
                           approval_json: str) -> dict[str, Any]:
    """Authorize a mission only after validating its Ed25519 envelope approval."""
    engine = _get_engine()
    envelope = authorization_from_dict(json.loads(envelope_json))
    approval = _approval_from_dict(json.loads(approval_json))
    mission = engine.get_mission(project_id, mission_id)
    return _mission_payload(engine.authorize_mission(mission, envelope, approval))


@server.tool()
def vane_start_mission(project_id: str, mission_id: str) -> dict[str, Any]:
    """Start an already authorized mission."""
    engine = _get_engine()
    return _mission_payload(engine.start_mission(engine.get_mission(project_id, mission_id)))


@server.tool()
def vane_attach_evidence(project_id: str, mission_id: str,
                         evidence_json: str) -> dict[str, Any]:
    """Validate and persist evidence, then update the mission evidence objectives it satisfies."""
    engine = _get_engine()
    mission = engine.get_mission(project_id, mission_id)
    evidence = _evidence_from_dict(json.loads(evidence_json))
    return _mission_payload(engine.attach_evidence(mission, evidence))


@server.tool()
def vane_add_blocker(project_id: str, mission_id: str, reason: str) -> dict[str, Any]:
    """Record a blocker and move an authorized/running mission into BLOCKED."""
    engine = _get_engine()
    mission = engine.get_mission(project_id, mission_id)
    return _mission_payload(engine.add_blocker(mission, reason))


@server.tool()
def vane_clear_blocker(project_id: str, mission_id: str, reason: str) -> dict[str, Any]:
    """Clear an exact blocker; resume a blocked mission only when no blockers remain."""
    engine = _get_engine()
    mission = engine.get_mission(project_id, mission_id)
    return _mission_payload(engine.clear_blocker(mission, reason))


@server.tool()
def vane_request_evidence_review(project_id: str, mission_id: str) -> dict[str, Any]:
    """Submit a running or blocked mission for independent evidence review."""
    engine = _get_engine()
    mission = engine.get_mission(project_id, mission_id)
    return _mission_payload(engine.request_evidence_review(mission))


@server.tool()
def vane_complete_mission(project_id: str, mission_id: str) -> dict[str, Any]:
    """Run independent closure checks and mark the mission COMPLETED only on full pass."""
    engine = _get_engine()
    mission = engine.get_mission(project_id, mission_id)
    return _mission_payload(engine.complete_mission(mission))


@server.tool()
def vane_close_mission(envelope_json: str, mission_id: str,
                       closure_approval_json: str) -> dict[str, Any]:
    """Close a COMPLETED mission only with a signed approval of its exact final snapshot."""
    engine = _get_engine()
    envelope = authorization_from_dict(json.loads(envelope_json))
    approval = _approval_from_dict(json.loads(closure_approval_json))
    mission = engine.get_mission(envelope.project_id, mission_id)
    return _mission_payload(engine.close_mission(mission, envelope, approval))


@server.tool()
def vane_plan_web2(envelope_json: str, assets_json: str) -> dict[str, Any]:
    """Create passive Web2 review work items for explicitly in-scope assets; performs no requests."""
    envelope = authorization_from_dict(json.loads(envelope_json))
    raw_assets = json.loads(assets_json)
    assets = [Asset(asset_id=str(item["asset_id"]), locator=str(item["locator"]),
                    asset_type=str(item.get("asset_type", "hostname"))) for item in raw_assets]
    classified = [classify_discovered_asset(asset, envelope) for asset in assets]
    work = plan_web2_surface_review(classified, envelope)
    return {"work_items": [{"locator": item.locator, "activity": item.activity,
                            "rationale": item.rationale} for item in work],
            "assets": [{"asset_id": a.asset_id, "locator": a.locator,
                        "disposition": a.disposition.value} for a in classified],
            "execution_performed": False}


@server.tool()
def vane_plan_web3(envelope_json: str, chain_id: str, contract_address: str) -> dict[str, Any]:
    """Plan read-only smart-contract review tracks for an explicitly scoped contract."""
    envelope = authorization_from_dict(json.loads(envelope_json))
    plan = plan_contract_review(chain_id, contract_address, envelope)
    return {"chain_id": plan.chain_id, "contract_address": plan.contract_address,
            "review_tracks": list(plan.review_tracks), "execution_performed": False}


@server.tool()
def vane_validate_evidence(evidence_json: str) -> dict[str, Any]:
    """Validate evidence identity, provenance, authorization link, and SHA-256 digest shape."""
    record = _evidence_from_dict(json.loads(evidence_json))
    validate_evidence(record)
    return {"valid": True, "evidence_id": record.evidence_id,
            "content_digest": record.content_digest}


@server.tool()
def vane_validate_finding(finding_json: str, evidence_json: str) -> dict[str, Any]:
    """Validate a finding against supplied evidence records."""
    item = json.loads(finding_json)
    evidence_items = json.loads(evidence_json)
    evidence = {record.evidence_id: record for record in
                (_evidence_from_dict(value) for value in evidence_items)}
    finding = Finding(
        finding_id=str(item["finding_id"]), project_id=str(item["project_id"]),
        title=str(item["title"]), description=str(item["description"]),
        severity=str(item["severity"]), status=FindingStatus(item.get("status", "DRAFT")),
        evidence_ids=list(item.get("evidence_ids", [])),
        affected_assets=list(item.get("affected_assets", [])),
        root_cause=item.get("root_cause"), confidence=str(item.get("confidence", "unknown")),
        remediation=str(item.get("remediation", "")),
    )
    validate_finding(finding, evidence)
    return {"valid": True, "finding_id": finding.finding_id,
            "status": finding.status.value, "evidence_ids": finding.evidence_ids}


@server.tool()
def vane_validate_mission_closure(mission_json: str, evidence_json: str,
                                  findings_json: str) -> dict[str, Any]:
    """Independently check evidence completeness, blockers, references, and mission state."""
    item = json.loads(mission_json)
    mission = Mission(
        mission_id=str(item["mission_id"]), project_id=str(item["project_id"]),
        objective=str(item["objective"]), status=MissionStatus(item["status"]),
        required_evidence=set(item.get("required_evidence", [])),
        completed_evidence=set(item.get("completed_evidence", [])),
        blockers=list(item.get("blockers", [])),
    )
    evidence = {record.evidence_id: record for record in
                (_evidence_from_dict(value) for value in json.loads(evidence_json))}
    findings = [Finding(
        finding_id=str(value["finding_id"]), project_id=str(value["project_id"]),
        title=str(value["title"]), description=str(value["description"]),
        severity=str(value["severity"]), evidence_ids=list(value.get("evidence_ids", [])),
    ) for value in json.loads(findings_json)]
    checks = validate_mission_closure(mission, evidence, findings)
    return {"passed": all(check.passed for check in checks),
            "checks": [{"code": check.code, "passed": check.passed,
                        "detail": check.detail} for check in checks]}


@server.tool()
def vane_plan_recovery(transient: bool, alternate_method_is_approved: bool,
                       failure_reason: str) -> dict[str, Any]:
    """Recommend a bounded recovery path without bypassing authorization."""
    plan = plan_recovery(transient=transient,
                         alternate_method_is_approved=alternate_method_is_approved,
                         failure_reason=failure_reason)
    return {"action": plan.action.value, "rationale": plan.rationale,
            "requires_approval": plan.requires_approval}


@server.tool()
def vane_lifecycle_decision(data_class: str, project_active: bool, disputed: bool = False,
                            legal_or_contractual_hold: bool = False,
                            ownership_known: bool = True,
                            retention_expired: bool = False) -> dict[str, Any]:
    """Return a policy-driven retention decision; never deletes data."""
    context = LifecycleContext(DataClass(data_class), project_active, disputed,
        legal_or_contractual_hold, ownership_known, retention_expired)
    action = decide_lifecycle(context)
    return {"action": action.value, "deletion_performed": False}


@server.tool()
def vane_verify_closure_approval(envelope_json: str, mission_json: str,
                                 approval_json: str) -> dict[str, Any]:
    """Verify Master Ed25519 approval for a completed mission closure snapshot."""
    envelope = authorization_from_dict(json.loads(envelope_json))
    item = json.loads(mission_json)
    mission = Mission(
        mission_id=str(item["mission_id"]), project_id=str(item["project_id"]),
        objective=str(item["objective"]), status=MissionStatus(item["status"]),
        authorization_id=item.get("authorization_id"),
        required_evidence=set(item.get("required_evidence", [])),
        completed_evidence=set(item.get("completed_evidence", [])),
        blockers=list(item.get("blockers", [])), history=list(item.get("history", [])),
    )
    if mission.status != MissionStatus.COMPLETED:
        return {"closure_approval_verified": False, "execution_authorized": False,
                "reason": "mission_not_completed"}
    if envelope.envelope_id != mission.authorization_id or envelope.project_id != mission.project_id:
        return {"closure_approval_verified": False, "execution_authorized": False,
                "reason": "authorization_mismatch"}
    result = _verify_approval(envelope_json, approval_json, mission_closure_digest(mission), None,
                              enforce_envelope_expiry=False)
    result["closure_approval_verified"] = result.pop("signature_valid", False)
    result["execution_authorized"] = False
    return result


@server.tool()
def vane_verify_event_chain(events_json: str) -> dict[str, Any]:
    """Verify a supplied hash-linked event sequence; does not anchor or mutate it."""
    result = verify_event_chain(json.loads(events_json))
    return {"valid": result.valid, "checked": result.checked,
            "failed_sequence": result.failed_sequence, "reason": result.reason}


@server.tool()
def vane_verify_project_integrity(project_id: str) -> dict[str, Any]:
    """Verify local SQLite event-chain and current-record integrity for one project."""
    db_path = os.environ.get("VANE_DB_PATH", "data/vane.sqlite3")
    if not os.path.isfile(db_path):
        return {"valid": False, "reason": "database_not_found", "project_id": project_id}
    store = SQLiteStore(db_path, read_only=True)
    return {"valid": store.verify_project_integrity(project_id),
            "event_chain_valid": store.verify_project_chain(project_id),
            "domain_records_valid": store.verify_domain_records(project_id),
            "project_id": project_id}

@server.tool()
def vane_list_specialists() -> list[dict[str, Any]]:
    """List registered VANE specialist roles and their bounded contracts."""
    registry = _get_engine().specialists
    return [{
        "profile_id": profile.profile_id,
        "title": profile.title,
        "responsibilities": list(profile.responsibilities),
        "required_inputs": list(profile.required_inputs),
        "allowed_activities": list(profile.allowed_activities),
        "prohibited_activities": list(profile.prohibited_activities),
        "output_type": profile.output_type,
        "required_output_fields": list(profile.required_output_fields),
    } for profile in (registry.get(item) for item in registry.profile_ids)]


@server.tool()
def vane_build_mission_report(project_id: str, mission_id: str, report_id: str,
                              limitations_json: str = "[]", persist: bool = False) -> dict[str, Any]:
    """Build an evidence-linked report bundle from a mission's durable records."""
    engine = _get_engine()
    mission = engine.get_mission(project_id, mission_id)
    limitations = json.loads(limitations_json)
    if not isinstance(limitations, list) or not all(isinstance(item, str) for item in limitations):
        raise ValueError("limitations_json must be a JSON array of strings.")
    report = (engine.persist_mission_report(
        mission, report_id=report_id, limitations=tuple(limitations)) if persist else
        engine.build_mission_report(mission, report_id=report_id, limitations=tuple(limitations)))
    return {
        "report_id": report.report_id,
        "generated_at": report.generated_at,
        "executive_summary": report.executive_summary,
        "mission": report.mission,
        "findings": list(report.findings),
        "evidence_index": list(report.evidence_index),
        "limitations": list(report.limitations),
        "unresolved_blockers": list(report.unresolved_blockers),
        "markdown": render_markdown(report),
        "persisted": persist,
    }


@server.tool()
def vane_validate_remediation_plan(project_id: str, actions_json: str) -> dict[str, Any]:
    """Validate remediation action references, dependencies, and plan acyclicity."""
    items = json.loads(actions_json)
    if not isinstance(items, list):
        raise ValueError("actions_json must be a JSON array.")
    actions = [RemediationAction(
        action_id=str(item["action_id"]),
        finding_id=str(item["finding_id"]),
        title=str(item["title"]),
        description=str(item["description"]),
        owner=str(item["owner"]),
        priority=str(item["priority"]),
        dependencies=tuple(item.get("dependencies", [])),
        verification_criteria=tuple(item.get("verification_criteria", [])),
        status=RemediationStatus(item.get("status", "PROPOSED")),
        verification_evidence_ids=tuple(item.get("verification_evidence_ids", [])),
    ) for item in items]
    _get_engine().validate_remediation_plan(project_id, actions)
    return {"valid": True, "action_ids": [item.action_id for item in actions],
            "application_performed": False}


@server.tool()
def vane_save_case_work_item(item_json: str) -> dict[str, Any]:
    """Persist a case work item with validated ownership, dependencies, and due date."""
    item = json.loads(item_json)
    due_at = datetime.fromisoformat(str(item["due_at"]).replace("Z", "+00:00"))
    record = CaseWorkItem(
        item_id=str(item["item_id"]), project_id=str(item["project_id"]),
        mission_id=str(item["mission_id"]), title=str(item["title"]),
        owner=str(item["owner"]), due_at=due_at,
        dependencies=tuple(item.get("dependencies", [])),
        status=WorkItemStatus(item.get("status", "OPEN")),
        escalation_level=int(item.get("escalation_level", 0)),
    )
    revision = _get_engine().save_case_work_item(record)
    return {"saved": True, "item_id": record.item_id, "revision": revision}


@server.tool()
def vane_list_case_work_items(project_id: str) -> list[dict[str, Any]]:
    """List persisted case work items for a project."""
    repository = _get_engine().governance_repository
    if repository is None:
        raise RuntimeError("Durable case repository is not configured.")
    return [{
        "item_id": item.item_id, "project_id": item.project_id,
        "mission_id": item.mission_id, "title": item.title, "owner": item.owner,
        "due_at": item.due_at.isoformat(), "dependencies": list(item.dependencies),
        "status": item.status.value, "escalation_level": item.escalation_level,
    } for item in repository.list_work_items(project_id)]


@server.tool()
def vane_save_case_timeline_event(event_json: str) -> dict[str, Any]:
    """Append a validated case timeline event to the project audit chain."""
    item = json.loads(event_json)
    event = CaseTimelineEvent(
        event_id=str(item["event_id"]), project_id=str(item["project_id"]),
        mission_id=str(item["mission_id"]), event_type=str(item["event_type"]),
        actor=str(item["actor"]),
        occurred_at=datetime.fromisoformat(str(item["occurred_at"]).replace("Z", "+00:00")),
        summary=str(item["summary"]), references=tuple(item.get("references", [])),
    )
    revision = _get_engine().save_case_timeline_event(event, actor=event.actor)
    return {"saved": True, "event_id": event.event_id, "revision": revision}


@server.tool()
def vane_list_case_timeline(project_id: str, mission_id: str = "") -> list[dict[str, Any]]:
    """List case timeline events in chronological order."""
    repository = _get_engine().governance_repository
    if repository is None:
        raise RuntimeError("Durable case repository is not configured.")
    events = repository.list_timeline_events(project_id, mission_id or None)
    return [{
        "event_id": event.event_id, "mission_id": event.mission_id,
        "event_type": event.event_type, "actor": event.actor,
        "occurred_at": event.occurred_at.isoformat(), "summary": event.summary,
        "references": list(event.references),
    } for event in events]


@server.tool()
def vane_save_threat_intel(intel_json: str) -> dict[str, Any]:
    """Validate and persist a supplied threat-intelligence record."""
    item = json.loads(intel_json)
    expiry = item.get("expires_at")
    record = ThreatIntelRecord(
        intel_id=str(item["intel_id"]), source_id=str(item["source_id"]),
        source_uri=str(item["source_uri"]), title=str(item["title"]),
        summary=str(item["summary"]),
        published_at=datetime.fromisoformat(str(item["published_at"]).replace("Z", "+00:00")),
        observed_at=datetime.fromisoformat(str(item["observed_at"]).replace("Z", "+00:00")),
        expires_at=datetime.fromisoformat(str(expiry).replace("Z", "+00:00")) if expiry else None,
        indicators=tuple(item.get("indicators", [])),
        affected_products=tuple(item.get("affected_products", [])),
        affected_versions=tuple(item.get("affected_versions", [])),
        confidence=IntelConfidence(item["confidence"]), tags=tuple(item.get("tags", [])),
    )
    revision = _get_engine().save_threat_intel(record)
    return {"saved": True, "intel_id": record.intel_id, "revision": revision}


@server.tool()
def vane_list_threat_intel() -> list[dict[str, Any]]:
    """List normalized threat-intelligence records from supplied feeds."""
    repository = _get_engine().governance_repository
    if repository is None:
        raise RuntimeError("Durable intelligence repository is not configured.")
    return [{
        "intel_id": item.intel_id, "source_id": item.source_id, "source_uri": item.source_uri,
        "title": item.title, "summary": item.summary,
        "published_at": item.published_at.isoformat(), "observed_at": item.observed_at.isoformat(),
        "expires_at": item.expires_at.isoformat() if item.expires_at else None,
        "indicators": list(item.indicators), "affected_products": list(item.affected_products),
        "affected_versions": list(item.affected_versions), "confidence": item.confidence.value,
        "tags": list(item.tags),
    } for item in repository.list_threat_intel()]


@server.tool()
def vane_save_remediation_action(project_id: str, action_json: str) -> dict[str, Any]:
    """Persist a remediation action after validating its accepted finding and plan dependencies."""
    item = json.loads(action_json)
    action = RemediationAction(
        action_id=str(item["action_id"]), finding_id=str(item["finding_id"]),
        title=str(item["title"]), description=str(item["description"]),
        owner=str(item["owner"]), priority=str(item["priority"]),
        dependencies=tuple(item.get("dependencies", [])),
        verification_criteria=tuple(item.get("verification_criteria", [])),
        status=RemediationStatus(item.get("status", "PROPOSED")),
        verification_evidence_ids=tuple(item.get("verification_evidence_ids", [])),
    )
    revision = _get_engine().save_remediation_action(project_id, action)
    return {"saved": True, "action_id": action.action_id, "revision": revision}


@server.tool()
def vane_list_remediation_actions(project_id: str) -> list[dict[str, Any]]:
    """List persisted remediation actions for a project."""
    repository = _get_engine().governance_repository
    if repository is None:
        raise RuntimeError("Durable governance repository is not configured.")
    return [{
        "action_id": item.action_id, "finding_id": item.finding_id,
        "title": item.title, "description": item.description, "owner": item.owner,
        "priority": item.priority, "dependencies": list(item.dependencies),
        "verification_criteria": list(item.verification_criteria),
        "status": item.status.value,
        "verification_evidence_ids": list(item.verification_evidence_ids),
    } for item in repository.list_remediation_actions(project_id)]


@server.tool()
def vane_review_data_lifecycle(project_id: str, review_id: str, record_id: str,
                               data_class: str, project_active: bool, disputed: bool,
                               legal_or_contractual_hold: bool, ownership_known: bool,
                               retention_expired: bool, rationale: str, actor: str,
                               approval_reference: str = "") -> dict[str, Any]:
    """Record a policy-driven lifecycle decision; this tool never deletes data."""
    context = LifecycleContext(
        data_class=DataClass(data_class), project_active=project_active,
        disputed=disputed, legal_or_contractual_hold=legal_or_contractual_hold,
        ownership_known=ownership_known, retention_expired=retention_expired,
    )
    review = _get_engine().review_data_lifecycle(
        review_id=review_id, project_id=project_id, record_id=record_id,
        context=context, rationale=rationale, actor=actor,
        approval_reference=approval_reference or None,
    )
    return {
        "review_id": review.review_id, "record_id": review.record_id,
        "action": review.action.value, "rationale": review.rationale,
        "approval_reference": review.approval_reference,
        "deletion_performed": False,
    }


@server.tool()
def vane_list_lifecycle_reviews(project_id: str) -> list[dict[str, Any]]:
    """List auditable lifecycle decisions for a project."""
    repository = _get_engine().governance_repository
    if repository is None:
        raise RuntimeError("Durable governance repository is not configured.")
    return [{
        "review_id": item.review_id, "record_id": item.record_id,
        "data_class": item.data_class.value, "action": item.action.value,
        "rationale": item.rationale, "actor": item.actor,
        "reviewed_at": item.reviewed_at.isoformat(),
        "approval_reference": item.approval_reference,
    } for item in repository.list_lifecycle_reviews(project_id)]


def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
