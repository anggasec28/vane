"""Local VANE MCP server exposing bounded governance utilities only.

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
from vane.evidence.manager import validate_evidence
from vane.findings.governance import validate_finding
from vane.lifecycle.policy import DataClass, LifecycleContext, decide_lifecycle
from vane.models import (
    Asset, EvidenceRecord, EvidenceStatus, Finding, FindingStatus, Mission, MissionStatus,
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
        return {"verified": False, "execution_authorized": False,
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

def main() -> None:
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
