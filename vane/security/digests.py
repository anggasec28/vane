"""Stable canonical digests used for authorization and approval signatures."""
import hashlib
import json
from dataclasses import asdict
from datetime import datetime
from vane.models import AuthorizationEnvelope
from vane.security.approval import Approval

def _json_default(value):
    if isinstance(value, datetime):
        return value.isoformat()
    raise TypeError(f"Unsupported canonical JSON value: {type(value).__name__}")

def _digest(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, default=_json_default).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()

def authorization_digest(envelope: AuthorizationEnvelope) -> str:
    return _digest(asdict(envelope))

def capability_action_digest(envelope: AuthorizationEnvelope, locator: str, method: str) -> str:
    return _digest({"authorization_digest": authorization_digest(envelope),
                    "locator": locator, "method": method.strip().lower()})

def approval_signing_payload(approval: Approval) -> bytes:
    payload = {
        "approval_id": approval.approval_id,
        "approver": approval.approver,
        "subject_digest": approval.subject_digest,
        "decision": approval.decision,
        "decided_at": approval.decided_at,
        "key_id": approval.key_id,
        "expires_at": approval.expires_at,
        "rationale": approval.rationale,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=_json_default).encode("utf-8")

from vane.models import Mission

def mission_closure_digest(mission: Mission) -> str:
    """Digest the independently validated completed mission snapshot."""
    if mission.status.value != "COMPLETED":
        raise ValueError("Only a completed mission can be closure-approved.")
    return _digest({
        "mission_id": mission.mission_id,
        "project_id": mission.project_id,
        "authorization_id": mission.authorization_id,
        "status": mission.status.value,
        "required_evidence": sorted(mission.required_evidence),
        "completed_evidence": sorted(mission.completed_evidence),
        "blockers": list(mission.blockers),
        "history": mission.history,
    })
