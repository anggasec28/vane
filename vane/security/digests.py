"""Stable digests used to bind approvals to exact authorization and action content."""
import hashlib
import json
from dataclasses import asdict
from vane.models import AuthorizationEnvelope

def _digest(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()

def authorization_digest(envelope: AuthorizationEnvelope) -> str:
    return _digest(asdict(envelope))

def capability_action_digest(envelope: AuthorizationEnvelope, locator: str, method: str) -> str:
    return _digest({"authorization_digest": authorization_digest(envelope),
                    "locator": locator, "method": method.strip().lower()})

from vane.security.approval import Approval

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
                      ensure_ascii=False, default=str).encode("utf-8")
