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
