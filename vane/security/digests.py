"""Stable action digests used to bind approvals to exact authorization content."""
import hashlib
import json
from dataclasses import asdict
from vane.models import AuthorizationEnvelope

def authorization_digest(envelope: AuthorizationEnvelope) -> str:
    payload = asdict(envelope)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
