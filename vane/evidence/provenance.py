"""Canonical evidence provenance payloads and chain digest calculation."""
import hashlib
import json
from typing import Any

def canonical_payload(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, default=str).encode("utf-8")

def chain_digest(previous_digest: str | None, payload: dict[str, Any]) -> str:
    previous = (previous_digest or "GENESIS").encode("ascii")
    material = previous + b"\n" + canonical_payload(payload)
    return hashlib.sha256(material).hexdigest()
