"""Load a public-only Ed25519 keyring from JSON."""
import base64
import json
from pathlib import Path

def load_public_keyring(path: str | Path) -> dict[str, bytes]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    entries = data.get("keys")
    if not isinstance(entries, dict):
        raise ValueError("Public keyring must contain a 'keys' object.")
    result: dict[str, bytes] = {}
    for key_id, encoded in entries.items():
        if not isinstance(key_id, str) or not key_id or not isinstance(encoded, str):
            raise ValueError("Public keyring entries require non-empty key IDs and base64 strings.")
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) != 32:
            raise ValueError(f"Ed25519 public key must be 32 bytes: {key_id}")
        result[key_id] = raw
    return result
