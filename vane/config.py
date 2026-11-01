"""Validated JSON engine configuration loader."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any

class ConfigurationError(ValueError):
    """Raised when an engine configuration is malformed or weakens core defaults."""

def load_config(path: str | Path) -> dict[str, Any]:
    config_path = Path(path)
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError(f"Cannot read JSON engine configuration: {exc}") from exc
    if not isinstance(data, dict):
        raise ConfigurationError("Configuration root must be a JSON object.")
    policy = data.get("policy")
    if not isinstance(policy, dict):
        raise ConfigurationError("Missing policy object.")
    if policy.get("default_decision") != "deny":
        raise ConfigurationError("policy.default_decision must remain 'deny'.")
    if policy.get("require_authorization_envelope") is not True:
        raise ConfigurationError("Authorization envelopes must be mandatory.")
    if policy.get("require_explicit_method_allowlist") is not True:
        raise ConfigurationError("Explicit method allowlisting must remain enabled.")
    mcp = data.get("mcp", {})
    if mcp.get("default_enabled") is not False:
        raise ConfigurationError("MCP capabilities must be disabled by default.")
    signing = data.get("signing", {})
    if signing.get("private_key_in_engine") is not False:
        raise ConfigurationError("Private signing keys must remain outside the engine.")
    return data
