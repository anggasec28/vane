"""Strict JSON deserialization for authorization envelopes."""
from datetime import datetime
from typing import Any
from vane.models import AuthorizationEnvelope, ScopeRule

def _datetime(value: str | None) -> datetime | None:
    if value is None:
        return None
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Authorization timestamps must include a timezone.")
    return parsed

def authorization_from_dict(data: dict[str, Any]) -> AuthorizationEnvelope:
    rules = tuple(ScopeRule(
        kind=str(item["kind"]), value=str(item["value"]),
        include_subdomains=bool(item.get("include_subdomains", False)),
        ports=tuple(int(port) for port in item.get("ports", [])),
        notes=str(item.get("notes", "")),
    ) for item in data.get("rules", []))
    return AuthorizationEnvelope(
        envelope_id=str(data["envelope_id"]), principal=str(data["principal"]),
        project_id=str(data["project_id"]), rules=rules,
        allowed_methods=tuple(str(x) for x in data.get("allowed_methods", [])),
        prohibited_methods=tuple(str(x) for x in data.get("prohibited_methods", [])),
        starts_at=_datetime(data.get("starts_at")), expires_at=_datetime(data.get("expires_at")),
        approval_id=data.get("approval_id"), revoked=bool(data.get("revoked", False)),
    )
