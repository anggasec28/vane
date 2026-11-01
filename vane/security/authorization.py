"""Fail-closed authorization checks for assets and methods."""
from urllib.parse import urlsplit
from vane.errors import AuthorizationError
from vane.models import AuthorizationEnvelope, ScopeRule, utc_now

def _host_matches(host: str, rule: ScopeRule) -> bool:
    candidate = rule.value.lower().strip(".")
    host = host.lower().strip(".")
    if rule.kind == "hostname":
        return host == candidate or (rule.include_subdomains and host.endswith("." + candidate))
    if rule.kind == "url":
        expected = urlsplit(rule.value)
        return host == (expected.hostname or "").lower()
    return False

def asset_is_in_scope(locator: str, rules: tuple[ScopeRule, ...]) -> bool:
    parsed = urlsplit(locator if "://" in locator else "//" + locator)
    host = parsed.hostname
    if not host:
        return False
    for rule in rules:
        if not _host_matches(host, rule):
            continue
        if rule.ports and parsed.port not in rule.ports:
            continue
        if rule.kind == "url":
            expected = urlsplit(rule.value)
            if expected.path not in ("", "/") and not parsed.path.startswith(expected.path):
                continue
        return True
    return False

def require_authorized(envelope: AuthorizationEnvelope | None, locator: str,
                       method: str, *, now=None) -> None:
    if envelope is None or not envelope.is_time_valid(now or utc_now()):
        raise AuthorizationError("No active, time-valid authorization envelope.")
    normalized = method.strip().lower()
    allowed = {item.lower() for item in envelope.allowed_methods}
    prohibited = {item.lower() for item in envelope.prohibited_methods}
    if normalized in prohibited or normalized not in allowed:
        raise AuthorizationError(f"Method is not explicitly allowed: {method}")
    if not asset_is_in_scope(locator, envelope.rules):
        raise AuthorizationError(f"Asset is outside the approved scope: {locator}")
