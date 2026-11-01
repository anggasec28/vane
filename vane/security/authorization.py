"""Fail-closed authorization checks for assets and methods."""
from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

from vane.errors import AuthorizationError
from vane.models import AuthorizationEnvelope, ScopeRule, utc_now


def _effective_port(parsed) -> int | None:
    if parsed.port is not None:
        return parsed.port
    return {"http": 80, "https": 443}.get(parsed.scheme.lower())


def _host_matches(host: str, rule: ScopeRule) -> bool:
    candidate = rule.value.lower().strip(".")
    normalized_host = host.lower().strip(".")
    if rule.kind == "hostname":
        return normalized_host == candidate or (
            rule.include_subdomains and normalized_host.endswith("." + candidate)
        )
    if rule.kind == "ip":
        try:
            return ipaddress.ip_address(normalized_host) == ipaddress.ip_address(candidate)
        except ValueError:
            return False
    if rule.kind == "cidr":
        try:
            return ipaddress.ip_address(normalized_host) in ipaddress.ip_network(candidate, strict=False)
        except ValueError:
            return False
    if rule.kind == "url":
        expected = urlsplit(rule.value)
        return normalized_host == (expected.hostname or "").lower().strip(".")
    return False


def asset_is_in_scope(locator: str, rules: tuple[ScopeRule, ...]) -> bool:
    """Return true only for a locator explicitly matched by a supported scope rule."""
    for rule in rules:
        if rule.kind in {"contract", "repository"}:
            if locator.strip().rstrip("/").lower() == rule.value.strip().rstrip("/").lower():
                return True
            continue
        try:
            parsed = urlsplit(locator if "://" in locator else "//" + locator)
            host = parsed.hostname
            if not host or not _host_matches(host, rule):
                continue
            if rule.ports and _effective_port(parsed) not in rule.ports:
                continue
            if rule.kind == "url":
                expected = urlsplit(rule.value)
                if expected.port is not None and _effective_port(parsed) != expected.port:
                    continue
                if expected.path not in ("", "/") and not parsed.path.startswith(expected.path):
                    continue
                if expected.scheme and parsed.scheme and expected.scheme.lower() != parsed.scheme.lower():
                    continue
            return True
        except ValueError:
            continue
    return False


def require_authorized(envelope: AuthorizationEnvelope | None, locator: str,
                      method: str, *, now=None) -> None:
    if envelope is None or not envelope.is_time_valid(now or utc_now()):
        raise AuthorizationError("No active, time-valid authorization envelope.")
    if not envelope.approval_id or not envelope.approval_id.strip():
        raise AuthorizationError("Authorization envelope has no approval reference.")
    normalized = method.strip().lower()
    allowed = {item.lower() for item in envelope.allowed_methods}
    prohibited = {item.lower() for item in envelope.prohibited_methods}
    if normalized in prohibited or normalized not in allowed:
        raise AuthorizationError(f"Method is not explicitly allowed: {method}")
    if not asset_is_in_scope(locator, envelope.rules):
        raise AuthorizationError(f"Asset is outside the approved scope: {locator}")
