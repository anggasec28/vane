from datetime import datetime, timedelta, timezone
import pytest
from vane.errors import AuthorizationError
from vane.models import AuthorizationEnvelope, ScopeRule
from vane.security.authorization import asset_is_in_scope, require_authorized

def envelope():
    return AuthorizationEnvelope(
        envelope_id="auth-1", principal="master", project_id="p-1",
        rules=(ScopeRule("hostname", "example.com", include_subdomains=True),),
        allowed_methods=("http_metadata",),
        starts_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        approval_id="approval-1")

def test_exact_and_subdomain_scope():
    assert asset_is_in_scope("https://example.com", envelope().rules)
    assert asset_is_in_scope("https://api.example.com", envelope().rules)
    assert not asset_is_in_scope("https://notexample.com", envelope().rules)

def test_denies_unlisted_method():
    with pytest.raises(AuthorizationError):
        require_authorized(envelope(), "https://example.com", "port_scan")

def test_denies_out_of_scope_asset():
    with pytest.raises(AuthorizationError):
        require_authorized(envelope(), "https://other.example.net", "http_metadata")

def test_denies_missing_approval_reference():
    item = envelope()
    invalid = AuthorizationEnvelope(item.envelope_id, item.principal, item.project_id,
        item.rules, item.allowed_methods, starts_at=item.starts_at,
        expires_at=item.expires_at)
    with pytest.raises(AuthorizationError):
        require_authorized(invalid, "https://example.com", "http_metadata")

def test_url_scope_enforces_scheme_and_path_boundary():
    rule = (ScopeRule("url", "https://example.com/api"),)
    assert asset_is_in_scope("https://example.com/api/v1", rule)
    assert not asset_is_in_scope("https://example.com/apix", rule)
    assert not asset_is_in_scope("http://example.com/api/v1", rule)

def test_ip_and_cidr_rules_are_supported():
    assert asset_is_in_scope("https://192.0.2.10", (ScopeRule("ip", "192.0.2.10"),))
    assert asset_is_in_scope("https://192.0.2.10", (ScopeRule("cidr", "192.0.2.0/24"),))
    assert not asset_is_in_scope("https://192.0.3.10", (ScopeRule("cidr", "192.0.2.0/24"),))
