from datetime import datetime, timedelta, timezone
import pytest
from vane.errors import AuthorizationError
from vane.models import AuthorizationEnvelope, ScopeRule
from vane.security.authorization import asset_is_in_scope, require_authorized

def envelope():
    return AuthorizationEnvelope(
        envelope_id="auth-1", principal="master", project_id="p-1",
        rules=(ScopeRule("hostname", "example.com", include_subdomains=True),),
        allowed_methods=("http_metadata",), expires_at=datetime.now(timezone.utc) + timedelta(hours=1))

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
