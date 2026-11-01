from datetime import datetime, timedelta, timezone
import pytest
from vane.assessment.web2 import plan_web2_surface_review
from vane.errors import AuthorizationError
from vane.models import Asset, AssetDisposition, AuthorizationEnvelope, ScopeRule

def envelope(methods=("http_metadata",)):
    return AuthorizationEnvelope("a1", "master", "p1",
        (ScopeRule("hostname", "example.com"),), methods,
        starts_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1), approval_id="ap1")

def test_web2_plan_only_includes_explicitly_in_scope_assets():
    assets = [Asset("1", "https://example.com", "hostname", AssetDisposition.IN_SCOPE),
              Asset("2", "https://outside.test", "hostname", AssetDisposition.OUT_OF_SCOPE)]
    plan = plan_web2_surface_review(assets, envelope())
    assert len(plan) == 1
    assert plan[0].activity == "http_metadata_review"

def test_web2_plan_requires_method_allowlist():
    with pytest.raises(AuthorizationError):
        plan_web2_surface_review([], envelope(methods=("port_scan",)))
