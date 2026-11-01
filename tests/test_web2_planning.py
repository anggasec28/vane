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


def test_http_metadata_adapter_requires_signed_mission_approval_and_scope():
    from vane.assessment.base import HTTPMetadataAdapter, ObservationRequest
    from vane.security.policy_engine import PolicyDecision

    class DenyEnforcer:
        def authorize_action(self, *args, **kwargs):
            return PolicyDecision(False, "DENY", "approval missing")

    auth = envelope()
    adapter = HTTPMetadataAdapter(DenyEnforcer(), transport=lambda *args: (200, {}, "HTTP/1.1"))
    result = adapter.observe(ObservationRequest(
        "https://example.com", "http_metadata", "metadata", auth,
        mission_id="mission-1", mission_approval=object(),
    ))
    assert result.success is False
    assert result.blocked_reason == "approval missing"


def test_http_metadata_adapter_records_only_header_evidence_after_authorization():
    from vane.assessment.base import HTTPMetadataAdapter, ObservationRequest
    from vane.security.policy_engine import PolicyDecision

    class AllowEnforcer:
        def authorize_action(self, *args, **kwargs):
            assert args[1] == "https://example.com"
            assert args[2] == "http_metadata"
            return PolicyDecision(True, "ALLOW", "approved")

    def fake_transport(locator, port, path, headers, timeout):
        assert locator == "https://example.com"
        assert port == 443 and path == "/"
        assert headers["User-Agent"].startswith("VANE-")
        return 200, {"content-type": "text/html", "server": "example"}, "HTTP/1.1"

    auth = envelope()
    adapter = HTTPMetadataAdapter(AllowEnforcer(), transport=fake_transport)
    result = adapter.observe(ObservationRequest(
        "https://example.com", "http_metadata", "metadata", auth,
        mission_id="mission-1", mission_approval=object(),
    ))
    assert result.success is True
    assert result.evidence is not None
    assert result.evidence.kind == "http_metadata"
    assert result.evidence.metadata["status_code"] == 200
    assert result.evidence.metadata["headers"] == {
        "content-type": "text/html", "server": "example"
    }
    assert "body" not in result.evidence.metadata


def test_http_metadata_adapter_rejects_unsupported_urls_without_transport():
    from vane.assessment.base import HTTPMetadataAdapter, ObservationRequest
    from vane.security.policy_engine import PolicyDecision

    class AllowEnforcer:
        def authorize_action(self, *args, **kwargs):
            return PolicyDecision(True, "ALLOW", "approved")

    called = []
    adapter = HTTPMetadataAdapter(
        AllowEnforcer(), transport=lambda *args: called.append(args) or (200, {}, "HTTP/1.1")
    )
    auth = envelope()
    result = adapter.observe(ObservationRequest(
        "file:///etc/passwd", "http_metadata", "metadata", auth,
        mission_id="mission-1", mission_approval=object(),
    ))
    assert result.success is False
    assert called == []


def test_tls_metadata_adapter_requires_policy_and_emits_certificate_evidence():
    from vane.assessment.base import ObservationRequest, TLSMetadataAdapter
    from vane.security.policy_engine import PolicyDecision

    class AllowEnforcer:
        def authorize_action(self, *args, **kwargs):
            assert args[2] == "tls_metadata"
            return PolicyDecision(True, "ALLOW", "approved")

    def fake_certificate(locator, timeout):
        assert locator == "https://example.com"
        assert timeout == 8.0
        return {
            "subject": ["commonName=example.com"],
            "issuer": ["commonName=Example CA"],
            "not_after": "Dec 31 23:59:59 2027 GMT",
            "subject_alt_names": ["DNS:example.com"],
            "sha256_fingerprint": "a" * 64,
        }

    auth = envelope(methods=("tls_metadata",))
    adapter = TLSMetadataAdapter(AllowEnforcer(), transport=fake_certificate)
    result = adapter.observe(ObservationRequest(
        "https://example.com", "tls_metadata", "certificate", auth,
        mission_id="mission-1", mission_approval=object(),
    ))
    assert result.success is True
    assert result.evidence is not None
    assert result.evidence.kind == "tls_certificate"
    assert result.evidence.metadata["sha256_fingerprint"] == "a" * 64
    assert result.evidence.metadata["method"] == "tls_metadata"


def test_tls_metadata_adapter_rejects_http_scheme():
    from vane.assessment.base import ObservationRequest, TLSMetadataAdapter
    from vane.security.policy_engine import PolicyDecision

    class AllowEnforcer:
        def authorize_action(self, *args, **kwargs):
            return PolicyDecision(True, "ALLOW", "approved")

    called = []
    adapter = TLSMetadataAdapter(
        AllowEnforcer(), transport=lambda *args: called.append(args) or {}
    )
    auth = envelope(methods=("tls_metadata",))
    result = adapter.observe(ObservationRequest(
        "http://example.com", "tls_metadata", "certificate", auth,
        mission_id="mission-1", mission_approval=object(),
    ))
    assert result.success is False
    assert called == []
