from vane.assessment.asset_mapping import classify_discovered_asset
from vane.models import Asset, AssetDisposition, AuthorizationEnvelope, ScopeRule

def test_discovered_out_of_scope_asset_is_not_inspected():
    envelope = AuthorizationEnvelope("a1", "master", "p1",
        (ScopeRule("hostname", "example.com"),), ("http_metadata",))
    asset = classify_discovered_asset(Asset("x1", "other.example.net", "hostname"), envelope)
    assert asset.disposition == AssetDisposition.OUT_OF_SCOPE
    assert "not inspected" in asset.notes
