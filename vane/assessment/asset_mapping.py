"""Asset mapping preserves provenance and out-of-scope discoveries."""
from vane.models import Asset, AssetDisposition, AuthorizationEnvelope
from vane.security.authorization import asset_is_in_scope

def classify_discovered_asset(asset: Asset, envelope: AuthorizationEnvelope) -> Asset:
    if asset_is_in_scope(asset.locator, envelope.rules):
        asset.disposition = AssetDisposition.IN_SCOPE
    else:
        asset.disposition = AssetDisposition.OUT_OF_SCOPE
        asset.notes = (asset.notes + " " if asset.notes else "") + "Discovered but not authorized; not inspected."
    return asset
