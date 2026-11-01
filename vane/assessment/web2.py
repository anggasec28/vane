"""Web2 assessment planner. Plans work without performing network actions."""
from dataclasses import dataclass
from vane.errors import AuthorizationError
from vane.models import Asset, AssetDisposition, AuthorizationEnvelope
from vane.security.authorization import asset_is_in_scope

@dataclass(frozen=True, slots=True)
class Web2WorkItem:
    locator: str
    activity: str
    rationale: str

def plan_web2_surface_review(assets: list[Asset], envelope: AuthorizationEnvelope) -> list[Web2WorkItem]:
    if not envelope.is_time_valid():
        raise AuthorizationError("Web2 planning requires an active, approved, time-bounded envelope.")
    if "http_metadata" not in {method.lower() for method in envelope.allowed_methods}:
        raise AuthorizationError("The envelope does not allow the http_metadata method.")
    return [Web2WorkItem(a.locator, "http_metadata_review", "Authorized asset only.")
            for a in assets if a.disposition == AssetDisposition.IN_SCOPE
            and asset_is_in_scope(a.locator, envelope.rules)]
