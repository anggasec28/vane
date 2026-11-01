"""Web2 assessment planner. Plans work without performing network actions."""
from dataclasses import dataclass
from vane.models import Asset, AssetDisposition, AuthorizationEnvelope
from vane.security.authorization import asset_is_in_scope

@dataclass(frozen=True, slots=True)
class Web2WorkItem:
    locator: str
    activity: str
    rationale: str

def plan_web2_surface_review(assets: list[Asset], envelope: AuthorizationEnvelope) -> list[Web2WorkItem]:
    return [Web2WorkItem(a.locator, "passive_metadata_review", "Authorized asset only.")
            for a in assets if a.disposition == AssetDisposition.IN_SCOPE
            and asset_is_in_scope(a.locator, envelope.rules)]
