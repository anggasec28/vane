"""Shared assessment contracts; adapters must be explicitly configured."""
from dataclasses import dataclass
from typing import Protocol
from vane.models import AuthorizationEnvelope, EvidenceRecord

@dataclass(frozen=True, slots=True)
class ObservationRequest:
    locator: str
    method: str
    purpose: str
    authorization: AuthorizationEnvelope

@dataclass(frozen=True, slots=True)
class ObservationResult:
    success: bool
    summary: str
    evidence: EvidenceRecord | None = None
    blocked_reason: str | None = None

class ObservationAdapter(Protocol):
    def observe(self, request: ObservationRequest) -> ObservationResult: ...


@dataclass(frozen=True, slots=True)
class WorkflowPhase:
    phase_id: str
    name: str
    objective: str
    gate: str


_WORKFLOW_PHASES = (
    ("MISSION_COMPREHENSION", "Confirm objective, ownership, exact scope and stop conditions.", "MASTER_SCOPE_REVIEW"),
    ("STRATEGIC_INTELLIGENCE", "Review permitted context and source confidence.", "AUTHORIZED_SOURCES_ONLY"),
    ("ECOSYSTEM_DISCOVERY", "Inventory explicitly authorized assets; discoveries never inherit scope.", "SCOPE_CHECK_PER_ASSET"),
    ("ADVERSARIAL_MODELING", "Map trust boundaries and evidence-backed attack-surface hypotheses.", "EVIDENCE_REQUIRED"),
    ("ADAPTIVE_PLANNING", "Prioritize evidence objectives, dependencies and permitted methods.", "METHOD_ALLOWLIST"),
    ("SPECIALIST_ORCHESTRATION", "Prepare finite specialist tasks with asset and method allowlists.", "WORKER_CONTRACT_REQUIRED"),
    ("DEEP_INVESTIGATION", "Use reviewed adapters with per-action authorization and provenance.", "ACTION_AUTHORIZATION"),
    ("EXPLOITABILITY_IMPACT", "Assess impact only within separately approved methods.", "HIGH_RISK_APPROVAL"),
    ("EVIDENCE_VALIDATION", "Correlate evidence and independently challenge claims.", "INDEPENDENT_VALIDATION"),
    ("STRATEGIC_REASSESSMENT", "Reprioritize without expanding the authorization envelope.", "REAUTHORIZE_SCOPE_CHANGE"),
    ("REPORTING_KNOWLEDGE", "Produce evidence-linked findings, limitations and closure recommendation.", "SIGNED_CLOSURE"),
)


def build_assessment_plan(authorization: AuthorizationEnvelope, assets: list, platform: str = "web2") -> dict:
    """Build an eleven-phase plan only; never performs network or target actions."""
    from vane.errors import AuthorizationError
    from vane.models import AssetDisposition
    from vane.security.authorization import asset_is_in_scope

    if not authorization.is_time_valid():
        raise AuthorizationError("A current, approved authorization envelope is required.")
    platform_key = platform.strip().casefold()
    if platform_key not in {"web2", "web3", "hybrid"}:
        raise ValueError("platform must be web2, web3, or hybrid")
    in_scope = []
    for asset in assets:
        if asset.disposition != AssetDisposition.IN_SCOPE:
            continue
        if not asset_is_in_scope(asset.locator, authorization.rules):
            raise AuthorizationError(f"Asset marked IN_SCOPE is outside authorization: {asset.locator}")
        in_scope.append(asset.asset_id)
    if not in_scope:
        raise AuthorizationError("At least one explicitly IN_SCOPE asset is required.")
    asset_ids = sorted(set(in_scope))
    methods = sorted({method.casefold() for method in authorization.allowed_methods})
    phases = []
    previous = []
    for index, (name, objective, gate) in enumerate(_WORKFLOW_PHASES, 1):
        uses_assets = name in {"ECOSYSTEM_DISCOVERY", "SPECIALIST_ORCHESTRATION", "DEEP_INVESTIGATION", "EXPLOITABILITY_IMPACT"}
        mode = "PLANNING_ONLY"
        if name == "SPECIALIST_ORCHESTRATION":
            mode = "BOUNDED_DELEGATION_CONTRACT_ONLY"
        elif name == "DEEP_INVESTIGATION":
            mode = "REQUIRES_REVIEWED_ADAPTER_AND_PER_ACTION_AUTHORIZATION"
        elif name == "EXPLOITABILITY_IMPACT":
            mode = "SEPARATE_HIGH_RISK_APPROVAL_REQUIRED"
        phase_id = f"P{index:02d}"
        phases.append({
            "phase_id": phase_id,
            "name": name,
            "objective": f"{platform_key.upper()}: {objective}",
            "depends_on": previous,
            "execution_mode": mode,
            "asset_ids": asset_ids if uses_assets else [],
            "required_methods": methods if name == "DEEP_INVESTIGATION" else [],
            "gate": gate,
            "status": "PLANNED",
        })
        previous = [phase_id]
    return {
        "plan_type": "VANE_ADAPTIVE_ASSESSMENT_WORKFLOW",
        "platform": platform_key,
        "authorization_id": authorization.envelope_id,
        "execution_performed": False,
        "target_requests_performed": False,
        "phases": phases,
    }
