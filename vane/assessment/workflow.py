"""Deterministic, authorization-bounded assessment workflow planning.

This module creates an execution plan only. It never performs network or target actions.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from vane.errors import AuthorizationError
from vane.models import Asset, AssetDisposition, AuthorizationEnvelope
from vane.security.authorization import asset_is_in_scope


@dataclass(frozen=True, slots=True)
class WorkflowStep:
    step_id: str
    phase: str
    objective: str
    depends_on: tuple[str, ...]
    execution_mode: str
    required_methods: tuple[str, ...] = ()
    asset_ids: tuple[str, ...] = ()
    gate: str | None = None


_PHASES = (
    ("P01", "MISSION_COMPREHENSION", "Confirm objective, owner, scope, exclusions, limits and stop conditions.", "GOVERNANCE_REVIEW"),
    ("P02", "STRATEGIC_INTELLIGENCE", "Review available, permitted context and record source confidence.", "AUTHORIZATION_REQUIRED"),
    ("P03", "ECOSYSTEM_DISCOVERY", "Inventory only explicitly authorized assets and classify discoveries.", "SCOPE_CHECK_PER_ASSET"),
    ("P04", "ADVERSARIAL_MODELING", "Model trust boundaries, attack surface hypotheses and dependencies.", "EVIDENCE_REQUIRED"),
    ("P05", "ADAPTIVE_INVESTIGATION_PLANNING", "Prioritize evidence objectives and select permitted methods.", "METHOD_ALLOWLIST"),
    ("P06", "SPECIALIST_ORCHESTRATION", "Create bounded specialist tasks with finite asset and method allowlists.", "WORKER_CONTRACT_REQUIRED"),
    ("P07", "DEEP_TECHNICAL_INVESTIGATION", "Perform approved investigation and preserve raw observations and provenance.", "ACTION_AUTHORIZATION_PER_ACTION"),
    ("P08", "EXPLOITABILITY_IMPACT", "Assess exploitability and impact only to the depth separately authorized.", "HIGH_RISK_ACTION_APPROVAL"),
    ("P09", "EVIDENCE_VALIDATION", "Correlate evidence, test claims and identify contradictions and gaps.", "INDEPENDENT_VALIDATION"),
    ("P10", "STRATEGIC_REASSESSMENT", "Reprioritize from evidence without expanding the authorization envelope.", "REAUTHORIZE_ON_SCOPE_CHANGE"),
    ("P11", "REPORTING_KNOWLEDGE", "Build evidence-linked report, limitations, remediation and closure recommendation.", "SEPARATE_SIGNED_CLOSURE"),
)


def build_assessment_workflow(
    envelope: AuthorizationEnvelope,
    assets: Iterable[Asset],
    *,
    platform: str = "web2",
) -> tuple[WorkflowStep, ...]:
    """Build an 11-phase plan for already-classified assets; does not execute steps."""
    if not envelope.is_time_valid():
        raise AuthorizationError("Workflow planning requires a currently valid signed authorization.")
    platform_key = platform.strip().casefold()
    if platform_key not in {"web2", "web3", "hybrid"}:
        raise ValueError("platform must be web2, web3, or hybrid")

    scoped: list[str] = []
    for asset in assets:
        if asset.disposition != AssetDisposition.IN_SCOPE:
            continue
        if not asset_is_in_scope(asset.locator, envelope.rules):
            raise AuthorizationError(f"Asset marked IN_SCOPE is not covered by the envelope: {asset.locator}")
        scoped.append(asset.asset_id)
    if not scoped:
        raise AuthorizationError("Workflow planning requires at least one explicitly IN_SCOPE asset.")

    methods = tuple(sorted({method.casefold() for method in envelope.allowed_methods}))
    steps: list[WorkflowStep] = []
    previous: tuple[str, ...] = ()
    for step_id, phase, objective, gate in _PHASES:
        step_methods: tuple[str, ...] = ()
        step_assets: tuple[str, ...] = ()
        mode = "PLANNING_ONLY"
        if phase in {"ECOSYSTEM_DISCOVERY", "DEEP_TECHNICAL_INVESTIGATION"}:
            step_assets = tuple(sorted(scoped))
            step_methods = methods
            mode = "REQUIRES_APPROVED_ADAPTER"
        elif phase == "EXPLOITABILITY_IMPACT":
            step_assets = tuple(sorted(scoped))
            step_methods = tuple(method for method in methods if method in {
                "active_scan", "authorized_exploit_validation", "transaction_simulation"
            })
            mode = "SEPARATE_ACTION_APPROVAL_REQUIRED"
        elif phase == "SPECIALIST_ORCHESTRATION":
            step_assets = tuple(sorted(scoped))
            mode = "BOUNDED_DELEGATION_ONLY"
        steps.append(WorkflowStep(
            step_id=step_id,
            phase=phase,
            objective=f"{platform_key.upper()}: {objective}",
            depends_on=previous,
            execution_mode=mode,
            required_methods=step_methods,
            asset_ids=step_assets,
            gate=gate,
        ))
        previous = (step_id,)
    return tuple(steps)


def workflow_plan_payload(steps: Iterable[WorkflowStep]) -> dict[str, object]:
    """Return a JSON-serializable plan and an explicit no-execution guarantee."""
    return {
        "plan_type": "VANE_ADAPTIVE_ASSESSMENT_WORKFLOW",
        "execution_performed": False,
        "target_requests_performed": False,
        "steps": [asdict(step) for step in steps],
    }
