"""Central policy decision point. All capability adapters must call this first."""
from dataclasses import dataclass
from datetime import datetime
from vane.errors import AuthorizationError, PolicyViolation
from vane.models import AuthorizationEnvelope
from vane.security.approval import Approval, ApprovalVerifier
from vane.security.authorization import require_authorized
from vane.security.digests import authorization_digest, capability_action_digest
from vane.security.emergency_suspension import MasterEmergencySuspension

HIGH_RISK_METHODS = {
    "active_scan", "exploit_validation", "credential_test", "transaction_submit",
    "state_change", "data_export", "destructive_action",
}

@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    code: str
    reason: str
    approval_required: bool = False

class PolicyEngine:
    def __init__(self, approval_verifier: ApprovalVerifier | None = None, *,
                 emergency_suspension: MasterEmergencySuspension | None = None,
                 require_emergency_control: bool = False) -> None:
        self._approval_verifier = approval_verifier
        self._emergency_suspension = emergency_suspension
        self._require_emergency_control = require_emergency_control

    def validate_approval(self, approval: Approval | None, expected_digest: str,
                          expected_approval_id: str | None,
                          now: datetime | None = None) -> bool:
        if (approval is None or self._approval_verifier is None
                or (expected_approval_id is not None and approval.approval_id != expected_approval_id)
                or not approval.is_valid_for(expected_digest, now)):
            return False
        return self._approval_verifier.verify(approval)

    def evaluate(self, *, envelope: AuthorizationEnvelope | None, locator: str,
                 method: str, mission_approval: Approval | None = None,
                 action_approval: Approval | None = None,
                 requires_human_approval: bool = False) -> PolicyDecision:
        if self._require_emergency_control and self._emergency_suspension is None:
            return PolicyDecision(False, "EMERGENCY_CONTROL_UNAVAILABLE",
                "Master emergency suspension control is not configured; fail closed.")
        if self._emergency_suspension is not None:
            try:
                if self._emergency_suspension.is_suspended():
                    return PolicyDecision(False, "MASTER_EMERGENCY_SUSPENSION",
                        "Master emergency suspension is active.")
            except Exception:
                return PolicyDecision(False, "EMERGENCY_CONTROL_UNAVAILABLE",
                    "Master emergency suspension state cannot be verified; fail closed.")
        try:
            require_authorized(envelope, locator, method)
        except AuthorizationError as exc:
            return PolicyDecision(False, "AUTHORIZATION_DENIED", str(exc))
        assert envelope is not None
        if (not self.validate_approval(mission_approval, authorization_digest(envelope),
                                       envelope.approval_id)
                or mission_approval is None or mission_approval.expires_at is None
                or mission_approval.expires_at > envelope.expires_at):
            return PolicyDecision(False, "MISSION_APPROVAL_REQUIRED",
                "A valid Ed25519 approval for this authorization envelope is required.", True)
        normalized = method.strip().lower()
        action_gate = requires_human_approval or normalized in HIGH_RISK_METHODS
        if action_gate:
            expected = capability_action_digest(envelope, locator, normalized)
            if (not self.validate_approval(action_approval, expected, None)
                    or action_approval is None or action_approval.expires_at is None
                    or action_approval.expires_at > envelope.expires_at):
                return PolicyDecision(False, "ACTION_APPROVAL_REQUIRED",
                    "A valid Ed25519 approval for this exact asset/method action is required.", True)
        return PolicyDecision(True, "ALLOW", "Mission approval, scope, method, and policy checks passed.")

    def enforce(self, *, envelope: AuthorizationEnvelope | None, locator: str,
                method: str, mission_approval: Approval | None = None,
                action_approval: Approval | None = None,
                requires_human_approval: bool = False) -> PolicyDecision:
        decision = self.evaluate(envelope=envelope, locator=locator, method=method,
            mission_approval=mission_approval, action_approval=action_approval,
            requires_human_approval=requires_human_approval)
        if not decision.allowed:
            raise PolicyViolation(f"{decision.code}: {decision.reason}")
        return decision
