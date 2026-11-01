"""Central policy decision point. All capability adapters must call this first."""
from dataclasses import dataclass
from datetime import datetime
from vane.errors import AuthorizationError, PolicyViolation
from vane.models import AuthorizationEnvelope
from vane.security.approval import Approval, ApprovalVerifier
from vane.security.authorization import require_authorized
from vane.security.digests import authorization_digest, capability_action_digest

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
    def __init__(self, approval_verifier: ApprovalVerifier | None = None) -> None:
        self._approval_verifier = approval_verifier

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
