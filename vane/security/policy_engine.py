"""Central policy decision point. All capability adapters must call this first."""
from dataclasses import dataclass
from vane.errors import AuthorizationError, PolicyViolation
from vane.models import AuthorizationEnvelope
from vane.security.approval import Approval
from vane.security.authorization import require_authorized
from vane.security.digests import capability_action_digest

@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    code: str
    reason: str
    approval_required: bool = False

class PolicyEngine:
    def evaluate(self, *, envelope: AuthorizationEnvelope | None, locator: str,
                 method: str, requires_human_approval: bool = False,
                 approval: Approval | None = None) -> PolicyDecision:
        try:
            require_authorized(envelope, locator, method)
        except AuthorizationError as exc:
            return PolicyDecision(False, "AUTHORIZATION_DENIED", str(exc))
        if requires_human_approval:
            expected = capability_action_digest(envelope, locator, method) if envelope else ""
            if (approval is None or not approval.is_valid_for(expected)
                    or envelope is None or approval.approval_id != envelope.approval_id):
                return PolicyDecision(False, "APPROVAL_REQUIRED",
                    "A valid approval record bound to this exact capability action is required.", True)
        return PolicyDecision(True, "ALLOW", "Covered by active authorization and policy.")

    def enforce(self, *, envelope: AuthorizationEnvelope | None, locator: str,
                method: str, requires_human_approval: bool = False,
                approval: Approval | None = None) -> PolicyDecision:
        decision = self.evaluate(envelope=envelope, locator=locator, method=method,
            requires_human_approval=requires_human_approval, approval=approval)
        if not decision.allowed:
            raise PolicyViolation(f"{decision.code}: {decision.reason}")
        return decision
