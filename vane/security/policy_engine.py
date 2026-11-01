"""Central policy decision point. All adapters must call this before execution."""
from dataclasses import dataclass
from vane.errors import AuthorizationError, PolicyViolation
from vane.models import AuthorizationEnvelope
from vane.security.authorization import require_authorized

@dataclass(frozen=True, slots=True)
class PolicyDecision:
    allowed: bool
    code: str
    reason: str
    approval_required: bool = False

class PolicyEngine:
    def evaluate(self, *, envelope: AuthorizationEnvelope | None, locator: str,
                 method: str, requires_human_approval: bool = False,
                 human_approved: bool = False) -> PolicyDecision:
        try:
            require_authorized(envelope, locator, method)
        except AuthorizationError as exc:
            return PolicyDecision(False, "AUTHORIZATION_DENIED", str(exc))
        if requires_human_approval and not human_approved:
            return PolicyDecision(False, "APPROVAL_REQUIRED",
                                  "The action requires explicit human approval.", True)
        return PolicyDecision(True, "ALLOW", "Covered by active authorization and policy.")

    def enforce(self, **kwargs) -> PolicyDecision:
        decision = self.evaluate(**kwargs)
        if not decision.allowed:
            raise PolicyViolation(f"{decision.code}: {decision.reason}")
        return decision
