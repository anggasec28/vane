"""Single enforcement facade used by capability adapters."""
from vane.models import AuthorizationEnvelope
from vane.security.policy_engine import PolicyDecision, PolicyEngine

class SecurityEnforcer:
    def __init__(self, policy: PolicyEngine | None = None) -> None:
        self._policy = policy or PolicyEngine()
    def authorize_action(self, envelope: AuthorizationEnvelope | None, locator: str,
                         method: str, *, approval_required: bool = False,
                         approved: bool = False) -> PolicyDecision:
        return self._policy.evaluate(envelope=envelope, locator=locator, method=method,
            requires_human_approval=approval_required, human_approved=approved)
