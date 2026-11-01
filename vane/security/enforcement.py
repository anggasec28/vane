"""Single enforcement facade used by every capability adapter."""
from vane.models import AuthorizationEnvelope
from vane.security.approval import Approval
from vane.security.policy_engine import PolicyDecision, PolicyEngine

class SecurityEnforcer:
    def __init__(self, policy: PolicyEngine | None = None) -> None:
        self._policy = policy or PolicyEngine()
    def authorize_action(self, envelope: AuthorizationEnvelope | None, locator: str,
                         method: str, *, approval_required: bool = False,
                         approval: Approval | None = None) -> PolicyDecision:
        return self._policy.evaluate(envelope=envelope, locator=locator, method=method,
            requires_human_approval=approval_required, approval=approval)
    def validate_approval(self, approval: Approval | None, expected_digest: str,
                          expected_approval_id: str | None) -> bool:
        return self._policy.validate_approval(approval, expected_digest, expected_approval_id)
