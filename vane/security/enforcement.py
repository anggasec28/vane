"""Single enforcement facade used by every capability adapter."""
from datetime import datetime
from vane.models import AuthorizationEnvelope
from vane.security.approval import Approval
from vane.security.policy_engine import PolicyDecision, PolicyEngine
from vane.security.approval import ApprovalVerifier
from vane.security.emergency_suspension import MasterEmergencySuspension

class SecurityEnforcer:
    def __init__(self, policy: PolicyEngine | None = None, *,
                 approval_verifier: ApprovalVerifier | None = None,
                 emergency_suspension: MasterEmergencySuspension | None = None,
                 require_emergency_control: bool = False) -> None:
        self._policy = policy or PolicyEngine(
            approval_verifier, emergency_suspension=emergency_suspension,
            require_emergency_control=require_emergency_control,
        )
    def authorize_action(self, envelope: AuthorizationEnvelope | None, locator: str,
                         method: str, *, mission_approval: Approval | None = None,
                         action_approval: Approval | None = None,
                         requires_human_approval: bool = False) -> PolicyDecision:
        return self._policy.evaluate(envelope=envelope, locator=locator, method=method,
            mission_approval=mission_approval, action_approval=action_approval,
            requires_human_approval=requires_human_approval)
    def validate_approval(self, approval: Approval | None, expected_digest: str,
                          expected_approval_id: str | None,
                          now: datetime | None = None) -> bool:
        return self._policy.validate_approval(approval, expected_digest, expected_approval_id, now)
