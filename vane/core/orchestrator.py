"""Mission orchestration facade with centrally verified authorization references."""
from vane.core.state_machine import transition
from vane.models import AuthorizationEnvelope, Mission, MissionStatus
from vane.security.approval import Approval
from vane.security.digests import authorization_digest
from vane.security.enforcement import SecurityEnforcer

class AssessmentOrchestrator:
    def __init__(self, enforcer: SecurityEnforcer | None = None) -> None:
        self.enforcer = enforcer or SecurityEnforcer()
    def submit_for_approval(self, mission: Mission, *, actor: str) -> Mission:
        transition(mission, MissionStatus.AWAITING_APPROVAL, actor=actor,
                   reason="Submitted for explicit Master authorization.")
        return mission
    def authorize_mission(self, mission: Mission, envelope: AuthorizationEnvelope,
                          approval: Approval, *, actor: str) -> Mission:
        if mission.project_id != envelope.project_id:
            raise ValueError("Authorization envelope project does not match mission project.")
        if mission.status != MissionStatus.AWAITING_APPROVAL:
            raise ValueError("Mission must be awaiting approval before authorization.")
        if not envelope.is_time_valid():
            raise ValueError("Authorization envelope is invalid or lacks a finite validity window.")
        if (not self.enforcer.validate_approval(approval, authorization_digest(envelope),
                                                envelope.approval_id)
                or approval.expires_at is None or approval.expires_at > envelope.expires_at):
            raise ValueError("Approval signature is invalid or not bound to this authorization envelope.")
        mission.authorization_id = envelope.envelope_id
        transition(mission, MissionStatus.AUTHORIZED, actor=actor,
                   reason="Trusted Ed25519 approval bound to authorization envelope.")
        return mission
    def authorize_observation(self, envelope: AuthorizationEnvelope | None,
                              locator: str, method: str, *, mission_approval: Approval | None,
                              action_approval: Approval | None = None,
                              requires_human_approval: bool = False):
        return self.enforcer.authorize_action(envelope, locator, method,
            mission_approval=mission_approval, action_approval=action_approval,
            requires_human_approval=requires_human_approval)
