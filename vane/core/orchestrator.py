"""Mission orchestration facade with centralized authorization."""
from vane.core.state_machine import transition
from vane.models import AuthorizationEnvelope, Mission, MissionStatus
from vane.security.enforcement import SecurityEnforcer

class AssessmentOrchestrator:
    def __init__(self, enforcer: SecurityEnforcer | None = None) -> None:
        self.enforcer = enforcer or SecurityEnforcer()
    def submit_for_approval(self, mission: Mission, *, actor: str) -> Mission:
        transition(mission, MissionStatus.AWAITING_APPROVAL, actor=actor,
                   reason="Submitted for explicit Master authorization.")
        return mission
    def authorize_mission(self, mission: Mission, envelope: AuthorizationEnvelope,
                          *, actor: str) -> Mission:
        if mission.project_id != envelope.project_id:
            raise ValueError("Authorization envelope project does not match mission project.")
        if mission.status != MissionStatus.AWAITING_APPROVAL:
            raise ValueError("Mission must be awaiting approval before authorization.")
        if not envelope.is_time_valid():
            raise ValueError("Authorization envelope is revoked, not yet valid, or expired.")
        mission.authorization_id = envelope.envelope_id
        transition(mission, MissionStatus.AUTHORIZED, actor=actor,
                   reason="Valid authorization envelope attached.")
        return mission
    def authorize_observation(self, envelope: AuthorizationEnvelope | None,
                              locator: str, method: str):
        return self.enforcer.authorize_action(envelope, locator, method)
