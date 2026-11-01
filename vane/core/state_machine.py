"""Explicit mission lifecycle. Closure is evidence-gated, never inferred from task completion."""
from vane.errors import InvalidTransition, PolicyViolation
from vane.models import Mission, MissionStatus

_ALLOWED = {
    MissionStatus.DRAFT: {MissionStatus.AWAITING_APPROVAL, MissionStatus.REJECTED},
    MissionStatus.AWAITING_APPROVAL: {MissionStatus.AUTHORIZED, MissionStatus.REJECTED},
    MissionStatus.AUTHORIZED: {MissionStatus.RUNNING, MissionStatus.BLOCKED},
    MissionStatus.RUNNING: {MissionStatus.BLOCKED, MissionStatus.EVIDENCE_REVIEW},
    MissionStatus.BLOCKED: {MissionStatus.RUNNING, MissionStatus.EVIDENCE_REVIEW},
    MissionStatus.EVIDENCE_REVIEW: {MissionStatus.RUNNING, MissionStatus.COMPLETED, MissionStatus.BLOCKED},
    MissionStatus.COMPLETED: {MissionStatus.CLOSED},
    MissionStatus.REJECTED: set(),
    MissionStatus.CLOSED: set(),
}

def transition(mission: Mission, target: MissionStatus, *, actor: str, reason: str = "") -> Mission:
    if target not in _ALLOWED[mission.status]:
        raise InvalidTransition(f"Transition {mission.status} -> {target} is not allowed.")
    if target == MissionStatus.COMPLETED:
        missing = mission.required_evidence - mission.completed_evidence
        if missing:
            raise PolicyViolation("Evidence sufficiency gate not met: " + ", ".join(sorted(missing)))
        if mission.blockers:
            raise PolicyViolation("Mission has unresolved blockers.")
    mission.history.append({"from": mission.status.value, "to": target.value,
                             "actor": actor, "reason": reason})
    mission.status = target
    return mission
