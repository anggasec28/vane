import pytest
from vane.errors import PolicyViolation
from vane.models import Mission, MissionStatus
from vane.core.state_machine import transition

def test_completion_requires_all_evidence():
    mission = Mission.create("p-1", "map approved surface")
    mission.status = MissionStatus.EVIDENCE_REVIEW
    mission.required_evidence = {"surface_map", "provenance"}
    with pytest.raises(PolicyViolation):
        transition(mission, MissionStatus.COMPLETED, actor="verifier")
    mission.completed_evidence = {"surface_map", "provenance"}
    transition(mission, MissionStatus.COMPLETED, actor="verifier")
    assert mission.status == MissionStatus.COMPLETED

def test_blocker_prevents_completion():
    mission = Mission.create("p-1", "assessment")
    mission.status = MissionStatus.EVIDENCE_REVIEW
    mission.blockers = ["target blocked"]
    with pytest.raises(PolicyViolation):
        transition(mission, MissionStatus.COMPLETED, actor="verifier")
