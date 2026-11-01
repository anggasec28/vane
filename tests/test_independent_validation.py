from vane.models import Mission, MissionStatus
from vane.validation.independent import validate_mission_closure

def test_independent_validator_flags_open_mission():
    mission = Mission.create("p1", "assessment")
    checks = validate_mission_closure(mission, {}, [])
    assert not next(c for c in checks if c.code == "MISSION_STATE").passed
