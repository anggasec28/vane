"""Independent validation rules for assessment outputs."""
from dataclasses import dataclass
from vane.models import EvidenceRecord, Finding, Mission, MissionStatus

@dataclass(frozen=True, slots=True)
class ValidationFinding:
    code: str
    passed: bool
    detail: str

def validate_mission_closure(mission: Mission, evidence: dict[str, EvidenceRecord],
                             findings: list[Finding]) -> tuple[ValidationFinding, ...]:
    checks: list[ValidationFinding] = []
    missing = mission.required_evidence - mission.completed_evidence
    checks.append(ValidationFinding("EVIDENCE_COMPLETE", not missing,
        "All required evidence is present." if not missing else f"Missing: {sorted(missing)}"))
    checks.append(ValidationFinding("NO_BLOCKERS", not mission.blockers,
        "No unresolved blockers." if not mission.blockers else f"Blockers: {mission.blockers}"))
    unknown = [f.finding_id for f in findings if any(eid not in evidence for eid in f.evidence_ids)]
    checks.append(ValidationFinding("FINDING_REFERENCES", not unknown,
        "All finding evidence references resolve." if not unknown else f"Unresolved evidence: {unknown}"))
    checks.append(ValidationFinding("MISSION_STATE", mission.status in
        {MissionStatus.COMPLETED, MissionStatus.CLOSED},
        f"Mission state is {mission.status.value}."))
    return tuple(checks)
