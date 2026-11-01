"""Evidence-linked finding lifecycle."""
from vane.errors import PolicyViolation
from vane.models import EvidenceRecord, EvidenceStatus, Finding, FindingStatus

_ALLOWED_SEVERITIES = {"info", "low", "medium", "high", "critical", "unknown"}

def validate_finding(finding: Finding, evidence: dict[str, EvidenceRecord]) -> None:
    if not finding.title.strip() or not finding.description.strip():
        raise PolicyViolation("Finding requires a title and description.")
    if finding.severity.lower() not in _ALLOWED_SEVERITIES:
        raise PolicyViolation("Finding severity is not a supported normalized value.")
    if not finding.evidence_ids:
        raise PolicyViolation("A finding cannot be validated without linked evidence.")
    if len(finding.evidence_ids) != len(set(finding.evidence_ids)):
        raise PolicyViolation("Finding evidence references must be unique.")
    missing = set(finding.evidence_ids) - evidence.keys()
    if missing:
        raise PolicyViolation("Finding references missing evidence: " + ", ".join(sorted(missing)))
    wrong_project = [eid for eid in finding.evidence_ids
                     if evidence[eid].project_id != finding.project_id]
    if wrong_project:
        raise PolicyViolation("Finding references evidence from another project: " + ", ".join(wrong_project))
    bad = [eid for eid in finding.evidence_ids if evidence[eid].status in
           {EvidenceStatus.DISPUTED, EvidenceStatus.INSUFFICIENT}]
    if bad:
        raise PolicyViolation("Finding relies on disputed or insufficient evidence: " + ", ".join(bad))
    finding.status = FindingStatus.VALIDATED
