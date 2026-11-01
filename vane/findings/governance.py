"""Evidence-linked finding lifecycle."""
from vane.errors import PolicyViolation
from vane.models import EvidenceRecord, EvidenceStatus, Finding, FindingStatus

def validate_finding(finding: Finding, evidence: dict[str, EvidenceRecord]) -> None:
    if not finding.title.strip() or not finding.description.strip():
        raise PolicyViolation("Finding requires a title and description.")
    if not finding.evidence_ids:
        raise PolicyViolation("A finding cannot be validated without linked evidence.")
    missing = set(finding.evidence_ids) - evidence.keys()
    if missing:
        raise PolicyViolation("Finding references missing evidence: " + ", ".join(sorted(missing)))
    bad = [eid for eid in finding.evidence_ids if evidence[eid].status in
           {EvidenceStatus.DISPUTED, EvidenceStatus.INSUFFICIENT}]
    if bad:
        raise PolicyViolation("Finding relies on disputed or insufficient evidence: " + ", ".join(bad))
    finding.status = FindingStatus.VALIDATED
