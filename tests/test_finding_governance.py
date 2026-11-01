from datetime import datetime, timezone
import pytest
from vane.errors import PolicyViolation
from vane.findings.governance import validate_finding
from vane.models import EvidenceRecord, Finding, FindingStatus, EvidenceStatus

def evidence(status=EvidenceStatus.OBSERVED, project_id="p1"):
    return EvidenceRecord("e1", project_id, "m1", "http_observation", "operator",
        datetime.now(timezone.utc), "a" * 64, status=status, authorization_id="auth1")

def test_finding_requires_valid_linked_evidence():
    finding = Finding("f1", "p1", "Access control issue", "Observed behavior", "high",
                      evidence_ids=["e1"])
    validate_finding(finding, {"e1": evidence()})
    assert finding.status == FindingStatus.VALIDATED

def test_finding_rejects_cross_project_or_disputed_evidence():
    finding = Finding("f1", "p1", "Access control issue", "Observed behavior", "high",
                      evidence_ids=["e1"])
    with pytest.raises(PolicyViolation):
        validate_finding(finding, {"e1": evidence(project_id="p2")})
    with pytest.raises(PolicyViolation):
        validate_finding(finding, {"e1": evidence(status=EvidenceStatus.DISPUTED)})
