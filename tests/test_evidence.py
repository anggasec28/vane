import pytest
from vane.errors import EvidenceError
from vane.evidence.manager import validate_evidence
from vane.models import EvidenceRecord

def test_evidence_requires_authorization_link():
    record = EvidenceRecord("e1", "p1", "m1", "http_observation", "operator",
                            __import__("datetime").datetime.now(__import__("datetime").timezone.utc),
                            "a" * 64)
    with pytest.raises(EvidenceError):
        validate_evidence(record)
