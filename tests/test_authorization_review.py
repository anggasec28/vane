from datetime import datetime, timedelta, timezone
from vane.assessment.authorization_review import review_envelope
from vane.models import AuthorizationEnvelope, ScopeRule

def test_envelope_review_requires_approval_reference():
    envelope = AuthorizationEnvelope("a1", "master", "p1",
        (ScopeRule("hostname", "example.com"),), ("http_metadata",),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1))
    result = review_envelope(envelope)
    assert not result.valid
    assert "missing_approval_reference" in result.issues
