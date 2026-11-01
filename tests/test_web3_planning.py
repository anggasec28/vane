from datetime import datetime, timedelta, timezone
import pytest
from vane.assessment.web3 import plan_contract_review
from vane.errors import AuthorizationError
from vane.models import AuthorizationEnvelope, ScopeRule

def envelope(methods=("contract_read",)):
    return AuthorizationEnvelope("a1", "master", "p1",
        (ScopeRule("contract", "0x1234"),), methods,
        starts_at=datetime.now(timezone.utc) - timedelta(minutes=1),
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1), approval_id="ap1")

def test_web3_plan_requires_exact_contract_and_method():
    plan = plan_contract_review("1", "0x1234", envelope())
    assert "access_control" in plan.review_tracks
    with pytest.raises(AuthorizationError):
        plan_contract_review("1", "0x5678", envelope())
    with pytest.raises(AuthorizationError):
        plan_contract_review("1", "0x1234", envelope(("transaction_submit",)))
