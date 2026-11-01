from datetime import datetime, timezone

import pytest

from vane.errors import PolicyViolation
from vane.findings.reporting import build_report
from vane.models import EvidenceRecord, Finding, Mission
from vane.workers.catalog import default_specialist_registry


def test_specialist_registry_exposes_eight_bounded_roles():
    registry = default_specialist_registry()
    assert len(registry.profile_ids) == 8
    with pytest.raises(PolicyViolation):
        registry.get("unregistered-role")


def test_report_rejects_evidence_from_another_mission():
    mission = Mission("m1", "p1", "review")
    finding = Finding("f1", "p1", "Finding", "Description", "high",
                      evidence_ids=["e2"])
    evidence = EvidenceRecord("e2", "p1", "different-mission", "source", "repo",
        datetime.now(timezone.utc), "a" * 64, authorization_id="auth")
    with pytest.raises(PolicyViolation):
        build_report(mission, [finding], {"e2": evidence}, report_id="report-1")
