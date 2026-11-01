import pytest

from vane.assessment.graph import EvidenceGraph, GraphNode
from vane.errors import PolicyViolation
from vane.intelligence.threat_intel import IntelConfidence, ThreatIntelRecord, validate_intel
from vane.projects.case_ops import CaseWorkItem, validate_work_items
from vane.findings.remediation import RemediationAction, validate_remediation_graph
from datetime import datetime, timedelta, timezone


def test_graph_does_not_traverse_from_out_of_scope_start():
    graph = EvidenceGraph([GraphNode("outside", "Outside", "asset-x"),
                           GraphNode("inside", "Inside", "asset-y")], [])
    assert graph.paths("outside", allowed_asset_ids={"asset-y"}) == ()


def test_threat_intel_rejects_future_observation():
    now = datetime.now(timezone.utc)
    record = ThreatIntelRecord("i1", "feed", "https://feed.invalid/item", "Advisory",
        "Summary", now - timedelta(days=1), now + timedelta(minutes=1), None,
        ("CVE-2099-0001",), (), (), IntelConfidence.HIGH)
    with pytest.raises(PolicyViolation):
        validate_intel(record, now=now)


def test_case_work_item_dependency_cycle_is_rejected():
    now = datetime.now(timezone.utc)
    first = CaseWorkItem("a", "p", "m", "A", "owner", now, ("b",))
    second = CaseWorkItem("b", "p", "m", "B", "owner", now, ("a",))
    with pytest.raises(PolicyViolation):
        validate_work_items([first, second])


def test_remediation_dependency_cycle_is_rejected():
    first = RemediationAction("a", "f", "A", "A", "owner", "high", ("b",), ("verify",))
    second = RemediationAction("b", "f", "B", "B", "owner", "high", ("a",), ("verify",))
    with pytest.raises(PolicyViolation):
        validate_remediation_graph([first, second])
