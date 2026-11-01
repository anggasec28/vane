from vane.assessment.graph import EvidenceGraph, GraphEdge, GraphNode
from vane.errors import PolicyViolation
import pytest


def test_graph_paths_are_bounded_and_scope_filtered():
    graph = EvidenceGraph(
        [GraphNode("a", "A", "asset-a"), GraphNode("b", "B", "asset-b"),
         GraphNode("c", "C", "asset-c")],
        [GraphEdge("a", "b", "depends_on", ("ev-1",)),
         GraphEdge("b", "c", "calls", ("ev-2",))],
    )
    assert len(graph.paths("a", max_depth=1)) == 1
    assert len(graph.paths("a", allowed_asset_ids={"asset-a", "asset-b"})) == 1
    assert graph.paths("a", allowed_asset_ids={"asset-b"}) == ()
    assert graph.paths("a", allowed_asset_ids=set()) == ()


def test_graph_rejects_dangling_edges_and_reports_missing_evidence():
    with pytest.raises(PolicyViolation):
        EvidenceGraph([GraphNode("a", "A")], [GraphEdge("a", "missing", "calls")])
    graph = EvidenceGraph([GraphNode("a", "A", evidence_ids=("ev-x",))], [])
    assert graph.validate_evidence_links(set()) == ("ev-x",)
