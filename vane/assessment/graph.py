"""Evidence-aware dependency graph primitives. Graph edges never confer authorization."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from typing import Iterable

from vane.errors import PolicyViolation


@dataclass(frozen=True, slots=True)
class GraphNode:
    node_id: str
    label: str
    asset_id: str | None = None
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class GraphEdge:
    source: str
    target: str
    relation: str
    evidence_ids: tuple[str, ...] = ()
    confidence: str = "unknown"


@dataclass(frozen=True, slots=True)
class GraphPath:
    nodes: tuple[str, ...]
    edge_relations: tuple[str, ...]
    evidence_ids: tuple[str, ...]


class EvidenceGraph:
    """Bounded traversal over supplied graph facts with explicit evidence provenance."""

    def __init__(self, nodes: Iterable[GraphNode], edges: Iterable[GraphEdge]) -> None:
        node_list = tuple(nodes)
        self.nodes = {node.node_id: node for node in node_list}
        if len(self.nodes) != len(node_list):
            raise PolicyViolation("Graph node IDs must be unique.")
        self._adjacency: dict[str, list[GraphEdge]] = {node_id: [] for node_id in self.nodes}
        for edge in edges:
            if edge.source not in self.nodes or edge.target not in self.nodes:
                raise PolicyViolation("Graph edge references an unknown node.")
            if not edge.relation.strip():
                raise PolicyViolation("Graph edge relation must not be empty.")
            self._adjacency[edge.source].append(edge)

    def paths(self, start: str, *, max_depth: int = 4,
              allowed_asset_ids: set[str] | None = None) -> tuple[GraphPath, ...]:
        if start not in self.nodes:
            raise KeyError(start)
        if max_depth < 0 or max_depth > 32:
            raise ValueError("max_depth must be between 0 and 32.")
        results: list[GraphPath] = []
        queue = deque([(start, (start,), (), ())])
        while queue:
            current, path_nodes, relations, evidence = queue.popleft()
            if len(relations) >= max_depth:
                continue
            for edge in self._adjacency[current]:
                target = self.nodes[edge.target]
                if (allowed_asset_ids is not None and target.asset_id is not None
                        and target.asset_id not in allowed_asset_ids):
                    continue
                if edge.target in path_nodes:
                    continue
                merged = tuple(dict.fromkeys((*evidence, *edge.evidence_ids, *target.evidence_ids)))
                next_nodes = (*path_nodes, edge.target)
                next_relations = (*relations, edge.relation)
                results.append(GraphPath(next_nodes, next_relations, merged))
                queue.append((edge.target, next_nodes, next_relations, merged))
        return tuple(results)

    def validate_evidence_links(self, known_evidence_ids: set[str]) -> tuple[str, ...]:
        missing: set[str] = set()
        for node in self.nodes.values():
            missing.update(set(node.evidence_ids) - known_evidence_ids)
        for edges in self._adjacency.values():
            for edge in edges:
                missing.update(set(edge.evidence_ids) - known_evidence_ids)
        return tuple(sorted(missing))
