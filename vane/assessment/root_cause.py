"""Root-cause graph primitives; dependency links do not confer scope."""
from dataclasses import dataclass, field

@dataclass(slots=True)
class DependencyNode:
    node_id: str
    label: str
    evidence_ids: list[str] = field(default_factory=list)
    in_scope: bool = False

@dataclass(slots=True)
class DependencyGraph:
    nodes: dict[str, DependencyNode] = field(default_factory=dict)
    edges: set[tuple[str, str, str]] = field(default_factory=set)
    def add_node(self, node: DependencyNode) -> None:
        self.nodes[node.node_id] = node
    def add_edge(self, source: str, target: str, relation: str) -> None:
        if source not in self.nodes or target not in self.nodes:
            raise KeyError("Both nodes must exist before linking.")
        self.edges.add((source, target, relation))
    def in_scope_neighborhood(self, start: str) -> set[str]:
        if start not in self.nodes:
            return set()
        reached = {start}; changed = True
        while changed:
            changed = False
            for left, right, _ in self.edges:
                if left in reached and right not in reached and self.nodes[right].in_scope:
                    reached.add(right); changed = True
                if right in reached and left not in reached and self.nodes[left].in_scope:
                    reached.add(left); changed = True
        return {n for n in reached if self.nodes[n].in_scope}
