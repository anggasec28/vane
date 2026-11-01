"""Rebuildable, project-scoped relationship index derived from the authoritative ledger."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from enum import StrEnum

from vane.decisions.ledger import DecisionLedger, DecisionSnapshot


class RelationshipType(StrEnum):
    DEPENDS_ON = "DEPENDS_ON"
    SUPERSEDES = "SUPERSEDES"
    SHARES_EVIDENCE = "SHARES_EVIDENCE"


@dataclass(frozen=True, slots=True)
class DecisionRelationship:
    project_id: str
    source_decision_id: str
    target_decision_id: str
    relationship: RelationshipType
    evidence_reference: str | None = None


class DecisionRelationshipIndex:
    """A disposable projection. The ledger remains the sole authoritative source."""

    def __init__(self, project_id: str, snapshots: tuple[DecisionSnapshot, ...]) -> None:
        if not project_id.strip():
            raise ValueError("project_id is required.")
        self.project_id = project_id
        self._snapshots = {item.decision_id: item for item in snapshots
                           if item.project_id == project_id}
        if len(self._snapshots) != len(snapshots):
            raise ValueError("Relationship index accepts only one project's snapshots.")
        relationships: set[DecisionRelationship] = set()
        evidence_owners: dict[str, list[str]] = defaultdict(list)
        for item in self._snapshots.values():
            for dependency_id in item.dependency_decision_ids:
                if dependency_id in self._snapshots:
                    relationships.add(DecisionRelationship(
                        project_id, item.decision_id, dependency_id,
                        RelationshipType.DEPENDS_ON,
                    ))
            if item.superseded_by_decision_id:
                if item.superseded_by_decision_id in self._snapshots:
                    relationships.add(DecisionRelationship(
                        project_id, item.decision_id, item.superseded_by_decision_id,
                        RelationshipType.SUPERSEDES,
                    ))
            for evidence_id in item.evidence_references:
                evidence_owners[evidence_id].append(item.decision_id)
        for evidence_id, owners in evidence_owners.items():
            for index, left in enumerate(sorted(set(owners))):
                for right in sorted(set(owners))[index + 1:]:
                    relationships.add(DecisionRelationship(
                        project_id, left, right, RelationshipType.SHARES_EVIDENCE,
                        evidence_reference=evidence_id,
                    ))
                    relationships.add(DecisionRelationship(
                        project_id, right, left, RelationshipType.SHARES_EVIDENCE,
                        evidence_reference=evidence_id,
                    ))
        self.relationships = tuple(sorted(
            relationships,
            key=lambda item: (item.source_decision_id, item.relationship.value,
                              item.target_decision_id, item.evidence_reference or ""),
        ))
        adjacency: dict[str, set[str]] = defaultdict(set)
        for relation in self.relationships:
            adjacency[relation.source_decision_id].add(relation.target_decision_id)
            adjacency[relation.target_decision_id].add(relation.source_decision_id)
        self._adjacency = {key: tuple(sorted(values)) for key, values in adjacency.items()}

    @classmethod
    def rebuild(cls, ledger: DecisionLedger, project_id: str) -> "DecisionRelationshipIndex":
        """Rebuild from latest authoritative snapshots; never reads cached projections."""
        return cls(project_id, ledger.list_decisions(project_id))

    def related(self, decision_id: str, *, depth: int = 1) -> tuple[str, ...]:
        if depth < 1 or depth > 3:
            raise ValueError("Relationship traversal depth must be between 1 and 3.")
        if decision_id not in self._snapshots:
            raise KeyError(decision_id)
        visited = {decision_id}
        frontier = deque([(decision_id, 0)])
        while frontier:
            current, level = frontier.popleft()
            if level >= depth:
                continue
            for neighbor in self._adjacency.get(current, ()):
                if neighbor not in visited:
                    visited.add(neighbor)
                    frontier.append((neighbor, level + 1))
        visited.remove(decision_id)
        return tuple(sorted(visited))

    def snapshot(self, decision_id: str) -> DecisionSnapshot:
        try:
            return self._snapshots[decision_id]
        except KeyError:
            raise KeyError(decision_id) from None
