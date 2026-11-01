"""Remediation planning records and deterministic readiness checks."""
from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from vane.errors import PolicyViolation
from vane.models import Finding, FindingStatus


class RemediationStatus(StrEnum):
    PROPOSED = "PROPOSED"
    APPROVED = "APPROVED"
    IN_PROGRESS = "IN_PROGRESS"
    BLOCKED = "BLOCKED"
    READY_FOR_VERIFICATION = "READY_FOR_VERIFICATION"
    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"


@dataclass(frozen=True, slots=True)
class RemediationAction:
    action_id: str
    finding_id: str
    title: str
    description: str
    owner: str
    priority: str
    dependencies: tuple[str, ...]
    verification_criteria: tuple[str, ...]
    status: RemediationStatus = RemediationStatus.PROPOSED
    verification_evidence_ids: tuple[str, ...] = ()


def validate_remediation(action: RemediationAction, findings: dict[str, Finding],
                         known_action_ids: set[str]) -> None:
    if not all((action.action_id, action.finding_id, action.title.strip(),
                action.description.strip(), action.owner.strip())):
        raise PolicyViolation("Remediation action identity, title, description, and owner are required.")
    finding = findings.get(action.finding_id)
    if finding is None or finding.status not in {FindingStatus.ACCEPTED, FindingStatus.CLOSED}:
        raise PolicyViolation("Remediation must reference an accepted or closed finding.")
    if action.priority.lower() not in {"critical", "high", "medium", "low"}:
        raise PolicyViolation("Remediation priority must be critical, high, medium, or low.")
    if action.action_id in action.dependencies:
        raise PolicyViolation("A remediation action cannot depend on itself.")
    missing = set(action.dependencies) - known_action_ids
    if missing:
        raise PolicyViolation("Unknown remediation dependencies: " + ", ".join(sorted(missing)))
    if action.status == RemediationStatus.VERIFIED and not action.verification_evidence_ids:
        raise PolicyViolation("Verified remediation requires verification evidence references.")
    if action.status == RemediationStatus.READY_FOR_VERIFICATION and not action.verification_criteria:
        raise PolicyViolation("Verification readiness requires explicit criteria.")


def validate_remediation_graph(actions: list[RemediationAction]) -> None:
    """Reject dependency cycles across a complete remediation plan."""
    by_id = {action.action_id: action for action in actions}
    if len(by_id) != len(actions):
        raise PolicyViolation("Remediation action IDs must be unique.")
    graph = {action_id: set(action.dependencies) for action_id, action in by_id.items()}
    for action_id, dependencies in graph.items():
        missing = dependencies - by_id.keys()
        if missing:
            raise PolicyViolation("Unknown remediation dependencies: " + ", ".join(sorted(missing)))
        if action_id in dependencies:
            raise PolicyViolation("A remediation action cannot depend on itself.")
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(action_id: str) -> None:
        if action_id in visiting:
            raise PolicyViolation("Remediation dependency cycle detected.")
        if action_id in visited:
            return
        visiting.add(action_id)
        for dependency in graph[action_id]:
            visit(dependency)
        visiting.remove(action_id)
        visited.add(action_id)

    for action_id in graph:
        visit(action_id)
