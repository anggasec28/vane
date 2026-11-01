"""Auditable data-lifecycle review records; no destructive action is executed."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from vane.errors import PolicyViolation
from vane.lifecycle.policy import DataClass, LifecycleAction, LifecycleContext, decide_lifecycle


@dataclass(frozen=True, slots=True)
class LifecycleReview:
    review_id: str
    project_id: str
    record_id: str
    data_class: DataClass
    project_active: bool
    disputed: bool
    legal_or_contractual_hold: bool
    ownership_known: bool
    retention_expired: bool
    action: LifecycleAction
    rationale: str
    actor: str
    reviewed_at: datetime
    approval_reference: str | None = None


def create_lifecycle_review(*, review_id: str, project_id: str, record_id: str,
                            context: LifecycleContext, rationale: str, actor: str,
                            approval_reference: str | None = None,
                            reviewed_at: datetime | None = None) -> LifecycleReview:
    if not all((review_id, project_id, record_id, rationale.strip(), actor.strip())):
        raise PolicyViolation("Lifecycle review requires identity, rationale, and actor.")
    timestamp = reviewed_at or datetime.now(timezone.utc)
    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
        raise PolicyViolation("Lifecycle review timestamp must be timezone-aware.")
    action = decide_lifecycle(context)
    if action == LifecycleAction.PRESERVE and not rationale.strip():
        raise PolicyViolation("Preservation decisions require a recorded rationale.")
    return LifecycleReview(
        review_id=review_id, project_id=project_id, record_id=record_id,
        data_class=context.data_class, project_active=context.project_active,
        disputed=context.disputed, legal_or_contractual_hold=context.legal_or_contractual_hold,
        ownership_known=context.ownership_known, retention_expired=context.retention_expired,
        action=action, rationale=rationale, actor=actor, reviewed_at=timestamp,
        approval_reference=approval_reference,
    )


def validate_lifecycle_review(review: LifecycleReview) -> None:
    expected = decide_lifecycle(LifecycleContext(
        data_class=review.data_class, project_active=review.project_active,
        disputed=review.disputed, legal_or_contractual_hold=review.legal_or_contractual_hold,
        ownership_known=review.ownership_known, retention_expired=review.retention_expired,
    ))
    if review.action != expected:
        raise PolicyViolation("Lifecycle action does not match the approved policy decision.")
    if review.reviewed_at.tzinfo is None or review.reviewed_at.utcoffset() is None:
        raise PolicyViolation("Lifecycle review timestamp must be timezone-aware.")
    if not review.rationale.strip() or not review.actor.strip():
        raise PolicyViolation("Lifecycle review rationale and actor are required.")
    if review.action == LifecycleAction.DISPOSE_PENDING_APPROVAL and not review.approval_reference:
        # This remains a pending recommendation; no deletion is authorized by this record.
        return
