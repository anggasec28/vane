"""Hybrid policy-driven lifecycle decisions; unknown ownership is preserved."""
from dataclasses import dataclass
from enum import StrEnum

class DataClass(StrEnum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    SECRET = "SECRET"
    EVIDENCE = "EVIDENCE"
    UNKNOWN = "UNKNOWN"

class LifecycleAction(StrEnum):
    RETAIN = "RETAIN"
    REVIEW = "REVIEW"
    PRESERVE = "PRESERVE"
    DISPOSE_PENDING_APPROVAL = "DISPOSE_PENDING_APPROVAL"

@dataclass(frozen=True, slots=True)
class LifecycleContext:
    data_class: DataClass
    project_active: bool
    disputed: bool = False
    legal_or_contractual_hold: bool = False
    ownership_known: bool = True
    retention_expired: bool = False

def decide_lifecycle(context: LifecycleContext) -> LifecycleAction:
    if (not context.ownership_known or context.data_class == DataClass.UNKNOWN
            or context.disputed or context.legal_or_contractual_hold):
        return LifecycleAction.PRESERVE
    if context.project_active or not context.retention_expired:
        return LifecycleAction.RETAIN
    return LifecycleAction.DISPOSE_PENDING_APPROVAL
