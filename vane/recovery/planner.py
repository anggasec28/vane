"""Recovery recommendations that never broaden scope or bypass a denied control."""
from dataclasses import dataclass
from enum import StrEnum

class RecoveryAction(StrEnum):
    RETRY_SAME_OBSERVATION = "RETRY_SAME_OBSERVATION"
    USE_APPROVED_ALTERNATE_METHOD = "USE_APPROVED_ALTERNATE_METHOD"
    REQUEST_SCOPE_OR_METHOD_APPROVAL = "REQUEST_SCOPE_OR_METHOD_APPROVAL"
    RECORD_BLOCKER = "RECORD_BLOCKER"

@dataclass(frozen=True, slots=True)
class RecoveryPlan:
    action: RecoveryAction
    rationale: str
    requires_approval: bool = False

def plan_recovery(*, transient: bool, alternate_method_is_approved: bool,
                  failure_reason: str) -> RecoveryPlan:
    if transient:
        return RecoveryPlan(RecoveryAction.RETRY_SAME_OBSERVATION,
                            "Retry only the same in-scope observation after bounded backoff.")
    if alternate_method_is_approved:
        return RecoveryPlan(RecoveryAction.USE_APPROVED_ALTERNATE_METHOD,
                            "Use only the already-approved alternate method.")
    if "scope" in failure_reason.lower() or "authorization" in failure_reason.lower():
        return RecoveryPlan(RecoveryAction.REQUEST_SCOPE_OR_METHOD_APPROVAL,
                            "The current envelope does not cover the proposed recovery.", True)
    return RecoveryPlan(RecoveryAction.RECORD_BLOCKER,
                        "Preserve the failure as a blocker; do not bypass the control.")
