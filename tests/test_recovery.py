from vane.recovery.planner import RecoveryAction, plan_recovery

def test_recovery_never_bypasses_authorization():
    plan = plan_recovery(transient=False, alternate_method_is_approved=False,
                         failure_reason="authorization denied")
    assert plan.action == RecoveryAction.REQUEST_SCOPE_OR_METHOD_APPROVAL
    assert plan.requires_approval
