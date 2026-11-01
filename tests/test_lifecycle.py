from vane.lifecycle.policy import (DataClass, LifecycleAction, LifecycleContext, decide_lifecycle)

def test_unknown_ownership_is_preserved():
    context = LifecycleContext(DataClass.UNKNOWN, False, ownership_known=False, retention_expired=True)
    assert decide_lifecycle(context) == LifecycleAction.PRESERVE

def test_expired_data_requires_approval_before_disposal():
    context = LifecycleContext(DataClass.INTERNAL, False, retention_expired=True)
    assert decide_lifecycle(context) == LifecycleAction.DISPOSE_PENDING_APPROVAL
