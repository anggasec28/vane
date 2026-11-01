from datetime import datetime, timedelta, timezone

import pytest

from vane.security.approval import Approval
from vane.security.emergency_suspension import (
    MasterEmergencySuspension, SuspensionStatus, suspension_approval_digest,
)
from vane.storage.sqlite_store import SQLiteStore


class AcceptingVerifier:
    def verify(self, approval):
        return approval.signature == "verified"


def make_approval(operation, revision, reason, authority, trigger, *,
                  approver="master-telegram-principal", key_id="master-key",
                  now=None):
    current = now or datetime.now(timezone.utc)
    digest = suspension_approval_digest(
        operation=operation, expected_revision=revision,
        master_principal="master-telegram-principal", reason=reason,
        authority_reference=authority, trigger=trigger,
    )
    return Approval(
        approval_id=f"approval-{revision}-{operation.value}",
        approver=approver, subject_digest=digest, decision="APPROVE",
        decided_at=current - timedelta(seconds=1), key_id=key_id,
        signature="verified", expires_at=current + timedelta(minutes=5),
    )


def controller(tmp_path):
    return MasterEmergencySuspension(
        SQLiteStore(tmp_path / "control.sqlite3"),
        master_principal="master-telegram-principal",
        master_key_ids={"master-key"}, verifier=AcceptingVerifier(),
    )


def test_master_can_suspend_and_release_with_action_bound_signed_approval(tmp_path):
    control = controller(tmp_path)
    assert control.is_suspended() is False
    now = datetime.now(timezone.utc)
    suspend = control.suspend(
        expected_revision=0, reason="Master emergency stop",
        authority_reference="master-directive-1", trigger="telegram-command",
        approval=make_approval(SuspensionStatus.SUSPENDED, 0, "Master emergency stop",
                               "master-directive-1", "telegram-command", now=now), now=now,
    )
    assert suspend.revision == 1
    assert control.is_suspended() is True
    release = control.release(
        expected_revision=1, reason="Master explicitly released suspension",
        authority_reference="master-directive-2", trigger="telegram-command",
        approval=make_approval(SuspensionStatus.ACTIVE, 1,
                               "Master explicitly released suspension",
                               "master-directive-2", "telegram-command", now=now), now=now,
    )
    assert release.status == SuspensionStatus.ACTIVE
    assert control.is_suspended() is False


def test_non_master_or_unapproved_key_cannot_suspend(tmp_path):
    control = controller(tmp_path)
    now = datetime.now(timezone.utc)
    approval = make_approval(
        SuspensionStatus.SUSPENDED, 0, "stop", "directive", "telegram",
        approver="specialist", now=now,
    )
    with pytest.raises(PermissionError, match="Master identity"):
        control.suspend(expected_revision=0, reason="stop", authority_reference="directive",
                        trigger="telegram", approval=approval, now=now)


def test_suspension_rejects_stale_revision_and_modified_reason(tmp_path):
    control = controller(tmp_path)
    now = datetime.now(timezone.utc)
    approval = make_approval(
        SuspensionStatus.SUSPENDED, 0, "original", "directive", "telegram", now=now,
    )
    with pytest.raises(PermissionError, match="signature"):
        control.suspend(expected_revision=0, reason="modified", authority_reference="directive",
                        trigger="telegram", approval=approval, now=now)
    with pytest.raises(ValueError, match="revision changed"):
        control.suspend(expected_revision=1, reason="original", authority_reference="directive",
                        trigger="telegram", approval=approval, now=now)


def test_suspension_fails_closed_on_tampered_chain(tmp_path):
    control = controller(tmp_path)
    control.store.append_chained_event(
        project_id=control.PROJECT_ID, event_type="unexpected", actor="unknown",
        payload={"tamper": True},
    )
    with pytest.raises(RuntimeError, match="integrity failed"):
        control.is_suspended()


def test_expired_master_approval_is_rejected(tmp_path):
    control = controller(tmp_path)
    now = datetime.now(timezone.utc)
    approval = make_approval(
        SuspensionStatus.SUSPENDED, 0, "stop", "directive", "telegram", now=now,
    )
    expired = Approval(
        approval_id=approval.approval_id, approver=approval.approver,
        subject_digest=approval.subject_digest, decision=approval.decision,
        decided_at=now - timedelta(minutes=10), key_id=approval.key_id,
        signature=approval.signature, expires_at=now - timedelta(minutes=1),
    )
    with pytest.raises(PermissionError, match="signature"):
        control.suspend(expected_revision=0, reason="stop", authority_reference="directive",
                        trigger="telegram", approval=expired, now=now)


def test_central_security_enforcement_blocks_actions_when_master_suspends(tmp_path):
    from vane.security.enforcement import SecurityEnforcer

    control = controller(tmp_path)
    enforcer = SecurityEnforcer(
        emergency_suspension=control, require_emergency_control=True,
    )
    now = datetime.now(timezone.utc)
    control.suspend(
        expected_revision=0, reason="Stop all operations",
        authority_reference="master-stop", trigger="telegram",
        approval=make_approval(
            SuspensionStatus.SUSPENDED, 0, "Stop all operations",
            "master-stop", "telegram", now=now,
        ), now=now,
    )
    decision = enforcer.authorize_action(None, "asset.example", "passive_scan")
    assert decision.allowed is False
    assert decision.code == "MASTER_EMERGENCY_SUSPENSION"


def test_central_enforcement_fails_closed_when_required_control_is_missing():
    from vane.security.enforcement import SecurityEnforcer

    enforcer = SecurityEnforcer(require_emergency_control=True)
    decision = enforcer.authorize_action(None, "asset.example", "passive_scan")
    assert decision.allowed is False
    assert decision.code == "EMERGENCY_CONTROL_UNAVAILABLE"
