"""Exact approval for one eligible Test-only Single Update Run Spec."""

from __future__ import annotations

import hmac

from tridentine_calendar_google_sync.baseline_models import TrustedBaseline
from tridentine_calendar_google_sync.test_single_update_plan_models import (
    SINGLE_UPDATE_CHANGED_FIELDS,
    TestSingleUpdatePlan,
)
from tridentine_calendar_google_sync.test_single_update_run_spec import (
    TestSingleUpdateRunSpecError,
    verify_test_single_update_run_spec_bindings,
)
from tridentine_calendar_google_sync.test_single_update_run_spec_models import (
    TestSingleUpdateRunSpec,
)


class TestSingleUpdateApprovalError(TestSingleUpdateRunSpecError):
    """The exact Single Update approval inputs or phrase did not match."""


def _valid_hash(value: str | None) -> bool:
    return (
        value is not None
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def test_single_update_approval_challenge(
    run_spec: TestSingleUpdateRunSpec,
    plan: TestSingleUpdatePlan,
    baseline: TrustedBaseline,
    *,
    current_snapshot_hash: str,
    current_plan_hash: str,
    current_baseline_hash: str | None,
) -> str:
    """Return the existing phrase only after exact dedicated binding checks."""

    verify_test_single_update_run_spec_bindings(run_spec, plan, baseline)
    if not _valid_hash(current_snapshot_hash) or not hmac.compare_digest(
        run_spec.current_snapshot_hash,
        current_snapshot_hash,
    ):
        raise TestSingleUpdateApprovalError(
            "test_single_update_snapshot_stale_or_mismatched",
            "Single Update approval requires the exact current snapshot",
        )
    if (
        not _valid_hash(current_plan_hash)
        or not hmac.compare_digest(run_spec.single_update_plan_hash, current_plan_hash)
        or not hmac.compare_digest(plan.plan_content_hash, current_plan_hash)
    ):
        raise TestSingleUpdateApprovalError(
            "test_single_update_plan_stale_or_mismatched",
            "Single Update approval requires the exact dedicated Plan",
        )
    if (
        not _valid_hash(current_baseline_hash)
        or current_baseline_hash is None
        or not hmac.compare_digest(run_spec.trusted_baseline_hash, current_baseline_hash)
        or not hmac.compare_digest(baseline.baseline_content_hash, current_baseline_hash)
    ):
        raise TestSingleUpdateApprovalError(
            "test_single_update_baseline_stale_or_mismatched",
            "Single Update approval requires the exact trusted Test baseline",
        )
    if (
        run_spec.operation_count != 1
        or run_spec.add_count != 0
        or run_spec.update_count != 1
        or run_spec.delete_count != 0
        or run_spec.changed_fields != SINGLE_UPDATE_CHANGED_FIELDS
        or run_spec.operation.changed_fields != SINGLE_UPDATE_CHANGED_FIELDS
    ):
        raise TestSingleUpdateApprovalError(
            "test_single_update_approval_operation_mismatch",
            "Single Update approval requires one Description-only update",
        )
    return (
        f"AUTHORIZE TEST CALENDAR WRITE {run_spec.target_safe_ref} "
        f"R-{run_spec.run_spec_content_hash[:12]} A-0 U-1"
    )


def approve_test_single_update_run_spec(
    run_spec: TestSingleUpdateRunSpec,
    plan: TestSingleUpdatePlan,
    baseline: TrustedBaseline,
    confirmation: str,
    *,
    current_snapshot_hash: str,
    current_plan_hash: str,
    current_baseline_hash: str | None,
) -> TestSingleUpdateRunSpec:
    """Verify the exact phrase without mutating the private Run Spec."""

    expected = test_single_update_approval_challenge(
        run_spec,
        plan,
        baseline,
        current_snapshot_hash=current_snapshot_hash,
        current_plan_hash=current_plan_hash,
        current_baseline_hash=current_baseline_hash,
    )
    if not hmac.compare_digest(
        confirmation.encode("utf-8", errors="strict"),
        expected.encode("utf-8", errors="strict"),
    ):
        raise TestSingleUpdateApprovalError(
            "test_single_update_approval_mismatch",
            "Test Single Update approval did not exactly match",
        )
    verify_test_single_update_run_spec_bindings(run_spec, plan, baseline)
    return run_spec


__all__ = [
    "TestSingleUpdateApprovalError",
    "approve_test_single_update_run_spec",
    "test_single_update_approval_challenge",
]
