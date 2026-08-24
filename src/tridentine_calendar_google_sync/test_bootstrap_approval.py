"""Exact offline approval for one eligible Test bootstrap Add Run Spec."""

from __future__ import annotations

import hmac

from tridentine_calendar_google_sync.test_bootstrap_plan_models import TestBootstrapAddPlan
from tridentine_calendar_google_sync.test_bootstrap_run_spec import (
    TestBootstrapRunSpecError,
    verify_test_bootstrap_add_run_spec_plan,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec_models import (
    TestBootstrapAddRunSpec,
)


class TestBootstrapApprovalError(TestBootstrapRunSpecError):
    """The Bootstrap approval phrase or its bound inputs did not match."""


def _valid_hash(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def test_bootstrap_add_approval_challenge(
    run_spec: TestBootstrapAddRunSpec,
    plan: TestBootstrapAddPlan,
    *,
    current_snapshot_hash: str,
    current_plan_hash: str,
    current_baseline_hash: str | None = None,
) -> str:
    """Return the existing phrase format only after Bootstrap eligibility verification."""

    verify_test_bootstrap_add_run_spec_plan(run_spec, plan)
    if not _valid_hash(current_snapshot_hash) or not hmac.compare_digest(
        run_spec.current_snapshot_hash, current_snapshot_hash
    ):
        raise TestBootstrapApprovalError(
            "test_bootstrap_snapshot_stale_or_mismatched",
            "Bootstrap approval requires the exact empty Test snapshot",
        )
    if (
        not _valid_hash(current_plan_hash)
        or not hmac.compare_digest(run_spec.bootstrap_plan_hash, current_plan_hash)
        or not hmac.compare_digest(plan.plan_content_hash, current_plan_hash)
    ):
        raise TestBootstrapApprovalError(
            "test_bootstrap_plan_stale_or_mismatched",
            "Bootstrap approval requires the exact eligible plan",
        )
    if current_baseline_hash is not None or run_spec.trusted_baseline_hash is not None:
        raise TestBootstrapApprovalError(
            "test_bootstrap_baseline_forbidden",
            "Bootstrap initial Add cannot use a trusted baseline",
        )
    if (
        run_spec.snapshot_event_count != 0
        or run_spec.operation_count != 1
        or run_spec.add_count != 1
        or run_spec.update_count != 0
        or run_spec.delete_count != 0
    ):
        raise TestBootstrapApprovalError(
            "test_bootstrap_approval_operation_mismatch",
            "Bootstrap approval requires exactly one Add operation",
        )
    return (
        f"AUTHORIZE TEST CALENDAR WRITE {run_spec.target_safe_ref} "
        f"R-{run_spec.run_spec_content_hash[:12]} A-1 U-0"
    )


def approve_test_bootstrap_add_run_spec(
    run_spec: TestBootstrapAddRunSpec,
    plan: TestBootstrapAddPlan,
    confirmation: str,
    *,
    current_snapshot_hash: str,
    current_plan_hash: str,
    current_baseline_hash: str | None = None,
) -> TestBootstrapAddRunSpec:
    """Verify exact confirmation without changing the private Run Spec."""

    expected = test_bootstrap_add_approval_challenge(
        run_spec,
        plan,
        current_snapshot_hash=current_snapshot_hash,
        current_plan_hash=current_plan_hash,
        current_baseline_hash=current_baseline_hash,
    )
    if not hmac.compare_digest(
        confirmation.encode("utf-8", errors="strict"),
        expected.encode("utf-8", errors="strict"),
    ):
        raise TestBootstrapApprovalError(
            "test_bootstrap_approval_mismatch",
            "Test bootstrap Add approval did not exactly match",
        )
    verify_test_bootstrap_add_run_spec_plan(run_spec, plan)
    return run_spec


__all__ = [
    "TestBootstrapApprovalError",
    "approve_test_bootstrap_add_run_spec",
    "test_bootstrap_add_approval_challenge",
]
