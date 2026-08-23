"""Exact approval challenge for one Test Calendar write Run Spec."""

from __future__ import annotations

import hmac

from tridentine_calendar_google_sync.test_write_models import TestWriteRunSpec
from tridentine_calendar_google_sync.test_write_run_spec import (
    TestWriteRunSpecError,
    verify_test_write_run_spec,
)


class TestWriteApprovalError(TestWriteRunSpecError):
    """The exact Test Calendar write approval was absent or mismatched."""


def _valid_hash(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def test_write_approval_challenge(
    run_spec: TestWriteRunSpec,
    *,
    current_snapshot_hash: str,
    current_plan_hash: str,
    current_baseline_hash: str | None = None,
) -> str:
    """Return the exact phrase for this intact, current, one-operation Test run."""

    verify_test_write_run_spec(run_spec)
    if not _valid_hash(current_snapshot_hash) or not hmac.compare_digest(
        run_spec.current_snapshot_hash, current_snapshot_hash
    ):
        raise TestWriteApprovalError(
            "test_write_snapshot_stale_or_mismatched",
            "Test write approval requires the exact current snapshot",
        )
    if not _valid_hash(current_plan_hash) or not hmac.compare_digest(
        run_spec.plan_hash,
        current_plan_hash,
    ):
        raise TestWriteApprovalError(
            "test_write_plan_stale_or_mismatched",
            "Test write approval requires the exact current Sync Plan",
        )
    expected_baseline = run_spec.trusted_baseline_hash
    if expected_baseline is None:
        if current_baseline_hash is not None:
            raise TestWriteApprovalError(
                "test_write_add_baseline_unexpected",
                "Test write add approval does not accept a baseline artifact",
            )
    elif (
        current_baseline_hash is None
        or not _valid_hash(current_baseline_hash)
        or not hmac.compare_digest(expected_baseline, current_baseline_hash)
    ):
        raise TestWriteApprovalError(
            "test_write_baseline_stale_or_mismatched",
            "Test write update approval requires the exact trusted Test baseline",
        )
    return (
        f"AUTHORIZE TEST CALENDAR WRITE {run_spec.target_safe_ref} "
        f"R-{run_spec.run_spec_content_hash[:12]} "
        f"A-{run_spec.add_count} U-{run_spec.update_count}"
    )


def approve_test_write_run_spec(
    run_spec: TestWriteRunSpec,
    confirmation: str,
    *,
    current_snapshot_hash: str,
    current_plan_hash: str,
    current_baseline_hash: str | None = None,
) -> TestWriteRunSpec:
    """Verify exact approval without mutating or weakening the private Run Spec."""

    expected = test_write_approval_challenge(
        run_spec,
        current_snapshot_hash=current_snapshot_hash,
        current_plan_hash=current_plan_hash,
        current_baseline_hash=current_baseline_hash,
    )
    if not hmac.compare_digest(
        confirmation.encode("utf-8", errors="strict"),
        expected.encode("utf-8", errors="strict"),
    ):
        raise TestWriteApprovalError(
            "test_write_approval_mismatch",
            "Test Calendar write approval did not exactly match",
        )
    verify_test_write_run_spec(run_spec)
    return run_spec


__all__ = [
    "TestWriteApprovalError",
    "approve_test_write_run_spec",
    "test_write_approval_challenge",
]
