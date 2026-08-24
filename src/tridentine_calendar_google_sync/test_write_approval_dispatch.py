"""Approval dispatch preserving normal behavior and isolating Bootstrap checks."""

from __future__ import annotations

from tridentine_calendar_google_sync.test_bootstrap_approval import (
    approve_test_bootstrap_add_run_spec,
    test_bootstrap_add_approval_challenge,
)
from tridentine_calendar_google_sync.test_bootstrap_plan_models import TestBootstrapAddPlan
from tridentine_calendar_google_sync.test_bootstrap_run_spec_models import (
    TestBootstrapAddRunSpec,
)
from tridentine_calendar_google_sync.test_write_approval import (
    approve_test_write_run_spec,
    test_write_approval_challenge,
)
from tridentine_calendar_google_sync.test_write_models import TestWriteRunSpec
from tridentine_calendar_google_sync.test_write_spec_dispatch import (
    AnyTestWriteRunSpec,
    TestWriteSpecDispatchError,
)


def any_test_write_approval_challenge(
    run_spec: AnyTestWriteRunSpec,
    *,
    current_snapshot_hash: str,
    current_plan_hash: str,
    current_baseline_hash: str | None = None,
    bootstrap_plan: TestBootstrapAddPlan | None = None,
) -> str:
    """Return the unchanged phrase format through exact type dispatch."""

    if isinstance(run_spec, TestBootstrapAddRunSpec):
        if bootstrap_plan is None:
            raise TestWriteSpecDispatchError(
                "test_bootstrap_plan_required",
                "Bootstrap approval requires its exact Bootstrap Plan",
            )
        return test_bootstrap_add_approval_challenge(
            run_spec,
            bootstrap_plan,
            current_snapshot_hash=current_snapshot_hash,
            current_plan_hash=current_plan_hash,
            current_baseline_hash=current_baseline_hash,
        )
    if isinstance(run_spec, TestWriteRunSpec):
        if bootstrap_plan is not None:
            raise TestWriteSpecDispatchError(
                "normal_run_spec_bootstrap_plan_forbidden",
                "Normal approval cannot use a Bootstrap Plan",
            )
        return test_write_approval_challenge(
            run_spec,
            current_snapshot_hash=current_snapshot_hash,
            current_plan_hash=current_plan_hash,
            current_baseline_hash=current_baseline_hash,
        )
    raise TestWriteSpecDispatchError(
        "unknown_test_write_run_spec_type",
        "Test write Run Spec type is unsupported",
    )


def approve_any_test_write_run_spec(
    run_spec: AnyTestWriteRunSpec,
    confirmation: str,
    *,
    current_snapshot_hash: str,
    current_plan_hash: str,
    current_baseline_hash: str | None = None,
    bootstrap_plan: TestBootstrapAddPlan | None = None,
) -> AnyTestWriteRunSpec:
    """Approve one normal or Bootstrap Run Spec without fallback conversion."""

    if isinstance(run_spec, TestBootstrapAddRunSpec):
        if bootstrap_plan is None:
            raise TestWriteSpecDispatchError(
                "test_bootstrap_plan_required",
                "Bootstrap approval requires its exact Bootstrap Plan",
            )
        return approve_test_bootstrap_add_run_spec(
            run_spec,
            bootstrap_plan,
            confirmation,
            current_snapshot_hash=current_snapshot_hash,
            current_plan_hash=current_plan_hash,
            current_baseline_hash=current_baseline_hash,
        )
    if isinstance(run_spec, TestWriteRunSpec):
        if bootstrap_plan is not None:
            raise TestWriteSpecDispatchError(
                "normal_run_spec_bootstrap_plan_forbidden",
                "Normal approval cannot use a Bootstrap Plan",
            )
        return approve_test_write_run_spec(
            run_spec,
            confirmation,
            current_snapshot_hash=current_snapshot_hash,
            current_plan_hash=current_plan_hash,
            current_baseline_hash=current_baseline_hash,
        )
    raise TestWriteSpecDispatchError(
        "unknown_test_write_run_spec_type",
        "Test write Run Spec type is unsupported",
    )


__all__ = [
    "any_test_write_approval_challenge",
    "approve_any_test_write_run_spec",
]
