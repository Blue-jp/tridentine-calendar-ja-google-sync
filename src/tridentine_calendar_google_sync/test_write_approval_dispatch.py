"""Approval dispatch preserving normal behavior across dedicated Run Specs."""

from __future__ import annotations

from tridentine_calendar_google_sync.baseline_models import TrustedBaseline
from tridentine_calendar_google_sync.test_bootstrap_approval import (
    approve_test_bootstrap_add_run_spec,
    test_bootstrap_add_approval_challenge,
)
from tridentine_calendar_google_sync.test_bootstrap_plan_models import TestBootstrapAddPlan
from tridentine_calendar_google_sync.test_bootstrap_run_spec_models import (
    TestBootstrapAddRunSpec,
)
from tridentine_calendar_google_sync.test_single_update_approval import (
    approve_test_single_update_run_spec,
    test_single_update_approval_challenge,
)
from tridentine_calendar_google_sync.test_single_update_plan_models import (
    TestSingleUpdatePlan,
)
from tridentine_calendar_google_sync.test_single_update_run_spec_models import (
    TestSingleUpdateRunSpec,
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
    single_update_plan: TestSingleUpdatePlan | None = None,
    trusted_baseline: TrustedBaseline | None = None,
) -> str:
    """Return the unchanged phrase format through exact type dispatch."""

    if isinstance(run_spec, TestBootstrapAddRunSpec):
        if bootstrap_plan is None or single_update_plan is not None or trusted_baseline is not None:
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
    if isinstance(run_spec, TestSingleUpdateRunSpec):
        if single_update_plan is None or trusted_baseline is None or bootstrap_plan is not None:
            raise TestWriteSpecDispatchError(
                "test_single_update_artifacts_required",
                "Single Update approval requires its exact Plan and trusted baseline",
            )
        return test_single_update_approval_challenge(
            run_spec,
            single_update_plan,
            trusted_baseline,
            current_snapshot_hash=current_snapshot_hash,
            current_plan_hash=current_plan_hash,
            current_baseline_hash=current_baseline_hash,
        )
    if isinstance(run_spec, TestWriteRunSpec):
        if (
            bootstrap_plan is not None
            or single_update_plan is not None
            or trusted_baseline is not None
        ):
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
    single_update_plan: TestSingleUpdatePlan | None = None,
    trusted_baseline: TrustedBaseline | None = None,
) -> AnyTestWriteRunSpec:
    """Approve one exact Run Spec type without fallback conversion."""

    if isinstance(run_spec, TestBootstrapAddRunSpec):
        if bootstrap_plan is None or single_update_plan is not None or trusted_baseline is not None:
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
    if isinstance(run_spec, TestSingleUpdateRunSpec):
        if single_update_plan is None or trusted_baseline is None or bootstrap_plan is not None:
            raise TestWriteSpecDispatchError(
                "test_single_update_artifacts_required",
                "Single Update approval requires its exact Plan and trusted baseline",
            )
        return approve_test_single_update_run_spec(
            run_spec,
            single_update_plan,
            trusted_baseline,
            confirmation,
            current_snapshot_hash=current_snapshot_hash,
            current_plan_hash=current_plan_hash,
            current_baseline_hash=current_baseline_hash,
        )
    if isinstance(run_spec, TestWriteRunSpec):
        if (
            bootstrap_plan is not None
            or single_update_plan is not None
            or trusted_baseline is not None
        ):
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
