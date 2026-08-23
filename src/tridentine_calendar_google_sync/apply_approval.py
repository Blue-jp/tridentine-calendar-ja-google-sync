"""Exact test-only approval and simulation-state transitions."""

from __future__ import annotations

import hmac

from tridentine_calendar_google_sync.apply_bundle import (
    rebuild_apply_bundle_state,
    verify_apply_bundle_integrity,
)
from tridentine_calendar_google_sync.apply_models import ApplyBundle, ApplyBundleState
from tridentine_calendar_google_sync.apply_policy import (
    ApplyConfirmationError,
    ApplyGuardError,
    require_test_bundle,
)


def apply_approval_challenge(
    bundle: ApplyBundle,
    current_plan_content_hash: str,
) -> str:
    """Return the exact phrase required to authorize test simulation only."""

    verify_apply_bundle_integrity(bundle)
    require_test_bundle(bundle)
    if bundle.state is not ApplyBundleState.APPROVAL_REQUIRED:
        raise ApplyGuardError(
            "apply_bundle_not_approval_required",
            "apply bundle is not awaiting approval",
        )
    if bundle.generated_operation_count == 0 or bundle.delete_count != 0:
        raise ApplyGuardError(
            "apply_approval_count_invalid",
            "apply approval requires nonzero add/update operations and zero delete",
        )
    valid_current_shape = len(current_plan_content_hash) == 64 and all(
        character in "0123456789abcdef" for character in current_plan_content_hash
    )
    if not valid_current_shape or not (
        hmac.compare_digest(bundle.plan_integrity_hash, current_plan_content_hash)
        and hmac.compare_digest(bundle.plan_content_hash, current_plan_content_hash)
    ):
        raise ApplyGuardError(
            "apply_plan_stale_or_mismatched",
            "apply bundle does not match the current verified plan",
        )
    return (
        f"AUTHORIZE TEST APPLY {bundle.target_reference} "
        f"P-{bundle.plan_content_hash[:12]} "
        f"A-{bundle.add_count} U-{bundle.update_count}"
    )


def approve_apply_bundle(
    bundle: ApplyBundle,
    confirmation: str,
    current_plan_content_hash: str,
) -> ApplyBundle:
    """Return a newly hashed test bundle approved only for offline simulation."""

    expected = apply_approval_challenge(bundle, current_plan_content_hash)
    if not hmac.compare_digest(
        confirmation.encode("utf-8", errors="strict"),
        expected.encode("utf-8", errors="strict"),
    ):
        raise ApplyConfirmationError(
            "apply_confirmation_mismatch",
            "test apply confirmation did not exactly match",
        )
    approved = rebuild_apply_bundle_state(
        bundle,
        ApplyBundleState.APPROVED_FOR_SIMULATION,
    )
    verify_apply_bundle_integrity(approved)
    return approved


def mark_apply_simulation_complete(bundle: ApplyBundle) -> ApplyBundle:
    """Record successful offline test simulation without enabling execution."""

    return _simulation_transition(bundle, ApplyBundleState.SIMULATION_COMPLETE)


def mark_apply_simulation_failed(bundle: ApplyBundle) -> ApplyBundle:
    """Record failed offline test simulation without retaining error content."""

    return _simulation_transition(bundle, ApplyBundleState.SIMULATION_FAILED)


def _simulation_transition(
    bundle: ApplyBundle,
    state: ApplyBundleState,
) -> ApplyBundle:
    verify_apply_bundle_integrity(bundle)
    require_test_bundle(bundle)
    if bundle.state is not ApplyBundleState.APPROVED_FOR_SIMULATION:
        raise ApplyGuardError(
            "apply_bundle_not_approved_for_simulation",
            "apply bundle is not approved for simulation",
        )
    transitioned = rebuild_apply_bundle_state(bundle, state)
    verify_apply_bundle_integrity(transitioned)
    return transitioned


__all__ = [
    "apply_approval_challenge",
    "approve_apply_bundle",
    "mark_apply_simulation_complete",
    "mark_apply_simulation_failed",
]
