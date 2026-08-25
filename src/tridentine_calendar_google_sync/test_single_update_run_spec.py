"""Construction and integrity for one Test-only Single Update Run Spec."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.baseline_engine import verify_baseline_content_hash
from tridentine_calendar_google_sync.baseline_models import BaselineState, TrustedBaseline
from tridentine_calendar_google_sync.google_models import CanonicalGoogleEvent
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    CanonicalSourceEvent,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.provenance import tool_version
from tridentine_calendar_google_sync.test_calendar_prewrite import (
    verify_test_calendar_prewrite_snapshot,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_models import (
    TestCalendarPrewriteSnapshot,
)
from tridentine_calendar_google_sync.test_single_update_plan import (
    build_test_single_update_plan,
    verify_test_single_update_plan,
)
from tridentine_calendar_google_sync.test_single_update_plan_models import (
    SINGLE_UPDATE_CHANGED_FIELDS,
    TestSingleUpdatePlan,
)
from tridentine_calendar_google_sync.test_single_update_run_spec_models import (
    TestSingleUpdateOperation,
    TestSingleUpdateRunSpec,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteManagedState,
    TestWriteOperationKind,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetConfig,
    test_write_target_reference,
    validate_test_write_target_config,
)

_OPERATION_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-single-update-operation:v1\x00"
_RUN_SPEC_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-single-update-run-spec:v1\x00"


class TestSingleUpdateRunSpecError(ValueError):
    """A content-free Single Update Run Spec policy or integrity failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _hash_mapping(domain: bytes, value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def _managed_state_data(state: TestWriteManagedState) -> dict[str, object]:
    return {
        "iCalUID": state.ical_uid,
        "summary": state.summary,
        "description": state.description,
        "start_date": state.start_date.isoformat(),
        "end_date": state.end_date.isoformat(),
        "all_day": state.all_day,
        "event_type": state.event_type,
    }


def private_test_single_update_operation_data(
    operation: TestSingleUpdateOperation,
) -> dict[str, object]:
    """Return the complete private operation document for hashing and I/O."""

    return {
        "operation": operation.operation.value,
        "source_ref": operation.source_ref,
        "google_ref": operation.google_ref,
        "changed_fields": list(operation.changed_fields),
        "current_state": _managed_state_data(operation.current_state),
        "desired_state": _managed_state_data(operation.desired_state),
        "google_event_id": operation.google_event_id,
        "expected_etag": operation.expected_etag,
        "operation_content_hash": operation.operation_content_hash,
    }


def private_test_single_update_run_spec_data(
    run_spec: TestSingleUpdateRunSpec,
) -> dict[str, object]:
    """Return the canonical local-private Single Update Run Spec document."""

    return {
        "schema_version": run_spec.schema_version,
        "run_type": run_spec.run_type,
        "planning_mode": run_spec.planning_mode,
        "single_update": run_spec.single_update,
        "test_only": run_spec.test_only,
        "production_locked": run_spec.production_locked,
        "tool_version": run_spec.tool_version,
        "target_fingerprint": run_spec.target_fingerprint,
        "target_safe_ref": run_spec.target_safe_ref,
        "target_environment": run_spec.target_environment,
        "baseline_state": run_spec.baseline_state,
        "trusted_baseline_hash": run_spec.trusted_baseline_hash,
        "baseline_snapshot_hash": run_spec.baseline_snapshot_hash,
        "source_profile": run_spec.source_profile,
        "source_sha256": run_spec.source_sha256,
        "source_event_count": run_spec.source_event_count,
        "current_snapshot_hash": run_spec.current_snapshot_hash,
        "single_update_plan_hash": run_spec.single_update_plan_hash,
        "operation_count": run_spec.operation_count,
        "add_count": run_spec.add_count,
        "update_count": run_spec.update_count,
        "delete_count": run_spec.delete_count,
        "changed_fields": list(run_spec.changed_fields),
        "operation": private_test_single_update_operation_data(run_spec.operation),
        "approval_required": run_spec.approval_required,
        "run_spec_content_hash": run_spec.run_spec_content_hash,
    }


def calculate_test_single_update_operation_hash(
    operation: TestSingleUpdateOperation,
) -> str:
    """Calculate the dedicated operation hash."""

    data = private_test_single_update_operation_data(operation)
    del data["operation_content_hash"]
    return _hash_mapping(_OPERATION_HASH_DOMAIN, data)


def calculate_test_single_update_run_spec_hash(
    run_spec: TestSingleUpdateRunSpec,
) -> str:
    """Calculate the dedicated Run Spec hash."""

    data = private_test_single_update_run_spec_data(run_spec)
    del data["run_spec_content_hash"]
    return _hash_mapping(_RUN_SPEC_HASH_DOMAIN, data)


def _exact_state_pair(
    source_event: CanonicalSourceEvent,
    google_event: CanonicalGoogleEvent,
) -> tuple[TestWriteManagedState, TestWriteManagedState]:
    if (
        source_event.uid is None
        or source_event.summary is None
        or source_event.description is None
        or source_event.start_date is None
        or source_event.effective_end_date is None
        or source_event.all_day is not True
        or source_event.rrule_present
        or source_event.recurrence_id_present
        or google_event.ical_uid != source_event.uid
        or google_event.summary is None
        or google_event.description is None
        or google_event.start is None
        or google_event.end is None
        or google_event.start.date is None
        or google_event.end.date is None
        or google_event.all_day is not True
        or google_event.end_time_unspecified
        or google_event.status == "cancelled"
        or google_event.event_type != "default"
        or google_event.recurrence
        or google_event.recurring_event_id is not None
        or google_event.original_start_time is not None
        or google_event.locked
        or google_event.private_copy
        or google_event.color_id is not None
        or google_event.event_label_id is not None
        or google_event.summary != source_event.summary
        or google_event.description == source_event.description
        or google_event.start.date != source_event.start_date
        or google_event.end.date != source_event.effective_end_date
    ):
        raise TestSingleUpdateRunSpecError(
            "test_single_update_event_shape_mismatch",
            "Single Update event state is incompatible",
        )
    return (
        TestWriteManagedState(
            ical_uid=google_event.ical_uid,
            summary=google_event.summary,
            description=google_event.description,
            start_date=google_event.start.date,
            end_date=google_event.end.date,
        ),
        TestWriteManagedState(
            ical_uid=source_event.uid,
            summary=source_event.summary,
            description=source_event.description,
            start_date=source_event.start_date,
            end_date=source_event.effective_end_date,
        ),
    )


def verify_test_single_update_run_spec(run_spec: TestSingleUpdateRunSpec) -> None:
    """Independently reject fixed-policy or integrity tampering."""

    if not isinstance(run_spec, TestSingleUpdateRunSpec):
        raise TestSingleUpdateRunSpecError(
            "invalid_test_single_update_run_spec",
            "Test Single Update Run Spec is invalid",
        )
    operation = run_spec.operation
    hashes = (
        run_spec.target_fingerprint,
        run_spec.trusted_baseline_hash,
        run_spec.baseline_snapshot_hash,
        run_spec.source_sha256,
        run_spec.current_snapshot_hash,
        run_spec.single_update_plan_hash,
        run_spec.run_spec_content_hash,
        operation.operation_content_hash,
    )
    if (
        run_spec.schema_version != "1.0"
        or run_spec.run_type != "test-single-update-run-spec-v1"
        or run_spec.planning_mode != "test_single_update"
        or run_spec.single_update is not True
        or run_spec.test_only is not True
        or run_spec.production_locked is not True
        or run_spec.target_environment != "test"
        or run_spec.target_safe_ref == PRODUCTION_TARGET_REFERENCE
        or run_spec.target_safe_ref != f"T-{run_spec.target_fingerprint[:12]}"
        or run_spec.baseline_state != "trusted"
        or not run_spec.tool_version
        or any(re.fullmatch(r"[0-9a-f]{64}", value) is None for value in hashes)
        or re.fullmatch(r"T-[0-9a-f]{12}", run_spec.target_safe_ref) is None
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", run_spec.source_profile) is None
        or run_spec.source_event_count != 1
        or run_spec.operation_count != 1
        or run_spec.add_count != 0
        or run_spec.update_count != 1
        or run_spec.delete_count != 0
        or run_spec.changed_fields != SINGLE_UPDATE_CHANGED_FIELDS
        or run_spec.approval_required is not True
        or operation.operation is not TestWriteOperationKind.UPDATE
        or re.fullmatch(r"U-[0-9a-f]{12}", operation.source_ref) is None
        or re.fullmatch(r"G-[0-9a-f]{12}", operation.google_ref) is None
        or operation.changed_fields != SINGLE_UPDATE_CHANGED_FIELDS
        or operation.current_state.ical_uid != operation.desired_state.ical_uid
        or not operation.current_state.ical_uid
        or operation.current_state.summary is None
        or operation.desired_state.summary is None
        or operation.current_state.summary != operation.desired_state.summary
        or operation.current_state.description == operation.desired_state.description
        or operation.current_state.description is None
        or operation.desired_state.description is None
        or operation.current_state.start_date != operation.desired_state.start_date
        or operation.current_state.end_date != operation.desired_state.end_date
        or operation.current_state.end_date <= operation.current_state.start_date
        or operation.desired_state.end_date <= operation.desired_state.start_date
        or operation.current_state.all_day is not True
        or operation.desired_state.all_day is not True
        or operation.current_state.event_type != "default"
        or operation.desired_state.event_type != "default"
        or operation.google_event_id == ""
        or len(operation.google_event_id) > 1024
        or operation.expected_etag == ""
        or len(operation.expected_etag) > 4096
        or operation.expected_etag == "*"
        or "\r" in operation.expected_etag
        or "\n" in operation.expected_etag
    ):
        raise TestSingleUpdateRunSpecError(
            "test_single_update_run_spec_policy_mismatch",
            "Test Single Update Run Spec policy verification failed",
        )
    if not hmac.compare_digest(
        run_spec.baseline_snapshot_hash,
        run_spec.current_snapshot_hash,
    ):
        raise TestSingleUpdateRunSpecError(
            "trusted_baseline_snapshot_mismatch",
            "Trusted Test baseline snapshot does not match the current snapshot",
        )
    if not hmac.compare_digest(
        calculate_test_single_update_operation_hash(operation),
        operation.operation_content_hash,
    ):
        raise TestSingleUpdateRunSpecError(
            "test_single_update_operation_hash_mismatch",
            "Test Single Update operation integrity verification failed",
        )
    if not hmac.compare_digest(
        calculate_test_single_update_run_spec_hash(run_spec),
        run_spec.run_spec_content_hash,
    ):
        raise TestSingleUpdateRunSpecError(
            "test_single_update_run_spec_hash_mismatch",
            "Test Single Update Run Spec integrity verification failed",
        )


def verify_test_single_update_run_spec_bindings(
    run_spec: TestSingleUpdateRunSpec,
    plan: TestSingleUpdatePlan,
    baseline: TrustedBaseline,
) -> None:
    """Bind one intact Run Spec to its exact Plan and trusted baseline."""

    verify_test_single_update_run_spec(run_spec)
    verify_test_single_update_plan(plan)
    try:
        verify_baseline_content_hash(baseline)
    except Exception as exc:
        raise TestSingleUpdateRunSpecError(
            "test_single_update_baseline_invalid",
            "Trusted Test baseline integrity verification failed",
        ) from exc
    snapshot_hashes = (
        baseline.snapshot_content_hash,
        plan.baseline_snapshot_hash,
        plan.snapshot_hash,
        run_spec.baseline_snapshot_hash,
        run_spec.current_snapshot_hash,
    )
    if any(not hmac.compare_digest(snapshot_hashes[0], value) for value in snapshot_hashes[1:]):
        raise TestSingleUpdateRunSpecError(
            "trusted_baseline_snapshot_mismatch",
            "Trusted Test baseline snapshot does not match the current snapshot",
        )
    if (
        baseline.state is not BaselineState.TRUSTED
        or run_spec.trusted_baseline_hash != baseline.baseline_content_hash
        or plan.baseline_hash != baseline.baseline_content_hash
        or baseline.target_fingerprint != plan.target_fingerprint
        or baseline.source_profile != plan.source_profile
        or baseline.source_event_count != 1
        or baseline.snapshot_event_count != 1
        or baseline.managed_uid_count != 1
        or len(baseline.managed_uids) != 1
        or run_spec.operation.desired_state.ical_uid not in baseline.managed_uids
        or run_spec.single_update_plan_hash != plan.plan_content_hash
        or run_spec.target_fingerprint != plan.target_fingerprint
        or run_spec.target_safe_ref != plan.target_safe_ref
        or run_spec.source_profile != plan.source_profile
        or run_spec.source_sha256 != plan.source_sha256
        or run_spec.current_snapshot_hash != plan.snapshot_hash
        or run_spec.operation.source_ref != plan.safe_uid_ref
        or run_spec.changed_fields != plan.changed_fields
        or plan.baseline_state != "trusted"
        or plan.operation_count != 1
        or plan.add_count != 0
        or plan.update_count != 1
        or plan.delete_count != 0
    ):
        raise TestSingleUpdateRunSpecError(
            "test_single_update_run_spec_binding_mismatch",
            "Single Update Plan, baseline, and Run Spec do not match",
        )


def build_test_single_update_run_spec(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    prewrite_snapshot: TestCalendarPrewriteSnapshot,
    plan: TestSingleUpdatePlan,
    baseline: TrustedBaseline,
    target: TestWriteTargetConfig,
) -> TestSingleUpdateRunSpec:
    """Build one dedicated Run Spec without API access."""

    target_fingerprint = validate_test_write_target_config(target)
    target_ref = test_write_target_reference(target)
    verify_test_calendar_prewrite_snapshot(prewrite_snapshot)
    try:
        verify_baseline_content_hash(baseline)
    except Exception as exc:
        raise TestSingleUpdateRunSpecError(
            "test_single_update_baseline_invalid",
            "Trusted Test baseline integrity verification failed",
        ) from exc
    if not hmac.compare_digest(
        baseline.snapshot_content_hash,
        prewrite_snapshot.snapshot_content_hash,
    ):
        raise TestSingleUpdateRunSpecError(
            "trusted_baseline_snapshot_mismatch",
            "Trusted Test baseline snapshot does not match the current snapshot",
        )
    expected_plan = build_test_single_update_plan(
        profile,
        source,
        prewrite_snapshot,
        baseline,
        target,
    )
    if not hmac.compare_digest(plan.plan_content_hash, expected_plan.plan_content_hash):
        raise TestSingleUpdateRunSpecError(
            "test_single_update_plan_recomputation_mismatch",
            "Single Update Plan does not match canonical inputs",
        )
    verify_test_single_update_plan(plan)
    try:
        verify_baseline_content_hash(baseline)
    except Exception as exc:
        raise TestSingleUpdateRunSpecError(
            "test_single_update_baseline_invalid",
            "Trusted Test baseline integrity verification failed",
        ) from exc
    if (
        target_ref == PRODUCTION_TARGET_REFERENCE
        or plan.target_fingerprint != target_fingerprint
        or plan.target_safe_ref != target_ref
        or plan.snapshot_hash != prewrite_snapshot.snapshot_content_hash
        or baseline.snapshot_content_hash != prewrite_snapshot.snapshot_content_hash
        or plan.baseline_snapshot_hash != baseline.snapshot_content_hash
        or baseline.state is not BaselineState.TRUSTED
        or baseline.target_fingerprint != target_fingerprint
        or plan.baseline_hash != baseline.baseline_content_hash
    ):
        raise TestSingleUpdateRunSpecError(
            "test_single_update_run_spec_input_mismatch",
            "Single Update Run Spec inputs do not match",
        )
    source_matches = [
        event for event in source.events if event.safe_uid_reference == plan.safe_uid_ref
    ]
    if len(source_matches) != 1 or source_matches[0].uid is None:
        raise TestSingleUpdateRunSpecError(
            "test_single_update_source_identity_unresolved",
            "Single Update Source identity could not be resolved",
        )
    google_matches = [
        event
        for event in prewrite_snapshot.snapshot.events
        if event.ical_uid == source_matches[0].uid
    ]
    if len(google_matches) != 1:
        raise TestSingleUpdateRunSpecError(
            "test_single_update_google_identity_unresolved",
            "Single Update Google identity could not be resolved exactly once",
        )
    google_event = google_matches[0]
    if (
        google_event.safe_event_reference is None
        or not google_event.event_id
        or not google_event.etag
    ):
        raise TestSingleUpdateRunSpecError(
            "test_single_update_concurrency_identity_missing",
            "Single Update requires an exact Google event identity and ETag",
        )
    current_state, desired_state = _exact_state_pair(source_matches[0], google_event)
    operation_provisional = TestSingleUpdateOperation(
        source_ref=plan.safe_uid_ref,
        google_ref=google_event.safe_event_reference,
        current_state=current_state,
        desired_state=desired_state,
        google_event_id=google_event.event_id,
        expected_etag=google_event.etag,
        operation_content_hash="0" * 64,
    )
    operation = operation_provisional.model_copy(
        update={
            "operation_content_hash": calculate_test_single_update_operation_hash(
                operation_provisional
            )
        }
    )
    provisional = TestSingleUpdateRunSpec(
        tool_version=tool_version(),
        target_fingerprint=target_fingerprint,
        target_safe_ref=target_ref,
        trusted_baseline_hash=baseline.baseline_content_hash,
        baseline_snapshot_hash=baseline.snapshot_content_hash,
        source_profile=profile.profile_id,
        source_sha256=source.raw_sha256,
        current_snapshot_hash=prewrite_snapshot.snapshot_content_hash,
        single_update_plan_hash=plan.plan_content_hash,
        operation=operation,
        run_spec_content_hash="0" * 64,
    )
    run_spec = provisional.model_copy(
        update={"run_spec_content_hash": calculate_test_single_update_run_spec_hash(provisional)}
    )
    verify_test_single_update_run_spec_bindings(run_spec, plan, baseline)
    return run_spec


__all__ = [
    "TestSingleUpdateRunSpecError",
    "build_test_single_update_run_spec",
    "calculate_test_single_update_operation_hash",
    "calculate_test_single_update_run_spec_hash",
    "private_test_single_update_operation_data",
    "private_test_single_update_run_spec_data",
    "verify_test_single_update_run_spec",
    "verify_test_single_update_run_spec_bindings",
]
