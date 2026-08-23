"""Build and verify a one-operation private Test Calendar write Run Spec."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections import defaultdict
from collections.abc import Mapping
from typing import cast

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.baseline_engine import (
    calculate_baseline_content_hash,
    verify_baseline_content_hash,
)
from tridentine_calendar_google_sync.baseline_models import BaselineState, TrustedBaseline
from tridentine_calendar_google_sync.google_models import CanonicalGoogleEvent, GoogleSnapshot
from tridentine_calendar_google_sync.google_sanitize import render_sanitized_snapshot
from tridentine_calendar_google_sync.google_snapshot import parse_google_snapshot_bytes
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    CanonicalSourceEvent,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.plan_engine import verify_sync_plan_content_hash
from tridentine_calendar_google_sync.plan_models import (
    ChangedFieldName,
    PlanAction,
    PlanActionKind,
    PlanState,
    SyncPlan,
)
from tridentine_calendar_google_sync.provenance import canonical_content_hash, tool_version
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteManagedState,
    TestWriteOperation,
    TestWriteOperationKind,
    TestWriteRunSpec,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetConfig,
    test_write_target_reference,
    validate_test_write_target_config,
)

_OPERATION_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-write-operation:v1\x00"
_RUN_SPEC_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-write-run-spec:v1\x00"


class TestWriteRunSpecError(ValueError):
    """A content-free Run Spec input, policy, or integrity failure."""

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


def private_managed_state_data(state: TestWriteManagedState) -> dict[str, object]:
    """Return exact private managed fields for integrity and local persistence."""

    return {
        "iCalUID": state.ical_uid,
        "summary": state.summary,
        "description": state.description,
        "start_date": state.start_date.isoformat(),
        "end_date": state.end_date.isoformat(),
        "all_day": state.all_day,
        "event_type": state.event_type,
    }


def private_test_write_operation_data(operation: TestWriteOperation) -> dict[str, object]:
    """Return the complete private operation document, including opaque values."""

    return {
        "operation": operation.operation.value,
        "source_ref": operation.source_ref,
        "google_ref": operation.google_ref,
        "changed_fields": list(operation.changed_fields),
        "current_state": (
            private_managed_state_data(operation.current_state)
            if operation.current_state is not None
            else None
        ),
        "desired_state": private_managed_state_data(operation.desired_state),
        "google_event_id": operation.google_event_id,
        "expected_etag": operation.expected_etag,
        "operation_content_hash": operation.operation_content_hash,
    }


def private_test_write_run_spec_data(run_spec: TestWriteRunSpec) -> dict[str, object]:
    """Return the canonical local-private Run Spec document."""

    return {
        "schema_version": run_spec.schema_version,
        "run_type": run_spec.run_type,
        "test_only": run_spec.test_only,
        "production_locked": run_spec.production_locked,
        "tool_version": run_spec.tool_version,
        "target_fingerprint": run_spec.target_fingerprint,
        "target_safe_ref": run_spec.target_safe_ref,
        "target_environment": run_spec.target_environment,
        "source_profile": run_spec.source_profile,
        "source_sha256": run_spec.source_sha256,
        "source_event_count": run_spec.source_event_count,
        "current_snapshot_hash": run_spec.current_snapshot_hash,
        "plan_hash": run_spec.plan_hash,
        "trusted_baseline_hash": run_spec.trusted_baseline_hash,
        "operation_count": run_spec.operation_count,
        "add_count": run_spec.add_count,
        "update_count": run_spec.update_count,
        "operation": private_test_write_operation_data(run_spec.operation),
        "approval_required": run_spec.approval_required,
        "run_spec_content_hash": run_spec.run_spec_content_hash,
    }


def calculate_test_write_operation_hash(operation: TestWriteOperation) -> str:
    """Calculate the domain-separated hash of one private operation."""

    data = private_test_write_operation_data(operation)
    del data["operation_content_hash"]
    return _hash_mapping(_OPERATION_HASH_DOMAIN, data)


def calculate_test_write_run_spec_hash(run_spec: TestWriteRunSpec) -> str:
    """Calculate the domain-separated hash of a private Run Spec."""

    data = private_test_write_run_spec_data(run_spec)
    del data["run_spec_content_hash"]
    return _hash_mapping(_RUN_SPEC_HASH_DOMAIN, data)


def verify_test_write_run_spec(run_spec: TestWriteRunSpec) -> None:
    """Fail closed on Production identity or operation/Run Spec tampering."""

    if not isinstance(run_spec, TestWriteRunSpec):
        raise TestWriteRunSpecError(
            "invalid_test_write_run_spec",
            "Test write Run Spec is invalid",
        )
    if (
        run_spec.target_environment != "test"
        or run_spec.target_safe_ref == PRODUCTION_TARGET_REFERENCE
        or run_spec.test_only is not True
        or run_spec.production_locked is not True
        or run_spec.operation_count != 1
        or run_spec.add_count + run_spec.update_count != 1
    ):
        raise TestWriteRunSpecError(
            "test_write_run_spec_policy_mismatch",
            "Test write Run Spec policy was not satisfied",
        )
    if not hmac.compare_digest(
        calculate_test_write_operation_hash(run_spec.operation),
        run_spec.operation.operation_content_hash,
    ):
        raise TestWriteRunSpecError(
            "test_write_operation_hash_mismatch",
            "Test write operation integrity verification failed",
        )
    if not hmac.compare_digest(
        calculate_test_write_run_spec_hash(run_spec),
        run_spec.run_spec_content_hash,
    ):
        raise TestWriteRunSpecError(
            "test_write_run_spec_hash_mismatch",
            "Test write Run Spec integrity verification failed",
        )


def _validated_source(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
) -> dict[str, CanonicalSourceEvent]:
    if (
        not source.source_valid
        or source.fatal
        or not source.source_sha_matches
        or source.uid_duplicate_count != 0
        or source.uid_total_count != source.uid_unique_count
        or profile.profile_id != source.profile_id
        or profile.html_sha256 != source.raw_sha256
    ):
        raise TestWriteRunSpecError(
            "invalid_test_write_source",
            "Source cannot produce a Test write Run Spec",
        )
    source_hash = canonical_content_hash(
        vcalendar_count=source.vcalendar_count,
        events=source.events,
    )
    if not hmac.compare_digest(source_hash, source.content_hash):
        raise TestWriteRunSpecError(
            "test_write_source_hash_mismatch",
            "Source integrity verification failed",
        )
    groups: dict[str, list[CanonicalSourceEvent]] = defaultdict(list)
    for event in source.events:
        if event.uid is None or event.safe_uid_reference is None:
            raise TestWriteRunSpecError(
                "test_write_source_uid_missing",
                "Source event identity is missing",
            )
        groups[event.safe_uid_reference].append(event)
    if any(len(events) != 1 for events in groups.values()):
        raise TestWriteRunSpecError(
            "test_write_source_reference_collision",
            "Source safe reference collision detected",
        )
    return {reference: events[0] for reference, events in groups.items()}


def _verify_snapshot(snapshot: GoogleSnapshot) -> None:
    if (
        not snapshot.complete
        or snapshot.event_count != len(snapshot.events)
        or any(
            count != 0
            for count in (
                snapshot.cancelled_event_count,
                snapshot.unknown_event_type_count,
                snapshot.dropped_private_extended_property_count,
                snapshot.dropped_shared_extended_property_count,
                snapshot.forbidden_field_count,
            )
        )
    ):
        raise TestWriteRunSpecError(
            "unsafe_test_write_snapshot",
            "Snapshot cannot produce a Test write Run Spec",
        )
    reparsed = parse_google_snapshot_bytes(render_sanitized_snapshot(snapshot))
    if not hmac.compare_digest(reparsed.content_hash, snapshot.content_hash):
        raise TestWriteRunSpecError(
            "test_write_snapshot_hash_mismatch",
            "Snapshot integrity verification failed",
        )


def _validate_plan(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    plan: SyncPlan,
) -> PlanAction:
    try:
        verify_sync_plan_content_hash(plan)
    except Exception as exc:
        raise TestWriteRunSpecError(
            "test_write_plan_hash_mismatch",
            "Sync Plan integrity verification failed",
        ) from exc
    counts = plan.diff_summary.counts
    forbidden_counts = (
        counts.delete_candidate,
        counts.duplicate_source_uid,
        counts.duplicate_google_icaluid,
        counts.ambiguous,
        counts.unmanaged_google_event,
        counts.invalid_source,
        counts.fatal_guard,
    )
    if (
        plan.executable
        or plan.state is not PlanState.REVIEW_REQUIRED
        or len(plan.proposed_actions) != 1
        or counts.add + counts.update != 1
        or any(forbidden_counts)
        or plan.diff_summary.fatal
        or plan.diff_summary.has_ambiguous
        or plan.diff_summary.warning_count != 0
        or any(guard.severity == "fatal" for guard in plan.safety_guards)
        or plan.target_fingerprint != snapshot.target_fingerprint
        or plan.snapshot_content_hash != snapshot.content_hash
        or plan.current_source.profile_id != profile.profile_id
        or plan.current_source.accepted_tag != profile.accepted_tag
        or plan.current_source.accepted_commit != profile.accepted_commit
        or plan.current_source.source_sha256 != source.raw_sha256
        or plan.current_source.source_content_hash != source.content_hash
        or plan.current_source.event_count != source.vevent_count
    ):
        raise TestWriteRunSpecError(
            "unsafe_test_write_plan",
            "Sync Plan cannot authorize a Test write Run Spec",
        )
    action = plan.proposed_actions[0]
    if action.action is PlanActionKind.ADD:
        if counts.add != 1 or counts.update != 0 or plan.thresholds.max_add < 1:
            raise TestWriteRunSpecError(
                "test_write_add_plan_invalid",
                "Sync Plan does not contain exactly one allowed add",
            )
    elif action.action is PlanActionKind.UPDATE:
        if counts.add != 0 or counts.update != 1 or plan.thresholds.max_update < 1:
            raise TestWriteRunSpecError(
                "test_write_update_plan_invalid",
                "Sync Plan does not contain exactly one allowed update",
            )
    else:
        raise TestWriteRunSpecError(
            "test_write_delete_forbidden",
            "Delete operations are not supported",
        )
    return action


def _desired_state(event: CanonicalSourceEvent) -> TestWriteManagedState:
    if (
        event.uid is None
        or event.summary is None
        or event.description is None
        or event.start_date is None
        or event.effective_end_date is None
        or not event.all_day
        or event.rrule_present
        or event.recurrence_id_present
    ):
        raise TestWriteRunSpecError(
            "unsupported_test_write_source_event",
            "Test writes require an ordinary non-recurring all-day Source event",
        )
    return TestWriteManagedState(
        ical_uid=event.uid,
        summary=event.summary,
        description=event.description,
        start_date=event.start_date,
        end_date=event.effective_end_date,
        all_day=True,
        event_type="default",
    )


def _current_state(event: CanonicalGoogleEvent) -> TestWriteManagedState:
    if (
        event.ical_uid is None
        or event.start is None
        or event.end is None
        or event.start.date is None
        or event.end.date is None
        or event.all_day is not True
        or event.status == "cancelled"
        or event.event_type != "default"
        or event.recurrence
        or event.recurring_event_id is not None
        or event.original_start_time is not None
        or event.locked
        or event.private_copy
    ):
        raise TestWriteRunSpecError(
            "unsupported_test_write_google_event",
            "Test updates require an ordinary non-recurring all-day Google event",
        )
    return TestWriteManagedState(
        ical_uid=event.ical_uid,
        summary=event.summary,
        description=event.description,
        start_date=event.start.date,
        end_date=event.end.date,
        all_day=True,
        event_type="default",
    )


def _finalize_operation(provisional: TestWriteOperation) -> TestWriteOperation:
    return provisional.model_copy(
        update={"operation_content_hash": calculate_test_write_operation_hash(provisional)}
    )


def _add_operation(
    action: PlanAction,
    source_event: CanonicalSourceEvent,
    snapshot: GoogleSnapshot,
) -> TestWriteOperation:
    desired = _desired_state(source_event)
    matches = [event for event in snapshot.events if event.ical_uid == desired.ical_uid]
    if matches:
        raise TestWriteRunSpecError(
            "test_write_add_identity_exists",
            "Add identity already exists in the current snapshot",
        )
    provisional = TestWriteOperation(
        operation=TestWriteOperationKind.ADD,
        source_ref=action.source_ref or "",
        google_ref=None,
        changed_fields=("summary", "description", "start_date", "end_date"),
        current_state=None,
        desired_state=desired,
        google_event_id=None,
        expected_etag=None,
        operation_content_hash="0" * 64,
    )
    return _finalize_operation(provisional)


def _update_operation(
    action: PlanAction,
    source_event: CanonicalSourceEvent,
    snapshot: GoogleSnapshot,
    baseline: TrustedBaseline | None,
) -> tuple[TestWriteOperation, str]:
    if baseline is None or baseline.state is not BaselineState.TRUSTED:
        raise TestWriteRunSpecError(
            "trusted_test_baseline_required",
            "A trusted Test baseline is required for update",
        )
    try:
        verify_baseline_content_hash(baseline)
    except Exception as exc:
        raise TestWriteRunSpecError(
            "trusted_test_baseline_invalid",
            "Trusted Test baseline integrity verification failed",
        ) from exc
    if (
        baseline.target_fingerprint != snapshot.target_fingerprint
        or baseline.baseline_content_hash != calculate_baseline_content_hash(baseline)
    ):
        raise TestWriteRunSpecError(
            "trusted_test_baseline_target_mismatch",
            "Trusted Test baseline does not match the target",
        )
    desired = _desired_state(source_event)
    if desired.ical_uid not in baseline.managed_uids:
        raise TestWriteRunSpecError(
            "test_write_update_not_owned",
            "Update identity is not owned by the trusted Test baseline",
        )
    if len(action.google_refs) != 1:
        raise TestWriteRunSpecError(
            "test_write_update_identity_ambiguous",
            "Update Google identity is ambiguous",
        )
    matches = [
        event for event in snapshot.events if event.safe_event_reference == action.google_refs[0]
    ]
    if len(matches) != 1:
        raise TestWriteRunSpecError(
            "test_write_update_identity_unresolved",
            "Update Google identity could not be resolved exactly once",
        )
    google_event = matches[0]
    current = _current_state(google_event)
    if current.ical_uid != desired.ical_uid:
        raise TestWriteRunSpecError(
            "test_write_update_uid_mismatch",
            "Update UID identity did not match",
        )
    if not google_event.event_id or not google_event.etag:
        raise TestWriteRunSpecError(
            "test_write_update_concurrency_identity_missing",
            "Update requires an exact Google event ID and ETag",
        )
    changed_fields = cast(tuple[ChangedFieldName, ...], tuple(action.changed_fields))
    provisional = TestWriteOperation(
        operation=TestWriteOperationKind.UPDATE,
        source_ref=action.source_ref or "",
        google_ref=action.google_refs[0],
        changed_fields=changed_fields,
        current_state=current,
        desired_state=desired,
        google_event_id=google_event.event_id,
        expected_etag=google_event.etag,
        operation_content_hash="0" * 64,
    )
    return _finalize_operation(provisional), baseline.baseline_content_hash


def build_test_write_run_spec(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    plan: SyncPlan,
    target: TestWriteTargetConfig,
    *,
    trusted_baseline: TrustedBaseline | None = None,
) -> TestWriteRunSpec:
    """Build one integrity-pinned Test-only Run Spec without any API access."""

    target_fingerprint = validate_test_write_target_config(target)
    target_ref = test_write_target_reference(target)
    if target_ref == PRODUCTION_TARGET_REFERENCE:
        raise TestWriteRunSpecError(
            "production_test_write_run_spec_forbidden",
            "Production Calendar write access is forbidden",
        )
    if snapshot.target_fingerprint != target_fingerprint:
        raise TestWriteRunSpecError(
            "test_write_snapshot_target_mismatch",
            "Snapshot does not match the configured Test target",
        )
    source_by_ref = _validated_source(profile, source)
    _verify_snapshot(snapshot)
    action = _validate_plan(profile, source, snapshot, plan)
    if action.source_ref is None or action.source_ref not in source_by_ref:
        raise TestWriteRunSpecError(
            "test_write_source_reference_unresolved",
            "Run Spec Source identity could not be resolved",
        )
    if action.action is PlanActionKind.ADD:
        operation = _add_operation(action, source_by_ref[action.source_ref], snapshot)
        baseline_hash = None
        add_count, update_count = 1, 0
    else:
        operation, baseline_hash = _update_operation(
            action,
            source_by_ref[action.source_ref],
            snapshot,
            trusted_baseline,
        )
        if (
            trusted_baseline is None
            or plan.baseline.baseline_content_hash != trusted_baseline.baseline_content_hash
            or plan.baseline.target_fingerprint != trusted_baseline.target_fingerprint
            or plan.baseline.managed_uid_count != trusted_baseline.managed_uid_count
        ):
            raise TestWriteRunSpecError(
                "test_write_plan_baseline_mismatch",
                "Sync Plan does not match the trusted Test baseline",
            )
        add_count, update_count = 0, 1
    provisional = TestWriteRunSpec(
        tool_version=tool_version(),
        target_fingerprint=target_fingerprint,
        target_safe_ref=target_ref,
        source_profile=profile.profile_id,
        source_sha256=source.raw_sha256,
        source_event_count=source.vevent_count,
        current_snapshot_hash=snapshot.content_hash,
        plan_hash=plan.plan_content_hash,
        trusted_baseline_hash=baseline_hash,
        add_count=add_count,
        update_count=update_count,
        operation=operation,
        run_spec_content_hash="0" * 64,
    )
    run_spec = provisional.model_copy(
        update={"run_spec_content_hash": calculate_test_write_run_spec_hash(provisional)}
    )
    verify_test_write_run_spec(run_spec)
    return run_spec


__all__ = [
    "TestWriteRunSpecError",
    "build_test_write_run_spec",
    "calculate_test_write_operation_hash",
    "calculate_test_write_run_spec_hash",
    "private_managed_state_data",
    "private_test_write_operation_data",
    "private_test_write_run_spec_data",
    "verify_test_write_run_spec",
]
