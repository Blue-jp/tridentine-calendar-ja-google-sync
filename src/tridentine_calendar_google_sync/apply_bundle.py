"""Deterministic offline construction and integrity verification of apply bundles."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections import defaultdict
from collections.abc import Mapping
from datetime import date
from typing import cast

from tridentine_calendar_google_sync.apply_models import (
    ApplyAddPayload,
    ApplyBundle,
    ApplyBundleState,
    ApplyEnvironment,
    ApplyOperation,
    ApplyOperationKind,
    ApplyPayload,
    ApplyTimeBoundary,
    ApplyUpdatePayload,
)
from tridentine_calendar_google_sync.apply_policy import (
    ApplyGuardError,
    ApplyInputError,
    ApplyValidationError,
    validate_bundle_environment_policy,
    validate_environment_target,
)
from tridentine_calendar_google_sync.baseline_engine import (
    BaselineError,
    calculate_baseline_content_hash,
    verify_baseline_content_hash,
)
from tridentine_calendar_google_sync.baseline_models import BaselineState, TrustedBaseline
from tridentine_calendar_google_sync.google_models import (
    CanonicalGoogleEvent,
    GoogleSnapshot,
)
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    CanonicalSourceEvent,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.plan_engine import (
    PlanError,
    build_sync_plan,
    calculate_sync_plan_content_hash,
    verify_sync_plan_content_hash,
)
from tridentine_calendar_google_sync.plan_models import (
    ChangedFieldName,
    PlanAction,
    PlanActionKind,
    PlanState,
    SyncPlan,
)
from tridentine_calendar_google_sync.provenance import (
    canonical_content_hash,
    tool_version,
)

_SOURCE_EVENT_HASH_DOMAIN = b"tridentine-calendar-google-sync:apply-source-event:v1\x00"
_BEFORE_HASH_DOMAIN = b"tridentine-calendar-google-sync:apply-before:v1\x00"
_AFTER_HASH_DOMAIN = b"tridentine-calendar-google-sync:apply-after:v1\x00"
_PAYLOAD_HASH_DOMAIN = b"tridentine-calendar-google-sync:apply-payload:v1\x00"
_OPERATION_HASH_DOMAIN = b"tridentine-calendar-google-sync:apply-operation:v1\x00"
_BUNDLE_HASH_DOMAIN = b"tridentine-calendar-google-sync:apply-bundle:v1\x00"


def _hash_mapping(domain: bytes, value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def _time_data(value: ApplyTimeBoundary) -> dict[str, str | None]:
    return {
        "date": value.date.isoformat() if value.date is not None else None,
        "dateTime": value.date_time.isoformat() if value.date_time is not None else None,
    }


def _payload_data(payload: ApplyPayload) -> dict[str, object]:
    if isinstance(payload, ApplyAddPayload):
        return {
            "payload_type": "add",
            "uid": payload.uid,
            "summary": payload.summary,
            "description": payload.description,
            "start": _time_data(payload.start),
            "effective_end": _time_data(payload.effective_end),
            "all_day": payload.all_day,
            "event_type": payload.event_type,
        }
    data: dict[str, object] = {
        "payload_type": "update",
        "event_id": payload.event_id,
        "etag": payload.etag,
        "changed_fields": list(payload.changed_fields),
    }
    if payload.summary is not None:
        data["summary"] = payload.summary
    if payload.description is not None:
        data["description"] = payload.description
    if payload.start is not None:
        data["start"] = _time_data(payload.start)
    if payload.effective_end is not None:
        data["effective_end"] = _time_data(payload.effective_end)
    return data


def private_operation_data(operation: ApplyOperation) -> dict[str, object]:
    """Return the exact private operation document, including opaque identifiers."""

    return {
        "operation": operation.operation.value,
        "operation_sequence": operation.operation_sequence,
        "source_ref": operation.source_ref,
        "google_ref": operation.google_ref,
        "start_date": operation.start_date.isoformat(),
        "changed_fields": list(operation.changed_fields),
        "source_event_hash": operation.source_event_hash,
        "before_hash": operation.before_hash,
        "after_hash": operation.after_hash,
        "payload_hash": operation.payload_hash,
        "source_uid": operation.source_uid,
        "payload": _payload_data(operation.payload),
        "destructive": operation.destructive,
        "approval_required": operation.approval_required,
        "operation_integrity_hash": operation.operation_integrity_hash,
    }


def private_bundle_data(bundle: ApplyBundle) -> dict[str, object]:
    """Return the exact private bundle document; public reports must not call this."""

    return {
        "schema_version": bundle.schema_version,
        "bundle_type": bundle.bundle_type,
        "tool_version": bundle.tool_version,
        "state": bundle.state.value,
        "environment": bundle.environment.value,
        "target_fingerprint": bundle.target_fingerprint,
        "target_reference": bundle.target_reference,
        "source_profile": bundle.source_profile,
        "accepted_tag": bundle.accepted_tag,
        "accepted_commit": bundle.accepted_commit,
        "source_sha256": bundle.source_sha256,
        "source_canonical_hash": bundle.source_canonical_hash,
        "source_event_count": bundle.source_event_count,
        "snapshot_integrity_hash": bundle.snapshot_integrity_hash,
        "snapshot_event_count": bundle.snapshot_event_count,
        "baseline_integrity_hash": bundle.baseline_integrity_hash,
        "baseline_managed_uid_count": bundle.baseline_managed_uid_count,
        "plan_integrity_hash": bundle.plan_integrity_hash,
        "plan_content_hash": bundle.plan_content_hash,
        "plan_state": bundle.plan_state.value,
        "generated_operation_count": bundle.generated_operation_count,
        "add_count": bundle.add_count,
        "update_count": bundle.update_count,
        "delete_count": bundle.delete_count,
        "operations": [private_operation_data(operation) for operation in bundle.operations],
        "production_locked": bundle.production_locked,
        "execution_enabled": bundle.execution_enabled,
        "bundle_integrity_hash": bundle.bundle_integrity_hash,
    }


def _bundle_hash_data(bundle: ApplyBundle) -> dict[str, object]:
    data = private_bundle_data(bundle)
    del data["bundle_integrity_hash"]
    return data


def calculate_apply_operation_integrity(operation: ApplyOperation) -> str:
    """Recalculate one operation hash without trusting its stored digest."""

    data = private_operation_data(operation)
    del data["operation_integrity_hash"]
    return _hash_mapping(_OPERATION_HASH_DOMAIN, data)


def calculate_apply_bundle_integrity(bundle: ApplyBundle) -> str:
    """Recalculate the bundle integrity hash, including every private operation."""

    return _hash_mapping(_BUNDLE_HASH_DOMAIN, _bundle_hash_data(bundle))


def verify_apply_bundle_integrity(bundle: ApplyBundle) -> None:
    """Reject stale, tampered, or policy-invalid apply bundle objects."""

    for operation in bundle.operations:
        payload_hash = _hash_mapping(_PAYLOAD_HASH_DOMAIN, _payload_data(operation.payload))
        if not hmac.compare_digest(payload_hash, operation.payload_hash):
            raise ApplyValidationError(
                "apply_payload_hash_mismatch",
                "apply payload integrity verification failed",
            )
        operation_hash = calculate_apply_operation_integrity(operation)
        if not hmac.compare_digest(operation_hash, operation.operation_integrity_hash):
            raise ApplyValidationError(
                "apply_operation_hash_mismatch",
                "apply operation integrity verification failed",
            )
    bundle_hash = calculate_apply_bundle_integrity(bundle)
    if not hmac.compare_digest(bundle_hash, bundle.bundle_integrity_hash):
        raise ApplyValidationError(
            "apply_bundle_hash_mismatch",
            "apply bundle integrity verification failed",
        )
    validate_bundle_environment_policy(bundle)


def _source_managed_data(event: CanonicalSourceEvent) -> dict[str, object]:
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
        raise ApplyGuardError(
            "unsupported_source_event_shape",
            "apply bundle supports only non-recurring all-day Source events",
        )
    return {
        "uid": event.uid,
        "summary": event.summary,
        "description": event.description,
        "start": event.start_date.isoformat(),
        "effective_end": event.effective_end_date.isoformat(),
        "all_day": True,
        "event_type": "default",
    }


def _google_managed_data(event: CanonicalGoogleEvent) -> dict[str, object]:
    if (
        event.ical_uid is None
        or event.summary is None
        or event.description is None
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
        raise ApplyGuardError(
            "unsupported_google_event_shape",
            "update supports only ordinary non-recurring all-day Google events",
        )
    return {
        "uid": event.ical_uid,
        "summary": event.summary,
        "description": event.description,
        "start": event.start.date.isoformat(),
        "effective_end": event.end.date.isoformat(),
        "all_day": True,
        "event_type": "default",
    }


def _source_maps(
    source: SourceCalendarInspection,
) -> tuple[dict[str, CanonicalSourceEvent], dict[str, CanonicalSourceEvent]]:
    by_ref_groups: dict[str, list[CanonicalSourceEvent]] = defaultdict(list)
    by_uid: dict[str, CanonicalSourceEvent] = {}
    for event in source.events:
        if event.uid is None or event.safe_uid_reference is None:
            raise ApplyGuardError("source_uid_missing", "Source event identity is missing")
        by_ref_groups[event.safe_uid_reference].append(event)
        if event.uid in by_uid:
            raise ApplyGuardError("source_uid_duplicate", "Source UID is duplicated")
        by_uid[event.uid] = event
    if any(len(group) != 1 for group in by_ref_groups.values()):
        raise ApplyGuardError(
            "source_safe_reference_collision",
            "Source safe reference collision detected",
        )
    return ({reference: group[0] for reference, group in by_ref_groups.items()}, by_uid)


def _google_map(snapshot: GoogleSnapshot) -> dict[str, CanonicalGoogleEvent]:
    groups: dict[str, list[CanonicalGoogleEvent]] = defaultdict(list)
    for event in snapshot.events:
        groups[event.safe_event_reference].append(event)
    if any(len(group) != 1 for group in groups.values()):
        raise ApplyGuardError(
            "google_safe_reference_collision",
            "Google safe reference collision detected",
        )
    return {reference: group[0] for reference, group in groups.items()}


def _time_boundary(value: date) -> ApplyTimeBoundary:
    return ApplyTimeBoundary(date=value, date_time=None)


def _build_add_payload(event: CanonicalSourceEvent) -> ApplyAddPayload:
    _source_managed_data(event)
    assert event.uid is not None
    assert event.summary is not None
    assert event.description is not None
    assert event.start_date is not None
    assert event.effective_end_date is not None
    return ApplyAddPayload(
        uid=event.uid,
        summary=event.summary,
        description=event.description,
        start=_time_boundary(event.start_date),
        effective_end=_time_boundary(event.effective_end_date),
        all_day=True,
        event_type="default",
    )


def _build_update_payload(
    source_event: CanonicalSourceEvent,
    google_event: CanonicalGoogleEvent,
    changed_fields: tuple[ChangedFieldName, ...],
) -> ApplyUpdatePayload:
    _source_managed_data(source_event)
    _google_managed_data(google_event)
    if not google_event.event_id or not google_event.etag:
        raise ApplyGuardError(
            "update_concurrency_identity_missing",
            "update requires an exact Google event ID and ETag",
        )
    assert source_event.summary is not None
    assert source_event.description is not None
    assert source_event.start_date is not None
    assert source_event.effective_end_date is not None
    return ApplyUpdatePayload(
        event_id=google_event.event_id,
        etag=google_event.etag,
        changed_fields=changed_fields,
        summary=source_event.summary if "summary" in changed_fields else None,
        description=(source_event.description if "description" in changed_fields else None),
        start=(_time_boundary(source_event.start_date) if "start_date" in changed_fields else None),
        effective_end=(
            _time_boundary(source_event.effective_end_date)
            if "end_date" in changed_fields
            else None
        ),
    )


def _operation_without_hash(
    *,
    sequence: int,
    kind: ApplyOperationKind,
    action: PlanAction,
    source_event: CanonicalSourceEvent,
    payload: ApplyPayload,
) -> ApplyOperation:
    source_data = _source_managed_data(source_event)
    source_event_hash = _hash_mapping(_SOURCE_EVENT_HASH_DOMAIN, source_data)
    after_hash = _hash_mapping(_AFTER_HASH_DOMAIN, source_data)
    if kind is ApplyOperationKind.ADD:
        before_hash = _hash_mapping(_BEFORE_HASH_DOMAIN, {"present": False})
        changed_fields = cast(
            tuple[ChangedFieldName, ...],
            ("summary", "description", "start_date", "end_date"),
        )
    else:
        if not isinstance(payload, ApplyUpdatePayload):
            raise ApplyInputError("invalid_update_payload", "update payload is invalid")
        changed_fields = payload.changed_fields
        before_hash = "0" * 64
    payload_hash = _hash_mapping(_PAYLOAD_HASH_DOMAIN, _payload_data(payload))
    assert source_event.uid is not None
    assert source_event.start_date is not None
    provisional = ApplyOperation(
        operation=kind,
        operation_sequence=sequence,
        source_ref=action.source_ref or "",
        google_ref=action.google_refs[0] if action.google_refs else None,
        start_date=source_event.start_date,
        changed_fields=changed_fields,
        source_event_hash=source_event_hash,
        before_hash=before_hash,
        after_hash=after_hash,
        payload_hash=payload_hash,
        source_uid=source_event.uid,
        payload=payload,
        destructive=False,
        approval_required=True,
        operation_integrity_hash="0" * 64,
    )
    return provisional


def _finalize_operation(
    provisional: ApplyOperation,
    *,
    before_hash: str | None = None,
) -> ApplyOperation:
    data = private_operation_data(provisional)
    if before_hash is not None:
        data["before_hash"] = before_hash
    del data["operation_integrity_hash"]
    operation_hash = _hash_mapping(_OPERATION_HASH_DOMAIN, data)
    return ApplyOperation(
        operation=provisional.operation,
        operation_sequence=provisional.operation_sequence,
        source_ref=provisional.source_ref,
        google_ref=provisional.google_ref,
        start_date=provisional.start_date,
        changed_fields=provisional.changed_fields,
        source_event_hash=provisional.source_event_hash,
        before_hash=before_hash or provisional.before_hash,
        after_hash=provisional.after_hash,
        payload_hash=provisional.payload_hash,
        source_uid=provisional.source_uid,
        payload=provisional.payload,
        destructive=False,
        approval_required=True,
        operation_integrity_hash=operation_hash,
    )


def _build_operation(
    sequence: int,
    action: PlanAction,
    source_by_ref: Mapping[str, CanonicalSourceEvent],
    google_by_ref: Mapping[str, CanonicalGoogleEvent],
    baseline: TrustedBaseline,
) -> ApplyOperation:
    if action.source_ref is None or action.source_ref not in source_by_ref:
        raise ApplyGuardError("plan_source_ref_unresolved", "plan Source reference is unresolved")
    source_event = source_by_ref[action.source_ref]
    if action.action is PlanActionKind.ADD:
        payload: ApplyPayload = _build_add_payload(source_event)
        provisional = _operation_without_hash(
            sequence=sequence,
            kind=ApplyOperationKind.ADD,
            action=action,
            source_event=source_event,
            payload=payload,
        )
        return _finalize_operation(provisional)
    if action.action is PlanActionKind.DELETE_CANDIDATE:
        raise ApplyGuardError("delete_operation_forbidden", "delete operations are not supported")
    if len(action.google_refs) != 1 or action.google_refs[0] not in google_by_ref:
        raise ApplyGuardError("plan_google_ref_unresolved", "plan Google reference is unresolved")
    google_event = google_by_ref[action.google_refs[0]]
    if source_event.uid is None or google_event.ical_uid != source_event.uid:
        raise ApplyGuardError("update_uid_mismatch", "update UID identity does not match")
    if source_event.uid not in baseline.managed_uids:
        raise ApplyGuardError(
            "update_not_owned_by_baseline",
            "update UID is not owned by the trusted baseline",
        )
    changed_fields = tuple(action.changed_fields)
    payload = _build_update_payload(source_event, google_event, changed_fields)
    before_hash = _hash_mapping(_BEFORE_HASH_DOMAIN, _google_managed_data(google_event))
    provisional = _operation_without_hash(
        sequence=sequence,
        kind=ApplyOperationKind.UPDATE,
        action=action,
        source_event=source_event,
        payload=payload,
    )
    return _finalize_operation(provisional, before_hash=before_hash)


def _validate_inputs(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    baseline: TrustedBaseline,
    plan: SyncPlan,
) -> tuple[str, str, str, str]:
    if not source.source_valid or source.fatal or not source.source_sha_matches:
        raise ApplyGuardError("apply_source_invalid", "Source input is not exactly valid")
    source_hash = canonical_content_hash(
        vcalendar_count=source.vcalendar_count,
        events=source.events,
    )
    if not hmac.compare_digest(source_hash, source.content_hash):
        raise ApplyValidationError("source_hash_mismatch", "Source integrity check failed")
    if not snapshot.complete:
        raise ApplyGuardError("apply_snapshot_incomplete", "snapshot is incomplete")
    if snapshot.event_count != len(snapshot.events):
        raise ApplyValidationError(
            "snapshot_event_count_mismatch",
            "snapshot event count does not match its inventory",
        )
    if any(
        value != 0
        for value in (
            snapshot.cancelled_event_count,
            snapshot.unknown_event_type_count,
            snapshot.dropped_private_extended_property_count,
            snapshot.dropped_shared_extended_property_count,
            snapshot.forbidden_field_count,
        )
    ):
        raise ApplyGuardError(
            "snapshot_safety_counter_nonzero",
            "snapshot safety counters are not exactly zero",
        )
    if baseline.state is not BaselineState.TRUSTED:
        raise ApplyGuardError("trusted_baseline_required", "trusted baseline is required")
    try:
        verify_baseline_content_hash(baseline)
        baseline_hash = calculate_baseline_content_hash(baseline)
        verify_sync_plan_content_hash(plan)
        plan_hash = calculate_sync_plan_content_hash(plan)
        recomputed = build_sync_plan(
            profile,
            source,
            snapshot,
            baseline,
            thresholds=plan.thresholds,
        )
    except (BaselineError, PlanError) as exc:
        raise ApplyValidationError(
            "apply_input_integrity_verification_failed",
            "apply input integrity verification failed",
        ) from exc
    if not hmac.compare_digest(recomputed.plan_content_hash, plan.plan_content_hash):
        raise ApplyValidationError("stale_sync_plan", "sync plan is stale or mismatched")
    valid_provenance = (
        profile.profile_id == source.profile_id == plan.current_source.profile_id
        and profile.accepted_tag == plan.current_source.accepted_tag
        and profile.accepted_commit == plan.current_source.accepted_commit
        and source.raw_sha256 == plan.current_source.source_sha256
        and source.content_hash == plan.current_source.source_content_hash
        and source.vevent_count == plan.current_source.event_count
        and snapshot.content_hash == plan.snapshot_content_hash
        and snapshot.target_fingerprint == plan.target_fingerprint
        and baseline.target_fingerprint == snapshot.target_fingerprint
        and plan.baseline.target_fingerprint == snapshot.target_fingerprint
        and baseline.baseline_content_hash == plan.baseline.baseline_content_hash
        and baseline.managed_uid_count == plan.baseline.managed_uid_count
        and baseline.snapshot_content_hash == plan.baseline.snapshot_content_hash
    )
    if not valid_provenance:
        raise ApplyValidationError("apply_provenance_mismatch", "apply input provenance mismatch")
    return source_hash, snapshot.content_hash, baseline_hash, plan_hash


def _validate_plan_for_apply(plan: SyncPlan) -> None:
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
    if plan.executable or plan.diff_summary.fatal or plan.diff_summary.has_ambiguous:
        raise ApplyGuardError("unsafe_sync_plan", "sync plan is blocked or unsafe")
    if plan.diff_summary.warning_count != 0:
        raise ApplyGuardError("sync_plan_warning_present", "sync plan contains a warning")
    if any(forbidden_counts) or any(guard.severity == "fatal" for guard in plan.safety_guards):
        raise ApplyGuardError("unsafe_sync_plan_counts", "sync plan contains forbidden counts")
    if any(action.action is PlanActionKind.DELETE_CANDIDATE for action in plan.proposed_actions):
        raise ApplyGuardError("delete_operation_forbidden", "delete operations are not supported")
    expected_actions = counts.add + counts.update
    if expected_actions != len(plan.proposed_actions):
        raise ApplyValidationError("plan_action_count_mismatch", "plan action count mismatch")
    if expected_actions == 0 and plan.state is not PlanState.DRAFT:
        raise ApplyGuardError("zero_plan_state_invalid", "zero-operation plan must be draft")
    if expected_actions > 0 and plan.state is not PlanState.REVIEW_REQUIRED:
        raise ApplyGuardError(
            "nonzero_plan_state_invalid",
            "nonzero apply plan must require review",
        )


def _bundle_with_hash(
    *,
    state: ApplyBundleState,
    environment: ApplyEnvironment,
    target_fingerprint: str,
    target_reference: str,
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    baseline: TrustedBaseline,
    plan: SyncPlan,
    source_hash: str,
    snapshot_hash: str,
    baseline_hash: str,
    plan_hash: str,
    operations: tuple[ApplyOperation, ...],
) -> ApplyBundle:
    add_count = sum(op.operation is ApplyOperationKind.ADD for op in operations)
    update_count = sum(op.operation is ApplyOperationKind.UPDATE for op in operations)
    provisional = ApplyBundle(
        schema_version="1.0",
        bundle_type="non-executable-apply-bundle-v1",
        tool_version=tool_version(),
        state=state,
        environment=environment,
        target_fingerprint=target_fingerprint,
        target_reference=target_reference,
        source_profile=profile.profile_id,
        accepted_tag=profile.accepted_tag,
        accepted_commit=profile.accepted_commit,
        source_sha256=source.raw_sha256,
        source_canonical_hash=source_hash,
        source_event_count=source.vevent_count,
        snapshot_integrity_hash=snapshot_hash,
        snapshot_event_count=snapshot.event_count,
        baseline_integrity_hash=baseline_hash,
        baseline_managed_uid_count=baseline.managed_uid_count,
        plan_integrity_hash=plan_hash,
        plan_content_hash=plan.plan_content_hash,
        plan_state=plan.state,
        generated_operation_count=len(operations),
        add_count=add_count,
        update_count=update_count,
        delete_count=0,
        operations=operations,
        production_locked=True,
        execution_enabled=False,
        bundle_integrity_hash="0" * 64,
    )
    integrity = calculate_apply_bundle_integrity(provisional)
    final_data = {
        **private_bundle_data(provisional),
        "state": state,
        "environment": environment,
        "plan_state": plan.state,
        "operations": operations,
        "bundle_integrity_hash": integrity,
    }
    return ApplyBundle.model_validate(
        final_data,
        strict=True,
    )


def rebuild_apply_bundle_state(
    bundle: ApplyBundle,
    state: ApplyBundleState,
) -> ApplyBundle:
    """Return the same private bundle with a new state and integrity hash."""

    verify_apply_bundle_integrity(bundle)
    provisional_data = private_bundle_data(bundle)
    provisional_data.update(
        {
            "state": state,
            "environment": bundle.environment,
            "plan_state": bundle.plan_state,
            "operations": bundle.operations,
            "bundle_integrity_hash": "0" * 64,
        }
    )
    provisional = ApplyBundle.model_validate(provisional_data, strict=True)
    final_data = dict(provisional_data)
    final_data["bundle_integrity_hash"] = calculate_apply_bundle_integrity(provisional)
    rebuilt = ApplyBundle.model_validate(final_data, strict=True)
    verify_apply_bundle_integrity(rebuilt)
    return rebuilt


def build_apply_bundle(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    trusted: TrustedBaseline,
    plan: SyncPlan,
    environment: ApplyEnvironment,
) -> ApplyBundle:
    """Build an integrity-pinned offline add/update bundle without executing it."""

    if not isinstance(environment, ApplyEnvironment):
        raise ApplyInputError("explicit_environment_required", "apply environment is required")
    source_hash, snapshot_hash, baseline_hash, plan_hash = _validate_inputs(
        profile,
        source,
        snapshot,
        trusted,
        plan,
    )
    _validate_plan_for_apply(plan)
    reference = validate_environment_target(environment, snapshot.target_fingerprint)
    operation_count = len(plan.proposed_actions)
    if environment is ApplyEnvironment.PRODUCTION and operation_count != 0:
        raise ApplyGuardError(
            "production_nonzero_apply_forbidden",
            "Production apply bundle must contain zero operations",
        )
    source_by_ref, _source_by_uid = _source_maps(source)
    google_by_ref = _google_map(snapshot)
    operations = tuple(
        _build_operation(index, action, source_by_ref, google_by_ref, trusted)
        for index, action in enumerate(plan.proposed_actions, start=1)
    )
    state = ApplyBundleState.DRAFT if not operations else ApplyBundleState.APPROVAL_REQUIRED
    bundle = _bundle_with_hash(
        state=state,
        environment=environment,
        target_fingerprint=snapshot.target_fingerprint,
        target_reference=reference,
        profile=profile,
        source=source,
        snapshot=snapshot,
        baseline=trusted,
        plan=plan,
        source_hash=source_hash,
        snapshot_hash=snapshot_hash,
        baseline_hash=baseline_hash,
        plan_hash=plan_hash,
        operations=operations,
    )
    verify_apply_bundle_integrity(bundle)
    return bundle


__all__ = [
    "build_apply_bundle",
    "calculate_apply_bundle_integrity",
    "calculate_apply_operation_integrity",
    "rebuild_apply_bundle_state",
    "verify_apply_bundle_integrity",
]
