"""Mock-only orchestration for one future Production Description patch.

This module has no Google SDK import, credential builder, token path, Calendar
ID input, network primitive, or live mode.  It executes only injected least-
capability readers/mutator and consumes a one-time permit before the first
mock API call.
"""

from __future__ import annotations

import hmac
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from functools import partial
from pathlib import Path
from typing import cast

from tridentine_calendar_google_sync.accepted_production_source_manifest import (
    verify_accepted_production_source_manifest,
)
from tridentine_calendar_google_sync.accepted_production_source_manifest_models import (
    AcceptedProductionSourceManifest,
)
from tridentine_calendar_google_sync.baseline_engine import verify_baseline_content_hash
from tridentine_calendar_google_sync.baseline_models import BaselineState, TrustedBaseline
from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.diff_models import ManagedScope
from tridentine_calendar_google_sync.google_models import (
    CanonicalGoogleEvent,
    GoogleEventTime,
    GoogleSnapshot,
)
from tridentine_calendar_google_sync.google_snapshot import parse_google_snapshot_bytes
from tridentine_calendar_google_sync.models import CanonicalSourceEvent, SourceCalendarInspection
from tridentine_calendar_google_sync.production_approval_state import (
    verify_production_execute_confirmation,
    verify_production_execute_permit,
    verify_production_kill_switch,
)
from tridentine_calendar_google_sync.production_approval_state_io import (
    consume_production_execute_permit,
    production_execute_permit_consumption_filename,
)
from tridentine_calendar_google_sync.production_approval_state_models import (
    ProductionArmReceipt,
    ProductionExecutePermit,
    ProductionKillSwitch,
    ProductionMockApprovalStore,
)
from tridentine_calendar_google_sync.production_execution_journal import (
    PRODUCTION_EXECUTION_SAFE_CODES,
    ProductionExecutionJournal,
    ProductionExecutionJournalEntryStatus,
    ProductionExecutionJournalPhase,
    ProductionExecutionJournalState,
    append_production_execution_journal_entry,
    append_production_execution_journal_file,
    create_production_execution_journal_file,
    initialize_production_execution_journal,
    verify_production_execution_journal,
)
from tridentine_calendar_google_sync.production_fake_transport import (
    ProductionTransportFailure,
    require_phase6c_mock_transport_capabilities,
)
from tridentine_calendar_google_sync.production_single_update_plan import (
    calculate_production_description_patch_hash,
    calculate_production_pre_image_hash,
    verify_production_single_update_plan,
)
from tridentine_calendar_google_sync.production_single_update_plan_models import (
    ProductionSingleUpdatePlan,
)
from tridentine_calendar_google_sync.production_single_update_run_spec import (
    verify_production_single_update_run_spec_bindings,
)
from tridentine_calendar_google_sync.production_single_update_run_spec_models import (
    ProductionSingleUpdateRunSpec,
)
from tridentine_calendar_google_sync.production_transport_models import (
    PRODUCTION_API_CALL_HARD_MAXIMUM,
    PRODUCTION_MUTATION_MAXIMUM_ATTEMPTS,
    PRODUCTION_SEND_UPDATES,
    PRODUCTION_TIME_ZONE,
    ProductionExecutionResultState,
    ProductionExecutionStateProvider,
    ProductionFreshEventReader,
    ProductionFullSnapshotReader,
    ProductionFullSnapshotRequest,
    ProductionMockExecutionResult,
    ProductionSingleUpdateMutator,
    ProductionSnapshotPage,
    ProductionTokenSeparationPolicy,
)

PRODUCTION_READ_RETRY_MAXIMUM = 1


class ProductionMockExecutionError(ValueError):
    """Content-free orchestration configuration failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class _ApiLimitExceeded(RuntimeError):
    pass


@dataclass
class _ExecutionContext:
    now: datetime
    journal: ProductionExecutionJournal
    journal_path: Path
    kill_switch_generation: int
    write_token_generation: int
    api_call_count: int = 0
    read_retry_count: int = 0
    mutation_attempt_count: int = 0
    permit_consumed: bool = False
    approval_validated: bool = False
    pre_snapshot_verified: bool = False
    pre_image_verified: bool = False
    read_back_verified: bool = False
    post_snapshot_verified: bool = False
    zero_diff_verified: bool = False
    recovered_uncertain_outcome: bool = False

    def append(
        self,
        phase: ProductionExecutionJournalPhase,
        status: ProductionExecutionJournalEntryStatus,
        *,
        safe_code: str | None = None,
        terminal_state: ProductionExecutionJournalState | None = None,
    ) -> None:
        previous = self.journal
        updated = append_production_execution_journal_entry(
            self.journal,
            timestamp=self.now,
            phase=phase,
            status=status,
            safe_code=safe_code,
            api_call_count=self.api_call_count,
            read_retry_count=self.read_retry_count,
            mutation_attempt_count=self.mutation_attempt_count,
            approval_consumed=self.permit_consumed,
            kill_switch_generation=self.kill_switch_generation,
            write_token_generation=self.write_token_generation,
            terminal_state=terminal_state,
        )
        append_production_execution_journal_file(self.journal_path, previous, updated)
        self.journal = updated

    def consume_api_call(self) -> None:
        if self.api_call_count >= PRODUCTION_API_CALL_HARD_MAXIMUM:
            raise _ApiLimitExceeded
        self.api_call_count += 1


def _utc_clock(value: datetime) -> bool:
    offset = value.utcoffset()
    return offset is not None and offset.total_seconds() == 0


def _safe_code(exc: BaseException, fallback: str) -> str:
    value = getattr(exc, "code", None)
    if isinstance(value, str) and value in PRODUCTION_EXECUTION_SAFE_CODES:
        return value
    return fallback


def _read_with_retry[T](
    context: _ExecutionContext,
    operation: Callable[[], T],
) -> T:
    while True:
        context.consume_api_call()
        try:
            return operation()
        except ProductionTransportFailure as exc:
            if not exc.retryable_read or context.read_retry_count >= PRODUCTION_READ_RETRY_MAXIMUM:
                raise
            if context.api_call_count >= PRODUCTION_API_CALL_HARD_MAXIMUM:
                raise _ApiLimitExceeded from exc
            context.read_retry_count += 1


def _time_document(value: GoogleEventTime | None) -> dict[str, object] | None:
    if value is None:
        return None
    if value.date is not None:
        return {"date": value.date.isoformat()}
    if value.date_time is not None:
        return {"dateTime": value.date_time.isoformat()}
    raise ProductionMockExecutionError(
        "production_snapshot_time_invalid",
        "Production snapshot time is invalid",
    )


def _event_document(event: CanonicalGoogleEvent) -> dict[str, object]:
    reminders = event.reminders
    extended = event.extended_properties
    return {
        "id": event.event_id,
        "iCalUID": event.ical_uid,
        "summary": event.summary,
        "description": event.description,
        "start": _time_document(event.start),
        "end": _time_document(event.end),
        "allDay": event.all_day,
        "endTimeUnspecified": event.end_time_unspecified,
        "status": event.status,
        "eventType": event.event_type,
        "etag": event.etag,
        "sequence": event.sequence,
        "recurrence": list(event.recurrence),
        "recurringEventId": event.recurring_event_id,
        "originalStartTime": _time_document(event.original_start_time),
        "transparency": event.transparency,
        "visibility": event.visibility,
        "colorId": event.color_id,
        "eventLabelId": event.event_label_id,
        "locked": event.locked,
        "privateCopy": event.private_copy,
        "reminders": (
            {
                "useDefault": reminders.use_default,
                "overrides": [item.model_dump(mode="json") for item in reminders.overrides],
            }
            if reminders is not None
            else None
        ),
        "location": event.location,
        "extendedProperties": (
            {"private": dict(extended.private), "shared": dict(extended.shared)}
            if extended is not None
            else None
        ),
        "created": event.created.isoformat() if event.created else None,
        "updated": event.updated.isoformat() if event.updated else None,
        "htmlLinkPresent": event.html_link_present,
        "creator": ({"self": event.creator.is_self} if event.creator else None),
        "organizer": ({"self": event.organizer.is_self} if event.organizer else None),
    }


def _assemble_snapshot(pages: tuple[ProductionSnapshotPage, ...]) -> GoogleSnapshot:
    if not pages or not pages[-1].collection_complete:
        raise ProductionMockExecutionError(
            "production_full_snapshot_incomplete",
            "Production full snapshot is incomplete",
        )
    first = pages[0]
    events = tuple(event for page in pages for event in page.events)
    if any(
        page.page_number != index
        or page.target_fingerprint != first.target_fingerprint
        or page.access_role != first.access_role
        or page.time_zone != first.time_zone
        or page.collection_metadata_hash != first.collection_metadata_hash
        or (index < len(pages) and page.collection_complete)
        for index, page in enumerate(pages, start=1)
    ):
        raise ProductionMockExecutionError(
            "production_full_snapshot_page_mismatch",
            "Production full snapshot pages do not form one collection",
        )
    document = {
        "schema_version": "1.0",
        "snapshot_format": "sanitized-google-calendar-v1",
        "target_fingerprint": first.target_fingerprint,
        "complete": True,
        "event_count": len(events),
        "page_count": len(pages),
        "collection_metadata_hash": first.collection_metadata_hash,
        "cancelled_event_count": sum(event.status == "cancelled" for event in events),
        "unknown_event_type_count": sum(event.event_type != "default" for event in events),
        "dropped_private_extended_property_count": 0,
        "dropped_shared_extended_property_count": 0,
        "forbidden_field_count": 0,
        "events": [_event_document(event) for event in events],
    }
    return parse_google_snapshot_bytes(
        json.dumps(document, ensure_ascii=False, sort_keys=True).encode("utf-8")
    )


def _collect_full_snapshot(
    context: _ExecutionContext,
    reader: ProductionFullSnapshotReader,
    *,
    target_fingerprint: str,
) -> GoogleSnapshot:
    pages: list[ProductionSnapshotPage] = []
    page_token: str | None = None
    while True:
        page = _read_with_retry(
            context,
            partial(
                reader.list_events,
                request=ProductionFullSnapshotRequest(page_token=page_token),
            ),
        )
        if (
            page.target_fingerprint != target_fingerprint
            or page.access_role != "owner"
            or page.time_zone != PRODUCTION_TIME_ZONE
        ):
            raise ProductionMockExecutionError(
                "production_full_snapshot_target_mismatch",
                "Production full snapshot target metadata does not match",
            )
        pages.append(page)
        if page.collection_complete:
            break
        if page.next_page_token is None:
            raise ProductionMockExecutionError(
                "production_full_snapshot_incomplete",
                "Production full snapshot is incomplete",
            )
        page_token = page.next_page_token
    return _assemble_snapshot(tuple(pages))


def _validate_snapshot_structure(
    snapshot: GoogleSnapshot,
    run_spec: ProductionSingleUpdateRunSpec,
) -> None:
    uid_values = tuple(event.ical_uid for event in snapshot.events if event.ical_uid is not None)
    event_ids = tuple(event.event_id for event in snapshot.events)
    safe_uid_refs = tuple(
        event.safe_ical_uid_reference
        for event in snapshot.events
        if event.safe_ical_uid_reference is not None
    )
    if (
        not snapshot.complete
        or snapshot.target_fingerprint != run_spec.target_fingerprint
        or snapshot.collection_metadata_hash is None
        or snapshot.event_count != run_spec.snapshot_event_count
        or len(snapshot.events) != snapshot.event_count
        or len(event_ids) != len(set(event_ids))
        or len(uid_values) != snapshot.event_count
        or len(uid_values) != len(set(uid_values))
        or len(safe_uid_refs) != len(set(safe_uid_refs))
        or snapshot.cancelled_event_count != 0
        or snapshot.unknown_event_type_count != 0
        or snapshot.forbidden_field_count != 0
    ):
        raise ProductionMockExecutionError(
            "production_full_snapshot_invalid",
            "Production full snapshot safety validation failed",
        )


def _resolve_target_event(
    snapshot: GoogleSnapshot,
    run_spec: ProductionSingleUpdateRunSpec,
) -> CanonicalGoogleEvent:
    matches = tuple(
        event
        for event in snapshot.events
        if event.safe_ical_uid_reference == run_spec.operation.safe_uid_ref
        and event.safe_event_reference == run_spec.operation.google_ref
    )
    if len(matches) != 1:
        raise ProductionMockExecutionError(
            "production_update_identity_ambiguous",
            "Production update identity could not be resolved exactly",
        )
    event = matches[0]
    if not _event_shape_is_patchable(event):
        raise ProductionMockExecutionError(
            "production_update_event_shape_invalid",
            "Production update event shape is not patchable",
        )
    return event


def _event_shape_is_patchable(event: CanonicalGoogleEvent) -> bool:
    return (
        event.ical_uid is not None
        and event.summary is not None
        and event.description is not None
        and event.start is not None
        and event.start.date is not None
        and event.end is not None
        and event.end.date is not None
        and event.all_day is True
        and event.status == "confirmed"
        and event.event_type == "default"
        and not event.recurrence
        and event.recurring_event_id is None
    )


def _desired_source_event(
    source: SourceCalendarInspection,
    run_spec: ProductionSingleUpdateRunSpec,
) -> CanonicalSourceEvent:
    matches = tuple(
        event
        for event in source.events
        if event.safe_uid_reference == run_spec.operation.safe_uid_ref
    )
    if len(matches) != 1:
        raise ProductionMockExecutionError(
            "production_desired_event_invalid",
            "Production desired event could not be resolved exactly",
        )
    event = matches[0]
    description = event.description
    if description is None:
        raise ProductionMockExecutionError(
            "production_desired_event_invalid",
            "Production desired event could not be resolved exactly",
        )
    if not hmac.compare_digest(
        calculate_production_description_patch_hash(description),
        run_spec.operation.patch_hash,
    ):
        raise ProductionMockExecutionError(
            "production_patch_hash_mismatch",
            "Production Description patch hash does not match",
        )
    return event


def _fresh_event_matches_pre_image(
    fresh: CanonicalGoogleEvent,
    snapshot_event: CanonicalGoogleEvent,
    run_spec: ProductionSingleUpdateRunSpec,
) -> bool:
    return (
        fresh.event_id == snapshot_event.event_id
        and fresh.ical_uid == snapshot_event.ical_uid
        and fresh.safe_event_reference == snapshot_event.safe_event_reference
        and fresh.safe_ical_uid_reference == snapshot_event.safe_ical_uid_reference
        and _event_shape_is_patchable(fresh)
        and fresh.etag is not None
        and fresh.etag != "*"
        and (snapshot_event.etag is None or fresh.etag == snapshot_event.etag)
        and hmac.compare_digest(
            calculate_production_pre_image_hash(fresh),
            run_spec.operation.pre_image_hash,
        )
    )


def _read_back_matches(
    event: CanonicalGoogleEvent,
    *,
    pre_event: CanonicalGoogleEvent,
    desired_event: CanonicalSourceEvent,
) -> bool:
    return (
        event.event_id == pre_event.event_id
        and event.ical_uid == pre_event.ical_uid
        and event.safe_event_reference == pre_event.safe_event_reference
        and event.safe_ical_uid_reference == pre_event.safe_ical_uid_reference
        and event.summary == pre_event.summary == desired_event.summary
        and event.description == desired_event.description
        and event.start == pre_event.start
        and event.end == pre_event.end
        and _event_shape_is_patchable(event)
        and event.color_id is None
        and event.event_label_id is None
        and event.etag is not None
        and event.etag != "*"
    )


def _semantic_event_data(event: CanonicalGoogleEvent) -> dict[str, object]:
    data = _event_document(event)
    data.pop("etag")
    data.pop("updated")
    data.pop("sequence")
    return data


def _post_snapshot_matches_intended_change(
    pre_snapshot: GoogleSnapshot,
    post_snapshot: GoogleSnapshot,
    *,
    run_spec: ProductionSingleUpdateRunSpec,
    desired_event: CanonicalSourceEvent,
) -> bool:
    if not hmac.compare_digest(
        pre_snapshot.collection_metadata_hash or "",
        post_snapshot.collection_metadata_hash or "",
    ):
        return False
    pre_by_id = {event.event_id: event for event in pre_snapshot.events}
    post_by_id = {event.event_id: event for event in post_snapshot.events}
    if pre_by_id.keys() != post_by_id.keys():
        return False
    target_id: str | None = None
    for event_id, pre_event in pre_by_id.items():
        post_event = post_by_id[event_id]
        if pre_event.safe_ical_uid_reference == run_spec.operation.safe_uid_ref:
            if target_id is not None:
                return False
            target_id = event_id
            pre_data = _semantic_event_data(pre_event)
            post_data = _semantic_event_data(post_event)
            pre_data.pop("description")
            post_description = post_data.pop("description")
            if pre_data != post_data or post_description != desired_event.description:
                return False
        elif _event_document(pre_event) != _event_document(post_event):
            return False
    return target_id is not None


def _zero_diff(
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    managed_scope: ManagedScope | None = None,
) -> bool:
    diff = diff_source_to_snapshot(source, snapshot, managed_scope)
    counts = diff.counts
    return (
        source.source_valid
        and not source.fatal
        and not source.findings
        and source.uid_duplicate_count == 0
        and not diff.fatal
        and not diff.warnings
        and counts.unchanged == source.vevent_count == snapshot.event_count
        and all(
            count == 0
            for count in (
                counts.add,
                counts.update,
                counts.delete_candidate,
                counts.duplicate_source_uid,
                counts.duplicate_google_icaluid,
                counts.ambiguous,
                counts.unmanaged_google_event,
                counts.invalid_source,
                counts.fatal_guard,
            )
        )
    )


def verify_production_post_write_zero_diff(
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    managed_scope: ManagedScope | None = None,
) -> None:
    """Require an exact post-write Source/snapshot zero difference."""

    if not _zero_diff(source, snapshot, managed_scope):
        raise ProductionMockExecutionError(
            "production_post_write_zero_diff_failed",
            "Production post-write snapshot is not zero-difference",
        )


def _validate_static_inputs(
    *,
    run_spec: ProductionSingleUpdateRunSpec,
    plan: ProductionSingleUpdatePlan,
    manifest: AcceptedProductionSourceManifest,
    trusted_baseline: TrustedBaseline,
    bound_snapshot: GoogleSnapshot,
    desired_source: SourceCalendarInspection,
    now: datetime,
) -> None:
    verify_production_single_update_plan(plan)
    verify_production_single_update_run_spec_bindings(run_spec, plan, now=now)
    verify_accepted_production_source_manifest(manifest)
    verify_baseline_content_hash(trusted_baseline)
    valid = (
        trusted_baseline.state is BaselineState.TRUSTED
        and trusted_baseline.baseline_content_hash == run_spec.trusted_baseline_hash
        and trusted_baseline.snapshot_content_hash == run_spec.current_snapshot_hash
        and trusted_baseline.target_fingerprint == run_spec.target_fingerprint
        and manifest.manifest_content_hash == run_spec.manifest_hash
        and manifest.ics_sha256 == run_spec.source_sha256 == desired_source.raw_sha256
        and manifest.source_content_hash
        == run_spec.source_content_hash
        == desired_source.content_hash
        and manifest.profile_id == run_spec.source_profile == desired_source.profile_id
        and manifest.event_count == run_spec.source_event_count == desired_source.vevent_count
        and bound_snapshot.content_hash == run_spec.current_snapshot_hash
        and bound_snapshot.target_fingerprint == run_spec.target_fingerprint
        and bound_snapshot.event_count == run_spec.snapshot_event_count
        and run_spec.operation_count == 1
        and run_spec.add_count == 0
        and run_spec.update_count == 1
        and run_spec.delete_count == 0
        and run_spec.changed_fields == ("description",)
    )
    if not valid:
        raise ProductionMockExecutionError(
            "production_execution_binding_mismatch",
            "Production mock execution bindings do not match",
        )


def _recheck_generations(
    provider: ProductionExecutionStateProvider,
    permit: ProductionExecutePermit,
) -> None:
    kill_switch = provider.current_kill_switch()
    verify_production_kill_switch(
        cast(ProductionKillSwitch, kill_switch),
        target_safe_ref=permit.target_safe_ref,
        required_generation=permit.kill_switch_generation,
        require_on=True,
    )
    token_generation = provider.current_write_token_generation()
    if (
        isinstance(token_generation, bool)
        or not isinstance(token_generation, int)
        or token_generation != permit.write_token_generation
    ):
        raise ProductionMockExecutionError(
            "production_write_token_generation_mismatch",
            "Production write-token generation does not match",
        )


def _journal_state(state: ProductionExecutionResultState) -> ProductionExecutionJournalState:
    return ProductionExecutionJournalState(state.value)


def _finish(
    context: _ExecutionContext,
    *,
    run_spec: ProductionSingleUpdateRunSpec,
    plan: ProductionSingleUpdatePlan,
    state: ProductionExecutionResultState,
    code: str | None,
) -> ProductionMockExecutionResult:
    succeeded = state is ProductionExecutionResultState.SUCCEEDED
    terminal_status = (
        ProductionExecutionJournalEntryStatus.RECOVERED
        if succeeded and context.recovered_uncertain_outcome
        else (
            ProductionExecutionJournalEntryStatus.SUCCEEDED
            if succeeded
            else (
                ProductionExecutionJournalEntryStatus.UNCERTAIN
                if state is ProductionExecutionResultState.WRITE_OUTCOME_UNCERTAIN
                else ProductionExecutionJournalEntryStatus.FAILED
            )
        )
    )
    context.append(
        ProductionExecutionJournalPhase.TERMINAL_RESULT,
        terminal_status,
        safe_code=code,
        terminal_state=_journal_state(state),
    )
    verify_production_execution_journal(context.journal)
    return ProductionMockExecutionResult(
        result_state=state,
        target_safe_ref=run_spec.target_safe_ref,
        run_spec_ref=f"R-{run_spec.run_spec_content_hash[:12]}",
        plan_ref=f"P-{plan.plan_content_hash[:12]}",
        approval_state="validated" if context.approval_validated else "rejected",
        permit_consumed=context.permit_consumed,
        patch_hash=run_spec.operation.patch_hash,
        api_call_count=context.api_call_count,
        read_retry_count=context.read_retry_count,
        mutation_attempt_count=context.mutation_attempt_count,
        pre_snapshot_verified=context.pre_snapshot_verified,
        pre_image_verified=context.pre_image_verified,
        read_back_verified=context.read_back_verified,
        post_snapshot_verified=context.post_snapshot_verified,
        zero_diff_verified=context.zero_diff_verified,
        baseline_renewal_required=succeeded,
        safe_findings=(() if code is None else (code,)),
        recovered_uncertain_outcome=context.recovered_uncertain_outcome,
        journal=context.journal,
    )


def _fail_phase(
    context: _ExecutionContext,
    *,
    phase: ProductionExecutionJournalPhase,
    state: ProductionExecutionResultState,
    code: str,
    uncertain: bool = False,
) -> None:
    context.append(
        phase,
        (
            ProductionExecutionJournalEntryStatus.UNCERTAIN
            if uncertain
            else ProductionExecutionJournalEntryStatus.FAILED
        ),
        safe_code=code,
    )


def run_production_single_update_mock(
    *,
    run_spec: ProductionSingleUpdateRunSpec,
    plan: ProductionSingleUpdatePlan,
    manifest: AcceptedProductionSourceManifest,
    trusted_baseline: TrustedBaseline,
    bound_snapshot: GoogleSnapshot,
    desired_source: SourceCalendarInspection,
    arm_receipt: ProductionArmReceipt,
    execute_permit: ProductionExecutePermit,
    execute_confirmation: str,
    approval_kill_switch: ProductionKillSwitch,
    approval_store: ProductionMockApprovalStore,
    write_token_generation: int,
    permit_consumption_directory: str | Path,
    journal_path: str | Path,
    full_snapshot_reader: ProductionFullSnapshotReader,
    fresh_event_reader: ProductionFreshEventReader,
    single_update_mutator: ProductionSingleUpdateMutator,
    state_provider: ProductionExecutionStateProvider,
    now: datetime,
) -> ProductionMockExecutionResult:
    """Run one synthetic/mock Production update with live execution hard-off."""

    if not _utc_clock(now):
        raise ProductionMockExecutionError(
            "production_execution_clock_invalid",
            "Production mock execution clock must be UTC",
        )
    if (
        isinstance(write_token_generation, bool)
        or not isinstance(write_token_generation, int)
        or write_token_generation < 1
    ):
        raise ProductionMockExecutionError(
            "production_write_token_generation_invalid",
            "Production write-token generation is invalid",
        )
    ProductionTokenSeparationPolicy(write_token_generation=write_token_generation)
    initial_journal = initialize_production_execution_journal(
        target_safe_ref=run_spec.target_safe_ref,
        run_spec_ref=f"R-{run_spec.run_spec_content_hash[:12]}",
        plan_ref=f"P-{plan.plan_content_hash[:12]}",
        approval_material_hash=run_spec.approval_material_hash,
        execute_permit_hash=execute_permit.content_hash,
        patch_hash=run_spec.operation.patch_hash,
        started_at=now,
    )
    resolved_journal_path = create_production_execution_journal_file(
        journal_path,
        initial_journal,
    )
    context = _ExecutionContext(
        now=now,
        journal=initial_journal,
        journal_path=resolved_journal_path,
        kill_switch_generation=execute_permit.kill_switch_generation,
        write_token_generation=write_token_generation,
    )
    context.append(
        ProductionExecutionJournalPhase.RUN_START,
        ProductionExecutionJournalEntryStatus.STARTED,
    )

    try:
        require_phase6c_mock_transport_capabilities(
            full_snapshot_reader,
            fresh_event_reader,
            single_update_mutator,
        )
        _validate_static_inputs(
            run_spec=run_spec,
            plan=plan,
            manifest=manifest,
            trusted_baseline=trusted_baseline,
            bound_snapshot=bound_snapshot,
            desired_source=desired_source,
            now=now,
        )
        verify_production_execute_confirmation(execute_permit, execute_confirmation)
        verify_production_execute_permit(
            execute_permit,
            arm_receipt,
            run_spec,
            plan,
            approval_kill_switch,
            approval_store,
            write_token_generation=write_token_generation,
            now=now,
        )
    except Exception as exc:
        code = _safe_code(exc, "production_approval_validation_failed")
        return _finish(
            context,
            run_spec=run_spec,
            plan=plan,
            state=ProductionExecutionResultState.FAILED_APPROVAL,
            code=code,
        )
    context.approval_validated = True
    context.append(
        ProductionExecutionJournalPhase.APPROVAL_VALIDATED,
        ProductionExecutionJournalEntryStatus.VALIDATED,
    )

    try:
        consume_production_execute_permit(
            execute_permit,
            Path(permit_consumption_directory)
            / production_execute_permit_consumption_filename(execute_permit),
            approval_store=approval_store,
            consumed_at=now,
        )
    except Exception as exc:
        return _finish(
            context,
            run_spec=run_spec,
            plan=plan,
            state=ProductionExecutionResultState.FAILED_APPROVAL,
            code=_safe_code(exc, "production_execute_permit_consume_failed"),
        )
    context.permit_consumed = True
    context.append(
        ProductionExecutionJournalPhase.EXECUTE_PERMIT_CONSUMED,
        ProductionExecutionJournalEntryStatus.CONSUMED,
    )

    try:
        _recheck_generations(state_provider, execute_permit)
    except Exception as exc:
        code = _safe_code(exc, "production_kill_switch_recheck_failed")
        _fail_phase(
            context,
            phase=ProductionExecutionJournalPhase.KILL_SWITCH_VERIFIED,
            state=ProductionExecutionResultState.FAILED_KILL_SWITCH,
            code=code,
        )
        return _finish(
            context,
            run_spec=run_spec,
            plan=plan,
            state=ProductionExecutionResultState.FAILED_KILL_SWITCH,
            code=code,
        )
    context.append(
        ProductionExecutionJournalPhase.KILL_SWITCH_VERIFIED,
        ProductionExecutionJournalEntryStatus.VERIFIED,
    )

    context.append(
        ProductionExecutionJournalPhase.PRE_SNAPSHOT_INTENT,
        ProductionExecutionJournalEntryStatus.INTENT,
    )
    try:
        pre_snapshot = _collect_full_snapshot(
            context,
            full_snapshot_reader,
            target_fingerprint=run_spec.target_fingerprint,
        )
        _validate_snapshot_structure(pre_snapshot, run_spec)
        if not hmac.compare_digest(pre_snapshot.content_hash, run_spec.current_snapshot_hash):
            raise ProductionMockExecutionError(
                "production_full_snapshot_drift",
                "Production full snapshot drifted before mutation",
            )
        pre_event = _resolve_target_event(pre_snapshot, run_spec)
    except _ApiLimitExceeded:
        code = "api_call_limit_exceeded"
        _fail_phase(
            context,
            phase=ProductionExecutionJournalPhase.PRE_SNAPSHOT_VERIFIED,
            state=ProductionExecutionResultState.API_CALL_LIMIT_EXCEEDED,
            code=code,
        )
        return _finish(
            context,
            run_spec=run_spec,
            plan=plan,
            state=ProductionExecutionResultState.API_CALL_LIMIT_EXCEEDED,
            code=code,
        )
    except Exception as exc:
        code = _safe_code(exc, "production_full_snapshot_failed")
        _fail_phase(
            context,
            phase=ProductionExecutionJournalPhase.PRE_SNAPSHOT_VERIFIED,
            state=ProductionExecutionResultState.FAILED_DRIFT,
            code=code,
        )
        return _finish(
            context,
            run_spec=run_spec,
            plan=plan,
            state=ProductionExecutionResultState.FAILED_DRIFT,
            code=code,
        )
    context.pre_snapshot_verified = True
    context.append(
        ProductionExecutionJournalPhase.PRE_SNAPSHOT_VERIFIED,
        ProductionExecutionJournalEntryStatus.VERIFIED,
    )

    context.append(
        ProductionExecutionJournalPhase.FRESH_GET_INTENT,
        ProductionExecutionJournalEntryStatus.INTENT,
    )
    try:
        fresh_event = _read_with_retry(
            context,
            lambda: fresh_event_reader.get_event(
                event_id=pre_event.event_id,
                token_role="production_read_only",
            ),
        )
        if not _fresh_event_matches_pre_image(fresh_event, pre_event, run_spec):
            raise ProductionMockExecutionError(
                "production_pre_image_mismatch",
                "Production fresh event does not match the bound pre-image",
            )
        desired_event = _desired_source_event(desired_source, run_spec)
    except _ApiLimitExceeded:
        code = "api_call_limit_exceeded"
        _fail_phase(
            context,
            phase=ProductionExecutionJournalPhase.PRE_IMAGE_VERIFIED,
            state=ProductionExecutionResultState.API_CALL_LIMIT_EXCEEDED,
            code=code,
        )
        return _finish(
            context,
            run_spec=run_spec,
            plan=plan,
            state=ProductionExecutionResultState.API_CALL_LIMIT_EXCEEDED,
            code=code,
        )
    except Exception as exc:
        code = _safe_code(exc, "production_pre_image_failed")
        _fail_phase(
            context,
            phase=ProductionExecutionJournalPhase.PRE_IMAGE_VERIFIED,
            state=ProductionExecutionResultState.FAILED_PREIMAGE,
            code=code,
        )
        return _finish(
            context,
            run_spec=run_spec,
            plan=plan,
            state=ProductionExecutionResultState.FAILED_PREIMAGE,
            code=code,
        )
    context.pre_image_verified = True
    context.append(
        ProductionExecutionJournalPhase.PRE_IMAGE_VERIFIED,
        ProductionExecutionJournalEntryStatus.VERIFIED,
    )

    try:
        _recheck_generations(state_provider, execute_permit)
    except Exception as exc:
        code = _safe_code(exc, "production_kill_switch_patch_recheck_failed")
        return _finish(
            context,
            run_spec=run_spec,
            plan=plan,
            state=ProductionExecutionResultState.FAILED_KILL_SWITCH,
            code=code,
        )

    context.mutation_attempt_count = PRODUCTION_MUTATION_MAXIMUM_ATTEMPTS
    context.append(
        ProductionExecutionJournalPhase.MUTATION_INTENT,
        ProductionExecutionJournalEntryStatus.INTENT,
    )
    patch_uncertain = False
    try:
        context.consume_api_call()
        etag = fresh_event.etag
        description = desired_event.description
        if etag is None or etag == "*" or description is None:
            raise ProductionMockExecutionError(
                "production_patch_contract_invalid",
                "Production patch contract is invalid",
            )
        single_update_mutator.patch_description(
            event_id=fresh_event.event_id,
            description=description,
            if_match=etag,
            send_updates=PRODUCTION_SEND_UPDATES,
            token_role="production_write",
            write_token_generation=write_token_generation,
        )
    except _ApiLimitExceeded:
        code = "api_call_limit_exceeded"
        _fail_phase(
            context,
            phase=ProductionExecutionJournalPhase.MUTATION_RESULT,
            state=ProductionExecutionResultState.API_CALL_LIMIT_EXCEEDED,
            code=code,
        )
        return _finish(
            context,
            run_spec=run_spec,
            plan=plan,
            state=ProductionExecutionResultState.API_CALL_LIMIT_EXCEEDED,
            code=code,
        )
    except ProductionTransportFailure as exc:
        code = _safe_code(exc, "production_patch_failed")
        if exc.etag_conflict:
            _fail_phase(
                context,
                phase=ProductionExecutionJournalPhase.MUTATION_RESULT,
                state=ProductionExecutionResultState.ETAG_CONFLICT,
                code="etag_conflict",
            )
            return _finish(
                context,
                run_spec=run_spec,
                plan=plan,
                state=ProductionExecutionResultState.ETAG_CONFLICT,
                code="etag_conflict",
            )
        if exc.uncertain_patch_outcome:
            patch_uncertain = True
            context.append(
                ProductionExecutionJournalPhase.MUTATION_RESULT,
                ProductionExecutionJournalEntryStatus.UNCERTAIN,
                safe_code="write_outcome_uncertain",
            )
        else:
            _fail_phase(
                context,
                phase=ProductionExecutionJournalPhase.MUTATION_RESULT,
                state=ProductionExecutionResultState.FAILED_TRANSPORT,
                code=code,
            )
            return _finish(
                context,
                run_spec=run_spec,
                plan=plan,
                state=ProductionExecutionResultState.FAILED_TRANSPORT,
                code=code,
            )
    except Exception as exc:
        code = _safe_code(exc, "production_patch_failed")
        _fail_phase(
            context,
            phase=ProductionExecutionJournalPhase.MUTATION_RESULT,
            state=ProductionExecutionResultState.FAILED_TRANSPORT,
            code=code,
        )
        return _finish(
            context,
            run_spec=run_spec,
            plan=plan,
            state=ProductionExecutionResultState.FAILED_TRANSPORT,
            code=code,
        )
    else:
        context.append(
            ProductionExecutionJournalPhase.MUTATION_RESULT,
            ProductionExecutionJournalEntryStatus.SUCCEEDED,
        )

    context.append(
        ProductionExecutionJournalPhase.READBACK_INTENT,
        ProductionExecutionJournalEntryStatus.INTENT,
    )
    try:
        read_back = _read_with_retry(
            context,
            lambda: fresh_event_reader.get_event(
                event_id=fresh_event.event_id,
                token_role="production_read_only",
            ),
        )
        if not _read_back_matches(
            read_back,
            pre_event=fresh_event,
            desired_event=desired_event,
        ):
            raise ProductionMockExecutionError(
                "production_read_back_mismatch",
                "Production patch read-back did not match",
            )
    except Exception as exc:
        if patch_uncertain:
            code = "write_outcome_uncertain"
            _fail_phase(
                context,
                phase=ProductionExecutionJournalPhase.READBACK_VERIFIED,
                state=ProductionExecutionResultState.WRITE_OUTCOME_UNCERTAIN,
                code=code,
                uncertain=True,
            )
            return _finish(
                context,
                run_spec=run_spec,
                plan=plan,
                state=ProductionExecutionResultState.WRITE_OUTCOME_UNCERTAIN,
                code=code,
            )
        state = (
            ProductionExecutionResultState.API_CALL_LIMIT_EXCEEDED
            if isinstance(exc, _ApiLimitExceeded)
            else ProductionExecutionResultState.FAILED_READBACK
        )
        code = (
            "api_call_limit_exceeded"
            if isinstance(exc, _ApiLimitExceeded)
            else _safe_code(exc, "production_read_back_failed")
        )
        _fail_phase(
            context,
            phase=ProductionExecutionJournalPhase.READBACK_VERIFIED,
            state=state,
            code=code,
        )
        return _finish(context, run_spec=run_spec, plan=plan, state=state, code=code)
    context.read_back_verified = True
    context.recovered_uncertain_outcome = patch_uncertain
    context.append(
        ProductionExecutionJournalPhase.READBACK_VERIFIED,
        (
            ProductionExecutionJournalEntryStatus.RECOVERED
            if patch_uncertain
            else ProductionExecutionJournalEntryStatus.VERIFIED
        ),
    )

    context.append(
        ProductionExecutionJournalPhase.POST_SNAPSHOT_INTENT,
        ProductionExecutionJournalEntryStatus.INTENT,
    )
    try:
        post_snapshot = _collect_full_snapshot(
            context,
            full_snapshot_reader,
            target_fingerprint=run_spec.target_fingerprint,
        )
        _validate_snapshot_structure(post_snapshot, run_spec)
        if not _post_snapshot_matches_intended_change(
            pre_snapshot,
            post_snapshot,
            run_spec=run_spec,
            desired_event=desired_event,
        ):
            raise ProductionMockExecutionError(
                "production_post_snapshot_drift",
                "Production post-write full snapshot contains unexpected drift",
            )
    except Exception as exc:
        state = (
            ProductionExecutionResultState.API_CALL_LIMIT_EXCEEDED
            if isinstance(exc, _ApiLimitExceeded)
            else ProductionExecutionResultState.FAILED_POST_SNAPSHOT
        )
        code = (
            "api_call_limit_exceeded"
            if isinstance(exc, _ApiLimitExceeded)
            else _safe_code(exc, "production_post_snapshot_failed")
        )
        _fail_phase(
            context,
            phase=ProductionExecutionJournalPhase.POST_SNAPSHOT_VERIFIED,
            state=state,
            code=code,
        )
        return _finish(context, run_spec=run_spec, plan=plan, state=state, code=code)
    context.post_snapshot_verified = True
    context.append(
        ProductionExecutionJournalPhase.POST_SNAPSHOT_VERIFIED,
        ProductionExecutionJournalEntryStatus.VERIFIED,
    )

    try:
        verify_production_post_write_zero_diff(
            desired_source,
            post_snapshot,
            ManagedScope(
                trusted_source_uids=frozenset(
                    event.uid for event in desired_source.events if event.uid is not None
                ),
                trusted_baseline_uids=frozenset(trusted_baseline.managed_uids),
            ),
        )
    except Exception as exc:
        code = _safe_code(exc, "production_post_write_zero_diff_failed")
        _fail_phase(
            context,
            phase=ProductionExecutionJournalPhase.ZERO_DIFF_VERIFIED,
            state=ProductionExecutionResultState.FAILED_ZERO_DIFF,
            code=code,
        )
        return _finish(
            context,
            run_spec=run_spec,
            plan=plan,
            state=ProductionExecutionResultState.FAILED_ZERO_DIFF,
            code=code,
        )
    context.zero_diff_verified = True
    context.append(
        ProductionExecutionJournalPhase.ZERO_DIFF_VERIFIED,
        ProductionExecutionJournalEntryStatus.VERIFIED,
    )
    return _finish(
        context,
        run_spec=run_spec,
        plan=plan,
        state=ProductionExecutionResultState.SUCCEEDED,
        code=None,
    )


def phase6c_production_live_execution_hard_off() -> None:
    """Expose one explicit safe-code gate without constructing any live client."""

    raise ProductionMockExecutionError(
        "production_live_execution_not_available_in_phase_6c",
        "Production live execution is not available in Phase 6C",
    )


__all__ = [
    "PRODUCTION_READ_RETRY_MAXIMUM",
    "ProductionMockExecutionError",
    "phase6c_production_live_execution_hard_off",
    "run_production_single_update_mock",
    "verify_production_post_write_zero_diff",
]
