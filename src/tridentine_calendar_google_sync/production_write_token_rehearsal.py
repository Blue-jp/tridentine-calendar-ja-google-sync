"""Mock-only orchestration for a dedicated Production write-token rehearsal."""

from __future__ import annotations

import hmac
import json
from dataclasses import dataclass
from functools import partial
from typing import Literal

from tridentine_calendar_google_sync.accepted_production_source_manifest import (
    build_accepted_production_source_manifest,
    verify_accepted_production_source_manifest,
)
from tridentine_calendar_google_sync.accepted_production_source_manifest_models import (
    AcceptedProductionSourceManifest,
)
from tridentine_calendar_google_sync.baseline_engine import verify_baseline_content_hash
from tridentine_calendar_google_sync.baseline_models import BaselineState, TrustedBaseline
from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.diff_models import CalendarDiff, ManagedScope
from tridentine_calendar_google_sync.google_models import CanonicalGoogleEvent, GoogleSnapshot
from tridentine_calendar_google_sync.google_sanitize import snapshot_document
from tridentine_calendar_google_sync.google_snapshot import parse_google_snapshot_bytes
from tridentine_calendar_google_sync.models import AcceptedSourceProfile, SourceCalendarInspection
from tridentine_calendar_google_sync.production_write_target import (
    ProductionWriteTargetConfig,
    production_write_target_reference,
    validate_production_write_target_config,
)
from tridentine_calendar_google_sync.production_write_token import (
    ProductionWriteTokenRefreshError,
    validate_production_token_role,
    validate_production_write_scopes,
    verify_production_write_authorized_user_token,
    verify_production_write_token_generation_state,
)
from tridentine_calendar_google_sync.production_write_token_models import (
    PRODUCTION_WRITE_SCOPES,
    ProductionTokenRole,
    ProductionWriteCredentialSession,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_models import (
    PRODUCTION_REHEARSAL_API_CALL_HARD_MAXIMUM,
    PRODUCTION_REHEARSAL_READ_RETRY_MAXIMUM,
    PRODUCTION_REHEARSAL_TIME_ZONE,
    ProductionWriteCredentialSessionProvider,
    ProductionWriteTokenFullSnapshotRequest,
    ProductionWriteTokenReadOnlyTransport,
    ProductionWriteTokenReadOnlyTransportProvider,
    ProductionWriteTokenRehearsalReport,
    ProductionWriteTokenRehearsalResultState,
    ProductionWriteTokenRehearsalSnapshot,
    ProductionWriteTokenSnapshotPage,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_report import (
    build_production_write_token_rehearsal_event_evidence,
    finalize_production_write_token_rehearsal_report,
    finalize_production_write_token_rehearsal_snapshot,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_transport import (
    ProductionWriteTokenRehearsalTransportError,
    require_phase6d0_rehearsal_providers,
    require_phase6d0_rehearsal_transport,
)

_NONPRODUCTION_MARKERS = ("test", "synthetic", "テスト", "架空", ".invalid")


class ProductionWriteTokenRehearsalError(ValueError):
    """Content-free Phase 6D.0 rehearsal failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class _ApiCallLimitExceeded(ProductionWriteTokenRehearsalError):
    def __init__(self) -> None:
        super().__init__(
            "api_call_limit_exceeded",
            "Production rehearsal API call hard maximum would be exceeded",
        )


@dataclass(frozen=True)
class ProductionWriteTokenRehearsalOutcome:
    """Safe result plus optional aggregate snapshot evidence."""

    report: ProductionWriteTokenRehearsalReport
    snapshot: ProductionWriteTokenRehearsalSnapshot | None


@dataclass
class _Context:
    target_safe_ref: str
    token_role: Literal["production_write", "production_read", "test_write", "invalid"]
    token_generation: int
    scope_count: int
    scope_exact: bool
    refresh_count: int
    browser_launch_count: Literal[0] = 0
    rehearsal_client_construction_count: int = 0
    api_call_count: int = 0
    list_call_count: int = 0
    get_call_count: int = 0
    read_retry_count: int = 0
    target_metadata_verified: bool = False
    snapshot_complete: bool = False
    page_count: int = 0
    event_count: int = 0
    snapshot_content_hash: str | None = None
    baseline_cross_binding: bool = False
    source_unchanged_count: int = 0
    source_add_count: int = 0
    source_update_count: int = 0
    source_delete_candidate_count: int = 0
    source_unmanaged_count: int = 0
    source_duplicate_count: int = 0
    source_ambiguous_count: int = 0
    source_invalid_count: int = 0
    source_fatal_count: int = 0
    source_zero_diff: bool = False
    get_performed: bool = False
    get_verified: bool = False
    selected_safe_uid_ref: str | None = None
    event_id_present_internally: bool = False
    etag_present_internally: bool = False

    def consume_call(self, method: str) -> None:
        if self.api_call_count >= PRODUCTION_REHEARSAL_API_CALL_HARD_MAXIMUM:
            raise _ApiCallLimitExceeded
        self.api_call_count += 1
        if method == "events.list":
            self.list_call_count += 1
        elif method == "events.get":
            self.get_call_count += 1
            self.get_performed = True
        else:
            raise ProductionWriteTokenRehearsalError(
                "production_rehearsal_method_forbidden",
                "Production rehearsal method is not read-only allowlisted",
            )


def production_write_token_rehearsal_challenge(target: ProductionWriteTargetConfig) -> str:
    """Build the exact target-bound read-only confirmation."""

    return (
        "READ PRODUCTION CALENDAR USING DEDICATED WRITE TOKEN "
        f"{production_write_target_reference(target)}"
    )


def verify_production_write_token_rehearsal_confirmation(
    target: ProductionWriteTargetConfig,
    confirmation: str,
) -> None:
    expected = production_write_token_rehearsal_challenge(target)
    if not hmac.compare_digest(confirmation.encode("utf-8"), expected.encode("utf-8")):
        raise ProductionWriteTokenRehearsalError(
            "production_rehearsal_confirmation_mismatch",
            "Production write-token read-only confirmation did not match",
        )


def _safe_public_token_role(
    role_value: object,
) -> Literal["production_write", "production_read", "test_write", "invalid"]:
    if role_value == ProductionTokenRole.PRODUCTION_WRITE:
        return "production_write"
    if role_value == ProductionTokenRole.PRODUCTION_READ:
        return "production_read"
    if role_value == ProductionTokenRole.TEST_WRITE:
        return "test_write"
    return "invalid"


def _session_context(
    session: ProductionWriteCredentialSession,
    target: ProductionWriteTargetConfig,
) -> _Context:
    if not isinstance(session, ProductionWriteCredentialSession):
        raise ProductionWriteTokenRehearsalError(
            "production_rehearsal_token_role_mismatch",
            "Production write-token rehearsal credential binding is invalid",
        )
    role = _safe_public_token_role(session.token.role)
    generation = session.generation_state.generation
    if isinstance(generation, bool) or not isinstance(generation, int):
        generation = 0
    scopes = session.token.granted_scopes
    refresh_count = session.refresh_count
    context = _Context(
        target_safe_ref=production_write_target_reference(target),
        token_role=role,
        token_generation=generation,
        scope_count=len(scopes),
        scope_exact=scopes == PRODUCTION_WRITE_SCOPES,
        refresh_count=refresh_count,
    )
    try:
        validate_production_token_role(session.token.role)
        validate_production_write_scopes(session.token.scopes)
        validate_production_write_scopes(session.token.granted_scopes)
        verify_production_write_token_generation_state(
            session.generation_state,
            target=target,
        )
        verify_production_write_authorized_user_token(
            session.token,
            session.generation_state,
            target,
        )
        if (
            session.token.role is not ProductionTokenRole.PRODUCTION_WRITE
            or session.token.generation != session.generation_state.generation
            or session.refresh_count not in (0, 1)
            or session.browser_fallback_count != 0
            or session.calendar_api_call_count != 0
        ):
            raise TypeError
    except Exception as exc:
        code = (
            "production_rehearsal_scope_mismatch"
            if context.token_role == "production_write" and not context.scope_exact
            else "production_rehearsal_token_role_mismatch"
        )
        raise ProductionWriteTokenRehearsalError(
            code,
            "Production write-token rehearsal credential binding is invalid",
        ) from exc
    return context


def _verify_manifest_source(
    manifest: AcceptedProductionSourceManifest,
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
) -> None:
    try:
        verify_accepted_production_source_manifest(manifest)
        expected = build_accepted_production_source_manifest(
            profile,
            source,
            repository_identity=manifest.repository_identity,
        )
    except Exception as exc:
        raise ProductionWriteTokenRehearsalError(
            "production_rehearsal_manifest_source_invalid",
            "Accepted Production source binding is invalid",
        ) from exc
    if not hmac.compare_digest(expected.manifest_content_hash, manifest.manifest_content_hash):
        raise ProductionWriteTokenRehearsalError(
            "production_rehearsal_manifest_source_mismatch",
            "Accepted Production source does not match its manifest",
        )


def _verify_baseline_provenance(
    baseline: TrustedBaseline,
    target_fingerprint: str,
    manifest: AcceptedProductionSourceManifest,
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
) -> None:
    try:
        verify_baseline_content_hash(baseline)
    except Exception as exc:
        raise ProductionWriteTokenRehearsalError(
            "production_rehearsal_baseline_integrity_failed",
            "Trusted Production baseline integrity verification failed",
        ) from exc
    markers = (baseline.source_profile, baseline.accepted_tag, *baseline.managed_uids)
    if (
        baseline.state is not BaselineState.TRUSTED
        or baseline.target_fingerprint != target_fingerprint
        or baseline.managed_uid_count < 1
        or baseline.accepted_commit == "0" * 40
        or baseline.source_sha256 == "0" * 64
        or baseline.source_profile != manifest.profile_id
        or baseline.source_profile != profile.profile_id
        or baseline.source_profile != source.profile_id
        or baseline.accepted_tag != manifest.repository_tag
        or baseline.accepted_tag != profile.accepted_tag
        or baseline.accepted_commit != manifest.repository_commit
        or baseline.accepted_commit != profile.accepted_commit
        or baseline.source_sha256 != manifest.ics_sha256
        or baseline.source_sha256 != source.raw_sha256
        or baseline.source_event_count != manifest.event_count
        or baseline.source_event_count != source.vevent_count
        or baseline.managed_uid_count != source.vevent_count
        or baseline.managed_uids
        != tuple(sorted(event.uid for event in source.events if event.uid is not None))
        or any(
            marker.casefold() in value.casefold()
            for value in markers
            for marker in _NONPRODUCTION_MARKERS
        )
    ):
        raise ProductionWriteTokenRehearsalError(
            "production_rehearsal_baseline_invalid",
            "Trusted Production baseline policy verification failed",
        )


def _read_with_retry(context: _Context, method: str, call: object) -> object:
    if not callable(call):
        raise TypeError
    while True:
        context.consume_call(method)
        try:
            return call()
        except ProductionWriteTokenRehearsalTransportError as exc:
            if (
                not exc.retryable
                or context.read_retry_count >= PRODUCTION_REHEARSAL_READ_RETRY_MAXIMUM
            ):
                raise
            context.read_retry_count += 1


def _assemble_snapshot(pages: tuple[ProductionWriteTokenSnapshotPage, ...]) -> GoogleSnapshot:
    if not pages or not pages[-1].collection_complete:
        raise ProductionWriteTokenRehearsalError(
            "production_rehearsal_snapshot_incomplete",
            "Production rehearsal full snapshot is incomplete",
        )
    first = pages[0]
    if any(
        page.page_number != index
        or page.target_fingerprint != first.target_fingerprint
        or page.target_summary != first.target_summary
        or page.access_role != first.access_role
        or page.time_zone != first.time_zone
        or page.collection_metadata_hash != first.collection_metadata_hash
        or page.dropped_private_extended_property_count != 0
        or page.dropped_shared_extended_property_count != 0
        or page.forbidden_field_count != 0
        or (index < len(pages) and page.collection_complete)
        for index, page in enumerate(pages, start=1)
    ):
        raise ProductionWriteTokenRehearsalError(
            "production_rehearsal_snapshot_page_mismatch",
            "Production rehearsal pages do not form one complete collection",
        )
    events = tuple(event for page in pages for event in page.events)
    provisional = GoogleSnapshot(
        schema_version="1.0",
        snapshot_format="sanitized-google-calendar-v1",
        target_fingerprint=first.target_fingerprint,
        complete=True,
        event_count=len(events),
        events=events,
        content_hash="0" * 64,
        page_count=len(pages),
        collection_metadata_hash=first.collection_metadata_hash,
        cancelled_event_count=sum(event.status == "cancelled" for event in events),
        unknown_event_type_count=sum(event.event_type != "default" for event in events),
    )
    document = snapshot_document(provisional)
    del document["content_hash"]
    return parse_google_snapshot_bytes(
        json.dumps(document, ensure_ascii=False, sort_keys=True).encode("utf-8")
    )


def _collect_snapshot(
    context: _Context,
    transport: ProductionWriteTokenReadOnlyTransport,
    target: ProductionWriteTargetConfig,
) -> GoogleSnapshot:
    pages: list[ProductionWriteTokenSnapshotPage] = []
    page_token: str | None = None
    while True:
        page = _read_with_retry(
            context,
            "events.list",
            partial(
                transport.list_events,
                request=ProductionWriteTokenFullSnapshotRequest(page_token=page_token),
            ),
        )
        if not isinstance(page, ProductionWriteTokenSnapshotPage):
            raise ProductionWriteTokenRehearsalError(
                "production_rehearsal_snapshot_malformed",
                "Production rehearsal snapshot response is malformed",
            )
        if (
            page.target_fingerprint != target.expected_target_fingerprint
            or page.target_summary != target.expected_summary
            or page.access_role != target.expected_access_role
            or page.time_zone != target.expected_time_zone
            or page.time_zone != PRODUCTION_REHEARSAL_TIME_ZONE
        ):
            raise ProductionWriteTokenRehearsalError(
                "production_rehearsal_target_mismatch",
                "Production rehearsal target metadata did not match",
            )
        pages.append(page)
        if page.collection_complete:
            break
        if page.next_page_token is None:
            raise ProductionWriteTokenRehearsalError(
                "production_rehearsal_snapshot_incomplete",
                "Production rehearsal full snapshot is incomplete",
            )
        page_token = page.next_page_token
    context.target_metadata_verified = True
    context.page_count = len(pages)
    return _assemble_snapshot(tuple(pages))


def _verify_snapshot_shape(snapshot: GoogleSnapshot, baseline: TrustedBaseline) -> None:
    event_ids = tuple(event.event_id for event in snapshot.events)
    uids = tuple(event.ical_uid for event in snapshot.events)
    unsafe = any(
        event.ical_uid is None
        or not event.all_day
        or event.status != "confirmed"
        or event.event_type != "default"
        or event.recurrence
        or event.recurring_event_id is not None
        or event.color_id is not None
        or event.event_label_id is not None
        for event in snapshot.events
    )
    if (
        not snapshot.complete
        or snapshot.collection_metadata_hash is None
        or snapshot.event_count != len(snapshot.events)
        or len(event_ids) != len(set(event_ids))
        or any(uid is None for uid in uids)
        or len(uids) != len(set(uids))
        or unsafe
        or snapshot.cancelled_event_count != 0
        or snapshot.unknown_event_type_count != 0
        or snapshot.dropped_private_extended_property_count != 0
        or snapshot.dropped_shared_extended_property_count != 0
        or snapshot.forbidden_field_count != 0
        or baseline.snapshot_event_count != snapshot.event_count
        or baseline.managed_uid_count != snapshot.event_count
        or tuple(sorted(uid for uid in uids if uid is not None)) != baseline.managed_uids
    ):
        raise ProductionWriteTokenRehearsalError(
            "production_rehearsal_snapshot_invalid",
            "Production rehearsal full snapshot safety validation failed",
        )


def _record_diff(context: _Context, diff: CalendarDiff) -> None:
    counts = diff.counts
    context.source_unchanged_count = counts.unchanged
    context.source_add_count = counts.add
    context.source_update_count = counts.update
    context.source_delete_candidate_count = counts.delete_candidate
    context.source_unmanaged_count = counts.unmanaged_google_event
    context.source_duplicate_count = counts.duplicate_source_uid + counts.duplicate_google_icaluid
    context.source_ambiguous_count = counts.ambiguous
    context.source_invalid_count = counts.invalid_source
    context.source_fatal_count = counts.fatal_guard
    context.source_zero_diff = (
        diff.snapshot_complete
        and not diff.fatal
        and counts.unchanged == diff.source_event_count == diff.google_event_count
        and all(
            value == 0
            for value in (
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


def _select_event(snapshot: GoogleSnapshot, baseline: TrustedBaseline) -> CanonicalGoogleEvent:
    owned = frozenset(baseline.managed_uids)
    candidates = tuple(
        sorted(
            (event for event in snapshot.events if event.ical_uid in owned),
            key=lambda event: (
                event.safe_ical_uid_reference or "",
                event.safe_event_reference,
            ),
        )
    )
    if len(candidates) != baseline.managed_uid_count or not candidates:
        raise ProductionWriteTokenRehearsalError(
            "production_rehearsal_managed_identity_mismatch",
            "Production rehearsal managed event selection is invalid",
        )
    return candidates[0]


def _fresh_get_matches(expected: CanonicalGoogleEvent, fresh: CanonicalGoogleEvent) -> bool:
    return (
        fresh.event_id == expected.event_id
        and fresh.ical_uid == expected.ical_uid
        and fresh.summary == expected.summary
        and fresh.description == expected.description
        and fresh.start == expected.start
        and fresh.end == expected.end
        and fresh.all_day is True
        and fresh.status == "confirmed"
        and fresh.event_type == "default"
        and fresh.recurrence == ()
        and fresh.recurring_event_id is None
        and fresh.etag is not None
        and fresh.etag == expected.etag
        and fresh.color_id is None
        and fresh.event_label_id is None
    )


def _state_for_error(code: str) -> ProductionWriteTokenRehearsalResultState:
    if "scope" in code:
        return ProductionWriteTokenRehearsalResultState.SCOPE_MISMATCH
    if "token_role" in code or "generation" in code:
        return ProductionWriteTokenRehearsalResultState.TOKEN_ROLE_MISMATCH
    if "confirmation" in code or "target" in code:
        return ProductionWriteTokenRehearsalResultState.TARGET_MISMATCH
    if "call_limit" in code:
        return ProductionWriteTokenRehearsalResultState.API_CALL_LIMIT_EXCEEDED
    if "incomplete" in code or "page_mismatch" in code:
        return ProductionWriteTokenRehearsalResultState.INCOMPLETE_SNAPSHOT
    if "duplicate" in code or "snapshot_invalid" in code:
        return ProductionWriteTokenRehearsalResultState.DUPLICATE_IDENTITY
    if "full_snapshot_drift" in code or "baseline" in code:
        return ProductionWriteTokenRehearsalResultState.PRODUCTION_FULL_SNAPSHOT_DRIFT
    if "source_change" in code:
        return ProductionWriteTokenRehearsalResultState.PRODUCTION_SOURCE_CHANGE_DETECTED
    if "get" in code:
        return ProductionWriteTokenRehearsalResultState.GET_VERIFICATION_FAILED
    if "privacy" in code:
        return ProductionWriteTokenRehearsalResultState.PRIVACY_FAILURE
    if "transport" in code or "server_" in code or "rate_limit" in code:
        return ProductionWriteTokenRehearsalResultState.TRANSPORT_FAILED
    return ProductionWriteTokenRehearsalResultState.INPUT_BINDING_MISMATCH


def _finish(
    context: _Context,
    *,
    state: ProductionWriteTokenRehearsalResultState,
    safe_code: str | None,
    snapshot: ProductionWriteTokenRehearsalSnapshot | None = None,
) -> ProductionWriteTokenRehearsalOutcome:
    report = ProductionWriteTokenRehearsalReport(
        target_safe_ref=context.target_safe_ref,
        token_role=context.token_role,
        token_generation=context.token_generation,
        scope_count=context.scope_count,
        scope_exact=context.scope_exact,
        token_refresh_count=context.refresh_count,
        browser_launch_count=context.browser_launch_count,
        rehearsal_client_construction_count=context.rehearsal_client_construction_count,
        calendar_api_call_count=context.api_call_count,
        list_call_count=context.list_call_count,
        get_call_count=context.get_call_count,
        read_retry_count=context.read_retry_count,
        target_metadata_verified=context.target_metadata_verified,
        snapshot_complete=context.snapshot_complete,
        page_count=context.page_count,
        event_count=context.event_count,
        snapshot_content_hash=context.snapshot_content_hash,
        baseline_cross_binding=context.baseline_cross_binding,
        source_unchanged_count=context.source_unchanged_count,
        source_add_count=context.source_add_count,
        source_update_count=context.source_update_count,
        source_delete_candidate_count=context.source_delete_candidate_count,
        source_unmanaged_count=context.source_unmanaged_count,
        source_duplicate_count=context.source_duplicate_count,
        source_ambiguous_count=context.source_ambiguous_count,
        source_invalid_count=context.source_invalid_count,
        source_fatal_count=context.source_fatal_count,
        source_zero_diff=context.source_zero_diff,
        get_performed=context.get_performed,
        get_verified=context.get_verified,
        selected_safe_uid_ref=context.selected_safe_uid_ref,
        event_id_present_internally=context.event_id_present_internally,
        etag_present_internally=context.etag_present_internally,
        result_state=state,
        safe_code=safe_code,
        snapshot_evidence_hash=(snapshot.snapshot_evidence_hash if snapshot else None),
        report_content_hash="0" * 64,
    )
    return ProductionWriteTokenRehearsalOutcome(
        report=finalize_production_write_token_rehearsal_report(report),
        snapshot=snapshot,
    )


def _run_production_write_token_readonly_rehearsal_with_session_mock(
    *,
    credential_session: ProductionWriteCredentialSession,
    target: ProductionWriteTargetConfig,
    manifest: AcceptedProductionSourceManifest,
    accepted_profile: AcceptedSourceProfile,
    accepted_source: SourceCalendarInspection,
    trusted_baseline: TrustedBaseline,
    confirmation: str,
    transport: ProductionWriteTokenReadOnlyTransport,
    rehearsal_client_construction_count: int,
) -> ProductionWriteTokenRehearsalOutcome:
    """Exercise list/get semantics with injected synthetic inputs and no network."""

    target_fingerprint = validate_production_write_target_config(target)
    target_safe_ref = production_write_target_reference(target)
    context = _Context(
        target_safe_ref=target_safe_ref,
        token_role="production_write",
        token_generation=0,
        scope_count=0,
        scope_exact=False,
        refresh_count=0,
    )
    try:
        verify_production_write_token_rehearsal_confirmation(target, confirmation)
        context = _session_context(credential_session, target)
        context.rehearsal_client_construction_count = rehearsal_client_construction_count
        require_phase6d0_rehearsal_transport(transport)
        _verify_manifest_source(manifest, accepted_profile, accepted_source)
        _verify_baseline_provenance(
            trusted_baseline,
            target_fingerprint,
            manifest,
            accepted_profile,
            accepted_source,
        )
    except Exception as exc:
        code = getattr(exc, "code", "production_rehearsal_input_binding_mismatch")
        return _finish(context, state=_state_for_error(code), safe_code=code)

    try:
        snapshot = _collect_snapshot(context, transport, target)
        context.snapshot_complete = snapshot.complete
        context.event_count = snapshot.event_count
        context.snapshot_content_hash = snapshot.content_hash
        _verify_snapshot_shape(snapshot, trusted_baseline)
        if not hmac.compare_digest(
            trusted_baseline.snapshot_content_hash,
            snapshot.content_hash,
        ):
            raise ProductionWriteTokenRehearsalError(
                "production_full_snapshot_drift",
                "Production full snapshot drifted from the Trusted Baseline",
            )
        context.baseline_cross_binding = True
        diff = diff_source_to_snapshot(
            accepted_source,
            snapshot,
            ManagedScope(
                trusted_source_uids=frozenset(
                    event.uid for event in accepted_source.events if event.uid is not None
                ),
                trusted_baseline_uids=frozenset(trusted_baseline.managed_uids),
            ),
        )
        _record_diff(context, diff)
        if not hmac.compare_digest(trusted_baseline.diff_content_hash, diff.content_hash):
            raise ProductionWriteTokenRehearsalError(
                "production_rehearsal_baseline_diff_mismatch",
                "Trusted Production baseline diff binding did not match",
            )
        if not context.source_zero_diff:
            raise ProductionWriteTokenRehearsalError(
                "production_source_change_detected",
                "Accepted Production source is not zero-difference",
            )
        selected = _select_event(snapshot, trusted_baseline)
        context.selected_safe_uid_ref = selected.safe_ical_uid_reference
        context.event_id_present_internally = bool(selected.event_id)
        fresh = _read_with_retry(
            context,
            "events.get",
            partial(
                transport.get_event,
                event_id=selected.event_id,
                token_role="production_write",
            ),
        )
        if not isinstance(fresh, CanonicalGoogleEvent) or not _fresh_get_matches(selected, fresh):
            raise ProductionWriteTokenRehearsalError(
                "production_rehearsal_get_verification_failed",
                "Production rehearsal fresh event verification failed",
            )
        context.etag_present_internally = fresh.etag is not None
        context.get_verified = True
    except Exception as exc:
        code = getattr(exc, "code", "production_rehearsal_transport_failed")
        return _finish(context, state=_state_for_error(code), safe_code=code)

    evidence = finalize_production_write_token_rehearsal_snapshot(
        ProductionWriteTokenRehearsalSnapshot(
            target_safe_ref=context.target_safe_ref,
            page_count=context.page_count,
            event_count=context.event_count,
            snapshot_content_hash=snapshot.content_hash,
            managed_event_count=trusted_baseline.managed_uid_count,
            unchanged_count=context.source_unchanged_count,
            events=tuple(
                sorted(
                    (
                        build_production_write_token_rehearsal_event_evidence(event)
                        for event in snapshot.events
                    ),
                    key=lambda event: (event.safe_uid_ref, event.safe_event_ref),
                )
            ),
            snapshot_evidence_hash="0" * 64,
        )
    )
    return _finish(
        context,
        state=ProductionWriteTokenRehearsalResultState.READY,
        safe_code=None,
        snapshot=evidence,
    )


def run_production_write_token_readonly_rehearsal_mock(
    *,
    credential_session_provider: ProductionWriteCredentialSessionProvider,
    transport_provider: ProductionWriteTokenReadOnlyTransportProvider,
    target: ProductionWriteTargetConfig,
    manifest: AcceptedProductionSourceManifest,
    accepted_profile: AcceptedSourceProfile,
    accepted_source: SourceCalendarInspection,
    trusted_baseline: TrustedBaseline,
    confirmation: str,
) -> ProductionWriteTokenRehearsalOutcome:
    """Invoke credentials and fake client only after exact read confirmation."""

    validate_production_write_target_config(target)
    context = _Context(
        target_safe_ref=production_write_target_reference(target),
        token_role="production_write",
        token_generation=0,
        scope_count=0,
        scope_exact=False,
        refresh_count=0,
    )
    try:
        verify_production_write_token_rehearsal_confirmation(target, confirmation)
    except Exception as exc:
        code = getattr(exc, "code", "production_rehearsal_confirmation_mismatch")
        return _finish(context, state=_state_for_error(code), safe_code=code)
    try:
        require_phase6d0_rehearsal_providers(
            credential_session_provider,
            transport_provider,
        )
        session = credential_session_provider.load_session(target=target)
    except ProductionWriteTokenRefreshError as exc:
        context.refresh_count = credential_session_provider.refresh_attempt_count
        context.browser_launch_count = credential_session_provider.browser_launch_count
        return _finish(
            context,
            state=ProductionWriteTokenRehearsalResultState.TOKEN_REFRESH_FAILED,
            safe_code=exc.code,
        )
    except Exception as exc:
        code = getattr(exc, "code", "production_rehearsal_token_session_failed")
        return _finish(context, state=_state_for_error(code), safe_code=code)
    try:
        validated_context = _session_context(session, target)
        transport = transport_provider.build_transport(session=session, target=target)
        validated_context.rehearsal_client_construction_count = 1
    except Exception as exc:
        code = getattr(exc, "code", "production_rehearsal_transport_provider_failed")
        return _finish(context, state=_state_for_error(code), safe_code=code)
    return _run_production_write_token_readonly_rehearsal_with_session_mock(
        credential_session=session,
        target=target,
        manifest=manifest,
        accepted_profile=accepted_profile,
        accepted_source=accepted_source,
        trusted_baseline=trusted_baseline,
        confirmation=confirmation,
        transport=transport,
        rehearsal_client_construction_count=validated_context.rehearsal_client_construction_count,
    )


__all__ = [
    "ProductionWriteTokenRehearsalError",
    "ProductionWriteTokenRehearsalOutcome",
    "production_write_token_rehearsal_challenge",
    "run_production_write_token_readonly_rehearsal_mock",
    "verify_production_write_token_rehearsal_confirmation",
]
