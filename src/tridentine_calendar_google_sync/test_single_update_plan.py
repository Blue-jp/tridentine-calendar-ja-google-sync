"""Eligibility and integrity for one Test-only Description update plan."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.baseline_engine import (
    BaselineError,
    calculate_baseline_content_hash,
    verify_baseline_content_hash,
)
from tridentine_calendar_google_sync.baseline_models import BaselineState, TrustedBaseline
from tridentine_calendar_google_sync.diff_models import (
    CalendarDiff,
    DiffClassification,
)
from tridentine_calendar_google_sync.google_models import CanonicalGoogleEvent
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    CanonicalSourceEvent,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.plan_engine import PlanError, diff_with_trusted_baseline
from tridentine_calendar_google_sync.provenance import canonical_content_hash, tool_version
from tridentine_calendar_google_sync.safe_refs import safe_uid_ref
from tridentine_calendar_google_sync.test_calendar_prewrite import (
    verify_test_calendar_prewrite_snapshot,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_models import (
    TestCalendarPrewriteSnapshot,
)
from tridentine_calendar_google_sync.test_single_update_plan_models import (
    ALLOWED_SINGLE_UPDATE_ORIGINAL_GUARDS,
    PRODUCTION_ACCEPTED_TAG,
    PRODUCTION_SOURCE_PROFILE_ID,
    SINGLE_UPDATE_CHANGED_FIELDS,
    TestSingleUpdateEligibility,
    TestSingleUpdatePlan,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetConfig,
    test_write_target_reference,
    validate_test_write_target_config,
)

_PLAN_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-single-update-plan:v1\x00"
_PROFILE_MARKERS = ("test", "synthetic")
_PROJECT_MARKERS = ("test", "synthetic", "テスト", "架空")


class TestSingleUpdatePlanError(ValueError):
    """Content-free Single Update eligibility, integrity, or policy failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _guard(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise TestSingleUpdatePlanError(code, message)


def _hash_mapping(domain: bytes, value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def private_test_single_update_plan_data(plan: TestSingleUpdatePlan) -> dict[str, object]:
    """Return canonical private Plan data without raw event identity or content."""

    return {
        "schema_version": plan.schema_version,
        "plan_type": plan.plan_type,
        "test_only": plan.test_only,
        "single_update_only": plan.single_update_only,
        "production_locked": plan.production_locked,
        "executable": plan.executable,
        "tool_version": plan.tool_version,
        "target_fingerprint": plan.target_fingerprint,
        "target_safe_ref": plan.target_safe_ref,
        "target_environment": plan.target_environment,
        "target_label": plan.target_label,
        "target_purpose": plan.target_purpose,
        "baseline_hash": plan.baseline_hash,
        "baseline_snapshot_hash": plan.baseline_snapshot_hash,
        "baseline_state": plan.baseline_state,
        "managed_uid_count": plan.managed_uid_count,
        "source_profile": plan.source_profile,
        "source_sha256": plan.source_sha256,
        "source_event_count": plan.source_event_count,
        "snapshot_hash": plan.snapshot_hash,
        "snapshot_event_count": plan.snapshot_event_count,
        "diff_hash": plan.diff_hash,
        "operation_count": plan.operation_count,
        "add_count": plan.add_count,
        "update_count": plan.update_count,
        "delete_count": plan.delete_count,
        "changed_fields": list(plan.changed_fields),
        "safe_uid_ref": plan.safe_uid_ref,
        "original_guard_codes": list(plan.original_guard_codes),
        "eligibility": plan.eligibility,
        "approval_required": plan.approval_required,
        "plan_content_hash": plan.plan_content_hash,
    }


def calculate_test_single_update_plan_hash(plan: TestSingleUpdatePlan) -> str:
    """Return the deterministic domain-separated Single Update Plan hash."""

    data = private_test_single_update_plan_data(plan)
    del data["plan_content_hash"]
    return _hash_mapping(_PLAN_HASH_DOMAIN, data)


def verify_test_single_update_plan(plan: TestSingleUpdatePlan) -> None:
    """Revalidate fixed semantics before accepting the integrity hash."""

    if not isinstance(plan, TestSingleUpdatePlan):
        raise TestSingleUpdatePlanError(
            "invalid_test_single_update_plan",
            "Test Single Update Plan is invalid",
        )
    sha_values = (
        plan.target_fingerprint,
        plan.baseline_hash,
        plan.baseline_snapshot_hash,
        plan.source_sha256,
        plan.snapshot_hash,
        plan.diff_hash,
        plan.plan_content_hash,
    )
    fixed_policy_valid = (
        plan.schema_version == "1.0"
        and plan.plan_type == "test_single_update"
        and plan.test_only is True
        and plan.single_update_only is True
        and plan.production_locked is True
        and plan.executable is False
        and isinstance(plan.tool_version, str)
        and bool(plan.tool_version)
        and all(re.fullmatch(r"[0-9a-f]{64}", value) is not None for value in sha_values)
        and re.fullmatch(r"T-[0-9a-f]{12}", plan.target_safe_ref) is not None
        and plan.target_safe_ref == f"T-{plan.target_fingerprint[:12]}"
        and plan.target_safe_ref != PRODUCTION_TARGET_REFERENCE
        and plan.target_environment == "test"
        and plan.target_label == "test"
        and plan.target_purpose == "test_calendar_write_acceptance"
        and plan.baseline_snapshot_hash == plan.snapshot_hash
        and plan.baseline_state == "trusted"
        and plan.managed_uid_count == 1
        and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", plan.source_profile) is not None
        and plan.source_profile != PRODUCTION_SOURCE_PROFILE_ID
        and plan.source_event_count == 1
        and plan.snapshot_event_count == 1
        and plan.operation_count == 1
        and plan.add_count == 0
        and plan.update_count == 1
        and plan.delete_count == 0
        and plan.changed_fields == SINGLE_UPDATE_CHANGED_FIELDS
        and re.fullmatch(r"U-[0-9a-f]{12}", plan.safe_uid_ref) is not None
        and plan.original_guard_codes == ALLOWED_SINGLE_UPDATE_ORIGINAL_GUARDS
        and plan.eligibility == "eligible"
        and plan.approval_required is True
    )
    if not fixed_policy_valid:
        raise TestSingleUpdatePlanError(
            "test_single_update_plan_policy_mismatch",
            "Test Single Update Plan policy verification failed",
        )
    if not hmac.compare_digest(
        calculate_test_single_update_plan_hash(plan),
        plan.plan_content_hash,
    ):
        raise TestSingleUpdatePlanError(
            "test_single_update_plan_hash_mismatch",
            "Test Single Update Plan integrity verification failed",
        )


def _contains_marker(value: str, markers: tuple[str, ...]) -> bool:
    folded = value.casefold()
    return any(marker.casefold() in folded for marker in markers)


def _validate_profile_and_source(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
) -> CanonicalSourceEvent:
    expected = profile.expected
    _guard(
        profile.profile_id != PRODUCTION_SOURCE_PROFILE_ID
        and profile.accepted_tag != PRODUCTION_ACCEPTED_TAG,
        "single_update_production_source_forbidden",
        "Production Accepted source is forbidden for Single Update planning",
    )
    _guard(
        _contains_marker(profile.profile_id, _PROFILE_MARKERS)
        and _contains_marker(profile.accepted_tag, _PROFILE_MARKERS)
        and _contains_marker(profile.project_name, _PROJECT_MARKERS),
        "single_update_source_profile_marker_missing",
        "Single Update source profile is not explicitly synthetic",
    )
    _guard(
        expected.vcalendar_count == 1
        and expected.vevent_count == 1
        and expected.uid_total_count == 1
        and expected.uid_unique_count == 1
        and expected.uid_duplicate_count == 0
        and expected.all_day_count == 1
        and expected.timed_count == 0
        and expected.summary_present_count == 1
        and expected.description_present_count == 1
        and expected.rrule_count == 0
        and expected.recurrence_id_count == 0,
        "single_update_source_profile_counts_invalid",
        "Single Update source profile aggregate is invalid",
    )
    _guard(
        source.profile_id == profile.profile_id
        and source.raw_sha256 == profile.html_sha256
        and source.source_sha_matches,
        "single_update_source_provenance_mismatch",
        "Single Update source provenance does not match its profile",
    )
    _guard(
        source.source_valid
        and not source.fatal
        and not source.findings
        and source.malformed_event_count == 0
        and source.vcalendar_count == 1
        and source.vevent_count == 1
        and len(source.events) == 1
        and source.uid_total_count == 1
        and source.uid_unique_count == 1
        and source.uid_duplicate_count == 0
        and source.all_day_count == 1
        and source.timed_count == 0
        and source.summary_present_count == 1
        and source.description_present_count == 1
        and source.rrule_count == 0
        and source.recurrence_id_count == 0,
        "single_update_source_invalid",
        "Single Update source must contain exactly one valid all-day event",
    )
    _guard(
        hmac.compare_digest(
            canonical_content_hash(
                vcalendar_count=source.vcalendar_count,
                events=source.events,
            ),
            source.content_hash,
        ),
        "single_update_source_hash_mismatch",
        "Single Update source integrity verification failed",
    )
    event = source.events[0]
    uid = event.uid
    _guard(
        uid is not None
        and event.safe_uid_reference is not None
        and event.safe_uid_reference == safe_uid_ref(uid),
        "single_update_source_uid_invalid",
        "Single Update source UID is invalid",
    )
    assert uid is not None
    parts = uid.rsplit("@", 1)
    _guard(
        len(parts) == 2 and bool(parts[0]) and parts[1].casefold().endswith(".invalid"),
        "single_update_source_uid_domain_forbidden",
        "Single Update source UID must use a reserved invalid domain",
    )
    _guard(
        event.summary is not None
        and ("同期テスト" in event.summary or "test" in event.summary.casefold())
        and event.description is not None
        and event.start_date is not None
        and event.effective_end_date is not None
        and event.effective_end_date > event.start_date
        and event.all_day
        and event.start_datetime is None
        and event.effective_end_datetime is None
        and not event.rrule_present
        and not event.recurrence_id_present,
        "single_update_source_event_shape_invalid",
        "Single Update source event shape is invalid",
    )
    return event


def _validate_baseline(
    baseline: TrustedBaseline,
    source: SourceCalendarInspection,
    snapshot: TestCalendarPrewriteSnapshot,
    target_fingerprint: str,
) -> None:
    _guard(
        isinstance(baseline, TrustedBaseline) and baseline.state is BaselineState.TRUSTED,
        "single_update_trusted_baseline_required",
        "Single Update requires a trusted Test baseline",
    )
    try:
        verify_baseline_content_hash(baseline)
    except Exception as exc:
        raise TestSingleUpdatePlanError(
            "single_update_baseline_integrity_failed",
            "Trusted Test baseline integrity verification failed",
        ) from exc
    _guard(
        hmac.compare_digest(
            baseline.baseline_content_hash,
            calculate_baseline_content_hash(baseline),
        )
        and baseline.target_fingerprint == target_fingerprint
        and baseline.source_profile == source.profile_id
        and baseline.source_event_count == 1
        and baseline.snapshot_event_count == 1
        and baseline.managed_uid_count == 1
        and len(baseline.managed_uids) == 1
        and source.events[0].uid in baseline.managed_uids,
        "single_update_baseline_binding_invalid",
        "Trusted Test baseline does not bind the Single Update inputs",
    )
    _guard(
        baseline.snapshot_content_hash == snapshot.snapshot_content_hash,
        "trusted_baseline_snapshot_mismatch",
        "Trusted baseline snapshot does not match the current Test snapshot",
    )


def _matching_google_event(
    source_event: CanonicalSourceEvent,
    snapshot: TestCalendarPrewriteSnapshot,
) -> CanonicalGoogleEvent:
    nested = snapshot.snapshot
    _guard(
        nested.complete
        and nested.event_count == 1
        and len(nested.events) == 1
        and nested.cancelled_event_count == 0
        and nested.unknown_event_type_count == 0
        and nested.dropped_private_extended_property_count == 0
        and nested.dropped_shared_extended_property_count == 0
        and nested.forbidden_field_count == 0,
        "single_update_snapshot_count_invalid",
        "Single Update requires one complete safe Test snapshot event",
    )
    matches = [event for event in nested.events if event.ical_uid == source_event.uid]
    _guard(
        len(matches) == 1,
        "single_update_google_identity_ambiguous",
        "Single Update Google identity did not match exactly once",
    )
    event = matches[0]
    _guard(
        event.ical_uid is not None
        and bool(event.event_id)
        and bool(event.etag)
        and event.status != "cancelled"
        and event.event_type == "default"
        and event.all_day is True
        and event.start is not None
        and event.end is not None
        and event.start.date is not None
        and event.end.date is not None
        and event.end.date > event.start.date
        and event.end_time_unspecified is False
        and not event.recurrence
        and event.recurring_event_id is None
        and event.original_start_time is None
        and event.color_id is None
        and event.event_label_id is None
        and event.locked is False
        and event.private_copy is False,
        "single_update_google_event_shape_invalid",
        "Single Update Google event is incompatible",
    )
    return event


def _validate_description_only_change(
    source_event: CanonicalSourceEvent,
    google_event: CanonicalGoogleEvent,
) -> None:
    _guard(
        google_event.start is not None and google_event.end is not None,
        "single_update_google_event_boundaries_missing",
        "Single Update Google event boundaries are missing",
    )
    assert google_event.start is not None and google_event.end is not None
    _guard(
        source_event.uid == google_event.ical_uid
        and source_event.summary == google_event.summary
        and source_event.description is not None
        and google_event.description is not None
        and source_event.description != google_event.description
        and source_event.start_date == google_event.start.date
        and source_event.effective_end_date == google_event.end.date
        and source_event.all_day is google_event.all_day
        and google_event.event_type == "default",
        "single_update_changed_fields_invalid",
        "Single Update must change Description only",
    )


def _validate_diff(diff: CalendarDiff, safe_source_ref: str) -> None:
    counts = diff.counts
    _guard(
        diff.source_event_count == 1
        and diff.google_event_count == 1
        and diff.snapshot_complete
        and counts.unchanged == 0
        and counts.add == 0
        and counts.update == 1
        and counts.delete_candidate == 0
        and counts.duplicate_source_uid == 0
        and counts.duplicate_google_icaluid == 0
        and counts.ambiguous == 0
        and counts.unmanaged_google_event == 0
        and counts.invalid_source == 0
        and counts.fatal_guard == 0
        and not diff.fatal
        and not diff.warnings
        and len(diff.events) == 1,
        "single_update_diff_classification_invalid",
        "Single Update diff must contain exactly one update",
    )
    event = diff.events[0]
    _guard(
        event.classification is DiffClassification.UPDATE
        and event.source_ref == safe_source_ref
        and len(event.google_refs) == 1
        and tuple(difference.field for difference in event.differences)
        == SINGLE_UPDATE_CHANGED_FIELDS
        and not event.ownership_evidence,
        "single_update_diff_fields_invalid",
        "Single Update diff must contain one owned Description change",
    )


def _derive_original_guard_codes(diff: CalendarDiff) -> tuple[str, ...]:
    codes: list[str] = []
    if diff.source_event_count > 0 and diff.counts.update == diff.source_event_count:
        codes.append("all_events_update")
    changed_count = diff.counts.add + diff.counts.update + diff.counts.delete_candidate
    if changed_count > 50 or (
        diff.source_event_count > 0 and changed_count * 100 > diff.source_event_count
    ):
        codes.append("mass_change_guard")
    return tuple(codes)


def validate_test_single_update_eligibility(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    current_snapshot: TestCalendarPrewriteSnapshot,
    trusted_baseline: TrustedBaseline,
    target: TestWriteTargetConfig,
    diff: CalendarDiff,
) -> TestSingleUpdateEligibility:
    """Return eligibility evidence for exactly one owned Description update."""

    try:
        verify_test_calendar_prewrite_snapshot(current_snapshot)
    except Exception as exc:
        raise TestSingleUpdatePlanError(
            "single_update_snapshot_integrity_failed",
            "Current Test snapshot integrity verification failed",
        ) from exc
    target_fingerprint = validate_test_write_target_config(target)
    target_ref = test_write_target_reference(target)
    _guard(
        current_snapshot.target_fingerprint == target_fingerprint
        and current_snapshot.target_safe_ref == target_ref
        and current_snapshot.snapshot.target_fingerprint == target_fingerprint,
        "single_update_snapshot_target_mismatch",
        "Current Test snapshot target does not match",
    )
    source_event = _validate_profile_and_source(profile, source)
    _validate_baseline(trusted_baseline, source, current_snapshot, target_fingerprint)
    google_event = _matching_google_event(source_event, current_snapshot)
    _validate_description_only_change(source_event, google_event)
    _validate_diff(diff, source_event.safe_uid_reference or "")
    guards = _derive_original_guard_codes(diff)
    _guard(
        guards == ALLOWED_SINGLE_UPDATE_ORIGINAL_GUARDS,
        "single_update_original_guards_forbidden",
        "Single Update original guard codes are not exactly allowlisted",
    )
    assert source_event.safe_uid_reference is not None
    return TestSingleUpdateEligibility(
        target_fingerprint=target_fingerprint,
        target_safe_ref=target_ref,
        safe_uid_ref=source_event.safe_uid_reference,
        baseline_hash=trusted_baseline.baseline_content_hash,
        source_sha256=source.raw_sha256,
        snapshot_hash=current_snapshot.snapshot_content_hash,
        diff_hash=diff.content_hash,
        original_guard_codes=guards,
    )


def build_test_single_update_plan(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    current_snapshot: TestCalendarPrewriteSnapshot,
    trusted_baseline: TrustedBaseline,
    target: TestWriteTargetConfig,
    *,
    diff: CalendarDiff | None = None,
) -> TestSingleUpdatePlan:
    """Build one non-executable Plan without calling the normal planner."""

    try:
        expected_diff = diff_with_trusted_baseline(
            source,
            current_snapshot.snapshot,
            trusted_baseline,
        )
    except (BaselineError, PlanError) as exc:
        raise TestSingleUpdatePlanError(
            "single_update_baseline_diff_failed",
            "Trusted Test baseline could not produce the canonical Single Update diff",
        ) from exc
    if diff is not None and not hmac.compare_digest(diff.content_hash, expected_diff.content_hash):
        raise TestSingleUpdatePlanError(
            "single_update_diff_mismatch",
            "Provided diff does not match Single Update inputs",
        )
    resolved_diff = expected_diff if diff is None else diff
    eligibility = validate_test_single_update_eligibility(
        profile,
        source,
        current_snapshot,
        trusted_baseline,
        target,
        resolved_diff,
    )
    provisional = TestSingleUpdatePlan(
        tool_version=tool_version(),
        target_fingerprint=eligibility.target_fingerprint,
        target_safe_ref=eligibility.target_safe_ref,
        baseline_hash=eligibility.baseline_hash,
        baseline_snapshot_hash=trusted_baseline.snapshot_content_hash,
        source_profile=profile.profile_id,
        source_sha256=eligibility.source_sha256,
        snapshot_hash=eligibility.snapshot_hash,
        diff_hash=eligibility.diff_hash,
        safe_uid_ref=eligibility.safe_uid_ref,
        original_guard_codes=eligibility.original_guard_codes,
        plan_content_hash="0" * 64,
    )
    plan = provisional.model_copy(
        update={"plan_content_hash": calculate_test_single_update_plan_hash(provisional)}
    )
    verify_test_single_update_plan(plan)
    return plan


__all__ = [
    "TestSingleUpdatePlanError",
    "build_test_single_update_plan",
    "calculate_test_single_update_plan_hash",
    "private_test_single_update_plan_data",
    "validate_test_single_update_eligibility",
    "verify_test_single_update_plan",
]
