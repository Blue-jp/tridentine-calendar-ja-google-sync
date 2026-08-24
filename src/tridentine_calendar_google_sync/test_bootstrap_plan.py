"""Eligibility, construction, and integrity for a Test-only bootstrap add plan."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.diff_models import (
    CalendarDiff,
    DiffClassification,
    ManagedScope,
)
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    CanonicalSourceEvent,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.provenance import canonical_content_hash, tool_version
from tridentine_calendar_google_sync.safe_refs import safe_uid_ref
from tridentine_calendar_google_sync.test_bootstrap_plan_models import (
    ALLOWED_BOOTSTRAP_ORIGINAL_GUARDS,
    PRODUCTION_ACCEPTED_TAG,
    PRODUCTION_SOURCE_PROFILE_ID,
    TestBootstrapAddPlan,
    TestBootstrapEligibility,
)
from tridentine_calendar_google_sync.test_calendar_prewrite import (
    verify_test_calendar_prewrite_snapshot,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_models import (
    TestCalendarPrewriteSnapshot,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetConfig,
    test_write_target_reference,
    validate_test_write_target_config,
)

_PLAN_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-bootstrap-add-plan:v1\x00"
_PROFILE_MARKERS = ("test", "synthetic")
_PROJECT_MARKERS = ("test", "synthetic", "テスト", "架空")


class TestBootstrapPlanError(ValueError):
    """Content-free bootstrap eligibility, integrity, or policy failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _guard(condition: bool, code: str, message: str) -> None:
    if not condition:
        raise TestBootstrapPlanError(code, message)


def _hash_mapping(domain: bytes, value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def private_test_bootstrap_add_plan_data(plan: TestBootstrapAddPlan) -> dict[str, object]:
    """Return the canonical private plan document; it contains no raw event content."""

    return {
        "schema_version": plan.schema_version,
        "plan_type": plan.plan_type,
        "test_only": plan.test_only,
        "bootstrap_only": plan.bootstrap_only,
        "executable": plan.executable,
        "production_locked": plan.production_locked,
        "tool_version": plan.tool_version,
        "target_fingerprint": plan.target_fingerprint,
        "target_safe_ref": plan.target_safe_ref,
        "target_environment": plan.target_environment,
        "target_label": plan.target_label,
        "target_purpose": plan.target_purpose,
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
        "safe_uid_ref": plan.safe_uid_ref,
        "original_guard_codes": list(plan.original_guard_codes),
        "bootstrap_eligibility": plan.bootstrap_eligibility,
        "approval_required": plan.approval_required,
        "plan_content_hash": plan.plan_content_hash,
    }


def calculate_test_bootstrap_add_plan_hash(plan: TestBootstrapAddPlan) -> str:
    """Return the deterministic domain-separated bootstrap plan hash."""

    data = private_test_bootstrap_add_plan_data(plan)
    del data["plan_content_hash"]
    return _hash_mapping(_PLAN_HASH_DOMAIN, data)


def verify_test_bootstrap_add_plan(plan: TestBootstrapAddPlan) -> None:
    """Reject a non-Test, non-bootstrap, or tampered plan."""

    if not isinstance(plan, TestBootstrapAddPlan):
        raise TestBootstrapPlanError(
            "invalid_test_bootstrap_plan",
            "Test bootstrap add plan is invalid",
        )
    valid_sha = re.fullmatch(r"[0-9a-f]{64}", plan.target_fingerprint) is not None
    valid_hashes = all(
        re.fullmatch(r"[0-9a-f]{64}", value) is not None
        for value in (
            plan.source_sha256,
            plan.snapshot_hash,
            plan.diff_hash,
            plan.plan_content_hash,
        )
    )
    fixed_policy_valid = (
        plan.schema_version == "1.0"
        and plan.plan_type == "test_bootstrap_add"
        and plan.test_only is True
        and plan.bootstrap_only is True
        and plan.executable is False
        and plan.production_locked is True
        and isinstance(plan.tool_version, str)
        and bool(plan.tool_version)
        and valid_sha
        and valid_hashes
        and re.fullmatch(r"T-[0-9a-f]{12}", plan.target_safe_ref) is not None
        and plan.target_safe_ref == f"T-{plan.target_fingerprint[:12]}"
        and plan.target_safe_ref != PRODUCTION_TARGET_REFERENCE
        and plan.target_environment == "test"
        and plan.target_label == "test"
        and plan.target_purpose == "test_calendar_write_acceptance"
        and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", plan.source_profile) is not None
        and plan.source_profile != PRODUCTION_SOURCE_PROFILE_ID
        and plan.source_event_count == 1
        and plan.snapshot_event_count == 0
        and plan.operation_count == 1
        and plan.add_count == 1
        and plan.update_count == 0
        and plan.delete_count == 0
        and re.fullmatch(r"U-[0-9a-f]{12}", plan.safe_uid_ref) is not None
        and plan.original_guard_codes == ALLOWED_BOOTSTRAP_ORIGINAL_GUARDS
        and plan.bootstrap_eligibility == "eligible"
        and plan.approval_required is True
    )
    if not fixed_policy_valid:
        raise TestBootstrapPlanError(
            "test_bootstrap_plan_policy_mismatch",
            "Test bootstrap add plan policy verification failed",
        )
    if not hmac.compare_digest(
        calculate_test_bootstrap_add_plan_hash(plan),
        plan.plan_content_hash,
    ):
        raise TestBootstrapPlanError(
            "test_bootstrap_plan_hash_mismatch",
            "Test bootstrap add plan integrity verification failed",
        )


def _contains_marker(value: str, markers: tuple[str, ...]) -> bool:
    folded = value.casefold()
    return any(marker.casefold() in folded for marker in markers)


def _validate_synthetic_profile(profile: AcceptedSourceProfile) -> None:
    expected = profile.expected
    _guard(
        profile.profile_id != PRODUCTION_SOURCE_PROFILE_ID
        and profile.accepted_tag != PRODUCTION_ACCEPTED_TAG,
        "production_source_profile_forbidden",
        "Production Accepted source is forbidden for bootstrap planning",
    )
    _guard(
        _contains_marker(profile.profile_id, _PROFILE_MARKERS)
        and _contains_marker(profile.accepted_tag, _PROFILE_MARKERS)
        and _contains_marker(profile.project_name, _PROJECT_MARKERS),
        "synthetic_source_profile_marker_missing",
        "Bootstrap source profile is not explicitly synthetic",
    )
    _guard(
        expected.vcalendar_count == 1
        and expected.vevent_count == 1
        and expected.uid_total_count == 1
        and expected.uid_unique_count == 1
        and expected.uid_duplicate_count == 0
        and expected.all_day_count == 1
        and expected.timed_count == 0
        and expected.dtstart_date_count == 1
        and expected.summary_present_count == 1
        and expected.description_present_count == 1
        and expected.rrule_count == 0
        and expected.recurrence_id_count == 0,
        "synthetic_source_profile_counts_invalid",
        "Bootstrap source profile aggregate is invalid",
    )


def _validate_synthetic_source(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
) -> CanonicalSourceEvent:
    _validate_synthetic_profile(profile)
    _guard(
        source.profile_id == profile.profile_id
        and source.raw_sha256 == profile.html_sha256
        and source.source_sha_matches,
        "bootstrap_source_provenance_mismatch",
        "Bootstrap source provenance does not match its profile",
    )
    _guard(
        source.source_valid
        and not source.fatal
        and not source.findings
        and source.malformed_event_count == 0,
        "bootstrap_source_invalid",
        "Bootstrap source validation is not exactly clean",
    )
    _guard(
        source.vcalendar_count == 1
        and source.vevent_count == 1
        and len(source.events) == 1
        and source.uid_total_count == 1
        and source.uid_unique_count == 1
        and source.uid_duplicate_count == 0
        and source.all_day_count == 1
        and source.timed_count == 0
        and source.dtstart_date_count == 1
        and source.summary_present_count == 1
        and source.description_present_count == 1
        and source.rrule_count == 0
        and source.recurrence_id_count == 0,
        "bootstrap_source_count_invalid",
        "Bootstrap source must contain exactly one valid all-day event",
    )
    _guard(
        hmac.compare_digest(
            canonical_content_hash(
                vcalendar_count=source.vcalendar_count,
                events=source.events,
            ),
            source.content_hash,
        ),
        "bootstrap_source_content_hash_mismatch",
        "Bootstrap source integrity verification failed",
    )
    event = source.events[0]
    uid = event.uid
    _guard(
        uid is not None
        and event.safe_uid_reference is not None
        and event.safe_uid_reference == safe_uid_ref(uid),
        "bootstrap_source_uid_invalid",
        "Bootstrap source UID is invalid",
    )
    assert uid is not None
    uid_parts = uid.rsplit("@", 1)
    _guard(
        len(uid_parts) == 2 and bool(uid_parts[0]) and uid_parts[1].casefold().endswith(".invalid"),
        "bootstrap_source_uid_domain_forbidden",
        "Bootstrap source UID must use a reserved invalid domain",
    )
    _guard(
        event.summary is not None
        and ("同期テスト" in event.summary or "test" in event.summary.casefold()),
        "bootstrap_source_summary_marker_missing",
        "Bootstrap source SUMMARY lacks the synthetic Test marker",
    )
    _guard(
        event.description is not None
        and event.start_date is not None
        and event.effective_end_date is not None
        and event.effective_end_date > event.start_date
        and event.all_day
        and event.start_datetime is None
        and event.effective_end_datetime is None
        and not event.rrule_present
        and not event.recurrence_id_present,
        "bootstrap_source_event_shape_invalid",
        "Bootstrap source event shape is invalid",
    )
    return event


def _validate_empty_test_snapshot(
    prewrite_snapshot: TestCalendarPrewriteSnapshot,
    target: TestWriteTargetConfig,
) -> None:
    try:
        verify_test_calendar_prewrite_snapshot(prewrite_snapshot)
    except Exception as exc:
        raise TestBootstrapPlanError(
            "bootstrap_snapshot_integrity_failed",
            "Test prewrite snapshot integrity verification failed",
        ) from exc
    target_fingerprint = validate_test_write_target_config(target)
    target_ref = test_write_target_reference(target)
    snapshot = prewrite_snapshot.snapshot
    _guard(
        prewrite_snapshot.target_fingerprint == target_fingerprint
        and prewrite_snapshot.target_safe_ref == target_ref
        and snapshot.target_fingerprint == target_fingerprint,
        "bootstrap_snapshot_target_mismatch",
        "Test prewrite snapshot target does not match",
    )
    _guard(
        prewrite_snapshot.complete
        and snapshot.complete
        and snapshot.event_count == 0
        and not snapshot.events
        and snapshot.collection_metadata_hash is not None
        and snapshot.cancelled_event_count == 0
        and snapshot.unknown_event_type_count == 0
        and snapshot.dropped_private_extended_property_count == 0
        and snapshot.dropped_shared_extended_property_count == 0
        and snapshot.forbidden_field_count == 0,
        "bootstrap_snapshot_not_empty_or_safe",
        "Bootstrap requires an exactly empty complete Test snapshot",
    )


def _validate_bootstrap_diff(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    prewrite_snapshot: TestCalendarPrewriteSnapshot,
    diff: CalendarDiff,
    event: CanonicalSourceEvent,
) -> None:
    snapshot = prewrite_snapshot.snapshot
    counts = diff.counts
    _guard(
        diff.source_profile_id == profile.profile_id
        and diff.source_sha256 == source.raw_sha256
        and diff.source_sha_matches
        and diff.snapshot_sha256 == snapshot.content_hash
        and diff.target_fingerprint == snapshot.target_fingerprint
        and diff.snapshot_complete,
        "bootstrap_diff_provenance_mismatch",
        "Bootstrap diff provenance does not match",
    )
    _guard(
        diff.source_event_count == 1
        and diff.google_event_count == 0
        and counts.unchanged == 0
        and counts.add == 1
        and counts.update == 0
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
        "bootstrap_diff_classification_invalid",
        "Bootstrap diff must contain exactly one add and no other classification",
    )
    event_diff = diff.events[0]
    _guard(
        event_diff.classification is DiffClassification.ADD
        and event_diff.source_ref == event.safe_uid_reference
        and not event_diff.google_refs,
        "bootstrap_diff_event_identity_invalid",
        "Bootstrap diff event identity is invalid",
    )


def _derive_original_guard_codes(diff: CalendarDiff) -> tuple[str, ...]:
    codes: list[str] = []
    if diff.google_event_count == 0:
        codes.append("zero_google_event_count")
    if diff.source_event_count > 0 and diff.counts.add == diff.source_event_count:
        codes.append("all_events_add")
    changed_count = diff.counts.add + diff.counts.update + diff.counts.delete_candidate
    if changed_count > 50 or (
        diff.source_event_count > 0 and changed_count * 100 > diff.source_event_count
    ):
        codes.append("mass_change_guard")
    return tuple(codes)


def validate_test_bootstrap_eligibility(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    prewrite_snapshot: TestCalendarPrewriteSnapshot,
    target: TestWriteTargetConfig,
    diff: CalendarDiff,
    *,
    original_guard_codes: tuple[str, ...] | None = None,
) -> TestBootstrapEligibility:
    """Return safe eligibility evidence only for the singular bootstrap case."""

    _validate_empty_test_snapshot(prewrite_snapshot, target)
    event = _validate_synthetic_source(profile, source)
    _validate_bootstrap_diff(profile, source, prewrite_snapshot, diff, event)
    derived_guards = _derive_original_guard_codes(diff)
    supplied_guards = derived_guards if original_guard_codes is None else original_guard_codes
    _guard(
        derived_guards == ALLOWED_BOOTSTRAP_ORIGINAL_GUARDS and supplied_guards == derived_guards,
        "bootstrap_original_guard_codes_forbidden",
        "Bootstrap original guard codes are not exactly allowlisted",
    )
    assert event.safe_uid_reference is not None
    return TestBootstrapEligibility(
        target_fingerprint=prewrite_snapshot.target_fingerprint,
        target_safe_ref=prewrite_snapshot.target_safe_ref,
        safe_uid_ref=event.safe_uid_reference,
        diff_hash=diff.content_hash,
        original_guard_codes=derived_guards,
    )


def build_test_bootstrap_add_plan(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    prewrite_snapshot: TestCalendarPrewriteSnapshot,
    target: TestWriteTargetConfig,
    *,
    diff: CalendarDiff | None = None,
) -> TestBootstrapAddPlan:
    """Build one non-executable plan without a baseline or normal plan mutation."""

    expected_diff = diff_source_to_snapshot(
        source,
        prewrite_snapshot.snapshot,
        ManagedScope(),
    )
    if diff is not None and not hmac.compare_digest(diff.content_hash, expected_diff.content_hash):
        raise TestBootstrapPlanError(
            "bootstrap_diff_mismatch",
            "Provided diff does not match bootstrap inputs",
        )
    resolved_diff = expected_diff if diff is None else diff
    eligibility = validate_test_bootstrap_eligibility(
        profile,
        source,
        prewrite_snapshot,
        target,
        resolved_diff,
    )
    provisional = TestBootstrapAddPlan(
        tool_version=tool_version(),
        target_fingerprint=eligibility.target_fingerprint,
        target_safe_ref=eligibility.target_safe_ref,
        source_profile=profile.profile_id,
        source_sha256=source.raw_sha256,
        snapshot_hash=prewrite_snapshot.snapshot_content_hash,
        diff_hash=eligibility.diff_hash,
        safe_uid_ref=eligibility.safe_uid_ref,
        original_guard_codes=eligibility.original_guard_codes,
        plan_content_hash="0" * 64,
    )
    plan = provisional.model_copy(
        update={"plan_content_hash": calculate_test_bootstrap_add_plan_hash(provisional)}
    )
    verify_test_bootstrap_add_plan(plan)
    return plan


__all__ = [
    "TestBootstrapPlanError",
    "build_test_bootstrap_add_plan",
    "calculate_test_bootstrap_add_plan_hash",
    "private_test_bootstrap_add_plan_data",
    "validate_test_bootstrap_eligibility",
    "verify_test_bootstrap_add_plan",
]
