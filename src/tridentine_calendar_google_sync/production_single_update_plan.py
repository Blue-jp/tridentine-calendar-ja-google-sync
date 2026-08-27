"""Offline eligibility and integrity for one Production Description update."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from datetime import date, datetime

from tridentine_calendar_google_sync.accepted_production_source_manifest import (
    AcceptedProductionSourceManifestError,
    build_accepted_production_source_manifest,
    verify_accepted_production_source_manifest,
)
from tridentine_calendar_google_sync.accepted_production_source_manifest_models import (
    AcceptedProductionSourceManifest,
)
from tridentine_calendar_google_sync.baseline_engine import (
    BaselineError,
    calculate_baseline_content_hash,
    verify_baseline_content_hash,
)
from tridentine_calendar_google_sync.baseline_models import BaselineState, TrustedBaseline
from tridentine_calendar_google_sync.diff_models import CalendarDiff, DiffClassification
from tridentine_calendar_google_sync.google_models import CanonicalGoogleEvent, GoogleSnapshot
from tridentine_calendar_google_sync.google_sanitize import render_sanitized_snapshot
from tridentine_calendar_google_sync.google_snapshot import (
    GoogleSnapshotError,
    parse_google_snapshot_bytes,
)
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    CanonicalSourceEvent,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.plan_engine import PlanError, diff_with_trusted_baseline
from tridentine_calendar_google_sync.production_single_update_plan_models import (
    PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS,
    ProductionSingleUpdateEligibility,
    ProductionSingleUpdatePlan,
)
from tridentine_calendar_google_sync.production_write_target import (
    PRODUCTION_WRITE_TARGET_PURPOSE,
    ProductionWriteTargetConfig,
    calculate_production_write_target_hash,
    production_write_target_reference,
    validate_production_write_target_config,
)
from tridentine_calendar_google_sync.provenance import tool_version

_PLAN_HASH_DOMAIN = b"tridentine-calendar-google-sync:production-single-update-plan:v1\x00"
_PRE_IMAGE_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:production-single-update-pre-image:v1\x00"
)
_PATCH_HASH_DOMAIN = b"tridentine-calendar-google-sync:production-single-update-patch:v1\x00"
_NONPRODUCTION_CONTENT_MARKERS = ("test", "synthetic", "テスト", "架空")
_NONPRODUCTION_BASELINE_MARKERS = (*_NONPRODUCTION_CONTENT_MARKERS, ".invalid")


class ProductionSingleUpdatePlanError(ValueError):
    """A content- and identifier-free Production planning failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _guard(condition: bool, code: str, public_message: str) -> None:
    if not condition:
        raise ProductionSingleUpdatePlanError(code, public_message)


def _hash_mapping(domain: bytes, value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def _time_value(value: object) -> object:
    if value is None:
        return None
    date_value = getattr(value, "date", None)
    datetime_value = getattr(value, "date_time", None)
    if isinstance(date_value, date):
        return {"date": date_value.isoformat()}
    if isinstance(datetime_value, datetime):
        return {"dateTime": datetime_value.isoformat()}
    raise ProductionSingleUpdatePlanError(
        "production_single_update_pre_image_invalid",
        "Production update pre-image is invalid",
    )


def _pre_image_data(event: CanonicalGoogleEvent) -> dict[str, object]:
    reminders = event.reminders
    extended = event.extended_properties
    return {
        "safe_event_reference": event.safe_event_reference,
        "iCalUID": event.ical_uid,
        "safe_iCalUID_reference": event.safe_ical_uid_reference,
        "summary": event.summary,
        "description": event.description,
        "start": _time_value(event.start),
        "end": _time_value(event.end),
        "all_day": event.all_day,
        "end_time_unspecified": event.end_time_unspecified,
        "status": event.status,
        "event_type": event.event_type,
        "sequence": event.sequence,
        "recurrence": list(event.recurrence),
        "recurring_event_reference": event.recurring_event_id,
        "original_start_time": _time_value(event.original_start_time),
        "transparency": event.transparency,
        "visibility": event.visibility,
        "color_id": event.color_id,
        "event_label_id": event.event_label_id,
        "locked": event.locked,
        "private_copy": event.private_copy,
        "reminders": (
            {
                "use_default": reminders.use_default,
                "overrides": [item.model_dump(mode="json") for item in reminders.overrides],
            }
            if reminders is not None
            else None
        ),
        "location": event.location,
        "extended_properties": (
            {
                "private": list(extended.private),
                "shared": list(extended.shared),
            }
            if extended is not None
            else None
        ),
        "created": event.created.isoformat() if event.created else None,
        "updated": event.updated.isoformat() if event.updated else None,
        "html_link_present": event.html_link_present,
        "creator": event.creator.model_dump(mode="json") if event.creator else None,
        "organizer": event.organizer.model_dump(mode="json") if event.organizer else None,
    }


def calculate_production_pre_image_hash(event: CanonicalGoogleEvent) -> str:
    """Hash the exact managed values and compatible event shape, not transport IDs."""

    if not isinstance(event, CanonicalGoogleEvent):
        raise ProductionSingleUpdatePlanError(
            "production_single_update_pre_image_invalid",
            "Production update pre-image is invalid",
        )
    return _hash_mapping(_PRE_IMAGE_HASH_DOMAIN, _pre_image_data(event))


def calculate_production_description_patch_hash(description: str) -> str:
    """Hash the exact future patch value without retaining it in artifacts."""

    if not isinstance(description, str):
        raise ProductionSingleUpdatePlanError(
            "production_single_update_patch_invalid",
            "Production update patch is invalid",
        )
    return _hash_mapping(_PATCH_HASH_DOMAIN, {"description": description})


def private_production_single_update_plan_data(
    plan: ProductionSingleUpdatePlan,
) -> dict[str, object]:
    """Return canonical Plan data; raw identity and event content are absent."""

    return {
        "schema_version": plan.schema_version,
        "plan_type": plan.plan_type,
        "planning_mode": plan.planning_mode,
        "production": plan.production,
        "production_only": plan.production_only,
        "synthetic": plan.synthetic,
        "single_update_only": plan.single_update_only,
        "update_only": plan.update_only,
        "state": plan.state,
        "executable": plan.executable,
        "tool_version": plan.tool_version,
        "target_fingerprint": plan.target_fingerprint,
        "target_safe_ref": plan.target_safe_ref,
        "target_config_hash": plan.target_config_hash,
        "target_environment": plan.target_environment,
        "target_label": plan.target_label,
        "target_purpose": plan.target_purpose,
        "baseline_hash": plan.baseline_hash,
        "baseline_snapshot_hash": plan.baseline_snapshot_hash,
        "baseline_state": plan.baseline_state,
        "managed_uid_count": plan.managed_uid_count,
        "manifest_hash": plan.manifest_hash,
        "source_profile": plan.source_profile,
        "accepted_tag": plan.accepted_tag,
        "accepted_commit": plan.accepted_commit,
        "source_sha256": plan.source_sha256,
        "source_content_hash": plan.source_content_hash,
        "source_event_count": plan.source_event_count,
        "snapshot_hash": plan.snapshot_hash,
        "snapshot_event_count": plan.snapshot_event_count,
        "diff_hash": plan.diff_hash,
        "unchanged_count": plan.unchanged_count,
        "operation_count": plan.operation_count,
        "add_count": plan.add_count,
        "update_count": plan.update_count,
        "delete_count": plan.delete_count,
        "changed_fields": list(plan.changed_fields),
        "safe_uid_ref": plan.safe_uid_ref,
        "google_ref": plan.google_ref,
        "pre_image_hash": plan.pre_image_hash,
        "patch_hash": plan.patch_hash,
        "eligibility": plan.eligibility,
        "approval_required": plan.approval_required,
        "plan_content_hash": plan.plan_content_hash,
    }


def calculate_production_single_update_plan_hash(plan: ProductionSingleUpdatePlan) -> str:
    """Calculate the complete domain-separated Plan hash."""

    data = private_production_single_update_plan_data(plan)
    del data["plan_content_hash"]
    return _hash_mapping(_PLAN_HASH_DOMAIN, data)


def verify_production_single_update_plan(plan: ProductionSingleUpdatePlan) -> None:
    """Independently enforce the fixed Production Plan policy and integrity."""

    if not isinstance(plan, ProductionSingleUpdatePlan):
        raise ProductionSingleUpdatePlanError(
            "invalid_production_single_update_plan",
            "Production Single Update Plan is invalid",
        )
    hash_values = (
        plan.target_fingerprint,
        plan.target_config_hash,
        plan.baseline_hash,
        plan.baseline_snapshot_hash,
        plan.manifest_hash,
        plan.source_sha256,
        plan.source_content_hash,
        plan.snapshot_hash,
        plan.diff_hash,
        plan.pre_image_hash,
        plan.patch_hash,
        plan.plan_content_hash,
    )
    valid = (
        plan.schema_version == "1.0"
        and plan.plan_type == "production_single_update"
        and plan.planning_mode == "production_single_update"
        and plan.production is True
        and plan.production_only is True
        and plan.synthetic is False
        and plan.single_update_only is True
        and plan.update_only is True
        and plan.state == "review_required"
        and plan.executable is False
        and bool(plan.tool_version)
        and all(re.fullmatch(r"[0-9a-f]{64}", value) is not None for value in hash_values)
        and plan.target_safe_ref == f"T-{plan.target_fingerprint[:12]}"
        and plan.target_environment == "production"
        and plan.target_label == "production"
        and plan.target_purpose == PRODUCTION_WRITE_TARGET_PURPOSE
        and plan.baseline_state == "trusted"
        and plan.baseline_snapshot_hash == plan.snapshot_hash
        and plan.managed_uid_count >= 2
        and plan.managed_uid_count == plan.source_event_count
        and plan.source_event_count == plan.snapshot_event_count
        and plan.unchanged_count == plan.source_event_count - 1
        and plan.operation_count == 1
        and plan.add_count == 0
        and plan.update_count == 1
        and plan.delete_count == 0
        and plan.changed_fields == PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
        and re.fullmatch(r"U-[0-9a-f]{12}", plan.safe_uid_ref) is not None
        and re.fullmatch(r"G-[0-9a-f]{12}", plan.google_ref) is not None
        and plan.eligibility == "eligible"
        and plan.approval_required is True
    )
    if not valid:
        raise ProductionSingleUpdatePlanError(
            "production_single_update_plan_policy_mismatch",
            "Production Single Update Plan policy verification failed",
        )
    if not hmac.compare_digest(
        calculate_production_single_update_plan_hash(plan),
        plan.plan_content_hash,
    ):
        raise ProductionSingleUpdatePlanError(
            "production_single_update_plan_hash_mismatch",
            "Production Single Update Plan integrity verification failed",
        )


def _validate_manifest_source(
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
    except AcceptedProductionSourceManifestError as exc:
        raise ProductionSingleUpdatePlanError(
            "production_single_update_manifest_invalid",
            "Accepted Production source manifest verification failed",
        ) from exc
    _guard(
        hmac.compare_digest(expected.manifest_content_hash, manifest.manifest_content_hash)
        and manifest.acceptance_state == "accepted"
        and manifest.source_profile == profile.profile_id == source.profile_id
        and manifest.source_sha256 == profile.html_sha256 == source.raw_sha256
        and manifest.source_content_hash == source.content_hash
        and manifest.source_event_count == source.vevent_count == len(source.events)
        and manifest.source_event_count >= 2
        and manifest.all_day_count == manifest.source_event_count
        and manifest.timed_count == 0
        and manifest.recurring_count == 0,
        "production_single_update_manifest_source_mismatch",
        "Accepted Production manifest and source do not match exactly",
    )
    _guard(
        all(
            event.description is not None
            and not any(
                marker.casefold() in event.description.casefold()
                for marker in _NONPRODUCTION_CONTENT_MARKERS
            )
            for event in source.events
        ),
        "production_single_update_source_marker_forbidden",
        "Accepted Production source contains a Test or synthetic marker",
    )


def _verify_snapshot(snapshot: GoogleSnapshot) -> None:
    try:
        reparsed = parse_google_snapshot_bytes(render_sanitized_snapshot(snapshot))
    except (GoogleSnapshotError, TypeError, ValueError) as exc:
        raise ProductionSingleUpdatePlanError(
            "production_single_update_snapshot_integrity_failed",
            "Production snapshot integrity verification failed",
        ) from exc
    _guard(
        hmac.compare_digest(reparsed.content_hash, snapshot.content_hash),
        "production_single_update_snapshot_integrity_failed",
        "Production snapshot integrity verification failed",
    )


def _validate_baseline_and_snapshot(
    baseline: TrustedBaseline,
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    target_fingerprint: str,
) -> None:
    try:
        verify_baseline_content_hash(baseline)
    except Exception as exc:
        raise ProductionSingleUpdatePlanError(
            "production_single_update_baseline_integrity_failed",
            "Trusted Production baseline integrity verification failed",
        ) from exc
    baseline_marker_values = (baseline.source_profile, baseline.accepted_tag)
    _guard(
        not any(
            marker.casefold() in value.casefold()
            for value in baseline_marker_values
            for marker in _NONPRODUCTION_BASELINE_MARKERS
        )
        and baseline.accepted_commit != "0" * 40
        and baseline.source_sha256 != "0" * 64,
        "production_single_update_baseline_provenance_invalid",
        "Trusted Production baseline provenance is not Production-safe",
    )
    source_uids = tuple(sorted(event.uid for event in source.events if event.uid is not None))
    _guard(
        baseline.state is BaselineState.TRUSTED
        and hmac.compare_digest(
            baseline.baseline_content_hash,
            calculate_baseline_content_hash(baseline),
        )
        and baseline.target_fingerprint == target_fingerprint
        and baseline.snapshot_content_hash == snapshot.content_hash
        and baseline.snapshot_event_count == snapshot.event_count
        and baseline.source_event_count == source.vevent_count
        and baseline.managed_uid_count == source.vevent_count
        and baseline.managed_uids == source_uids,
        "production_single_update_baseline_binding_invalid",
        "Trusted Production baseline does not bind the current inputs",
    )
    _guard(
        snapshot.complete
        and snapshot.page_count >= 1
        and snapshot.collection_metadata_hash is not None
        and snapshot.target_fingerprint == target_fingerprint
        and snapshot.event_count == source.vevent_count == len(snapshot.events)
        and snapshot.event_count >= 2
        and snapshot.cancelled_event_count == 0
        and snapshot.unknown_event_type_count == 0
        and snapshot.dropped_private_extended_property_count == 0
        and snapshot.dropped_shared_extended_property_count == 0
        and snapshot.forbidden_field_count == 0,
        "production_single_update_snapshot_policy_mismatch",
        "Production snapshot is incomplete or unsafe",
    )


def _validate_diff(diff: CalendarDiff) -> tuple[str, str]:
    counts = diff.counts
    _guard(
        diff.snapshot_complete
        and diff.source_event_count >= 2
        and diff.google_event_count == diff.source_event_count
        and counts.unchanged == diff.source_event_count - 1
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
        and len(diff.events) == diff.source_event_count,
        "production_single_update_diff_classification_invalid",
        "Production diff must contain exactly one safe update",
    )
    updates = [event for event in diff.events if event.classification is DiffClassification.UPDATE]
    _guard(
        len(updates) == 1
        and updates[0].source_ref is not None
        and len(updates[0].google_refs) == 1
        and tuple(item.field for item in updates[0].differences)
        == PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS,
        "production_single_update_diff_fields_invalid",
        "Production diff must contain one Description-only update",
    )
    assert updates[0].source_ref is not None
    return updates[0].source_ref, updates[0].google_refs[0]


def _resolve_update_events(
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    safe_uid_reference: str,
    google_reference: str,
) -> tuple[CanonicalSourceEvent, CanonicalGoogleEvent]:
    source_matches = [
        event for event in source.events if event.safe_uid_reference == safe_uid_reference
    ]
    google_matches = [
        event for event in snapshot.events if event.safe_event_reference == google_reference
    ]
    _guard(
        len(source_matches) == 1
        and len(google_matches) == 1
        and source_matches[0].uid is not None
        and google_matches[0].ical_uid == source_matches[0].uid,
        "production_single_update_identity_ambiguous",
        "Production update identity did not resolve exactly once",
    )
    source_event = source_matches[0]
    google_event = google_matches[0]
    _guard(
        source_event.summary is not None
        and source_event.description is not None
        and source_event.start_date is not None
        and source_event.effective_end_date is not None
        and source_event.all_day is True
        and not source_event.rrule_present
        and not source_event.recurrence_id_present
        and google_event.summary == source_event.summary
        and google_event.description is not None
        and google_event.description != source_event.description
        and google_event.start is not None
        and google_event.end is not None
        and google_event.start.date == source_event.start_date
        and google_event.end.date == source_event.effective_end_date
        and google_event.all_day is True
        and google_event.end_time_unspecified is False
        and google_event.status == "confirmed"
        and google_event.event_type == "default"
        and not google_event.recurrence
        and google_event.recurring_event_id is None
        and google_event.original_start_time is None
        and google_event.locked is False
        and google_event.private_copy is False
        and bool(google_event.event_id)
        and bool(google_event.etag),
        "production_single_update_event_shape_invalid",
        "Production update event shape is incompatible",
    )
    return source_event, google_event


def validate_production_single_update_eligibility(
    manifest: AcceptedProductionSourceManifest,
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    current_snapshot: GoogleSnapshot,
    trusted_baseline: TrustedBaseline,
    target: ProductionWriteTargetConfig,
    diff: CalendarDiff,
) -> ProductionSingleUpdateEligibility:
    """Return raw-free eligibility for one canonical Production update."""

    _validate_manifest_source(manifest, profile, source)
    _verify_snapshot(current_snapshot)
    target_fingerprint = validate_production_write_target_config(target)
    target_ref = production_write_target_reference(target)
    _validate_baseline_and_snapshot(
        trusted_baseline,
        source,
        current_snapshot,
        target_fingerprint,
    )
    safe_uid_reference, google_reference = _validate_diff(diff)
    source_event, google_event = _resolve_update_events(
        source,
        current_snapshot,
        safe_uid_reference,
        google_reference,
    )
    assert source_event.description is not None
    return ProductionSingleUpdateEligibility(
        target_fingerprint=target_fingerprint,
        target_safe_ref=target_ref,
        target_config_hash=calculate_production_write_target_hash(target),
        safe_uid_ref=safe_uid_reference,
        google_ref=google_reference,
        baseline_hash=trusted_baseline.baseline_content_hash,
        manifest_hash=manifest.manifest_content_hash,
        source_sha256=source.raw_sha256,
        source_content_hash=source.content_hash,
        snapshot_hash=current_snapshot.content_hash,
        diff_hash=diff.content_hash,
        pre_image_hash=calculate_production_pre_image_hash(google_event),
        patch_hash=calculate_production_description_patch_hash(source_event.description),
    )


def build_production_single_update_plan(
    manifest: AcceptedProductionSourceManifest,
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    current_snapshot: GoogleSnapshot,
    trusted_baseline: TrustedBaseline,
    target: ProductionWriteTargetConfig,
    *,
    diff: CalendarDiff | None = None,
) -> ProductionSingleUpdatePlan:
    """Build one non-executable Production Plan without online capabilities."""

    try:
        expected_diff = diff_with_trusted_baseline(source, current_snapshot, trusted_baseline)
    except (BaselineError, PlanError) as exc:
        raise ProductionSingleUpdatePlanError(
            "production_single_update_baseline_diff_failed",
            "Trusted Production baseline could not produce the canonical diff",
        ) from exc
    if diff is not None and not hmac.compare_digest(diff.content_hash, expected_diff.content_hash):
        raise ProductionSingleUpdatePlanError(
            "production_single_update_diff_mismatch",
            "Provided diff does not match Production planning inputs",
        )
    resolved_diff = expected_diff if diff is None else diff
    eligibility = validate_production_single_update_eligibility(
        manifest,
        profile,
        source,
        current_snapshot,
        trusted_baseline,
        target,
        resolved_diff,
    )
    provisional = ProductionSingleUpdatePlan(
        tool_version=tool_version(),
        target_fingerprint=eligibility.target_fingerprint,
        target_safe_ref=eligibility.target_safe_ref,
        target_config_hash=eligibility.target_config_hash,
        baseline_hash=trusted_baseline.baseline_content_hash,
        baseline_snapshot_hash=trusted_baseline.snapshot_content_hash,
        managed_uid_count=trusted_baseline.managed_uid_count,
        manifest_hash=manifest.manifest_content_hash,
        source_profile=manifest.source_profile,
        accepted_tag=manifest.accepted_tag,
        accepted_commit=manifest.accepted_commit,
        source_sha256=eligibility.source_sha256,
        source_content_hash=eligibility.source_content_hash,
        source_event_count=source.vevent_count,
        snapshot_hash=eligibility.snapshot_hash,
        snapshot_event_count=current_snapshot.event_count,
        diff_hash=eligibility.diff_hash,
        unchanged_count=resolved_diff.counts.unchanged,
        safe_uid_ref=eligibility.safe_uid_ref,
        google_ref=eligibility.google_ref,
        pre_image_hash=eligibility.pre_image_hash,
        patch_hash=eligibility.patch_hash,
        plan_content_hash="0" * 64,
    )
    plan = provisional.model_copy(
        update={"plan_content_hash": calculate_production_single_update_plan_hash(provisional)}
    )
    verify_production_single_update_plan(plan)
    return plan


__all__ = [
    "ProductionSingleUpdatePlanError",
    "build_production_single_update_plan",
    "calculate_production_description_patch_hash",
    "calculate_production_pre_image_hash",
    "calculate_production_single_update_plan_hash",
    "private_production_single_update_plan_data",
    "validate_production_single_update_eligibility",
    "verify_production_single_update_plan",
]
