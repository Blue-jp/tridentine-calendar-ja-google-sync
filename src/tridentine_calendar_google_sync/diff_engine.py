"""Pure offline identity matching and deterministic diff classification."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from datetime import date
from typing import Any

from tridentine_calendar_google_sync.diff_models import (
    CLASSIFICATION_ORDER,
    CalendarDiff,
    DiffClassification,
    DiffCounts,
    DiffWarning,
    EventDiff,
    FieldDifference,
    ManagedScope,
)
from tridentine_calendar_google_sync.google_models import (
    CanonicalGoogleEvent,
    GoogleSnapshot,
)
from tridentine_calendar_google_sync.models import (
    CanonicalSourceEvent,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.safe_refs import (
    safe_google_event_ref,
    safe_uid_ref,
)

_VALUE_HASH_DOMAIN = b"tridentine-calendar-google-sync:field-difference:v1\x00"
_DIFF_HASH_DOMAIN = b"tridentine-calendar-google-sync:calendar-diff:v1\x00"
_CLASSIFICATION_RANK = {
    classification: index for index, classification in enumerate(CLASSIFICATION_ORDER)
}


def _hash_value(field: str, value: str | date | None) -> tuple[str, int, bool]:
    present = value is not None
    rendered = value.isoformat() if isinstance(value, date) else value or ""
    marker = b"present\x00" if present else b"absent\x00"
    encoded = field.encode("ascii") + b"\x00" + marker + rendered.encode("utf-8")
    return hashlib.sha256(_VALUE_HASH_DOMAIN + encoded).hexdigest(), len(rendered), present


def _field_difference(
    field: str,
    current: str | date | None,
    desired: str | date | None,
) -> FieldDifference:
    current_hash, current_length, current_present = _hash_value(field, current)
    desired_hash, desired_length, desired_present = _hash_value(field, desired)
    return FieldDifference(
        field=field,
        current_present=current_present,
        desired_present=desired_present,
        current_hash=current_hash,
        desired_hash=desired_hash,
        current_length=current_length,
        desired_length=desired_length,
    )


def _event_differences(
    source: CanonicalSourceEvent,
    google: CanonicalGoogleEvent,
) -> tuple[FieldDifference, ...]:
    pairs: tuple[tuple[str, str | date | None, str | date | None], ...] = (
        ("summary", google.summary, source.summary),
        ("description", google.description, source.description),
        ("start_date", _google_start_date(google), source.start_date),
        ("end_date", _google_end_date(google), source.effective_end_date),
    )
    return tuple(
        _field_difference(field, current, desired)
        for field, current, desired in pairs
        if current != desired
    )


def _google_start_date(event: CanonicalGoogleEvent) -> date | None:
    return event.start.date if event.start is not None else None


def _google_end_date(event: CanonicalGoogleEvent) -> date | None:
    return event.end.date if event.end is not None else None


def _compatibility_reasons(event: CanonicalGoogleEvent) -> tuple[str, ...]:
    reasons: list[str] = []
    if event.event_type != "default":
        reasons.append("non_default_event_type")
    if event.status == "cancelled":
        reasons.append("cancelled_event")
    if event.recurrence:
        reasons.append("recurring_master")
    if event.recurring_event_id is not None:
        reasons.append("recurring_instance")
    if event.original_start_time is not None:
        reasons.append("original_start_time_present")
    if event.end_time_unspecified:
        reasons.append("end_time_unspecified")
    if event.locked:
        reasons.append("locked_event")
    if event.private_copy:
        reasons.append("private_copy_event")
    if event.start is None or event.end is None:
        reasons.append("missing_event_time")
    elif not event.all_day or event.start.date is None or event.end.date is None:
        reasons.append("not_all_day")
    elif event.end.date <= event.start.date:
        reasons.append("invalid_all_day_end")
    return tuple(sorted(set(reasons)))


def _private_properties(value: Any) -> Mapping[str, str]:
    if value is None:
        return {}
    private = getattr(value, "private", None)
    if private is None and isinstance(value, Mapping):
        private = value.get("private")
    if isinstance(private, Mapping):
        return {
            str(key): str(item)
            for key, item in private.items()
            if isinstance(key, str) and isinstance(item, str)
        }
    if isinstance(private, (list, tuple)):
        result: dict[str, str] = {}
        for item in private:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                key, item_value = item
                if isinstance(key, str) and isinstance(item_value, str):
                    result[key] = item_value
        return result
    return {}


def _ownership_evidence(
    event: CanonicalGoogleEvent,
    managed_scope: ManagedScope,
) -> tuple[str, ...]:
    evidence: list[str] = []
    if event.ical_uid is not None and event.ical_uid in managed_scope.trusted_baseline_uids:
        evidence.append("trusted_baseline")
    if event.ical_uid is not None and event.ical_uid in managed_scope.trusted_source_uids:
        evidence.append("trusted_source_uid")
    if event.event_id in managed_scope.trusted_google_event_ids:
        evidence.append("trusted_google_event_id")
    marker_key = managed_scope.private_marker_key
    marker_value = managed_scope.private_marker_value
    if (
        marker_key is not None
        and marker_value is not None
        and _private_properties(event.extended_properties).get(marker_key) == marker_value
    ):
        evidence.append("private_extended_property")
    return tuple(sorted(evidence))


def _color_warnings(event: CanonicalGoogleEvent) -> tuple[str, ...]:
    warnings: list[str] = []
    if event.color_id is not None:
        warnings.append("google_event_color_present")
    if event.event_label_id is not None:
        warnings.append("google_event_label_present")
    return tuple(warnings)


def _event_sort_key(event: EventDiff) -> tuple[int, date, str, tuple[str, ...]]:
    return (
        _CLASSIFICATION_RANK[event.classification],
        event.source_date or event.google_date or date.max,
        event.source_ref or "",
        event.google_refs,
    )


def _warning_sort_key(warning: DiffWarning) -> tuple[str, str, str]:
    return (warning.code, warning.source_ref or "", warning.google_ref or "")


def _diff_counts(events: Sequence[EventDiff]) -> DiffCounts:
    counts = Counter(event.classification for event in events)
    return DiffCounts(
        unchanged=counts[DiffClassification.UNCHANGED],
        add=counts[DiffClassification.ADD],
        update=counts[DiffClassification.UPDATE],
        delete_candidate=counts[DiffClassification.DELETE_CANDIDATE],
        duplicate_source_uid=counts[DiffClassification.DUPLICATE_SOURCE_UID],
        duplicate_google_icaluid=counts[DiffClassification.DUPLICATE_GOOGLE_ICALUID],
        ambiguous=counts[DiffClassification.AMBIGUOUS],
        unmanaged_google_event=counts[DiffClassification.UNMANAGED_GOOGLE_EVENT],
        invalid_source=counts[DiffClassification.INVALID_SOURCE],
        fatal_guard=counts[DiffClassification.FATAL_GUARD],
    )


def _event_hash_data(event: EventDiff) -> dict[str, object]:
    return {
        "classification": event.classification.value,
        "source_ref": event.source_ref,
        "google_refs": list(event.google_refs),
        "source_date": event.source_date.isoformat() if event.source_date else None,
        "google_date": event.google_date.isoformat() if event.google_date else None,
        "differences": [difference.model_dump(mode="json") for difference in event.differences],
        "reason_codes": list(event.reason_codes),
        "ownership_evidence": list(event.ownership_evidence),
        "warnings": list(event.warnings),
        "fatal": event.fatal,
    }


def _diff_content_hash(
    *,
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    events: Sequence[EventDiff],
    warnings: Sequence[DiffWarning],
) -> str:
    payload = {
        "schema_version": "1.0",
        "source_sha256": source.raw_sha256,
        "source_sha_matches": source.source_sha_matches,
        "snapshot_sha256": snapshot.content_hash,
        "target_fingerprint": snapshot.target_fingerprint,
        "events": [_event_hash_data(event) for event in events],
        "warnings": [warning.model_dump(mode="json") for warning in warnings],
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_DIFF_HASH_DOMAIN + encoded).hexdigest()


def _source_guard_events(source: SourceCalendarInspection) -> list[EventDiff]:
    duplicate_groups: dict[str, list[CanonicalSourceEvent]] = defaultdict(list)
    for event in source.events:
        if event.uid is not None:
            duplicate_groups[event.uid].append(event)
    duplicates = [
        EventDiff(
            classification=DiffClassification.DUPLICATE_SOURCE_UID,
            source_uid=uid,
            source_ref=safe_uid_ref(uid),
            source_date=min(
                (event.start_date for event in group if event.start_date is not None),
                default=None,
            ),
            reason_codes=("duplicate_source_uid",),
            fatal=True,
        )
        for uid, group in duplicate_groups.items()
        if len(group) > 1
    ]
    guard_events = list(duplicates)
    source_codes = {finding.code for finding in source.findings}
    invalid_codes = sorted(
        code
        for code in source_codes
        if not code.startswith("expected_") and code != "source_sha256_mismatch"
    )
    invalid_codes = [code for code in invalid_codes if code != "duplicate_uid"]
    guard_codes = sorted(
        code
        for code in source_codes
        if code.startswith("expected_") or code == "source_sha256_mismatch"
    )
    if invalid_codes:
        guard_events.append(
            EventDiff(
                classification=DiffClassification.INVALID_SOURCE,
                reason_codes=tuple(invalid_codes),
                fatal=True,
            )
        )
    if guard_codes and not duplicates and not invalid_codes:
        guard_events.append(
            EventDiff(
                classification=DiffClassification.FATAL_GUARD,
                reason_codes=tuple(guard_codes),
                fatal=True,
            )
        )
    return guard_events


def _google_refs(events: Sequence[CanonicalGoogleEvent]) -> tuple[str, ...]:
    return tuple(sorted(event.safe_event_reference for event in events))


def _finalize_diff(
    *,
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    snapshot_complete: bool,
    events: list[EventDiff],
) -> CalendarDiff:
    ordered_events = tuple(sorted(events, key=_event_sort_key))
    warnings = tuple(
        sorted(
            (
                DiffWarning(
                    code=warning_code,
                    message="Google event-specific display metadata is present",
                    source_ref=event.source_ref,
                    google_ref=event.google_refs[0] if len(event.google_refs) == 1 else None,
                )
                for event in ordered_events
                for warning_code in event.warnings
            ),
            key=_warning_sort_key,
        )
    )
    counts = _diff_counts(ordered_events)
    fatal = any(event.fatal for event in ordered_events)
    return CalendarDiff(
        schema_version="1.0",
        source_profile_id=source.profile_id,
        source_sha256=source.raw_sha256,
        source_sha_matches=source.source_sha_matches,
        snapshot_sha256=snapshot.content_hash,
        target_fingerprint=snapshot.target_fingerprint,
        source_event_count=source.vevent_count,
        google_event_count=snapshot.event_count,
        snapshot_complete=snapshot_complete,
        counts=counts,
        events=ordered_events,
        warnings=warnings,
        fatal=fatal,
        content_hash=_diff_content_hash(
            source=source,
            snapshot=snapshot,
            events=ordered_events,
            warnings=warnings,
        ),
    )


def diff_source_to_snapshot(
    source: SourceCalendarInspection,
    snapshot: GoogleSnapshot,
    managed_scope: ManagedScope | None = None,
) -> CalendarDiff:
    """Classify exact UID-to-iCalUID differences without network or side effects."""

    scope = managed_scope or ManagedScope()
    snapshot_complete = bool(getattr(snapshot, "complete", True))
    guard_events = _source_guard_events(source)
    if not snapshot_complete:
        guard_events.append(
            EventDiff(
                classification=DiffClassification.FATAL_GUARD,
                reason_codes=("incomplete_google_snapshot",),
                fatal=True,
            )
        )
    if guard_events:
        return _finalize_diff(
            source=source,
            snapshot=snapshot,
            snapshot_complete=snapshot_complete,
            events=guard_events,
        )

    source_groups: dict[str, list[CanonicalSourceEvent]] = defaultdict(list)
    for source_event in source.events:
        if source_event.uid is not None:
            source_groups[source_event.uid].append(source_event)

    google_groups: dict[str, list[CanonicalGoogleEvent]] = defaultdict(list)
    for google_event in snapshot.events:
        if google_event.ical_uid is None:
            continue
        else:
            google_groups[google_event.ical_uid].append(google_event)

    results: list[EventDiff] = []
    consumed_google_ids: set[str] = set()
    duplicate_google_uids = {
        ical_uid for ical_uid, group in google_groups.items() if len(group) > 1
    }
    for ical_uid in sorted(duplicate_google_uids, key=safe_uid_ref):
        group = google_groups[ical_uid]
        consumed_google_ids.update(event.event_id for event in group)
        results.append(
            EventDiff(
                classification=DiffClassification.DUPLICATE_GOOGLE_ICALUID,
                source_uid=ical_uid if ical_uid in source_groups else None,
                google_ical_uid=ical_uid,
                google_event_ids=tuple(event.event_id for event in group),
                source_ref=safe_uid_ref(ical_uid),
                google_refs=_google_refs(group),
                source_date=source_groups[ical_uid][0].start_date
                if ical_uid in source_groups
                else None,
                google_date=min(
                    (
                        start_date
                        for event in group
                        if (start_date := _google_start_date(event)) is not None
                    ),
                    default=None,
                ),
                reason_codes=("duplicate_google_icaluid",),
                warnings=tuple(
                    sorted({warning for event in group for warning in _color_warnings(event)})
                ),
                fatal=True,
            )
        )

    for uid in sorted(source_groups, key=safe_uid_ref):
        if uid in duplicate_google_uids:
            continue
        source_event = source_groups[uid][0]
        google_group = google_groups.get(uid, [])
        if not google_group:
            results.append(
                EventDiff(
                    classification=DiffClassification.ADD,
                    source_uid=uid,
                    source_ref=source_event.safe_uid_reference,
                    source_date=source_event.start_date,
                    reason_codes=("source_only",),
                )
            )
            continue

        google_event = google_group[0]
        consumed_google_ids.add(google_event.event_id)
        compatibility_reasons = _compatibility_reasons(google_event)
        warnings = _color_warnings(google_event)
        if compatibility_reasons:
            results.append(
                EventDiff(
                    classification=DiffClassification.AMBIGUOUS,
                    source_uid=uid,
                    google_ical_uid=google_event.ical_uid,
                    google_event_ids=(google_event.event_id,),
                    source_ref=source_event.safe_uid_reference,
                    google_refs=(google_event.safe_event_reference,),
                    source_date=source_event.start_date,
                    google_date=_google_start_date(google_event),
                    reason_codes=compatibility_reasons,
                    warnings=warnings,
                    fatal=True,
                )
            )
            continue

        differences = _event_differences(source_event, google_event)
        classification = DiffClassification.UPDATE if differences else DiffClassification.UNCHANGED
        results.append(
            EventDiff(
                classification=classification,
                source_uid=uid,
                google_ical_uid=google_event.ical_uid,
                google_event_ids=(google_event.event_id,),
                source_ref=source_event.safe_uid_reference,
                google_refs=(google_event.safe_event_reference,),
                source_date=source_event.start_date,
                google_date=_google_start_date(google_event),
                differences=differences,
                warnings=warnings,
            )
        )

    remaining_events = [
        event for event in snapshot.events if event.event_id not in consumed_google_ids
    ]
    for google_event in sorted(remaining_events, key=lambda event: event.safe_event_reference):
        evidence = _ownership_evidence(google_event, scope)
        compatibility_reasons = _compatibility_reasons(google_event)
        google_ref = google_event.safe_event_reference or safe_google_event_ref(
            google_event.event_id
        )
        if google_event.ical_uid is None:
            classification = (
                DiffClassification.AMBIGUOUS
                if evidence
                else DiffClassification.UNMANAGED_GOOGLE_EVENT
            )
            reason = "owned_event_missing_icaluid" if evidence else "missing_icaluid_unmanaged"
            source_ref = None
        else:
            if evidence and compatibility_reasons:
                classification = DiffClassification.AMBIGUOUS
                reason_codes = ("managed_google_only_incompatible", *compatibility_reasons)
            elif evidence:
                classification = DiffClassification.DELETE_CANDIDATE
                reason_codes = ("managed_google_only",)
            else:
                classification = DiffClassification.UNMANAGED_GOOGLE_EVENT
                reason_codes = ("google_only_unmanaged",)
            source_ref = safe_uid_ref(google_event.ical_uid)
        if google_event.ical_uid is None:
            reason_codes = (reason,)
        results.append(
            EventDiff(
                classification=classification,
                google_ical_uid=google_event.ical_uid,
                google_event_ids=(google_event.event_id,),
                source_ref=source_ref,
                google_refs=(google_ref,),
                google_date=_google_start_date(google_event),
                reason_codes=reason_codes,
                ownership_evidence=evidence,
                warnings=_color_warnings(google_event),
                fatal=classification is DiffClassification.AMBIGUOUS,
            )
        )

    return _finalize_diff(
        source=source,
        snapshot=snapshot,
        snapshot_complete=snapshot_complete,
        events=results,
    )


diff_calendars = diff_source_to_snapshot


__all__ = ["diff_calendars", "diff_source_to_snapshot"]
