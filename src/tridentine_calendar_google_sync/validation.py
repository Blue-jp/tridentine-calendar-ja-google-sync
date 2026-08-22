"""Strict deterministic validation for parsed Accepted source calendars."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    CanonicalSourceEvent,
    ParsedSourceCalendar,
    SourceCalendarInspection,
    ValidationFinding,
)
from tridentine_calendar_google_sync.provenance import (
    canonical_content_hash,
    unparsed_content_hash,
)

_ISSUE_DETAILS: dict[str, tuple[str, str]] = {
    "missing_uid": ("uid", "VEVENT is missing required UID"),
    "empty_uid": ("uid", "VEVENT has an empty required UID"),
    "multiple_uid": ("uid", "VEVENT has multiple UID properties"),
    "missing_summary": ("summary", "VEVENT is missing required SUMMARY"),
    "empty_summary": ("summary", "VEVENT has an empty required SUMMARY"),
    "multiple_summary": ("summary", "VEVENT has multiple SUMMARY properties"),
    "missing_description": ("description", "VEVENT is missing required DESCRIPTION"),
    "empty_description": (
        "description",
        "VEVENT has an empty required DESCRIPTION",
    ),
    "multiple_description": (
        "description",
        "VEVENT has multiple DESCRIPTION properties",
    ),
    "missing_dtstart": ("dtstart", "VEVENT is missing required DTSTART"),
    "invalid_dtstart": ("dtstart", "VEVENT DTSTART is neither a date nor a datetime"),
    "multiple_dtstart": ("dtstart", "VEVENT has multiple DTSTART properties"),
    "invalid_dtend": ("dtend", "VEVENT DTEND is neither a date nor a datetime"),
    "multiple_dtend": ("dtend", "VEVENT has multiple DTEND properties"),
    "mixed_dtend_type": ("dtend", "VEVENT DTSTART and DTEND types do not match"),
    "dtend_not_after_start": ("dtend", "VEVENT DTEND is not after DTSTART"),
    "invalid_sequence": ("calendar", "VEVENT SEQUENCE is invalid"),
    "multiple_sequence": ("calendar", "VEVENT has multiple SEQUENCE properties"),
    "multiple_status": ("calendar", "VEVENT has multiple STATUS properties"),
    "multiple_rrule": ("rrule", "VEVENT has multiple RRULE properties"),
    "multiple_recurrence_id": (
        "recurrence_id",
        "VEVENT has multiple RECURRENCE-ID properties",
    ),
}


def finding_sort_key(finding: ValidationFinding) -> tuple[int, str, str, str, str]:
    """Return the stable ordering key used by all reports."""

    return (
        0 if finding.severity == "fatal" else 1,
        finding.code,
        finding.field or "",
        finding.event_ref or "",
        finding.message,
    )


def sorted_findings(findings: Iterable[ValidationFinding]) -> tuple[ValidationFinding, ...]:
    """Return findings in a deterministic, privacy-safe order."""

    return tuple(sorted(findings, key=finding_sort_key))


def _event_findings(event: CanonicalSourceEvent) -> list[ValidationFinding]:
    findings: list[ValidationFinding] = []
    for issue_code in event.parser_issue_codes:
        field, message = _ISSUE_DETAILS.get(
            issue_code,
            ("calendar", "VEVENT contains an invalid property"),
        )
        findings.append(
            ValidationFinding(
                severity="fatal",
                code=issue_code,
                message=message,
                field=field,
                event_ref=event.safe_uid_reference,
            )
        )
    return findings


def _expected_count_findings(
    actual: dict[str, int],
    expected: dict[str, int],
) -> list[ValidationFinding]:
    fields = {
        "vcalendar_count": "vcalendar",
        "vevent_count": "vevent",
        "uid_total_count": "uid",
        "uid_unique_count": "uid",
        "uid_duplicate_count": "uid",
        "all_day_count": "dtstart",
        "timed_count": "dtstart",
        "dtstart_date_count": "dtstart",
        "dtend_present_count": "dtend",
        "summary_present_count": "summary",
        "description_present_count": "description",
        "dtstamp_present_count": "dtstamp",
        "rrule_count": "rrule",
        "recurrence_id_count": "recurrence_id",
        "event_x_property_count": "event_x_property",
    }
    findings: list[ValidationFinding] = []
    for name in fields:
        if actual[name] != expected[name]:
            findings.append(
                ValidationFinding(
                    severity="fatal",
                    code=f"expected_{name}_mismatch",
                    message=f"{name} does not match the accepted profile",
                    field=fields[name],
                )
            )
    return findings


def validate_source_events(
    *,
    parsed: ParsedSourceCalendar,
    profile: AcceptedSourceProfile,
    raw_sha256: str,
) -> SourceCalendarInspection:
    """Aggregate canonical events and validate them against ``profile``."""

    events = parsed.events
    present_uids = [event.uid for event in events if event.uid is not None]
    uid_counts = Counter(present_uids)
    unique_uids = len(uid_counts)
    duplicate_uids = len(present_uids) - unique_uids

    source_dates = []
    for event in events:
        if event.start_date is not None:
            source_dates.append(event.start_date)
        elif event.start_datetime is not None:
            source_dates.append(event.start_datetime.date())
    first_date = min(source_dates, default=None)
    last_date = max(source_dates, default=None)

    actual = {
        "vcalendar_count": parsed.vcalendar_count,
        "vevent_count": parsed.vevent_count,
        "uid_total_count": len(present_uids),
        "uid_unique_count": unique_uids,
        "uid_duplicate_count": duplicate_uids,
        "all_day_count": sum(event.all_day for event in events),
        "timed_count": sum(event.start_datetime is not None for event in events),
        "dtstart_date_count": sum(event.start_date is not None for event in events),
        "dtend_present_count": sum(event.dtend_present for event in events),
        "summary_present_count": sum(event.summary is not None for event in events),
        "description_present_count": sum(event.description is not None for event in events),
        "dtstamp_present_count": sum(event.dtstamp_present for event in events),
        "rrule_count": sum(event.rrule_present for event in events),
        "recurrence_id_count": sum(event.recurrence_id_present for event in events),
        "event_x_property_count": sum(len(event.event_x_property_names) for event in events),
    }
    expected_model = profile.expected
    expected = {
        "vcalendar_count": expected_model.vcalendar_count,
        "vevent_count": expected_model.vevent_count,
        "uid_total_count": expected_model.uid_total_count,
        "uid_unique_count": expected_model.uid_unique_count,
        "uid_duplicate_count": expected_model.uid_duplicate_count,
        "all_day_count": expected_model.all_day_count,
        "timed_count": expected_model.timed_count,
        "dtstart_date_count": expected_model.dtstart_date_count,
        "dtend_present_count": expected_model.dtend_present_count,
        "summary_present_count": expected_model.summary_present_count,
        "description_present_count": expected_model.description_present_count,
        "dtstamp_present_count": expected_model.dtstamp_present_count,
        "rrule_count": expected_model.rrule_count,
        "recurrence_id_count": expected_model.recurrence_id_count,
        "event_x_property_count": expected_model.event_x_property_count,
    }

    findings: list[ValidationFinding] = []
    for event in events:
        findings.extend(_event_findings(event))
        if event.start_datetime is not None and expected_model.timed_count == 0:
            findings.append(
                ValidationFinding(
                    severity="fatal",
                    code="timed_event_not_allowed",
                    message="timed VEVENT is not allowed by the accepted profile",
                    field="dtstart",
                    event_ref=event.safe_uid_reference,
                )
            )

    duplicate_refs = sorted(
        (event_uid for event_uid, count in uid_counts.items() if count > 1),
        key=lambda event_uid: next(
            event.safe_uid_reference or "" for event in events if event.uid == event_uid
        ),
    )
    for duplicate_uid in duplicate_refs:
        event_ref = next(event.safe_uid_reference for event in events if event.uid == duplicate_uid)
        findings.append(
            ValidationFinding(
                severity="fatal",
                code="duplicate_uid",
                message="multiple VEVENT components share one UID",
                field="uid",
                event_ref=event_ref,
            )
        )

    findings.extend(_expected_count_findings(actual, expected))
    if first_date != expected_model.first_date:
        findings.append(
            ValidationFinding(
                severity="fatal",
                code="expected_first_date_mismatch",
                message="first DTSTART date does not match the accepted profile",
                field="dtstart",
            )
        )
    if last_date != expected_model.last_date:
        findings.append(
            ValidationFinding(
                severity="fatal",
                code="expected_last_date_mismatch",
                message="last DTSTART date does not match the accepted profile",
                field="dtstart",
            )
        )

    ordered_findings = sorted_findings(findings)
    fatal = any(finding.severity == "fatal" for finding in ordered_findings)
    source_valid = not ordered_findings
    content_hash = canonical_content_hash(
        vcalendar_count=parsed.vcalendar_count,
        events=events,
    )
    return SourceCalendarInspection(
        profile_id=profile.profile_id,
        raw_sha256=raw_sha256,
        source_sha_matches=True,
        vcalendar_count=actual["vcalendar_count"],
        vevent_count=actual["vevent_count"],
        uid_total_count=actual["uid_total_count"],
        uid_unique_count=actual["uid_unique_count"],
        uid_duplicate_count=actual["uid_duplicate_count"],
        first_date=first_date,
        last_date=last_date,
        all_day_count=actual["all_day_count"],
        timed_count=actual["timed_count"],
        dtstart_date_count=actual["dtstart_date_count"],
        dtend_present_count=actual["dtend_present_count"],
        summary_present_count=actual["summary_present_count"],
        description_present_count=actual["description_present_count"],
        dtstamp_present_count=actual["dtstamp_present_count"],
        rrule_count=actual["rrule_count"],
        recurrence_id_count=actual["recurrence_id_count"],
        event_x_property_count=actual["event_x_property_count"],
        malformed_event_count=sum(bool(event.parser_issue_codes) for event in events),
        findings=ordered_findings,
        fatal=fatal,
        source_valid=source_valid,
        content_hash=content_hash,
        events=events,
    )


def unparsed_fatal_inspection(
    *,
    profile: AcceptedSourceProfile,
    raw_sha256: str,
    source_sha_matches: bool,
    code: str,
    message: str,
    field: str,
) -> SourceCalendarInspection:
    """Create a minimal safe result when parsing is rejected or fails."""

    finding = ValidationFinding(
        severity="fatal",
        code=code,
        message=message,
        field=field,
    )
    return SourceCalendarInspection(
        profile_id=profile.profile_id,
        raw_sha256=raw_sha256,
        source_sha_matches=source_sha_matches,
        vcalendar_count=0,
        vevent_count=0,
        uid_total_count=0,
        uid_unique_count=0,
        uid_duplicate_count=0,
        first_date=None,
        last_date=None,
        all_day_count=0,
        timed_count=0,
        dtstart_date_count=0,
        dtend_present_count=0,
        summary_present_count=0,
        description_present_count=0,
        dtstamp_present_count=0,
        rrule_count=0,
        recurrence_id_count=0,
        event_x_property_count=0,
        malformed_event_count=1 if code == "malformed_ics" else 0,
        findings=(finding,),
        fatal=True,
        source_valid=False,
        content_hash=unparsed_content_hash(raw_sha256=raw_sha256, reason_code=code),
        events=(),
    )


__all__ = [
    "finding_sort_key",
    "sorted_findings",
    "unparsed_fatal_inspection",
    "validate_source_events",
]
