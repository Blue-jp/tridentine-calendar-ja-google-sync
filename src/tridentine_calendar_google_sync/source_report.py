"""Privacy-safe deterministic human and JSON inspection reports."""

from __future__ import annotations

import json

from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    SourceCalendarInspection,
    ValidationFinding,
)
from tridentine_calendar_google_sync.provenance import (
    deterministic_report_hash,
    tool_version,
)


def _finding_data(finding: ValidationFinding) -> dict[str, object]:
    data: dict[str, object] = {
        "severity": finding.severity,
        "code": finding.code,
        "message": finding.message,
    }
    if finding.field is not None:
        data["field"] = finding.field
    if finding.event_ref is not None:
        data["event_ref"] = finding.event_ref
    return data


def build_json_report(
    inspection: SourceCalendarInspection,
    profile: AcceptedSourceProfile,
) -> dict[str, object]:
    """Build the schema-v1 report without raw events, paths, or volatile fields."""

    if inspection.profile_id != profile.profile_id:
        raise ValueError("inspection and profile identities do not match")
    findings = [_finding_data(finding) for finding in inspection.findings]
    fatal_errors = [
        _finding_data(finding) for finding in inspection.findings if finding.severity == "fatal"
    ]
    return {
        "schema_version": "1.0",
        "tool_version": tool_version(),
        "mode": "offline",
        "profile": {
            "profile_id": profile.profile_id,
            "accepted_tag": profile.accepted_tag,
            "accepted_commit": profile.accepted_commit,
        },
        "source": {
            "sha256": inspection.raw_sha256,
            "sha256_match": inspection.source_sha_matches,
        },
        "aggregate": {
            "vcalendar_count": inspection.vcalendar_count,
            "vevent_count": inspection.vevent_count,
            "uid_total_count": inspection.uid_total_count,
            "uid_unique_count": inspection.uid_unique_count,
            "uid_duplicate_count": inspection.uid_duplicate_count,
            "date_range": {
                "first": inspection.first_date.isoformat()
                if inspection.first_date is not None
                else None,
                "last": inspection.last_date.isoformat()
                if inspection.last_date is not None
                else None,
            },
            "all_day_count": inspection.all_day_count,
            "timed_count": inspection.timed_count,
            "dtstart_date_count": inspection.dtstart_date_count,
            "dtend_present_count": inspection.dtend_present_count,
            "summary_present_count": inspection.summary_present_count,
            "description_present_count": inspection.description_present_count,
            "dtstamp_present_count": inspection.dtstamp_present_count,
            "rrule_count": inspection.rrule_count,
            "recurrence_id_count": inspection.recurrence_id_count,
            "event_x_property_count": inspection.event_x_property_count,
            "malformed_event_count": inspection.malformed_event_count,
        },
        "findings": findings,
        "fatal_errors": fatal_errors,
        "source_valid": inspection.source_valid,
        "content_hash": inspection.content_hash,
    }


def render_json_report(
    inspection: SourceCalendarInspection,
    profile: AcceptedSourceProfile,
) -> str:
    """Render a deterministic UTF-8 JSON report with a final newline."""

    return (
        json.dumps(
            build_json_report(inspection, profile),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )


def render_text_report(
    inspection: SourceCalendarInspection,
    profile: AcceptedSourceProfile,
) -> str:
    """Render the compact human report without local paths or source content."""

    report_data = build_json_report(inspection, profile)
    report_hash = deterministic_report_hash(report_data)
    first_date = inspection.first_date.isoformat() if inspection.first_date else "none"
    last_date = inspection.last_date.isoformat() if inspection.last_date else "none"
    lines = [
        "Accepted ICS source inspection",
        f"tool version: {tool_version()}",
        "mode: offline",
        f"profile ID: {profile.profile_id}",
        f"accepted tag: {profile.accepted_tag}",
        f"accepted commit: {profile.accepted_commit[:12]}",
        f"source SHA match: {'yes' if inspection.source_sha_matches else 'no'}",
        f"VEVENT count: {inspection.vevent_count}",
        f"UID total: {inspection.uid_total_count}",
        f"UID unique: {inspection.uid_unique_count}",
        f"duplicate UID count: {inspection.uid_duplicate_count}",
        f"all-day count: {inspection.all_day_count}",
        f"timed count: {inspection.timed_count}",
        f"date range: {first_date} to {last_date}",
        f"DTEND-present count: {inspection.dtend_present_count}",
        f"SUMMARY-present count: {inspection.summary_present_count}",
        f"DESCRIPTION-present count: {inspection.description_present_count}",
        f"DTSTAMP-present count: {inspection.dtstamp_present_count}",
        f"RRULE count: {inspection.rrule_count}",
        f"RECURRENCE-ID count: {inspection.recurrence_id_count}",
        f"fatal count: {inspection.fatal_count}",
        f"source valid: {'yes' if inspection.source_valid else 'no'}",
        f"report hash: {report_hash}",
    ]
    if inspection.findings:
        lines.append("findings:")
        for finding in inspection.findings:
            event_suffix = f" [{finding.event_ref}]" if finding.event_ref else ""
            lines.append(f"- {finding.severity} {finding.code}{event_suffix}: {finding.message}")
    return "\n".join(lines) + "\n"


__all__ = ["build_json_report", "render_json_report", "render_text_report"]
