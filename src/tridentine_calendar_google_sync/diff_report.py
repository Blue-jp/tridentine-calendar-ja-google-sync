"""Deterministic privacy-safe human and JSON calendar diff reports."""

from __future__ import annotations

import json

from tridentine_calendar_google_sync.diff_models import (
    CLASSIFICATION_ORDER,
    CalendarDiff,
    EventDiff,
)
from tridentine_calendar_google_sync.provenance import tool_version


def _event_report_data(event: EventDiff) -> dict[str, object]:
    data: dict[str, object] = {
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
    return data


def build_diff_json_report(diff: CalendarDiff) -> dict[str, object]:
    """Build a closed-schema report without raw UID, event ID, content, or paths."""

    events = [_event_report_data(event) for event in diff.events]
    differences = [
        _event_report_data(event)
        for event in diff.events
        if event.classification.value != "unchanged"
    ]
    fatal_errors = [_event_report_data(event) for event in diff.events if event.fatal]
    proposed = [
        {
            "classification": event.classification.value,
            "source_ref": event.source_ref,
            "google_refs": list(event.google_refs),
        }
        for event in diff.events
        if not diff.fatal and event.classification.value in {"add", "update", "delete_candidate"}
    ]
    return {
        "schema_version": "1.0",
        "tool_version": tool_version(),
        "mode": "offline",
        "source": {
            "profile_id": diff.source_profile_id,
            "sha256": diff.source_sha256,
            "sha256_match": diff.source_sha_matches,
            "event_count": diff.source_event_count,
        },
        "target": {
            "fingerprint": diff.target_fingerprint,
            "snapshot_sha256": diff.snapshot_sha256,
            "event_count": diff.google_event_count,
            "complete": diff.snapshot_complete,
        },
        "counts": {
            classification.value: diff.counts.for_classification(classification)
            for classification in CLASSIFICATION_ORDER
        },
        "events": events,
        "differences": differences,
        "warnings": [warning.model_dump(mode="json") for warning in diff.warnings],
        "fatal_errors": fatal_errors,
        "proposed_operations": proposed,
        "fatal": diff.fatal,
        "content_hash": diff.content_hash,
    }


def render_diff_json_report(diff: CalendarDiff) -> str:
    """Render deterministic UTF-8 JSON with no volatile generated timestamp."""

    return (
        json.dumps(
            build_diff_json_report(diff),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )


def render_diff_text_report(diff: CalendarDiff) -> str:
    """Render a compact content-free human diff report."""

    lines = [
        "Offline Google snapshot diff",
        f"tool version: {tool_version()}",
        "mode: offline",
        f"source profile: {diff.source_profile_id}",
        f"source SHA-256: {diff.source_sha256}",
        f"source SHA match: {'yes' if diff.source_sha_matches else 'no'}",
        f"source event count: {diff.source_event_count}",
        f"target fingerprint: T-{diff.target_fingerprint[:12]}",
        f"snapshot SHA-256: {diff.snapshot_sha256}",
        f"Google event count: {diff.google_event_count}",
        f"snapshot complete: {'yes' if diff.snapshot_complete else 'no'}",
    ]
    lines.extend(
        f"{classification.value}: {diff.counts.for_classification(classification)}"
        for classification in CLASSIFICATION_ORDER
    )
    changed_field_counts = {
        field: sum(
            difference.field == field for event in diff.events for difference in event.differences
        )
        for field in ("summary", "description", "start_date", "end_date")
    }
    lines.extend(
        f"changed field {field}: {changed_field_counts[field]}"
        for field in ("summary", "description", "start_date", "end_date")
    )
    lines.extend(
        (
            f"fatal: {'yes' if diff.fatal else 'no'}",
            f"content hash: {diff.content_hash}",
        )
    )
    if diff.events:
        lines.append("events:")
        for event in diff.events:
            references = ",".join(
                value for value in (event.source_ref, *event.google_refs) if value is not None
            )
            difference_fields = ",".join(difference.field for difference in event.differences)
            reasons = ",".join(event.reason_codes)
            details = "; ".join(
                value
                for value in (
                    f"refs={references}" if references else "",
                    f"source_date={event.source_date.isoformat()}" if event.source_date else "",
                    f"google_date={event.google_date.isoformat()}" if event.google_date else "",
                    f"fields={difference_fields}" if difference_fields else "",
                    f"reasons={reasons}" if reasons else "",
                )
                if value
            )
            suffix = f" ({details})" if details else ""
            lines.append(f"- {event.classification.value}{suffix}")
    if diff.warnings:
        lines.append("warnings:")
        for warning in diff.warnings:
            safe_ref = warning.source_ref or warning.google_ref
            suffix = f" [{safe_ref}]" if safe_ref else ""
            lines.append(f"- {warning.code}{suffix}: {warning.message}")
    return "\n".join(lines) + "\n"


render_diff_report = render_diff_text_report


__all__ = [
    "build_diff_json_report",
    "render_diff_json_report",
    "render_diff_report",
    "render_diff_text_report",
]
