"""Deterministic aggregate-only reports for Test Calendar prewrite inspection."""

from __future__ import annotations

import json

from tridentine_calendar_google_sync.test_calendar_prewrite import (
    TestCalendarPrewriteResult,
    verify_test_calendar_prewrite_result,
)


def build_test_calendar_prewrite_json_report(
    result: TestCalendarPrewriteResult,
) -> dict[str, object]:
    """Return the verified public-safe report document."""

    verify_test_calendar_prewrite_result(result)
    return result.report.model_dump(mode="json")


def render_test_calendar_prewrite_json_report(
    result: TestCalendarPrewriteResult,
) -> str:
    """Render deterministic JSON without event identity or content."""

    return (
        json.dumps(
            build_test_calendar_prewrite_json_report(result),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def render_test_calendar_prewrite_text_report(
    result: TestCalendarPrewriteResult,
) -> str:
    """Render aggregate Test readiness using safe references only."""

    report = result.report
    verify_test_calendar_prewrite_result(result)
    lines = [
        "Test Calendar read-only prewrite inspection",
        "read only: yes",
        "Test Calendar only: yes",
        "Production locked: yes",
        "Google API method: events.list only",
        "Google Calendar writes: 0",
        "Google Calendar event changes: 0",
        f"target reference: {report.target_safe_ref}",
        f"scope: {report.scope_label}",
        f"target metadata: {report.target_metadata_validation}",
        f"snapshot complete: {'yes' if report.snapshot_complete else 'no'}",
        f"prewrite ready: {'yes' if report.prewrite_ready else 'no'}",
        f"events: {report.event_count}",
        f"cancelled: {report.cancelled_count}",
        f"recurring: {report.recurring_count}",
        f"timed: {report.timed_count}",
        f"non-default event types: {report.non_default_event_type_count}",
        f"event colors: {report.color_id_count}",
        f"event labels: {report.event_label_id_count}",
        f"pages: {report.page_count}",
        f"API calls: {report.api_call_count}",
        f"read retries: {report.retry_count}",
        f"snapshot hash: {report.snapshot_hash}",
    ]
    if report.findings:
        lines.append("safe findings:")
        lines.extend(
            f"- {finding.severity}: {finding.code}: {finding.message}"
            for finding in report.findings
        )
    else:
        lines.append("safe findings: none")
    lines.append(f"report hash: {report.report_content_hash}")
    return "\n".join(lines) + "\n"


__all__ = [
    "build_test_calendar_prewrite_json_report",
    "render_test_calendar_prewrite_json_report",
    "render_test_calendar_prewrite_text_report",
]
