from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from conftest import PROFILES_DIR

from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.diff_report import render_diff_json_report
from tridentine_calendar_google_sync.google_snapshot import parse_google_snapshot_bytes
from tridentine_calendar_google_sync.models import SourceCalendarInspection
from tridentine_calendar_google_sync.profiles import load_profile
from tridentine_calendar_google_sync.source_ics import inspect_source


def _memory_snapshot_document(
    inspection: SourceCalendarInspection,
) -> dict[str, object]:
    events: list[dict[str, object]] = []
    for index, event in enumerate(inspection.events):
        if event.uid is None or event.start_date is None or event.effective_end_date is None:
            pytest.fail("Accepted source contains an unsupported event shape")
        events.append(
            {
                "id": f"evtfixtureintegration{index:04d}",
                "iCalUID": event.uid,
                "summary": event.summary,
                "description": event.description,
                "start": {"date": event.start_date.isoformat()},
                "end": {"date": event.effective_end_date.isoformat()},
                "allDay": True,
                "status": "confirmed",
                "eventType": "default",
            }
        )
    return {
        "schema_version": "1.0",
        "snapshot_format": "sanitized-google-calendar-v1",
        "target_fingerprint": "c" * 64,
        "complete": True,
        "event_count": len(events),
        "page_count": 1,
        "events": events,
    }


def _parse_memory_document(document: dict[str, object]):
    raw = json.dumps(document, ensure_ascii=False).encode("utf-8")
    return parse_google_snapshot_bytes(raw)


@pytest.mark.integration
def test_full_accepted_source_offline_diff_scale_and_single_mutation(tmp_path: Path) -> None:
    configured_path = os.environ.get("TRIDENTINE_ACCEPTED_HTML_ICS_PATH")
    if not configured_path:
        pytest.skip("Accepted HTML ICS path is not configured")

    profile = load_profile("accepted-20260814", profiles_dir=PROFILES_DIR)
    try:
        inspection = inspect_source(Path(configured_path), profile)
        document = _memory_snapshot_document(inspection)
        exact_snapshot = _parse_memory_document(document)
        exact_diff = diff_source_to_snapshot(inspection, exact_snapshot)
    except Exception as exc:  # Broad catch deliberately redacts Production content and path.
        pytest.fail(f"Offline Accepted scale validation failed safely: {type(exc).__name__}")

    if not inspection.source_valid or inspection.vevent_count != 4938:
        pytest.fail("Accepted source aggregate did not match the pinned profile")
    if exact_diff.counts.unchanged != 4938 or exact_diff.has_changes:
        pytest.fail("Exact in-memory snapshot did not produce 4938 unchanged events")
    if any(
        (
            exact_diff.counts.add,
            exact_diff.counts.update,
            exact_diff.counts.delete_candidate,
            exact_diff.counts.unmanaged_google_event,
            exact_diff.counts.ambiguous,
            exact_diff.counts.duplicate_source_uid,
            exact_diff.counts.duplicate_google_icaluid,
            exact_diff.counts.invalid_source,
            exact_diff.counts.fatal_guard,
        )
    ):
        pytest.fail("Exact in-memory snapshot produced an unexpected classification")
    if exact_diff.fatal:
        pytest.fail("Exact in-memory snapshot unexpectedly triggered a fatal guard")

    first_event = document["events"][0]  # type: ignore[index]
    first_event["summary"] = "Synthetic integration mutation"
    try:
        mutated_snapshot = _parse_memory_document(document)
        mutated_diff = diff_source_to_snapshot(inspection, mutated_snapshot)
        rendered = render_diff_json_report(mutated_diff)
    except Exception as exc:  # Broad catch deliberately redacts Production content and path.
        pytest.fail(f"Offline mutation validation failed safely: {type(exc).__name__}")

    if mutated_diff.counts.unchanged != 4937 or mutated_diff.counts.update != 1:
        pytest.fail("Single in-memory mutation did not produce the expected aggregate")
    if any(
        (
            mutated_diff.counts.add,
            mutated_diff.counts.delete_candidate,
            mutated_diff.counts.unmanaged_google_event,
            mutated_diff.counts.ambiguous,
            mutated_diff.counts.duplicate_source_uid,
            mutated_diff.counts.duplicate_google_icaluid,
            mutated_diff.counts.invalid_source,
            mutated_diff.counts.fatal_guard,
        )
    ):
        pytest.fail("Single mutation produced an unexpected classification")
    if mutated_diff.fatal:
        pytest.fail("Single safe mutation unexpectedly triggered a fatal guard")

    source_event = inspection.events[0]
    sensitive_values = tuple(
        value
        for value in (source_event.uid, source_event.summary, source_event.description)
        if value
    )
    if any(value in rendered for value in sensitive_values):
        pytest.fail("Diff report exposed raw Accepted event content")
    if configured_path in rendered:
        pytest.fail("Diff report exposed the configured Accepted asset path")
    if list(tmp_path.iterdir()):
        pytest.fail("Offline scale test persisted an unexpected snapshot file")
