from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from conftest import build_synthetic_profile
from phase5a1_helpers import SequencePrewriteClient, prewrite_page
from phase5a_helpers import SYNTHETIC_TEST_SUMMARY, make_test_target_config

from tridentine_calendar_google_sync.baseline_engine import (
    baseline_confirmation_phrase,
    build_baseline_candidate,
    trust_baseline,
)
from tridentine_calendar_google_sync.baseline_models import TrustedBaseline
from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.google_snapshot import parse_google_snapshot_bytes
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.source_ics import inspect_source
from tridentine_calendar_google_sync.test_calendar_prewrite import (
    calculate_test_calendar_prewrite_snapshot_hash,
    inspect_test_calendar_prewrite,
    verify_test_calendar_prewrite_snapshot,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_models import (
    TestCalendarPrewriteSnapshot,
)
from tridentine_calendar_google_sync.test_single_update_plan import (
    build_test_single_update_plan,
)
from tridentine_calendar_google_sync.test_single_update_plan_models import (
    TestSingleUpdatePlan,
)
from tridentine_calendar_google_sync.test_write_target import TestWriteTargetConfig

SINGLE_UPDATE_UID = "fixture-single-update-001@example.invalid"
SINGLE_UPDATE_SUMMARY = "Synthetic Test single update event"
CURRENT_DESCRIPTION = "Synthetic current Description"
UPDATED_DESCRIPTION = "Synthetic updated Description"
SINGLE_UPDATE_EVENT_ID = "evtfixturesingleupdate001"
SINGLE_UPDATE_ETAG = "fixture-etag-single-update-001"


@dataclass(frozen=True)
class SingleUpdateBundle:
    current_path: Path
    updated_path: Path
    current_profile: AcceptedSourceProfile
    updated_profile: AcceptedSourceProfile
    current_source: SourceCalendarInspection
    updated_source: SourceCalendarInspection
    prewrite_snapshot: TestCalendarPrewriteSnapshot
    baseline: TrustedBaseline
    target: TestWriteTargetConfig
    plan: TestSingleUpdatePlan


def single_update_ics_bytes(
    description: str,
    *,
    uid: str = SINGLE_UPDATE_UID,
    summary: str = SINGLE_UPDATE_SUMMARY,
) -> bytes:
    lines = (
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Synthetic Single Update Test//EN",
        "BEGIN:VEVENT",
        f"UID:{uid}",
        "DTSTAMP:20260101T000000Z",
        "DTSTART;VALUE=DATE:20260115",
        f"SUMMARY:{summary}",
        f"DESCRIPTION:{description}",
        "END:VEVENT",
        "END:VCALENDAR",
    )
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def single_update_snapshot_document(
    target_fingerprint: str,
    **event_overrides: Any,
) -> dict[str, object]:
    event: dict[str, object] = {
        "id": SINGLE_UPDATE_EVENT_ID,
        "iCalUID": SINGLE_UPDATE_UID,
        "summary": SINGLE_UPDATE_SUMMARY,
        "description": CURRENT_DESCRIPTION,
        "start": {"date": "2026-01-15"},
        "end": {"date": "2026-01-16"},
        "allDay": True,
        "status": "confirmed",
        "eventType": "default",
        "etag": SINGLE_UPDATE_ETAG,
    }
    event.update(event_overrides)
    return {
        "schema_version": "1.0",
        "snapshot_format": "sanitized-google-calendar-v1",
        "target_fingerprint": target_fingerprint,
        "complete": True,
        "event_count": 1,
        "page_count": 1,
        "events": [event],
    }


def wrap_test_snapshot(document: dict[str, object]) -> TestCalendarPrewriteSnapshot:
    nested = parse_google_snapshot_bytes(json.dumps(document, ensure_ascii=False).encode("utf-8"))
    provisional = TestCalendarPrewriteSnapshot(
        target_fingerprint=nested.target_fingerprint,
        target_safe_ref=f"T-{nested.target_fingerprint[:12]}",
        page_count=1,
        api_call_count=1,
        retry_count=0,
        snapshot=nested,
        snapshot_content_hash=nested.content_hash,
        wrapper_content_hash="0" * 64,
    )
    wrapped = provisional.model_copy(
        update={"wrapper_content_hash": calculate_test_calendar_prewrite_snapshot_hash(provisional)}
    )
    verify_test_calendar_prewrite_snapshot(wrapped)
    return wrapped


def build_single_update_prewrite_snapshot(
    target: TestWriteTargetConfig,
    **event_overrides: Any,
) -> TestCalendarPrewriteSnapshot:
    document = single_update_snapshot_document(
        target.expected_target_fingerprint,
        **event_overrides,
    )
    events = document["events"]
    assert isinstance(events, list) and len(events) == 1
    raw_event_value = events[0]
    assert isinstance(raw_event_value, dict)
    raw_event = dict(raw_event_value)
    raw_event.pop("allDay", None)
    return inspect_test_calendar_prewrite(
        SequencePrewriteClient([prewrite_page([raw_event], summary=target.expected_summary)]),
        target,
        captured_at=datetime(2026, 1, 1, tzinfo=UTC),
        sleep=lambda _delay: None,
        jitter=lambda _maximum: 0.0,
    ).snapshot


def build_single_update_bundle(tmp_path: Path) -> SingleUpdateBundle:
    tmp_path.mkdir(parents=True, exist_ok=True)
    current_path = tmp_path / "current.ics"
    updated_path = tmp_path / "updated.ics"
    current_path.write_bytes(single_update_ics_bytes(CURRENT_DESCRIPTION))
    updated_path.write_bytes(single_update_ics_bytes(UPDATED_DESCRIPTION))
    current_profile = build_synthetic_profile(current_path)
    updated_profile = build_synthetic_profile(updated_path)
    current_source = inspect_source(current_path, current_profile)
    updated_source = inspect_source(updated_path, updated_profile)
    target = make_test_target_config(expected_summary=SYNTHETIC_TEST_SUMMARY)
    prewrite_snapshot = build_single_update_prewrite_snapshot(target)
    current_diff = diff_source_to_snapshot(current_source, prewrite_snapshot.snapshot)
    candidate = build_baseline_candidate(
        current_profile,
        current_source,
        prewrite_snapshot.snapshot,
        current_diff,
    )
    baseline = trust_baseline(candidate, baseline_confirmation_phrase(candidate))
    plan = build_test_single_update_plan(
        updated_profile,
        updated_source,
        prewrite_snapshot,
        baseline,
        target,
    )
    return SingleUpdateBundle(
        current_path=current_path,
        updated_path=updated_path,
        current_profile=current_profile,
        updated_profile=updated_profile,
        current_source=current_source,
        updated_source=updated_source,
        prewrite_snapshot=prewrite_snapshot,
        baseline=baseline,
        target=target,
        plan=plan,
    )


def write_test_target_config(target: TestWriteTargetConfig, path: Path) -> Path:
    path.write_text(
        "\n".join(
            (
                f"schema_version = {target.schema_version}",
                f'target_environment = "{target.target_environment}"',
                f'target_label = "{target.target_label}"',
                f'target_purpose = "{target.target_purpose}"',
                f'calendar_id = "{target.calendar_id}"',
                (f'expected_target_fingerprint = "{target.expected_target_fingerprint}"'),
                f'expected_summary = "{target.expected_summary}"',
                f'expected_access_role = "{target.expected_access_role}"',
                f'expected_time_zone = "{target.expected_time_zone}"',
                "",
            )
        ),
        encoding="utf-8",
        newline="\n",
    )
    return path
