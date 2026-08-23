from __future__ import annotations

from collections.abc import Mapping
from datetime import date
from typing import Any

from tridentine_calendar_google_sync.google_target import calendar_id_fingerprint
from tridentine_calendar_google_sync.test_write_models import TestWriteManagedState
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetConfig,
    TestWriteTargetObservation,
)

SYNTHETIC_TEST_CALENDAR_ID = "fixture-test-calendar@example.invalid"
SYNTHETIC_TEST_SUMMARY = "Synthetic Test Calendar"
SYNTHETIC_UID = "fixture-test-write-001@example.invalid"
SYNTHETIC_EVENT_ID = "evtfixturetestwrite001"
SYNTHETIC_ETAG = "fixture-etag-test-write-001"


def make_test_target_config(**overrides: Any) -> TestWriteTargetConfig:
    calendar_id = str(overrides.pop("calendar_id", SYNTHETIC_TEST_CALENDAR_ID))
    values: dict[str, Any] = {
        "schema_version": 1,
        "target_environment": "test",
        "target_label": "test",
        "target_purpose": "test_calendar_write_acceptance",
        "calendar_id": calendar_id,
        "expected_target_fingerprint": calendar_id_fingerprint(calendar_id),
        "expected_summary": SYNTHETIC_TEST_SUMMARY,
        "expected_access_role": "owner",
        "expected_time_zone": "Asia/Tokyo",
    }
    values.update(overrides)
    return TestWriteTargetConfig.model_validate(values, strict=True)


def make_test_target_observation(**overrides: Any) -> TestWriteTargetObservation:
    values: dict[str, Any] = {
        "summary": SYNTHETIC_TEST_SUMMARY,
        "access_role": "owner",
        "time_zone": "Asia/Tokyo",
    }
    values.update(overrides)
    return TestWriteTargetObservation.model_validate(values, strict=True)


def managed_state(**overrides: Any) -> TestWriteManagedState:
    values: dict[str, Any] = {
        "ical_uid": SYNTHETIC_UID,
        "summary": "Synthetic Test Event",
        "description": "Synthetic test description",
        "start_date": date(2026, 6, 1),
        "end_date": date(2026, 6, 2),
        "all_day": True,
        "event_type": "default",
    }
    values.update(overrides)
    return TestWriteManagedState.model_validate(values, strict=True)


def google_event_response(**overrides: Any) -> Mapping[str, object]:
    values: dict[str, object] = {
        "id": SYNTHETIC_EVENT_ID,
        "iCalUID": SYNTHETIC_UID,
        "summary": "Synthetic Test Event",
        "description": "Synthetic test description",
        "start": {"date": "2026-06-01"},
        "end": {"date": "2026-06-02"},
        "status": "confirmed",
        "eventType": "default",
        "etag": SYNTHETIC_ETAG,
    }
    values.update(overrides)
    return values
