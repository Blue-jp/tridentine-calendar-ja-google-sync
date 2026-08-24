from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field

from phase5a_helpers import make_test_target_config

from tridentine_calendar_google_sync.test_write_target import TestWriteTargetConfig

SYNTHETIC_PREWRITE_CALENDAR_ID = "fixture-test-prewrite@example.invalid"
SYNTHETIC_PREWRITE_SUMMARY = "Synthetic Test Prewrite Calendar"


def make_prewrite_target_config() -> TestWriteTargetConfig:
    return make_test_target_config(
        calendar_id=SYNTHETIC_PREWRITE_CALENDAR_ID,
        expected_summary=SYNTHETIC_PREWRITE_SUMMARY,
    )


def prewrite_page(
    items: list[Mapping[str, object]] | None = None,
    *,
    next_page_token: str | None = None,
    summary: str = SYNTHETIC_PREWRITE_SUMMARY,
    time_zone: str = "Asia/Tokyo",
    access_role: str = "owner",
) -> dict[str, object]:
    page: dict[str, object] = {
        "summary": summary,
        "timeZone": time_zone,
        "accessRole": access_role,
        "items": list(items or []),
    }
    if next_page_token is not None:
        page["nextPageToken"] = next_page_token
    return page


def prewrite_event(**overrides: object) -> dict[str, object]:
    event: dict[str, object] = {
        "id": "evtfixtureprewrite001",
        "iCalUID": "fixture-prewrite-001@example.invalid",
        "summary": "Synthetic prewrite event",
        "description": "Synthetic prewrite description",
        "start": {"date": "2026-09-01"},
        "end": {"date": "2026-09-02"},
        "status": "confirmed",
        "eventType": "default",
        "etag": "fixture-etag-prewrite-001",
        "sequence": 0,
    }
    event.update(overrides)
    return event


@dataclass
class SequencePrewriteClient:
    responses: list[object]
    calls: list[tuple[str, str | None]] = field(default_factory=list)

    def list_events(
        self,
        *,
        calendar_id: str,
        page_token: str | None,
    ) -> Mapping[str, object]:
        self.calls.append((calendar_id, page_token))
        if not self.responses:
            raise AssertionError("synthetic prewrite response sequence exhausted")
        value = self.responses.pop(0)
        if isinstance(value, BaseException):
            raise value
        assert isinstance(value, Mapping)
        return value
