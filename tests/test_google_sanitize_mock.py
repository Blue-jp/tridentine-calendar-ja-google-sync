from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path

import pytest

from tridentine_calendar_google_sync.google_errors import SafeGoogleError
from tridentine_calendar_google_sync.google_fetch import FetchedGooglePages
from tridentine_calendar_google_sync.google_sanitize import (
    PRIVATE_EXTENDED_PROPERTY_PREFIX,
    render_sanitized_snapshot,
    sanitize_fetched_pages,
    snapshot_document,
)
from tridentine_calendar_google_sync.google_snapshot import (
    GoogleSnapshotParseError,
    parse_google_snapshot_bytes,
)
from tridentine_calendar_google_sync.safe_refs import safe_uid_ref

pytestmark = pytest.mark.google_read
TARGET_FINGERPRINT = "d" * 64
CAPTURED_AT = datetime(2026, 8, 23, 0, 0, tzinfo=UTC)


def _scenario(fixtures: Path, name: str) -> dict[str, object]:
    return json.loads((fixtures / f"{name}.json").read_text(encoding="utf-8"))


def _fetched(responses: list[Mapping[str, object]], *, retry_count: int = 0):
    item_count = 0
    for page in responses:
        items = page.get("items", [])
        if isinstance(items, list):
            item_count += len(items)
    return FetchedGooglePages(
        target_fingerprint=TARGET_FINGERPRINT,
        pages=tuple(responses),
        page_count=len(responses),
        item_count=item_count,
        retry_count=retry_count,
        refreshed_after_401=False,
        collection_metadata_hash="f" * 64,
    )


def _responses(fixtures: Path, name: str) -> list[Mapping[str, object]]:
    value = _scenario(fixtures, name)["responses"]
    assert isinstance(value, list)
    assert all(isinstance(page, Mapping) for page in value)
    return value


def test_one_page_sanitizes_to_complete_snapshot_with_fetch_metadata(
    google_api_pages_dir: Path,
) -> None:
    fetched = _fetched(_responses(google_api_pages_dir, "one_page"), retry_count=2)
    snapshot = sanitize_fetched_pages(fetched, captured_at=CAPTURED_AT)

    assert snapshot.complete is True
    assert snapshot.event_count == 1
    assert snapshot.page_count == 1
    assert fetched.retry_count == 2
    assert not hasattr(snapshot, "retry_count")
    assert snapshot.collection_metadata_hash == "f" * 64
    assert snapshot.events[0].summary == "Synthetic API observance"
    assert snapshot.events[0].description == "Safe synthetic API description"
    assert snapshot.forbidden_field_count >= 1


def test_exact_text_whitespace_unicode_and_newline_are_preserved() -> None:
    exact_summary = "  架空　ＡＢＣ  "  # noqa: RUF001 - exact full-width text is intentional
    exact_description = " first\nsecond é and é "
    page = {
        "items": [
            {
                "id": "evtfixtureexacttext001",
                "iCalUID": "fixture-exact-text@example.invalid",
                "summary": exact_summary,
                "description": exact_description,
                "start": {"date": "2026-08-01"},
                "end": {"date": "2026-08-02"},
                "status": "confirmed",
                "eventType": "default",
            }
        ]
    }

    snapshot = sanitize_fetched_pages(_fetched([page]), captured_at=CAPTURED_AT)

    assert snapshot.events[0].summary == exact_summary
    assert snapshot.events[0].description == exact_description


def test_forbidden_raw_fields_are_counted_and_dropped() -> None:
    forbidden_values = (
        "synthetic-html-link-value",
        "synthetic-attendee-value",
        "synthetic-conference-value",
    )
    page = {
        "items": [
            {
                "id": "evtfixtureforbidden001",
                "iCalUID": "fixture-forbidden@example.invalid",
                "summary": "Synthetic forbidden-field event",
                "description": "Safe description",
                "start": {"date": "2026-08-02"},
                "end": {"date": "2026-08-03"},
                "status": "confirmed",
                "eventType": "default",
                "htmlLink": forbidden_values[0],
                "attendees": [forbidden_values[1]],
                "conferenceData": forbidden_values[2],
                "creator": {"self": True},
                "organizer": {"self": True},
            }
        ]
    }

    snapshot = sanitize_fetched_pages(_fetched([page]), captured_at=CAPTURED_AT)
    rendered = render_sanitized_snapshot(snapshot).decode("utf-8")

    assert snapshot.forbidden_field_count == 5
    assert snapshot.events[0].html_link_present is False
    assert snapshot.events[0].creator is None
    assert snapshot.events[0].organizer is None
    for forbidden_value in forbidden_values:
        assert forbidden_value not in rendered


def test_only_namespaced_private_marker_is_retained(
    google_api_pages_dir: Path,
) -> None:
    snapshot = sanitize_fetched_pages(
        _fetched(_responses(google_api_pages_dir, "unknown_extended")),
        captured_at=CAPTURED_AT,
    )
    event = snapshot.events[0]
    rendered = render_sanitized_snapshot(snapshot).decode("utf-8")

    assert PRIVATE_EXTENDED_PROPERTY_PREFIX == "tridentine_calendar_google_sync."
    assert event.extended_properties is not None
    assert event.extended_properties.private == (
        ("tridentine_calendar_google_sync.managed", "true"),
    )
    assert event.extended_properties.shared == ()
    assert snapshot.dropped_private_extended_property_count == 1
    assert snapshot.dropped_shared_extended_property_count == 1
    assert snapshot.forbidden_field_count == 1
    assert "fixture-private-key" not in rendered
    assert "fixture-shared-key" not in rendered
    assert "discard-this-field" not in rendered


def test_event_order_and_snapshot_hash_are_deterministic() -> None:
    events = [
        {
            "id": "evtfixtureorder002",
            "iCalUID": "fixture-order-002@example.invalid",
            "start": {"date": "2026-08-02"},
            "end": {"date": "2026-08-03"},
            "status": "confirmed",
            "eventType": "default",
        },
        {
            "id": "evtfixtureorder001",
            "iCalUID": "fixture-order-001@example.invalid",
            "start": {"date": "2026-08-01"},
            "end": {"date": "2026-08-02"},
            "status": "confirmed",
            "eventType": "default",
        },
    ]
    first = sanitize_fetched_pages(_fetched([{"items": events}]), captured_at=CAPTURED_AT)
    second = sanitize_fetched_pages(
        _fetched([{"items": list(reversed(events))}]),
        captured_at=CAPTURED_AT,
    )

    expected_uids = sorted(
        (
            "fixture-order-001@example.invalid",
            "fixture-order-002@example.invalid",
        ),
        key=safe_uid_ref,
    )
    assert [event.ical_uid for event in first.events] == expected_uids
    assert first.content_hash == second.content_hash
    assert render_sanitized_snapshot(first) == render_sanitized_snapshot(second)


def test_retry_history_is_not_persisted_or_hashed() -> None:
    page = {"items": []}
    first_fetch = _fetched([page], retry_count=0)
    second_fetch = FetchedGooglePages(
        target_fingerprint=TARGET_FINGERPRINT,
        pages=(page,),
        page_count=1,
        item_count=0,
        retry_count=4,
        refreshed_after_401=True,
        collection_metadata_hash="f" * 64,
    )

    first = sanitize_fetched_pages(first_fetch, captured_at=CAPTURED_AT)
    second = sanitize_fetched_pages(second_fetch, captured_at=CAPTURED_AT)
    first_document = snapshot_document(first)

    assert first == second
    assert first.content_hash == second.content_hash
    assert render_sanitized_snapshot(first) == render_sanitized_snapshot(second)
    assert "retry_count" not in first_document
    assert "refreshed_after_401" not in first_document


def test_retry_transport_metadata_does_not_change_snapshot_json_or_hash(
    google_api_pages_dir: Path,
) -> None:
    responses = _responses(google_api_pages_dir, "one_page")
    first = sanitize_fetched_pages(
        _fetched(responses, retry_count=0),
        captured_at=CAPTURED_AT,
    )
    second = sanitize_fetched_pages(
        _fetched(responses, retry_count=4),
        captured_at=CAPTURED_AT,
    )

    assert first.content_hash == second.content_hash
    assert render_sanitized_snapshot(first) == render_sanitized_snapshot(second)


def test_cancelled_special_color_and_label_are_observed(
    google_api_pages_dir: Path,
) -> None:
    cancelled = sanitize_fetched_pages(
        _fetched(_responses(google_api_pages_dir, "cancelled")),
        captured_at=CAPTURED_AT,
    )
    special = sanitize_fetched_pages(
        _fetched(_responses(google_api_pages_dir, "special")),
        captured_at=CAPTURED_AT,
    )
    colored = sanitize_fetched_pages(
        _fetched(_responses(google_api_pages_dir, "color_label")),
        captured_at=CAPTURED_AT,
    )

    assert cancelled.cancelled_event_count == 1
    assert cancelled.events[0].status == "cancelled"
    assert special.events[0].event_type == "focusTime"
    assert special.unknown_event_type_count == 0
    assert colored.events[0].color_id == "6"
    assert colored.events[0].event_label_id == "fixture-label"


def test_unknown_event_type_is_preserved_and_counted() -> None:
    page = {
        "items": [
            {
                "id": "evtfixturefuture001",
                "iCalUID": "fixture-future@example.invalid",
                "start": {"date": "2026-08-01"},
                "end": {"date": "2026-08-02"},
                "status": "confirmed",
                "eventType": "futureSyntheticType",
            }
        ]
    }

    snapshot = sanitize_fetched_pages(_fetched([page]), captured_at=CAPTURED_AT)

    assert snapshot.unknown_event_type_count == 1
    assert snapshot.events[0].event_type == "futureSyntheticType"


def test_missing_icaluid_is_preserved_as_missing() -> None:
    page = {
        "items": [
            {
                "id": "evtfixturemissingical001",
                "start": {"date": "2026-08-01"},
                "end": {"date": "2026-08-02"},
                "status": "confirmed",
                "eventType": "default",
            }
        ]
    }

    snapshot = sanitize_fetched_pages(_fetched([page]), captured_at=CAPTURED_AT)

    assert snapshot.events[0].ical_uid is None
    assert snapshot.events[0].safe_ical_uid_reference is None


def test_cancelled_tombstone_may_omit_boundaries() -> None:
    page = {"items": [{"id": "evtfixturetombstone001", "status": "cancelled"}]}

    snapshot = sanitize_fetched_pages(_fetched([page]), captured_at=CAPTURED_AT)

    event = snapshot.events[0]
    assert event.start is None
    assert event.end is None
    assert event.all_day is None
    assert event.event_type == "default"


def test_duplicate_event_id_is_rejected() -> None:
    event = {
        "id": "evtfixtureduplicateapi001",
        "start": {"date": "2026-08-01"},
        "end": {"date": "2026-08-02"},
        "status": "confirmed",
        "eventType": "default",
    }

    with pytest.raises(GoogleSnapshotParseError) as caught:
        sanitize_fetched_pages(
            _fetched([{"items": [event, dict(event)]}]),
            captured_at=CAPTURED_AT,
        )

    assert caught.value.code == "duplicate_google_event_id"


@pytest.mark.parametrize(
    "event",
    [
        {
            "id": "evtfixturebadshape001",
            "start": {"date": "2026-08-01"},
            "end": {"dateTime": "2026-08-02T00:00:00Z"},
            "status": "confirmed",
            "eventType": "default",
        },
        {
            "id": "evtfixturebadshape002",
            "start": {"date": "2026-08-01", "dateTime": "2026-08-01T00:00:00Z"},
            "end": {"date": "2026-08-02"},
            "status": "confirmed",
            "eventType": "default",
        },
    ],
)
def test_invalid_event_time_shapes_are_rejected(event: dict[str, object]) -> None:
    with pytest.raises(SafeGoogleError) as caught:
        sanitize_fetched_pages(_fetched([{"items": [event]}]), captured_at=CAPTURED_AT)

    assert caught.value.reason == "invalid_response"


def test_naive_capture_timestamp_is_rejected() -> None:
    with pytest.raises(SafeGoogleError):
        sanitize_fetched_pages(
            _fetched([{"items": []}]),
            captured_at=datetime(2026, 8, 23),
        )


def test_rendered_snapshot_round_trips_through_strict_parser(
    google_api_pages_dir: Path,
) -> None:
    snapshot = sanitize_fetched_pages(
        _fetched(_responses(google_api_pages_dir, "one_page")),
        captured_at=CAPTURED_AT,
    )
    rendered = render_sanitized_snapshot(snapshot)

    reparsed = parse_google_snapshot_bytes(rendered)

    assert reparsed == snapshot
    assert json.loads(rendered)["content_hash"] == snapshot.content_hash
    assert snapshot_document(reparsed) == snapshot_document(snapshot)


def test_declared_snapshot_content_hash_is_verified(
    google_api_pages_dir: Path,
) -> None:
    snapshot = sanitize_fetched_pages(
        _fetched(_responses(google_api_pages_dir, "one_page")),
        captured_at=CAPTURED_AT,
    )
    document = json.loads(render_sanitized_snapshot(snapshot))
    document["content_hash"] = "0" * 64

    with pytest.raises(GoogleSnapshotParseError) as caught:
        parse_google_snapshot_bytes(json.dumps(document).encode("utf-8"))

    assert caught.value.code == "google_snapshot_content_hash_mismatch"
