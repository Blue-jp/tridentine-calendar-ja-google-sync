"""Explicit allowlist sanitizer from raw API pages to local snapshot models."""

from __future__ import annotations

import json
from collections.abc import Mapping
from datetime import datetime

from tridentine_calendar_google_sync.google_errors import SafeGoogleError
from tridentine_calendar_google_sync.google_fetch import FetchedGooglePages
from tridentine_calendar_google_sync.google_models import (
    CanonicalGoogleEvent,
    GoogleEventTime,
    GoogleSnapshot,
)
from tridentine_calendar_google_sync.google_snapshot import parse_google_snapshot_bytes
from tridentine_calendar_google_sync.safe_refs import safe_google_event_ref, safe_uid_ref

PRIVATE_EXTENDED_PROPERTY_PREFIX = "tridentine_calendar_google_sync."
_KNOWN_EVENT_TYPES = frozenset(
    {
        "birthday",
        "default",
        "focusTime",
        "fromGmail",
        "outOfOffice",
        "workingLocation",
    }
)
_RAW_EVENT_KEYS = frozenset(
    {
        "colorId",
        "description",
        "end",
        "endTimeUnspecified",
        "etag",
        "eventLabelId",
        "eventType",
        "extendedProperties",
        "iCalUID",
        "id",
        "location",
        "locked",
        "originalStartTime",
        "privateCopy",
        "recurrence",
        "recurringEventId",
        "reminders",
        "sequence",
        "start",
        "status",
        "summary",
        "transparency",
        "visibility",
    }
)


def _sanitize_error() -> SafeGoogleError:
    return SafeGoogleError(
        status=None,
        reason="invalid_response",
        retryable=False,
        attempt=1,
        operation="snapshot.sanitize",
    )


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise _sanitize_error()
    return value


def _required_string(value: object) -> str:
    result = _optional_string(value)
    if not result:
        raise _sanitize_error()
    return result


def _optional_boolean(value: object, *, default: bool = False) -> bool:
    if value is None:
        return default
    if not isinstance(value, bool):
        raise _sanitize_error()
    return value


def _sanitize_time(value: object) -> tuple[dict[str, str], int]:
    if not isinstance(value, Mapping):
        raise _sanitize_error()
    date_value = value.get("date")
    date_time_value = value.get("dateTime")
    if (date_value is None) == (date_time_value is None):
        raise _sanitize_error()
    if date_value is not None:
        result = {"date": _required_string(date_value)}
    else:
        result = {"dateTime": _required_string(date_time_value)}
    forbidden_count = sum(key not in {"date", "dateTime"} for key in value)
    return result, forbidden_count


def _sanitize_reminders(value: object) -> tuple[dict[str, object] | None, int]:
    if value is None:
        return None, 0
    if not isinstance(value, Mapping):
        raise _sanitize_error()
    use_default = value.get("useDefault")
    if not isinstance(use_default, bool):
        raise _sanitize_error()
    result: dict[str, object] = {"useDefault": use_default}
    overrides = value.get("overrides", [])
    if not isinstance(overrides, list):
        raise _sanitize_error()
    sanitized_overrides: list[dict[str, object]] = []
    forbidden_count = sum(key not in {"useDefault", "overrides"} for key in value)
    for override in overrides:
        if not isinstance(override, Mapping):
            raise _sanitize_error()
        method = _required_string(override.get("method"))
        minutes = override.get("minutes")
        if not isinstance(minutes, int) or isinstance(minutes, bool) or minutes < 0:
            raise _sanitize_error()
        sanitized_overrides.append({"method": method, "minutes": minutes})
        forbidden_count += sum(key not in {"method", "minutes"} for key in override)
    if sanitized_overrides:
        result["overrides"] = sanitized_overrides
    return result, forbidden_count


def _sanitize_extended_properties(
    value: object,
) -> tuple[dict[str, object] | None, int, int, int]:
    if value is None:
        return None, 0, 0, 0
    if not isinstance(value, Mapping):
        raise _sanitize_error()
    forbidden_count = sum(key not in {"private", "shared"} for key in value)
    private_value = value.get("private", {})
    shared_value = value.get("shared", {})
    if not isinstance(private_value, Mapping) or not isinstance(shared_value, Mapping):
        raise _sanitize_error()
    retained_private: dict[str, str] = {}
    dropped_private = 0
    for key, item in private_value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise _sanitize_error()
        if key.startswith(PRIVATE_EXTENDED_PROPERTY_PREFIX):
            retained_private[key] = item
        else:
            dropped_private += 1
    dropped_shared = 0
    for key, item in shared_value.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise _sanitize_error()
        dropped_shared += 1
    if not retained_private:
        return None, dropped_private, dropped_shared, forbidden_count
    return (
        {"private": dict(sorted(retained_private.items()))},
        dropped_private,
        dropped_shared,
        forbidden_count,
    )


def _sanitize_event(raw: Mapping[str, object]) -> tuple[dict[str, object], tuple[int, int, int]]:
    event_id = _required_string(raw.get("id"))
    status = _required_string(raw.get("status"))
    event_type_value = raw.get("eventType")
    event_type = (
        "default"
        if status == "cancelled" and event_type_value is None
        else _required_string(event_type_value)
    )
    result: dict[str, object] = {
        "id": event_id,
        "status": status,
        "eventType": event_type,
        "endTimeUnspecified": _optional_boolean(raw.get("endTimeUnspecified")),
        "locked": _optional_boolean(raw.get("locked")),
        "privateCopy": _optional_boolean(raw.get("privateCopy")),
    }
    forbidden_count = sum(key not in _RAW_EVENT_KEYS for key in raw)
    start_value = raw.get("start")
    end_value = raw.get("end")
    if start_value is None or end_value is None:
        if status != "cancelled" or start_value is not None or end_value is not None:
            raise _sanitize_error()
    else:
        start, start_forbidden = _sanitize_time(start_value)
        end, end_forbidden = _sanitize_time(end_value)
        if ("date" in start) != ("date" in end):
            raise _sanitize_error()
        result["start"] = start
        result["end"] = end
        result["allDay"] = "date" in start
        forbidden_count += start_forbidden + end_forbidden

    for key in (
        "iCalUID",
        "summary",
        "description",
        "etag",
        "recurringEventId",
        "transparency",
        "visibility",
        "colorId",
        "eventLabelId",
        "location",
    ):
        value = _optional_string(raw.get(key))
        if value is not None:
            result[key] = value

    sequence = raw.get("sequence")
    if sequence is not None:
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 0:
            raise _sanitize_error()
        result["sequence"] = sequence
    recurrence = raw.get("recurrence")
    if recurrence is not None:
        if not isinstance(recurrence, list) or not all(
            isinstance(item, str) for item in recurrence
        ):
            raise _sanitize_error()
        result["recurrence"] = list(recurrence)
    original_start = raw.get("originalStartTime")
    if original_start is not None:
        sanitized_original_start, original_forbidden = _sanitize_time(original_start)
        result["originalStartTime"] = sanitized_original_start
        forbidden_count += original_forbidden
    reminders, reminders_forbidden = _sanitize_reminders(raw.get("reminders"))
    if reminders is not None:
        result["reminders"] = reminders
    forbidden_count += reminders_forbidden
    extended, dropped_private, dropped_shared, extended_forbidden = _sanitize_extended_properties(
        raw.get("extendedProperties")
    )
    if extended is not None:
        result["extendedProperties"] = extended
    forbidden_count += extended_forbidden
    return result, (dropped_private, dropped_shared, forbidden_count)


def _raw_items(fetched: FetchedGooglePages) -> list[Mapping[str, object]]:
    items: list[Mapping[str, object]] = []
    for page in fetched.pages:
        page_items = page.get("items", [])
        if not isinstance(page_items, list):
            raise _sanitize_error()
        for item in page_items:
            if not isinstance(item, Mapping):
                raise _sanitize_error()
            items.append(item)
    if len(items) != fetched.item_count:
        raise _sanitize_error()
    return items


def _safe_event_sort_key(event: Mapping[str, object]) -> tuple[str, str, str, str]:
    start = event.get("start")
    start_date = ""
    start_date_time = ""
    if isinstance(start, Mapping):
        start_date = str(start.get("date", ""))
        start_date_time = str(start.get("dateTime", ""))
    ical_uid = event.get("iCalUID")
    return (
        safe_uid_ref(str(ical_uid)) if ical_uid is not None else "U-000000000000",
        start_date,
        start_date_time,
        safe_google_event_ref(str(event["id"])),
    )


def sanitize_fetched_pages(
    fetched: FetchedGooglePages,
    *,
    captured_at: datetime,
) -> GoogleSnapshot:
    """Sanitize all fetched pages through an explicit field and property allowlist."""

    if captured_at.tzinfo is None:
        raise _sanitize_error()
    sanitized_events: list[dict[str, object]] = []
    dropped_private = 0
    dropped_shared = 0
    forbidden_fields = 0
    for raw_event in _raw_items(fetched):
        event, counts = _sanitize_event(raw_event)
        sanitized_events.append(event)
        dropped_private += counts[0]
        dropped_shared += counts[1]
        forbidden_fields += counts[2]
    sanitized_events.sort(key=_safe_event_sort_key)
    cancelled_count = sum(event["status"] == "cancelled" for event in sanitized_events)
    unknown_type_count = sum(
        event["eventType"] not in _KNOWN_EVENT_TYPES for event in sanitized_events
    )
    document: dict[str, object] = {
        "schema_version": "1.0",
        "snapshot_format": "sanitized-google-calendar-v1",
        "target_fingerprint": fetched.target_fingerprint,
        "complete": True,
        "captured_at": captured_at.isoformat(),
        "event_count": len(sanitized_events),
        "page_count": fetched.page_count,
        "collection_metadata_hash": fetched.collection_metadata_hash,
        "cancelled_event_count": cancelled_count,
        "unknown_event_type_count": unknown_type_count,
        "dropped_private_extended_property_count": dropped_private,
        "dropped_shared_extended_property_count": dropped_shared,
        "forbidden_field_count": forbidden_fields,
        "events": sanitized_events,
    }
    encoded = json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return parse_google_snapshot_bytes(encoded)


def _time_document(value: GoogleEventTime | None) -> dict[str, str] | None:
    if value is None:
        return None
    if value.date is not None:
        return {"date": value.date.isoformat()}
    if value.date_time is None:
        raise _sanitize_error()
    return {"dateTime": value.date_time.isoformat()}


def _event_document(event: CanonicalGoogleEvent) -> dict[str, object]:
    result: dict[str, object] = {
        "id": event.event_id,
        "status": event.status,
        "eventType": event.event_type,
        "endTimeUnspecified": event.end_time_unspecified,
        "locked": event.locked,
        "privateCopy": event.private_copy,
    }
    start = _time_document(event.start)
    end = _time_document(event.end)
    if start is not None and end is not None:
        result.update({"start": start, "end": end, "allDay": event.all_day})
    optional_values: tuple[tuple[str, object | None], ...] = (
        ("iCalUID", event.ical_uid),
        ("summary", event.summary),
        ("description", event.description),
        ("etag", event.etag),
        ("sequence", event.sequence),
        ("recurrence", list(event.recurrence) if event.recurrence else None),
        ("recurringEventId", event.recurring_event_id),
        ("originalStartTime", _time_document(event.original_start_time)),
        ("transparency", event.transparency),
        ("visibility", event.visibility),
        ("colorId", event.color_id),
        ("eventLabelId", event.event_label_id),
        ("location", event.location),
    )
    result.update({key: value for key, value in optional_values if value is not None})
    if event.reminders is not None:
        reminders: dict[str, object] = {"useDefault": event.reminders.use_default}
        if event.reminders.overrides:
            reminders["overrides"] = [
                {"method": override.method, "minutes": override.minutes}
                for override in event.reminders.overrides
            ]
        result["reminders"] = reminders
    if event.extended_properties is not None and event.extended_properties.private:
        result["extendedProperties"] = {
            "private": dict(event.extended_properties.private),
        }
    return result


def snapshot_document(snapshot: GoogleSnapshot) -> dict[str, object]:
    """Return the deterministic sensitive snapshot document for local storage."""

    return {
        "schema_version": snapshot.schema_version,
        "snapshot_format": snapshot.snapshot_format,
        "target_fingerprint": snapshot.target_fingerprint,
        "complete": snapshot.complete,
        "captured_at": snapshot.captured_at.isoformat() if snapshot.captured_at else None,
        "event_count": snapshot.event_count,
        "page_count": snapshot.page_count,
        "collection_metadata_hash": snapshot.collection_metadata_hash,
        "cancelled_event_count": snapshot.cancelled_event_count,
        "unknown_event_type_count": snapshot.unknown_event_type_count,
        "dropped_private_extended_property_count": (
            snapshot.dropped_private_extended_property_count
        ),
        "dropped_shared_extended_property_count": (snapshot.dropped_shared_extended_property_count),
        "forbidden_field_count": snapshot.forbidden_field_count,
        "content_hash": snapshot.content_hash,
        "events": [_event_document(event) for event in snapshot.events],
    }


def render_sanitized_snapshot(snapshot: GoogleSnapshot) -> bytes:
    """Render deterministic UTF-8 bytes without forbidden raw API fields."""

    return (
        json.dumps(
            snapshot_document(snapshot),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


sanitize_google_pages = sanitize_fetched_pages


__all__ = [
    "PRIVATE_EXTENDED_PROPERTY_PREFIX",
    "render_sanitized_snapshot",
    "sanitize_fetched_pages",
    "sanitize_google_pages",
    "snapshot_document",
]
