"""Safe local loading of strict sanitized Google Calendar snapshot JSON."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import date, datetime
from pathlib import Path
from typing import Any, Self

from pydantic import ConfigDict, Field, ValidationError, model_validator

from tridentine_calendar_google_sync.google_models import (
    CanonicalGoogleEvent,
    GoogleActorObservation,
    GoogleEventTime,
    GoogleExtendedProperties,
    GoogleReminderOverride,
    GoogleReminders,
    GoogleSnapshot,
)
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.safe_refs import safe_google_event_ref, safe_uid_ref

MAX_GOOGLE_SNAPSHOT_BYTES = 64 * 1024 * 1024
_SNAPSHOT_HASH_DOMAIN = b"tridentine-calendar-google-sync:google-snapshot:v1\x00"


class GoogleSnapshotError(ValueError):
    """Base snapshot failure with content-free public text."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class GoogleSnapshotInputError(GoogleSnapshotError):
    """Unsafe or unavailable local snapshot input."""


class GoogleSnapshotParseError(GoogleSnapshotError):
    """Malformed JSON or invalid sanitized snapshot structure."""


class _SnapshotInputModel(StrictFrozenModel):
    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
        hide_input_in_errors=True,
        validate_by_alias=True,
        validate_by_name=False,
    )


class _EventTimeInput(_SnapshotInputModel):
    date_value: str | None = Field(
        default=None,
        alias="date",
        pattern=r"^\d{4}-\d{2}-\d{2}$",
    )
    date_time_value: str | None = Field(default=None, alias="dateTime", min_length=1)

    @model_validator(mode="after")
    def exactly_one_representation(self) -> Self:
        if (self.date_value is None) == (self.date_time_value is None):
            raise ValueError("event time must contain exactly one representation")
        return self


class _ReminderOverrideInput(_SnapshotInputModel):
    method: str = Field(min_length=1)
    minutes: int = Field(ge=0)


class _RemindersInput(_SnapshotInputModel):
    use_default: bool = Field(alias="useDefault")
    overrides: list[_ReminderOverrideInput] = Field(default_factory=list)


class _ActorInput(_SnapshotInputModel):
    is_self: bool = Field(alias="self")


class _ExtendedPropertiesInput(_SnapshotInputModel):
    private: dict[str, str] = Field(default_factory=dict)
    shared: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def keys_are_nonempty(self) -> Self:
        if any(not key for key in (*self.private, *self.shared)):
            raise ValueError("extended property keys must not be empty")
        return self


class _SnapshotEventInput(_SnapshotInputModel):
    event_id: str = Field(alias="id", min_length=1)
    ical_uid: str | None = Field(default=None, alias="iCalUID", min_length=1)
    summary: str | None = None
    description: str | None = None
    start: _EventTimeInput
    end: _EventTimeInput
    all_day: bool = Field(alias="allDay")
    status: str = Field(min_length=1)
    event_type: str = Field(alias="eventType", min_length=1)
    etag: str | None = Field(default=None, min_length=1)
    sequence: int | None = Field(default=None, ge=0)
    recurrence: list[str] = Field(default_factory=list)
    recurring_event_id: str | None = Field(
        default=None,
        alias="recurringEventId",
        min_length=1,
    )
    original_start_time: _EventTimeInput | None = Field(
        default=None,
        alias="originalStartTime",
    )
    transparency: str | None = Field(default=None, min_length=1)
    visibility: str | None = Field(default=None, min_length=1)
    color_id: str | None = Field(default=None, alias="colorId", min_length=1)
    event_label_id: str | None = Field(
        default=None,
        alias="eventLabelId",
        min_length=1,
    )
    reminders: _RemindersInput | None = None
    location: str | None = None
    extended_properties: _ExtendedPropertiesInput | None = Field(
        default=None,
        alias="extendedProperties",
    )
    created: str | None = Field(default=None, min_length=1)
    updated: str | None = Field(default=None, min_length=1)
    html_link_present: bool = Field(default=False, alias="htmlLinkPresent")
    creator: _ActorInput | None = None
    organizer: _ActorInput | None = None


class _SnapshotDocumentInput(_SnapshotInputModel):
    schema_version: str = Field(pattern=r"^1\.[0-9]+$")
    snapshot_format: str = Field(pattern=r"^sanitized-google-calendar-v1$")
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    complete: bool
    captured_at: str | None = Field(default=None, min_length=1)
    event_count: int = Field(ge=0)
    events: list[_SnapshotEventInput]

    @model_validator(mode="after")
    def declared_count_matches_events(self) -> Self:
        if self.event_count != len(self.events):
            raise ValueError("event_count must equal the events array length")
        return self


class _DuplicateJsonKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def _parse_datetime(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        raise ValueError
    return parsed


def _canonical_time(value: _EventTimeInput) -> GoogleEventTime:
    parsed_date = date.fromisoformat(value.date_value) if value.date_value else None
    parsed_datetime = _parse_datetime(value.date_time_value) if value.date_time_value else None
    return GoogleEventTime(date=parsed_date, date_time=parsed_datetime)


def _canonical_event(value: _SnapshotEventInput) -> CanonicalGoogleEvent:
    reminders = None
    if value.reminders is not None:
        reminders = GoogleReminders(
            use_default=value.reminders.use_default,
            overrides=tuple(
                GoogleReminderOverride(method=item.method, minutes=item.minutes)
                for item in value.reminders.overrides
            ),
        )
    extended = None
    if value.extended_properties is not None:
        extended = GoogleExtendedProperties(
            private=tuple(sorted(value.extended_properties.private.items())),
            shared=tuple(sorted(value.extended_properties.shared.items())),
        )
    return CanonicalGoogleEvent(
        event_id=value.event_id,
        ical_uid=value.ical_uid,
        safe_event_reference=safe_google_event_ref(value.event_id),
        safe_ical_uid_reference=(safe_uid_ref(value.ical_uid) if value.ical_uid else None),
        summary=value.summary,
        description=value.description,
        start=_canonical_time(value.start),
        end=_canonical_time(value.end),
        all_day=value.all_day,
        status=value.status,
        event_type=value.event_type,
        etag=value.etag,
        sequence=value.sequence,
        recurrence=tuple(value.recurrence),
        recurring_event_id=value.recurring_event_id,
        original_start_time=(
            _canonical_time(value.original_start_time)
            if value.original_start_time is not None
            else None
        ),
        transparency=value.transparency,
        visibility=value.visibility,
        color_id=value.color_id,
        event_label_id=value.event_label_id,
        reminders=reminders,
        location=value.location,
        extended_properties=extended,
        created=_parse_datetime(value.created) if value.created else None,
        updated=_parse_datetime(value.updated) if value.updated else None,
        html_link_present=value.html_link_present,
        creator=(
            GoogleActorObservation(is_self=value.creator.is_self)
            if value.creator is not None
            else None
        ),
        organizer=(
            GoogleActorObservation(is_self=value.organizer.is_self)
            if value.organizer is not None
            else None
        ),
    )


def _time_payload(value: GoogleEventTime | None) -> dict[str, str | None] | None:
    if value is None:
        return None
    return {
        "date": value.date.isoformat() if value.date else None,
        "dateTime": value.date_time.isoformat() if value.date_time else None,
    }


def _event_hash_payload(event: CanonicalGoogleEvent) -> dict[str, object]:
    extended = event.extended_properties
    reminders = event.reminders
    return {
        "id": event.event_id,
        "iCalUID": event.ical_uid,
        "summary": event.summary,
        "description": event.description,
        "start": _time_payload(event.start),
        "end": _time_payload(event.end),
        "allDay": event.all_day,
        "status": event.status,
        "eventType": event.event_type,
        "etag": event.etag,
        "sequence": event.sequence,
        "recurrence": list(event.recurrence),
        "recurringEventId": event.recurring_event_id,
        "originalStartTime": _time_payload(event.original_start_time),
        "transparency": event.transparency,
        "visibility": event.visibility,
        "colorId": event.color_id,
        "eventLabelId": event.event_label_id,
        "reminders": (
            {
                "useDefault": reminders.use_default,
                "overrides": [item.model_dump(mode="json") for item in reminders.overrides],
            }
            if reminders is not None
            else None
        ),
        "location": event.location,
        "extendedProperties": (
            {"private": list(extended.private), "shared": list(extended.shared)}
            if extended is not None
            else None
        ),
        "created": event.created.isoformat() if event.created else None,
        "updated": event.updated.isoformat() if event.updated else None,
        "htmlLinkPresent": event.html_link_present,
        "creator": event.creator.model_dump(mode="json") if event.creator else None,
        "organizer": event.organizer.model_dump(mode="json") if event.organizer else None,
    }


def _snapshot_content_hash(
    document: _SnapshotDocumentInput,
    events: tuple[CanonicalGoogleEvent, ...],
) -> str:
    payload = {
        "schema_version": document.schema_version,
        "snapshot_format": document.snapshot_format,
        "target_fingerprint": document.target_fingerprint,
        "complete": document.complete,
        "event_count": document.event_count,
        "events": [_event_hash_payload(event) for event in events],
    }
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_SNAPSHOT_HASH_DOMAIN + encoded).hexdigest()


def parse_google_snapshot_bytes(raw_bytes: bytes) -> GoogleSnapshot:
    """Parse exact UTF-8 JSON bytes into the strict sanitized snapshot model."""

    try:
        text = raw_bytes.decode("utf-8", errors="strict")
        loaded = json.loads(
            text,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        document = _SnapshotDocumentInput.model_validate(loaded, strict=True)
        events = tuple(_canonical_event(item) for item in document.events)
        event_ids = [event.event_id for event in events]
        if len(event_ids) != len(set(event_ids)):
            raise GoogleSnapshotParseError(
                "duplicate_google_event_id",
                "snapshot contains duplicate Google event identifiers",
            )
        captured_at = _parse_datetime(document.captured_at) if document.captured_at else None
        return GoogleSnapshot(
            schema_version=document.schema_version,
            snapshot_format=document.snapshot_format,
            target_fingerprint=document.target_fingerprint,
            complete=document.complete,
            captured_at=captured_at,
            event_count=document.event_count,
            events=events,
            content_hash=_snapshot_content_hash(document, events),
        )
    except GoogleSnapshotError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        ValidationError,
        TypeError,
        ValueError,
    ) as exc:
        raise GoogleSnapshotParseError(
            "invalid_google_snapshot",
            "Google snapshot is not a valid sanitized snapshot",
        ) from exc


def _reject_nonlocal_path(value: str) -> None:
    lowered = value.casefold()
    if "//" in value or "://" in value or lowered.startswith("file:"):
        raise GoogleSnapshotInputError(
            "nonlocal_google_snapshot",
            "Google snapshot must be a local filesystem path",
        )
    if value.startswith(("\\\\", "//")) or "\x00" in value:
        raise GoogleSnapshotInputError(
            "invalid_google_snapshot_path",
            "Google snapshot path is invalid",
        )


def load_google_snapshot(
    source: str | Path,
    *,
    max_size: int = MAX_GOOGLE_SNAPSHOT_BYTES,
) -> GoogleSnapshot:
    """Load one bounded regular local JSON file without copying or modifying it."""

    if max_size <= 0:
        raise ValueError("max_size must be positive")
    if isinstance(source, str):
        _reject_nonlocal_path(source)
    path = Path(source)
    try:
        if path.is_symlink():
            raise GoogleSnapshotInputError(
                "google_snapshot_symlink",
                "symbolic-link Google snapshots are not accepted",
            )
        if not path.is_file():
            raise GoogleSnapshotInputError(
                "google_snapshot_not_file",
                "Google snapshot is not a regular local file",
            )
        with path.open("rb") as snapshot_file:
            stat_result = os.fstat(snapshot_file.fileno())
            if stat_result.st_size > max_size:
                raise GoogleSnapshotInputError(
                    "google_snapshot_too_large",
                    "Google snapshot exceeds the size limit",
                )
            raw_bytes = snapshot_file.read(max_size + 1)
    except GoogleSnapshotError:
        raise
    except OSError as exc:
        raise GoogleSnapshotInputError(
            "google_snapshot_unavailable",
            "Google snapshot is unavailable",
        ) from exc
    if len(raw_bytes) > max_size:
        raise GoogleSnapshotInputError(
            "google_snapshot_too_large",
            "Google snapshot exceeds the size limit",
        )
    return parse_google_snapshot_bytes(raw_bytes)


__all__ = [
    "MAX_GOOGLE_SNAPSHOT_BYTES",
    "GoogleSnapshotError",
    "GoogleSnapshotInputError",
    "GoogleSnapshotParseError",
    "load_google_snapshot",
    "parse_google_snapshot_bytes",
]
