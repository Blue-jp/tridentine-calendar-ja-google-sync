"""Strict canonical models for sanitized offline Google Calendar snapshots."""

from __future__ import annotations

from datetime import date as Date
from datetime import datetime as DateTime
from typing import Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.models import StrictFrozenModel


class GoogleEventTime(StrictFrozenModel):
    """One Google event boundary represented as either a date or date-time."""

    date: Date | None = None
    date_time: DateTime | None = None

    @model_validator(mode="after")
    def exactly_one_representation(self) -> Self:
        """Reject absent or conflicting time representations."""

        if (self.date is None) == (self.date_time is None):
            raise ValueError("event time must contain exactly one representation")
        return self


class GoogleReminderOverride(StrictFrozenModel):
    """One sanitized reminder override."""

    method: str = Field(min_length=1)
    minutes: int = Field(ge=0)


class GoogleReminders(StrictFrozenModel):
    """Sanitized reminder observation; never a managed Source field."""

    use_default: bool
    overrides: tuple[GoogleReminderOverride, ...] = ()


class GoogleActorObservation(StrictFrozenModel):
    """Privacy-safe creator or organizer observation without an email address."""

    is_self: bool


class GoogleExtendedProperties(StrictFrozenModel):
    """Sanitized extended properties retained only for ownership evidence."""

    private: tuple[tuple[str, str], ...] = Field(default=(), repr=False, exclude=True)
    shared: tuple[tuple[str, str], ...] = Field(default=(), repr=False, exclude=True)


class CanonicalGoogleEvent(StrictFrozenModel):
    """Canonical Google event decoded from the sanitized snapshot boundary.

    Opaque identifiers and event content are internal-only.  Dedicated report
    builders expose only domain-separated safe references and content hashes.
    """

    event_id: str = Field(min_length=1, repr=False, exclude=True)
    ical_uid: str | None = Field(default=None, repr=False, exclude=True)
    safe_event_reference: str = Field(pattern=r"^G-[0-9a-f]{12}$")
    safe_ical_uid_reference: str | None = Field(
        default=None,
        pattern=r"^U-[0-9a-f]{12}$",
    )
    summary: str | None = Field(default=None, repr=False, exclude=True)
    description: str | None = Field(default=None, repr=False, exclude=True)
    start: GoogleEventTime
    end: GoogleEventTime
    all_day: bool
    status: str = Field(min_length=1)
    event_type: str = Field(min_length=1)
    etag: str | None = Field(default=None, repr=False, exclude=True)
    sequence: int | None = Field(default=None, ge=0)
    recurrence: tuple[str, ...] = ()
    recurring_event_id: str | None = Field(default=None, repr=False, exclude=True)
    original_start_time: GoogleEventTime | None = None
    transparency: str | None = None
    visibility: str | None = None
    color_id: str | None = None
    event_label_id: str | None = None
    reminders: GoogleReminders | None = Field(default=None, repr=False, exclude=True)
    location: str | None = Field(default=None, repr=False, exclude=True)
    extended_properties: GoogleExtendedProperties | None = Field(
        default=None,
        repr=False,
        exclude=True,
    )
    created: DateTime | None = None
    updated: DateTime | None = None
    html_link_present: bool = False
    creator: GoogleActorObservation | None = None
    organizer: GoogleActorObservation | None = None

    @model_validator(mode="after")
    def time_shape_matches_all_day_flag(self) -> Self:
        """Require a coherent sanitized time representation."""

        if self.all_day:
            if self.start.date is None or self.end.date is None:
                raise ValueError("all-day events require date boundaries")
        elif self.start.date_time is None or self.end.date_time is None:
            raise ValueError("timed events require date-time boundaries")
        return self


class GoogleSnapshot(StrictFrozenModel):
    """One complete or intentionally incomplete sanitized local snapshot."""

    schema_version: str = Field(pattern=r"^1\.[0-9]+$")
    snapshot_format: str = Field(pattern=r"^sanitized-google-calendar-v1$")
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    complete: bool
    captured_at: DateTime | None = Field(default=None, repr=False, exclude=True)
    event_count: int = Field(ge=0)
    events: tuple[CanonicalGoogleEvent, ...] = Field(default=(), repr=False, exclude=True)
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


__all__ = [
    "CanonicalGoogleEvent",
    "GoogleActorObservation",
    "GoogleEventTime",
    "GoogleExtendedProperties",
    "GoogleReminderOverride",
    "GoogleReminders",
    "GoogleSnapshot",
]
