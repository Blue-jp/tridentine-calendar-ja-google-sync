"""Strict, immutable models for offline Accepted ICS inspection.

The canonical event model intentionally retains exact decoded source text for
future comparison work.  Those sensitive-to-noise values are excluded from
``repr`` and normal Pydantic serialization; reports are built by the dedicated
redacting report module instead.
"""

from __future__ import annotations

from datetime import date, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

Sha256Hex = str
FindingSeverity = Literal["error", "fatal"]


class StrictFrozenModel(BaseModel):
    """Base for configuration and inspection records.

    Strict validation prevents implicit coercion after transport-specific
    parsing.  Hiding input values in Pydantic errors prevents a malformed UID,
    SUMMARY, or DESCRIPTION from being echoed by an exception.
    """

    model_config = ConfigDict(
        strict=True,
        frozen=True,
        extra="forbid",
        hide_input_in_errors=True,
    )


class AcceptedSourceProvenance(StrictFrozenModel):
    """Public immutable identity of an accepted source release."""

    accepted_tag: str = Field(min_length=1)
    accepted_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    html_sha256: Sha256Hex = Field(pattern=r"^[0-9a-f]{64}$")
    plain_sha256: Sha256Hex = Field(pattern=r"^[0-9a-f]{64}$")


class ExpectedSourceAggregate(StrictFrozenModel):
    """Expected aggregate values pinned by an Accepted source profile."""

    vcalendar_count: int = Field(ge=0)
    vevent_count: int = Field(ge=0)
    uid_total_count: int = Field(ge=0)
    uid_unique_count: int = Field(ge=0)
    uid_duplicate_count: int = Field(ge=0)
    first_date: date
    last_date: date
    all_day_count: int = Field(ge=0)
    timed_count: int = Field(ge=0)
    dtstart_date_count: int = Field(ge=0)
    dtend_present_count: int = Field(ge=0)
    summary_present_count: int = Field(ge=0)
    description_present_count: int = Field(ge=0)
    dtstamp_present_count: int = Field(ge=0)
    rrule_count: int = Field(ge=0)
    recurrence_id_count: int = Field(ge=0)
    event_x_property_count: int = Field(ge=0)


class AcceptedSourceProfile(StrictFrozenModel):
    """Machine-readable contract for one accepted calendar artifact."""

    schema_version: str = Field(pattern=r"^1\.[0-9]+$")
    profile_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    project_name: str = Field(min_length=1)
    source: AcceptedSourceProvenance
    expected: ExpectedSourceAggregate

    @property
    def accepted_tag(self) -> str:
        """Return the pinned source tag."""

        return self.source.accepted_tag

    @property
    def accepted_commit(self) -> str:
        """Return the pinned peeled source commit."""

        return self.source.accepted_commit

    @property
    def html_sha256(self) -> Sha256Hex:
        """Return the expected HTML ICS byte hash."""

        return self.source.html_sha256

    @property
    def plain_sha256(self) -> Sha256Hex:
        """Return the provenance-only Plain ICS byte hash."""

        return self.source.plain_sha256


class ValidationFinding(StrictFrozenModel):
    """One deterministic, redacted source validation result."""

    severity: FindingSeverity
    code: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    message: str = Field(min_length=1)
    field: str | None = None
    event_ref: str | None = Field(default=None, pattern=r"^U-[0-9a-f]{12}$")


class CanonicalSourceEvent(StrictFrozenModel):
    """Canonical transport-decoded representation of one source VEVENT.

    No semantic text normalization is performed.  ``uid``, ``summary``, and
    ``description`` are exact decoded values and are deliberately unavailable
    to normal model serialization or repr output.
    """

    source_index: int = Field(ge=0)
    uid: str | None = Field(default=None, repr=False, exclude=True)
    safe_uid_reference: str | None = Field(
        default=None,
        pattern=r"^U-[0-9a-f]{12}$",
    )
    summary: str | None = Field(default=None, repr=False, exclude=True)
    description: str | None = Field(default=None, repr=False, exclude=True)
    dtstart_present: bool
    start_date: date | None = None
    start_datetime: datetime | None = None
    all_day: bool
    dtend_present: bool
    explicit_end_date: date | None = None
    explicit_end_datetime: datetime | None = None
    effective_end_date: date | None = None
    effective_end_datetime: datetime | None = None
    dtstamp_present: bool
    status_present: bool
    status: str | None = None
    sequence_present: bool
    sequence: int | None = None
    rrule_present: bool
    rrule_values: tuple[str, ...] = ()
    recurrence_id_present: bool
    recurrence_id_value: str | None = None
    optional_property_names: tuple[str, ...] = ()
    event_x_property_names: tuple[str, ...] = ()
    parser_issue_codes: tuple[str, ...] = ()


class ParsedSourceCalendar(StrictFrozenModel):
    """Parser output before Accepted-profile validation."""

    vcalendar_count: int = Field(ge=0)
    vevent_count: int = Field(ge=0)
    events: tuple[CanonicalSourceEvent, ...] = Field(default=(), repr=False, exclude=True)


class SourceCalendarInspection(StrictFrozenModel):
    """Aggregate result of parsing and validating one local ICS artifact."""

    schema_version: Literal["1.0"] = "1.0"
    profile_id: str
    raw_sha256: Sha256Hex = Field(pattern=r"^[0-9a-f]{64}$")
    source_sha_matches: bool
    vcalendar_count: int = Field(ge=0)
    vevent_count: int = Field(ge=0)
    uid_total_count: int = Field(ge=0)
    uid_unique_count: int = Field(ge=0)
    uid_duplicate_count: int = Field(ge=0)
    first_date: date | None = None
    last_date: date | None = None
    all_day_count: int = Field(ge=0)
    timed_count: int = Field(ge=0)
    dtstart_date_count: int = Field(ge=0)
    dtend_present_count: int = Field(ge=0)
    summary_present_count: int = Field(ge=0)
    description_present_count: int = Field(ge=0)
    dtstamp_present_count: int = Field(ge=0)
    rrule_count: int = Field(ge=0)
    recurrence_id_count: int = Field(ge=0)
    event_x_property_count: int = Field(ge=0)
    malformed_event_count: int = Field(ge=0)
    findings: tuple[ValidationFinding, ...] = ()
    fatal: bool
    source_valid: bool
    content_hash: Sha256Hex = Field(pattern=r"^[0-9a-f]{64}$")
    events: tuple[CanonicalSourceEvent, ...] = Field(default=(), repr=False, exclude=True)

    @property
    def fatal_count(self) -> int:
        """Return the number of fatal findings."""

        return sum(finding.severity == "fatal" for finding in self.findings)

    @property
    def error_count(self) -> int:
        """Return the number of non-fatal error findings."""

        return sum(finding.severity == "error" for finding in self.findings)


__all__ = [
    "AcceptedSourceProfile",
    "AcceptedSourceProvenance",
    "CanonicalSourceEvent",
    "ExpectedSourceAggregate",
    "FindingSeverity",
    "ParsedSourceCalendar",
    "Sha256Hex",
    "SourceCalendarInspection",
    "StrictFrozenModel",
    "ValidationFinding",
]
