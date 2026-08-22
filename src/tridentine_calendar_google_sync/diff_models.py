"""Strict redacted models for deterministic offline calendar differences."""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.models import StrictFrozenModel


class DiffClassification(StrEnum):
    """Complete Phase 2 classification vocabulary."""

    UNCHANGED = "unchanged"
    ADD = "add"
    UPDATE = "update"
    DELETE_CANDIDATE = "delete_candidate"
    DUPLICATE_SOURCE_UID = "duplicate_source_uid"
    DUPLICATE_GOOGLE_ICALUID = "duplicate_google_icaluid"
    AMBIGUOUS = "ambiguous"
    UNMANAGED_GOOGLE_EVENT = "unmanaged_google_event"
    INVALID_SOURCE = "invalid_source"
    FATAL_GUARD = "fatal_guard"


CLASSIFICATION_ORDER: tuple[DiffClassification, ...] = (
    DiffClassification.FATAL_GUARD,
    DiffClassification.INVALID_SOURCE,
    DiffClassification.DUPLICATE_SOURCE_UID,
    DiffClassification.DUPLICATE_GOOGLE_ICALUID,
    DiffClassification.AMBIGUOUS,
    DiffClassification.ADD,
    DiffClassification.UPDATE,
    DiffClassification.DELETE_CANDIDATE,
    DiffClassification.UNMANAGED_GOOGLE_EVENT,
    DiffClassification.UNCHANGED,
)


class ManagedScope(StrictFrozenModel):
    """In-memory-only evidence that a Google event belongs to this tool.

    No repository state or implicit dedicated-calendar ownership is assumed.
    Empty scope is the safe default: Google-only events remain unmanaged.
    """

    trusted_source_uids: frozenset[str] = Field(default=frozenset(), repr=False, exclude=True)
    trusted_google_event_ids: frozenset[str] = Field(
        default=frozenset(),
        repr=False,
        exclude=True,
    )
    private_marker_key: str | None = Field(default=None, repr=False, exclude=True)
    private_marker_value: str | None = Field(default=None, repr=False, exclude=True)

    @model_validator(mode="after")
    def marker_is_complete(self) -> Self:
        """Require marker key and value together to avoid partial ownership rules."""

        if (self.private_marker_key is None) != (self.private_marker_value is None):
            raise ValueError("private marker key and value must be supplied together")
        if self.private_marker_key == "" or self.private_marker_value == "":
            raise ValueError("private marker key and value must not be empty")
        return self


class FieldDifference(StrictFrozenModel):
    """A content-free exact field difference represented by hashes and lengths."""

    field: str = Field(pattern=r"^(summary|description|start_date|end_date)$")
    current_present: bool
    desired_present: bool
    current_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    desired_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    current_length: int = Field(ge=0)
    desired_length: int = Field(ge=0)


class EventDiff(StrictFrozenModel):
    """One classified identity group with only safe display references."""

    classification: DiffClassification
    source_uid: str | None = Field(default=None, repr=False, exclude=True)
    google_ical_uid: str | None = Field(default=None, repr=False, exclude=True)
    google_event_ids: tuple[str, ...] = Field(default=(), repr=False, exclude=True)
    source_ref: str | None = Field(default=None, pattern=r"^U-[0-9a-f]{12}$")
    google_refs: tuple[str, ...] = ()
    source_date: date | None = None
    google_date: date | None = None
    differences: tuple[FieldDifference, ...] = ()
    reason_codes: tuple[str, ...] = ()
    ownership_evidence: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    fatal: bool = False


class DiffWarning(StrictFrozenModel):
    """A deterministic warning that never contains raw identifiers or content."""

    code: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    message: str = Field(min_length=1)
    source_ref: str | None = Field(default=None, pattern=r"^U-[0-9a-f]{12}$")
    google_ref: str | None = Field(default=None, pattern=r"^G-[0-9a-f]{12}$")


class DiffCounts(StrictFrozenModel):
    """Count for every required classification."""

    unchanged: int = Field(ge=0)
    add: int = Field(ge=0)
    update: int = Field(ge=0)
    delete_candidate: int = Field(ge=0)
    duplicate_source_uid: int = Field(ge=0)
    duplicate_google_icaluid: int = Field(ge=0)
    ambiguous: int = Field(ge=0)
    unmanaged_google_event: int = Field(ge=0)
    invalid_source: int = Field(ge=0)
    fatal_guard: int = Field(ge=0)

    def for_classification(self, classification: DiffClassification) -> int:
        """Return the count for ``classification``."""

        return int(getattr(self, classification.value))


class CalendarDiff(StrictFrozenModel):
    """Complete deterministic diff between one source and one snapshot."""

    schema_version: str = Field(pattern=r"^1\.[0-9]+$")
    source_profile_id: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_sha_matches: bool
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_event_count: int = Field(ge=0)
    google_event_count: int = Field(ge=0)
    snapshot_complete: bool
    counts: DiffCounts
    events: tuple[EventDiff, ...]
    warnings: tuple[DiffWarning, ...] = ()
    fatal: bool
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def has_changes(self) -> bool:
        """Return whether any classification other than unchanged exists."""

        return len(self.events) != self.counts.unchanged

    @property
    def has_ambiguous(self) -> bool:
        """Return whether automatic action must stop for ambiguity."""

        return any(
            (
                self.counts.ambiguous,
                self.counts.duplicate_source_uid,
                self.counts.duplicate_google_icaluid,
            )
        )


DiffResult = CalendarDiff


__all__ = [
    "CLASSIFICATION_ORDER",
    "CalendarDiff",
    "DiffClassification",
    "DiffCounts",
    "DiffResult",
    "DiffWarning",
    "EventDiff",
    "FieldDifference",
    "ManagedScope",
]
