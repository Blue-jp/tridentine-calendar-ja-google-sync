"""Strict private snapshot and public-safe Test prewrite report models."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.google_models import GoogleSnapshot
from tridentine_calendar_google_sync.models import StrictFrozenModel

TEST_CALENDAR_NOT_EMPTY_FINDING: Literal["test_calendar_not_empty_manual_review_required"] = (
    "test_calendar_not_empty_manual_review_required"
)
TEST_CALENDAR_NOT_EMPTY_MESSAGE: Literal[
    "Test Calendar is not empty; manual review is required."
] = "Test Calendar is not empty; manual review is required."


class TestCalendarPrewriteFinding(StrictFrozenModel):
    """One content-free finding suitable for public reports."""

    severity: Literal["fatal"] = "fatal"
    code: Literal["test_calendar_not_empty_manual_review_required"] = (
        "test_calendar_not_empty_manual_review_required"
    )
    message: Literal["Test Calendar is not empty; manual review is required."] = (
        "Test Calendar is not empty; manual review is required."
    )


class TestCalendarPrewriteSnapshot(StrictFrozenModel):
    """Local-private wrapper binding a complete sanitized Test snapshot to a call budget."""

    schema_version: Literal["1.0"] = "1.0"
    snapshot_type: Literal["test-calendar-prewrite-snapshot-v1"] = (
        "test-calendar-prewrite-snapshot-v1"
    )
    test_only: Literal[True] = True
    production_locked: Literal[True] = True
    target_fingerprint: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        repr=False,
        exclude=True,
    )
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    complete: Literal[True] = True
    page_count: int = Field(ge=1, le=5)
    api_call_count: int = Field(ge=1, le=5)
    retry_count: int = Field(ge=0, le=4)
    snapshot: GoogleSnapshot = Field(repr=False, exclude=True)
    snapshot_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    wrapper_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def private_snapshot_binding_is_coherent(self) -> Self:
        if self.target_safe_ref != f"T-{self.target_fingerprint[:12]}":
            raise ValueError("Test prewrite target reference does not match fingerprint")
        if self.target_safe_ref == PRODUCTION_TARGET_REFERENCE:
            raise ValueError("Production target is forbidden")
        if (
            self.snapshot.target_fingerprint != self.target_fingerprint
            or self.snapshot.complete is not True
            or self.snapshot.page_count != self.page_count
            or self.snapshot.content_hash != self.snapshot_content_hash
        ):
            raise ValueError("Test prewrite sanitized snapshot binding is invalid")
        if self.api_call_count != self.page_count + self.retry_count:
            raise ValueError("Test prewrite API call count is inconsistent")
        return self

    @property
    def event_count(self) -> int:
        """Return the private sanitized event count without exposing event content."""

        return self.snapshot.event_count


class TestCalendarPrewriteReport(StrictFrozenModel):
    """Public aggregate report with no Calendar ID, event identity, ETag, or text."""

    schema_version: Literal["1.0"] = "1.0"
    inspection_type: Literal["test-calendar-read-only-prewrite-v1"] = (
        "test-calendar-read-only-prewrite-v1"
    )
    read_only: Literal[True] = True
    prewrite_ready: bool
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    scope_label: Literal["calendar.events.owned"] = "calendar.events.owned"
    target_metadata_validation: Literal["verified"] = "verified"
    snapshot_complete: Literal[True] = True
    event_count: int = Field(ge=0)
    cancelled_count: int = Field(ge=0)
    recurring_count: int = Field(ge=0)
    timed_count: int = Field(ge=0)
    non_default_event_type_count: int = Field(ge=0)
    color_id_count: int = Field(ge=0)
    event_label_id_count: int = Field(ge=0)
    page_count: int = Field(ge=1, le=5)
    api_call_count: int = Field(ge=1, le=5)
    retry_count: int = Field(ge=0, le=4)
    google_write_method_count: Literal[0] = 0
    google_write_operation_count: Literal[0] = 0
    event_changes: Literal[0] = 0
    snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    findings: tuple[TestCalendarPrewriteFinding, ...] = ()
    result_binding_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    report_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def readiness_and_aggregate_counts_are_coherent(self) -> Self:
        if self.target_safe_ref == PRODUCTION_TARGET_REFERENCE:
            raise ValueError("Production target is forbidden")
        aggregate_counts = (
            self.cancelled_count,
            self.recurring_count,
            self.timed_count,
            self.non_default_event_type_count,
            self.color_id_count,
            self.event_label_id_count,
        )
        if any(count > self.event_count for count in aggregate_counts):
            raise ValueError("Test prewrite aggregate count exceeds event count")
        if self.api_call_count != self.page_count + self.retry_count:
            raise ValueError("Test prewrite API call count is inconsistent")
        finding_codes = tuple(finding.code for finding in self.findings)
        if finding_codes != tuple(sorted(set(finding_codes))):
            raise ValueError("Test prewrite findings must be sorted and unique")
        if self.prewrite_ready:
            if self.event_count != 0 or any(aggregate_counts) or self.findings:
                raise ValueError("Only an empty Test Calendar can be write-ready")
        elif (
            self.event_count < 1
            or TEST_CALENDAR_NOT_EMPTY_FINDING not in finding_codes
            or not any(
                finding.code == TEST_CALENDAR_NOT_EMPTY_FINDING and finding.severity == "fatal"
                for finding in self.findings
            )
        ):
            raise ValueError("A nonempty Test Calendar requires manual review")
        return self


__all__ = [
    "TEST_CALENDAR_NOT_EMPTY_FINDING",
    "TEST_CALENDAR_NOT_EMPTY_MESSAGE",
    "TestCalendarPrewriteFinding",
    "TestCalendarPrewriteReport",
    "TestCalendarPrewriteSnapshot",
]
