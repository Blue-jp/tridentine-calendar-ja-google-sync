"""Strict private models for a single Test Calendar write run."""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.plan_models import ChangedFieldName


class TestWriteOperationKind(StrEnum):
    """The complete Phase 5A mutation vocabulary; delete is absent."""

    ADD = "add"
    UPDATE = "update"


class TestWriteManagedState(StrictFrozenModel):
    """Exact Source-managed fields retained only inside a private Run Spec."""

    ical_uid: str = Field(min_length=1, repr=False, exclude=True)
    summary: str | None = Field(default=None, repr=False, exclude=True)
    description: str | None = Field(default=None, repr=False, exclude=True)
    start_date: date
    end_date: date
    all_day: Literal[True] = True
    event_type: Literal["default"] = "default"

    @model_validator(mode="after")
    def valid_exclusive_all_day_span(self) -> Self:
        if self.end_date <= self.start_date:
            raise ValueError("Test write end date must be after start date")
        return self


class TestWriteOperation(StrictFrozenModel):
    """One integrity-pinned add or update with raw identity kept private."""

    operation: TestWriteOperationKind
    source_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    google_ref: str | None = Field(default=None, pattern=r"^G-[0-9a-f]{12}$")
    changed_fields: tuple[ChangedFieldName, ...]
    current_state: TestWriteManagedState | None = Field(
        default=None,
        repr=False,
        exclude=True,
    )
    desired_state: TestWriteManagedState = Field(repr=False, exclude=True)
    google_event_id: str | None = Field(default=None, repr=False, exclude=True)
    expected_etag: str | None = Field(default=None, repr=False, exclude=True)
    operation_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def exactly_one_safe_operation_shape(self) -> Self:
        canonical_order = ("summary", "description", "start_date", "end_date")
        ordered = tuple(name for name in canonical_order if name in self.changed_fields)
        if ordered != self.changed_fields or len(set(self.changed_fields)) != len(
            self.changed_fields
        ):
            raise ValueError("Test write changed fields must be unique and ordered")
        if self.operation is TestWriteOperationKind.ADD:
            if (
                self.google_ref is not None
                or self.current_state is not None
                or self.google_event_id is not None
                or self.expected_etag is not None
                or self.changed_fields != canonical_order
            ):
                raise ValueError("Test write add operation shape is invalid")
            if self.desired_state.summary is None or self.desired_state.description is None:
                raise ValueError("Test write add requires complete desired text")
        else:
            if (
                self.google_ref is None
                or self.current_state is None
                or not self.google_event_id
                or not self.expected_etag
                or not self.changed_fields
            ):
                raise ValueError("Test write update operation shape is invalid")
            if (
                self.expected_etag == "*"
                or "\r" in self.expected_etag
                or "\n" in self.expected_etag
            ):
                raise ValueError("Test write ETag is invalid")
            if self.current_state.ical_uid != self.desired_state.ical_uid:
                raise ValueError("Test write update UID identity changed")
            if self.desired_state.summary is None or self.desired_state.description is None:
                raise ValueError("Test write update requires complete desired text")
        return self


class TestWriteRunSpec(StrictFrozenModel):
    """Local-private, one-operation contract that can target only a Test Calendar."""

    schema_version: Literal["1.0"] = "1.0"
    run_type: Literal["test-calendar-write-run-spec-v1"] = "test-calendar-write-run-spec-v1"
    test_only: Literal[True] = True
    production_locked: Literal[True] = True
    tool_version: str = Field(min_length=1)
    target_fingerprint: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        repr=False,
        exclude=True,
    )
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    target_environment: Literal["test"] = "test"
    source_profile: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_event_count: int = Field(ge=0)
    current_snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_baseline_hash: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    operation_count: Literal[1] = 1
    add_count: int = Field(ge=0, le=1)
    update_count: int = Field(ge=0, le=1)
    operation: TestWriteOperation = Field(repr=False, exclude=True)
    approval_required: Literal[True] = True
    run_spec_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def one_operation_and_production_lock_are_coherent(self) -> Self:
        if self.target_safe_ref != f"T-{self.target_fingerprint[:12]}":
            raise ValueError("Test write target reference does not match fingerprint")
        if self.target_safe_ref == PRODUCTION_TARGET_REFERENCE:
            raise ValueError("Production target is forbidden")
        if self.add_count + self.update_count != 1:
            raise ValueError("Test write run must contain exactly one operation")
        if self.operation.operation is TestWriteOperationKind.ADD:
            if self.add_count != 1 or self.update_count != 0:
                raise ValueError("Test write add count is invalid")
            if self.trusted_baseline_hash is not None:
                raise ValueError("Test write add must not bind a baseline artifact")
        else:
            if self.add_count != 0 or self.update_count != 1:
                raise ValueError("Test write update count is invalid")
            if self.trusted_baseline_hash is None:
                raise ValueError("Test write update requires a trusted baseline hash")
        return self


__all__ = [
    "TestWriteManagedState",
    "TestWriteOperation",
    "TestWriteOperationKind",
    "TestWriteRunSpec",
]
