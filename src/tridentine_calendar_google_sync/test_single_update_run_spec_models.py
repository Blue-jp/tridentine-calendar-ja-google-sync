"""Strict private Run Spec models for one Test-only Description update."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.test_single_update_plan_models import (
    SINGLE_UPDATE_CHANGED_FIELDS,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteManagedState,
    TestWriteOperationKind,
)


class TestSingleUpdateOperation(StrictFrozenModel):
    """One private Description-only update; Add cannot be represented."""

    operation: Literal[TestWriteOperationKind.UPDATE] = TestWriteOperationKind.UPDATE
    source_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    google_ref: str = Field(pattern=r"^G-[0-9a-f]{12}$")
    changed_fields: tuple[Literal["description"], ...] = SINGLE_UPDATE_CHANGED_FIELDS
    current_state: TestWriteManagedState = Field(repr=False, exclude=True)
    desired_state: TestWriteManagedState = Field(repr=False, exclude=True)
    google_event_id: str = Field(min_length=1, max_length=1024, repr=False, exclude=True)
    expected_etag: str = Field(min_length=1, max_length=4096, repr=False, exclude=True)
    operation_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def exact_update_shape(self) -> Self:
        if (
            self.operation is not TestWriteOperationKind.UPDATE
            or self.changed_fields != SINGLE_UPDATE_CHANGED_FIELDS
            or self.current_state.ical_uid != self.desired_state.ical_uid
            or self.current_state.summary is None
            or self.desired_state.summary is None
            or self.current_state.summary != self.desired_state.summary
            or self.current_state.description is None
            or self.desired_state.description is None
            or self.current_state.description == self.desired_state.description
            or self.current_state.start_date != self.desired_state.start_date
            or self.current_state.end_date != self.desired_state.end_date
            or self.current_state.all_day is not True
            or self.desired_state.all_day is not True
            or self.current_state.event_type != "default"
            or self.desired_state.event_type != "default"
            or self.expected_etag == "*"
            or "\r" in self.expected_etag
            or "\n" in self.expected_etag
        ):
            raise ValueError("Single Update operation must change Description only")
        return self


class TestSingleUpdateRunSpec(StrictFrozenModel):
    """Integrity-pinned Test-only contract for one dedicated update."""

    schema_version: Literal["1.0"] = "1.0"
    run_type: Literal["test-single-update-run-spec-v1"] = "test-single-update-run-spec-v1"
    planning_mode: Literal["test_single_update"] = "test_single_update"
    single_update: Literal[True] = True
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
    baseline_state: Literal["trusted"] = "trusted"
    trusted_baseline_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_profile: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_event_count: Literal[1] = 1
    current_snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    single_update_plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_count: Literal[1] = 1
    add_count: Literal[0] = 0
    update_count: Literal[1] = 1
    delete_count: Literal[0] = 0
    changed_fields: tuple[Literal["description"], ...] = SINGLE_UPDATE_CHANGED_FIELDS
    operation: TestSingleUpdateOperation = Field(repr=False, exclude=True)
    approval_required: Literal[True] = True
    run_spec_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def fixed_contract(self) -> Self:
        if (
            self.target_safe_ref != f"T-{self.target_fingerprint[:12]}"
            or self.target_safe_ref == PRODUCTION_TARGET_REFERENCE
            or self.baseline_snapshot_hash != self.current_snapshot_hash
            or self.changed_fields != SINGLE_UPDATE_CHANGED_FIELDS
            or self.operation.operation is not TestWriteOperationKind.UPDATE
            or self.operation.changed_fields != SINGLE_UPDATE_CHANGED_FIELDS
        ):
            raise ValueError("Single Update Run Spec policy is invalid")
        return self

    @property
    def plan_hash(self) -> str:
        """Expose the dedicated Plan hash through the shared execution contract."""

        return self.single_update_plan_hash


__all__ = ["TestSingleUpdateOperation", "TestSingleUpdateRunSpec"]
