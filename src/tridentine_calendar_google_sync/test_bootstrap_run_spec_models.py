"""Strict private Add-only Run Spec for Test bootstrap execution."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.plan_models import ChangedFieldName
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteManagedState,
    TestWriteOperationKind,
)

_ADD_CHANGED_FIELDS: tuple[ChangedFieldName, ...] = (
    "summary",
    "description",
    "start_date",
    "end_date",
)


class TestBootstrapAddOperation(StrictFrozenModel):
    """One bootstrap Add operation; Update state cannot be represented."""

    operation: Literal[TestWriteOperationKind.ADD] = TestWriteOperationKind.ADD
    source_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    changed_fields: tuple[ChangedFieldName, ...] = _ADD_CHANGED_FIELDS
    desired_state: TestWriteManagedState = Field(repr=False, exclude=True)
    operation_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def fixed_add_shape(self) -> Self:
        if (
            self.operation is not TestWriteOperationKind.ADD
            or self.changed_fields != _ADD_CHANGED_FIELDS
            or self.desired_state.summary is None
            or self.desired_state.description is None
        ):
            raise ValueError("Bootstrap operation must be one complete Add")
        return self

    @property
    def google_ref(self) -> None:
        """Bootstrap Add has no pre-existing Google identity."""

        return None

    @property
    def current_state(self) -> None:
        """Bootstrap Add has no current managed event state."""

        return None

    @property
    def google_event_id(self) -> None:
        """Bootstrap Add has no Google event ID before import."""

        return None

    @property
    def expected_etag(self) -> None:
        """Bootstrap Add has no ETag before import."""

        return None


class TestBootstrapAddRunSpec(StrictFrozenModel):
    """Integrity-pinned Test-only contract produced by one eligible bootstrap plan."""

    schema_version: Literal["1.0"] = "1.0"
    run_type: Literal["test-bootstrap-add-run-spec-v1"] = "test-bootstrap-add-run-spec-v1"
    planning_mode: Literal["test_bootstrap_add"] = "test_bootstrap_add"
    bootstrap_add: Literal[True] = True
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
    source_event_count: Literal[1] = 1
    current_snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_event_count: Literal[0] = 0
    bootstrap_plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_baseline_hash: Literal[None] = None
    operation_count: Literal[1] = 1
    add_count: Literal[1] = 1
    update_count: Literal[0] = 0
    delete_count: Literal[0] = 0
    operation: TestBootstrapAddOperation = Field(repr=False, exclude=True)
    approval_required: Literal[True] = True
    run_spec_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def fixed_bootstrap_contract(self) -> Self:
        if (
            self.target_safe_ref != f"T-{self.target_fingerprint[:12]}"
            or self.target_safe_ref == PRODUCTION_TARGET_REFERENCE
            or self.operation.operation is not TestWriteOperationKind.ADD
        ):
            raise ValueError("Bootstrap Run Spec policy is invalid")
        return self

    @property
    def plan_hash(self) -> str:
        """Expose the bootstrap plan hash through the shared execution contract."""

        return self.bootstrap_plan_hash


__all__ = [
    "TestBootstrapAddOperation",
    "TestBootstrapAddRunSpec",
]
