"""Strict private models for non-executable add/update apply bundles."""

from __future__ import annotations

from datetime import date as Date
from datetime import datetime as DateTime
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.plan_models import ChangedFieldName, PlanState


class ApplyEnvironment(StrEnum):
    """An explicit target environment; there is intentionally no default."""

    PRODUCTION = "production"
    TEST = "test"


class ApplyBundleState(StrEnum):
    """Offline approval and simulation lifecycle."""

    DRAFT = "draft"
    APPROVAL_REQUIRED = "approval_required"
    APPROVED_FOR_SIMULATION = "approved_for_simulation"
    SIMULATION_COMPLETE = "simulation_complete"
    SIMULATION_FAILED = "simulation_failed"


class ApplyOperationKind(StrEnum):
    """The complete Phase 4B operation vocabulary; delete is absent by design."""

    ADD = "add"
    UPDATE = "update"


_OPERATION_KIND_ORDER = {
    ApplyOperationKind.ADD: 0,
    ApplyOperationKind.UPDATE: 1,
}


class ApplyTimeBoundary(StrictFrozenModel):
    """One exact all-day date or timezone-aware date-time boundary."""

    date: Date | None = None
    date_time: DateTime | None = Field(default=None, repr=False, exclude=True)

    @model_validator(mode="after")
    def exactly_one_representation(self) -> Self:
        if (self.date is None) == (self.date_time is None):
            raise ValueError("apply time must contain exactly one representation")
        if self.date_time is not None and self.date_time.tzinfo is None:
            raise ValueError("apply date-time must include a timezone offset")
        return self


class ApplyAddPayload(StrictFrozenModel):
    """Exact Source fields permitted for an add simulation."""

    uid: str = Field(min_length=1, repr=False, exclude=True)
    summary: str = Field(min_length=1, repr=False, exclude=True)
    description: str = Field(min_length=1, repr=False, exclude=True)
    start: ApplyTimeBoundary = Field(repr=False, exclude=True)
    effective_end: ApplyTimeBoundary = Field(repr=False, exclude=True)
    all_day: bool
    event_type: Literal["default"] = "default"

    @model_validator(mode="after")
    def boundaries_match_event_shape(self) -> Self:
        if self.all_day:
            if self.start.date is None or self.effective_end.date is None:
                raise ValueError("all-day add requires date boundaries")
            if self.effective_end.date <= self.start.date:
                raise ValueError("add end date must be exclusive and after start")
        else:
            if self.start.date_time is None or self.effective_end.date_time is None:
                raise ValueError("timed add requires date-time boundaries")
            if self.effective_end.date_time <= self.start.date_time:
                raise ValueError("add end date-time must be after start")
        return self


class ApplyUpdatePayload(StrictFrozenModel):
    """Only explicitly changed Source fields plus exact Google concurrency keys."""

    event_id: str = Field(min_length=1, repr=False, exclude=True)
    etag: str = Field(min_length=1, repr=False, exclude=True)
    changed_fields: tuple[ChangedFieldName, ...]
    summary: str | None = Field(default=None, repr=False, exclude=True)
    description: str | None = Field(default=None, repr=False, exclude=True)
    start: ApplyTimeBoundary | None = Field(default=None, repr=False, exclude=True)
    effective_end: ApplyTimeBoundary | None = Field(default=None, repr=False, exclude=True)

    @model_validator(mode="after")
    def contains_exactly_changed_fields(self) -> Self:
        if not self.changed_fields:
            raise ValueError("update requires at least one changed field")
        expected_order = ("summary", "description", "start_date", "end_date")
        ordered = tuple(field for field in expected_order if field in self.changed_fields)
        if self.changed_fields != ordered or len(set(self.changed_fields)) != len(
            self.changed_fields
        ):
            raise ValueError("update changed fields must be unique and ordered")
        presence = {
            "summary": self.summary is not None,
            "description": self.description is not None,
            "start_date": self.start is not None,
            "end_date": self.effective_end is not None,
        }
        if any(presence[name] != (name in self.changed_fields) for name in expected_order):
            raise ValueError("update payload includes missing or unchanged fields")
        return self


ApplyPayload = ApplyAddPayload | ApplyUpdatePayload


class ApplyOperation(StrictFrozenModel):
    """One deterministic operation with raw execution data kept internal-only."""

    operation: ApplyOperationKind
    operation_sequence: int = Field(ge=1)
    source_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    google_ref: str | None = Field(default=None, pattern=r"^G-[0-9a-f]{12}$")
    start_date: Date
    changed_fields: tuple[ChangedFieldName, ...]
    source_event_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    before_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    after_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    payload_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_uid: str = Field(min_length=1, repr=False, exclude=True)
    payload: ApplyPayload = Field(repr=False, exclude=True)
    destructive: Literal[False] = False
    approval_required: Literal[True] = True
    operation_integrity_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def operation_matches_payload(self) -> Self:
        if self.operation is ApplyOperationKind.ADD:
            if self.google_ref is not None or not isinstance(self.payload, ApplyAddPayload):
                raise ValueError("add operation shape is invalid")
            if self.payload.uid != self.source_uid:
                raise ValueError("add UID does not match the operation identity")
            if self.changed_fields != (
                "summary",
                "description",
                "start_date",
                "end_date",
            ):
                raise ValueError("add operation must include all managed fields")
        elif self.google_ref is None or not isinstance(self.payload, ApplyUpdatePayload):
            raise ValueError("update operation shape is invalid")
        elif self.changed_fields != self.payload.changed_fields:
            raise ValueError("update changed fields do not match the payload")
        return self


class ApplyBundle(StrictFrozenModel):
    """Integrity-pinned private bundle that can never enable execution."""

    schema_version: Literal["1.0"] = "1.0"
    bundle_type: Literal["non-executable-apply-bundle-v1"] = "non-executable-apply-bundle-v1"
    tool_version: str = Field(min_length=1)
    state: ApplyBundleState
    environment: ApplyEnvironment
    target_fingerprint: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        repr=False,
        exclude=True,
    )
    target_reference: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    source_profile: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    accepted_tag: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
    accepted_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_canonical_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_event_count: int = Field(ge=0)
    snapshot_integrity_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_event_count: int = Field(ge=0)
    baseline_integrity_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_managed_uid_count: int = Field(ge=0)
    plan_integrity_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_state: PlanState
    generated_operation_count: int = Field(ge=0)
    add_count: int = Field(ge=0)
    update_count: int = Field(ge=0)
    delete_count: Literal[0] = 0
    operations: tuple[ApplyOperation, ...] = Field(repr=False, exclude=True)
    production_locked: Literal[True] = True
    execution_enabled: Literal[False] = False
    bundle_integrity_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def counts_and_state_are_coherent(self) -> Self:
        if self.target_reference != f"T-{self.target_fingerprint[:12]}":
            raise ValueError("target reference does not match the fingerprint")
        if self.generated_operation_count != len(self.operations):
            raise ValueError("generated operation count does not match operations")
        if self.generated_operation_count != self.add_count + self.update_count:
            raise ValueError("operation counts do not add up")
        if tuple(operation.operation_sequence for operation in self.operations) != tuple(
            range(1, len(self.operations) + 1)
        ):
            raise ValueError("operation sequences must be ordered and contiguous")
        canonical_operations = tuple(
            sorted(
                self.operations,
                key=lambda operation: (
                    _OPERATION_KIND_ORDER[operation.operation],
                    operation.start_date,
                    operation.source_ref,
                ),
            )
        )
        if self.operations != canonical_operations:
            raise ValueError("apply operations are not in canonical order")
        source_refs = tuple(operation.source_ref for operation in self.operations)
        if len(source_refs) != len(set(source_refs)):
            raise ValueError("apply bundle contains a duplicate operation identity")
        if self.add_count != sum(
            operation.operation is ApplyOperationKind.ADD for operation in self.operations
        ):
            raise ValueError("add count does not match operations")
        if self.update_count != sum(
            operation.operation is ApplyOperationKind.UPDATE for operation in self.operations
        ):
            raise ValueError("update count does not match operations")
        if self.state is ApplyBundleState.DRAFT and self.operations:
            raise ValueError("draft bundle must contain no operations")
        if self.state is ApplyBundleState.APPROVAL_REQUIRED and not self.operations:
            raise ValueError("approval-required bundle must contain operations")
        if (
            self.state
            in {
                ApplyBundleState.APPROVED_FOR_SIMULATION,
                ApplyBundleState.SIMULATION_COMPLETE,
                ApplyBundleState.SIMULATION_FAILED,
            }
            and not self.operations
        ):
            raise ValueError("simulation lifecycle requires operations")
        return self


__all__ = [
    "ApplyAddPayload",
    "ApplyBundle",
    "ApplyBundleState",
    "ApplyEnvironment",
    "ApplyOperation",
    "ApplyOperationKind",
    "ApplyPayload",
    "ApplyTimeBoundary",
    "ApplyUpdatePayload",
]
