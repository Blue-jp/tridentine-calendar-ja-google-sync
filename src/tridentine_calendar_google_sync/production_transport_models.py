"""Closed mock-only transport contracts for one Production Description update.

The models in this module describe the minimum capabilities that Phase 6C may
exercise.  They deliberately contain no Calendar ID, credential, token, URL,
Google service object, or persistent Event ID/ETag field.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Protocol, runtime_checkable

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.google_models import CanonicalGoogleEvent
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.production_execution_journal import (
    PRODUCTION_EXECUTION_SAFE_CODES,
    ProductionExecutionJournal,
)

PRODUCTION_API_CALL_HARD_MAXIMUM = 10
PRODUCTION_MUTATION_MAXIMUM_ATTEMPTS = 1
PRODUCTION_MUTATION_RETRY_COUNT = 0
PRODUCTION_SEND_UPDATES: Literal["none"] = "none"
PRODUCTION_TIME_ZONE: Literal["Asia/Tokyo"] = "Asia/Tokyo"

PRODUCTION_SAFE_RESULT_CODES = PRODUCTION_EXECUTION_SAFE_CODES


class ProductionExecutionResultState(StrEnum):
    """Closed public result states for the Phase 6C mock orchestration."""

    SUCCEEDED = "succeeded"
    FAILED_PREFLIGHT = "failed_preflight"
    FAILED_DRIFT = "failed_drift"
    FAILED_PREIMAGE = "failed_preimage"
    ETAG_CONFLICT = "etag_conflict"
    WRITE_OUTCOME_UNCERTAIN = "write_outcome_uncertain"
    FAILED_TRANSPORT = "failed_transport"
    FAILED_READBACK = "failed_readback"
    FAILED_POST_SNAPSHOT = "failed_post_snapshot"
    FAILED_ZERO_DIFF = "failed_zero_diff"
    FAILED_APPROVAL = "failed_approval"
    FAILED_KILL_SWITCH = "failed_kill_switch"
    API_CALL_LIMIT_EXCEEDED = "api_call_limit_exceeded"


class ProductionSnapshotPage(StrictFrozenModel):
    """One in-memory page returned by a deterministic full-snapshot reader."""

    schema_version: Literal["1.0"] = "1.0"
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False, exclude=True)
    access_role: Literal["owner"] = "owner"
    time_zone: str = Field(min_length=1)
    page_number: int = Field(ge=1)
    collection_complete: bool
    next_page_token: str | None = Field(default=None, min_length=1, repr=False, exclude=True)
    collection_metadata_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    events: tuple[CanonicalGoogleEvent, ...] = Field(default=(), repr=False, exclude=True)

    @model_validator(mode="after")
    def pagination_shape_is_closed(self) -> ProductionSnapshotPage:
        if self.collection_complete and self.next_page_token is not None:
            raise ValueError("Production snapshot page completion is invalid")
        return self


class ProductionFullSnapshotRequest(StrictFrozenModel):
    """Closed future ``events.list`` semantics with no subset controls."""

    page_token: str | None = Field(default=None, min_length=1, repr=False, exclude=True)
    token_role: Literal["production_read_only"] = "production_read_only"
    single_events: Literal[False] = False
    show_deleted: Literal[True] = True
    max_results: Literal[2500] = 2500
    time_min: Literal[None] = None
    time_max: Literal[None] = None
    sync_token: Literal[None] = None
    query: Literal[None] = None


class ProductionTokenSeparationPolicy(StrictFrozenModel):
    """Secret-free three-role policy plus the bound future write generation."""

    production_read_role: Literal["production_read_only"] = "production_read_only"
    test_write_role: Literal["test_write"] = "test_write"
    production_write_role: Literal["production_write"] = "production_write"
    roles_distinct: Literal[True] = True
    write_token_generation: int = Field(ge=1)
    token_paths_present: Literal[False] = False
    token_values_present: Literal[False] = False


class ProductionPatchAcknowledgement(StrictFrozenModel):
    """Content-free acknowledgement; the response is never trusted as read-back."""

    accepted: Literal[True] = True


class ProductionMockExecutionResult(StrictFrozenModel):
    """Public-safe in-memory result consumed by the report builder."""

    schema_version: Literal["1.0"] = "1.0"
    result_type: Literal["production-single-update-mock-result-v1"] = (
        "production-single-update-mock-result-v1"
    )
    mock_only: Literal[True] = True
    live_execution: Literal[False] = False
    result_state: ProductionExecutionResultState
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    run_spec_ref: str = Field(pattern=r"^R-[0-9a-f]{12}$")
    plan_ref: str = Field(pattern=r"^P-[0-9a-f]{12}$")
    approval_state: Literal["validated", "rejected"]
    permit_consumed: bool
    operation_count: Literal[1] = 1
    changed_fields: tuple[Literal["description"], ...] = ("description",)
    patch_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    api_call_count: int = Field(ge=0, le=PRODUCTION_API_CALL_HARD_MAXIMUM)
    read_retry_count: int = Field(ge=0, le=PRODUCTION_API_CALL_HARD_MAXIMUM)
    mutation_attempt_count: int = Field(ge=0, le=PRODUCTION_MUTATION_MAXIMUM_ATTEMPTS)
    mutation_retry_count: Literal[0] = 0
    pre_snapshot_verified: bool
    pre_image_verified: bool
    read_back_verified: bool
    post_snapshot_verified: bool
    zero_diff_verified: bool
    baseline_renewal_required: bool
    safe_findings: tuple[str, ...] = ()
    recovered_uncertain_outcome: bool = False
    journal: ProductionExecutionJournal

    @model_validator(mode="after")
    def success_is_fully_verified(self) -> ProductionMockExecutionResult:
        succeeded = self.result_state is ProductionExecutionResultState.SUCCEEDED
        if succeeded != all(
            (
                self.permit_consumed,
                self.pre_snapshot_verified,
                self.pre_image_verified,
                self.read_back_verified,
                self.post_snapshot_verified,
                self.zero_diff_verified,
                self.baseline_renewal_required,
            )
        ):
            raise ValueError("Production mock execution result verification is invalid")
        if any(code not in PRODUCTION_SAFE_RESULT_CODES for code in self.safe_findings):
            raise ValueError("Production mock execution result safe finding is invalid")
        return self


@runtime_checkable
class ProductionFullSnapshotReader(Protocol):
    """Only the future ``events.list``-equivalent capability."""

    def list_events(self, *, request: ProductionFullSnapshotRequest) -> ProductionSnapshotPage:
        """Return one deterministic full-collection page."""


@runtime_checkable
class ProductionFreshEventReader(Protocol):
    """Only the future ``events.get``-equivalent capability."""

    def get_event(
        self,
        *,
        event_id: str,
        token_role: Literal["production_read_only"],
    ) -> CanonicalGoogleEvent:
        """Return one fresh event by an identity held only in memory."""


@runtime_checkable
class ProductionSingleUpdateMutator(Protocol):
    """Only the future description-only ``events.patch`` capability."""

    def patch_description(
        self,
        *,
        event_id: str,
        description: str,
        if_match: str,
        send_updates: Literal["none"],
        token_role: Literal["production_write"],
        write_token_generation: int,
    ) -> ProductionPatchAcknowledgement:
        """Attempt exactly one Description-only conditional patch."""


@runtime_checkable
class ProductionExecutionStateProvider(Protocol):
    """Opaque generation-only state rechecked before reads and mutation."""

    def current_kill_switch(self) -> object:
        """Return the current immutable kill-switch state."""

    def current_write_token_generation(self) -> int | None:
        """Return only an opaque generation, never token material."""


__all__ = [
    "PRODUCTION_API_CALL_HARD_MAXIMUM",
    "PRODUCTION_MUTATION_MAXIMUM_ATTEMPTS",
    "PRODUCTION_MUTATION_RETRY_COUNT",
    "PRODUCTION_SAFE_RESULT_CODES",
    "PRODUCTION_SEND_UPDATES",
    "PRODUCTION_TIME_ZONE",
    "ProductionExecutionResultState",
    "ProductionExecutionStateProvider",
    "ProductionFreshEventReader",
    "ProductionFullSnapshotReader",
    "ProductionFullSnapshotRequest",
    "ProductionMockExecutionResult",
    "ProductionPatchAcknowledgement",
    "ProductionSingleUpdateMutator",
    "ProductionSnapshotPage",
    "ProductionTokenSeparationPolicy",
]
