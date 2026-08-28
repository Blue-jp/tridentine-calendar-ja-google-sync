"""Closed, secret-free models for the Phase 6D.0 read-only rehearsal.

These models deliberately expose only the two future Calendar read
capabilities.  They contain no credential, token value, Calendar ID, raw UID,
Google Event ID, ETag, URL, or generic Google service object.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Protocol, Self, runtime_checkable

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.google_models import CanonicalGoogleEvent
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.production_write_target import ProductionWriteTargetConfig
from tridentine_calendar_google_sync.production_write_token_models import (
    ProductionWriteCredentialSession,
)

PRODUCTION_REHEARSAL_API_CALL_HARD_MAXIMUM = 5
PRODUCTION_REHEARSAL_READ_RETRY_MAXIMUM = 1
PRODUCTION_REHEARSAL_TIME_ZONE: Literal["Asia/Tokyo"] = "Asia/Tokyo"


class ProductionWriteTokenRehearsalResultState(StrEnum):
    """Closed public terminal states for one read-only rehearsal."""

    READY = "ready"
    TARGET_MISMATCH = "target_mismatch"
    SCOPE_MISMATCH = "scope_mismatch"
    TOKEN_ROLE_MISMATCH = "token_role_mismatch"
    TOKEN_REFRESH_FAILED = "token_refresh_failed"
    PRODUCTION_FULL_SNAPSHOT_DRIFT = "production_full_snapshot_drift"
    PRODUCTION_SOURCE_CHANGE_DETECTED = "production_source_change_detected"
    INCOMPLETE_SNAPSHOT = "incomplete_snapshot"
    DUPLICATE_IDENTITY = "duplicate_identity"
    GET_VERIFICATION_FAILED = "get_verification_failed"
    API_CALL_LIMIT_EXCEEDED = "api_call_limit_exceeded"
    PRIVACY_FAILURE = "privacy_failure"
    INPUT_BINDING_MISMATCH = "input_binding_mismatch"
    TRANSPORT_FAILED = "transport_failed"


class ProductionWriteTokenFullSnapshotRequest(StrictFrozenModel):
    """Fixed ``events.list`` semantics with no subset controls."""

    page_token: str | None = Field(default=None, min_length=1, repr=False, exclude=True)
    token_role: Literal["production_write"] = "production_write"
    single_events: Literal[False] = False
    show_deleted: Literal[True] = True
    max_results: Literal[2500] = 2500
    time_min: Literal[None] = None
    time_max: Literal[None] = None
    sync_token: Literal[None] = None
    query: Literal[None] = None


class ProductionWriteTokenSnapshotPage(StrictFrozenModel):
    """One in-memory page returned through the read-only capability."""

    schema_version: Literal["1.0"] = "1.0"
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False, exclude=True)
    target_summary: str = Field(min_length=1, repr=False, exclude=True)
    access_role: Literal["owner"] = "owner"
    time_zone: str = Field(min_length=1)
    page_number: int = Field(ge=1)
    collection_complete: bool
    next_page_token: str | None = Field(default=None, min_length=1, repr=False, exclude=True)
    collection_metadata_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    dropped_private_extended_property_count: Literal[0] = 0
    dropped_shared_extended_property_count: Literal[0] = 0
    forbidden_field_count: Literal[0] = 0
    events: tuple[CanonicalGoogleEvent, ...] = Field(default=(), repr=False, exclude=True)

    @model_validator(mode="after")
    def pagination_shape_is_closed(self) -> Self:
        if self.collection_complete and self.next_page_token is not None:
            raise ValueError("Production rehearsal completion is invalid")
        if not self.collection_complete and self.next_page_token is None:
            raise ValueError("Production rehearsal pagination is incomplete")
        return self


class ProductionWriteTokenRehearsalEventEvidence(StrictFrozenModel):
    """One event-level coverage record without raw identity or managed text."""

    safe_event_ref: str = Field(pattern=r"^G-[0-9a-f]{12}$")
    safe_uid_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    managed_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ProductionWriteTokenRehearsalSnapshot(StrictFrozenModel):
    """Redacted event-level evidence for one complete full snapshot."""

    schema_version: Literal["1.0"] = "1.0"
    snapshot_type: Literal["production-write-token-rehearsal-snapshot-v1"] = (
        "production-write-token-rehearsal-snapshot-v1"
    )
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    complete: Literal[True] = True
    page_count: int = Field(ge=1, le=PRODUCTION_REHEARSAL_API_CALL_HARD_MAXIMUM)
    event_count: int = Field(ge=0)
    snapshot_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_cross_binding: Literal[True] = True
    source_zero_diff: Literal[True] = True
    managed_event_count: int = Field(ge=0)
    unchanged_count: int = Field(ge=0)
    cancelled_count: Literal[0] = 0
    recurring_count: Literal[0] = 0
    timed_count: Literal[0] = 0
    non_default_event_type_count: Literal[0] = 0
    color_id_count: Literal[0] = 0
    event_label_id_count: Literal[0] = 0
    duplicate_identity_count: Literal[0] = 0
    ambiguous_count: Literal[0] = 0
    unmanaged_count: Literal[0] = 0
    events: tuple[ProductionWriteTokenRehearsalEventEvidence, ...]
    raw_uid_count: Literal[0] = 0
    event_id_count: Literal[0] = 0
    etag_count: Literal[0] = 0
    snapshot_evidence_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def counts_are_coherent(self) -> Self:
        safe_uid_refs = tuple(event.safe_uid_ref for event in self.events)
        safe_event_refs = tuple(event.safe_event_ref for event in self.events)
        if (
            self.managed_event_count != self.event_count
            or self.unchanged_count != self.event_count
            or len(self.events) != self.event_count
            or self.events
            != tuple(
                sorted(self.events, key=lambda event: (event.safe_uid_ref, event.safe_event_ref))
            )
            or len(safe_uid_refs) != len(set(safe_uid_refs))
            or len(safe_event_refs) != len(set(safe_event_refs))
        ):
            raise ValueError("Production rehearsal snapshot counts are invalid")
        return self


class ProductionWriteTokenRehearsalReport(StrictFrozenModel):
    """Public-safe aggregate report for one rehearsal attempt."""

    schema_version: Literal["1.0"] = "1.0"
    report_type: Literal["production-write-token-readonly-rehearsal-report-v1"] = (
        "production-write-token-readonly-rehearsal-report-v1"
    )
    foundation_only: Literal[True] = True
    live_execution: Literal[False] = False
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    token_role: Literal["production_write", "production_read", "test_write", "invalid"]
    token_generation: int = Field(ge=0)
    scope_count: int = Field(ge=0, le=32)
    scope_exact: bool
    token_refresh_count: int = Field(ge=0, le=1)
    browser_launch_count: Literal[0] = 0
    rehearsal_client_construction_count: int = Field(ge=0, le=1)
    calendar_api_call_count: int = Field(
        ge=0,
        le=PRODUCTION_REHEARSAL_API_CALL_HARD_MAXIMUM,
    )
    list_call_count: int = Field(ge=0, le=PRODUCTION_REHEARSAL_API_CALL_HARD_MAXIMUM)
    get_call_count: int = Field(ge=0, le=1)
    read_retry_count: int = Field(ge=0, le=PRODUCTION_REHEARSAL_READ_RETRY_MAXIMUM)
    mutation_call_count: Literal[0] = 0
    target_metadata_verified: bool
    snapshot_complete: bool
    page_count: int = Field(ge=0, le=PRODUCTION_REHEARSAL_API_CALL_HARD_MAXIMUM)
    event_count: int = Field(ge=0)
    snapshot_content_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    baseline_cross_binding: bool
    source_unchanged_count: int = Field(ge=0)
    source_add_count: int = Field(ge=0)
    source_update_count: int = Field(ge=0)
    source_delete_candidate_count: int = Field(ge=0)
    source_unmanaged_count: int = Field(ge=0)
    source_duplicate_count: int = Field(ge=0)
    source_ambiguous_count: int = Field(ge=0)
    source_invalid_count: int = Field(ge=0)
    source_fatal_count: int = Field(ge=0)
    source_zero_diff: bool
    get_performed: bool
    get_verified: bool
    selected_safe_uid_ref: str | None = Field(default=None, pattern=r"^U-[0-9a-f]{12}$")
    event_id_present_internally: bool
    etag_present_internally: bool
    privacy_findings: tuple[str, ...] = ()
    result_state: ProductionWriteTokenRehearsalResultState
    safe_code: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]{0,95}$")
    snapshot_evidence_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    report_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def terminal_shape_is_coherent(self) -> Self:
        if self.calendar_api_call_count != self.list_call_count + self.get_call_count:
            raise ValueError("Production rehearsal API counts are invalid")
        if self.get_verified and not self.get_performed:
            raise ValueError("Production rehearsal get state is invalid")
        if self.get_performed != (self.get_call_count > 0):
            raise ValueError("Production rehearsal get count is invalid")
        if self.result_state is ProductionWriteTokenRehearsalResultState.READY:
            if not all(
                (
                    self.token_role == "production_write",
                    self.token_generation >= 1,
                    self.scope_count == 1,
                    self.scope_exact,
                    self.target_metadata_verified,
                    self.snapshot_complete,
                    self.baseline_cross_binding,
                    self.source_zero_diff,
                    self.get_verified,
                    self.event_id_present_internally,
                    self.etag_present_internally,
                )
            ):
                raise ValueError("Ready Production rehearsal is incompletely verified")
            if self.safe_code is not None or self.privacy_findings:
                raise ValueError("Ready Production rehearsal contains a finding")
        elif self.safe_code is None:
            raise ValueError("Stopped Production rehearsal requires a safe code")
        return self


@runtime_checkable
class ProductionWriteTokenReadOnlyTransport(Protocol):
    """Only ``events.list`` and ``events.get`` are exposed."""

    def list_events(
        self,
        *,
        request: ProductionWriteTokenFullSnapshotRequest,
    ) -> ProductionWriteTokenSnapshotPage:
        """Return one deterministic full-collection page."""

    def get_event(
        self,
        *,
        event_id: str,
        token_role: Literal["production_write"],
    ) -> CanonicalGoogleEvent:
        """Return one fresh managed event; identity stays memory-only."""


@runtime_checkable
class ProductionWriteCredentialSessionProvider(Protocol):
    """Lazy mock-only credential boundary invoked after confirmation."""

    mock_only: Literal[True]
    live_capable: Literal[False]
    browser_launch_count: Literal[0]
    refresh_attempt_count: int

    def load_session(
        self,
        *,
        target: ProductionWriteTargetConfig,
    ) -> ProductionWriteCredentialSession:
        """Return one validated session or a content-free refresh failure."""


@runtime_checkable
class ProductionWriteTokenReadOnlyTransportProvider(Protocol):
    """Lazy fake client boundary invoked only after credential validation."""

    mock_only: Literal[True]
    live_capable: Literal[False]

    def build_transport(
        self,
        *,
        session: ProductionWriteCredentialSession,
        target: ProductionWriteTargetConfig,
    ) -> ProductionWriteTokenReadOnlyTransport:
        """Return the sealed list/get-only fake transport."""


__all__ = [
    "PRODUCTION_REHEARSAL_API_CALL_HARD_MAXIMUM",
    "PRODUCTION_REHEARSAL_READ_RETRY_MAXIMUM",
    "PRODUCTION_REHEARSAL_TIME_ZONE",
    "ProductionWriteCredentialSessionProvider",
    "ProductionWriteTokenFullSnapshotRequest",
    "ProductionWriteTokenReadOnlyTransport",
    "ProductionWriteTokenReadOnlyTransportProvider",
    "ProductionWriteTokenRehearsalEventEvidence",
    "ProductionWriteTokenRehearsalReport",
    "ProductionWriteTokenRehearsalResultState",
    "ProductionWriteTokenRehearsalSnapshot",
    "ProductionWriteTokenSnapshotPage",
]
