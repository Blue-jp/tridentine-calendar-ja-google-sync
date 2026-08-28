"""Append-only, public-safe journal for mock Production update execution.

The journal deliberately contains only safe references, hashes, counters, and
closed result codes.  It never accepts a Calendar ID, raw UID, event ID, ETag,
event content, token, request URL, or request payload.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import sys
from contextlib import suppress
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import Field, ValidationError, model_validator

from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    validate_sensitive_input_path,
)

PRODUCTION_EXECUTION_JOURNAL_GENESIS_HASH = "0" * 64
MAX_PRODUCTION_EXECUTION_JOURNAL_BYTES = 8 * 1024 * 1024
MAX_PRODUCTION_EXECUTION_JOURNAL_ENTRIES = 64
_ENTRY_HASH_DOMAIN = b"tridentine-calendar-google-sync:production-execution-journal-entry:v1\x00"
_HEADER_HASH_DOMAIN = b"tridentine-calendar-google-sync:production-execution-journal-header:v1\x00"
_JOURNAL_HASH_DOMAIN = b"tridentine-calendar-google-sync:production-execution-journal:v1\x00"
_HEADER_RECORD_TYPE = "production-execution-journal-header-v1"
_ENTRY_RECORD_TYPE = "production-execution-journal-entry-v1"

PRODUCTION_EXECUTION_SAFE_CODES = frozenset(
    {
        "api_call_limit_exceeded",
        "etag_conflict",
        "invalid_production_approval_state",
        "invalid_production_arm_receipt",
        "invalid_production_execute_consumption",
        "invalid_production_execute_permit",
        "invalid_production_kill_switch",
        "mock_get_script_exhausted",
        "mock_list_page_exhausted",
        "mock_list_page_token_mismatch",
        "mock_list_script_exhausted",
        "mock_patch_contract_mismatch",
        "noncanonical_production_approval_state",
        "phase6c_mock_approval_store_binding_mismatch",
        "phase6c_mock_approval_store_directory_mismatch",
        "production_approval_state_too_large",
        "production_approval_state_write_failed",
        "production_approval_validation_failed",
        "production_arm_binding_mismatch",
        "production_arm_clock_invalid",
        "production_arm_confirmation_mismatch",
        "production_arm_expired",
        "production_arm_hash_mismatch",
        "production_arm_invalid",
        "production_arm_lifetime_invalid",
        "production_arm_not_yet_valid",
        "production_desired_event_invalid",
        "production_execute_clock_invalid",
        "production_execute_confirmation_mismatch",
        "production_execute_consumption_binding_mismatch",
        "production_execute_consumption_failed",
        "production_execute_consumption_invalid",
        "production_execute_consumption_path_mismatch",
        "production_execute_permit_already_consumed",
        "production_execute_permit_binding_mismatch",
        "production_execute_permit_consume_failed",
        "production_execute_permit_expired",
        "production_execute_permit_hash_mismatch",
        "production_execute_permit_invalid",
        "production_execute_permit_not_yet_valid",
        "production_execution_binding_mismatch",
        "production_execution_clock_invalid",
        "production_full_snapshot_drift",
        "production_full_snapshot_failed",
        "production_full_snapshot_incomplete",
        "production_full_snapshot_invalid",
        "production_full_snapshot_page_mismatch",
        "production_full_snapshot_target_mismatch",
        "production_kill_switch_generation_mismatch",
        "production_kill_switch_hash_mismatch",
        "production_kill_switch_invalid",
        "production_kill_switch_off",
        "production_kill_switch_patch_recheck_failed",
        "production_kill_switch_recheck_failed",
        "production_kill_switch_target_mismatch",
        "production_live_execution_not_available_in_phase_6c",
        "production_mock_transport_required",
        "production_patch_contract_invalid",
        "production_patch_failed",
        "production_patch_hash_mismatch",
        "production_post_snapshot_drift",
        "production_post_snapshot_failed",
        "production_post_write_zero_diff_failed",
        "production_pre_image_failed",
        "production_pre_image_mismatch",
        "production_read_back_failed",
        "production_read_back_mismatch",
        "production_snapshot_time_invalid",
        "production_update_event_shape_invalid",
        "production_update_identity_ambiguous",
        "production_write_token_generation_invalid",
        "production_write_token_generation_mismatch",
        "rate_limit",
        "rate_limit_403",
        "sensitive_output_exists",
        "server_500",
        "server_502",
        "server_503",
        "unsafe_production_approval_state_path",
        "write_outcome_uncertain",
    }
)


class ProductionExecutionJournalPhase(StrEnum):
    """Closed write-ahead lifecycle for one mock Production update."""

    RUN_START = "run_start"
    APPROVAL_VALIDATED = "approval_validated"
    EXECUTE_PERMIT_CONSUMED = "execute_permit_consumed"
    KILL_SWITCH_VERIFIED = "kill_switch_verified"
    PRE_SNAPSHOT_INTENT = "pre_snapshot_intent"
    PRE_SNAPSHOT_VERIFIED = "pre_snapshot_verified"
    FRESH_GET_INTENT = "fresh_get_intent"
    PRE_IMAGE_VERIFIED = "pre_image_verified"
    MUTATION_INTENT = "mutation_intent"
    MUTATION_RESULT = "mutation_result"
    READBACK_INTENT = "readback_intent"
    READBACK_VERIFIED = "readback_verified"
    POST_SNAPSHOT_INTENT = "post_snapshot_intent"
    POST_SNAPSHOT_VERIFIED = "post_snapshot_verified"
    ZERO_DIFF_VERIFIED = "zero_diff_verified"
    TERMINAL_RESULT = "terminal_result"


PRODUCTION_EXECUTION_PHASE_ORDER = tuple(ProductionExecutionJournalPhase)
_PHASE_INDEX = {phase: index for index, phase in enumerate(PRODUCTION_EXECUTION_PHASE_ORDER)}


class ProductionExecutionJournalEntryStatus(StrEnum):
    """Safe status vocabulary for write-ahead and verification entries."""

    STARTED = "started"
    VALIDATED = "validated"
    CONSUMED = "consumed"
    INTENT = "intent"
    VERIFIED = "verified"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNCERTAIN = "uncertain"
    RECOVERED = "recovered"


class ProductionExecutionJournalState(StrEnum):
    """Closed aggregate result states shared with the public report."""

    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED_PREFLIGHT = "failed_preflight"
    FAILED_DRIFT = "failed_drift"
    FAILED_PREIMAGE = "failed_preimage"
    ETAG_CONFLICT = "etag_conflict"
    WRITE_OUTCOME_UNCERTAIN = "write_outcome_uncertain"
    FAILED_READBACK = "failed_readback"
    FAILED_POST_SNAPSHOT = "failed_post_snapshot"
    FAILED_ZERO_DIFF = "failed_zero_diff"
    FAILED_APPROVAL = "failed_approval"
    FAILED_KILL_SWITCH = "failed_kill_switch"
    API_CALL_LIMIT_EXCEEDED = "api_call_limit_exceeded"
    FAILED_TRANSPORT = "failed_transport"
    FAILED_JOURNAL = "failed_journal"


class ProductionExecutionJournalEntry(StrictFrozenModel):
    """One content-free, hash-chained execution observation."""

    sequence: int = Field(ge=0, le=MAX_PRODUCTION_EXECUTION_JOURNAL_ENTRIES - 1)
    timestamp: datetime
    phase: ProductionExecutionJournalPhase
    status: ProductionExecutionJournalEntryStatus
    safe_code: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_]*$")
    api_call_count: int = Field(ge=0, le=10)
    read_retry_count: int = Field(ge=0, le=10)
    mutation_attempt_count: int = Field(ge=0, le=1)
    mutation_retry_count: Literal[0] = 0
    approval_consumed: bool
    kill_switch_generation: int = Field(ge=1)
    write_token_generation: int = Field(ge=1)
    fsync_required: Literal[True] = True
    terminal_state: ProductionExecutionJournalState | None = None
    previous_entry_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    entry_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def safe_entry_shape(self) -> Self:
        _require_utc(self.timestamp)
        if self.phase is ProductionExecutionJournalPhase.TERMINAL_RESULT:
            if self.terminal_state in {None, ProductionExecutionJournalState.RUNNING}:
                raise ValueError("terminal journal entry requires a terminal state")
            if self.terminal_state is ProductionExecutionJournalState.SUCCEEDED:
                if (
                    self.status
                    not in {
                        ProductionExecutionJournalEntryStatus.SUCCEEDED,
                        ProductionExecutionJournalEntryStatus.RECOVERED,
                    }
                    or self.safe_code is not None
                ):
                    raise ValueError("successful terminal journal entry is invalid")
            elif (
                self.status
                not in {
                    ProductionExecutionJournalEntryStatus.FAILED,
                    ProductionExecutionJournalEntryStatus.UNCERTAIN,
                }
                or self.safe_code is None
            ):
                raise ValueError("failed terminal journal entry is invalid")
        elif self.terminal_state is not None:
            raise ValueError("only terminal_result may set terminal state")
        if (
            self.status
            in {
                ProductionExecutionJournalEntryStatus.FAILED,
                ProductionExecutionJournalEntryStatus.UNCERTAIN,
            }
            and self.safe_code is None
        ):
            raise ValueError("failed journal entry requires a safe code")
        if (
            self.status
            in {
                ProductionExecutionJournalEntryStatus.STARTED,
                ProductionExecutionJournalEntryStatus.VALIDATED,
                ProductionExecutionJournalEntryStatus.CONSUMED,
                ProductionExecutionJournalEntryStatus.INTENT,
                ProductionExecutionJournalEntryStatus.VERIFIED,
                ProductionExecutionJournalEntryStatus.SUCCEEDED,
                ProductionExecutionJournalEntryStatus.RECOVERED,
            }
            and self.safe_code is not None
        ):
            raise ValueError("nonfailure journal entry cannot have a safe code")
        if self.safe_code is not None and self.safe_code not in PRODUCTION_EXECUTION_SAFE_CODES:
            raise ValueError("journal safe code is not allowlisted")
        return self


class ProductionExecutionJournal(StrictFrozenModel):
    """Immutable aggregate reconstructed from an append-only journal file."""

    schema_version: Literal["1.0"] = "1.0"
    journal_type: Literal["production-single-update-execution-journal-v1"] = (
        "production-single-update-execution-journal-v1"
    )
    mock_only: Literal[True] = True
    live_execution: Literal[False] = False
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    run_spec_ref: str = Field(pattern=r"^R-[0-9a-f]{12}$")
    plan_ref: str = Field(pattern=r"^P-[0-9a-f]{12}$")
    approval_material_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    execute_permit_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    patch_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    started_at: datetime
    header_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    state: ProductionExecutionJournalState
    entries: tuple[ProductionExecutionJournalEntry, ...]
    entry_count: int = Field(ge=0, le=MAX_PRODUCTION_EXECUTION_JOURNAL_ENTRIES)
    api_call_count: int = Field(ge=0, le=10)
    read_retry_count: int = Field(ge=0, le=10)
    mutation_attempt_count: int = Field(ge=0, le=1)
    mutation_retry_count: Literal[0] = 0
    approval_consumed: bool
    last_entry_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    rollback_available: Literal[False] = False
    terminal: bool
    journal_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def aggregate_shape(self) -> Self:
        _require_utc(self.started_at)
        if self.entry_count != len(self.entries):
            raise ValueError("Production execution journal count mismatch")
        expected_last = self.entries[-1].entry_hash if self.entries else self.header_hash
        if self.last_entry_hash != expected_last:
            raise ValueError("Production execution journal last hash mismatch")
        if self.entries:
            final = self.entries[-1]
            if (
                self.api_call_count != final.api_call_count
                or self.read_retry_count != final.read_retry_count
                or self.mutation_attempt_count != final.mutation_attempt_count
                or self.approval_consumed != final.approval_consumed
            ):
                raise ValueError("Production execution journal aggregate mismatch")
        elif any(
            (
                self.api_call_count,
                self.read_retry_count,
                self.mutation_attempt_count,
                self.approval_consumed,
            )
        ):
            raise ValueError("empty Production execution journal must have zero state")
        if self.terminal != (self.state is not ProductionExecutionJournalState.RUNNING):
            raise ValueError("Production execution journal terminal marker mismatch")
        return self


class ProductionExecutionJournalError(ValueError):
    """Content-free journal validation or I/O failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _require_utc(value: datetime) -> None:
    offset = value.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("Production execution journal timestamps must be UTC")


def _canonical_hash(domain: bytes, value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def _header_hash_data(journal: ProductionExecutionJournal) -> dict[str, object]:
    return {
        "schema_version": journal.schema_version,
        "journal_type": journal.journal_type,
        "mock_only": journal.mock_only,
        "live_execution": journal.live_execution,
        "target_safe_ref": journal.target_safe_ref,
        "run_spec_ref": journal.run_spec_ref,
        "plan_ref": journal.plan_ref,
        "approval_material_hash": journal.approval_material_hash,
        "execute_permit_hash": journal.execute_permit_hash,
        "patch_hash": journal.patch_hash,
        "started_at": journal.started_at.isoformat(),
        "previous_record_hash": PRODUCTION_EXECUTION_JOURNAL_GENESIS_HASH,
    }


def calculate_production_execution_journal_header_hash(
    journal: ProductionExecutionJournal,
) -> str:
    """Bind all immutable header fields to the first entry in the chain."""

    return _canonical_hash(_HEADER_HASH_DOMAIN, _header_hash_data(journal))


def _entry_hash_data(entry: ProductionExecutionJournalEntry) -> dict[str, object]:
    return {
        "sequence": entry.sequence,
        "timestamp": entry.timestamp.isoformat(),
        "phase": entry.phase.value,
        "status": entry.status.value,
        "safe_code": entry.safe_code,
        "api_call_count": entry.api_call_count,
        "read_retry_count": entry.read_retry_count,
        "mutation_attempt_count": entry.mutation_attempt_count,
        "mutation_retry_count": entry.mutation_retry_count,
        "approval_consumed": entry.approval_consumed,
        "kill_switch_generation": entry.kill_switch_generation,
        "write_token_generation": entry.write_token_generation,
        "fsync_required": entry.fsync_required,
        "terminal_state": (None if entry.terminal_state is None else entry.terminal_state.value),
        "previous_entry_hash": entry.previous_entry_hash,
    }


def calculate_production_execution_journal_entry_hash(
    entry: ProductionExecutionJournalEntry,
) -> str:
    """Recalculate one journal entry hash without trusting stored content."""

    return _canonical_hash(_ENTRY_HASH_DOMAIN, _entry_hash_data(entry))


def _journal_hash_data(journal: ProductionExecutionJournal) -> dict[str, object]:
    return {
        "schema_version": journal.schema_version,
        "journal_type": journal.journal_type,
        "mock_only": journal.mock_only,
        "live_execution": journal.live_execution,
        "target_safe_ref": journal.target_safe_ref,
        "run_spec_ref": journal.run_spec_ref,
        "plan_ref": journal.plan_ref,
        "approval_material_hash": journal.approval_material_hash,
        "execute_permit_hash": journal.execute_permit_hash,
        "patch_hash": journal.patch_hash,
        "started_at": journal.started_at.isoformat(),
        "header_hash": journal.header_hash,
        "state": journal.state.value,
        "entries": [entry.model_dump(mode="json") for entry in journal.entries],
        "entry_count": journal.entry_count,
        "api_call_count": journal.api_call_count,
        "read_retry_count": journal.read_retry_count,
        "mutation_attempt_count": journal.mutation_attempt_count,
        "mutation_retry_count": journal.mutation_retry_count,
        "approval_consumed": journal.approval_consumed,
        "last_entry_hash": journal.last_entry_hash,
        "rollback_available": journal.rollback_available,
        "terminal": journal.terminal,
    }


def calculate_production_execution_journal_hash(
    journal: ProductionExecutionJournal,
) -> str:
    """Recalculate the aggregate journal hash."""

    return _canonical_hash(_JOURNAL_HASH_DOMAIN, _journal_hash_data(journal))


def _rehash_journal(journal: ProductionExecutionJournal) -> ProductionExecutionJournal:
    unsigned = journal.model_copy(update={"journal_content_hash": "0" * 64})
    return unsigned.model_copy(
        update={"journal_content_hash": calculate_production_execution_journal_hash(unsigned)}
    )


def initialize_production_execution_journal(
    *,
    target_safe_ref: str,
    run_spec_ref: str,
    plan_ref: str,
    approval_material_hash: str,
    execute_permit_hash: str,
    patch_hash: str,
    started_at: datetime,
) -> ProductionExecutionJournal:
    """Initialize an empty in-memory mock execution journal."""

    journal = ProductionExecutionJournal(
        target_safe_ref=target_safe_ref,
        run_spec_ref=run_spec_ref,
        plan_ref=plan_ref,
        approval_material_hash=approval_material_hash,
        execute_permit_hash=execute_permit_hash,
        patch_hash=patch_hash,
        started_at=started_at,
        header_hash="0" * 64,
        state=ProductionExecutionJournalState.RUNNING,
        entries=(),
        entry_count=0,
        api_call_count=0,
        read_retry_count=0,
        mutation_attempt_count=0,
        approval_consumed=False,
        last_entry_hash=PRODUCTION_EXECUTION_JOURNAL_GENESIS_HASH,
        terminal=False,
        journal_content_hash="0" * 64,
    )
    header_hash = calculate_production_execution_journal_header_hash(journal)
    journal = journal.model_copy(
        update={
            "header_hash": header_hash,
            "last_entry_hash": header_hash,
        }
    )
    return _rehash_journal(journal)


def append_production_execution_journal_entry(
    journal: ProductionExecutionJournal,
    *,
    timestamp: datetime,
    phase: ProductionExecutionJournalPhase,
    status: ProductionExecutionJournalEntryStatus,
    safe_code: str | None = None,
    api_call_count: int,
    read_retry_count: int,
    mutation_attempt_count: int,
    approval_consumed: bool,
    kill_switch_generation: int,
    write_token_generation: int,
    terminal_state: ProductionExecutionJournalState | None = None,
) -> ProductionExecutionJournal:
    """Append one immutable entry after fail-closed transition checks."""

    verify_production_execution_journal(journal, require_terminal=False)
    if journal.terminal:
        raise ProductionExecutionJournalError(
            "production_journal_already_terminal",
            "Production execution journal is already terminal",
        )
    if len(journal.entries) >= MAX_PRODUCTION_EXECUTION_JOURNAL_ENTRIES:
        raise ProductionExecutionJournalError(
            "production_journal_entry_limit",
            "Production execution journal entry limit exceeded",
        )
    prior_counts = (
        journal.api_call_count,
        journal.read_retry_count,
        journal.mutation_attempt_count,
    )
    new_counts = (api_call_count, read_retry_count, mutation_attempt_count)
    if any(new < prior for new, prior in zip(new_counts, prior_counts, strict=True)):
        raise ProductionExecutionJournalError(
            "production_journal_counts_regressed",
            "Production execution journal counters regressed",
        )
    if journal.approval_consumed and not approval_consumed:
        raise ProductionExecutionJournalError(
            "production_journal_consumption_regressed",
            "Production execution approval consumption regressed",
        )
    entry = ProductionExecutionJournalEntry(
        sequence=len(journal.entries),
        timestamp=timestamp,
        phase=phase,
        status=status,
        safe_code=safe_code,
        api_call_count=api_call_count,
        read_retry_count=read_retry_count,
        mutation_attempt_count=mutation_attempt_count,
        approval_consumed=approval_consumed,
        kill_switch_generation=kill_switch_generation,
        write_token_generation=write_token_generation,
        terminal_state=terminal_state,
        previous_entry_hash=journal.last_entry_hash,
        entry_hash="0" * 64,
    )
    entry = entry.model_copy(
        update={"entry_hash": calculate_production_execution_journal_entry_hash(entry)}
    )
    state = ProductionExecutionJournalState.RUNNING if terminal_state is None else terminal_state
    updated = journal.model_copy(
        update={
            "state": state,
            "entries": (*journal.entries, entry),
            "entry_count": len(journal.entries) + 1,
            "api_call_count": api_call_count,
            "read_retry_count": read_retry_count,
            "mutation_attempt_count": mutation_attempt_count,
            "approval_consumed": approval_consumed,
            "last_entry_hash": entry.entry_hash,
            "terminal": terminal_state is not None,
            "journal_content_hash": "0" * 64,
        }
    )
    updated = _rehash_journal(updated)
    verify_production_execution_journal(updated, require_terminal=False)
    return updated


def _raise_semantic_error(code: str) -> None:
    raise ProductionExecutionJournalError(
        code,
        "Production execution journal semantic verification failed",
    )


def _verify_journal_semantics(journal: ProductionExecutionJournal) -> None:
    entries = journal.entries
    if not entries:
        if journal.state is not ProductionExecutionJournalState.RUNNING:
            _raise_semantic_error("production_journal_empty_terminal")
        return

    prior_timestamp = journal.started_at
    prior_phase_index = -1
    seen: set[ProductionExecutionJournalPhase] = set()
    generations = (
        entries[0].kill_switch_generation,
        entries[0].write_token_generation,
    )
    if (
        entries[0].phase is not ProductionExecutionJournalPhase.RUN_START
        or entries[0].status is not ProductionExecutionJournalEntryStatus.STARTED
    ):
        _raise_semantic_error("production_journal_run_start_missing")
    intent_phases = {
        ProductionExecutionJournalPhase.PRE_SNAPSHOT_INTENT,
        ProductionExecutionJournalPhase.FRESH_GET_INTENT,
        ProductionExecutionJournalPhase.MUTATION_INTENT,
        ProductionExecutionJournalPhase.READBACK_INTENT,
        ProductionExecutionJournalPhase.POST_SNAPSHOT_INTENT,
    }
    verification_phases = {
        ProductionExecutionJournalPhase.KILL_SWITCH_VERIFIED,
        ProductionExecutionJournalPhase.PRE_SNAPSHOT_VERIFIED,
        ProductionExecutionJournalPhase.PRE_IMAGE_VERIFIED,
        ProductionExecutionJournalPhase.POST_SNAPSHOT_VERIFIED,
        ProductionExecutionJournalPhase.ZERO_DIFF_VERIFIED,
    }
    for entry in entries:
        if entry.timestamp < prior_timestamp:
            _raise_semantic_error("production_journal_timestamp_order")
        prior_timestamp = entry.timestamp
        phase_index = _PHASE_INDEX[entry.phase]
        if phase_index <= prior_phase_index or entry.phase in seen:
            _raise_semantic_error("production_journal_phase_order")
        prior_phase_index = phase_index
        seen.add(entry.phase)
        if (
            entry.kill_switch_generation,
            entry.write_token_generation,
        ) != generations:
            _raise_semantic_error("production_journal_generation_changed")
        if entry.phase is ProductionExecutionJournalPhase.APPROVAL_VALIDATED and (
            entry.status is not ProductionExecutionJournalEntryStatus.VALIDATED
        ):
            _raise_semantic_error("production_journal_approval_status")
        if entry.phase is ProductionExecutionJournalPhase.EXECUTE_PERMIT_CONSUMED:
            if (
                entry.status is not ProductionExecutionJournalEntryStatus.CONSUMED
                or not entry.approval_consumed
            ):
                _raise_semantic_error("production_journal_consume_missing")
        elif (
            _PHASE_INDEX[entry.phase]
            < _PHASE_INDEX[ProductionExecutionJournalPhase.EXECUTE_PERMIT_CONSUMED]
            and entry.approval_consumed
        ):
            _raise_semantic_error("production_journal_consumed_too_early")
        elif (
            _PHASE_INDEX[entry.phase]
            > _PHASE_INDEX[ProductionExecutionJournalPhase.EXECUTE_PERMIT_CONSUMED]
            and ProductionExecutionJournalPhase.EXECUTE_PERMIT_CONSUMED in seen
            and not entry.approval_consumed
        ):
            _raise_semantic_error("production_journal_consume_regressed")
        if entry.phase in intent_phases and (
            entry.status is not ProductionExecutionJournalEntryStatus.INTENT
        ):
            _raise_semantic_error("production_journal_intent_status")
        if entry.phase in verification_phases and entry.status not in {
            ProductionExecutionJournalEntryStatus.VERIFIED,
            ProductionExecutionJournalEntryStatus.FAILED,
            ProductionExecutionJournalEntryStatus.UNCERTAIN,
        }:
            _raise_semantic_error("production_journal_verification_status")
        if entry.phase is ProductionExecutionJournalPhase.MUTATION_RESULT and (
            entry.status
            not in {
                ProductionExecutionJournalEntryStatus.SUCCEEDED,
                ProductionExecutionJournalEntryStatus.FAILED,
                ProductionExecutionJournalEntryStatus.UNCERTAIN,
            }
        ):
            _raise_semantic_error("production_journal_mutation_result_status")
        if entry.phase is ProductionExecutionJournalPhase.READBACK_VERIFIED and (
            entry.status
            not in {
                ProductionExecutionJournalEntryStatus.VERIFIED,
                ProductionExecutionJournalEntryStatus.RECOVERED,
                ProductionExecutionJournalEntryStatus.FAILED,
                ProductionExecutionJournalEntryStatus.UNCERTAIN,
            }
        ):
            _raise_semantic_error("production_journal_readback_status")
        if (
            _PHASE_INDEX[entry.phase]
            <= _PHASE_INDEX[ProductionExecutionJournalPhase.PRE_SNAPSHOT_INTENT]
            and entry.api_call_count != 0
        ):
            _raise_semantic_error("production_journal_api_count_too_early")
        if (
            _PHASE_INDEX[entry.phase]
            < _PHASE_INDEX[ProductionExecutionJournalPhase.MUTATION_INTENT]
            and entry.mutation_attempt_count != 0
        ):
            _raise_semantic_error("production_journal_mutation_count_too_early")

    first_api_phase = ProductionExecutionJournalPhase.PRE_SNAPSHOT_INTENT
    if any(
        _PHASE_INDEX[first_api_phase]
        <= _PHASE_INDEX[entry.phase]
        < _PHASE_INDEX[ProductionExecutionJournalPhase.TERMINAL_RESULT]
        for entry in entries
    ):
        required_pre_api = {
            ProductionExecutionJournalPhase.RUN_START,
            ProductionExecutionJournalPhase.APPROVAL_VALIDATED,
            ProductionExecutionJournalPhase.EXECUTE_PERMIT_CONSUMED,
            ProductionExecutionJournalPhase.KILL_SWITCH_VERIFIED,
        }
        if not required_pre_api.issubset(seen):
            _raise_semantic_error("production_journal_pre_api_order")
        if not entries[-1].approval_consumed:
            _raise_semantic_error("production_journal_pre_api_unconsumed")
    if ProductionExecutionJournalPhase.MUTATION_INTENT in seen:
        required_pre_mutation = {
            ProductionExecutionJournalPhase.PRE_SNAPSHOT_VERIFIED,
            ProductionExecutionJournalPhase.FRESH_GET_INTENT,
            ProductionExecutionJournalPhase.PRE_IMAGE_VERIFIED,
        }
        if not required_pre_mutation.issubset(seen):
            _raise_semantic_error("production_journal_pre_mutation_order")
        mutation_entry = next(
            item
            for item in entries
            if item.phase is ProductionExecutionJournalPhase.MUTATION_INTENT
        )
        if mutation_entry.mutation_attempt_count != 1 or not mutation_entry.fsync_required:
            _raise_semantic_error("production_journal_mutation_intent_not_durable")
    if ProductionExecutionJournalPhase.MUTATION_RESULT in seen and (
        ProductionExecutionJournalPhase.MUTATION_INTENT not in seen
    ):
        _raise_semantic_error("production_journal_mutation_without_intent")

    final = entries[-1]
    if journal.terminal:
        if final.phase is not ProductionExecutionJournalPhase.TERMINAL_RESULT:
            _raise_semantic_error("production_journal_terminal_entry_missing")
        if final.terminal_state is not journal.state:
            _raise_semantic_error("production_journal_terminal_state_mismatch")
        if journal.state is ProductionExecutionJournalState.SUCCEEDED:
            if tuple(item.phase for item in entries) != PRODUCTION_EXECUTION_PHASE_ORDER:
                _raise_semantic_error("production_journal_success_lifecycle_incomplete")
            if not journal.approval_consumed or journal.mutation_attempt_count != 1:
                _raise_semantic_error("production_journal_success_counts_invalid")
    elif final.phase is ProductionExecutionJournalPhase.TERMINAL_RESULT:
        _raise_semantic_error("production_journal_running_has_terminal_entry")


def verify_production_execution_journal(
    journal: ProductionExecutionJournal,
    *,
    require_terminal: bool = True,
) -> None:
    """Verify hashes, ordering, safety transitions, and terminal completeness."""

    if not hmac.compare_digest(
        calculate_production_execution_journal_header_hash(journal),
        journal.header_hash,
    ):
        raise ProductionExecutionJournalError(
            "production_journal_header_hash_mismatch",
            "Production execution journal header verification failed",
        )
    expected_previous = journal.header_hash
    previous_counts = (0, 0, 0)
    for expected_sequence, entry in enumerate(journal.entries):
        if entry.sequence != expected_sequence:
            raise ProductionExecutionJournalError(
                "production_journal_sequence_mismatch",
                "Production execution journal sequence verification failed",
            )
        if not hmac.compare_digest(entry.previous_entry_hash, expected_previous):
            raise ProductionExecutionJournalError(
                "production_journal_chain_mismatch",
                "Production execution journal hash-chain verification failed",
            )
        if not hmac.compare_digest(
            calculate_production_execution_journal_entry_hash(entry), entry.entry_hash
        ):
            raise ProductionExecutionJournalError(
                "production_journal_entry_hash_mismatch",
                "Production execution journal entry verification failed",
            )
        counts = (
            entry.api_call_count,
            entry.read_retry_count,
            entry.mutation_attempt_count,
        )
        if any(current < prior for current, prior in zip(counts, previous_counts, strict=True)):
            raise ProductionExecutionJournalError(
                "production_journal_count_order_mismatch",
                "Production execution journal counter verification failed",
            )
        previous_counts = counts
        expected_previous = entry.entry_hash
    if journal.entry_count != len(journal.entries) or not hmac.compare_digest(
        journal.last_entry_hash, expected_previous
    ):
        raise ProductionExecutionJournalError(
            "production_journal_aggregate_mismatch",
            "Production execution journal aggregate verification failed",
        )
    if not hmac.compare_digest(
        calculate_production_execution_journal_hash(journal),
        journal.journal_content_hash,
    ):
        raise ProductionExecutionJournalError(
            "production_journal_content_hash_mismatch",
            "Production execution journal content verification failed",
        )
    _verify_journal_semantics(journal)
    if require_terminal and not journal.terminal:
        raise ProductionExecutionJournalError(
            "production_journal_terminal_missing",
            "Production execution journal terminal result is missing",
        )


def production_execution_journal_data(
    journal: ProductionExecutionJournal,
) -> dict[str, object]:
    """Return the verified canonical safe journal document."""

    verify_production_execution_journal(journal)
    return journal.model_dump(mode="json")


def render_production_execution_journal_json(
    journal: ProductionExecutionJournal,
) -> str:
    """Render deterministic public-safe JSON."""

    return (
        json.dumps(
            production_execution_journal_data(journal),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def _header_data(journal: ProductionExecutionJournal) -> dict[str, object]:
    return {
        "record_type": _HEADER_RECORD_TYPE,
        **_header_hash_data(journal),
        "header_hash": journal.header_hash,
    }


def _entry_record_data(entry: ProductionExecutionJournalEntry) -> dict[str, object]:
    return {
        "record_type": _ENTRY_RECORD_TYPE,
        **entry.model_dump(mode="json"),
    }


def _render_line(value: object) -> str:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    )


def create_production_execution_journal_file(
    path: str | Path,
    journal: ProductionExecutionJournal,
) -> Path:
    """Exclusively create an append-only repository-external journal file."""

    verify_production_execution_journal(journal, require_terminal=False)
    if journal.entries:
        raise ProductionExecutionJournalError(
            "production_journal_create_not_empty",
            "Production execution journal file must begin empty",
        )
    try:
        atomic_write_private_text(
            path,
            _render_line(_header_data(journal)),
            overwrite=False,
            max_size=MAX_PRODUCTION_EXECUTION_JOURNAL_BYTES,
        )
        return Path(path)
    except SensitivePathError as exc:
        raise ProductionExecutionJournalError(
            "production_journal_create_failed",
            "Production execution journal could not be created safely",
        ) from exc


if sys.platform == "win32":
    import msvcrt

    def _lock_descriptor(descriptor: int, *, exclusive: bool) -> None:
        """Acquire one Windows journal lock owned by the open descriptor."""

        os.lseek(descriptor, 0, os.SEEK_SET)
        mode = msvcrt.LK_LOCK if exclusive else msvcrt.LK_RLCK
        msvcrt.locking(descriptor, mode, 1)

    def _unlock_descriptor(descriptor: int) -> None:
        """Release the matching Windows descriptor lock."""

        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _lock_descriptor(descriptor: int, *, exclusive: bool) -> None:
        """Acquire one POSIX journal lock owned by the open descriptor."""

        os.lseek(descriptor, 0, os.SEEK_SET)
        mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        fcntl.flock(descriptor, mode)

    def _unlock_descriptor(descriptor: int) -> None:
        """Release the matching POSIX descriptor lock."""

        os.lseek(descriptor, 0, os.SEEK_SET)
        fcntl.flock(descriptor, fcntl.LOCK_UN)


def _open_locked_journal(path: Path, *, exclusive: bool) -> int:
    descriptor = -1
    try:
        flags = (os.O_RDWR | os.O_APPEND) if exclusive else os.O_RDONLY
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        _lock_descriptor(descriptor, exclusive=exclusive)
        opened = os.fstat(descriptor)
        current = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev,
            opened.st_ino,
        ) != (current.st_dev, current.st_ino):
            raise OSError("journal identity changed")
        return descriptor
    except OSError as exc:
        if descriptor >= 0:
            with suppress(OSError):
                _unlock_descriptor(descriptor)
            os.close(descriptor)
        raise ProductionExecutionJournalError(
            "production_journal_lock_failed",
            "Production execution journal could not be locked safely",
        ) from exc


def _close_locked_journal(descriptor: int) -> None:
    try:
        _unlock_descriptor(descriptor)
    except OSError as exc:
        raise ProductionExecutionJournalError(
            "production_journal_unlock_failed",
            "Production execution journal lock could not be released safely",
        ) from exc
    finally:
        os.close(descriptor)


def _read_locked_journal(descriptor: int) -> bytes:
    try:
        size = os.fstat(descriptor).st_size
        if size <= 0 or size > MAX_PRODUCTION_EXECUTION_JOURNAL_BYTES:
            raise OSError("journal size is invalid")
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks: list[bytes] = []
        remaining = MAX_PRODUCTION_EXECUTION_JOURNAL_BYTES + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(64 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw_bytes = b"".join(chunks)
        if len(raw_bytes) != size or len(raw_bytes) > MAX_PRODUCTION_EXECUTION_JOURNAL_BYTES:
            raise OSError("journal read is incomplete")
        return raw_bytes
    except OSError as exc:
        raise ProductionExecutionJournalError(
            "production_journal_read_failed",
            "Production execution journal could not be read safely",
        ) from exc


def _append_locked_journal_line(descriptor: int, line: str) -> None:
    content = line.encode("utf-8", errors="strict")
    try:
        opened = os.fstat(descriptor)
        if opened.st_size + len(content) > MAX_PRODUCTION_EXECUTION_JOURNAL_BYTES:
            raise OSError("journal size limit exceeded")
        written = os.write(descriptor, content)
        if written != len(content):
            raise OSError("short journal write")
        os.fsync(descriptor)
    except OSError as exc:
        raise ProductionExecutionJournalError(
            "production_journal_append_failed",
            "Production execution journal could not be appended safely",
        ) from exc


def append_production_execution_journal_file(
    path: str | Path,
    previous: ProductionExecutionJournal,
    updated: ProductionExecutionJournal,
) -> Path:
    """Durably append exactly one entry using optimistic hash-chain matching."""

    verify_production_execution_journal(previous, require_terminal=False)
    verify_production_execution_journal(updated, require_terminal=False)
    if len(updated.entries) != len(previous.entries) + 1:
        raise ProductionExecutionJournalError(
            "production_journal_append_shape",
            "Production execution journal append must add exactly one entry",
        )
    if updated.entries[:-1] != previous.entries:
        raise ProductionExecutionJournalError(
            "production_journal_append_prefix",
            "Production execution journal append prefix changed",
        )
    try:
        safe_path = validate_sensitive_input_path(
            path,
            max_size=MAX_PRODUCTION_EXECUTION_JOURNAL_BYTES,
        )
    except SensitivePathError as exc:
        raise ProductionExecutionJournalError(
            "production_journal_append_path_unsafe",
            "Production execution journal path is unsafe or unavailable",
        ) from exc
    descriptor = _open_locked_journal(safe_path, exclusive=True)
    try:
        on_disk = parse_production_execution_journal_file_bytes(
            _read_locked_journal(descriptor),
            require_terminal=False,
        )
        if not hmac.compare_digest(
            on_disk.journal_content_hash,
            previous.journal_content_hash,
        ):
            raise ProductionExecutionJournalError(
                "production_journal_stale_append",
                "Production execution journal append state is stale",
            )
        _append_locked_journal_line(
            descriptor,
            _render_line(_entry_record_data(updated.entries[-1])),
        )
    finally:
        _close_locked_journal(descriptor)
    return safe_path


class _DuplicateJsonKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise _DuplicateJsonKey
        value[key] = item
    return value


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def _parse_record(line: bytes) -> dict[str, Any]:
    value = json.loads(
        line.decode("utf-8", errors="strict"),
        object_pairs_hook=_object_without_duplicate_keys,
        parse_constant=_reject_json_constant,
    )
    if not isinstance(value, dict):
        raise TypeError
    return value


def parse_production_execution_journal_file_bytes(
    raw_bytes: bytes,
    *,
    require_terminal: bool = True,
) -> ProductionExecutionJournal:
    """Strictly reconstruct one bounded append-only NDJSON journal."""

    if not raw_bytes or len(raw_bytes) > MAX_PRODUCTION_EXECUTION_JOURNAL_BYTES:
        raise ProductionExecutionJournalError(
            "invalid_production_journal_file",
            "Production execution journal file is invalid",
        )
    if not raw_bytes.endswith(b"\n"):
        raise ProductionExecutionJournalError(
            "production_journal_truncated",
            "Production execution journal file is truncated",
        )
    try:
        lines = raw_bytes.splitlines()
        if not lines or len(lines) > MAX_PRODUCTION_EXECUTION_JOURNAL_ENTRIES + 1:
            raise ValueError
        header = _parse_record(lines[0])
        if header.pop("record_type", None) != _HEADER_RECORD_TYPE:
            raise ValueError
        exact_header_keys = {
            "schema_version",
            "journal_type",
            "mock_only",
            "live_execution",
            "target_safe_ref",
            "run_spec_ref",
            "plan_ref",
            "approval_material_hash",
            "execute_permit_hash",
            "patch_hash",
            "started_at",
            "previous_record_hash",
            "header_hash",
        }
        if set(header) != exact_header_keys:
            raise ValueError
        started_at = datetime.fromisoformat(str(header["started_at"]))
        journal = initialize_production_execution_journal(
            target_safe_ref=str(header["target_safe_ref"]),
            run_spec_ref=str(header["run_spec_ref"]),
            plan_ref=str(header["plan_ref"]),
            approval_material_hash=str(header["approval_material_hash"]),
            execute_permit_hash=str(header["execute_permit_hash"]),
            patch_hash=str(header["patch_hash"]),
            started_at=started_at,
        )
        if (
            header["schema_version"] != journal.schema_version
            or header["journal_type"] != journal.journal_type
            or header["mock_only"] is not True
            or header["live_execution"] is not False
            or header["previous_record_hash"] != PRODUCTION_EXECUTION_JOURNAL_GENESIS_HASH
            or not hmac.compare_digest(str(header["header_hash"]), journal.header_hash)
        ):
            raise ValueError
        for raw_line in lines[1:]:
            record = _parse_record(raw_line)
            if record.pop("record_type", None) != _ENTRY_RECORD_TYPE:
                raise ValueError
            record["timestamp"] = datetime.fromisoformat(str(record["timestamp"]))
            record["phase"] = ProductionExecutionJournalPhase(record["phase"])
            record["status"] = ProductionExecutionJournalEntryStatus(record["status"])
            if record.get("terminal_state") is not None:
                record["terminal_state"] = ProductionExecutionJournalState(record["terminal_state"])
            entry = ProductionExecutionJournalEntry.model_validate(record, strict=True)
            if entry.sequence != len(journal.entries):
                raise ProductionExecutionJournalError(
                    "production_journal_sequence_mismatch",
                    "Production execution journal sequence verification failed",
                )
            if not hmac.compare_digest(entry.previous_entry_hash, journal.last_entry_hash):
                raise ProductionExecutionJournalError(
                    "production_journal_chain_mismatch",
                    "Production execution journal hash-chain verification failed",
                )
            if not hmac.compare_digest(
                calculate_production_execution_journal_entry_hash(entry), entry.entry_hash
            ):
                raise ProductionExecutionJournalError(
                    "production_journal_entry_hash_mismatch",
                    "Production execution journal entry verification failed",
                )
            journal = journal.model_copy(
                update={
                    "state": (
                        ProductionExecutionJournalState.RUNNING
                        if entry.terminal_state is None
                        else entry.terminal_state
                    ),
                    "entries": (*journal.entries, entry),
                    "entry_count": len(journal.entries) + 1,
                    "api_call_count": entry.api_call_count,
                    "read_retry_count": entry.read_retry_count,
                    "mutation_attempt_count": entry.mutation_attempt_count,
                    "approval_consumed": entry.approval_consumed,
                    "last_entry_hash": entry.entry_hash,
                    "terminal": entry.terminal_state is not None,
                    "journal_content_hash": "0" * 64,
                }
            )
            journal = _rehash_journal(journal)
        verify_production_execution_journal(journal, require_terminal=require_terminal)
        return journal
    except ProductionExecutionJournalError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        KeyError,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise ProductionExecutionJournalError(
            "invalid_production_journal_file",
            "Production execution journal file is invalid",
        ) from exc


def load_production_execution_journal_file(
    path: str | Path,
    *,
    require_terminal: bool = True,
) -> ProductionExecutionJournal:
    """Load one repository-external append-only journal without path disclosure."""

    try:
        safe_path = validate_sensitive_input_path(
            path,
            max_size=MAX_PRODUCTION_EXECUTION_JOURNAL_BYTES,
        )
    except SensitivePathError as exc:
        raise ProductionExecutionJournalError(
            "production_journal_read_failed",
            "Production execution journal could not be read safely",
        ) from exc
    descriptor = _open_locked_journal(safe_path, exclusive=False)
    try:
        return parse_production_execution_journal_file_bytes(
            _read_locked_journal(descriptor),
            require_terminal=require_terminal,
        )
    finally:
        _close_locked_journal(descriptor)


__all__ = [
    "MAX_PRODUCTION_EXECUTION_JOURNAL_BYTES",
    "MAX_PRODUCTION_EXECUTION_JOURNAL_ENTRIES",
    "PRODUCTION_EXECUTION_JOURNAL_GENESIS_HASH",
    "PRODUCTION_EXECUTION_PHASE_ORDER",
    "PRODUCTION_EXECUTION_SAFE_CODES",
    "ProductionExecutionJournal",
    "ProductionExecutionJournalEntry",
    "ProductionExecutionJournalEntryStatus",
    "ProductionExecutionJournalError",
    "ProductionExecutionJournalPhase",
    "ProductionExecutionJournalState",
    "append_production_execution_journal_entry",
    "append_production_execution_journal_file",
    "calculate_production_execution_journal_entry_hash",
    "calculate_production_execution_journal_hash",
    "calculate_production_execution_journal_header_hash",
    "create_production_execution_journal_file",
    "initialize_production_execution_journal",
    "load_production_execution_journal_file",
    "parse_production_execution_journal_file_bytes",
    "production_execution_journal_data",
    "render_production_execution_journal_json",
    "verify_production_execution_journal",
]
