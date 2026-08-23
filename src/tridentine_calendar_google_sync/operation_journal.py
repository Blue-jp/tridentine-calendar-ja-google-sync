"""Tamper-evident in-memory hash-chain journal for fake apply simulation."""

from __future__ import annotations

import hashlib
import hmac
import json
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import Field, ValidationError, model_validator

from tridentine_calendar_google_sync.apply_bundle import verify_apply_bundle_integrity
from tridentine_calendar_google_sync.apply_models import (
    ApplyBundle,
    ApplyBundleState,
    ApplyOperationKind,
)
from tridentine_calendar_google_sync.apply_policy import (
    PRODUCTION_TARGET_REFERENCE,
    ApplyGuardError,
    require_test_bundle,
)
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    read_sensitive_bytes,
)

MAX_OPERATION_JOURNAL_BYTES = 64 * 1024 * 1024
GENESIS_ENTRY_HASH = "0" * 64
_ENTRY_HASH_DOMAIN = b"tridentine-calendar-google-sync:operation-journal-entry:v1\x00"
_JOURNAL_HASH_DOMAIN = b"tridentine-calendar-google-sync:operation-journal:v1\x00"
_ABSENT_RESPONSE_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:operation-journal-absent-response:v1\x00"
)


class JournalEntryStatus(StrEnum):
    """Complete safe status vocabulary for simulation attempts and skips."""

    SUCCEEDED = "succeeded"
    RETRYING = "retrying"
    FAILED = "failed"
    UNCERTAIN = "uncertain"
    ETAG_CONFLICT = "etag_conflict"
    SKIPPED = "skipped"


class JournalState(StrEnum):
    """Aggregate journal lifecycle for sequential simulation."""

    INITIALIZED = "initialized"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL_FAILURE = "partial_failure"
    UNCERTAIN = "uncertain"
    ETAG_CONFLICT = "etag_conflict"
    BLOCKED = "blocked"


class OperationJournalEntry(StrictFrozenModel):
    """One safe hash-chained attempt or skipped operation observation."""

    sequence: int = Field(ge=0)
    operation_index: int = Field(ge=1)
    operation_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation: ApplyOperationKind
    source_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    google_ref: str | None = Field(default=None, pattern=r"^G-[0-9a-f]{12}$")
    attempt: int = Field(ge=0)
    status: JournalEntryStatus
    outcome_code: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    delay_units: int = Field(default=0, ge=0)
    payload_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    response_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_etag_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    result_state_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    previous_entry_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    entry_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def status_and_identity_shape_is_safe(self) -> Self:
        if self.operation is ApplyOperationKind.ADD and self.google_ref is not None:
            raise ValueError("add journal entry cannot have a Google reference")
        if self.operation is ApplyOperationKind.UPDATE and self.google_ref is None:
            raise ValueError("update journal entry requires a Google reference")
        if self.status is JournalEntryStatus.SKIPPED:
            if self.attempt != 0 or self.delay_units != 0:
                raise ValueError("skipped journal entry cannot record an attempt")
        elif self.attempt < 1:
            raise ValueError("attempted journal entry requires a positive attempt")
        if self.status is not JournalEntryStatus.RETRYING and self.delay_units != 0:
            raise ValueError("only retrying entries can record abstract delay units")
        return self


class OperationJournal(StrictFrozenModel):
    """Immutable private journal with no raw identity, ETag, or payload content."""

    schema_version: Literal["1.0"] = "1.0"
    journal_type: Literal["fake-apply-operation-journal-v1"] = "fake-apply-operation-journal-v1"
    start_marker: Literal["simulation_start"] = "simulation_start"
    completion_marker: Literal["simulation_complete", "simulation_failed"] | None
    state: JournalState
    bundle_integrity_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_integrity_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_reference: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    operation_count: int = Field(ge=1)
    entries: tuple[OperationJournalEntry, ...]
    entry_count: int = Field(ge=0)
    last_entry_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    mutation_mode: Literal["fake"] = "fake"
    rollback_available: Literal[False] = False
    journal_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def count_and_terminal_shape_is_coherent(self) -> Self:
        if self.entry_count != len(self.entries):
            raise ValueError("journal entry count mismatch")
        if self.entries:
            if self.last_entry_hash != self.entries[-1].entry_hash:
                raise ValueError("journal last hash mismatch")
        elif self.last_entry_hash != GENESIS_ENTRY_HASH:
            raise ValueError("empty journal must use the genesis hash")
        if self.state is JournalState.INITIALIZED and self.entries:
            raise ValueError("initialized journal must be empty")
        if (
            self.entries
            and max(entry.operation_index for entry in self.entries) > self.operation_count
        ):
            raise ValueError("journal operation index exceeds the operation count")
        if self.state in {JournalState.INITIALIZED, JournalState.RUNNING}:
            if self.completion_marker is not None:
                raise ValueError("nonterminal journal cannot have a completion marker")
        elif self.state is JournalState.COMPLETED:
            if self.completion_marker != "simulation_complete":
                raise ValueError("completed journal requires its completion marker")
        elif self.completion_marker != "simulation_failed":
            raise ValueError("failed journal requires its completion marker")
        return self


class OperationJournalError(ValueError):
    """Safe journal validation or IO failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _entry_hash_data(
    *,
    sequence: int,
    operation_index: int,
    operation_key: str,
    operation: ApplyOperationKind,
    source_ref: str,
    google_ref: str | None,
    attempt: int,
    status: JournalEntryStatus,
    outcome_code: str,
    delay_units: int,
    payload_hash: str,
    response_hash: str,
    expected_etag_hash: str | None,
    result_state_hash: str | None,
    previous_entry_hash: str,
) -> dict[str, object]:
    return {
        "sequence": sequence,
        "operation_index": operation_index,
        "operation_key": operation_key,
        "operation": operation.value,
        "source_ref": source_ref,
        "google_ref": google_ref,
        "attempt": attempt,
        "status": status.value,
        "outcome_code": outcome_code,
        "delay_units": delay_units,
        "payload_hash": payload_hash,
        "response_hash": response_hash,
        "expected_etag_hash": expected_etag_hash,
        "result_state_hash": result_state_hash,
        "previous_entry_hash": previous_entry_hash,
    }


def _hash_data(domain: bytes, data: object) -> str:
    encoded = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def calculate_journal_entry_hash(entry: OperationJournalEntry) -> str:
    """Recalculate one entry hash without trusting stored content."""

    return _hash_data(
        _ENTRY_HASH_DOMAIN,
        _entry_hash_data(
            sequence=entry.sequence,
            operation_index=entry.operation_index,
            operation_key=entry.operation_key,
            operation=entry.operation,
            source_ref=entry.source_ref,
            google_ref=entry.google_ref,
            attempt=entry.attempt,
            status=entry.status,
            outcome_code=entry.outcome_code,
            delay_units=entry.delay_units,
            payload_hash=entry.payload_hash,
            response_hash=entry.response_hash,
            expected_etag_hash=entry.expected_etag_hash,
            result_state_hash=entry.result_state_hash,
            previous_entry_hash=entry.previous_entry_hash,
        ),
    )


def _journal_hash_data(journal: OperationJournal) -> dict[str, object]:
    return {
        "schema_version": journal.schema_version,
        "journal_type": journal.journal_type,
        "start_marker": journal.start_marker,
        "completion_marker": journal.completion_marker,
        "state": journal.state.value,
        "bundle_integrity_hash": journal.bundle_integrity_hash,
        "plan_content_hash": journal.plan_content_hash,
        "baseline_integrity_hash": journal.baseline_integrity_hash,
        "target_reference": journal.target_reference,
        "operation_count": journal.operation_count,
        "entries": [entry.model_dump(mode="json") for entry in journal.entries],
        "entry_count": journal.entry_count,
        "last_entry_hash": journal.last_entry_hash,
        "mutation_mode": journal.mutation_mode,
        "rollback_available": journal.rollback_available,
    }


def calculate_operation_journal_hash(journal: OperationJournal) -> str:
    """Recalculate the aggregate journal hash."""

    return _hash_data(_JOURNAL_HASH_DOMAIN, _journal_hash_data(journal))


def _raise_semantic_error(code: str) -> None:
    raise OperationJournalError(code, "operation journal semantic verification failed")


def _verify_operation_journal_semantics(journal: OperationJournal) -> None:
    expected_completion_marker = {
        JournalState.INITIALIZED: None,
        JournalState.RUNNING: None,
        JournalState.COMPLETED: "simulation_complete",
        JournalState.PARTIAL_FAILURE: "simulation_failed",
        JournalState.UNCERTAIN: "simulation_failed",
        JournalState.ETAG_CONFLICT: "simulation_failed",
        JournalState.BLOCKED: "simulation_failed",
    }[journal.state]
    if (
        journal.start_marker != "simulation_start"
        or journal.completion_marker != expected_completion_marker
    ):
        _raise_semantic_error("journal_completion_marker_invalid")
    if journal.state is JournalState.INITIALIZED:
        if journal.entries:
            _raise_semantic_error("journal_initialized_entries_invalid")
        return
    if not journal.entries:
        _raise_semantic_error("journal_terminal_entries_missing")

    expected_operation_index = 1
    cursor = 0
    seen_operation_attempts: set[tuple[int, int]] = set()
    terminal_failure: JournalEntryStatus | None = None
    skipped_started = False
    last_group_was_retrying = False

    while cursor < len(journal.entries):
        operation_index = journal.entries[cursor].operation_index
        if operation_index != expected_operation_index:
            _raise_semantic_error("journal_operation_order_invalid")
        group_end = cursor + 1
        while (
            group_end < len(journal.entries)
            and journal.entries[group_end].operation_index == operation_index
        ):
            group_end += 1
        group = journal.entries[cursor:group_end]
        expected_operation_index += 1
        cursor = group_end

        identity = (
            group[0].operation_key,
            group[0].operation,
            group[0].source_ref,
            group[0].google_ref,
            group[0].payload_hash,
            group[0].expected_etag_hash,
        )
        for entry in group:
            pair = (entry.operation_index, entry.attempt)
            if pair in seen_operation_attempts:
                _raise_semantic_error("journal_operation_attempt_duplicate")
            seen_operation_attempts.add(pair)
            if (
                entry.operation_key,
                entry.operation,
                entry.source_ref,
                entry.google_ref,
                entry.payload_hash,
                entry.expected_etag_hash,
            ) != identity:
                _raise_semantic_error("journal_attempt_identity_mismatch")
            if entry.operation is ApplyOperationKind.ADD:
                if entry.expected_etag_hash is not None:
                    _raise_semantic_error("journal_add_etag_invalid")
            elif entry.expected_etag_hash is None:
                _raise_semantic_error("journal_update_etag_missing")

        if group[0].status is JournalEntryStatus.SKIPPED:
            if (
                terminal_failure is None
                or len(group) != 1
                or group[0].attempt != 0
                or group[0].outcome_code != "skipped_after_stop"
                or group[0].result_state_hash is not None
            ):
                _raise_semantic_error("journal_skipped_sequence_invalid")
            skipped_started = True
            last_group_was_retrying = False
            continue

        if terminal_failure is not None or skipped_started:
            _raise_semantic_error("journal_continued_after_terminal_stop")
        if tuple(entry.attempt for entry in group) != tuple(range(1, len(group) + 1)):
            _raise_semantic_error("journal_attempt_order_invalid")
        for retry_entry in group[:-1]:
            if (
                retry_entry.status is not JournalEntryStatus.RETRYING
                or retry_entry.outcome_code
                not in {"rate_limit", "server_500", "server_502", "server_503"}
                or retry_entry.delay_units < 1
                or retry_entry.result_state_hash is not None
            ):
                _raise_semantic_error("journal_retry_sequence_invalid")

        terminal_entry = group[-1]
        last_group_was_retrying = terminal_entry.status is JournalEntryStatus.RETRYING
        if last_group_was_retrying:
            if (
                cursor != len(journal.entries)
                or journal.state is not JournalState.RUNNING
                or terminal_entry.outcome_code
                not in {"rate_limit", "server_500", "server_502", "server_503"}
                or terminal_entry.delay_units < 1
                or terminal_entry.result_state_hash is not None
            ):
                _raise_semantic_error("journal_open_retry_invalid")
            continue
        if terminal_entry.status is JournalEntryStatus.SUCCEEDED:
            if terminal_entry.outcome_code != "success" or terminal_entry.result_state_hash is None:
                _raise_semantic_error("journal_success_entry_invalid")
        elif terminal_entry.status in {
            JournalEntryStatus.FAILED,
            JournalEntryStatus.UNCERTAIN,
            JournalEntryStatus.ETAG_CONFLICT,
        }:
            if terminal_entry.result_state_hash is not None:
                _raise_semantic_error("journal_failure_state_hash_invalid")
            allowed_outcomes = {
                JournalEntryStatus.FAILED: {
                    "validation_failure",
                    "permission_denied",
                    "target_missing",
                    "ambiguous_identity",
                    "duplicate_identity",
                    "permanent_failure",
                    "retry_exhausted",
                },
                JournalEntryStatus.UNCERTAIN: {"uncertain_outcome"},
                JournalEntryStatus.ETAG_CONFLICT: {"etag_conflict"},
            }[terminal_entry.status]
            if terminal_entry.outcome_code not in allowed_outcomes:
                _raise_semantic_error("journal_terminal_outcome_invalid")
            terminal_failure = terminal_entry.status
        else:
            _raise_semantic_error("journal_terminal_status_invalid")

    if journal.state is JournalState.RUNNING:
        if expected_operation_index - 1 > journal.operation_count:
            _raise_semantic_error("journal_operation_count_exceeded")
        return
    if last_group_was_retrying:
        _raise_semantic_error("journal_terminal_retry_incomplete")
    expected_failure = {
        JournalState.COMPLETED: None,
        JournalState.PARTIAL_FAILURE: JournalEntryStatus.FAILED,
        JournalState.UNCERTAIN: JournalEntryStatus.UNCERTAIN,
        JournalState.ETAG_CONFLICT: JournalEntryStatus.ETAG_CONFLICT,
        JournalState.BLOCKED: JournalEntryStatus.FAILED,
    }[journal.state]
    if terminal_failure is not expected_failure:
        _raise_semantic_error("journal_terminal_state_mismatch")
    if expected_operation_index - 1 != journal.operation_count:
        _raise_semantic_error("journal_terminal_operation_missing")


def verify_operation_journal(journal: OperationJournal) -> None:
    """Verify sequence, previous-hash chain, entry hashes, and aggregate hash."""

    expected_previous = GENESIS_ENTRY_HASH
    for expected_sequence, entry in enumerate(journal.entries):
        if entry.sequence != expected_sequence:
            raise OperationJournalError(
                "journal_sequence_mismatch",
                "journal entry sequence verification failed",
            )
        if not hmac.compare_digest(entry.previous_entry_hash, expected_previous):
            raise OperationJournalError(
                "journal_chain_mismatch",
                "journal hash chain verification failed",
            )
        if not hmac.compare_digest(calculate_journal_entry_hash(entry), entry.entry_hash):
            raise OperationJournalError(
                "journal_entry_hash_mismatch",
                "journal entry hash verification failed",
            )
        expected_previous = entry.entry_hash
    if journal.entry_count != len(journal.entries):
        raise OperationJournalError(
            "journal_count_mismatch",
            "journal entry count verification failed",
        )
    if not hmac.compare_digest(journal.last_entry_hash, expected_previous):
        raise OperationJournalError(
            "journal_last_hash_mismatch",
            "journal last hash verification failed",
        )
    if not hmac.compare_digest(
        calculate_operation_journal_hash(journal),
        journal.journal_content_hash,
    ):
        raise OperationJournalError(
            "journal_content_hash_mismatch",
            "journal content hash verification failed",
        )
    _verify_operation_journal_semantics(journal)


def _new_journal(
    *,
    state: JournalState,
    bundle_integrity_hash: str,
    plan_content_hash: str,
    baseline_integrity_hash: str,
    target_reference: str,
    operation_count: int,
    entries: tuple[OperationJournalEntry, ...],
) -> OperationJournal:
    last_hash = entries[-1].entry_hash if entries else GENESIS_ENTRY_HASH
    completion_marker: Literal["simulation_complete", "simulation_failed"] | None = {
        JournalState.INITIALIZED: None,
        JournalState.RUNNING: None,
        JournalState.COMPLETED: "simulation_complete",
        JournalState.PARTIAL_FAILURE: "simulation_failed",
        JournalState.UNCERTAIN: "simulation_failed",
        JournalState.ETAG_CONFLICT: "simulation_failed",
        JournalState.BLOCKED: "simulation_failed",
    }[state]
    provisional = OperationJournal(
        completion_marker=completion_marker,
        state=state,
        bundle_integrity_hash=bundle_integrity_hash,
        plan_content_hash=plan_content_hash,
        baseline_integrity_hash=baseline_integrity_hash,
        target_reference=target_reference,
        operation_count=operation_count,
        entries=entries,
        entry_count=len(entries),
        last_entry_hash=last_hash,
        journal_content_hash=GENESIS_ENTRY_HASH,
    )
    journal = provisional.model_copy(
        update={"journal_content_hash": calculate_operation_journal_hash(provisional)}
    )
    verify_operation_journal(journal)
    return journal


def initialize_operation_journal(bundle: ApplyBundle) -> OperationJournal:
    """Create an empty journal bound to an integrity-pinned private bundle."""

    verify_apply_bundle_integrity(bundle)
    require_test_bundle(bundle)
    if (
        bundle.state is not ApplyBundleState.APPROVED_FOR_SIMULATION
        or bundle.generated_operation_count == 0
        or bundle.delete_count != 0
        or bundle.generated_operation_count != bundle.add_count + bundle.update_count
    ):
        raise ApplyGuardError(
            "operation_journal_bundle_not_approved",
            "operation journal requires an approved nonzero test apply bundle",
        )
    return _new_journal(
        state=JournalState.INITIALIZED,
        bundle_integrity_hash=bundle.bundle_integrity_hash,
        plan_content_hash=bundle.plan_content_hash,
        baseline_integrity_hash=bundle.baseline_integrity_hash,
        target_reference=bundle.target_reference,
        operation_count=bundle.generated_operation_count,
        entries=(),
    )


def append_operation_journal_entry(
    journal: OperationJournal,
    *,
    operation_index: int,
    operation_key: str,
    operation: ApplyOperationKind,
    source_ref: str,
    google_ref: str | None,
    attempt: int,
    status: JournalEntryStatus,
    outcome_code: str,
    payload_hash: str,
    response_hash: str | None = None,
    expected_etag_hash: str | None = None,
    result_state_hash: str | None = None,
    delay_units: int = 0,
    state: JournalState = JournalState.RUNNING,
) -> OperationJournal:
    """Return a new journal with exactly one hash-chained entry appended."""

    verify_operation_journal(journal)
    if journal.state not in {JournalState.INITIALIZED, JournalState.RUNNING}:
        raise OperationJournalError(
            "journal_terminal_state",
            "cannot append to a terminal journal",
        )
    if operation_index > journal.operation_count:
        raise OperationJournalError(
            "journal_operation_count_exceeded",
            "journal operation index exceeds the approved operation count",
        )
    effective_response_hash = response_hash
    if effective_response_hash is None:
        effective_response_hash = _hash_data(
            _ABSENT_RESPONSE_HASH_DOMAIN,
            {
                "operation_key": operation_key,
                "attempt": attempt,
                "status": status.value,
                "outcome_code": outcome_code,
            },
        )
    data = _entry_hash_data(
        sequence=journal.entry_count,
        operation_index=operation_index,
        operation_key=operation_key,
        operation=operation,
        source_ref=source_ref,
        google_ref=google_ref,
        attempt=attempt,
        status=status,
        outcome_code=outcome_code,
        delay_units=delay_units,
        payload_hash=payload_hash,
        response_hash=effective_response_hash,
        expected_etag_hash=expected_etag_hash,
        result_state_hash=result_state_hash,
        previous_entry_hash=journal.last_entry_hash,
    )
    entry = OperationJournalEntry(
        sequence=journal.entry_count,
        operation_index=operation_index,
        operation_key=operation_key,
        operation=operation,
        source_ref=source_ref,
        google_ref=google_ref,
        attempt=attempt,
        status=status,
        outcome_code=outcome_code,
        delay_units=delay_units,
        payload_hash=payload_hash,
        response_hash=effective_response_hash,
        expected_etag_hash=expected_etag_hash,
        result_state_hash=result_state_hash,
        previous_entry_hash=journal.last_entry_hash,
        entry_hash=_hash_data(_ENTRY_HASH_DOMAIN, data),
    )
    return _new_journal(
        state=state,
        bundle_integrity_hash=journal.bundle_integrity_hash,
        plan_content_hash=journal.plan_content_hash,
        baseline_integrity_hash=journal.baseline_integrity_hash,
        target_reference=journal.target_reference,
        operation_count=journal.operation_count,
        entries=(*journal.entries, entry),
    )


def transition_operation_journal(
    journal: OperationJournal,
    state: JournalState,
) -> OperationJournal:
    """Return a rehashed terminal-state view without changing existing entries."""

    verify_operation_journal(journal)
    if journal.state not in {JournalState.INITIALIZED, JournalState.RUNNING}:
        raise OperationJournalError(
            "journal_terminal_state",
            "journal is already terminal",
        )
    if state in {JournalState.INITIALIZED, JournalState.RUNNING}:
        raise OperationJournalError(
            "journal_transition_invalid",
            "journal terminal transition is invalid",
        )
    return _new_journal(
        state=state,
        bundle_integrity_hash=journal.bundle_integrity_hash,
        plan_content_hash=journal.plan_content_hash,
        baseline_integrity_hash=journal.baseline_integrity_hash,
        target_reference=journal.target_reference,
        operation_count=journal.operation_count,
        entries=journal.entries,
    )


def operation_journal_data(journal: OperationJournal) -> dict[str, object]:
    """Return the complete safe journal document after full verification."""

    verify_operation_journal(journal)
    return {
        **_journal_hash_data(journal),
        "journal_content_hash": journal.journal_content_hash,
    }


def render_operation_journal_json(journal: OperationJournal) -> str:
    """Render deterministic private JSON without raw identity or payload content."""

    return (
        json.dumps(
            operation_journal_data(journal),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )


class _DuplicateJsonKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def parse_operation_journal_bytes(raw_bytes: bytes) -> OperationJournal:
    """Strictly parse and hash-verify one safe private journal document."""

    if len(raw_bytes) > MAX_OPERATION_JOURNAL_BYTES:
        raise OperationJournalError("journal_too_large", "operation journal is too large")
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        if not isinstance(value, dict):
            raise TypeError
        normalized = dict(value)
        normalized["state"] = JournalState(normalized["state"])
        raw_entries = normalized.get("entries")
        if not isinstance(raw_entries, list):
            raise TypeError
        entries: list[OperationJournalEntry] = []
        for raw_entry in raw_entries:
            if not isinstance(raw_entry, dict):
                raise TypeError
            item = dict(raw_entry)
            item["operation"] = ApplyOperationKind(item["operation"])
            item["status"] = JournalEntryStatus(item["status"])
            entries.append(OperationJournalEntry.model_validate(item, strict=True))
        normalized["entries"] = tuple(entries)
        journal = OperationJournal.model_validate(normalized, strict=True)
        verify_operation_journal(journal)
        return journal
    except OperationJournalError:
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
        raise OperationJournalError(
            "invalid_operation_journal",
            "operation journal is invalid",
        ) from exc


def load_operation_journal(path: str | Path) -> OperationJournal:
    """Load one repository-external safe journal path."""

    try:
        return parse_operation_journal_bytes(
            read_sensitive_bytes(path, max_size=MAX_OPERATION_JOURNAL_BYTES)
        )
    except OperationJournalError:
        raise
    except SensitivePathError as exc:
        raise OperationJournalError(
            "unsafe_operation_journal_path",
            "operation journal path is unsafe or unavailable",
        ) from exc


def write_operation_journal(journal: OperationJournal, path: str | Path) -> Path:
    """Atomically create the final private journal without overwrite."""

    verify_operation_journal(journal)
    if journal.target_reference == PRODUCTION_TARGET_REFERENCE:
        raise OperationJournalError(
            "production_operation_journal_write_forbidden",
            "Production operation journals cannot be written",
        )
    try:
        atomic_write_private_text(
            path,
            render_operation_journal_json(journal),
            overwrite=False,
            max_size=MAX_OPERATION_JOURNAL_BYTES,
        )
        return Path(path)
    except OperationJournalError:
        raise
    except SensitivePathError as exc:
        raise OperationJournalError(
            "operation_journal_write_failed",
            "operation journal could not be written safely",
        ) from exc


__all__ = [
    "GENESIS_ENTRY_HASH",
    "MAX_OPERATION_JOURNAL_BYTES",
    "JournalEntryStatus",
    "JournalState",
    "OperationJournal",
    "OperationJournalEntry",
    "OperationJournalError",
    "append_operation_journal_entry",
    "calculate_journal_entry_hash",
    "calculate_operation_journal_hash",
    "initialize_operation_journal",
    "load_operation_journal",
    "operation_journal_data",
    "parse_operation_journal_bytes",
    "render_operation_journal_json",
    "transition_operation_journal",
    "verify_operation_journal",
    "write_operation_journal",
]
