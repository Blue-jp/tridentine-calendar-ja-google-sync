"""Tamper-evident public-safe journal for one Test Calendar write run."""

from __future__ import annotations

import hashlib
import hmac
import json
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Self

from pydantic import Field, ValidationError, model_validator

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.google_errors import ALLOWED_GOOGLE_REASONS
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    read_sensitive_bytes,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteOperationKind,
    TestWriteRunSpec,
)
from tridentine_calendar_google_sync.test_write_run_spec import verify_test_write_run_spec

TEST_WRITE_JOURNAL_GENESIS_HASH = "0" * 64
MAX_TEST_WRITE_JOURNAL_BYTES = 64 * 1024 * 1024
_ENTRY_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-write-journal-entry:v1\x00"
_JOURNAL_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-write-journal:v1\x00"
TEST_WRITE_SAFE_ERROR_CODES = ALLOWED_GOOGLE_REASONS | frozenset(
    {
        "duplicate_identity",
        "production_or_mismatched_test_write_target",
        "production_test_write_forbidden",
        "test_write_add_identity_exists",
        "test_write_api_call_budget_exceeded",
        "test_write_desired_text_missing",
        "test_write_duplicate_identity",
        "test_write_guard_failed",
        "test_write_mutation_attempt_exceeded",
        "test_write_pagination_cycle",
        "test_write_pagination_limit",
        "test_write_read_back_etag_missing",
        "test_write_read_back_identity_missing",
        "test_write_read_back_mismatch",
        "test_write_read_retry_exhausted",
        "test_write_snapshot_hash_mismatch",
        "test_write_target_access_role_mismatch",
        "test_write_target_metadata_changed",
        "test_write_target_metadata_missing",
        "test_write_target_not_owned",
        "test_write_target_summary_mismatch",
        "test_write_target_timezone_mismatch",
        "test_write_update_identity_missing",
        "test_write_update_snapshot_mismatch",
        "unexpected_event_color_or_label",
        "write_outcome_uncertain",
    }
)


class TestWriteJournalPhase(StrEnum):
    """Safe phases in one guarded write lifecycle."""

    PREFLIGHT = "preflight"
    MUTATION = "mutation"
    READ_BACK = "read_back"
    UNCERTAIN_CHECK = "uncertain_check"
    COMPLETE = "complete"


class TestWriteJournalEntryStatus(StrEnum):
    """Safe per-phase outcomes."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNCERTAIN = "uncertain"
    RECOVERED = "recovered"


class TestWriteJournalState(StrEnum):
    """Terminal and nonterminal journal states."""

    INITIALIZED = "initialized"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    UNCERTAIN = "uncertain"
    ETAG_CONFLICT = "etag_conflict"


class TestWriteJournalEntry(StrictFrozenModel):
    """One cumulative safe observation in a hash chain."""

    sequence: int = Field(ge=0)
    run_spec_ref: str = Field(pattern=r"^R-[0-9a-f]{12}$")
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    source_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    operation: TestWriteOperationKind
    phase: TestWriteJournalPhase
    status: TestWriteJournalEntryStatus
    safe_error_code: str | None = Field(
        default=None,
        pattern=r"^[a-z][a-z0-9_]*$",
    )
    api_call_count: int = Field(ge=0, le=10)
    read_retry_count: int = Field(ge=0)
    mutation_attempt_count: int = Field(ge=0, le=1)
    mutation_retry_count: Literal[0] = 0
    recovered_after_uncertain: bool = False
    previous_entry_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    entry_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def safe_status_shape(self) -> Self:
        if (
            self.safe_error_code is not None
            and self.safe_error_code not in TEST_WRITE_SAFE_ERROR_CODES
        ):
            raise ValueError("journal error code is not allowlisted")
        if self.status is TestWriteJournalEntryStatus.SUCCEEDED and self.safe_error_code:
            raise ValueError("successful journal entry cannot have an error code")
        if self.status is TestWriteJournalEntryStatus.RECOVERED:
            if not self.recovered_after_uncertain or self.safe_error_code:
                raise ValueError("recovered journal entry shape is invalid")
        elif self.recovered_after_uncertain:
            raise ValueError("only a recovered entry may record recovery")
        if (
            self.status
            in {
                TestWriteJournalEntryStatus.FAILED,
                TestWriteJournalEntryStatus.UNCERTAIN,
            }
            and self.safe_error_code is None
        ):
            raise ValueError("failed journal entry requires a safe code")
        return self


class TestWriteJournal(StrictFrozenModel):
    """One immutable journal containing no raw write identity or content."""

    schema_version: Literal["1.0"] = "1.0"
    journal_type: Literal["test-write-operation-journal-v1"] = "test-write-operation-journal-v1"
    live_test_write: Literal[True] = True
    test_only: Literal[True] = True
    production_locked: Literal[True] = True
    run_spec_ref: str = Field(pattern=r"^R-[0-9a-f]{12}$")
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    source_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    operation: TestWriteOperationKind
    state: TestWriteJournalState
    entries: tuple[TestWriteJournalEntry, ...]
    entry_count: int = Field(ge=0)
    api_call_count: int = Field(ge=0, le=10)
    read_retry_count: int = Field(ge=0)
    mutation_attempt_count: int = Field(ge=0, le=1)
    mutation_retry_count: Literal[0] = 0
    recovered_after_uncertain: bool = False
    last_entry_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    rollback_available: Literal[False] = False
    journal_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def aggregate_shape(self) -> Self:
        if self.target_safe_ref == PRODUCTION_TARGET_REFERENCE:
            raise ValueError("Production Test write journal is forbidden")
        if self.entry_count != len(self.entries):
            raise ValueError("Test write journal entry count mismatch")
        expected_last = (
            self.entries[-1].entry_hash if self.entries else TEST_WRITE_JOURNAL_GENESIS_HASH
        )
        if self.last_entry_hash != expected_last:
            raise ValueError("Test write journal last hash mismatch")
        if self.entries:
            final = self.entries[-1]
            if (
                self.api_call_count != final.api_call_count
                or self.read_retry_count != final.read_retry_count
                or self.mutation_attempt_count != final.mutation_attempt_count
                or self.recovered_after_uncertain != final.recovered_after_uncertain
            ):
                raise ValueError("Test write journal aggregate counts mismatch")
        elif any(
            (
                self.api_call_count,
                self.read_retry_count,
                self.mutation_attempt_count,
                self.mutation_retry_count,
                self.recovered_after_uncertain,
            )
        ):
            raise ValueError("empty Test write journal must have zero counts")
        _verify_test_write_journal_semantics(self)
        return self


class TestWriteJournalError(ValueError):
    """A content-free journal validation failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _verify_test_write_journal_semantics(journal: TestWriteJournal) -> None:
    """Require an exact lifecycle topology, not merely recomputable hashes."""

    shape = tuple((entry.phase, entry.status) for entry in journal.entries)
    preflight_succeeded = (
        TestWriteJournalPhase.PREFLIGHT,
        TestWriteJournalEntryStatus.SUCCEEDED,
    )
    mutation_succeeded = (
        TestWriteJournalPhase.MUTATION,
        TestWriteJournalEntryStatus.SUCCEEDED,
    )
    mutation_uncertain = (
        TestWriteJournalPhase.MUTATION,
        TestWriteJournalEntryStatus.UNCERTAIN,
    )
    running_shapes = {
        (preflight_succeeded,),
        (preflight_succeeded, mutation_succeeded),
        (preflight_succeeded, mutation_uncertain),
    }
    completed_shapes = {
        (
            preflight_succeeded,
            mutation_succeeded,
            (TestWriteJournalPhase.READ_BACK, TestWriteJournalEntryStatus.SUCCEEDED),
        ),
        (
            preflight_succeeded,
            mutation_uncertain,
            (TestWriteJournalPhase.UNCERTAIN_CHECK, TestWriteJournalEntryStatus.RECOVERED),
        ),
    }
    failed_shapes = {
        ((TestWriteJournalPhase.PREFLIGHT, TestWriteJournalEntryStatus.FAILED),),
        (
            preflight_succeeded,
            (TestWriteJournalPhase.MUTATION, TestWriteJournalEntryStatus.FAILED),
        ),
        (
            preflight_succeeded,
            mutation_succeeded,
            (TestWriteJournalPhase.READ_BACK, TestWriteJournalEntryStatus.FAILED),
        ),
        (
            preflight_succeeded,
            mutation_uncertain,
            (TestWriteJournalPhase.UNCERTAIN_CHECK, TestWriteJournalEntryStatus.FAILED),
        ),
    }
    uncertain_shape = (
        preflight_succeeded,
        mutation_uncertain,
        (TestWriteJournalPhase.UNCERTAIN_CHECK, TestWriteJournalEntryStatus.UNCERTAIN),
    )
    etag_conflict_shapes = {
        ((TestWriteJournalPhase.PREFLIGHT, TestWriteJournalEntryStatus.FAILED),),
        (
            preflight_succeeded,
            (TestWriteJournalPhase.MUTATION, TestWriteJournalEntryStatus.FAILED),
        ),
    }

    valid_shape = {
        TestWriteJournalState.INITIALIZED: shape == (),
        TestWriteJournalState.RUNNING: shape in running_shapes,
        TestWriteJournalState.COMPLETED: shape in completed_shapes,
        TestWriteJournalState.FAILED: shape in failed_shapes,
        TestWriteJournalState.UNCERTAIN: shape == uncertain_shape,
        TestWriteJournalState.ETAG_CONFLICT: shape in etag_conflict_shapes,
    }[journal.state]
    if not valid_shape:
        raise TestWriteJournalError(
            "test_write_journal_lifecycle_mismatch",
            "Test write journal lifecycle verification failed",
        )

    if journal.entries:
        first = journal.entries[0]
        if (
            first.phase is not TestWriteJournalPhase.PREFLIGHT
            or first.api_call_count < 1
            or first.mutation_attempt_count != 0
        ):
            raise TestWriteJournalError(
                "test_write_journal_preflight_mismatch",
                "Test write journal preflight verification failed",
            )
        for entry in journal.entries:
            expected_mutations = 0 if entry.phase is TestWriteJournalPhase.PREFLIGHT else 1
            if (
                entry.mutation_attempt_count != expected_mutations
                or entry.read_retry_count > entry.api_call_count
            ):
                raise TestWriteJournalError(
                    "test_write_journal_counter_semantics_mismatch",
                    "Test write journal counter verification failed",
                )
        for previous, current in zip(journal.entries, journal.entries[1:], strict=False):
            if current.api_call_count <= previous.api_call_count:
                raise TestWriteJournalError(
                    "test_write_journal_api_sequence_mismatch",
                    "Test write journal API sequence verification failed",
                )

    if journal.state is TestWriteJournalState.COMPLETED:
        if journal.mutation_attempt_count != 1 or journal.api_call_count < 3:
            raise TestWriteJournalError(
                "test_write_journal_completion_mismatch",
                "Completed Test write journal verification failed",
            )
    elif journal.state is TestWriteJournalState.ETAG_CONFLICT:
        final = journal.entries[-1]
        if final.safe_error_code != "etag_conflict":
            raise TestWriteJournalError(
                "test_write_journal_etag_conflict_mismatch",
                "ETag conflict journal verification failed",
            )
    elif journal.state is TestWriteJournalState.FAILED:
        if journal.entries[-1].safe_error_code == "etag_conflict":
            raise TestWriteJournalError(
                "test_write_journal_failed_state_mismatch",
                "Failed Test write journal verification failed",
            )
    elif journal.state is TestWriteJournalState.UNCERTAIN:
        final = journal.entries[-1]
        if final.safe_error_code != "write_outcome_uncertain":
            raise TestWriteJournalError(
                "test_write_journal_uncertain_mismatch",
                "Uncertain Test write journal verification failed",
            )


def _hash(domain: bytes, value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def _entry_data(entry: TestWriteJournalEntry) -> dict[str, object]:
    return {
        "sequence": entry.sequence,
        "run_spec_ref": entry.run_spec_ref,
        "target_safe_ref": entry.target_safe_ref,
        "source_ref": entry.source_ref,
        "operation": entry.operation.value,
        "phase": entry.phase.value,
        "status": entry.status.value,
        "safe_error_code": entry.safe_error_code,
        "api_call_count": entry.api_call_count,
        "read_retry_count": entry.read_retry_count,
        "mutation_attempt_count": entry.mutation_attempt_count,
        "mutation_retry_count": entry.mutation_retry_count,
        "recovered_after_uncertain": entry.recovered_after_uncertain,
        "previous_entry_hash": entry.previous_entry_hash,
    }


def calculate_test_write_journal_entry_hash(entry: TestWriteJournalEntry) -> str:
    """Recalculate one entry hash without trusting the stored digest."""

    return _hash(_ENTRY_HASH_DOMAIN, _entry_data(entry))


def _journal_data(journal: TestWriteJournal) -> dict[str, object]:
    return {
        "schema_version": journal.schema_version,
        "journal_type": journal.journal_type,
        "live_test_write": journal.live_test_write,
        "test_only": journal.test_only,
        "production_locked": journal.production_locked,
        "run_spec_ref": journal.run_spec_ref,
        "target_safe_ref": journal.target_safe_ref,
        "source_ref": journal.source_ref,
        "operation": journal.operation.value,
        "state": journal.state.value,
        "entries": [entry.model_dump(mode="json") for entry in journal.entries],
        "entry_count": journal.entry_count,
        "api_call_count": journal.api_call_count,
        "read_retry_count": journal.read_retry_count,
        "mutation_attempt_count": journal.mutation_attempt_count,
        "mutation_retry_count": journal.mutation_retry_count,
        "recovered_after_uncertain": journal.recovered_after_uncertain,
        "last_entry_hash": journal.last_entry_hash,
        "rollback_available": journal.rollback_available,
    }


def calculate_test_write_journal_hash(journal: TestWriteJournal) -> str:
    """Recalculate the aggregate journal hash."""

    return _hash(_JOURNAL_HASH_DOMAIN, _journal_data(journal))


def initialize_test_write_journal(run_spec: TestWriteRunSpec) -> TestWriteJournal:
    """Verify one Test-only Run Spec and create its empty safe journal."""

    verify_test_write_run_spec(run_spec)
    if run_spec.target_safe_ref == PRODUCTION_TARGET_REFERENCE:
        raise TestWriteJournalError(
            "production_test_write_forbidden",
            "Production Calendar write access is forbidden",
        )
    provisional = TestWriteJournal(
        run_spec_ref=f"R-{run_spec.run_spec_content_hash[:12]}",
        target_safe_ref=run_spec.target_safe_ref,
        source_ref=run_spec.operation.source_ref,
        operation=run_spec.operation.operation,
        state=TestWriteJournalState.INITIALIZED,
        entries=(),
        entry_count=0,
        api_call_count=0,
        read_retry_count=0,
        mutation_attempt_count=0,
        mutation_retry_count=0,
        recovered_after_uncertain=False,
        last_entry_hash=TEST_WRITE_JOURNAL_GENESIS_HASH,
        journal_content_hash="0" * 64,
    )
    return provisional.model_copy(
        update={"journal_content_hash": calculate_test_write_journal_hash(provisional)}
    )


def append_test_write_journal_entry(
    journal: TestWriteJournal,
    *,
    phase: TestWriteJournalPhase,
    status: TestWriteJournalEntryStatus,
    api_call_count: int,
    read_retry_count: int,
    mutation_attempt_count: int,
    safe_error_code: str | None = None,
    recovered_after_uncertain: bool = False,
    terminal_state: TestWriteJournalState | None = None,
) -> TestWriteJournal:
    """Append one cumulative safe entry and rebuild both integrity hashes."""

    verify_test_write_journal(journal)
    if journal.state not in {
        TestWriteJournalState.INITIALIZED,
        TestWriteJournalState.RUNNING,
    }:
        raise TestWriteJournalError(
            "test_write_journal_already_terminal",
            "Test write journal is already terminal",
        )
    if journal.entries:
        previous = journal.entries[-1]
        if (
            api_call_count < previous.api_call_count
            or read_retry_count < previous.read_retry_count
            or mutation_attempt_count < previous.mutation_attempt_count
        ):
            raise TestWriteJournalError(
                "test_write_journal_counts_regressed",
                "Test write journal counts are invalid",
            )
    if api_call_count > 10 or mutation_attempt_count > 1:
        raise TestWriteJournalError(
            "test_write_journal_budget_exceeded",
            "Test write journal safety budget was exceeded",
        )
    entry_provisional = TestWriteJournalEntry(
        sequence=len(journal.entries),
        run_spec_ref=journal.run_spec_ref,
        target_safe_ref=journal.target_safe_ref,
        source_ref=journal.source_ref,
        operation=journal.operation,
        phase=phase,
        status=status,
        safe_error_code=safe_error_code,
        api_call_count=api_call_count,
        read_retry_count=read_retry_count,
        mutation_attempt_count=mutation_attempt_count,
        mutation_retry_count=0,
        recovered_after_uncertain=recovered_after_uncertain,
        previous_entry_hash=journal.last_entry_hash,
        entry_hash="0" * 64,
    )
    entry = entry_provisional.model_copy(
        update={"entry_hash": calculate_test_write_journal_entry_hash(entry_provisional)}
    )
    state = terminal_state or TestWriteJournalState.RUNNING
    entries = (*journal.entries, entry)
    provisional = journal.model_copy(
        update={
            "state": state,
            "entries": entries,
            "entry_count": len(entries),
            "api_call_count": api_call_count,
            "read_retry_count": read_retry_count,
            "mutation_attempt_count": mutation_attempt_count,
            "recovered_after_uncertain": recovered_after_uncertain,
            "last_entry_hash": entry.entry_hash,
            "journal_content_hash": "0" * 64,
        }
    )
    result = provisional.model_copy(
        update={"journal_content_hash": calculate_test_write_journal_hash(provisional)}
    )
    verify_test_write_journal(result)
    return result


def verify_test_write_journal(journal: TestWriteJournal) -> None:
    """Verify safe identity, sequence, chain, and aggregate content hash."""

    _verify_test_write_journal_semantics(journal)
    if journal.target_safe_ref == PRODUCTION_TARGET_REFERENCE:
        raise TestWriteJournalError(
            "production_test_write_forbidden",
            "Production Calendar write access is forbidden",
        )
    expected_previous = TEST_WRITE_JOURNAL_GENESIS_HASH
    previous_counts = (0, 0, 0)
    for expected_sequence, entry in enumerate(journal.entries):
        if entry.sequence != expected_sequence:
            raise TestWriteJournalError(
                "test_write_journal_sequence_mismatch",
                "Test write journal sequence verification failed",
            )
        if (
            entry.run_spec_ref != journal.run_spec_ref
            or entry.target_safe_ref != journal.target_safe_ref
            or entry.source_ref != journal.source_ref
            or entry.operation is not journal.operation
        ):
            raise TestWriteJournalError(
                "test_write_journal_identity_mismatch",
                "Test write journal identity verification failed",
            )
        if not hmac.compare_digest(entry.previous_entry_hash, expected_previous):
            raise TestWriteJournalError(
                "test_write_journal_chain_mismatch",
                "Test write journal hash-chain verification failed",
            )
        if not hmac.compare_digest(
            calculate_test_write_journal_entry_hash(entry),
            entry.entry_hash,
        ):
            raise TestWriteJournalError(
                "test_write_journal_entry_hash_mismatch",
                "Test write journal entry verification failed",
            )
        counts = (
            entry.api_call_count,
            entry.read_retry_count,
            entry.mutation_attempt_count,
        )
        if any(current < prior for current, prior in zip(counts, previous_counts, strict=True)):
            raise TestWriteJournalError(
                "test_write_journal_count_order_mismatch",
                "Test write journal count verification failed",
            )
        previous_counts = counts
        expected_previous = entry.entry_hash
    if journal.entry_count != len(journal.entries) or not hmac.compare_digest(
        journal.last_entry_hash,
        expected_previous,
    ):
        raise TestWriteJournalError(
            "test_write_journal_aggregate_mismatch",
            "Test write journal aggregate verification failed",
        )
    if not hmac.compare_digest(
        calculate_test_write_journal_hash(journal),
        journal.journal_content_hash,
    ):
        raise TestWriteJournalError(
            "test_write_journal_content_hash_mismatch",
            "Test write journal content verification failed",
        )


def test_write_journal_data(journal: TestWriteJournal) -> dict[str, object]:
    """Return the canonical safe journal document after full verification."""

    verify_test_write_journal(journal)
    return {
        **_journal_data(journal),
        "journal_content_hash": journal.journal_content_hash,
    }


def render_test_write_journal_json(journal: TestWriteJournal) -> str:
    """Render deterministic JSON containing no raw identity or event content."""

    return (
        json.dumps(
            test_write_journal_data(journal),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
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


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def parse_test_write_journal_bytes(raw_bytes: bytes) -> TestWriteJournal:
    """Strictly parse and integrity-check one bounded safe journal."""

    if len(raw_bytes) > MAX_TEST_WRITE_JOURNAL_BYTES:
        raise TestWriteJournalError(
            "test_write_journal_too_large",
            "Test write journal exceeds the size limit",
        )
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict):
            raise TypeError
        normalized = dict(value)
        normalized["operation"] = TestWriteOperationKind(normalized["operation"])
        normalized["state"] = TestWriteJournalState(normalized["state"])
        raw_entries = normalized.get("entries")
        if not isinstance(raw_entries, list):
            raise TypeError
        entries: list[TestWriteJournalEntry] = []
        for raw_entry in raw_entries:
            if not isinstance(raw_entry, dict):
                raise TypeError
            item = dict(raw_entry)
            item["operation"] = TestWriteOperationKind(item["operation"])
            item["phase"] = TestWriteJournalPhase(item["phase"])
            item["status"] = TestWriteJournalEntryStatus(item["status"])
            entries.append(TestWriteJournalEntry.model_validate(item, strict=True))
        normalized["entries"] = tuple(entries)
        journal = TestWriteJournal.model_validate(normalized, strict=True)
        verify_test_write_journal(journal)
        return journal
    except TestWriteJournalError:
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
        raise TestWriteJournalError(
            "invalid_test_write_journal",
            "Test write journal is invalid",
        ) from exc


def load_test_write_journal(path: str | Path) -> TestWriteJournal:
    """Load one bounded repository-external journal without path disclosure."""

    try:
        return parse_test_write_journal_bytes(
            read_sensitive_bytes(path, max_size=MAX_TEST_WRITE_JOURNAL_BYTES)
        )
    except TestWriteJournalError:
        raise
    except SensitivePathError as exc:
        raise TestWriteJournalError(
            "unsafe_test_write_journal_path",
            "Test write journal path is unsafe or unavailable",
        ) from exc


def write_test_write_journal(journal: TestWriteJournal, path: str | Path) -> Path:
    """Atomically create a repository-external journal without overwrite."""

    verify_test_write_journal(journal)
    if journal.target_safe_ref == PRODUCTION_TARGET_REFERENCE:
        raise TestWriteJournalError(
            "production_test_write_journal_forbidden",
            "Production Test write journal output is forbidden",
        )
    try:
        atomic_write_private_text(
            path,
            render_test_write_journal_json(journal),
            overwrite=False,
            max_size=MAX_TEST_WRITE_JOURNAL_BYTES,
        )
        return Path(path)
    except SensitivePathError as exc:
        raise TestWriteJournalError(
            "test_write_journal_write_failed",
            "Test write journal could not be written safely",
        ) from exc


__all__ = [
    "MAX_TEST_WRITE_JOURNAL_BYTES",
    "TEST_WRITE_JOURNAL_GENESIS_HASH",
    "TEST_WRITE_SAFE_ERROR_CODES",
    "TestWriteJournal",
    "TestWriteJournalEntry",
    "TestWriteJournalEntryStatus",
    "TestWriteJournalError",
    "TestWriteJournalPhase",
    "TestWriteJournalState",
    "append_test_write_journal_entry",
    "calculate_test_write_journal_entry_hash",
    "calculate_test_write_journal_hash",
    "initialize_test_write_journal",
    "load_test_write_journal",
    "parse_test_write_journal_bytes",
    "render_test_write_journal_json",
    "test_write_journal_data",
    "verify_test_write_journal",
    "write_test_write_journal",
]
