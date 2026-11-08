"""Standalone synthetic start records; no credential or execution authority.

Linux storage calls own one advisory directory lock and retain an occupied slot.
The caller-supplied binding is not authenticated enrollment. A confirmed write
covers only the observed save/checkpoint interval, not crash durability or a
positive attestation of every descriptor close. Cancellation is never success.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from contextlib import AbstractContextManager, ExitStack
from dataclasses import dataclass, field, fields
from enum import StrEnum
from pathlib import Path
from types import TracebackType
from typing import Literal, Never, Protocol, TypeGuard

from tridentine_calendar_google_sync import _posix_private_create as private_create
from tridentine_calendar_google_sync import _posix_private_lock as private_lock
from tridentine_calendar_google_sync.sensitive_paths import (
    read_private_sensitive_bytes,
    validate_sensitive_output_path,
)

RECORD_LEAF = "production-write-operation-start-v1.json"
MAX_RECORD_BYTES = 4096


class OperationKind(StrEnum):
    NEW_PAIR = "new_pair"
    REFRESH = "refresh"


class RecordState(StrEnum):
    START_CONFIRMED = "start_confirmed"
    START_OBSERVED = "start_observed"
    SLOT_OCCUPIED = "slot_occupied"
    UNVERIFIABLE = "unverifiable"
    PERSISTENCE_UNCERTAIN = "persistence_uncertain"
    LOCK_BUSY = "lock_busy"
    LOCK_UNAVAILABLE = "lock_unavailable"
    UNSUPPORTED_PLATFORM = "unsupported_platform"


@dataclass(frozen=True, slots=True)
class SyntheticBinding:
    """Explicit test metadata, not registration authority or a path capability."""

    directory: Path = field(repr=False)
    storage_ref: str = field(repr=False)
    pair_ref: str = field(repr=False)
    token_slot: str = field(repr=False)
    state_slot: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class RecordOperation:
    operation_id: str = field(repr=False)
    predecessor_id: str | None = field(repr=False)
    kind: OperationKind = field(repr=False)


@dataclass(frozen=True, slots=True)
class RecordResult:
    """Fixed observations only; publication evidence is local to this call."""

    state: RecordState
    publication_possible: bool | None = False
    reuse_authorized: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if (
            type(self.state) is not RecordState
            or (
                self.publication_possible is not None
                and type(self.publication_possible) is not bool
            )
            or self.reuse_authorized is not False
        ):
            raise ValueError("Invalid operation-record result")


class _RecordFormatError(ValueError):
    def __init__(self) -> None:
        super().__init__("Invalid synthetic operation-start record")


def _valid_ref(value: object) -> TypeGuard[str]:
    return (
        type(value) is str
        and 1 <= len(value) <= 96
        and value.isascii()
        and value[0].isalnum()
        and all(character.isalnum() or character in "._-" for character in value)
    )


def _valid_slot(value: object) -> TypeGuard[str]:
    # Keep slot labels portable; never use them as I/O destinations.
    return (
        _valid_ref(value)
        and not value.endswith(".")
        and value.split(".", 1)[0].upper()
        not in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            *(f"COM{i}" for i in range(1, 10)),
            *(f"LPT{i}" for i in range(1, 10)),
        }
    )


def _valid_directory(value: object) -> TypeGuard[Path]:
    # Path has already normalized some spelling; do not claim to recover it.
    if type(value) is not type(Path()):
        return False
    if not isinstance(value, Path) or not value.is_absolute() or not value.name:
        return False
    if value.anchor.startswith(("//", "\\\\")) or "\x00" in str(value):
        return False
    return all(
        part not in {".", "..", ".git"}
        and not part.endswith((" ", "."))
        and not any(character in part for character in "\\:\x00")
        for part in value.parts[1:]
    )


def _valid_binding(value: object) -> TypeGuard[SyntheticBinding]:
    return (
        type(value) is SyntheticBinding
        and _valid_directory(value.directory)
        and _valid_ref(value.storage_ref)
        and _valid_ref(value.pair_ref)
        and _valid_slot(value.token_slot)
        and _valid_slot(value.state_slot)
        and len({value.token_slot, value.state_slot, RECORD_LEAF}) == 3
    )


def _valid_operation(value: object) -> TypeGuard[RecordOperation]:
    if (
        type(value) is not RecordOperation
        or not _valid_ref(value.operation_id)
        or type(value.kind) is not OperationKind
    ):
        return False
    if value.kind is OperationKind.NEW_PAIR:
        return value.predecessor_id is None
    return _valid_ref(value.predecessor_id) and value.predecessor_id != value.operation_id


def _record_data(binding: SyntheticBinding, operation: RecordOperation) -> dict[str, object]:
    return {
        "format_version": 1,
        "record_kind": "production_write_operation_start",
        "storage_ref": binding.storage_ref,
        "pair_ref": binding.pair_ref,
        "role": "production_write",
        "token_slot": binding.token_slot,
        "state_slot": binding.state_slot,
        "operation_id": operation.operation_id,
        "predecessor_id": operation.predecessor_id,
        "operation_kind": operation.kind.value,
        "phase": "started",
        "outcome": "incomplete",
    }


def _encode_start_record(binding: object, operation: object) -> bytes:
    """Pure private codec; storage APIs never return the input references."""

    if not _valid_binding(binding) or not _valid_operation(operation):
        raise _RecordFormatError()
    encoded = (
        json.dumps(
            _record_data(binding, operation),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")
    if len(encoded) > MAX_RECORD_BYTES:
        raise _RecordFormatError()
    return encoded


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _RecordFormatError()
        result[key] = value
    return result


def _reject_constant(_value: str) -> object:
    raise _RecordFormatError()


def _matches_start_record(raw: object, binding: object, operation: object) -> bool:
    """Reject malformed, noncanonical or foreign bytes without reflecting them."""

    if (
        type(raw) is not bytes
        or not 0 < len(raw) <= MAX_RECORD_BYTES
        or raw.startswith(b"\xef\xbb\xbf")
        or not _valid_binding(binding)
        or not _valid_operation(operation)
    ):
        return False
    try:
        decoded: object = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        expected = _record_data(binding, operation)
        if type(decoded) is not dict or decoded.keys() != expected.keys():
            return False
        # Exact types prevent True from matching version 1; nested data is refused.
        if any(type(decoded[key]) is not type(value) for key, value in expected.items()):
            return False
        return decoded == expected and raw == _encode_start_record(binding, operation)
    except (ValueError, RecursionError):
        return False


def _failure_result(
    error: Exception, *, publisher_entered: bool, publication_possible: bool | None
) -> RecordResult:
    if publisher_entered:
        return RecordResult(RecordState.PERSISTENCE_UNCERTAIN, publication_possible)
    if type(error) is private_lock.PosixPrivateLockError:
        busy = type(error.code) is str and error.code == "posix_directory_lock_busy"
        return RecordResult(RecordState.LOCK_BUSY if busy else RecordState.LOCK_UNAVAILABLE)
    return RecordResult(RecordState.UNVERIFIABLE)


def _linux_storage_available() -> bool:
    return sys.platform == "linux" and os.name == "posix"


class _ScopePhase(StrEnum):
    NEW = "new"
    ACTIVE = "active"
    FAILED = "failed"
    CLOSED = "closed"


class _HeldCheckpoint(StrEnum):
    HELD_START_CHECKPOINT = "held_start_checkpoint"
    HELD_START_OBSERVED = "held_start_observed"


@dataclass(frozen=True, slots=True)
class _HeldResult:
    checkpoint: _HeldCheckpoint | None = None
    refusal: RecordState | None = None
    publication_possible: bool | None = False
    reuse_authorized: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if (
            (self.checkpoint is None) == (self.refusal is None)
            or (self.checkpoint is not None and type(self.checkpoint) is not _HeldCheckpoint)
            or (
                self.refusal is not None
                and (
                    type(self.refusal) is not RecordState
                    or self.refusal in {RecordState.START_CONFIRMED, RecordState.START_OBSERVED}
                )
            )
            or (
                self.publication_possible is not None
                and type(self.publication_possible) is not bool
            )
            or self.reuse_authorized is not False
        ):
            raise ValueError("Invalid held-record result")


class _ScopeUseError(ValueError):
    def __init__(self) -> None:
        super().__init__("Invalid operation-record scope")


class _ScopeFailure(ValueError):
    def __init__(self, result: RecordResult) -> None:
        self.result = result
        super().__init__("Operation-record scope failed")


class _NoScopeCopy:
    __slots__ = ()

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise _ScopeUseError()

    def __repr__(self) -> str:
        return "<private record ownership>"

    def __copy__(self) -> Never:
        raise _ScopeUseError()

    def __deepcopy__(self, _memo: dict[int, object]) -> Never:
        raise _ScopeUseError()

    def __reduce_ex__(self, _protocol: object, /) -> Never:
        raise _ScopeUseError()


class _Checkpoint(Protocol):
    def revalidate(self) -> None: ...


@dataclass(init=False, repr=False, eq=False, slots=True)
class _HeldRecordScope(_NoScopeCopy):
    _owner: _RecordScopeContext


@dataclass(init=False, repr=False, eq=False, slots=True)
class _RecordScopeContext(_NoScopeCopy, AbstractContextManager[_HeldRecordScope]):
    _factory_identity: _RecordScopeContext
    _binding_input: object
    _operation_input: object
    _revision_input: object
    _binding: SyntheticBinding | None
    _operation: RecordOperation | None
    _revision: str | None
    _pid: int
    _thread: threading.Thread
    _phase: _ScopePhase
    _scope: _HeldRecordScope | None
    _stack: ExitStack | None
    _held: _Checkpoint | None
    _busy: bool
    _entering: bool
    _create_attempted: bool
    _creation_publication: bool | None
    _first_failure: RecordResult | None
    _cancellation: BaseException | None
    _link: _SharedStartSessionContext | None

    def _check_owner(self) -> None:
        if type(self) is not _RecordScopeContext:
            raise _ScopeUseError()
        try:
            valid = (
                self._factory_identity is self
                and self._pid == os.getpid()
                and self._thread is threading.current_thread()
                and self._thread.is_alive()
            )
        except AttributeError:
            raise _ScopeUseError() from None
        if not valid:
            raise _ScopeUseError()

    def _remember(self, result: RecordResult) -> None:
        if self._first_failure is None:
            self._first_failure = result
        self._phase = _ScopePhase.FAILED

    def __enter__(self) -> _HeldRecordScope:
        self._check_owner()
        if self._phase is not _ScopePhase.NEW or self._entering:
            # Invalid reentry must not release or invalidate an existing owner.
            raise _ScopeUseError()
        self._entering = True
        try:
            if not _linux_storage_available():
                self._remember(RecordResult(RecordState.UNSUPPORTED_PLATFORM))
                raise _ScopeFailure(RecordResult(RecordState.UNSUPPORTED_PLATFORM))
            binding, operation, revision = (
                self._binding_input,
                self._operation_input,
                self._revision_input,
            )
            if (
                not _valid_binding(binding)
                or not _valid_operation(operation)
                or (revision is not None and not _valid_ref(revision))
            ):
                self._remember(RecordResult(RecordState.UNVERIFIABLE))
                raise _ScopeFailure(RecordResult(RecordState.UNVERIFIABLE))
            try:
                _encode_start_record(binding, operation)
            except _RecordFormatError:
                self._remember(RecordResult(RecordState.UNVERIFIABLE))
                raise _ScopeFailure(RecordResult(RecordState.UNVERIFIABLE)) from None
            self._binding = SyntheticBinding(
                binding.directory,
                binding.storage_ref,
                binding.pair_ref,
                binding.token_slot,
                binding.state_slot,
            )
            self._operation = RecordOperation(
                operation.operation_id, operation.predecessor_id, operation.kind
            )
            self._revision = revision if type(revision) is str else None
            stack = ExitStack()
            try:
                self._held = stack.enter_context(
                    private_lock.acquire_posix_private_directory_lock(binding.directory)
                )
                self._stack = stack
                scope = object.__new__(_HeldRecordScope)
                scope._owner = self
                self._scope = scope
                self._phase = _ScopePhase.ACTIVE
                return scope
            except BaseException as error:
                self._phase = _ScopePhase.FAILED
                self._held = None
                self._stack = None
                if isinstance(error, Exception):
                    self._remember(
                        _failure_result(error, publisher_entered=False, publication_possible=False)
                    )
                try:
                    stack.__exit__(type(error), error, error.__traceback__)
                except BaseException as cleanup:
                    if not isinstance(error, Exception):
                        raise error from None
                    if not isinstance(cleanup, Exception):
                        raise
                if not isinstance(error, Exception):
                    raise
                if self._first_failure is None:
                    raise _ScopeUseError() from None
                raise _ScopeFailure(self._first_failure) from None
        except BaseException as error:
            # Only an accepted first entry reaches this handler. Precondition
            # refusals above must leave the legitimate owner untouched.
            self._phase = _ScopePhase.FAILED
            self._scope = None
            self._cancellation = None
            if not isinstance(error, Exception):
                raise
            failure = self._first_failure
            if failure is None:
                failure = _failure_result(
                    error, publisher_entered=False, publication_possible=False
                )
                self._remember(failure)
            raise _ScopeFailure(failure) from None
        finally:
            self._entering = False

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        self._check_owner()
        if self._link is not None:
            raise _ScopeUseError()
        if (
            self._phase not in {_ScopePhase.ACTIVE, _ScopePhase.FAILED}
            or self._stack is None
            or self._busy
            or self._entering
        ):
            raise _ScopeUseError()
        stack, self._stack = self._stack, None
        self._held = None
        self._phase = _ScopePhase.CLOSED
        cancellation = self._cancellation
        terminal = self._first_failure
        # Occupation is an observation. Preserve the public exit-error behavior
        # while retaining that earlier observation in the private owner.
        has_error = terminal is not None and terminal.state is not RecordState.SLOT_OCCUPIED
        if exc is not None:
            if not isinstance(exc, Exception):
                cancellation = cancellation if cancellation is not None else exc
            elif not has_error:
                terminal = _failure_result(
                    exc,
                    publisher_entered=self._create_attempted,
                    publication_possible=self._creation_publication,
                )
                has_error = True
                if self._first_failure is None:
                    self._first_failure = terminal
        try:
            try:
                stack.__exit__(exc_type, exc, traceback)
            except BaseException as cleanup:
                if cancellation is not None:
                    raise cancellation from None
                if not isinstance(cleanup, Exception):
                    raise
                if not has_error:
                    terminal = _failure_result(
                        cleanup,
                        publisher_entered=self._create_attempted,
                        publication_possible=self._creation_publication,
                    )
                    if self._first_failure is None:
                        self._first_failure = terminal
            if cancellation is not None:
                raise cancellation from None
            if terminal is not None:
                raise _ScopeFailure(terminal) from None
            return False
        finally:
            # A closed scope retains classifications, never cancellation objects.
            self._cancellation = None


def _record_scope(
    binding: object, operation: object, *, revision_ref: object = None
) -> _RecordScopeContext:
    """Issue one private owner; revision is only an in-memory synthetic label."""

    owner = object.__new__(_RecordScopeContext)
    owner._factory_identity = owner
    owner._binding_input = binding
    owner._operation_input = operation
    owner._revision_input = revision_ref
    owner._binding = None
    owner._operation = None
    owner._revision = None
    owner._pid = os.getpid()
    owner._thread = threading.current_thread()
    owner._phase = _ScopePhase.NEW
    owner._scope = None
    owner._stack = None
    owner._held = None
    owner._busy = False
    owner._entering = False
    owner._create_attempted = False
    owner._creation_publication = False
    owner._first_failure = None
    owner._cancellation = None
    owner._link = None
    return owner


def _require_scope(
    scope: object, binding: object, operation: object, revision_ref: object, *, create: bool = False
) -> _RecordScopeContext:
    if type(scope) is not _HeldRecordScope:
        raise _ScopeUseError()
    try:
        owner = scope._owner
        if type(owner) is not _RecordScopeContext or owner._scope is not scope:
            raise _ScopeUseError()
        owner._check_owner()
        if owner._phase is not _ScopePhase.ACTIVE or owner._busy or owner._entering:
            raise _ScopeUseError()
        if (
            not _valid_binding(binding)
            or not _valid_operation(operation)
            or (revision_ref is not None and not _valid_ref(revision_ref))
            or binding != owner._binding
            or operation != owner._operation
            or revision_ref != owner._revision
        ):
            raise _ScopeUseError()
        link = owner._link
        if link is not None and (
            not create
            or type(link) is not _SharedStartSessionContext
            or link._record is not owner
            or link._phase is not _LinkedPhase.RECORD_HELD
            or not link._creating
        ):
            raise _ScopeUseError()
        return owner
    except AttributeError:
        raise _ScopeUseError() from None


def _held_record_io(
    scope: object, binding: object, operation: object, *, revision_ref: object, create: bool
) -> _HeldResult:
    owner = _require_scope(scope, binding, operation, revision_ref, create=create)
    if create and owner._create_attempted:
        raise _ScopeUseError()
    # Use the validated immutable snapshots, not caller-owned mutable state.
    current_binding, current_operation, held = owner._binding, owner._operation, owner._held
    if current_binding is None or current_operation is None or held is None:
        raise _ScopeUseError()
    publisher_entered = False
    publication_possible: bool | None = False
    try:
        owner._busy = True
        held.revalidate()
        record_path = current_binding.directory / RECORD_LEAF
        if create:
            try:
                record_path.lstat()
            except FileNotFoundError:
                pass
            else:
                held.revalidate()
                owner._remember(RecordResult(RecordState.SLOT_OCCUPIED))
                return _HeldResult(refusal=RecordState.SLOT_OCCUPIED)
            validated = validate_sensitive_output_path(record_path, overwrite=False)
            if validated != record_path:
                raise _RecordFormatError()
            held.revalidate()
            content = _encode_start_record(current_binding, current_operation)
            owner._create_attempted = True
            publisher_entered = True
            owner._creation_publication = publication_possible = None
            try:
                private_create.create_posix_private_bytes(record_path, content)
            except private_create.PosixPrivateCreateError as error:
                evidence = error.publication_possible
                publication_possible = evidence if type(evidence) is bool else None
                owner._creation_publication = publication_possible
                raise
            owner._creation_publication = publication_possible = True
        observed = read_private_sensitive_bytes(record_path, max_size=MAX_RECORD_BYTES)
        if not _matches_start_record(observed, current_binding, current_operation):
            raise _RecordFormatError()
        held.revalidate()
        checkpoint = (
            _HeldCheckpoint.HELD_START_CHECKPOINT if create else _HeldCheckpoint.HELD_START_OBSERVED
        )
        result = _HeldResult(checkpoint=checkpoint, publication_possible=publication_possible)
        if create and owner._link is not None:
            owner._link._start_latch = result
        return result
    except Exception as error:
        failure = _failure_result(
            error, publisher_entered=publisher_entered, publication_possible=publication_possible
        )
        owner._remember(failure)
        return _HeldResult(refusal=failure.state, publication_possible=failure.publication_possible)
    except BaseException as error:
        owner._phase = _ScopePhase.FAILED
        if owner._cancellation is None:
            owner._cancellation = error
        raise
    finally:
        owner._busy = False


def _create_start_record_held(
    scope: object, binding: object, operation: object, *, revision_ref: object = None
) -> _HeldResult:
    """Observe a bounded start checkpoint without releasing or reacquiring."""

    return _held_record_io(scope, binding, operation, revision_ref=revision_ref, create=True)


def _read_start_record_held(
    scope: object, binding: object, operation: object, *, revision_ref: object = None
) -> _HeldResult:
    """Observe pending bytes; this read's publication evidence remains False."""

    return _held_record_io(scope, binding, operation, revision_ref=revision_ref, create=False)


def _storage_call(binding: object, operation: object, *, create: bool) -> RecordResult:
    if not _linux_storage_available():
        return RecordResult(RecordState.UNSUPPORTED_PLATFORM)
    owner: _RecordScopeContext | None = None
    try:
        owner = _record_scope(binding, operation)
        with owner as scope:
            outcome = (
                _create_start_record_held(scope, binding, operation)
                if create
                else _read_start_record_held(scope, binding, operation)
            )
    except _ScopeFailure as error:
        return error.result
    except Exception as error:
        if owner is not None:
            if owner._cancellation is not None:
                raise owner._cancellation from None
            if (
                owner._first_failure is not None
                and owner._first_failure.state is not RecordState.SLOT_OCCUPIED
            ):
                return owner._first_failure
            return _failure_result(
                error,
                publisher_entered=create and owner._create_attempted,
                publication_possible=owner._creation_publication if create else False,
            )
        return RecordResult(RecordState.UNVERIFIABLE)
    # This wrapper alone maps its own held outcome after successful owner exit.
    if outcome.checkpoint is _HeldCheckpoint.HELD_START_CHECKPOINT and create:
        return RecordResult(RecordState.START_CONFIRMED, outcome.publication_possible)
    if outcome.checkpoint is _HeldCheckpoint.HELD_START_OBSERVED and not create:
        return RecordResult(RecordState.START_OBSERVED)
    return RecordResult(RecordState.UNVERIFIABLE)


def create_start_record(binding: object, operation: object) -> RecordResult:
    """Attempt one create-only start publication; an occupied slot is never success."""

    return _storage_call(binding, operation, create=True)


def read_start_record(binding: object, operation: object) -> RecordResult:
    """Observe one expected incomplete record; absence is never permission."""

    return _storage_call(binding, operation, create=False)


class _LinkedPhase(StrEnum):
    NEW = "new"
    ENTERING = "entering"
    RECORD_HELD = "record_held"
    START_READY = "start_ready"
    SESSION_RUNNING = "session_running"
    CONSUMED = "consumed"
    FAILED = "failed"
    EXITING = "exiting"
    CLOSED = "closed"


class _SessionFailureClass(StrEnum):
    SESSION_OTHER = "session_other"
    PERSISTENCE = "persistence"
    PREWRITE = "prewrite"
    LOCK = "lock"
    REFRESH = "refresh"


class _LinkedCheckpointFailure(ValueError):
    def __init__(self) -> None:
        super().__init__("START-linked final checkpoint failed")


class _LinkedDiagnosticIncompleteFailure(ValueError):
    def __init__(self) -> None:
        super().__init__("START-linked diagnostics are incomplete")


_LinkedTriple = tuple[type[BaseException] | None, BaseException | None, TracebackType | None]
_FailureKind = Literal["ordinary", "cancellation"]
_FailureDomain = Literal[
    "record", "session", "phase_exit", "final_checkpoint", "exit", "diagnostic"
]
_CancelPhase = Literal[
    "record",
    "session",
    "phase_exit",
    "final_checkpoint",
    "writer",
    "annotation",
    "exit",
    "snapshot",
]
_DiagnosticStep = Literal[
    "initial",
    "classification",
    "refinement",
    "pre_writer",
    "writer_raised",
    "writer_returned",
    "snapshot",
    "phase_exit",
    "candidate",
]
_WriterPhase = Literal["not_called", "call_started", "raised", "returned"]
_Outcome = Literal["return_path_selected", "failure", "cancellation"]


@dataclass(frozen=True, repr=False, slots=True)
class _LinkedExpected:
    binding: SyntheticBinding
    operation: RecordOperation
    checked_token_path: Path
    checked_state_path: Path


@dataclass(slots=True)
class _LinkedCoreFacts:
    record_observation: RecordState | _HeldCheckpoint | None = None
    record_publication: bool | None = False
    logical_save_called: bool = False
    writer_phase: _WriterPhase = "not_called"
    writer_failure_kind: _FailureKind | None = None
    credential_publication: bool | None = False
    candidate_constructed: bool = False
    delivery: Literal["withheld", "return_path_selected"] = "withheld"
    first_ordinary_domain: _FailureDomain | None = None
    session_failure: _SessionFailureClass | None = None
    selected_outcome: _Outcome = "failure"
    first_cancel_phase: _CancelPhase | None = None
    phase_exit_failure: _FailureKind | None = None
    cleanup_failure: _FailureKind | None = None
    diagnostic_status: Literal["complete", "incomplete"] = "complete"
    first_diagnostic_step: _DiagnosticStep | None = None
    first_diagnostic_kind: _FailureKind | None = None


@dataclass(frozen=True, slots=True)
class _LinkedAnnotations:
    session_failure: _SessionFailureClass | None = None
    publication: tuple[_WriterPhase, bool | None] | None = None


@dataclass(frozen=True, slots=True)
class _LinkedDiagnosticsSnapshot:
    record_observation: RecordState | _HeldCheckpoint | None
    record_publication: bool | None
    logical_save_called: bool
    writer_phase: _WriterPhase
    writer_failure_kind: _FailureKind | None
    credential_publication: bool | None
    candidate_constructed: bool
    delivery: Literal["withheld", "return_path_selected"]
    first_ordinary_domain: _FailureDomain | None
    session_failure: _SessionFailureClass | None
    selected_outcome: _Outcome
    first_cancel_phase: _CancelPhase | None
    phase_exit_failure: _FailureKind | None
    cleanup_failure: _FailureKind | None
    diagnostic_status: Literal["complete", "incomplete"]
    first_diagnostic_step: _DiagnosticStep | None
    first_diagnostic_kind: _FailureKind | None
    annotations: _LinkedAnnotations


_LINKED_FACT_FIELDS = tuple(item.name for item in fields(_LinkedCoreFacts))
_EMPTY_LINKED_ANNOTATIONS = _LinkedAnnotations()


@dataclass(repr=False, eq=False, slots=True)
class _LinkedAttemptState:
    parent: _SharedStartSessionContext
    request: object
    facts: _LinkedCoreFacts = field(default_factory=_LinkedCoreFacts)
    notes: _LinkedAnnotations = field(default_factory=_LinkedAnnotations)
    primary: Exception | None = None
    first_cancel: BaseException | None = None
    session_body_triple: _LinkedTriple | None = None
    phase_exit_triple: _LinkedTriple | None = None
    record_exit_triple: _LinkedTriple | None = None
    writer_error: BaseException | None = None
    writer_diagnostic: Exception | None = None
    fallback: _LinkedDiagnosticsSnapshot = field(
        default_factory=lambda: object.__new__(_LinkedDiagnosticsSnapshot)
    )
    incomplete_failure: _LinkedDiagnosticIncompleteFailure | None = field(
        default_factory=_LinkedDiagnosticIncompleteFailure
    )


@dataclass(init=False, repr=False, eq=False, slots=True)
class _LinkedSessionChild(_NoScopeCopy):
    _factory_identity: _LinkedSessionChild
    _parent: _SharedStartSessionContext
    _active: bool


@dataclass(init=False, repr=False, eq=False, slots=True)
class _SharedStartSessionContext(
    _NoScopeCopy, AbstractContextManager["_SharedStartSessionContext"]
):
    _factory_identity: _SharedStartSessionContext
    _request: object
    _expected: _LinkedExpected
    _record: _RecordScopeContext
    _attempt: _LinkedAttemptState
    _phase: _LinkedPhase
    _creating: bool
    _issuing: bool
    _start_latch: _HeldResult | None
    _current_child: _LinkedSessionChild | None
    _candidate_noted: bool
    _final_checking: bool
    _final_checked: bool
    _diagnostics: _LinkedDiagnosticsSnapshot | None

    def __enter__(self) -> _SharedStartSessionContext:
        _check_linked_actor(self)
        _verify_linked_parent_binding(self, self._request, expected=self._expected)
        try:
            self._phase = _LinkedPhase.ENTERING
            self._record.__enter__()
            self._phase = _LinkedPhase.RECORD_HELD
            _require_linked_record(
                self, self._request, expected_parent=self, expected=self._expected
            )
            return self
        except BaseException as error:
            # The legacy entry already unwinds an unsuccessful acquisition.
            self._phase = _LinkedPhase.FAILED
            _finalize_linked_scope(self, type(error), error, error.__traceback__)
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        return _finalize_linked_scope(self, exc_type, exc, traceback)


def _check_linked_actor(parent: object) -> _SharedStartSessionContext:
    if type(parent) is not _SharedStartSessionContext:
        raise _ScopeUseError()
    try:
        record = parent._record
        attempt = parent._attempt
        valid = (
            parent._factory_identity is parent
            and type(record) is _RecordScopeContext
            and record._link is parent
            and type(attempt) is _LinkedAttemptState
            and attempt.parent is parent
            and attempt.request is parent._request
            and type(parent._phase) is _LinkedPhase
        )
        if not valid:
            raise _ScopeUseError()
        record._check_owner()
    except AttributeError:
        raise _ScopeUseError() from None
    return parent


def _valid_linked_layout(expected: _LinkedExpected) -> bool:
    binding, operation = expected.binding, expected.operation
    token, state = expected.checked_token_path, expected.checked_state_path
    return (
        _valid_binding(binding)
        and _valid_operation(operation)
        and operation.kind is OperationKind.REFRESH
        and _valid_ref(operation.predecessor_id)
        and type(token) is type(Path())
        and type(state) is type(Path())
        and token.parent == state.parent == binding.directory
        and token.name == binding.token_slot
        and state.name == binding.state_slot
    )


def _shared_start_session_scope(
    binding: SyntheticBinding,
    operation: RecordOperation,
    request_key: object,
    *,
    token_path: Path,
    state_path: Path,
) -> _SharedStartSessionContext:
    if not _valid_binding(binding) or not _valid_operation(operation):
        raise _ScopeUseError()
    binding_snapshot = SyntheticBinding(
        binding.directory,
        binding.storage_ref,
        binding.pair_ref,
        binding.token_slot,
        binding.state_slot,
    )
    operation_snapshot = RecordOperation(
        operation.operation_id, operation.predecessor_id, operation.kind
    )
    expected = _LinkedExpected(binding_snapshot, operation_snapshot, token_path, state_path)
    if not _valid_linked_layout(expected):
        raise _ScopeUseError()
    parent = object.__new__(_SharedStartSessionContext)
    parent._factory_identity = parent
    parent._request = request_key
    parent._expected = expected
    parent._record = _record_scope(binding_snapshot, operation_snapshot)
    parent._record._link = parent
    parent._attempt = _LinkedAttemptState(parent, request_key)
    parent._phase = _LinkedPhase.NEW
    parent._creating = False
    parent._issuing = False
    parent._start_latch = None
    parent._current_child = None
    parent._candidate_noted = False
    parent._final_checking = False
    parent._final_checked = False
    parent._diagnostics = None
    return parent


def _check_linked_binding(
    parent: object, request_key: object, *, expected_parent: object, expected: _LinkedExpected
) -> _SharedStartSessionContext:
    if parent is not expected_parent or type(expected) is not _LinkedExpected:
        raise _ScopeUseError()
    bound = _check_linked_actor(parent)
    try:
        record = bound._record
        valid = (
            bound._request is request_key
            and _valid_linked_layout(expected)
            and bound._expected == expected
            and record._binding_input == expected.binding
            and record._operation_input == expected.operation
            and record._revision_input is None
            and (
                bound._phase in {_LinkedPhase.NEW, _LinkedPhase.CLOSED}
                or (
                    record._binding == expected.binding
                    and record._operation == expected.operation
                    and record._revision is None
                )
            )
        )
    except AttributeError:
        raise _ScopeUseError() from None
    if not valid:
        raise _ScopeUseError()
    return bound


def _verify_linked_parent_binding(
    parent: object, request_key: object, *, expected: _LinkedExpected
) -> None:
    bound = _check_linked_binding(parent, request_key, expected_parent=parent, expected=expected)
    record = bound._record
    if (
        bound._phase is not _LinkedPhase.NEW
        or record._phase is not _ScopePhase.NEW
        or record._scope is not None
        or record._held is not None
        or record._stack is not None
        or record._busy
        or record._entering
        or bound._current_child is not None
        or bound._start_latch is not None
    ):
        raise _ScopeUseError()


def _linked_attempt_state(
    parent: object, request_key: object, *, expected_parent: object, expected: _LinkedExpected
) -> _LinkedAttemptState:
    bound = _check_linked_binding(
        parent, request_key, expected_parent=expected_parent, expected=expected
    )
    _verify_linked_parent_binding(bound, request_key, expected=expected)
    return bound._attempt


def _require_linked_record(
    parent: _SharedStartSessionContext,
    request_key: object,
    *,
    expected_parent: object,
    expected: _LinkedExpected,
) -> _RecordScopeContext:
    _check_linked_binding(parent, request_key, expected_parent=expected_parent, expected=expected)
    record = parent._record
    if (
        record._phase is not _ScopePhase.ACTIVE
        or type(record._scope) is not _HeldRecordScope
        or record._scope._owner is not record
        or record._held is None
        or record._stack is None
        or record._busy
        or record._entering
        or record._first_failure is not None
        or record._cancellation is not None
    ):
        raise _ScopeUseError()
    return record


def _create_linked_start(
    parent: _SharedStartSessionContext,
    request_key: object,
    *,
    expected_parent: object,
    expected: _LinkedExpected,
) -> None:
    record = _require_linked_record(
        parent, request_key, expected_parent=expected_parent, expected=expected
    )
    if parent._phase is not _LinkedPhase.RECORD_HELD or parent._creating:
        raise _ScopeUseError()
    start_ready = False
    try:
        parent._creating = True
        result = _create_start_record_held(record._scope, expected.binding, expected.operation)
        if record._first_failure is not None:
            raise _ScopeFailure(record._first_failure)
        if (
            type(result) is not _HeldResult
            or result is not parent._start_latch
            or result.checkpoint is not _HeldCheckpoint.HELD_START_CHECKPOINT
            or record._creation_publication is not True
            or not record._create_attempted
        ):
            raise _ScopeFailure(
                RecordResult(RecordState.UNVERIFIABLE, record._creation_publication)
            )
        _require_linked_record(
            parent, request_key, expected_parent=expected_parent, expected=expected
        )
        parent._phase = _LinkedPhase.START_READY
        start_ready = True
    except BaseException as error:
        state = parent._attempt
        if isinstance(error, Exception):
            if state.primary is None:
                state.primary = error
                state.facts.first_ordinary_domain = "record"
            if isinstance(error, _ScopeFailure):
                state.facts.record_observation = error.result.state
        elif state.first_cancel is None:
            state.first_cancel = error
            state.facts.first_cancel_phase = "record"
        raise
    finally:
        parent._creating = False
        if not start_ready:
            parent._phase = _LinkedPhase.FAILED


def _require_linked_start_ready(
    parent: _SharedStartSessionContext,
    request_key: object,
    *,
    expected_parent: object,
    expected: _LinkedExpected,
) -> None:
    record = _require_linked_record(
        parent, request_key, expected_parent=expected_parent, expected=expected
    )
    state = parent._attempt
    if (
        parent._phase is not _LinkedPhase.START_READY
        or parent._current_child is not None
        or parent._start_latch is None
        or not record._create_attempted
        or record._creation_publication is not True
        or state.primary is not None
        or state.first_cancel is not None
    ):
        raise _ScopeUseError()


def _issue_linked_child(
    parent: _SharedStartSessionContext,
    request_key: object,
    *,
    expected_parent: object,
    expected: _LinkedExpected,
) -> _LinkedSessionChild:
    _require_linked_start_ready(
        parent, request_key, expected_parent=expected_parent, expected=expected
    )
    if not parent._issuing:
        raise _ScopeUseError()
    child = object.__new__(_LinkedSessionChild)
    child._factory_identity = child
    child._parent = parent
    child._active = True
    parent._current_child = child
    parent._phase = _LinkedPhase.SESSION_RUNNING
    return child


def _retain_phase_failure(state: _LinkedAttemptState, error: BaseException) -> None:
    if isinstance(error, Exception):
        if state.primary is None:
            state.primary = error
            state.facts.first_ordinary_domain = "phase_exit"
    elif state.first_cancel is None:
        state.first_cancel = error
        state.facts.first_cancel_phase = "phase_exit"


@dataclass(init=False, repr=False, eq=False, slots=True)
class _LinkedSessionPhaseContext(_NoScopeCopy, AbstractContextManager[_LinkedSessionChild]):
    _factory_identity: _LinkedSessionPhaseContext
    _parent: _SharedStartSessionContext
    _request: object
    _expected_parent: object
    _expected: _LinkedExpected
    _lifecycle: Literal["new", "entering", "active", "exiting", "closed"]
    _child: _LinkedSessionChild | None

    def _check_handle(self) -> None:
        if type(self) is not _LinkedSessionPhaseContext:
            raise _ScopeUseError()
        try:
            _ = (
                self._parent,
                self._request,
                self._expected_parent,
                self._expected,
                self._lifecycle,
                self._child,
            )
            if self._factory_identity is not self:
                raise _ScopeUseError()
        except AttributeError:
            raise _ScopeUseError() from None

    def __finish_phase(self, *, completed: bool) -> None:
        parent = _check_linked_actor(self._parent)
        # Issuance may have installed the child before entry could retain it.
        child = parent._current_child
        if child is not None:
            child._active = False
        parent._issuing = False
        parent._phase = _LinkedPhase.CONSUMED if completed else _LinkedPhase.FAILED
        self._lifecycle = "closed"

    def __enter__(self) -> _LinkedSessionChild:
        _LinkedSessionPhaseContext._check_handle(self)
        if self._lifecycle != "new" or self._child is not None:
            raise _ScopeUseError()
        parent = self._parent
        _require_linked_start_ready(
            parent, self._request, expected_parent=self._expected_parent, expected=self._expected
        )
        if parent._issuing:
            raise _ScopeUseError()

        state = parent._attempt
        try:
            self._lifecycle = "entering"
            parent._issuing = True
            child = _issue_linked_child(
                parent,
                self._request,
                expected_parent=self._expected_parent,
                expected=self._expected,
            )
            _require_linked_child(
                child, self._request, expected_parent=self._expected_parent, expected=self._expected
            )
            self._child = child
            self._lifecycle = "active"
            return child
        except BaseException as error:
            state.phase_exit_triple = (type(error), error, error.__traceback__)
            _retain_phase_failure(state, error)
            self.__finish_phase(completed=False)
            raise

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        _LinkedSessionPhaseContext._check_handle(self)
        child = self._child
        parent = self._parent
        if (
            self._lifecycle != "active"
            or child is None
            or parent is not self._expected_parent
            or not parent._issuing
        ):
            raise _ScopeUseError()
        _require_linked_child(
            child, self._request, expected_parent=self._expected_parent, expected=self._expected
        )

        state = parent._attempt
        try:
            if exc is not None:
                state.phase_exit_triple = (exc_type, exc, traceback)
                _retain_phase_failure(state, exc)
            self._lifecycle = "exiting"
            self.__finish_phase(completed=exc is None)
        except BaseException as error:
            if exc is None:
                state.phase_exit_triple = (type(error), error, error.__traceback__)
            _retain_phase_failure(state, error)
            state.facts.phase_exit_failure = (
                "ordinary" if isinstance(error, Exception) else "cancellation"
            )
            if parent._phase is _LinkedPhase.SESSION_RUNNING:
                self.__finish_phase(completed=False)
            else:
                self._lifecycle = "closed"
            raise
        return False


def _linked_session_phase(
    parent: _SharedStartSessionContext,
    request_key: object,
    *,
    expected_parent: object,
    expected: _LinkedExpected,
) -> _LinkedSessionPhaseContext:
    phase = object.__new__(_LinkedSessionPhaseContext)
    phase._factory_identity = phase
    phase._parent = parent
    phase._request = request_key
    phase._expected_parent = expected_parent
    phase._expected = expected
    phase._lifecycle = "new"
    phase._child = None
    return phase


def _require_linked_child(
    child: object, request_key: object, *, expected_parent: object, expected: _LinkedExpected
) -> None:
    if type(child) is not _LinkedSessionChild:
        raise _ScopeUseError()
    try:
        parent = child._parent
        _require_linked_record(
            parent, request_key, expected_parent=expected_parent, expected=expected
        )
        if (
            child._factory_identity is not child
            or parent._current_child is not child
            or not child._active
            or parent._phase is not _LinkedPhase.SESSION_RUNNING
        ):
            raise _ScopeUseError()
    except AttributeError:
        raise _ScopeUseError() from None


def _checkpoint_linked_child(
    child: _LinkedSessionChild,
    request_key: object,
    *,
    expected_parent: object,
    expected: _LinkedExpected,
) -> None:
    _require_linked_child(child, request_key, expected_parent=expected_parent, expected=expected)
    held = child._parent._record._held
    if held is None:
        raise _ScopeUseError()
    held.revalidate()


def _note_linked_candidate(
    parent: _SharedStartSessionContext,
    request_key: object,
    *,
    expected_parent: object,
    expected: _LinkedExpected,
) -> None:
    _check_linked_binding(parent, request_key, expected_parent=expected_parent, expected=expected)
    _require_linked_child(
        parent._current_child, request_key, expected_parent=expected_parent, expected=expected
    )
    if parent._candidate_noted or not parent._attempt.facts.candidate_constructed:
        raise _ScopeUseError()
    parent._candidate_noted = True


def _final_linked_checkpoint(
    parent: _SharedStartSessionContext,
    request_key: object,
    *,
    expected_parent: object,
    expected: _LinkedExpected,
) -> None:
    record = _require_linked_record(
        parent, request_key, expected_parent=expected_parent, expected=expected
    )
    child, held, state = parent._current_child, record._held, parent._attempt
    if (
        parent._phase is not _LinkedPhase.CONSUMED
        or type(child) is not _LinkedSessionChild
        or child._factory_identity is not child
        or child._parent is not parent
        or child._active
        or held is None
        or parent._final_checking
        or parent._final_checked
        or not parent._candidate_noted
        or not state.facts.candidate_constructed
        or state.primary is not None
        or state.first_cancel is not None
    ):
        raise _ScopeUseError()
    try:
        parent._final_checking = True
        try:
            held.revalidate()
        except Exception:
            raise _LinkedCheckpointFailure() from None
        parent._final_checked = True
    except BaseException as error:
        if isinstance(error, Exception):
            state.primary = error
            state.facts.first_ordinary_domain = "final_checkpoint"
        elif state.first_cancel is None:
            state.first_cancel = error
            state.facts.first_cancel_phase = "final_checkpoint"
        parent._phase = _LinkedPhase.FAILED
        raise
    finally:
        parent._final_checking = False


def _copy_linked_failure_annotations(
    parent: _SharedStartSessionContext,
    request_key: object,
    *,
    expected_parent: object,
    expected: _LinkedExpected,
    classification: _SessionFailureClass | None = None,
) -> None:
    _check_linked_binding(parent, request_key, expected_parent=expected_parent, expected=expected)
    if classification is not None and type(classification) is not _SessionFailureClass:
        raise _ScopeUseError()
    _require_linked_child(
        parent._current_child, request_key, expected_parent=expected_parent, expected=expected
    )
    state = parent._attempt
    state.notes = _LinkedAnnotations(classification, state.notes.publication)


def _copy_linked_publication_annotations(
    parent: _SharedStartSessionContext,
    request_key: object,
    *,
    expected_parent: object,
    expected: _LinkedExpected,
) -> None:
    _check_linked_binding(parent, request_key, expected_parent=expected_parent, expected=expected)
    _require_linked_child(
        parent._current_child, request_key, expected_parent=expected_parent, expected=expected
    )
    state = parent._attempt
    state.notes = _LinkedAnnotations(
        state.notes.session_failure, (state.facts.writer_phase, state.facts.credential_publication)
    )


def _mark_linked_diagnostic_failure(
    facts: _LinkedCoreFacts, step: _DiagnosticStep, kind: _FailureKind
) -> None:
    facts.diagnostic_status = "incomplete"
    if facts.first_diagnostic_step is None:
        facts.first_diagnostic_step = step
        facts.first_diagnostic_kind = kind


def _fill_linked_snapshot(
    snapshot: _LinkedDiagnosticsSnapshot, facts: _LinkedCoreFacts, notes: _LinkedAnnotations
) -> None:
    for name in _LINKED_FACT_FIELDS:
        object.__setattr__(snapshot, name, object.__getattribute__(facts, name))
    object.__setattr__(snapshot, "annotations", notes)


def _build_linked_diagnostics(
    facts: _LinkedCoreFacts, notes: _LinkedAnnotations
) -> _LinkedDiagnosticsSnapshot:
    snapshot = object.__new__(_LinkedDiagnosticsSnapshot)
    completed = _LinkedAnnotations(
        notes.session_failure if notes.session_failure is facts.session_failure else None,
        notes.publication
        if notes.publication == (facts.writer_phase, facts.credential_publication)
        else None,
    )
    _fill_linked_snapshot(snapshot, facts, completed)
    return snapshot


def _select_linked_outcome(state: _LinkedAttemptState) -> BaseException | None:
    facts = state.facts
    facts.delivery = "withheld"
    if state.first_cancel is not None:
        facts.selected_outcome = "cancellation"
        return state.first_cancel
    if state.primary is not None:
        facts.selected_outcome = "failure"
        return state.primary
    facts.selected_outcome = "return_path_selected"
    facts.delivery = "return_path_selected"
    return None


def _finalize_linked_scope(
    parent: _SharedStartSessionContext,
    exc_type: type[BaseException] | None,
    exc: BaseException | None,
    traceback: TracebackType | None,
) -> Literal[False]:
    _check_linked_actor(parent)
    record, state = parent._record, parent._attempt
    if (
        parent._phase
        not in {
            _LinkedPhase.RECORD_HELD,
            _LinkedPhase.START_READY,
            _LinkedPhase.CONSUMED,
            _LinkedPhase.FAILED,
        }
        or parent._creating
        or parent._issuing
        or parent._final_checking
        or record._busy
        or record._entering
    ):
        raise _ScopeUseError()
    state.record_exit_triple = (exc_type, exc, traceback)
    facts = state.facts
    if isinstance(exc, Exception):
        if state.primary is None:
            state.primary = exc
            facts.first_ordinary_domain = (
                "final_checkpoint" if parent._phase is _LinkedPhase.CONSUMED else "record"
            )
    elif exc is not None and state.first_cancel is None:
        state.first_cancel = exc
        facts.first_cancel_phase = (
            "final_checkpoint" if parent._phase is _LinkedPhase.CONSUMED else "record"
        )

    terminal = record._first_failure
    if terminal is not None:
        facts.record_observation = terminal.state
    elif facts.first_ordinary_domain == "record" and isinstance(exc, _ScopeFailure):
        facts.record_observation = exc.result.state
    elif facts.record_observation is None and parent._start_latch is not None:
        facts.record_observation = _HeldCheckpoint.HELD_START_CHECKPOINT
    facts.record_publication = record._creation_publication
    if state.first_cancel is None and record._cancellation is not None:
        state.first_cancel = record._cancellation
        facts.first_cancel_phase = "record"
    if state.primary is None and state.first_cancel is None and not parent._final_checked:
        state.primary = _ScopeUseError()
        facts.first_ordinary_domain = "record"

    try:
        parent._phase = _LinkedPhase.EXITING
        child = parent._current_child
        if child is not None:
            child._active = False
        stack, record._stack = record._stack, None
        record._held = None
        record._scope = None
        record._cancellation = None
        record._phase = _ScopePhase.CLOSED
        if stack is not None:
            stack.__exit__(exc_type, exc, traceback)
    except BaseException as cleanup:
        if isinstance(cleanup, Exception):
            facts.cleanup_failure = "ordinary"
            if state.primary is None:
                state.primary = cleanup
                facts.first_ordinary_domain = "exit"
        else:
            facts.cleanup_failure = "cancellation"
            if state.first_cancel is None:
                state.first_cancel = cleanup
                facts.first_cancel_phase = "exit"
    finally:
        parent._phase = _LinkedPhase.CLOSED

    if (
        facts.diagnostic_status == "incomplete"
        and state.first_cancel is None
        and state.primary is None
    ):
        state.primary = state.incomplete_failure
        facts.first_ordinary_domain = "diagnostic"
    selected = _select_linked_outcome(state)
    try:
        snapshot = _build_linked_diagnostics(facts, state.notes)
        if type(snapshot) is not _LinkedDiagnosticsSnapshot:
            incomplete = state.incomplete_failure
            if incomplete is None:
                raise _ScopeUseError()
            raise incomplete
        parent._diagnostics = snapshot
    except BaseException as diagnostic:
        if isinstance(diagnostic, Exception):
            if state.primary is None:
                state.primary = diagnostic
                facts.first_ordinary_domain = "diagnostic"
            _mark_linked_diagnostic_failure(facts, "snapshot", "ordinary")
        else:
            if state.first_cancel is None:
                state.first_cancel = diagnostic
                facts.first_cancel_phase = "snapshot"
            _mark_linked_diagnostic_failure(facts, "snapshot", "cancellation")
        selected = _select_linked_outcome(state)
        _fill_linked_snapshot(state.fallback, facts, _EMPTY_LINKED_ANNOTATIONS)
        parent._diagnostics = state.fallback
    finally:
        state.primary = None
        state.first_cancel = None
        state.session_body_triple = None
        state.phase_exit_triple = None
        state.record_exit_triple = None
        state.writer_error = None
        state.writer_diagnostic = None
        state.incomplete_failure = None
    if selected is not None and selected is not exc:
        raise selected
    return False


def _read_linked_diagnostics(
    parent: object, request_key: object, *, expected_parent: object, expected: _LinkedExpected
) -> _LinkedDiagnosticsSnapshot:
    bound = _check_linked_binding(
        parent, request_key, expected_parent=expected_parent, expected=expected
    )
    if (
        bound._phase is not _LinkedPhase.CLOSED
        or type(bound._diagnostics) is not _LinkedDiagnosticsSnapshot
    ):
        raise _ScopeUseError()
    return bound._diagnostics
