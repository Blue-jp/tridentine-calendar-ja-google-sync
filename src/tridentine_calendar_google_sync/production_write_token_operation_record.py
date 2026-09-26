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
from dataclasses import dataclass, field
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
    return owner


def _require_scope(
    scope: object, binding: object, operation: object, revision_ref: object
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
        return owner
    except AttributeError:
        raise _ScopeUseError() from None


def _held_record_io(
    scope: object, binding: object, operation: object, *, revision_ref: object, create: bool
) -> _HeldResult:
    owner = _require_scope(scope, binding, operation, revision_ref)
    if create and owner._create_attempted:
        raise _ScopeUseError()
    # Use the validated immutable snapshots, not caller-owned mutable state.
    current_binding, current_operation, held = owner._binding, owner._operation, owner._held
    if current_binding is None or current_operation is None or held is None:
        raise _ScopeUseError()
    owner._busy = True
    publisher_entered = False
    publication_possible: bool | None = False
    try:
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
        return _HeldResult(checkpoint=checkpoint, publication_possible=publication_possible)
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
