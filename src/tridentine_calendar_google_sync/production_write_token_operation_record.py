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
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Literal, TypeGuard

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


def _storage_call(binding: object, operation: object, *, create: bool) -> RecordResult:
    # No inspection of even the binding occurs on unsupported platforms.
    if not _linux_storage_available():
        return RecordResult(RecordState.UNSUPPORTED_PLATFORM)
    if not _valid_binding(binding) or not _valid_operation(operation):
        return RecordResult(RecordState.UNVERIFIABLE)
    try:
        content = _encode_start_record(binding, operation)
    except _RecordFormatError:
        return RecordResult(RecordState.UNVERIFIABLE)

    state = RecordState.UNVERIFIABLE
    publisher_entered = False
    publication_possible: bool | None = False
    failure: RecordResult | None = None
    cancellation: BaseException | None = None
    try:
        with private_lock.acquire_posix_private_directory_lock(binding.directory) as held:
            try:
                held.revalidate()
                record_path = binding.directory / RECORD_LEAF
                occupied = False
                if create:
                    try:
                        record_path.lstat()
                    except FileNotFoundError:
                        pass
                    else:
                        occupied = True
                if occupied:
                    state = RecordState.SLOT_OCCUPIED
                else:
                    if create:
                        validated = validate_sensitive_output_path(record_path, overwrite=False)
                        if validated != record_path:
                            raise _RecordFormatError()
                        held.revalidate()
                        publisher_entered = True
                        publication_possible = None
                        try:
                            private_create.create_posix_private_bytes(record_path, content)
                        except private_create.PosixPrivateCreateError as error:
                            evidence = error.publication_possible
                            publication_possible = evidence if type(evidence) is bool else None
                            raise
                        publication_possible = True
                    observed = read_private_sensitive_bytes(record_path, max_size=MAX_RECORD_BYTES)
                    if not _matches_start_record(observed, binding, operation):
                        raise _RecordFormatError()
                    state = RecordState.START_CONFIRMED if create else RecordState.START_OBSERVED
                held.revalidate()
            except Exception as error:
                # Preserve the first failure if context cleanup also raises.
                failure = _failure_result(
                    error,
                    publisher_entered=publisher_entered,
                    publication_possible=publication_possible,
                )
            except BaseException as error:
                cancellation = error
                raise
    except Exception as error:
        if cancellation is not None:
            raise cancellation from None
        if failure is None:
            failure = _failure_result(
                error,
                publisher_entered=publisher_entered,
                publication_possible=publication_possible,
            )
    # Success is constructed only after the lock context has exited.
    if failure is not None:
        return failure
    return RecordResult(state, publication_possible)


def create_start_record(binding: object, operation: object) -> RecordResult:
    """Attempt one create-only start publication; an occupied slot is never success."""

    return _storage_call(binding, operation, create=True)


def read_start_record(binding: object, operation: object) -> RecordResult:
    """Observe one expected incomplete record; absence is never permission."""

    return _storage_call(binding, operation, create=False)
