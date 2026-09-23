"""Synthetic single-directory preparation; never enrollment or use authority.

Only this call's confirmed pending permits its descriptor publication. Existing
entries refuse resumption. Same-user races, suppressed backend cleanup errors
and crash durability remain outside this bounded observation.
"""

from __future__ import annotations

import json
import os
import sys
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Literal, TypeGuard

from tridentine_calendar_google_sync import _posix_private_create as private_create
from tridentine_calendar_google_sync import _posix_private_lock as private_lock
from tridentine_calendar_google_sync.production_write_token_enrollment_descriptor import (
    EnrollmentDescriptorState,
    SyntheticEnrollmentExpectation,
    validate_enrollment_descriptor,
)
from tridentine_calendar_google_sync.sensitive_paths import (
    read_private_sensitive_bytes,
    validate_sensitive_output_path,
)

_EXPECTATION_FIELDS = (
    "enrollment_revision",
    "administrative_state",
    "storage_ref",
    "pair_ref",
    "artifact_directory",
    "token_slot",
    "state_slot",
    "active_intent_slot",
    "descriptor_pin",
    "descriptor_slot",
    "administrative_pending_slot",
)
_PENDING_KEYS = {
    "format_version",
    "record_kind",
    "target_revision",
    "target_pin",
    "outcome",
}


class PreparationState(StrEnum):
    INPUT_UNVERIFIABLE = "INPUT_UNVERIFIABLE"
    PREPARING_REQUIRED = "PREPARING_REQUIRED"
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
    LOCK_BUSY = "LOCK_BUSY"
    LOCK_UNAVAILABLE = "LOCK_UNAVAILABLE"
    PENDING_OCCUPIED = "PENDING_OCCUPIED"
    DESCRIPTOR_OCCUPIED = "DESCRIPTOR_OCCUPIED"
    BOTH_OCCUPIED = "BOTH_OCCUPIED"
    PREWRITE_UNVERIFIABLE = "PREWRITE_UNVERIFIABLE"
    PENDING_PERSISTENCE_UNCERTAIN = "PENDING_PERSISTENCE_UNCERTAIN"
    DESCRIPTOR_PERSISTENCE_UNCERTAIN = "DESCRIPTOR_PERSISTENCE_UNCERTAIN"
    PREPARATION_OBSERVED_UNAPPROVED = "PREPARATION_OBSERVED_UNAPPROVED"


@dataclass(frozen=True, slots=True)
class PreparationResult:
    """Fixed call-local evidence, not an execution permit or durable receipt."""

    state: PreparationState
    pending_attempted: bool = False
    pending_publication_possible: bool | None = False
    descriptor_attempted: bool = False
    descriptor_publication_possible: bool | None = False
    exit_failure_observed: bool = False
    reuse_authorized: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if (
            type(self.state) is not PreparationState
            or any(
                type(value) is not bool
                for value in (
                    self.pending_attempted,
                    self.descriptor_attempted,
                    self.exit_failure_observed,
                )
            )
            or any(
                value is not None and type(value) is not bool
                for value in (
                    self.pending_publication_possible,
                    self.descriptor_publication_possible,
                )
            )
            or self.reuse_authorized is not False
        ):
            raise ValueError("Invalid preparation result")
        if (
            (not self.pending_attempted and self.pending_publication_possible is not False)
            or (not self.descriptor_attempted and self.descriptor_publication_possible is not False)
            or (
                self.descriptor_attempted
                and (not self.pending_attempted or self.pending_publication_possible is not True)
            )
        ):
            raise ValueError("Invalid preparation result")
        state = self.state
        if state is PreparationState.PREPARATION_OBSERVED_UNAPPROVED:
            valid = (
                self.pending_attempted
                and self.descriptor_attempted
                and self.pending_publication_possible is True
                and self.descriptor_publication_possible is True
                and not self.exit_failure_observed
            )
        elif state is PreparationState.DESCRIPTOR_PERSISTENCE_UNCERTAIN:
            valid = self.descriptor_attempted
        elif state is PreparationState.PENDING_PERSISTENCE_UNCERTAIN:
            valid = self.pending_attempted and not self.descriptor_attempted
        elif state is PreparationState.DESCRIPTOR_OCCUPIED:
            valid = not self.descriptor_attempted and (
                not self.pending_attempted or self.pending_publication_possible is True
            )
        else:
            valid = not self.pending_attempted and not self.descriptor_attempted
        if (
            state
            in {
                PreparationState.INPUT_UNVERIFIABLE,
                PreparationState.PREPARING_REQUIRED,
                PreparationState.UNSUPPORTED_PLATFORM,
            }
            and self.exit_failure_observed
        ):
            valid = False
        if not valid:
            raise ValueError("Invalid preparation result")


class _PreparationFormatError(ValueError):
    def __init__(self) -> None:
        super().__init__("Invalid synthetic preparation input")


class _InputRefusal(ValueError):
    def __init__(self, state: PreparationState) -> None:
        self.state = state
        super().__init__("Synthetic preparation input refused")


@dataclass(frozen=True, slots=True)
class _Inputs:
    root: Path = field(repr=False)
    raw: bytes = field(repr=False)
    expectation: SyntheticEnrollmentExpectation = field(repr=False)
    pending: bytes = field(repr=False)


@dataclass(slots=True, repr=False)
class _Progress:
    state: PreparationState | None = None
    pending_attempted: bool = False
    pending_publication_possible: bool | None = False
    descriptor_attempted: bool = False
    descriptor_publication_possible: bool | None = False
    pending_confirmed: bool = False
    descriptor_confirmed: bool = False
    exit_failure_observed: bool = False

    def fail(self, error: Exception, *, lock_stage: bool = False) -> None:
        if self.state is not None:
            return
        if self.descriptor_attempted:
            self.state = PreparationState.DESCRIPTOR_PERSISTENCE_UNCERTAIN
        elif self.pending_attempted:
            self.state = PreparationState.PENDING_PERSISTENCE_UNCERTAIN
        elif type(error) is private_lock.PosixPrivateLockError:
            busy = type(error.code) is str and error.code == "posix_directory_lock_busy"
            self.state = PreparationState.LOCK_BUSY if busy else PreparationState.LOCK_UNAVAILABLE
        elif lock_stage:
            self.state = PreparationState.LOCK_UNAVAILABLE
        else:
            self.state = PreparationState.PREWRITE_UNVERIFIABLE

    def result(self) -> PreparationResult:
        state = self.state
        if state is None:
            if self.pending_confirmed and self.descriptor_confirmed:
                state = PreparationState.PREPARATION_OBSERVED_UNAPPROVED
            else:
                self.fail(_PreparationFormatError())
                state = self.state
        if state is None:
            raise _PreparationFormatError()
        return PreparationResult(
            state,
            self.pending_attempted,
            self.pending_publication_possible,
            self.descriptor_attempted,
            self.descriptor_publication_possible,
            self.exit_failure_observed,
        )


def _linux_storage_available() -> bool:
    return sys.platform == "linux" and os.name == "posix"


def _valid_root(value: object) -> TypeGuard[str]:
    if type(value) is not str or not 1 < len(value) <= 1024:
        return False
    if (
        not value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or any(char in value for char in "\\:")
        or any(unicodedata.category(char) in {"Cc", "Cs"} for char in value)
        or len(value.encode("utf-8")) > 1024
    ):
        return False
    return all(
        part not in {".", "..", ".git"} and not part.endswith((" ", "."))
        for part in value.split("/")[1:]
    )


def _valid_pending(data: object) -> TypeGuard[dict[str, object]]:
    if type(data) is not dict or data.keys() != _PENDING_KEYS:
        return False
    if type(data["format_version"]) is not int or data["format_version"] != 1:
        return False
    if any(type(value) is not str for key, value in data.items() if key != "format_version"):
        return False
    revision, pin = data["target_revision"], data["target_pin"]
    return (
        data["record_kind"] == "enrollment_preparation"
        and data["outcome"] == "pending"
        and 1 <= len(revision) <= 96
        and revision.isascii()
        and revision[0].isalnum()
        and all(char.isalnum() or char in "._-" for char in revision)
        and len(pin) == 64
        and all(char in "0123456789abcdef" for char in pin)
    )


def _canonical_pending(data: dict[str, object]) -> bytes:
    raw = (
        json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")
    if not 1 <= len(raw) <= 512:
        raise _PreparationFormatError()
    return raw


def _encode_pending(expectation: SyntheticEnrollmentExpectation) -> bytes:
    if type(expectation) is not SyntheticEnrollmentExpectation:
        raise _PreparationFormatError()
    data: dict[str, object] = {
        "format_version": 1,
        "record_kind": "enrollment_preparation",
        "target_revision": expectation.enrollment_revision,
        "target_pin": expectation.descriptor_pin,
        "outcome": "pending",
    }
    if not _valid_pending(data):
        raise _PreparationFormatError()
    return _canonical_pending(data)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    data: dict[str, object] = {}
    for key, value in pairs:
        if key in data:
            raise _PreparationFormatError()
        data[key] = value
    return data


def _reject_constant(_value: str) -> object:
    raise _PreparationFormatError()


def _matches_pending(raw: object, expected: bytes) -> bool:
    if (
        type(raw) is not bytes
        or type(expected) is not bytes
        or not 1 <= len(raw) <= 512
        or not 1 <= len(expected) <= 512
        or raw.startswith(b"\xef\xbb\xbf")
    ):
        return False
    try:
        data: object = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        return _valid_pending(data) and _canonical_pending(data) == raw and raw == expected
    except Exception:
        return False


def _snapshot(control_root: object, raw: object, expectation: object) -> _Inputs:
    if not _valid_root(control_root) or type(expectation) is not SyntheticEnrollmentExpectation:
        raise _PreparationFormatError()
    values: dict[str, str] = {name: getattr(expectation, name) for name in _EXPECTATION_FIELDS}
    if any(type(value) is not str for value in values.values()):
        raise _PreparationFormatError()
    retained = SyntheticEnrollmentExpectation(**values)
    comparison = validate_enrollment_descriptor(raw, retained)
    if comparison.state is not EnrollmentDescriptorState.DESCRIPTOR_MATCHED_UNAPPROVED:
        raise _PreparationFormatError()
    if retained.administrative_state != "PREPARING":
        raise _InputRefusal(PreparationState.PREPARING_REQUIRED)
    if type(raw) is not bytes:
        raise _PreparationFormatError()
    return _Inputs(Path(control_root), raw, retained, _encode_pending(retained))


def _occupied(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _preflight(path: Path) -> None:
    validated = validate_sensitive_output_path(path, overwrite=False)
    if type(validated) is not type(path) or validated != path:
        raise _PreparationFormatError()


def _publish(path: Path, content: bytes, progress: _Progress, *, descriptor: bool) -> None:
    if descriptor:
        if not progress.pending_confirmed or progress.descriptor_attempted:
            raise _PreparationFormatError()
        progress.descriptor_attempted = True
        progress.descriptor_publication_possible = None
    else:
        if progress.pending_attempted:
            raise _PreparationFormatError()
        progress.pending_attempted = True
        progress.pending_publication_possible = None
    try:
        private_create.create_posix_private_bytes(path, content)
    except Exception as error:
        if type(error) is private_create.PosixPrivateCreateError:
            evidence = error.publication_possible
            publication = evidence if type(evidence) is bool else None
            if descriptor:
                progress.descriptor_publication_possible = publication
            else:
                progress.pending_publication_possible = publication
        raise
    if descriptor:
        progress.descriptor_publication_possible = True
    else:
        progress.pending_publication_possible = True


def _read_pending(path: Path, expected: bytes) -> None:
    observed = read_private_sensitive_bytes(path, max_size=512)
    if not _matches_pending(observed, expected):
        raise _PreparationFormatError()


def _run_owned(
    inputs: _Inputs, owned: private_lock._PrivateDirectoryLock, progress: _Progress
) -> None:
    pending = inputs.root / inputs.expectation.administrative_pending_slot
    descriptor = inputs.root / inputs.expectation.descriptor_slot
    owned.revalidate()
    has_pending = _occupied(pending)
    if has_pending:
        progress.state = PreparationState.PENDING_OCCUPIED
    if _occupied(descriptor):
        progress.state = (
            PreparationState.BOTH_OCCUPIED if has_pending else PreparationState.DESCRIPTOR_OCCUPIED
        )
    owned.revalidate()
    if progress.state is not None:
        return
    _preflight(pending)
    owned.revalidate()
    _publish(pending, inputs.pending, progress, descriptor=False)
    _read_pending(pending, inputs.pending)
    owned.revalidate()
    progress.pending_confirmed = True
    if _occupied(descriptor):
        progress.state = PreparationState.DESCRIPTOR_OCCUPIED
        owned.revalidate()
        return
    owned.revalidate()
    _read_pending(pending, inputs.pending)
    owned.revalidate()
    _preflight(descriptor)
    owned.revalidate()
    _publish(descriptor, inputs.raw, progress, descriptor=True)
    observed = read_private_sensitive_bytes(descriptor, max_size=8192)
    if type(observed) is not bytes or observed != inputs.raw:
        raise _PreparationFormatError()
    comparison = validate_enrollment_descriptor(observed, inputs.expectation)
    if comparison.state is not EnrollmentDescriptorState.DESCRIPTOR_MATCHED_UNAPPROVED:
        raise _PreparationFormatError()
    owned.revalidate()
    progress.descriptor_confirmed = True


def prepare_synthetic_enrollment(
    control_root: object, raw: object, expectation: object
) -> PreparationResult:
    """Retain pending before one PREPARING descriptor; never resume existing entries."""
    if not _linux_storage_available():
        return PreparationResult(PreparationState.UNSUPPORTED_PLATFORM)
    try:
        inputs = _snapshot(control_root, raw, expectation)
    except _InputRefusal as refusal:
        return PreparationResult(refusal.state)
    except Exception:
        return PreparationResult(PreparationState.INPUT_UNVERIFIABLE)
    progress = _Progress()
    try:
        owned = private_lock.acquire_posix_private_directory_lock(inputs.root)
    except Exception as error:
        progress.fail(error, lock_stage=True)
        return progress.result()
    # Acquisition transfers an already-held resource before context entry.
    try:
        owned.__enter__()
    except BaseException as entry_error:
        if isinstance(entry_error, Exception):
            progress.fail(entry_error, lock_stage=True)
        try:
            # Public close detaches ownership first. Already-invalidated means
            # a no-op; do not inspect private handles or retry lower-level close.
            owned.close()
        except BaseException as cleanup:
            if isinstance(cleanup, Exception):
                progress.exit_failure_observed = True
            elif isinstance(entry_error, Exception):
                raise
        if not isinstance(entry_error, Exception):
            raise
        return progress.result()
    observed_error: BaseException | None = None
    try:
        _run_owned(inputs, owned, progress)
    except BaseException as body_error:
        observed_error = body_error
        if isinstance(body_error, Exception):
            progress.fail(body_error)
    try:
        owned.__exit__(
            type(observed_error) if observed_error is not None else None,
            observed_error,
            observed_error.__traceback__ if observed_error is not None else None,
        )
    except BaseException as exit_error:
        if isinstance(exit_error, Exception):
            progress.exit_failure_observed = True
            progress.fail(exit_error, lock_stage=True)
        elif observed_error is None or isinstance(observed_error, Exception):
            observed_error = exit_error
    # Successful entry has exactly one exit, never an additional close attempt.
    if observed_error is not None and not isinstance(observed_error, Exception):
        raise observed_error from None
    return progress.result()
