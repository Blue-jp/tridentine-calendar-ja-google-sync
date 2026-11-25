"""Synthetic single-directory preparation; never enrollment or use authority.

Only this call's confirmed pending permits its descriptor publication. Existing
entries refuse resumption. Same-user races, suppressed backend cleanup errors
and crash durability remain outside this bounded observation.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
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


class InspectionState(StrEnum):
    INPUT_UNVERIFIABLE = "INPUT_UNVERIFIABLE"
    PREPARING_REQUIRED = "PREPARING_REQUIRED"
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
    LOCK_BUSY = "LOCK_BUSY"
    LOCK_UNAVAILABLE = "LOCK_UNAVAILABLE"
    ABSENCE_UNVERIFIABLE = "ABSENCE_UNVERIFIABLE"
    ADMIN_PENDING = "ADMIN_PENDING"
    ORPHAN_DESCRIPTOR = "ORPHAN_DESCRIPTOR"
    PREPARATION_RETAINED_UNAPPROVED = "PREPARATION_RETAINED_UNAPPROVED"
    PREPARATION_CONFLICT = "PREPARATION_CONFLICT"
    PREPARATION_UNVERIFIABLE = "PREPARATION_UNVERIFIABLE"


class Presence(StrEnum):
    UNKNOWN = "UNKNOWN"
    ABSENT = "ABSENT"
    PRESENT = "PRESENT"


class ContentStatus(StrEnum):
    NOT_READ = "NOT_READ"
    READ_UNVERIFIABLE = "READ_UNVERIFIABLE"
    SCHEMA_UNVERIFIABLE = "SCHEMA_UNVERIFIABLE"
    SCHEMA_VALID = "SCHEMA_VALID"


class TargetRelation(StrEnum):
    NOT_COMPARED = "NOT_COMPARED"
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"


class InspectionFailure(StrEnum):
    NONE = "NONE"
    INPUT = "INPUT"
    ACQUIRE = "ACQUIRE"
    ENTRY = "ENTRY"
    PENDING_ENTRY = "PENDING_ENTRY"
    DESCRIPTOR_ENTRY = "DESCRIPTOR_ENTRY"
    PENDING_READ = "PENDING_READ"
    DESCRIPTOR_READ = "DESCRIPTOR_READ"
    PENDING_SCHEMA = "PENDING_SCHEMA"
    DESCRIPTOR_COMPARE = "DESCRIPTOR_COMPARE"
    TARGET_EXTRACTION = "TARGET_EXTRACTION"
    ENTRY_CHANGED = "ENTRY_CHANGED"
    ROOT_CHECK = "ROOT_CHECK"
    EXIT = "EXIT"


@dataclass(frozen=True, slots=True)
class LeafObservation:
    presence: Presence = Presence.UNKNOWN
    content: ContentStatus = ContentStatus.NOT_READ
    target: TargetRelation = TargetRelation.NOT_COMPARED
    changed: bool = False

    def __post_init__(self) -> None:
        if not _inspection_leaf_consistent(self):
            raise ValueError("Invalid leaf observation")


def _inspection_leaf_consistent(leaf: object) -> TypeGuard[LeafObservation]:
    if type(leaf) is not LeafObservation:
        return False
    try:
        if (
            type(leaf.presence) is not Presence
            or type(leaf.content) is not ContentStatus
            or type(leaf.target) is not TargetRelation
            or type(leaf.changed) is not bool
        ):
            return False
        if leaf.presence is not Presence.PRESENT:
            return (
                leaf.content is ContentStatus.NOT_READ
                and leaf.target is TargetRelation.NOT_COMPARED
                and not leaf.changed
            )
        return (
            leaf.target is TargetRelation.NOT_COMPARED or leaf.content is ContentStatus.SCHEMA_VALID
        )
    except AttributeError:
        return False


def _inspection_leaf_complete(leaf: LeafObservation) -> bool:
    return not leaf.changed and (
        leaf.presence is Presence.ABSENT
        or (
            leaf.presence is Presence.PRESENT
            and leaf.content is ContentStatus.SCHEMA_VALID
            and leaf.target is not TargetRelation.NOT_COMPARED
        )
    )


def _inspection_summary(
    pending: LeafObservation,
    descriptor: LeafObservation,
    relation: TargetRelation,
    non_preparing: bool,
    complete: bool,
) -> InspectionState:
    if (
        pending.target is TargetRelation.MISMATCH
        or descriptor.target is TargetRelation.MISMATCH
        or relation is TargetRelation.MISMATCH
        or non_preparing
    ):
        return InspectionState.PREPARATION_CONFLICT
    if not complete:
        return InspectionState.PREPARATION_UNVERIFIABLE
    if pending.presence is Presence.ABSENT:
        return (
            InspectionState.ABSENCE_UNVERIFIABLE
            if descriptor.presence is Presence.ABSENT
            else InspectionState.ORPHAN_DESCRIPTOR
        )
    if descriptor.presence is Presence.ABSENT:
        return InspectionState.ADMIN_PENDING
    return InspectionState.PREPARATION_RETAINED_UNAPPROVED


@dataclass(frozen=True, slots=True)
class PreparationInspection:
    """Fixed read observations, never writer evidence or authority to resume."""

    state: InspectionState
    pending: LeafObservation = field(default_factory=LeafObservation)
    descriptor: LeafObservation = field(default_factory=LeafObservation)
    target_relation: TargetRelation = TargetRelation.NOT_COMPARED
    non_preparing_observed: bool = False
    verification_complete: bool = False
    first_failure: InspectionFailure = InspectionFailure.NONE
    exit_failure_observed: bool = False
    reuse_authorized: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if (
            type(self.state) is not InspectionState
            or not _inspection_leaf_consistent(self.pending)
            or not _inspection_leaf_consistent(self.descriptor)
            or type(self.target_relation) is not TargetRelation
            or type(self.first_failure) is not InspectionFailure
            or any(
                type(value) is not bool
                for value in (
                    self.non_preparing_observed,
                    self.verification_complete,
                    self.exit_failure_observed,
                )
            )
            or self.reuse_authorized is not False
        ):
            raise ValueError("Invalid preparation inspection")
        both_valid = all(
            leaf.presence is Presence.PRESENT and leaf.content is ContentStatus.SCHEMA_VALID
            for leaf in (self.pending, self.descriptor)
        )
        if (
            (self.target_relation is not TargetRelation.NOT_COMPARED and not both_valid)
            or (
                self.pending.target is TargetRelation.MATCH
                and self.descriptor.target is TargetRelation.MATCH
                and self.target_relation is TargetRelation.MISMATCH
            )
            or (
                self.pending.target is TargetRelation.MISMATCH
                and self.descriptor.target is TargetRelation.MATCH
                and self.target_relation is TargetRelation.MATCH
            )
            or (
                self.non_preparing_observed
                and (
                    self.descriptor.presence is not Presence.PRESENT
                    or self.descriptor.content is not ContentStatus.SCHEMA_VALID
                    or self.descriptor.target is not TargetRelation.MISMATCH
                )
            )
            or (self.exit_failure_observed and self.first_failure is InspectionFailure.NONE)
            or (self.first_failure is InspectionFailure.EXIT and not self.exit_failure_observed)
        ):
            raise ValueError("Invalid preparation inspection")
        gates = {
            InspectionState.INPUT_UNVERIFIABLE,
            InspectionState.PREPARING_REQUIRED,
            InspectionState.UNSUPPORTED_PLATFORM,
            InspectionState.LOCK_BUSY,
            InspectionState.LOCK_UNAVAILABLE,
        }
        if self.state in gates:
            valid = (
                all(
                    leaf.presence is Presence.UNKNOWN
                    and leaf.content is ContentStatus.NOT_READ
                    and leaf.target is TargetRelation.NOT_COMPARED
                    and not leaf.changed
                    for leaf in (self.pending, self.descriptor)
                )
                and self.target_relation is TargetRelation.NOT_COMPARED
                and not self.non_preparing_observed
                and not self.verification_complete
            )
            if self.state is InspectionState.UNSUPPORTED_PLATFORM:
                valid = valid and self.first_failure is InspectionFailure.NONE
            elif self.state in {
                InspectionState.INPUT_UNVERIFIABLE,
                InspectionState.PREPARING_REQUIRED,
            }:
                valid = valid and self.first_failure is InspectionFailure.INPUT
            elif self.state is InspectionState.LOCK_BUSY:
                valid = valid and self.first_failure is InspectionFailure.ACQUIRE
            else:
                valid = valid and self.first_failure in {
                    InspectionFailure.ACQUIRE,
                    InspectionFailure.ENTRY,
                }
            if self.exit_failure_observed:
                valid = (
                    valid
                    and self.state is InspectionState.LOCK_UNAVAILABLE
                    and (self.first_failure is InspectionFailure.ENTRY)
                )
        else:
            valid = self.first_failure not in {
                InspectionFailure.INPUT,
                InspectionFailure.ACQUIRE,
                InspectionFailure.ENTRY,
            } and self.state is _inspection_summary(
                self.pending,
                self.descriptor,
                self.target_relation,
                self.non_preparing_observed,
                self.verification_complete,
            )
            if self.verification_complete:
                valid = valid and (
                    self.first_failure is InspectionFailure.NONE
                    and not self.exit_failure_observed
                    and _inspection_leaf_complete(self.pending)
                    and _inspection_leaf_complete(self.descriptor)
                    and (not both_valid or self.target_relation is not TargetRelation.NOT_COMPARED)
                )
            else:
                valid = valid and self.first_failure is not InspectionFailure.NONE
        if not valid:
            raise ValueError("Invalid preparation inspection")


@dataclass(slots=True)
class _InspectionLeaf:
    presence: Presence = Presence.UNKNOWN
    content: ContentStatus = ContentStatus.NOT_READ
    target: TargetRelation = TargetRelation.NOT_COMPARED
    changed: bool = False
    initial_known: bool = False
    initial_absent: bool = False
    final_absent: bool = False
    eligible: bool = False
    signature: tuple[int, ...] | None = field(default=None, repr=False)
    target_values: tuple[str, str] | None = field(default=None, repr=False)

    def observation(self, root_complete: bool) -> LeafObservation:
        presence = self.presence
        if (
            presence is not Presence.PRESENT
            and self.initial_known
            and self.initial_absent
            and self.final_absent
            and root_complete
        ):
            presence = Presence.ABSENT
        return LeafObservation(presence, self.content, self.target, self.changed)


@dataclass(slots=True)
class _InspectionWork:
    pending: _InspectionLeaf = field(default_factory=_InspectionLeaf, repr=False)
    descriptor: _InspectionLeaf = field(default_factory=_InspectionLeaf, repr=False)
    relation: TargetRelation = TargetRelation.NOT_COMPARED
    non_preparing: bool = False
    first_failure: InspectionFailure = InspectionFailure.NONE
    exit_failure: bool = False
    root_complete: bool = False
    stage: InspectionFailure = InspectionFailure.NONE

    def fail(self, stage: InspectionFailure) -> None:
        if self.first_failure is InspectionFailure.NONE:
            self.first_failure = stage

    def result(self) -> PreparationInspection:
        pending = self.pending.observation(self.root_complete)
        descriptor = self.descriptor.observation(self.root_complete)
        complete = (
            self.root_complete
            and self.first_failure is InspectionFailure.NONE
            and not self.exit_failure
            and _inspection_leaf_complete(pending)
            and _inspection_leaf_complete(descriptor)
            and (
                pending.presence is Presence.ABSENT
                or descriptor.presence is Presence.ABSENT
                or self.relation is not TargetRelation.NOT_COMPARED
            )
        )
        return PreparationInspection(
            _inspection_summary(pending, descriptor, self.relation, self.non_preparing, complete),
            pending,
            descriptor,
            self.relation,
            self.non_preparing,
            complete,
            self.first_failure,
            self.exit_failure,
        )


def _inspection_lstat(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None


def _inspection_signature(info: os.stat_result) -> tuple[int, ...]:
    signature = (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )
    if any(type(value) is not int for value in signature):
        raise ValueError("Invalid inspection metadata")
    return signature


def _inspection_entry(
    path: Path,
    leaf: _InspectionLeaf,
    work: _InspectionWork,
    stage: InspectionFailure,
    limit: int,
    *,
    final: bool,
) -> None:
    work.stage = stage
    try:
        info = _inspection_lstat(path)
        if info is not None and type(info) is not os.stat_result:
            raise ValueError("Invalid inspection metadata")
        if not final:
            leaf.initial_known = True
            leaf.initial_absent = info is None
        if info is None:
            if final:
                leaf.final_absent = True
                if leaf.initial_known and not leaf.initial_absent:
                    leaf.changed = True
                    work.fail(InspectionFailure.ENTRY_CHANGED)
            return
        # Presence is a fact even if signature validation subsequently fails.
        leaf.presence = Presence.PRESENT
        if final and leaf.initial_known and leaf.initial_absent:
            leaf.changed = True
            work.fail(InspectionFailure.ENTRY_CHANGED)
        signature = _inspection_signature(info)
        if final:
            if leaf.signature is not None and signature != leaf.signature:
                leaf.changed = True
                work.fail(InspectionFailure.ENTRY_CHANGED)
        else:
            leaf.signature = signature
            leaf.eligible = (
                stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 <= info.st_size <= limit
            )
            if not leaf.eligible:
                leaf.content = ContentStatus.READ_UNVERIFIABLE
                work.fail(stage)
    except Exception:
        if not final and leaf.presence is Presence.PRESENT:
            leaf.content = ContentStatus.READ_UNVERIFIABLE
        work.fail(stage)


def _inspection_checkpoint(
    owned: private_lock._PrivateDirectoryLock, work: _InspectionWork
) -> None:
    work.stage = InspectionFailure.ROOT_CHECK
    try:
        owned.revalidate()
    except Exception:
        work.fail(InspectionFailure.ROOT_CHECK)
        raise


def _inspection_read(
    path: Path,
    leaf: _InspectionLeaf,
    work: _InspectionWork,
    stage: InspectionFailure,
    limit: int,
) -> bytes | None:
    if not leaf.eligible:
        return None
    work.stage = stage
    try:
        raw = read_private_sensitive_bytes(path, max_size=limit)
        if type(raw) is not bytes or len(raw) > limit:
            raise ValueError("Invalid inspection bytes")
        return raw
    except Exception:
        leaf.content = ContentStatus.READ_UNVERIFIABLE
        work.fail(stage)
        return None


def _inspection_pending(raw: bytes, inputs: _Inputs, work: _InspectionWork) -> None:
    work.stage = InspectionFailure.PENDING_SCHEMA
    leaf = work.pending
    try:
        if type(raw) is not bytes or not 1 <= len(raw) <= 512 or raw.startswith(b"\xef\xbb\xbf"):
            raise ValueError("Invalid inspection pending")
        data: object = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_constant,
        )
        if not _valid_pending(data) or _canonical_pending(data) != raw:
            raise ValueError("Invalid inspection pending")
        leaf.content = ContentStatus.SCHEMA_VALID
        revision, pin = data["target_revision"], data["target_pin"]
        if type(revision) is not str or type(pin) is not str:
            raise ValueError("Invalid inspection pending")
        leaf.target_values = (revision, pin)
        leaf.target = (
            TargetRelation.MATCH
            if leaf.target_values
            == (inputs.expectation.enrollment_revision, inputs.expectation.descriptor_pin)
            else TargetRelation.MISMATCH
        )
    except Exception:
        if leaf.content is not ContentStatus.SCHEMA_VALID:
            leaf.content = ContentStatus.SCHEMA_UNVERIFIABLE
        work.fail(InspectionFailure.PENDING_SCHEMA)


def _inspection_extract_descriptor(raw: bytes) -> tuple[str, str]:
    # The caller already established the complete schema with the public validator.
    data: object = json.loads(raw.decode("utf-8"))
    if type(data) is not dict:
        raise ValueError("Invalid inspection extraction")
    revision, state = data["enrollment_revision"], data["administrative_state"]
    if type(revision) is not str or type(state) is not str:
        raise ValueError("Invalid inspection extraction")
    return revision, state


def _inspection_digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _inspection_descriptor(raw: bytes, inputs: _Inputs, work: _InspectionWork) -> None:
    work.stage = InspectionFailure.DESCRIPTOR_COMPARE
    leaf = work.descriptor
    try:
        result = validate_enrollment_descriptor(raw, inputs.expectation)
        if result.state is EnrollmentDescriptorState.DESCRIPTOR_MATCHED_UNAPPROVED:
            leaf.target = TargetRelation.MATCH
        elif result.state is EnrollmentDescriptorState.ENROLLMENT_MISMATCH:
            leaf.target = TargetRelation.MISMATCH
        else:
            raise ValueError("Descriptor inspection unverifiable")
        leaf.content = ContentStatus.SCHEMA_VALID
    except Exception:
        leaf.content = ContentStatus.SCHEMA_UNVERIFIABLE
        work.fail(InspectionFailure.DESCRIPTOR_COMPARE)
        return
    work.stage = InspectionFailure.TARGET_EXTRACTION
    try:
        revision, state = _inspection_extract_descriptor(raw)
        work.non_preparing = state != "PREPARING"
        leaf.target_values = (revision, _inspection_digest(raw))
        if work.pending.target_values is not None:
            work.relation = (
                TargetRelation.MATCH
                if work.pending.target_values == leaf.target_values
                else TargetRelation.MISMATCH
            )
    except Exception:
        work.fail(InspectionFailure.TARGET_EXTRACTION)


def _inspection_body(
    inputs: _Inputs, owned: private_lock._PrivateDirectoryLock, work: _InspectionWork
) -> None:
    pending = inputs.root / inputs.expectation.administrative_pending_slot
    descriptor = inputs.root / inputs.expectation.descriptor_slot
    _inspection_checkpoint(owned, work)
    _inspection_entry(
        pending, work.pending, work, InspectionFailure.PENDING_ENTRY, 512, final=False
    )
    _inspection_entry(
        descriptor, work.descriptor, work, InspectionFailure.DESCRIPTOR_ENTRY, 8192, final=False
    )
    _inspection_checkpoint(owned, work)
    pending_raw = _inspection_read(pending, work.pending, work, InspectionFailure.PENDING_READ, 512)
    if pending_raw is not None:
        _inspection_pending(pending_raw, inputs, work)
    _inspection_checkpoint(owned, work)
    descriptor_raw = _inspection_read(
        descriptor, work.descriptor, work, InspectionFailure.DESCRIPTOR_READ, 8192
    )
    if descriptor_raw is not None:
        _inspection_descriptor(descriptor_raw, inputs, work)
    _inspection_entry(pending, work.pending, work, InspectionFailure.PENDING_ENTRY, 512, final=True)
    _inspection_entry(
        descriptor, work.descriptor, work, InspectionFailure.DESCRIPTOR_ENTRY, 8192, final=True
    )
    _inspection_checkpoint(owned, work)
    work.root_complete = True


def inspect_synthetic_enrollment_preparation(
    control_root: object, expected_raw: object, expectation: object
) -> PreparationInspection:
    """Read two retained leaves once; matching observations never permit reuse.

    Expected bytes are supplied independently, not learned from either record.
    No freshness, approved-location, prior-writer or atomic-snapshot claim follows.
    """
    if not _linux_storage_available():
        return PreparationInspection(InspectionState.UNSUPPORTED_PLATFORM)
    try:
        inputs = _snapshot(control_root, expected_raw, expectation)
        work = _InspectionWork()
    except _InputRefusal as refusal:
        state = (
            InspectionState.PREPARING_REQUIRED
            if refusal.state is PreparationState.PREPARING_REQUIRED
            else InspectionState.INPUT_UNVERIFIABLE
        )
        return PreparationInspection(state, first_failure=InspectionFailure.INPUT)
    except Exception:
        return PreparationInspection(
            InspectionState.INPUT_UNVERIFIABLE, first_failure=InspectionFailure.INPUT
        )
    try:
        owned = private_lock.acquire_posix_private_directory_lock(inputs.root)
    except Exception as error:
        busy = (
            type(error) is private_lock.PosixPrivateLockError
            and type(error.code) is str
            and error.code == "posix_directory_lock_busy"
        )
        return PreparationInspection(
            InspectionState.LOCK_BUSY if busy else InspectionState.LOCK_UNAVAILABLE,
            first_failure=InspectionFailure.ACQUIRE,
        )
    try:
        owned.__enter__()
    except BaseException as entry_error:
        exit_failure = False
        try:
            owned.close()
        except BaseException as cleanup:
            if isinstance(cleanup, Exception):
                exit_failure = True
            elif isinstance(entry_error, Exception):
                raise
        if not isinstance(entry_error, Exception):
            raise
        return PreparationInspection(
            InspectionState.LOCK_UNAVAILABLE,
            first_failure=InspectionFailure.ENTRY,
            exit_failure_observed=exit_failure,
        )
    observed_error: BaseException | None = None
    try:
        work.stage = InspectionFailure.ROOT_CHECK
        _inspection_body(inputs, owned, work)
    except BaseException as body_error:
        observed_error = body_error
        if isinstance(body_error, Exception):
            work.fail(work.stage)
    try:
        owned.__exit__(
            type(observed_error) if observed_error is not None else None,
            observed_error,
            observed_error.__traceback__ if observed_error is not None else None,
        )
    except BaseException as exit_error:
        if isinstance(exit_error, Exception):
            work.exit_failure = True
            work.fail(InspectionFailure.EXIT)
        elif observed_error is None or isinstance(observed_error, Exception):
            observed_error = exit_error
    if observed_error is not None and not isinstance(observed_error, Exception):
        raise observed_error from None
    return work.result()
