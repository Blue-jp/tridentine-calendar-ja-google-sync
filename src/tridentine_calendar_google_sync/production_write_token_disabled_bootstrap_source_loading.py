"""Load only independently supplied synthetic sources for unapproved inspection.

Fixture ownership, physical separation and stable ancestors are external test
conditions. Private reads do not establish deployment provenance or freshness.
"""

from __future__ import annotations

import os
import stat
import sys
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Literal, cast

from tridentine_calendar_google_sync.production_write_token_disabled_bootstrap_inspection import (
    DisabledBootstrapInspectionResult,
    DisabledBootstrapInspectionResultError,
    inspect_synthetic_disabled_bootstrap,
)
from tridentine_calendar_google_sync.production_write_token_enrollment_descriptor import (
    SyntheticEnrollmentExpectation,
)
from tridentine_calendar_google_sync.sensitive_paths import read_private_sensitive_bytes

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


class DisabledBootstrapSourceStage(StrEnum):
    CAPTURE = "CAPTURE"
    PLATFORM = "PLATFORM"
    PRECHECK = "PRECHECK"
    POLICY_READ = "POLICY_READ"
    COMPANION_READ = "COMPANION_READ"
    RECHECK = "RECHECK"
    HANDOFF = "HANDOFF"


class DisabledBootstrapSourceReason(StrEnum):
    INPUT_UNVERIFIABLE = "INPUT_UNVERIFIABLE"
    UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"
    SOURCE_OVERLAP = "SOURCE_OVERLAP"
    SOURCE_UNVERIFIABLE = "SOURCE_UNVERIFIABLE"
    SOURCE_CHANGED = "SOURCE_CHANGED"
    HANDOFF_FAILED = "HANDOFF_FAILED"
    HANDOFF_RESULT_UNVERIFIABLE = "HANDOFF_RESULT_UNVERIFIABLE"


_ALLOWED_REASONS = {
    DisabledBootstrapSourceStage.CAPTURE: (
        DisabledBootstrapSourceReason.INPUT_UNVERIFIABLE,
        DisabledBootstrapSourceReason.SOURCE_OVERLAP,
    ),
    DisabledBootstrapSourceStage.PLATFORM: (DisabledBootstrapSourceReason.UNSUPPORTED_PLATFORM,),
    DisabledBootstrapSourceStage.PRECHECK: (
        DisabledBootstrapSourceReason.SOURCE_UNVERIFIABLE,
        DisabledBootstrapSourceReason.SOURCE_OVERLAP,
    ),
    DisabledBootstrapSourceStage.POLICY_READ: (DisabledBootstrapSourceReason.SOURCE_UNVERIFIABLE,),
    DisabledBootstrapSourceStage.COMPANION_READ: (
        DisabledBootstrapSourceReason.SOURCE_UNVERIFIABLE,
    ),
    DisabledBootstrapSourceStage.RECHECK: (
        DisabledBootstrapSourceReason.SOURCE_UNVERIFIABLE,
        DisabledBootstrapSourceReason.SOURCE_CHANGED,
    ),
    DisabledBootstrapSourceStage.HANDOFF: (
        DisabledBootstrapSourceReason.HANDOFF_FAILED,
        DisabledBootstrapSourceReason.HANDOFF_RESULT_UNVERIFIABLE,
    ),
}


@dataclass(frozen=True, slots=True)
class DisabledBootstrapSourceRefusal:
    """Fixed acquisition/call refusal, never a use or recovery permit."""

    stage: DisabledBootstrapSourceStage
    reason: DisabledBootstrapSourceReason
    reuse_authorized: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if (
            type(self.stage) is not DisabledBootstrapSourceStage
            or type(self.reason) is not DisabledBootstrapSourceReason
            or self.reuse_authorized is not False
            or not any(self.stage is member for member in DisabledBootstrapSourceStage)
            or not any(self.reason is member for member in DisabledBootstrapSourceReason)
            or self.reason not in _ALLOWED_REASONS[self.stage]
        ):
            raise ValueError("Invalid disabled bootstrap source refusal")


class DisabledBootstrapSourceResultError(RuntimeError):
    """Terminal refusal when the fixed source diagnostic cannot be constructed."""

    __slots__ = ()

    def __init__(self) -> None:
        super().__init__("Disabled bootstrap source result construction failed")

    @property
    def reuse_authorized(self) -> Literal[False]:
        return False


def _refuse(
    stage: DisabledBootstrapSourceStage, reason: DisabledBootstrapSourceReason
) -> DisabledBootstrapSourceRefusal:
    try:
        return DisabledBootstrapSourceRefusal(stage, reason)
    except Exception:
        pass
    failure = DisabledBootstrapSourceResultError()
    try:
        raise failure from None
    except DisabledBootstrapSourceResultError:
        failure.__cause__ = None
        failure.__context__ = None
        raise


@dataclass(frozen=True, slots=True)
class _CapturedInputs:
    source_root: str = field(repr=False)
    policy_leaf: str = field(repr=False)
    expected_descriptor_leaf: str = field(repr=False)
    expectation: SyntheticEnrollmentExpectation = field(repr=False)
    expected_control_root: str = field(repr=False)


def _path_text(value: object) -> str:
    if type(value) is not str or not 1 < len(value) <= 1024:
        raise ValueError("Invalid synthetic source placement")
    if (
        not value.startswith("/")
        or value.endswith("/")
        or "//" in value
        or any(char in value for char in "\\:")
        or any(unicodedata.category(char) in {"Cc", "Cs"} for char in value)
        or len(value.encode("utf-8")) > 1024
        or any(
            part in {".", "..", ".git"} or part.endswith((" ", "."))
            for part in value.split("/")[1:]
        )
    ):
        raise ValueError("Invalid synthetic source placement")
    return value


def _leaf_text(value: object) -> str:
    if type(value) is not str or not 1 <= len(value) <= 96:
        raise ValueError("Invalid synthetic source leaf")
    if (
        not value.isascii()
        or not value[0].isalnum()
        or any(not (char.isalnum() or char in "._-") for char in value)
        or value.endswith(".")
        or value.split(".", 1)[0].upper()
        in {
            "CON",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "COM2",
            "COM3",
            "COM4",
            "COM5",
            "COM6",
            "COM7",
            "COM8",
            "COM9",
            "LPT1",
            "LPT2",
            "LPT3",
            "LPT4",
            "LPT5",
            "LPT6",
            "LPT7",
            "LPT8",
            "LPT9",
        }
    ):
        raise ValueError("Invalid synthetic source leaf")
    return value


def _capture_inputs(
    source_root: object,
    policy_leaf: object,
    expected_descriptor_leaf: object,
    expectation: object,
    expected_control_root: object,
) -> _CapturedInputs:
    root = _path_text(source_root)
    policy = _leaf_text(policy_leaf)
    companion = _leaf_text(expected_descriptor_leaf)
    control = _path_text(expected_control_root)
    if type(expectation) is not SyntheticEnrollmentExpectation:
        raise ValueError("Invalid synthetic source expectation")
    values: dict[str, object] = {name: getattr(expectation, name) for name in _EXPECTATION_FIELDS}
    if any(type(value) is not str for value in values.values()):
        raise ValueError("Invalid synthetic source expectation")
    retained = SyntheticEnrollmentExpectation(
        **{name: cast(str, value) for name, value in values.items()}
    )
    _path_text(retained.artifact_directory)
    return _CapturedInputs(root, policy, companion, retained, control)


def _overlaps(left: str, right: str) -> bool:
    return left == right or left.startswith(right + "/") or right.startswith(left + "/")


def _linux_supported() -> bool:
    return sys.platform == "linux" and os.name == "posix"


def _effective_uid() -> int:
    if sys.platform == "linux":
        return os.geteuid()
    raise ValueError("Unavailable synthetic source owner")


def _lstat(path: Path) -> os.stat_result:
    return path.lstat()


@dataclass(frozen=True, slots=True)
class _Signature:
    dev: int = field(repr=False)
    ino: int = field(repr=False)
    mode: int = field(repr=False)
    uid: int = field(repr=False)
    gid: int = field(repr=False)
    nlink: int = field(repr=False)
    size: int = field(repr=False)
    mtime_ns: int = field(repr=False)
    ctime_ns: int = field(repr=False)


def _signature(value: os.stat_result) -> _Signature:
    values = (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if any(type(item) is not int for item in values) or any(item < 0 for item in values[:7]):
        raise ValueError("Invalid synthetic source metadata")
    return _Signature(*values)


def _require_private(value: _Signature, uid: int, *, root: bool) -> None:
    if value.uid != uid:
        raise ValueError("Unverifiable synthetic source")
    if root:
        valid = stat.S_ISDIR(value.mode) and stat.S_IMODE(value.mode) == 0o700
    else:
        valid = (
            stat.S_ISREG(value.mode)
            and value.nlink == 1
            and not stat.S_IMODE(value.mode) & 0o077
            and 1 <= value.size <= 8192
        )
    if not valid:
        raise ValueError("Unverifiable synthetic source")


def _require_bytes(value: object) -> bytes:
    if type(value) is not bytes or not 1 <= len(value) <= 8192:
        raise ValueError("Invalid synthetic source bytes")
    return value


def _recheck(
    path: Path,
    previous: _Signature,
    uid: int,
    *,
    root: bool,
    payload: bytes | None = None,
) -> DisabledBootstrapSourceReason | None:
    try:
        current = _signature(_lstat(path))
    except Exception:
        return DisabledBootstrapSourceReason.SOURCE_UNVERIFIABLE
    if current != previous:
        return DisabledBootstrapSourceReason.SOURCE_CHANGED
    try:
        _require_private(current, uid, root=root)
    except Exception:
        return DisabledBootstrapSourceReason.SOURCE_UNVERIFIABLE
    if payload is not None and len(payload) != previous.size:
        return DisabledBootstrapSourceReason.SOURCE_CHANGED
    return None


def _copy_handoff(value: object) -> DisabledBootstrapInspectionResult:
    if type(value) is not DisabledBootstrapInspectionResult:
        raise ValueError("Invalid synthetic source handoff result")
    state, inputs, observation, authorized = (
        value.state,
        value.input_result,
        value.inspection_result,
        value.reuse_authorized,
    )
    if authorized is not False:
        raise ValueError("Invalid synthetic source handoff result")
    return DisabledBootstrapInspectionResult(state, inputs, observation)


def load_synthetic_disabled_bootstrap(
    source_root: object,
    policy_leaf: object,
    expected_descriptor_leaf: object,
    expectation: object,
    *,
    expected_control_root: object,
) -> DisabledBootstrapInspectionResult | DisabledBootstrapSourceRefusal:
    """Read two independent synthetic sources once before one unapproved handoff."""
    try:
        inputs = _capture_inputs(
            source_root, policy_leaf, expected_descriptor_leaf, expectation, expected_control_root
        )
    except Exception:
        return _refuse(
            DisabledBootstrapSourceStage.CAPTURE,
            DisabledBootstrapSourceReason.INPUT_UNVERIFIABLE,
        )
    if (
        inputs.policy_leaf == inputs.expected_descriptor_leaf
        or _overlaps(inputs.source_root, inputs.expected_control_root)
        or _overlaps(inputs.source_root, inputs.expectation.artifact_directory)
    ):
        return _refuse(
            DisabledBootstrapSourceStage.CAPTURE, DisabledBootstrapSourceReason.SOURCE_OVERLAP
        )
    if not _linux_supported():
        return _refuse(
            DisabledBootstrapSourceStage.PLATFORM,
            DisabledBootstrapSourceReason.UNSUPPORTED_PLATFORM,
        )
    try:
        root_path = Path(inputs.source_root)
        policy_path = root_path / inputs.policy_leaf
        companion_path = root_path / inputs.expected_descriptor_leaf
        uid = _effective_uid()
        if type(uid) is not int or uid < 0:
            raise ValueError("Invalid synthetic source owner")
        before_root = _signature(_lstat(root_path))
        _require_private(before_root, uid, root=True)
        before_policy = _signature(_lstat(policy_path))
        _require_private(before_policy, uid, root=False)
        before_companion = _signature(_lstat(companion_path))
        _require_private(before_companion, uid, root=False)
    except Exception:
        return _refuse(
            DisabledBootstrapSourceStage.PRECHECK,
            DisabledBootstrapSourceReason.SOURCE_UNVERIFIABLE,
        )
    if (before_policy.dev, before_policy.ino) == (before_companion.dev, before_companion.ino):
        return _refuse(
            DisabledBootstrapSourceStage.PRECHECK, DisabledBootstrapSourceReason.SOURCE_OVERLAP
        )
    try:
        policy_raw = _require_bytes(read_private_sensitive_bytes(policy_path, max_size=8192))
    except Exception:
        return _refuse(
            DisabledBootstrapSourceStage.POLICY_READ,
            DisabledBootstrapSourceReason.SOURCE_UNVERIFIABLE,
        )
    try:
        expected_raw = _require_bytes(read_private_sensitive_bytes(companion_path, max_size=8192))
    except Exception:
        return _refuse(
            DisabledBootstrapSourceStage.COMPANION_READ,
            DisabledBootstrapSourceReason.SOURCE_UNVERIFIABLE,
        )
    reason = _recheck(root_path, before_root, uid, root=True)
    if reason is not None:
        return _refuse(DisabledBootstrapSourceStage.RECHECK, reason)
    reason = _recheck(policy_path, before_policy, uid, root=False, payload=policy_raw)
    if reason is not None:
        return _refuse(DisabledBootstrapSourceStage.RECHECK, reason)
    reason = _recheck(companion_path, before_companion, uid, root=False, payload=expected_raw)
    if reason is not None:
        return _refuse(DisabledBootstrapSourceStage.RECHECK, reason)
    try:
        result = inspect_synthetic_disabled_bootstrap(
            policy_raw,
            expected_raw,
            inputs.expectation,
            expected_control_root=inputs.expected_control_root,
        )
    except DisabledBootstrapInspectionResultError as error:
        if type(error) is DisabledBootstrapInspectionResultError:
            raise
        return _refuse(
            DisabledBootstrapSourceStage.HANDOFF, DisabledBootstrapSourceReason.HANDOFF_FAILED
        )
    except Exception:
        return _refuse(
            DisabledBootstrapSourceStage.HANDOFF, DisabledBootstrapSourceReason.HANDOFF_FAILED
        )
    try:
        return _copy_handoff(result)
    except Exception:
        return _refuse(
            DisabledBootstrapSourceStage.HANDOFF,
            DisabledBootstrapSourceReason.HANDOFF_RESULT_UNVERIFIABLE,
        )
