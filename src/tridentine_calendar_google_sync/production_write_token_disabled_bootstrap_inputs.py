"""Compare synthetic disabled policy inputs without deployment or use authority.

The caller supplies every expectation independently. Matching values neither
authenticate their origin nor establish freshness or clear an upper refusal.
"""

from __future__ import annotations

import json
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal, TypeGuard, cast

from tridentine_calendar_google_sync.production_write_token_enrollment_descriptor import (
    EnrollmentDescriptorState,
    SyntheticEnrollmentExpectation,
    validate_enrollment_descriptor,
)

_MAX_BYTES = 8192
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
_POLICY_KEYS = {
    "format_version",
    "policy_kind",
    "control_root",
    "descriptor_slot",
    "administrative_pending_slot",
    "expected_revision",
    "descriptor_pin",
    "expected_state",
    "entry_mode",
}


class DisabledBootstrapInputState(StrEnum):
    POLICY_UNVERIFIABLE = "POLICY_UNVERIFIABLE"
    INPUTS_UNVERIFIABLE = "INPUTS_UNVERIFIABLE"
    ENTRY_MODE_REFUSED = "ENTRY_MODE_REFUSED"
    INPUTS_MISMATCH = "INPUTS_MISMATCH"
    STATE_OUT_OF_SCOPE = "STATE_OUT_OF_SCOPE"
    INPUTS_MATCHED_UNAPPROVED = "INPUTS_MATCHED_UNAPPROVED"


@dataclass(frozen=True, slots=True)
class DisabledBootstrapInputResult:
    state: DisabledBootstrapInputState
    reuse_authorized: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if (
            type(self.state) is not DisabledBootstrapInputState
            or self.reuse_authorized is not False
        ):
            raise ValueError("Invalid disabled bootstrap input result")


@dataclass(frozen=True, slots=True)
class _Inputs:
    policy_raw: bytes = field(repr=False)
    expected_raw: bytes = field(repr=False)
    expectation: SyntheticEnrollmentExpectation = field(repr=False)
    expected_control_root: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class _Policy:
    control_root: str = field(repr=False)
    descriptor_slot: str = field(repr=False)
    administrative_pending_slot: str = field(repr=False)
    expected_revision: str = field(repr=False)
    descriptor_pin: str = field(repr=False)
    expected_state: str = field(repr=False)
    entry_mode: str = field(repr=False)


class _InputFormatError(ValueError):
    def __init__(self) -> None:
        super().__init__("Invalid synthetic bootstrap inputs")


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


def _valid_ref(value: object) -> TypeGuard[str]:
    return (
        type(value) is str
        and 1 <= len(value) <= 96
        and value.isascii()
        and value[0].isalnum()
        and all(char.isalnum() or char in "._-" for char in value)
    )


def _valid_slot(value: object) -> bool:
    return (
        _valid_ref(value)
        and not value.endswith(".")
        and value.split(".", 1)[0].upper()
        not in {
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
    )


def _capture_inputs(
    policy_raw: bytes,
    expected_raw: object,
    expectation: object,
    expected_control_root: object,
) -> _Inputs:
    if type(expected_raw) is not bytes or not 1 <= len(expected_raw) <= _MAX_BYTES:
        raise _InputFormatError()
    if not _valid_root(expected_control_root):
        raise _InputFormatError()
    if type(expectation) is not SyntheticEnrollmentExpectation:
        raise _InputFormatError()
    values: dict[str, object] = {name: getattr(expectation, name) for name in _EXPECTATION_FIELDS}
    if any(type(value) is not str for value in values.values()):
        raise _InputFormatError()
    retained = SyntheticEnrollmentExpectation(
        **{name: cast(str, value) for name, value in values.items()}
    )
    return _Inputs(policy_raw, expected_raw, retained, expected_control_root)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    data: dict[str, object] = {}
    for key, value in pairs:
        if key in data:
            raise _InputFormatError()
        data[key] = value
    return data


def _reject_constant(_value: str) -> object:
    raise _InputFormatError()


def _canonical_policy(data: dict[str, object]) -> bytes:
    raw = (
        json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")
    if not 1 <= len(raw) <= _MAX_BYTES:
        raise _InputFormatError()
    return raw


def _parse_policy(raw: bytes) -> _Policy:
    if raw.startswith(b"\xef\xbb\xbf"):
        raise _InputFormatError()
    data: object = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if type(data) is not dict or data.keys() != _POLICY_KEYS:
        raise _InputFormatError()
    if type(data["format_version"]) is not int or data["format_version"] != 1:
        raise _InputFormatError()
    if any(type(value) is not str for key, value in data.items() if key != "format_version"):
        raise _InputFormatError()
    if any(
        unicodedata.category(char) == "Cs"
        for key, value in data.items()
        if key != "format_version"
        for char in value
    ):
        raise _InputFormatError()
    if (
        data["policy_kind"] != "enrollment_bootstrap"
        or not _valid_root(data["control_root"])
        or not _valid_slot(data["descriptor_slot"])
        or not _valid_slot(data["administrative_pending_slot"])
        or data["descriptor_slot"] == data["administrative_pending_slot"]
        or not _valid_ref(data["expected_revision"])
        or len(data["descriptor_pin"]) != 64
        or any(char not in "0123456789abcdef" for char in data["descriptor_pin"])
        or data["expected_state"] not in {"PREPARING", "ACTIVE", "REVOKED"}
        or _canonical_policy(data) != raw
    ):
        raise _InputFormatError()
    return _Policy(
        data["control_root"],
        cast(str, data["descriptor_slot"]),
        cast(str, data["administrative_pending_slot"]),
        data["expected_revision"],
        cast(str, data["descriptor_pin"]),
        cast(str, data["expected_state"]),
        cast(str, data["entry_mode"]),
    )


def _policy_matches(policy: _Policy, inputs: _Inputs) -> bool:
    expected = inputs.expectation
    return (
        policy.control_root == inputs.expected_control_root
        and policy.descriptor_slot == expected.descriptor_slot
        and policy.administrative_pending_slot == expected.administrative_pending_slot
        and policy.expected_revision == expected.enrollment_revision
        and policy.descriptor_pin == expected.descriptor_pin
        and policy.expected_state == expected.administrative_state
    )


def _checked_descriptor_state(state: object, reuse_authorized: object) -> EnrollmentDescriptorState:
    if type(state) is not EnrollmentDescriptorState or reuse_authorized is not False:
        raise _InputFormatError()
    return state


def _checked_match(value: object) -> bool:
    if type(value) is not bool:
        raise _InputFormatError()
    return value


def validate_disabled_bootstrap_inputs(
    policy_raw: object,
    expected_raw: object,
    expectation: object,
    *,
    expected_control_root: object,
) -> DisabledBootstrapInputResult:
    """Return the first fixed refusal, or an unapproved synthetic comparison."""
    if type(policy_raw) is not bytes or not 1 <= len(policy_raw) <= _MAX_BYTES:
        return DisabledBootstrapInputResult(DisabledBootstrapInputState.POLICY_UNVERIFIABLE)
    try:
        inputs = _capture_inputs(policy_raw, expected_raw, expectation, expected_control_root)
    except Exception:
        return DisabledBootstrapInputResult(DisabledBootstrapInputState.INPUTS_UNVERIFIABLE)
    try:
        policy = _parse_policy(inputs.policy_raw)
    except Exception:
        return DisabledBootstrapInputResult(DisabledBootstrapInputState.POLICY_UNVERIFIABLE)
    if policy.entry_mode != "disabled":
        return DisabledBootstrapInputResult(DisabledBootstrapInputState.ENTRY_MODE_REFUSED)
    try:
        comparison = validate_enrollment_descriptor(inputs.expected_raw, inputs.expectation)
        state = _checked_descriptor_state(comparison.state, comparison.reuse_authorized)
        if state is EnrollmentDescriptorState.ENROLLMENT_MISMATCH:
            return DisabledBootstrapInputResult(DisabledBootstrapInputState.INPUTS_MISMATCH)
        if state is not EnrollmentDescriptorState.DESCRIPTOR_MATCHED_UNAPPROVED:
            return DisabledBootstrapInputResult(DisabledBootstrapInputState.INPUTS_UNVERIFIABLE)
        matched = _checked_match(_policy_matches(policy, inputs))
        if not matched:
            return DisabledBootstrapInputResult(DisabledBootstrapInputState.INPUTS_MISMATCH)
        if policy.expected_state != "PREPARING":
            return DisabledBootstrapInputResult(DisabledBootstrapInputState.STATE_OUT_OF_SCOPE)
    except Exception:
        return DisabledBootstrapInputResult(DisabledBootstrapInputState.INPUTS_UNVERIFIABLE)
    return DisabledBootstrapInputResult(DisabledBootstrapInputState.INPUTS_MATCHED_UNAPPROVED)
