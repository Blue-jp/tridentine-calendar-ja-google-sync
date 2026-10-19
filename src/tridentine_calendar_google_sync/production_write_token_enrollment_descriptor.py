"""Compare synthetic enrollment metadata without bootstrap or use authority.

Even matching ACTIVE or REVOKED metadata is only MATCHED_UNAPPROVED. This
comparison cannot clear ADMIN_REVOKED, ADMIN_PENDING or ADMIN_COMMIT_UNCERTAIN.
Caller-controlled expectations prove neither authenticity nor freshness.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Literal, TypeGuard

_MAX_BYTES = 8192
_RECORD_SLOT = "production-write-operation-start-v1.json"
_VARIABLE_FIELDS = (
    "enrollment_revision",
    "administrative_state",
    "storage_ref",
    "pair_ref",
    "artifact_directory",
    "token_slot",
    "state_slot",
    "active_intent_slot",
)
_EXPECTATION_FIELDS = (
    *_VARIABLE_FIELDS,
    "descriptor_pin",
    "descriptor_slot",
    "administrative_pending_slot",
)
_FIXED_FIELDS: dict[str, object] = {
    "format_version": 1,
    "record_kind": "enrollment_descriptor",
    "role": "production_write",
    "record_slot": _RECORD_SLOT,
}


class EnrollmentDescriptorState(StrEnum):
    EXPECTATION_UNVERIFIABLE = "EXPECTATION_UNVERIFIABLE"
    DESCRIPTOR_UNVERIFIABLE = "DESCRIPTOR_UNVERIFIABLE"
    ENROLLMENT_MISMATCH = "ENROLLMENT_MISMATCH"
    DESCRIPTOR_MATCHED_UNAPPROVED = "DESCRIPTOR_MATCHED_UNAPPROVED"


@dataclass(frozen=True, slots=True)
class SyntheticEnrollmentExpectation:
    """Explicit synthetic assertions, not trusted deployment or approval."""

    enrollment_revision: str = field(repr=False)
    administrative_state: str = field(repr=False)
    storage_ref: str = field(repr=False)
    pair_ref: str = field(repr=False)
    artifact_directory: str = field(repr=False)
    token_slot: str = field(repr=False)
    state_slot: str = field(repr=False)
    active_intent_slot: str = field(repr=False)
    descriptor_pin: str = field(repr=False)
    descriptor_slot: str = field(repr=False)
    administrative_pending_slot: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class EnrollmentDescriptorResult:
    """Fixed comparison only; no metadata, permit or administrative override."""

    state: EnrollmentDescriptorState
    reuse_authorized: Literal[False] = field(default=False, init=False)

    def __post_init__(self) -> None:
        if type(self.state) is not EnrollmentDescriptorState or self.reuse_authorized is not False:
            raise ValueError("Invalid enrollment comparison result")


class _DescriptorFormatError(ValueError):
    def __init__(self) -> None:
        super().__init__("Invalid synthetic enrollment descriptor")


def _valid_ref(value: object) -> TypeGuard[str]:
    return (
        type(value) is str
        and 1 <= len(value) <= 96
        and value.isascii()
        and value[0].isalnum()
        and all(char.isalnum() or char in "._-" for char in value)
    )


def _valid_slot(value: object) -> TypeGuard[str]:
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


def _valid_directory(value: object) -> bool:
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


def _valid_descriptor(data: dict[str, object]) -> bool:
    if data.keys() != _FIXED_FIELDS.keys() | set(_VARIABLE_FIELDS):
        return False
    if type(data["format_version"]) is not int or data["format_version"] != 1:
        return False
    if any(type(value) is not str for key, value in data.items() if key != "format_version"):
        return False
    if any(data[key] != value for key, value in _FIXED_FIELDS.items()):
        return False
    return (
        data["administrative_state"] in {"PREPARING", "ACTIVE", "REVOKED"}
        and all(_valid_ref(data[key]) for key in ("enrollment_revision", "storage_ref", "pair_ref"))
        and _valid_directory(data["artifact_directory"])
        and all(
            _valid_slot(data[key]) for key in ("token_slot", "state_slot", "active_intent_slot")
        )
        and len({data["token_slot"], data["state_slot"], _RECORD_SLOT}) == 3
    )


def _canonical(data: dict[str, object]) -> bytes:
    encoded = (
        json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")
    if not 1 <= len(encoded) <= _MAX_BYTES:
        raise _DescriptorFormatError()
    return encoded


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _expected_descriptor(
    expectation: object,
) -> tuple[dict[str, object], str, tuple[str, str]]:
    if type(expectation) is not SyntheticEnrollmentExpectation:
        raise _DescriptorFormatError()
    values: dict[str, object] = {name: getattr(expectation, name) for name in _EXPECTATION_FIELDS}
    if any(type(value) is not str for value in values.values()):
        raise _DescriptorFormatError()
    pin = expectation.descriptor_pin
    descriptor_slot = expectation.descriptor_slot
    pending_slot = expectation.administrative_pending_slot
    if (
        len(pin) != 64
        or any(char not in "0123456789abcdef" for char in pin)
        or not _valid_slot(descriptor_slot)
        or not _valid_slot(pending_slot)
        or len({descriptor_slot, pending_slot, expectation.active_intent_slot}) != 3
    ):
        raise _DescriptorFormatError()
    data = {**_FIXED_FIELDS, **{name: values[name] for name in _VARIABLE_FIELDS}}
    if not _valid_descriptor(data) or _digest(_canonical(data)) != pin:
        raise _DescriptorFormatError()
    return data, pin, (descriptor_slot, pending_slot)


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    data: dict[str, object] = {}
    for key, value in pairs:
        if key in data:
            raise _DescriptorFormatError()
        data[key] = value
    return data


def _reject_constant(_value: str) -> object:
    raise _DescriptorFormatError()


def _parse_descriptor(raw: object) -> dict[str, object]:
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_BYTES:
        raise _DescriptorFormatError()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise _DescriptorFormatError()
    data: object = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    if type(data) is not dict or not _valid_descriptor(data) or _canonical(data) != raw:
        raise _DescriptorFormatError()
    return data


def validate_enrollment_descriptor(raw: object, expectation: object) -> EnrollmentDescriptorResult:
    """Validate expectations first, without inspecting raw on expectation failure.

    Matching PREPARING, ACTIVE or REVOKED grants no administrative or use
    authority and cannot clear an upper-layer refusal. Paths are lexical data
    only; no filesystem, history or restart evidence is established.
    """
    try:
        expected, pin, control_slots = _expected_descriptor(expectation)
    except Exception:
        return EnrollmentDescriptorResult(EnrollmentDescriptorState.EXPECTATION_UNVERIFIABLE)
    try:
        candidate = _parse_descriptor(raw)
        # Parsing has established exact bytes and exact built-in metadata types.
        if type(raw) is not bytes:
            raise _DescriptorFormatError()
        candidate_pin = _digest(raw)
        if (
            candidate != expected
            or candidate_pin != pin
            or candidate["active_intent_slot"] in control_slots
        ):
            return EnrollmentDescriptorResult(EnrollmentDescriptorState.ENROLLMENT_MISMATCH)
    except Exception:
        return EnrollmentDescriptorResult(EnrollmentDescriptorState.DESCRIPTOR_UNVERIFIABLE)
    return EnrollmentDescriptorResult(EnrollmentDescriptorState.DESCRIPTOR_MATCHED_UNAPPROVED)
