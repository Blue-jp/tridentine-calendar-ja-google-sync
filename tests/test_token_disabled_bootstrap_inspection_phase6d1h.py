"""Synthetic handoff only; no deployment, startup, retirement, or use authority."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
import stat
import subprocess
import sys
from dataclasses import FrozenInstanceError, fields, replace
from enum import StrEnum
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tridentine_calendar_google_sync import (
    production_write_token_disabled_bootstrap_inputs as inputs,
)
from tridentine_calendar_google_sync import (
    production_write_token_disabled_bootstrap_inspection as adapter,
)
from tridentine_calendar_google_sync import (
    production_write_token_enrollment_descriptor as descriptor,
)
from tridentine_calendar_google_sync import production_write_token_enrollment_preparation as prep

S = adapter.DisabledBootstrapInspectionState
B = inputs.DisabledBootstrapInputState
IS = prep.InspectionState
P = prep.Presence
C = prep.ContentStatus
T = prep.TargetRelation
F = prep.InspectionFailure
ROOT = "/synthetic-handoff-control"
PENDING = "pending.json"
DESCRIPTOR = "descriptor.json"
RAW = (
    b'{"active_intent_slot":"intent.json","administrative_state":"PREPARING",'
    b'"artifact_directory":"/synthetic-handoff-pair","enrollment_revision":"revision-one",'
    b'"format_version":1,"pair_ref":"pair-one","record_kind":"enrollment_descriptor",'
    b'"record_slot":"production-write-operation-start-v1.json","role":"production_write",'
    b'"state_slot":"state.json","storage_ref":"store-one","token_slot":"token.json"}\n'
)
EXPECTATION_FIELDS = (
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
OBSERVATION_FIELDS = (
    "state",
    "pending",
    "descriptor",
    "target_relation",
    "non_preparing_observed",
    "verification_complete",
    "first_failure",
    "exit_failure_observed",
    "reuse_authorized",
)
LEAF_FIELDS = ("presence", "content", "target", "changed")
LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="native Linux synthetic handoff")
WINDOWS_ONLY = pytest.mark.skipif(sys.platform != "win32", reason="native Windows platform gate")
_UNSET = object()


def _wire(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _expect(raw: bytes = RAW) -> descriptor.SyntheticEnrollmentExpectation:
    data = json.loads(raw)
    return descriptor.SyntheticEnrollmentExpectation(
        **{name: data[name] for name in EXPECTATION_FIELDS[:8]},
        descriptor_pin=hashlib.sha256(raw).hexdigest(),
        descriptor_slot=DESCRIPTOR,
        administrative_pending_slot=PENDING,
    )


def _policy(root: str = ROOT, expected: Any = None) -> bytes:
    expectation = _expect() if expected is None else expected
    return _wire(
        {
            "format_version": 1,
            "policy_kind": "enrollment_bootstrap",
            "control_root": root,
            "descriptor_slot": expectation.descriptor_slot,
            "administrative_pending_slot": expectation.administrative_pending_slot,
            "expected_revision": expectation.enrollment_revision,
            "descriptor_pin": expectation.descriptor_pin,
            "expected_state": expectation.administrative_state,
            "entry_mode": "disabled",
        }
    )


def _pending(raw: bytes = RAW, revision: str = "revision-one") -> bytes:
    return _wire(
        {
            "format_version": 1,
            "record_kind": "enrollment_preparation",
            "target_revision": revision,
            "target_pin": hashlib.sha256(raw).hexdigest(),
            "outcome": "pending",
        }
    )


def _call(
    *,
    policy: object = _UNSET,
    raw: object = RAW,
    expectation: object = _UNSET,
    root: object = ROOT,
) -> adapter.DisabledBootstrapInspectionResult:
    return adapter.inspect_synthetic_disabled_bootstrap(
        _policy() if policy is _UNSET else policy,
        raw,
        _expect() if expectation is _UNSET else expectation,
        expected_control_root=root,
    )


def _check(result: Any, state: S) -> Any:
    assert type(result) is adapter.DisabledBootstrapInspectionResult
    assert result.state is state and result.reuse_authorized is False
    assert tuple(item.name for item in fields(result)) == (
        "state",
        "input_result",
        "inspection_result",
        "reuse_authorized",
    )
    assert not hasattr(result, "__dict__")
    if result.input_result is not None:
        assert type(result.input_result) is inputs.DisabledBootstrapInputResult
        assert result.input_result.reuse_authorized is False
    if result.inspection_result is not None:
        assert type(result.inspection_result) is prep.PreparationInspection
        assert result.inspection_result.reuse_authorized is False
    return result


class _UnexpectedEffect(BaseException):
    pass


def _deny(*args: object, **kwargs: object) -> Any:
    raise _UnexpectedEffect("unexpected synthetic input hook or effect")


class _Poison:
    __repr__ = __str__ = __bytes__ = __len__ = __iter__ = __eq__ = __hash__ = _deny
    __getattribute__ = _deny


class _Bytes(bytes):
    pass


class _String(str):
    pass


class _UnknownState(StrEnum):
    MATCHED = "INPUTS_MATCHED_UNAPPROVED"


def _forged_member(enum: Any) -> Any:
    value = str.__new__(enum, "SYNTHETIC_UNKNOWN_ENUM")
    object.__setattr__(value, "_name_", "SYNTHETIC_UNKNOWN_ENUM")
    object.__setattr__(value, "_value_", "SYNTHETIC_UNKNOWN_ENUM")
    return value


def _counterfeit_member(member: Any) -> Any:
    value = str.__new__(type(member), member.value)
    object.__setattr__(value, "_name_", member.name)
    object.__setattr__(value, "_value_", member.value)
    return value


class _Boundaries:
    def __init__(
        self,
        monkeypatch: pytest.MonkeyPatch,
        *,
        validated: Any = _UNSET,
        observed: Any = _UNSET,
    ) -> None:
        self.validated = (
            inputs.DisabledBootstrapInputResult(B.INPUTS_MATCHED_UNAPPROVED)
            if validated is _UNSET
            else validated
        )
        self.observed = (
            prep.PreparationInspection(IS.UNSUPPORTED_PLATFORM) if observed is _UNSET else observed
        )
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        monkeypatch.setattr(adapter, "validate_disabled_bootstrap_inputs", self.validate)
        monkeypatch.setattr(adapter, "inspect_synthetic_enrollment_preparation", self.observe)

    def validate(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(("validate", args, kwargs))
        if type(self.validated) in (RuntimeError, KeyboardInterrupt, SystemExit, _UnexpectedEffect):
            raise self.validated
        return self.validated

    def observe(self, *args: Any, **kwargs: Any) -> Any:
        self.calls.append(("inspect", args, kwargs))
        if type(self.observed) in (RuntimeError, KeyboardInterrupt, SystemExit, _UnexpectedEffect):
            raise self.observed
        return self.observed

    def counts(self, validation: int, inspection: int) -> None:
        assert [item[0] for item in self.calls] == (
            ["validate"] * validation + ["inspect"] * inspection
        )
        assert validation <= 1 and inspection <= 1


def _observation(case: str) -> prep.PreparationInspection:
    absent = prep.LeafObservation(P.ABSENT)
    match = prep.LeafObservation(P.PRESENT, C.SCHEMA_VALID, T.MATCH)
    mismatch = prep.LeafObservation(P.PRESENT, C.SCHEMA_VALID, T.MISMATCH)
    if case == "unsupported":
        return prep.PreparationInspection(IS.UNSUPPORTED_PLATFORM)
    if case == "input":
        return prep.PreparationInspection(IS.INPUT_UNVERIFIABLE, first_failure=F.INPUT)
    if case == "preparing":
        return prep.PreparationInspection(IS.PREPARING_REQUIRED, first_failure=F.INPUT)
    if case == "busy":
        return prep.PreparationInspection(IS.LOCK_BUSY, first_failure=F.ACQUIRE)
    if case == "unavailable":
        return prep.PreparationInspection(
            IS.LOCK_UNAVAILABLE, first_failure=F.ENTRY, exit_failure_observed=True
        )
    if case == "empty":
        return prep.PreparationInspection(
            IS.ABSENCE_UNVERIFIABLE, absent, absent, verification_complete=True
        )
    if case == "pending":
        return prep.PreparationInspection(
            IS.ADMIN_PENDING, match, absent, verification_complete=True
        )
    if case == "descriptor":
        return prep.PreparationInspection(
            IS.ORPHAN_DESCRIPTOR, absent, match, verification_complete=True
        )
    if case == "both":
        return prep.PreparationInspection(
            IS.PREPARATION_RETAINED_UNAPPROVED, match, match, T.MATCH, verification_complete=True
        )
    if case == "conflict":
        return prep.PreparationInspection(
            IS.PREPARATION_CONFLICT, mismatch, match, T.MISMATCH, verification_complete=True
        )
    if case == "nonpreparing":
        return prep.PreparationInspection(
            IS.PREPARATION_CONFLICT, match, mismatch, T.MISMATCH, True, True
        )
    if case == "changed":
        return prep.PreparationInspection(
            IS.PREPARATION_UNVERIFIABLE,
            replace(match, changed=True),
            match,
            T.MATCH,
            first_failure=F.ENTRY_CHANGED,
        )
    if case == "failed-conflict":
        return prep.PreparationInspection(
            IS.PREPARATION_CONFLICT,
            mismatch,
            match,
            T.MISMATCH,
            first_failure=F.ROOT_CHECK,
            exit_failure_observed=True,
        )
    if case == "failed-read":
        return prep.PreparationInspection(
            IS.PREPARATION_UNVERIFIABLE,
            prep.LeafObservation(P.PRESENT, C.READ_UNVERIFIABLE),
            match,
            first_failure=F.PENDING_READ,
        )
    raise AssertionError("unknown synthetic observation case")


def test_public_api_has_four_required_inputs_and_one_keyword_only_root() -> None:
    signature = inspect.signature(adapter.inspect_synthetic_disabled_bootstrap)
    assert tuple(signature.parameters) == (
        "policy_raw",
        "expected_raw",
        "expectation",
        "expected_control_root",
    )
    assert all(item.default is inspect.Parameter.empty for item in signature.parameters.values())
    assert signature.parameters["expected_control_root"].kind is inspect.Parameter.KEYWORD_ONLY
    assert len(S) == 6
    assert _wire(json.loads(RAW)) == RAW and _expect().artifact_directory != ROOT
    with pytest.raises(TypeError):
        adapter.inspect_synthetic_disabled_bootstrap(_policy(), RAW, _expect())
    with pytest.raises(TypeError):
        adapter.inspect_synthetic_disabled_bootstrap(_policy(), RAW, _expect(), ROOT)


@pytest.mark.parametrize("argument", ("policy", "raw"))
@pytest.mark.parametrize(
    "case", ("none", "poison", "text", "subclass", "bytearray", "memoryview", "empty", "large")
)
def test_exact_bytes_capture_rejects_before_both_dependencies(
    argument: str, case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    value = {
        "none": lambda: None,
        "poison": _Poison,
        "text": lambda: "synthetic",
        "subclass": lambda: _Bytes(b"x"),
        "bytearray": lambda: bytearray(b"x"),
        "memoryview": lambda: memoryview(b"x"),
        "empty": lambda: b"",
        "large": lambda: b"x" * 8193,
    }[case]()
    result = _check(_call(**{argument: value}), S.CAPTURE_REFUSED)
    assert result.input_result is None and result.inspection_result is None
    boundary.counts(0, 0)


@pytest.mark.parametrize("argument", ("policy", "raw"))
@pytest.mark.parametrize("size", (1, 8192))
def test_capture_accepts_exact_envelope_bounds_without_parsing(
    argument: str, size: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    value = b"x" * size
    _check(_call(**{argument: value}), S.INSPECTION_OBSERVED)
    boundary.counts(1, 1)
    assert boundary.calls[0][1][0 if argument == "policy" else 1] is value


@pytest.mark.parametrize(
    "case",
    ("root-poison", "root-subclass", "root-none", "expectation-poison", "expectation-subclass"),
)
def test_root_and_expectation_require_exact_types_without_hooks(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class ExpectationSubclass(descriptor.SyntheticEnrollmentExpectation):
        pass

    boundary = _Boundaries(monkeypatch)
    changes = {
        "root-poison": {"root": _Poison()},
        "root-subclass": {"root": _String(ROOT)},
        "root-none": {"root": None},
        "expectation-poison": {"expectation": _Poison()},
        "expectation-subclass": {"expectation": object.__new__(ExpectationSubclass)},
    }
    _check(_call(**changes[case]), S.CAPTURE_REFUSED)
    boundary.counts(0, 0)


@pytest.mark.parametrize("name", EXPECTATION_FIELDS)
@pytest.mark.parametrize("case", ("missing", "poison", "integer", "subclass"))
def test_all_eleven_capture_fields_refuse_missing_or_nonexact_strings(
    name: str, case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    expectation = _expect()
    if case == "missing":
        object.__delattr__(expectation, name)
    else:
        value = _Poison() if case == "poison" else (1 if case == "integer" else _String("value"))
        object.__setattr__(expectation, name, value)
    _check(_call(expectation=expectation), S.CAPTURE_REFUSED)
    boundary.counts(0, 0)


@pytest.mark.parametrize("defect", ("policy", "raw", "root"))
def test_capture_sequence_refuses_before_expectation_field_access(
    defect: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    expectation = _expect()
    original = descriptor.SyntheticEnrollmentExpectation.__getattribute__

    def access(self: Any, name: str) -> Any:
        if self is expectation:
            _deny()
        return original(self, name)

    monkeypatch.setattr(descriptor.SyntheticEnrollmentExpectation, "__getattribute__", access)
    _check(_call(expectation=expectation, **{defect: None}), S.CAPTURE_REFUSED)
    boundary.counts(0, 0)


@pytest.mark.parametrize("root", ("", "relative", "/bad/../root", "/bad/", "/" + "x" * 1024))
def test_exact_root_lexical_refusal_is_delegated_to_real_validator(
    root: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    def validate(*args: Any, **kwargs: Any) -> Any:
        calls.append("validate")
        return inputs.validate_disabled_bootstrap_inputs(*args, **kwargs)

    monkeypatch.setattr(adapter, "validate_disabled_bootstrap_inputs", validate)
    monkeypatch.setattr(adapter, "inspect_synthetic_enrollment_preparation", _deny)
    result = _check(_call(root=root), S.VALIDATION_REFUSED)
    assert result.input_result.state is B.INPUTS_UNVERIFIABLE
    assert calls == ["validate"]


@pytest.mark.parametrize("state", tuple(B), ids=lambda value: value.name)
def test_each_validator_state_has_exact_gating_and_one_call(
    state: B, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = inputs.DisabledBootstrapInputResult(state)
    boundary = _Boundaries(monkeypatch, validated=original)
    matched = state is B.INPUTS_MATCHED_UNAPPROVED
    result = _check(_call(), S.INSPECTION_OBSERVED if matched else S.VALIDATION_REFUSED)
    assert result.input_result == original and result.input_result is not original
    assert result.inspection_result is None if not matched else result.inspection_result is not None
    boundary.counts(1, int(matched))


@pytest.mark.parametrize(
    "case,state",
    (
        ("policy", B.POLICY_UNVERIFIABLE),
        ("descriptor", B.INPUTS_UNVERIFIABLE),
        ("enabled", B.ENTRY_MODE_REFUSED),
        ("mismatch", B.INPUTS_MISMATCH),
        ("active", B.STATE_OUT_OF_SCOPE),
        ("matched", B.INPUTS_MATCHED_UNAPPROVED),
    ),
)
def test_real_validator_six_classifications_control_the_handoff(
    case: str, state: B, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = RAW.replace(b"PREPARING", b"ACTIVE") if case == "active" else RAW
    expectation = _expect(raw)
    policy = _policy(expected=expectation)
    if case == "policy":
        policy = b"{}\n"
    elif case == "descriptor":
        raw = b"{}\n"
    elif case == "enabled":
        policy = _wire(json.loads(policy) | {"entry_mode": "enabled"})
    elif case == "mismatch":
        policy = _policy("/different-synthetic-root", expectation)
    calls: list[str] = []
    retained: list[Any] = []
    internal: list[Any] = []

    def validate(*args: Any, **kwargs: Any) -> Any:
        calls.append("validate")
        retained.append(args[2])
        return inputs.validate_disabled_bootstrap_inputs(*args, **kwargs)

    def compare(raw: Any, expected: Any) -> Any:
        internal.append(expected)
        return descriptor.validate_enrollment_descriptor(raw, expected)

    def observe(root: Any, raw: Any, expected: Any) -> Any:
        calls.append("inspect")
        assert expected is retained[0]
        return _observation("pending")

    monkeypatch.setattr(adapter, "validate_disabled_bootstrap_inputs", validate)
    monkeypatch.setattr(inputs, "validate_enrollment_descriptor", compare)
    monkeypatch.setattr(adapter, "inspect_synthetic_enrollment_preparation", observe)
    matched = state is B.INPUTS_MATCHED_UNAPPROVED
    result = _check(
        _call(policy=policy, raw=raw, expectation=expectation),
        S.INSPECTION_OBSERVED if matched else S.VALIDATION_REFUSED,
    )
    assert result.input_result.state is state
    assert calls == (["validate", "inspect"] if matched else ["validate"])
    assert retained[0] is not expectation
    if internal:
        assert internal[0] == retained[0] and internal[0] is not retained[0]


@pytest.mark.parametrize(
    "case",
    (
        "exception",
        "none",
        "poison",
        "dict",
        "namespace",
        "subclass",
        "missing-state",
        "missing-flag",
        "state-text",
        "unknown-enum",
        "state-poison",
        "true",
        "zero",
        "flag-poison",
    ),
)
def test_validator_return_is_checked_before_inspection(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class ResultSubclass(inputs.DisabledBootstrapInputResult):
        pass

    value: Any = inputs.DisabledBootstrapInputResult(B.INPUTS_MATCHED_UNAPPROVED)
    if case == "exception":
        value = RuntimeError("SYNTHETIC_VALIDATOR_EXCEPTION")
    elif case == "none":
        value = None
    elif case == "poison":
        value = _Poison()
    elif case == "dict":
        value = {"state": B.INPUTS_MATCHED_UNAPPROVED, "reuse_authorized": False}
    elif case == "namespace":
        value = SimpleNamespace(state=B.INPUTS_MATCHED_UNAPPROVED, reuse_authorized=False)
    elif case == "subclass":
        value = object.__new__(ResultSubclass)
    elif case.startswith("missing-"):
        object.__delattr__(value, "state" if case == "missing-state" else "reuse_authorized")
    else:
        name, replacement = {
            "state-text": ("state", "INPUTS_MATCHED_UNAPPROVED"),
            "unknown-enum": ("state", _UnknownState.MATCHED),
            "state-poison": ("state", _Poison()),
            "true": ("reuse_authorized", True),
            "zero": ("reuse_authorized", 0),
            "flag-poison": ("reuse_authorized", _Poison()),
        }[case]
        object.__setattr__(value, name, replacement)
    boundary = _Boundaries(monkeypatch, validated=value)
    result = _check(_call(), S.VALIDATION_UNVERIFIABLE)
    assert result.input_result is None and result.inspection_result is None
    boundary.counts(1, 0)


def test_forged_exact_input_enum_is_not_a_known_validator_classification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = inputs.DisabledBootstrapInputResult(B.INPUTS_MATCHED_UNAPPROVED)
    object.__setattr__(original, "state", _forged_member(B))
    boundary = _Boundaries(monkeypatch, validated=original)
    _check(_call(), S.VALIDATION_UNVERIFIABLE)
    boundary.counts(1, 0)
    with pytest.raises(ValueError, match=r"^Invalid disabled bootstrap inspection result$"):
        adapter.DisabledBootstrapInspectionResult(S.VALIDATION_REFUSED, original)


@pytest.mark.parametrize(
    "case",
    (
        "unsupported",
        "input",
        "preparing",
        "busy",
        "unavailable",
        "empty",
        "pending",
        "descriptor",
        "both",
        "conflict",
        "nonpreparing",
        "changed",
        "failed-conflict",
        "failed-read",
    ),
)
def test_complete_nested_observation_is_copied_without_erasing_negative_facts(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = _observation(case)
    boundary = _Boundaries(monkeypatch, observed=original)
    result = _check(_call(), S.INSPECTION_OBSERVED)
    copied = result.inspection_result
    assert copied == original and copied is not original
    assert copied.pending is not original.pending and copied.descriptor is not original.descriptor
    assert tuple(getattr(copied, name) for name in OBSERVATION_FIELDS) == tuple(
        getattr(original, name) for name in OBSERVATION_FIELDS
    )
    boundary.counts(1, 1)


@pytest.mark.parametrize(
    "case", ("exception", "none", "poison", "dict", "namespace", "subclass", "true", "zero")
)
def test_inspection_call_failure_and_invalid_return_are_distinct(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class InspectionSubclass(prep.PreparationInspection):
        pass

    value: Any = _observation("pending")
    if case == "exception":
        value = RuntimeError("SYNTHETIC_INSPECTION_EXCEPTION")
    elif case == "none":
        value = None
    elif case == "poison":
        value = _Poison()
    elif case == "dict":
        value = {"state": IS.ADMIN_PENDING}
    elif case == "namespace":
        value = SimpleNamespace(state=IS.ADMIN_PENDING, reuse_authorized=False)
    elif case == "subclass":
        value = object.__new__(InspectionSubclass)
    else:
        object.__setattr__(value, "reuse_authorized", True if case == "true" else 0)
    boundary = _Boundaries(monkeypatch, observed=value)
    state = S.INSPECTION_FAILED if case == "exception" else S.INSPECTION_RESULT_UNVERIFIABLE
    result = _check(_call(), state)
    assert result.input_result.state is B.INPUTS_MATCHED_UNAPPROVED
    assert result.inspection_result is None
    boundary.counts(1, 1)


@pytest.mark.parametrize("name", OBSERVATION_FIELDS)
@pytest.mark.parametrize("defect", ("missing", "poison"))
def test_all_nine_inspection_fields_are_revalidated(
    name: str, defect: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = _observation("both")
    if defect == "missing":
        object.__delattr__(value, name)
    else:
        object.__setattr__(value, name, _Poison())
    boundary = _Boundaries(monkeypatch, observed=value)
    _check(_call(), S.INSPECTION_RESULT_UNVERIFIABLE)
    boundary.counts(1, 1)


@pytest.mark.parametrize(
    "field",
    (
        "state",
        "target_relation",
        "first_failure",
        "pending.presence",
        "pending.content",
        "pending.target",
        "descriptor.presence",
        "descriptor.content",
        "descriptor.target",
    ),
)
def test_forged_exact_observation_enums_are_not_known_members(
    field: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed = _observation("conflict")
    if "." in field:
        leaf_name, name = field.split(".")
        target = getattr(observed, leaf_name)
    else:
        target, name = observed, field
    object.__setattr__(target, name, _forged_member(type(getattr(target, name))))
    boundary = _Boundaries(monkeypatch, observed=observed)
    _check(_call(), S.INSPECTION_RESULT_UNVERIFIABLE)
    boundary.counts(1, 1)
    with pytest.raises(ValueError, match=r"^Invalid disabled bootstrap inspection result$"):
        adapter.DisabledBootstrapInspectionResult(
            S.INSPECTION_OBSERVED,
            inputs.DisabledBootstrapInputResult(B.INPUTS_MATCHED_UNAPPROVED),
            observed,
        )


@pytest.mark.parametrize("location", ("input", "observation", "leaf", "outer"))
def test_enum_spelling_equality_cannot_replace_actual_member_identity(
    location: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    validated = inputs.DisabledBootstrapInputResult(B.INPUTS_MATCHED_UNAPPROVED)
    observed = _observation("pending")
    if location == "outer":
        with pytest.raises(ValueError, match=r"^Invalid disabled bootstrap inspection result$"):
            adapter.DisabledBootstrapInspectionResult(
                _counterfeit_member(S.INSPECTION_OBSERVED), validated, observed
            )
        return
    if location == "input":
        target, name = validated, "state"
    elif location == "observation":
        target, name = observed, "state"
    else:
        target, name = observed.pending, "presence"
    original = getattr(target, name)
    forged = _counterfeit_member(original)
    assert forged == original and forged is not original and type(forged) is type(original)
    object.__setattr__(target, name, forged)
    boundary = _Boundaries(monkeypatch, validated=validated, observed=observed)
    _check(
        _call(),
        S.VALIDATION_UNVERIFIABLE if location == "input" else S.INSPECTION_RESULT_UNVERIFIABLE,
    )
    boundary.counts(1, 0 if location == "input" else 1)


@pytest.mark.parametrize("leaf_name", ("pending", "descriptor"))
@pytest.mark.parametrize("name", LEAF_FIELDS)
@pytest.mark.parametrize("defect", ("missing", "poison"))
def test_both_leaves_require_all_four_exact_fields(
    leaf_name: str, name: str, defect: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = _observation("both")
    leaf = replace(getattr(value, leaf_name))
    object.__setattr__(value, leaf_name, leaf)
    if defect == "missing":
        object.__delattr__(leaf, name)
    else:
        object.__setattr__(leaf, name, _Poison())
    boundary = _Boundaries(monkeypatch, observed=value)
    _check(_call(), S.INSPECTION_RESULT_UNVERIFIABLE)
    boundary.counts(1, 1)


@pytest.mark.parametrize(
    "case",
    (
        "leaf-subclass",
        "leaf-absent-content",
        "leaf-changed-integer",
        "wrong-summary",
        "complete-failure",
        "relation-text",
        "state-text",
        "exit-without-failure",
        "nonpreparing-with-match",
    ),
)
def test_existing_constructors_reject_forged_observation_combinations(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class LeafSubclass(prep.LeafObservation):
        pass

    value = _observation("both")
    if case.startswith("leaf-"):
        leaf = replace(value.pending)
        if case == "leaf-subclass":
            leaf = object.__new__(LeafSubclass)
        else:
            object.__setattr__(
                leaf,
                "presence" if case == "leaf-absent-content" else "changed",
                P.ABSENT if case == "leaf-absent-content" else 1,
            )
        object.__setattr__(value, "pending", leaf)
    else:
        name, replacement = {
            "wrong-summary": ("state", IS.ADMIN_PENDING),
            "complete-failure": ("first_failure", F.ROOT_CHECK),
            "relation-text": ("target_relation", "MATCH"),
            "state-text": ("state", "PREPARATION_RETAINED_UNAPPROVED"),
            "exit-without-failure": ("exit_failure_observed", True),
            "nonpreparing-with-match": ("non_preparing_observed", True),
        }[case]
        object.__setattr__(value, name, replacement)
    boundary = _Boundaries(monkeypatch, observed=value)
    _check(_call(), S.INSPECTION_RESULT_UNVERIFIABLE)
    boundary.counts(1, 1)


def test_capture_reads_original_once_and_retained_identity_survives_caller_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    caller = {"policy": _policy(), "raw": RAW, "root": ROOT, "expectation": _expect()}
    original = caller["expectation"]
    held = dict(caller)
    reads: list[str] = []
    observed: list[tuple[Any, ...]] = []
    original_access = descriptor.SyntheticEnrollmentExpectation.__getattribute__

    def access(self: Any, name: str) -> Any:
        if self is original:
            reads.append(name)
        return original_access(self, name)

    def validate(policy: Any, raw: Any, expectation: Any, *, expected_control_root: Any) -> Any:
        assert policy is held["policy"] and raw is held["raw"]
        assert expected_control_root is held["root"] and expectation is not original
        observed.append((policy, raw, expectation, expected_control_root))
        object.__setattr__(original, "storage_ref", "changed-caller-store")
        caller.update(policy=b"changed", raw=b"changed", root="/changed", expectation=None)
        return inputs.DisabledBootstrapInputResult(B.INPUTS_MATCHED_UNAPPROVED)

    def inspect_retained(control_root: Any, raw: Any, expectation: Any) -> Any:
        assert control_root is observed[0][3] and raw is observed[0][1]
        assert expectation is observed[0][2] and expectation.storage_ref == "store-one"
        observed.append((control_root, raw, expectation))
        return _observation("pending")

    monkeypatch.setattr(descriptor.SyntheticEnrollmentExpectation, "__getattribute__", access)
    monkeypatch.setattr(adapter, "validate_disabled_bootstrap_inputs", validate)
    monkeypatch.setattr(adapter, "inspect_synthetic_enrollment_preparation", inspect_retained)
    result = _check(_call(**caller), S.INSPECTION_OBSERVED)
    assert result.inspection_result.state is IS.ADMIN_PENDING
    assert reads == list(EXPECTATION_FIELDS) and len(observed) == 2


def test_dependency_original_fields_are_captured_once_before_safe_reconstruction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validated = inputs.DisabledBootstrapInputResult(B.INPUTS_MATCHED_UNAPPROVED)
    observed = _observation("conflict")
    counts: dict[str, list[str]] = {"input": [], "inspection": [], "pending": [], "descriptor": []}
    original_input = inputs.DisabledBootstrapInputResult.__getattribute__
    original_inspection = prep.PreparationInspection.__getattribute__
    original_leaf = prep.LeafObservation.__getattribute__
    pending, final = observed.pending, observed.descriptor

    def input_access(self: Any, name: str) -> Any:
        if self is validated and name in ("state", "reuse_authorized"):
            counts["input"].append(name)
        return original_input(self, name)

    def inspection_access(self: Any, name: str) -> Any:
        if self is observed and name in OBSERVATION_FIELDS:
            counts["inspection"].append(name)
        return original_inspection(self, name)

    def leaf_access(self: Any, name: str) -> Any:
        if name in LEAF_FIELDS:
            if self is pending:
                counts["pending"].append(name)
            elif self is final:
                counts["descriptor"].append(name)
        return original_leaf(self, name)

    boundary = _Boundaries(monkeypatch, validated=validated, observed=observed)
    monkeypatch.setattr(inputs.DisabledBootstrapInputResult, "__getattribute__", input_access)
    monkeypatch.setattr(prep.PreparationInspection, "__getattribute__", inspection_access)
    monkeypatch.setattr(prep.LeafObservation, "__getattribute__", leaf_access)
    _check(_call(), S.INSPECTION_OBSERVED)
    assert sorted(counts["input"]) == ["reuse_authorized", "state"]
    assert sorted(counts["inspection"]) == sorted(OBSERVATION_FIELDS)
    assert sorted(counts["pending"]) == sorted(LEAF_FIELDS)
    assert sorted(counts["descriptor"]) == sorted(LEAF_FIELDS)
    boundary.counts(1, 1)


def _outer_values(state: S) -> tuple[Any, Any]:
    if state in {S.CAPTURE_REFUSED, S.VALIDATION_UNVERIFIABLE}:
        return None, None
    if state is S.VALIDATION_REFUSED:
        return inputs.DisabledBootstrapInputResult(B.ENTRY_MODE_REFUSED), None
    return (
        inputs.DisabledBootstrapInputResult(B.INPUTS_MATCHED_UNAPPROVED),
        _observation("pending") if state is S.INSPECTION_OBSERVED else None,
    )


@pytest.mark.parametrize("state", tuple(S), ids=lambda value: value.name)
def test_all_six_outer_states_have_exact_frozen_nonauthorizing_representation(state: S) -> None:
    checked, observed = _outer_values(state)
    result = _check(adapter.DisabledBootstrapInspectionResult(state, checked, observed), state)
    if checked is not None:
        assert result.input_result == checked and result.input_result is not checked
    if observed is not None:
        assert result.inspection_result == observed and result.inspection_result is not observed
    with pytest.raises(FrozenInstanceError):
        result.reuse_authorized = True
    with pytest.raises(TypeError):
        adapter.DisabledBootstrapInspectionResult(state, checked, observed, reuse_authorized=True)


@pytest.mark.parametrize("state", tuple(S), ids=lambda value: value.name)
@pytest.mark.parametrize(
    "case", ("extra-inspection", "bad-input", "matched-without-state", "missing-input")
)
def test_outer_constructor_rejects_inconsistent_table_combinations(state: S, case: str) -> None:
    checked, observed = _outer_values(state)
    if case == "extra-inspection":
        observed = None if state is S.INSPECTION_OBSERVED else _observation("pending")
    elif case == "bad-input":
        checked = _Poison()
    elif case == "matched-without-state":
        checked = inputs.DisabledBootstrapInputResult(
            B.INPUTS_MATCHED_UNAPPROVED
            if state in {S.CAPTURE_REFUSED, S.VALIDATION_UNVERIFIABLE, S.VALIDATION_REFUSED}
            else B.ENTRY_MODE_REFUSED
        )
    elif state in {S.CAPTURE_REFUSED, S.VALIDATION_UNVERIFIABLE}:
        checked = inputs.DisabledBootstrapInputResult(B.ENTRY_MODE_REFUSED)
    else:
        checked = None
    with pytest.raises(ValueError, match=r"^Invalid disabled bootstrap inspection result$"):
        adapter.DisabledBootstrapInspectionResult(state, checked, observed)


@pytest.mark.parametrize(
    "case",
    (
        "state-text",
        "state-poison",
        "input-true",
        "input-zero",
        "input-state",
        "leaf-field",
        "observation-true",
        "observation-summary",
    ),
)
def test_normal_outer_constructor_rechecks_forged_nested_exact_objects(case: str) -> None:
    state: Any = S.INSPECTION_OBSERVED
    checked, observed = _outer_values(state)
    if case == "state-text":
        state = "INSPECTION_OBSERVED"
    elif case == "state-poison":
        state = _Poison()
    elif case.startswith("input-"):
        field, value = {
            "input-true": ("reuse_authorized", True),
            "input-zero": ("reuse_authorized", 0),
            "input-state": ("state", "INPUTS_MATCHED_UNAPPROVED"),
        }[case]
        object.__setattr__(checked, field, value)
    elif case == "leaf-field":
        object.__setattr__(observed.pending, "presence", "PRESENT")
    else:
        object.__setattr__(
            observed,
            "reuse_authorized" if case == "observation-true" else "state",
            True if case == "observation-true" else IS.ABSENCE_UNVERIFIABLE,
        )
    with pytest.raises(ValueError, match=r"^Invalid disabled bootstrap inspection result$"):
        adapter.DisabledBootstrapInspectionResult(state, checked, observed)


def test_outer_enum_must_be_an_actual_member_and_fixed_error_has_no_public_override() -> None:
    with pytest.raises(ValueError, match=r"^Invalid disabled bootstrap inspection result$"):
        adapter.DisabledBootstrapInspectionResult(_forged_member(S))
    error = adapter.DisabledBootstrapInspectionResultError()
    assert error.input_result is None and error.inspection_result is None
    assert error.reuse_authorized is False and error.__cause__ is None and error.__context__ is None
    for name in ("input_result", "inspection_result", "reuse_authorized"):
        with pytest.raises(AttributeError):
            setattr(error, name, True)
    with pytest.raises(TypeError):
        adapter.DisabledBootstrapInspectionResultError("SYNTHETIC_MESSAGE_OVERRIDE")


@pytest.mark.parametrize("caller_state", ("ordinary", "except", "finally"))
@pytest.mark.parametrize("observation", ("pending", "failed-conflict"))
def test_fixed_construction_failure_preserves_negative_diagnostics_and_clears_links(
    caller_state: str, observation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    validated = inputs.DisabledBootstrapInputResult(B.INPUTS_MATCHED_UNAPPROVED)
    observed = _observation(observation)
    boundary = _Boundaries(monkeypatch, validated=validated, observed=observed)
    original = RuntimeError("SYNTHETIC_ORIGINAL_CONSTRUCTOR_CANARY")
    original.add_note("SYNTHETIC_ORIGINAL_NOTE_CANARY")
    caller = ValueError("SYNTHETIC_CALLER_EXCEPTION_CANARY")
    caller.add_note("SYNTHETIC_CALLER_NOTE_CANARY")
    caller.__cause__ = LookupError("SYNTHETIC_CALLER_CAUSE_CANARY")
    before = (caller.args, caller.__cause__, caller.__context__, tuple(caller.__notes__))

    def fail(self: Any) -> None:
        raise original

    monkeypatch.setattr(adapter.DisabledBootstrapInspectionResult, "__post_init__", fail)
    with pytest.raises(adapter.DisabledBootstrapInspectionResultError) as caught:
        if caller_state == "ordinary":
            _call()
        elif caller_state == "except":
            try:
                raise caller
            except ValueError:
                _call()
        else:
            try:
                raise caller
            finally:
                _call()
    error = caught.value
    message = "Disabled bootstrap inspection result construction failed"
    assert error.args == (message,) and str(error) == message
    assert repr(error) == f"DisabledBootstrapInspectionResultError({message!r})"
    assert error.__cause__ is None and error.__context__ is None
    assert not hasattr(error, "__notes__")
    assert error.reuse_authorized is False
    assert error.input_result == validated and error.input_result is not validated
    assert error.inspection_result == observed and error.inspection_result is not observed
    assert (caller.args, caller.__cause__, caller.__context__, tuple(caller.__notes__)) == before
    assert original.args == ("SYNTHETIC_ORIGINAL_CONSTRUCTOR_CANARY",)
    assert original.__notes__ == ["SYNTHETIC_ORIGINAL_NOTE_CANARY"]
    assert set(vars(error)) <= {"_input_result", "_inspection_result"}
    assert "CANARY" not in repr(vars(error))
    boundary.counts(1, 1)


@pytest.mark.parametrize(
    "cancel_type", (KeyboardInterrupt, SystemExit), ids=lambda value: value.__name__
)
@pytest.mark.parametrize(
    "phase",
    (
        "capture",
        "expectation-copy",
        "validator",
        "validator-result",
        "inspection",
        "inspection-result",
        "leaf-result",
        "outer-result",
    ),
)
def test_cancellation_at_each_phase_propagates_original_unmodified(
    phase: str, cancel_type: type[BaseException], monkeypatch: pytest.MonkeyPatch
) -> None:
    expectation = _expect()
    policy = _policy()
    validated = inputs.DisabledBootstrapInputResult(B.INPUTS_MATCHED_UNAPPROVED)
    observed = _observation("pending")
    boundary = _Boundaries(monkeypatch, validated=validated, observed=observed)
    cancel = cancel_type("SYNTHETIC_CANCEL")
    cancel.add_note("SYNTHETIC_CANCEL_NOTE")

    def cancelled(*args: Any, **kwargs: Any) -> Any:
        raise cancel

    if phase in {"capture", "validator-result", "inspection-result", "leaf-result"}:
        target = {
            "capture": expectation,
            "validator-result": validated,
            "inspection-result": observed,
            "leaf-result": observed.pending,
        }[phase]
        cls = type(target)
        original = cls.__getattribute__

        def access(self: Any, name: str) -> Any:
            if self is target and name != "__class__":
                raise cancel
            return original(self, name)

        monkeypatch.setattr(cls, "__getattribute__", access)
    elif phase == "expectation-copy":
        monkeypatch.setattr(descriptor.SyntheticEnrollmentExpectation, "__init__", cancelled)
    elif phase == "validator":
        boundary.validated = cancel
    elif phase == "inspection":
        boundary.observed = cancel
    else:
        monkeypatch.setattr(adapter.DisabledBootstrapInspectionResult, "__post_init__", cancelled)
    with pytest.raises(cancel_type) as caught:
        _call(policy=policy, expectation=expectation)
    assert caught.value is cancel and cancel.args == ("SYNTHETIC_CANCEL",)
    assert cancel.__notes__ == ["SYNTHETIC_CANCEL_NOTE"] and cancel.__cause__ is None
    counts = (
        (0, 0)
        if phase in {"capture", "expectation-copy"}
        else ((1, 0) if phase in {"validator", "validator-result"} else (1, 1))
    )
    boundary.counts(*counts)


def test_public_payload_and_streams_never_contain_input_or_exception_canaries(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    boundary = _Boundaries(monkeypatch, observed=RuntimeError("SYNTHETIC_EXCEPTION_CANARY"))
    result = _check(
        _call(
            policy=b"SYNTHETIC_POLICY_CANARY",
            raw=b"SYNTHETIC_RAW_CANARY",
            root="SYNTHETIC_ROOT_CANARY",
        ),
        S.INSPECTION_FAILED,
    )
    assert "CANARY" not in repr(result) and "CANARY" not in str(result)
    captured = capsys.readouterr()
    assert captured.out == "" and captured.err == ""
    boundary.counts(1, 1)


def test_persistent_outer_revalidation_failure_does_not_repeat_check_or_drop_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observation = _observation("failed-conflict")
    boundary = _Boundaries(monkeypatch, observed=observation)
    original = adapter._copy_inspection_result
    checked: list[prep.PreparationInspection] = []
    calls = 0

    def copy_once(value: object) -> prep.PreparationInspection:
        nonlocal calls
        calls += 1
        if calls > 1:
            raise RuntimeError("SYNTHETIC_PERSISTENT_CONSTRUCTION_CANARY")
        result = original(value)
        checked.append(result)
        return result

    monkeypatch.setattr(adapter, "_copy_inspection_result", copy_once)
    with pytest.raises(adapter.DisabledBootstrapInspectionResultError) as caught:
        _call()
    assert calls == 2 and caught.value.inspection_result is checked[0]
    assert caught.value.inspection_result == observation
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    boundary.counts(1, 1)


def test_private_capture_container_hides_every_retained_field_and_has_no_export() -> None:
    captured = adapter._capture_inputs(_policy(), RAW, _expect(), ROOT)
    assert tuple(item.name for item in fields(captured)) == (
        "policy_raw",
        "expected_raw",
        "expectation",
        "expected_control_root",
    )
    assert all(not item.repr for item in fields(captured))
    assert repr(captured) == "_CapturedInputs()" and not hasattr(captured, "__dict__")
    with pytest.raises(FrozenInstanceError):
        captured.policy_raw = b"changed"
    assert not hasattr(adapter, "snapshot") and not hasattr(adapter, "export_snapshot")


_APPLICATION_IMPORTS = {
    "tridentine_calendar_google_sync.production_write_token_disabled_bootstrap_inputs": {
        "DisabledBootstrapInputState",
        "DisabledBootstrapInputResult",
        "validate_disabled_bootstrap_inputs",
    },
    "tridentine_calendar_google_sync.production_write_token_enrollment_descriptor": {
        "SyntheticEnrollmentExpectation"
    },
    "tridentine_calendar_google_sync.production_write_token_enrollment_preparation": {
        "LeafObservation",
        "PreparationInspection",
        "inspect_synthetic_enrollment_preparation",
    },
}
_LOCAL_FUNCTIONS = {
    "_capture_inputs",
    "_require_false",
    "_require_member",
    "_copy_input_result",
    "_copy_leaf",
    "_copy_inspection_result",
    "_finish",
    "inspect_synthetic_disabled_bootstrap",
}
_LOCAL_CLASSES = {
    "DisabledBootstrapInspectionState",
    "_CapturedInputs",
    "DisabledBootstrapInspectionResult",
    "DisabledBootstrapInspectionResultError",
}
_BUILTIN_CALLS = {"type", "len", "getattr", "any", "ValueError", "super"}


def _check_closed_adapter(source: str) -> set[str]:
    """Accept only this adapter's finite syntax, not general Python dispatch."""
    tree = ast.parse(source)
    definitions = [node.name for node in tree.body if isinstance(node, ast.FunctionDef)]
    classes = [node.name for node in tree.body if isinstance(node, ast.ClassDef)]
    assert len(definitions) == len(_LOCAL_FUNCTIONS) and set(definitions) == _LOCAL_FUNCTIONS
    assert len(classes) == len(_LOCAL_CLASSES) and set(classes) == _LOCAL_CLASSES
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}

    def scope(node: ast.AST) -> tuple[str | None, str | None]:
        function = owner = None
        current = parents.get(node)
        while current is not None:
            if isinstance(current, ast.FunctionDef) and function is None:
                function = current.name
            if isinstance(current, ast.ClassDef):
                owner = current.name
            current = parents.get(current)
        return function, owner

    allowed_imports = _APPLICATION_IMPORTS | {
        "__future__": {"annotations"},
        "dataclasses": {"dataclass", "field"},
        "enum": {"StrEnum"},
        "typing": {"Literal", "cast"},
    }
    observed_imports: dict[str, set[str]] = {}
    imported: set[str] = set()
    for node in ast.walk(tree):
        assert not isinstance(node, ast.Import)
        if isinstance(node, ast.ImportFrom):
            assert isinstance(parents[node], ast.Module)
            assert node.level == 0 and node.module is not None
            assert node.module in allowed_imports and node.module not in observed_imports
            assert all(item.asname is None for item in node.names)
            names = {item.name for item in node.names}
            assert len(names) == len(node.names) and names == allowed_imports[node.module]
            observed_imports[node.module] = names
            imported.update(names)
    assert observed_imports == allowed_imports
    for node in tree.body:
        if isinstance(node, ast.Expr):
            assert isinstance(node.value, ast.Constant) and type(node.value.value) is str
        elif isinstance(node, ast.Assign):
            assert len(node.targets) == 1 and ast.unparse(node.targets[0]) == "_EXPECTATION_FIELDS"
            assert ast.literal_eval(node.value) == EXPECTATION_FIELDS
        else:
            assert isinstance(node, (ast.ImportFrom, ast.FunctionDef, ast.ClassDef))
    protected = (
        imported
        | _LOCAL_FUNCTIONS
        | _LOCAL_CLASSES
        | _BUILTIN_CALLS
        | {"object", "property", "RuntimeError"}
    )
    calls: set[str] = set()
    direct_calls = {
        "validate_disabled_bootstrap_inputs": 0,
        "inspect_synthetic_enrollment_preparation": 0,
    }
    blocked_syntax = (
        ast.AsyncFunctionDef,
        ast.Await,
        ast.Yield,
        ast.YieldFrom,
        ast.Lambda,
        ast.NamedExpr,
        ast.Global,
        ast.Nonlocal,
        ast.With,
        ast.AsyncWith,
        ast.While,
        ast.For,
        ast.AsyncFor,
        ast.Delete,
        ast.AugAssign,
        ast.Match,
        ast.TryStar,
    )
    expected_methods = {
        "DisabledBootstrapInspectionState": set(),
        "_CapturedInputs": set(),
        "DisabledBootstrapInspectionResult": {"__post_init__"},
        "DisabledBootstrapInspectionResultError": {
            "__init__",
            "input_result",
            "inspection_result",
            "reuse_authorized",
        },
    }
    for node in ast.walk(tree):
        assert not isinstance(node, blocked_syntax)
        assert not (
            isinstance(node, ast.Subscript) and isinstance(node.ctx, (ast.Store, ast.Del))
        ), "item mutation is not supported"
        assert not (isinstance(node, ast.Attribute) and node.attr == "__globals__"), (
            "function namespace access is not supported"
        )
        if isinstance(node, ast.ClassDef):
            assert isinstance(parents[node], ast.Module)
            methods = [item.name for item in node.body if isinstance(item, ast.FunctionDef)]
            assert len(methods) == len(expected_methods[node.name])
            assert set(methods) == expected_methods[node.name]
            assert not node.keywords
            bases = {
                "DisabledBootstrapInspectionState": ["StrEnum"],
                "DisabledBootstrapInspectionResultError": ["RuntimeError"],
                "DisabledBootstrapInspectionResult": [],
                "_CapturedInputs": [],
            }
            assert [ast.unparse(base) for base in node.bases] == bases[node.name]
            decorated = node.name in {"DisabledBootstrapInspectionResult", "_CapturedInputs"}
            assert len(node.decorator_list) == int(decorated)
            if decorated:
                assert isinstance(node.decorator_list[0], ast.Call)
                assert ast.unparse(node.decorator_list[0].func) == "dataclass"
        if isinstance(node, ast.FunctionDef):
            assert isinstance(parents[node], (ast.Module, ast.ClassDef))
            method = isinstance(parents[node], ast.ClassDef)
            decorated = method and node.name in {
                "input_result",
                "inspection_result",
                "reuse_authorized",
            }
            assert [ast.unparse(item) for item in node.decorator_list] == (
                ["property"] if decorated else []
            )
            if method:
                assert [item.arg for item in node.args.args] == ["self"]
                assert not node.args.posonlyargs and not node.args.kwonlyargs
                assert (
                    node.args.vararg is None and node.args.kwarg is None and not node.args.defaults
                )
        if isinstance(node, ast.arg):
            assert node.arg not in protected | {"failure", "values", "_EXPECTATION_FIELDS"}
            if node.arg == "self":
                assert scope(node)[1] in _LOCAL_CLASSES
        if isinstance(node, ast.ExceptHandler):
            assert node.name is None
        if isinstance(node, ast.comprehension):
            assert not node.is_async
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            assert node.id not in protected and node.id != "self"
            if node.id == "_EXPECTATION_FIELDS":
                assert isinstance(parents[node], ast.Assign)
                assert isinstance(parents[parents[node]], ast.Module)
            if node.id == "failure":
                assert scope(node) == ("_finish", None)
                statement = parents[node]
                assert isinstance(statement, ast.Assign) and len(statement.targets) == 1
                assert isinstance(statement.value, ast.Call)
                assert isinstance(statement.value.func, ast.Name)
                assert statement.value.func.id == "DisabledBootstrapInspectionResultError"
                assert not statement.value.args and not statement.value.keywords
            if node.id == "values":
                assert scope(node) == ("_capture_inputs", None)
                statement = parents[node]
                assert isinstance(statement, ast.AnnAssign)
                assert isinstance(statement.value, ast.DictComp)
                assert len(statement.value.generators) == 1
                assert ast.unparse(statement.value.generators[0].iter) == "_EXPECTATION_FIELDS"
                assert ast.unparse(statement.value.key) == "name"
                assert ast.unparse(statement.value.value) == "getattr(expectation, name)"
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store):
            assert isinstance(node.value, ast.Name)
            statement = parents[node]
            if node.value.id == "self":
                assert scope(node) == ("__init__", "DisabledBootstrapInspectionResultError")
                assert node.attr in {"_input_result", "_inspection_result"}
                assert isinstance(statement, ast.AnnAssign)
                assert isinstance(statement.value, ast.Constant) and statement.value.value is None
            else:
                assert node.value.id == "failure" and scope(node) == ("_finish", None)
                assert isinstance(statement, ast.Assign) and len(statement.targets) == 1
                if node.attr in {"_input_result", "_inspection_result"}:
                    assert ast.unparse(statement.value) == node.attr.removeprefix("_")
                else:
                    assert node.attr in {"__cause__", "__context__"}
                    assert (
                        isinstance(statement.value, ast.Constant) and statement.value.value is None
                    )
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                name = node.func.id
                assert name in protected and name not in {
                    "object",
                    "Literal",
                    "StrEnum",
                    "annotations",
                    "property",
                    "RuntimeError",
                    "DisabledBootstrapInputState",
                    "DisabledBootstrapInspectionState",
                }
                calls.add(name)
                if name in direct_calls:
                    assert scope(node) == ("inspect_synthetic_disabled_bootstrap", None)
                    direct_calls[name] += 1
                if name == "type":
                    assert len(node.args) == 1 and not node.keywords
                if name == "dataclass":
                    assert isinstance(parents[node], ast.ClassDef) and not node.args
                    assert len(node.keywords) == 2
                    assert {item.arg for item in node.keywords} == {"frozen", "slots"}
                    assert all(
                        isinstance(item.value, ast.Constant) and item.value.value is True
                        for item in node.keywords
                    )
                if name == "field":
                    assert isinstance(parents[node], ast.AnnAssign) and not node.args
                    assert isinstance(parents[parents[node]], ast.ClassDef)
                    assert all(
                        isinstance(item.value, ast.Constant) and type(item.value.value) is bool
                        for item in node.keywords
                    )
                    keywords = {item.arg: item.value.value for item in node.keywords}
                    assert len(keywords) == len(node.keywords)
                    owner = scope(node)[1]
                    if owner == "_CapturedInputs":
                        assert keywords == {"repr": False}
                    else:
                        assert owner == "DisabledBootstrapInspectionResult"
                        assert ast.unparse(parents[node].target) == "reuse_authorized"
                        assert keywords == {"default": False, "init": False}
                if name == "getattr":
                    assert not node.keywords and len(node.args) == 2
                    assert ast.unparse(node.args[0]) == "expectation"
                    assert ast.unparse(node.args[1]) == "name"
                    comprehension = parents[node]
                    assert isinstance(comprehension, ast.DictComp)
                    assert comprehension.value is node and len(comprehension.generators) == 1
                    assert ast.unparse(comprehension.generators[0].iter) == "_EXPECTATION_FIELDS"
                    assert ast.unparse(comprehension.generators[0].target) == "name"
                if name == "super":
                    assert not node.args and not node.keywords
                    assert scope(node) == ("__init__", "DisabledBootstrapInspectionResultError")
                continue
            assert isinstance(node.func, ast.Attribute)
            receiver, method = node.func.value, node.func.attr
            if isinstance(receiver, ast.Name) and receiver.id == "object":
                assert scope(node) == ("__post_init__", "DisabledBootstrapInspectionResult")
                assert method == "__setattr__" and len(node.args) == 3 and not node.keywords
                assert ast.unparse(node.args[0]) == "self"
                assert isinstance(node.args[1], ast.Constant)
                assert node.args[1].value in {"input_result", "inspection_result"}
            elif isinstance(receiver, ast.Name) and receiver.id == "values":
                assert scope(node) == ("_capture_inputs", None)
                assert method in {"items", "values"} and not node.args and not node.keywords
            else:
                assert isinstance(receiver, ast.Call) and ast.unparse(receiver) == "super()"
                assert method == "__init__" and len(node.args) == 1 and not node.keywords
                assert isinstance(node.args[0], ast.Constant)
                assert (
                    node.args[0].value == "Disabled bootstrap inspection result construction failed"
                )
    constants = [
        node
        for node in tree.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "_EXPECTATION_FIELDS"
            for target in node.targets
        )
    ]
    assert len(constants) == 1 and ast.literal_eval(constants[0].value) == EXPECTATION_FIELDS
    assert direct_calls == {
        "validate_disabled_bootstrap_inputs": 1,
        "inspect_synthetic_enrollment_preparation": 1,
    }
    assert _LOCAL_FUNCTIONS - {"inspect_synthetic_disabled_bootstrap"} <= calls
    assert {
        "DisabledBootstrapInspectionResult",
        "DisabledBootstrapInspectionResultError",
        "_CapturedInputs",
    } <= calls
    return calls


def test_closed_adapter_calls_cover_helpers_constructors_and_no_external_consumer() -> None:
    source = Path(adapter.__file__)
    calls = _check_closed_adapter(source.read_text(encoding="utf-8"))
    assert calls & {
        "validate_disabled_bootstrap_inputs",
        "inspect_synthetic_enrollment_preparation",
    } == {"validate_disabled_bootstrap_inputs", "inspect_synthetic_enrollment_preparation"}
    assert {
        other.relative_to(source.parent).as_posix()
        for other in source.parent.rglob("*.py")
        if other != source and source.stem in other.read_text(encoding="utf-8")
    } == {"production_write_token_disabled_bootstrap_source_loading.py"}


@pytest.mark.parametrize(
    "injection",
    (
        "alias = validate_disabled_bootstrap_inputs\nalias()",
        "validate_disabled_bootstrap_inputs = _finish",
        "validate_disabled_bootstrap_inputs: object = _finish",
        "validate_disabled_bootstrap_inputs, safe = (_finish, None)",
        "for validate_disabled_bootstrap_inputs in []:\n    pass",
        "[None for validate_disabled_bootstrap_inputs in []]",
        "{name: None for name, validate_disabled_bootstrap_inputs in []}",
        "(validate_disabled_bootstrap_inputs := _finish)",
        "validate_disabled_bootstrap_inputs.__call__()",
        "getattr(_finish, '__call__')()",
        "(lambda: _finish())()",
        "values = expected_raw\nvalues.values()",
        "object.__setattr__(expectation, 'storage_ref', 'changed')",
        "object.__setattr__(self, 'reuse_authorized', True)",
        "failure = expectation",
        "self = expectation",
        "name = '__repr__'\ngetattr(expectation, name)",
    ),
    ids=(
        "alias",
        "assignment",
        "annotation",
        "tuple-binding",
        "loop-binding",
        "list-binding",
        "dict-binding",
        "walrus",
        "attribute-dispatch",
        "getattr-dispatch",
        "lambda-dispatch",
        "receiver-rebinding",
        "input-mutation",
        "authorization-mutation",
        "exception-rebinding",
        "self-rebinding",
        "dynamic-field",
    ),
)
def test_closed_checker_rejects_alias_binding_and_unsupported_dispatch(injection: str) -> None:
    source = Path(adapter.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    target = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_finish"
    )
    target.body[0:0] = ast.parse(injection).body
    with pytest.raises(AssertionError):
        _check_closed_adapter(ast.unparse(tree))


@pytest.mark.parametrize("case", ("parameter", "import-alias", "constructor-hook", "helper-call"))
def test_closed_checker_rejects_shadowed_or_added_runtime_entry(case: str) -> None:
    tree = ast.parse(Path(adapter.__file__).read_text(encoding="utf-8"))
    if case == "parameter":
        target = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_finish"
        )
        target.args.args[0].arg = "validate_disabled_bootstrap_inputs"
    elif case == "import-alias":
        target = next(
            node
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module == "dataclasses"
        )
        target.names[0].asname = "replacement"
    elif case == "constructor-hook":
        target = next(
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == "_CapturedInputs"
        )
        target.body.extend(ast.parse("def __post_init__(self):\n    writer()").body)
    else:
        target = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_copy_leaf"
        )
        target.body.insert(0, ast.Expr(ast.Call(ast.Name("writer", ast.Load()), [], [])))
    with pytest.raises(AssertionError):
        _check_closed_adapter(ast.unparse(ast.fix_missing_locations(tree)))


@pytest.mark.parametrize(
    "case",
    (
        "duplicate-import",
        "nested-import",
        "forbidden-import-hidden-by-approved",
        "duplicate-function",
        "duplicate-class",
        "duplicate-method",
        "field-factory",
        "failure-parameter",
        "values-parameter",
        "self-parameter",
        "property-binding",
        "runtime-error-binding",
        "foreign-payload-store",
        "foreign-result-mutation",
        "type-three-arguments",
        "helper-dependency-call",
        "second-dependency-call",
        "method-decorator",
        "error-base",
    ),
)
def test_closed_checker_rejects_duplicate_bindings_factories_and_cross_scope_effects(
    case: str,
) -> None:
    tree = ast.parse(Path(adapter.__file__).read_text(encoding="utf-8"))
    finish = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "_finish"
    )
    capture = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "_CapturedInputs"
    )
    error = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "DisabledBootstrapInspectionResultError"
    )
    if case in {"duplicate-import", "nested-import", "forbidden-import-hidden-by-approved"}:
        names = (
            "prepare_synthetic_enrollment"
            if case == "forbidden-import-hidden-by-approved"
            else "LeafObservation, PreparationInspection, inspect_synthetic_enrollment_preparation"
        )
        imported = ast.parse(
            "from tridentine_calendar_google_sync.production_write_token_enrollment_preparation "
            f"import {names}"
        ).body[0]
        (finish.body if case == "nested-import" else tree.body).insert(0, imported)
    elif case == "duplicate-function":
        tree.body.append(ast.parse("def _finish():\n    pass").body[0])
    elif case == "duplicate-class":
        tree.body.append(ast.parse("class _CapturedInputs:\n    pass").body[0])
    elif case == "duplicate-method":
        error.body.append(ast.parse("def __init__(self):\n    pass").body[0])
    elif case == "field-factory":
        field_call = next(
            node
            for node in ast.walk(capture)
            if isinstance(node, ast.Call) and ast.unparse(node.func) == "field"
        )
        field_call.keywords.append(ast.keyword("default_factory", ast.Name("_finish", ast.Load())))
    elif case.endswith("-parameter"):
        finish.args.args[0].arg = case.removesuffix("-parameter")
    elif case in {"property-binding", "runtime-error-binding"}:
        name = "property" if case == "property-binding" else "RuntimeError"
        finish.body.insert(0, ast.parse(f"{name} = _finish").body[0])
    elif case in {
        "foreign-payload-store",
        "foreign-result-mutation",
        "type-three-arguments",
        "helper-dependency-call",
    }:
        target = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_copy_input_result"
        )
        statement = {
            "foreign-payload-store": "failure._input_result = input_result",
            "foreign-result-mutation": "object.__setattr__(self, 'input_result', checked_input)",
            "type-three-arguments": "type('synthetic', (), {})",
            "helper-dependency-call": "validate_disabled_bootstrap_inputs()",
        }[case]
        target.body.insert(0, ast.parse(statement).body[0])
    elif case == "second-dependency-call":
        target = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "inspect_synthetic_disabled_bootstrap"
        )
        target.body.append(ast.parse("inspect_synthetic_enrollment_preparation()").body[0])
    elif case == "method-decorator":
        method = next(
            node
            for node in error.body
            if isinstance(node, ast.FunctionDef) and node.name == "__init__"
        )
        method.decorator_list = [ast.Name("property", ast.Load())]
    else:
        error.bases = [ast.Name("Exception", ast.Load())]
    with pytest.raises(AssertionError):
        _check_closed_adapter(ast.unparse(ast.fix_missing_locations(tree)))


def test_closed_checker_rejects_async_comprehension_dispatch() -> None:
    tree = ast.parse(Path(adapter.__file__).read_text(encoding="utf-8"))
    helper = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_require_member"
    )
    comprehension = next(node for node in ast.walk(helper) if isinstance(node, ast.comprehension))
    comprehension.is_async = 1
    with pytest.raises(AssertionError):
        _check_closed_adapter(ast.unparse(tree))


def _adapter_source_with_statement(statement: str) -> str:
    """Transform syntax in memory; never execute the modified application source."""
    tree = ast.parse(Path(adapter.__file__).read_text(encoding="utf-8"))
    entry = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "inspect_synthetic_disabled_bootstrap"
    )
    assert isinstance(entry.body[0], ast.Expr)
    assert isinstance(entry.body[0].value, ast.Constant)
    assert type(entry.body[0].value.value) is str
    entry.body[1:1] = ast.parse(statement).body
    return ast.unparse(tree)


@pytest.mark.parametrize("form", ("direct", "alias"))
def test_closed_checker_rejects_dependency_namespace_item_rebinding(
    form: str, record_property: Any
) -> None:
    original = _check_closed_adapter(Path(adapter.__file__).read_text(encoding="utf-8"))
    statement = {
        "direct": (
            'inspect_synthetic_enrollment_preparation.__globals__["_inspection_lstat"] = '
            'inspect_synthetic_enrollment_preparation.__globals__["Path"].unlink'
        ),
        "alias": (
            "namespace = inspect_synthetic_enrollment_preparation.__globals__\n"
            'namespace["_inspection_lstat"] = namespace["Path"].unlink'
        ),
    }[form]
    with pytest.raises(AssertionError):
        accepted = _check_closed_adapter(_adapter_source_with_statement(statement))
        # RED evidence is retained only if the checker wrongly accepts the syntax.
        record_property("unsafe_call_count", len(accepted))
        record_property("unsafe_calls_equal_baseline", accepted == original)


@pytest.mark.parametrize(
    "statement",
    (
        'items = {}\nitems["synthetic"] = None',
        'items = {}\nitems["synthetic"]: object = None',
        'items = {}\ndel items["synthetic"]',
    ),
    ids=("assignment", "annotated-assignment", "deletion"),
)
def test_closed_checker_rejects_item_mutation_without_namespace_access(statement: str) -> None:
    with pytest.raises(AssertionError):
        _check_closed_adapter(_adapter_source_with_statement(statement))


@pytest.mark.parametrize(
    "statement",
    (
        "inspect_synthetic_enrollment_preparation.__globals__",
        "namespace = inspect_synthetic_enrollment_preparation.__globals__\n"
        'sample = namespace["Path"]',
    ),
    ids=("direct-read", "alias-read"),
)
def test_closed_checker_rejects_namespace_access_without_item_mutation(statement: str) -> None:
    with pytest.raises(AssertionError):
        _check_closed_adapter(_adapter_source_with_statement(statement))


def test_closed_checker_preserves_exact_reviewed_calls_and_subscript_loads() -> None:
    source = Path(adapter.__file__).read_text(encoding="utf-8")
    calls = _check_closed_adapter(source)
    assert calls == {
        "dataclass",
        "field",
        "type",
        "len",
        "ValueError",
        "getattr",
        "any",
        "SyntheticEnrollmentExpectation",
        "cast",
        "_CapturedInputs",
        "_require_false",
        "DisabledBootstrapInputResult",
        "_require_member",
        "LeafObservation",
        "PreparationInspection",
        "_copy_leaf",
        "_copy_input_result",
        "_copy_inspection_result",
        "super",
        "DisabledBootstrapInspectionResult",
        "DisabledBootstrapInspectionResultError",
        "_capture_inputs",
        "_finish",
        "validate_disabled_bootstrap_inputs",
        "inspect_synthetic_enrollment_preparation",
    }
    assert any(
        isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load)
        for node in ast.walk(ast.parse(source))
    )
    with_load = _adapter_source_with_statement('sample = ("synthetic",)[0]')
    assert _check_closed_adapter(with_load) == calls


def _forbid_writes(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        calls.append("FORBIDDEN_WRITE")
        raise _UnexpectedEffect("forbidden synthetic handoff effect")

    for name in (
        "prepare_synthetic_enrollment",
        "_preflight",
        "_publish",
        "validate_sensitive_output_path",
    ):
        monkeypatch.setattr(prep, name, forbidden)
    monkeypatch.setattr(prep.private_create, "create_posix_private_bytes", forbidden)
    return calls


def test_mock_handoff_never_reaches_direct_storage_or_writer_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boundary = _Boundaries(monkeypatch, observed=_observation("pending"))
    effects = _forbid_writes(monkeypatch)
    monkeypatch.setattr(prep, "read_private_sensitive_bytes", _deny)
    monkeypatch.setattr(prep.private_lock, "acquire_posix_private_directory_lock", _deny)
    _check(_call(), S.INSPECTION_OBSERVED)
    boundary.counts(1, 1)
    assert effects == []


@WINDOWS_ONLY
def test_native_windows_validates_then_observes_platform_refusal_without_record_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []
    effects = _forbid_writes(monkeypatch)
    monkeypatch.setattr(prep, "read_private_sensitive_bytes", _deny)
    monkeypatch.setattr(prep, "_inspection_lstat", _deny)
    monkeypatch.setattr(prep.private_lock, "acquire_posix_private_directory_lock", _deny)

    def validate(*args: Any, **kwargs: Any) -> Any:
        calls.append("validate")
        return inputs.validate_disabled_bootstrap_inputs(*args, **kwargs)

    def observe(*args: Any, **kwargs: Any) -> Any:
        calls.append("inspect")
        return prep.inspect_synthetic_enrollment_preparation(*args, **kwargs)

    monkeypatch.setattr(adapter, "validate_disabled_bootstrap_inputs", validate)
    monkeypatch.setattr(adapter, "inspect_synthetic_enrollment_preparation", observe)
    result = _check(_call(), S.INSPECTION_OBSERVED)
    assert result.input_result.state is B.INPUTS_MATCHED_UNAPPROVED
    assert result.inspection_result.state is IS.UNSUPPORTED_PLATFORM
    assert not result.inspection_result.verification_complete
    assert calls == ["validate", "inspect"] and effects == []


def _private_fixture(tmp_path: Path, contents: dict[str, bytes]) -> Path:
    root = tmp_path / "handoff-control"
    root.mkdir(mode=0o700)
    for name, raw in contents.items():
        path = root / name
        path.write_bytes(raw)
        path.chmod(0o600)
    return root


def _fingerprint(root: Path) -> dict[str, tuple[object, ...]]:
    return {
        path.name: (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_nlink,
            info.st_uid,
            info.st_gid,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
            path.read_bytes() if stat.S_ISREG(info.st_mode) else None,
        )
        for path in root.iterdir()
        for info in (path.lstat(),)
    }


@LINUX_ONLY
@pytest.mark.parametrize(
    "case,state,complete",
    (
        ("empty", IS.ABSENCE_UNVERIFIABLE, True),
        ("pending", IS.ADMIN_PENDING, True),
        ("descriptor", IS.ORPHAN_DESCRIPTOR, True),
        ("both", IS.PREPARATION_RETAINED_UNAPPROVED, True),
        ("foreign", IS.PREPARATION_CONFLICT, True),
        ("broken", IS.PREPARATION_UNVERIFIABLE, False),
        ("active", IS.PREPARATION_CONFLICT, True),
        ("revoked", IS.PREPARATION_CONFLICT, True),
    ),
)
def test_linux_real_handoff_preserves_records_and_bounded_internal_schedule(
    case: str, state: IS, complete: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    contents = {PENDING: _pending(), DESCRIPTOR: RAW}
    if case == "empty":
        contents = {}
    elif case in {"pending", "descriptor"}:
        contents = {PENDING: _pending()} if case == "pending" else {DESCRIPTOR: RAW}
    elif case == "foreign":
        contents[PENDING] = _pending(revision="different-revision")
    elif case == "broken":
        contents[PENDING] = b"{}\n"
    elif case in {"active", "revoked"}:
        contents[DESCRIPTOR] = RAW.replace(b"PREPARING", case.upper().encode("ascii"))
    root = _private_fixture(tmp_path, contents)
    before, names = _fingerprint(root), sorted(path.name for path in root.iterdir())
    effects = _forbid_writes(monkeypatch)
    counts = {"validate": 0, "inspect": 0, "acquire": 0, "checkpoint": 0, "lstat": 0, "read": 0}
    original_acquire = prep.private_lock.acquire_posix_private_directory_lock

    def counted(name: str, operation: Any) -> Any:
        def invoke(*args: Any, **kwargs: Any) -> Any:
            counts[name] += 1
            return operation(*args, **kwargs)

        return invoke

    monkeypatch.setattr(
        adapter,
        "validate_disabled_bootstrap_inputs",
        counted("validate", inputs.validate_disabled_bootstrap_inputs),
    )
    monkeypatch.setattr(
        adapter,
        "inspect_synthetic_enrollment_preparation",
        counted("inspect", prep.inspect_synthetic_enrollment_preparation),
    )
    monkeypatch.setattr(
        prep.private_lock,
        "acquire_posix_private_directory_lock",
        counted("acquire", original_acquire),
    )
    monkeypatch.setattr(
        prep, "_inspection_checkpoint", counted("checkpoint", prep._inspection_checkpoint)
    )
    monkeypatch.setattr(prep, "_inspection_lstat", counted("lstat", prep._inspection_lstat))
    monkeypatch.setattr(
        prep, "read_private_sensitive_bytes", counted("read", prep.read_private_sensitive_bytes)
    )
    result = _check(_call(policy=_policy(str(root)), root=str(root)), S.INSPECTION_OBSERVED)
    assert result.inspection_result.state is state
    assert result.inspection_result.verification_complete is complete
    assert counts["validate"] == counts["inspect"] == counts["acquire"] == 1
    assert counts["checkpoint"] <= 4 and counts["lstat"] <= 4 and counts["read"] <= 2
    assert effects == [] and _fingerprint(root) == before
    assert sorted(path.name for path in root.iterdir()) == names
    with original_acquire(root):
        pass


@LINUX_ONLY
def test_linux_input_refusal_does_not_access_existing_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private_fixture(tmp_path, {PENDING: _pending(), DESCRIPTOR: RAW})
    before = _fingerprint(root)
    effects = _forbid_writes(monkeypatch)
    monkeypatch.setattr(adapter, "inspect_synthetic_enrollment_preparation", _deny)
    monkeypatch.setattr(prep.private_lock, "acquire_posix_private_directory_lock", _deny)
    monkeypatch.setattr(prep, "read_private_sensitive_bytes", _deny)
    monkeypatch.setattr(prep, "_inspection_lstat", _deny)
    result = _check(_call(policy=b"{}\n", root=str(root)), S.VALIDATION_REFUSED)
    assert result.input_result.state is B.POLICY_UNVERIFIABLE
    assert effects == [] and _fingerprint(root) == before


@LINUX_ONLY
def test_linux_internal_read_failure_keeps_observed_pending_and_releases_owned_lock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private_fixture(tmp_path, {PENDING: _pending(), DESCRIPTOR: RAW})
    before = _fingerprint(root)
    effects = _forbid_writes(monkeypatch)
    original = prep.read_private_sensitive_bytes
    reads: list[str] = []

    def fail_descriptor(path: Path, **kwargs: Any) -> bytes:
        reads.append(path.name)
        if path.name == DESCRIPTOR:
            raise RuntimeError("SYNTHETIC_READ_FAILURE")
        return original(path, **kwargs)

    monkeypatch.setattr(prep, "read_private_sensitive_bytes", fail_descriptor)
    result = _check(_call(policy=_policy(str(root)), root=str(root)), S.INSPECTION_OBSERVED)
    observed = result.inspection_result
    assert observed.state is IS.PREPARATION_UNVERIFIABLE
    assert observed.pending == prep.LeafObservation(P.PRESENT, C.SCHEMA_VALID, T.MATCH)
    assert observed.first_failure is F.DESCRIPTOR_READ and not observed.verification_complete
    assert reads == [PENDING, DESCRIPTOR] and effects == [] and _fingerprint(root) == before
    with prep.private_lock.acquire_posix_private_directory_lock(root):
        pass


@LINUX_ONLY
@pytest.mark.parametrize("both", (False, True), ids=("pending", "both"))
def test_linux_fresh_process_uses_independent_inputs_and_keeps_records(
    both: bool, tmp_path: Path
) -> None:
    contents = {PENDING: _pending()}
    if both:
        contents[DESCRIPTOR] = RAW
    root = _private_fixture(tmp_path, contents)
    before = _fingerprint(root)
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(Path(adapter.__file__).resolve().parents[1])
    child = subprocess.run(
        [sys.executable, "-B", __file__, "--handoff-observe", str(root)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
        check=False,
        env=environment,
    )
    expected = b"PREPARATION_RETAINED_UNAPPROVED\n" if both else b"ADMIN_PENDING\n"
    assert child.returncode == 0 and child.stdout == expected and child.stderr == b""
    assert _fingerprint(root) == before
    with prep.private_lock.acquire_posix_private_directory_lock(root):
        pass


def _child_main() -> int:
    """One finite synthetic observation; expected records are never learned from disk."""
    try:
        if len(sys.argv) != 3 or sys.argv[1] != "--handoff-observe" or sys.platform != "linux":
            return 2
        root = sys.argv[2]
        with pytest.MonkeyPatch.context() as scoped:
            effects = _forbid_writes(scoped)
            result = _call(policy=_policy(root), raw=RAW, expectation=_expect(), root=root)
            if result.state is not S.INSPECTION_OBSERVED or result.reuse_authorized is not False:
                return 2
            observed = result.inspection_result
            if effects or observed is None or not observed.verification_complete:
                return 2
            if observed.reuse_authorized is not False:
                return 2
        if observed.state is IS.ADMIN_PENDING:
            print("ADMIN_PENDING")
        elif observed.state is IS.PREPARATION_RETAINED_UNAPPROVED:
            print("PREPARATION_RETAINED_UNAPPROVED")
        else:
            return 2
        return 0
    except BaseException:
        return 2


if __name__ == "__main__":
    raise SystemExit(_child_main())
