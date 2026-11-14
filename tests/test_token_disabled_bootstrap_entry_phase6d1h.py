"""Synthetic configuration/request separation; never installation or startup authority."""

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
from typing import Any

import pytest

from tridentine_calendar_google_sync import production_write_token_disabled_bootstrap_entry as entry
from tridentine_calendar_google_sync import (
    production_write_token_disabled_bootstrap_inputs as inputs,
)
from tridentine_calendar_google_sync import (
    production_write_token_disabled_bootstrap_inspection as handoff,
)
from tridentine_calendar_google_sync import (
    production_write_token_disabled_bootstrap_source_loading as loader,
)
from tridentine_calendar_google_sync import (
    production_write_token_enrollment_descriptor as descriptor,
)
from tridentine_calendar_google_sync import production_write_token_enrollment_preparation as prep
from tridentine_calendar_google_sync import sensitive_paths

E = entry.DisabledBootstrapEntryState
S = loader.DisabledBootstrapSourceStage
R = loader.DisabledBootstrapSourceReason
H = handoff.DisabledBootstrapInspectionState
B = inputs.DisabledBootstrapInputState
IS = prep.InspectionState
P = prep.Presence
C = prep.ContentStatus
T = prep.TargetRelation
F = prep.InspectionFailure
SOURCE = "/synthetic-entry-source"
CONTROL = "/synthetic-entry-control"
PAIR = "/synthetic-entry-pair"
POLICY = "policy.json"
COMPANION = "expected.json"
PENDING = "pending.json"
DESCRIPTOR = "descriptor.json"
CANARY = "SYNTHETIC_ENTRY_PRIVATE_CANARY"
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
DIRECT_FIELDS = ("source_root", "policy_leaf", "expected_descriptor_leaf", "expected_control_root")
ROLES = DIRECT_FIELDS + EXPECTATION_FIELDS
PATH_ROLES = {"source_root", "expected_control_root", "artifact_directory"}
VALID_SOURCE_PAIRS = (
    (S.CAPTURE, R.INPUT_UNVERIFIABLE),
    (S.CAPTURE, R.SOURCE_OVERLAP),
    (S.PLATFORM, R.UNSUPPORTED_PLATFORM),
    (S.PRECHECK, R.SOURCE_UNVERIFIABLE),
    (S.PRECHECK, R.SOURCE_OVERLAP),
    (S.POLICY_READ, R.SOURCE_UNVERIFIABLE),
    (S.COMPANION_READ, R.SOURCE_UNVERIFIABLE),
    (S.RECHECK, R.SOURCE_UNVERIFIABLE),
    (S.RECHECK, R.SOURCE_CHANGED),
    (S.HANDOFF, R.HANDOFF_FAILED),
    (S.HANDOFF, R.HANDOFF_RESULT_UNVERIFIABLE),
)
LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="native Linux synthetic entry")
WINDOWS_ONLY = pytest.mark.skipif(sys.platform != "win32", reason="native Windows entry gate")


class _UnexpectedEffect(BaseException):
    pass


class _Cancel(BaseException):
    pass


def _deny(*args: object, **kwargs: object) -> Any:
    raise _UnexpectedEffect("unexpected synthetic entry effect")


class _Poison:
    __repr__ = __str__ = __bytes__ = __len__ = __iter__ = __eq__ = __hash__ = _deny
    __getattribute__ = __fspath__ = _deny


class _String(str):
    pass


class _OtherState(StrEnum):
    PAIR_MISMATCH = "PAIR_MISMATCH"


def _wire(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _materials(
    control: str = CONTROL, pair: str = PAIR
) -> tuple[bytes, bytes, descriptor.SyntheticEnrollmentExpectation]:
    """Fixture plan is independently declared before any source or target read."""
    raw = _wire(
        {
            "format_version": 1,
            "record_kind": "enrollment_descriptor",
            "role": "production_write",
            "record_slot": "production-write-operation-start-v1.json",
            "enrollment_revision": "revision-one",
            "administrative_state": "PREPARING",
            "storage_ref": "synthetic-store",
            "pair_ref": "synthetic-pair",
            "artifact_directory": pair,
            "token_slot": "token.json",
            "state_slot": "state.json",
            "active_intent_slot": "intent.json",
        }
    )
    expectation = descriptor.SyntheticEnrollmentExpectation(
        "revision-one",
        "PREPARING",
        "synthetic-store",
        "synthetic-pair",
        pair,
        "token.json",
        "state.json",
        "intent.json",
        hashlib.sha256(raw).hexdigest(),
        DESCRIPTOR,
        PENDING,
    )
    policy = _wire(
        {
            "format_version": 1,
            "policy_kind": "enrollment_bootstrap",
            "control_root": control,
            "descriptor_slot": DESCRIPTOR,
            "administrative_pending_slot": PENDING,
            "expected_revision": "revision-one",
            "descriptor_pin": expectation.descriptor_pin,
            "expected_state": "PREPARING",
            "entry_mode": "disabled",
        }
    )
    return policy, raw, expectation


def _values() -> dict[str, Any]:
    expected = _materials()[2]
    return {
        "source_root": SOURCE,
        "policy_leaf": POLICY,
        "expected_descriptor_leaf": COMPANION,
        "expected_control_root": CONTROL,
        **{name: getattr(expected, name) for name in EXPECTATION_FIELDS},
    }


def _bind_values(values: dict[str, Any]) -> Any:
    expected = descriptor.SyntheticEnrollmentExpectation(
        **{name: values[name] for name in EXPECTATION_FIELDS}
    )
    return entry.bind_synthetic_disabled_bootstrap(
        values["source_root"],
        values["policy_leaf"],
        values["expected_descriptor_leaf"],
        expected,
        expected_control_root=values["expected_control_root"],
    )


def _bind(expected: object = None) -> Any:
    if expected is None:
        expected = _materials()[2]
    return entry.bind_synthetic_disabled_bootstrap(
        SOURCE, POLICY, COMPANION, expected, expected_control_root=CONTROL
    )


def _refused(value: Any, state: E) -> None:
    assert type(value) is entry.DisabledBootstrapEntryRefusal
    assert value.state is state and value.reuse_authorized is False
    assert tuple(item.name for item in fields(value)) == ("state", "reuse_authorized")
    assert not hasattr(value, "__dict__")


def _observation(state: IS) -> prep.PreparationInspection:
    absent = prep.LeafObservation(P.ABSENT)
    matched = prep.LeafObservation(P.PRESENT, C.SCHEMA_VALID, T.MATCH)
    mismatch = prep.LeafObservation(P.PRESENT, C.SCHEMA_VALID, T.MISMATCH)
    if state in {IS.INPUT_UNVERIFIABLE, IS.PREPARING_REQUIRED}:
        return prep.PreparationInspection(state, first_failure=F.INPUT)
    if state is IS.UNSUPPORTED_PLATFORM:
        return prep.PreparationInspection(state)
    if state is IS.LOCK_BUSY:
        return prep.PreparationInspection(state, first_failure=F.ACQUIRE)
    if state is IS.LOCK_UNAVAILABLE:
        return prep.PreparationInspection(state, first_failure=F.ENTRY, exit_failure_observed=True)
    if state is IS.ABSENCE_UNVERIFIABLE:
        return prep.PreparationInspection(state, absent, absent, verification_complete=True)
    if state is IS.ADMIN_PENDING:
        return prep.PreparationInspection(state, matched, absent, verification_complete=True)
    if state is IS.ORPHAN_DESCRIPTOR:
        return prep.PreparationInspection(state, absent, matched, verification_complete=True)
    if state is IS.PREPARATION_RETAINED_UNAPPROVED:
        return prep.PreparationInspection(
            state, matched, matched, T.MATCH, verification_complete=True
        )
    if state is IS.PREPARATION_CONFLICT:
        return prep.PreparationInspection(
            state,
            mismatch,
            mismatch,
            T.MISMATCH,
            non_preparing_observed=True,
            first_failure=F.ROOT_CHECK,
            exit_failure_observed=True,
        )
    return prep.PreparationInspection(
        state,
        replace(matched, changed=True),
        matched,
        T.MATCH,
        first_failure=F.ENTRY_CHANGED,
        exit_failure_observed=True,
    )


def _diagnostic(
    state: H = H.INSPECTION_OBSERVED, observed: IS = IS.ADMIN_PENDING
) -> handoff.DisabledBootstrapInspectionResult:
    if state in {H.CAPTURE_REFUSED, H.VALIDATION_UNVERIFIABLE}:
        return handoff.DisabledBootstrapInspectionResult(state)
    if state is H.VALIDATION_REFUSED:
        return handoff.DisabledBootstrapInspectionResult(
            state, inputs.DisabledBootstrapInputResult(B.INPUTS_MISMATCH)
        )
    return handoff.DisabledBootstrapInspectionResult(
        state,
        inputs.DisabledBootstrapInputResult(B.INPUTS_MATCHED_UNAPPROVED),
        _observation(observed) if state is H.INSPECTION_OBSERVED else None,
    )


class _Spy:
    def __init__(self, monkeypatch: pytest.MonkeyPatch, *results: Any) -> None:
        self.results = results or (_diagnostic(),)
        self.calls: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        monkeypatch.setattr(entry, "load_synthetic_disabled_bootstrap", self.invoke)

    def invoke(self, *args: Any, **kwargs: Any) -> Any:
        index = len(self.calls)
        self.calls.append((args, kwargs))
        assert index < len(self.results), "unexpected additional loader call"
        value = self.results[index]
        if issubclass(type(value), BaseException):
            raise value
        return value


def _assert_arguments(
    call: tuple[tuple[Any, ...], dict[str, Any]], expected: dict[str, Any]
) -> None:
    args, kwargs = call
    assert len(args) == 4 and set(kwargs) == {"expected_control_root"}
    assert args[:3] == (
        expected["source_root"],
        expected["policy_leaf"],
        expected["expected_descriptor_leaf"],
    )
    assert kwargs["expected_control_root"] == expected["expected_control_root"]
    assert type(args[3]) is descriptor.SyntheticEnrollmentExpectation
    assert {name: getattr(args[3], name) for name in EXPECTATION_FIELDS} == {
        name: expected[name] for name in EXPECTATION_FIELDS
    }


def test_exact_public_signatures_no_override_and_no_setup_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert tuple(state.name for state in E) == (
        "CONFIGURATION_REQUIRED",
        "CONFIGURATION_UNVERIFIABLE",
        "REQUEST_UNVERIFIABLE",
        "PAIR_MISMATCH",
        "LOADER_FAILED",
        "LOADER_RESULT_UNVERIFIABLE",
    )
    spy = _Spy(monkeypatch)
    signature = inspect.signature(entry.bind_synthetic_disabled_bootstrap)
    assert tuple(signature.parameters) == (
        "source_root",
        "policy_leaf",
        "expected_descriptor_leaf",
        "expectation",
        "expected_control_root",
    )
    assert all(item.default is inspect.Parameter.empty for item in signature.parameters.values())
    assert signature.parameters["expected_control_root"].kind is inspect.Parameter.KEYWORD_ONLY
    assert tuple(inspect.signature(entry.SyntheticDisabledBootstrapEntry).parameters) == ()
    configured = _bind()
    assert type(configured) is entry.SyntheticDisabledBootstrapEntry
    assert tuple(inspect.signature(configured.diagnose).parameters) == ("requested_pair_ref",)
    for field in signature.parameters:
        kwargs = {
            "source_root": SOURCE,
            "policy_leaf": POLICY,
            "expected_descriptor_leaf": COMPANION,
            "expectation": _materials()[2],
            "expected_control_root": CONTROL,
        }
        del kwargs[field]
        with pytest.raises(TypeError):
            entry.bind_synthetic_disabled_bootstrap(**kwargs)
    with pytest.raises(TypeError):
        entry.bind_synthetic_disabled_bootstrap(SOURCE, POLICY, COMPANION, _materials()[2], CONTROL)
    for name in (*ROLES, "action", "enabled", "callback", "plan", "entry_selector"):
        with pytest.raises(TypeError):
            configured.diagnose("synthetic-pair", **{name: _Poison()})
    with pytest.raises(TypeError):
        entry.SyntheticDisabledBootstrapEntry(_Poison())
    with pytest.raises(TypeError):
        entry.SyntheticDisabledBootstrapEntry(plan=_Poison())
    assert spy.calls == []


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize(
    "kind",
    ("none", "integer", "boolean", "bytes", "mapping", "subclass", "poison", "empty", "surrogate"),
)
def test_configuration_exact_types_nonempty_utf8_before_conversion(
    role: str, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy(monkeypatch)
    bad: dict[str, Any] = {
        "none": None,
        "integer": 0,
        "boolean": True,
        "bytes": b"synthetic",
        "mapping": {},
        "subclass": _String("synthetic"),
        "poison": _Poison(),
        "empty": "",
        "surrogate": "\ud800",
    }
    values = _values()
    values[role] = bad[kind]
    _refused(_bind_values(values), E.CONFIGURATION_UNVERIFIABLE)
    assert spy.calls == []


@pytest.mark.parametrize("role", EXPECTATION_FIELDS)
def test_missing_caller_expectation_field_refuses(
    role: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy(monkeypatch)
    expected = _materials()[2]
    object.__delattr__(expected, role)
    _refused(_bind(expected), E.CONFIGURATION_UNVERIFIABLE)
    assert spy.calls == []


@pytest.mark.parametrize("kind", ("poison", "subclass", "mapping"))
def test_expectation_type_precedes_field_getters(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Child(descriptor.SyntheticEnrollmentExpectation):
        __getattribute__ = _deny

    spy = _Spy(monkeypatch)
    candidate: Any = (
        _Poison() if kind == "poison" else (object.__new__(Child) if kind == "subclass" else {})
    )
    _refused(_bind(candidate), E.CONFIGURATION_UNVERIFIABLE)
    assert spy.calls == []


@pytest.mark.parametrize("role", ROLES)
@pytest.mark.parametrize("over", (False, True))
def test_representation_byte_boundaries(
    role: str, over: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy(monkeypatch)
    values = _values()
    limit = 1024 if role in PATH_ROLES else (64 if role == "descriptor_pin" else 96)
    values[role] = "a" * (limit + int(over))
    result = _bind_values(values)
    if over:
        _refused(result, E.CONFIGURATION_UNVERIFIABLE)
    else:
        assert type(result) is entry.SyntheticDisabledBootstrapEntry
        assert result.reuse_authorized is False
    assert spy.calls == []


@pytest.mark.parametrize(
    "role", tuple(name for name in ROLES if name not in {"descriptor_pin", "pair_ref"})
)
@pytest.mark.parametrize("over", (False, True))
def test_utf8_byte_limits_do_not_count_characters(
    role: str, over: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy(monkeypatch)
    limit = 1024 if role in PATH_ROLES else 96
    values = _values()
    values[role] = "é" * (limit // 2 + int(over))
    result = _bind_values(values)
    if over:
        _refused(result, E.CONFIGURATION_UNVERIFIABLE)
    else:
        assert type(result) is entry.SyntheticDisabledBootstrapEntry
    assert spy.calls == []


@pytest.mark.parametrize("pin", ("A" * 64, "g" * 64, "é" * 64, "a" * 63, "a" * 65, "a" * 63 + " "))
def test_pin_representation_is_exact_lowercase_hex(
    pin: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy(monkeypatch)
    values = _values()
    values["descriptor_pin"] = pin
    _refused(_bind_values(values), E.CONFIGURATION_UNVERIFIABLE)
    assert spy.calls == []


@pytest.mark.parametrize("pair", ("a", "A.B_c-9", "CON", "COM1.txt", "pair.", "x" * 96))
def test_pair_reference_does_not_inherit_source_leaf_rules(
    pair: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy(monkeypatch)
    values = _values()
    values["pair_ref"] = pair
    configured = _bind_values(values)
    assert configured.diagnose(pair).reuse_authorized is False
    assert len(spy.calls) == 1
    _assert_arguments(spy.calls[0], values)


@pytest.mark.parametrize(
    "requested", ("", ".pair", "-pair", "_pair", "pair/", "pair ", "é", "x" * 97)
)
def test_bad_pair_representation_in_configuration_and_request(
    requested: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy(monkeypatch)
    values = _values()
    values["pair_ref"] = requested
    _refused(_bind_values(values), E.CONFIGURATION_UNVERIFIABLE)
    _refused(_bind().diagnose(requested), E.REQUEST_UNVERIFIABLE)
    assert spy.calls == []


def test_capture_once_in_declared_order_detaches_every_field(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = _materials()[2]
    before = _values()
    calls: list[str] = []
    real_get = descriptor.SyntheticEnrollmentExpectation.__getattribute__

    def get(self: Any, name: str) -> Any:
        if self is expected:
            calls.append(name)
        return real_get(self, name)

    spy = _Spy(monkeypatch)
    with monkeypatch.context() as scoped:
        scoped.setattr(descriptor.SyntheticEnrollmentExpectation, "__getattribute__", get)
        configured = _bind(expected)
        assert calls == list(EXPECTATION_FIELDS)
        for name in EXPECTATION_FIELDS:
            object.__setattr__(expected, name, _Poison())
        source_variable: Any = configured
        configured = None
        result = source_variable.diagnose("synthetic-pair")
        assert result.reuse_authorized is False and calls == list(EXPECTATION_FIELDS)
    assert len(spy.calls) == 1 and spy.calls[0][0][3] is not expected
    _assert_arguments(spy.calls[0], before)


@pytest.mark.parametrize("role", DIRECT_FIELDS)
def test_invalid_direct_value_precedes_expectation_access(
    role: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy(monkeypatch)
    kwargs = {
        "source_root": SOURCE,
        "policy_leaf": POLICY,
        "expected_descriptor_leaf": COMPANION,
        "expectation": _Poison(),
        "expected_control_root": CONTROL,
    }
    kwargs[role] = _Poison()
    _refused(entry.bind_synthetic_disabled_bootstrap(**kwargs), E.CONFIGURATION_UNVERIFIABLE)
    assert spy.calls == []


@pytest.mark.parametrize(
    "role,value",
    (
        ("source_root", "relative"),
        ("policy_leaf", "CON."),
        ("artifact_directory", CONTROL),
        ("administrative_state", "ACTIVE"),
        ("token_slot", "with/slash"),
    ),
)
def test_capture_completeness_does_not_duplicate_lower_semantics(
    role: str, value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    lower = loader.DisabledBootstrapSourceRefusal(S.CAPTURE, R.INPUT_UNVERIFIABLE)
    spy = _Spy(monkeypatch, lower)
    values = _values()
    values[role] = value
    configured = _bind_values(values)
    assert type(configured) is entry.SyntheticDisabledBootstrapEntry and spy.calls == []
    result = configured.diagnose("synthetic-pair")
    assert result == lower and result is not lower and result.reuse_authorized is False
    _assert_arguments(spy.calls[0], values)


@pytest.mark.parametrize("missing", (False, True))
def test_unconfigured_precedes_even_poison_request(
    missing: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy(monkeypatch)
    value = entry.SyntheticDisabledBootstrapEntry()
    if missing:
        object.__delattr__(value, "_plan")
    _refused(value.diagnose(_Poison()), E.CONFIGURATION_REQUIRED)
    assert spy.calls == []


@pytest.mark.parametrize("role", ("_plan", *DIRECT_FIELDS, "expectation", *EXPECTATION_FIELDS))
@pytest.mark.parametrize("missing", (False, True))
def test_detected_retained_plan_corruption_precedes_request_and_loader(
    role: str, missing: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy(monkeypatch)
    configured = _bind()
    owner: Any = configured if role == "_plan" else configured._plan
    if role in EXPECTATION_FIELDS:
        owner = owner.expectation
    if missing:
        object.__delattr__(owner, role)
    else:
        object.__setattr__(owner, role, _Poison())
    required = role == "_plan" and missing
    _refused(
        configured.diagnose(_Poison()),
        E.CONFIGURATION_REQUIRED if required else E.CONFIGURATION_UNVERIFIABLE,
    )
    assert spy.calls == []


@pytest.mark.parametrize("kind", ("none", "bool", "zero", "bytes", "subclass", "poison"))
def test_request_exact_type_has_no_conversion_or_comparison_hook(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidates = {
        "none": None,
        "bool": True,
        "zero": 0,
        "bytes": b"synthetic-pair",
        "subclass": _String("synthetic-pair"),
        "poison": _Poison(),
    }
    spy = _Spy(monkeypatch)
    _refused(_bind().diagnose(candidates[kind]), E.REQUEST_UNVERIFIABLE)
    assert spy.calls == []


@pytest.mark.parametrize("requested", ("different-pair", "Synthetic-pair", "synthetic-pair."))
def test_pair_mismatch_has_zero_loader_calls(
    requested: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy(monkeypatch)
    _refused(_bind().diagnose(requested), E.PAIR_MISMATCH)
    assert spy.calls == []


def test_explicit_rediagnosis_has_no_success_cache_or_automatic_retry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    previous = _diagnostic(observed=IS.PREPARATION_RETAINED_UNAPPROVED)
    later = loader.DisabledBootstrapSourceRefusal(S.RECHECK, R.SOURCE_CHANGED)
    spy = _Spy(monkeypatch, previous, later, RuntimeError(CANARY))
    configured = _bind()
    plan = configured._plan
    assert configured.diagnose("synthetic-pair") == previous
    assert configured.diagnose("synthetic-pair") == later
    _refused(configured.diagnose("wrong-pair"), E.PAIR_MISMATCH)
    _refused(configured.diagnose("synthetic-pair"), E.LOADER_FAILED)
    assert len(spy.calls) == 3 and configured._plan is plan
    for call in spy.calls:
        _assert_arguments(call, _values())


@pytest.mark.parametrize(
    "role", tuple(name for name in ROLES if name not in {"pair_ref", "enrollment_revision"})
)
def test_same_revision_and_pair_do_not_merge_distinct_entries(
    role: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy(monkeypatch, _diagnostic(), _diagnostic(), _diagnostic())
    original, changed = _values(), _values()
    changed[role] = "b" * 64 if role == "descriptor_pin" else "different"
    first, second = _bind_values(original), _bind_values(changed)
    assert first is not second and first._plan is not second._plan
    first.diagnose("synthetic-pair")
    second.diagnose("synthetic-pair")
    first.diagnose("synthetic-pair")
    for call, values in zip(spy.calls, (original, changed, original), strict=True):
        _assert_arguments(call, values)


@pytest.mark.parametrize("configured", (False, True))
def test_reinitialization_never_clears_or_replaces_plan(
    configured: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    spy = _Spy(monkeypatch)
    value = _bind() if configured else entry.SyntheticDisabledBootstrapEntry()
    plan = value._plan
    with pytest.raises(ValueError):
        value.__init__()
    assert value._plan is plan and spy.calls == [] and value.reuse_authorized is False
    if configured:
        value.diagnose("synthetic-pair")
        assert len(spy.calls) == 1
    else:
        _refused(value.diagnose(_Poison()), E.CONFIGURATION_REQUIRED)


def test_frozen_slotted_objects_have_no_configuration_export_or_setter() -> None:
    configured = _bind()
    for value in (configured, configured._plan, configured._plan.expectation):
        assert not hasattr(value, "__dict__")
        assert all(not item.repr for item in fields(value))
        for item in fields(value):
            with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
                setattr(value, item.name, _Poison())
            with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
                delattr(value, item.name)
    assert not any(hasattr(configured, name) for name in ("rebind", "set_plan", "plan", "export"))
    with pytest.raises((FrozenInstanceError, AttributeError, TypeError)):
        configured.reuse_authorized = True
    assert configured.reuse_authorized is False


@pytest.mark.parametrize("state", tuple(E))
def test_all_entry_refusals_are_closed_non_authorizing_and_immutable(state: E) -> None:
    value = entry.DisabledBootstrapEntryRefusal(state)
    _refused(value, state)
    with pytest.raises(TypeError):
        entry.DisabledBootstrapEntryRefusal(state, reuse_authorized=True)
    with pytest.raises(FrozenInstanceError):
        value.state = E.LOADER_FAILED
    with pytest.raises(FrozenInstanceError):
        del value.state


@pytest.mark.parametrize("kind", ("string", "other-enum", "forged-member", "poison", "none"))
def test_invalid_refusal_state_has_fixed_diagnostic(kind: str) -> None:
    forged = str.__new__(E, "PAIR_MISMATCH")
    forged._name_ = "PAIR_MISMATCH"
    forged._value_ = "PAIR_MISMATCH"
    value = {
        "string": "PAIR_MISMATCH",
        "other-enum": _OtherState.PAIR_MISMATCH,
        "forged-member": forged,
        "poison": _Poison(),
        "none": None,
    }[kind]
    with pytest.raises(ValueError, match=r"^Invalid disabled bootstrap entry refusal$"):
        entry.DisabledBootstrapEntryRefusal(value)


@pytest.mark.parametrize("kind", ("true", "zero", "none", "poison"))
def test_refusal_post_init_checks_false_identity(kind: str) -> None:
    candidates = {"true": True, "zero": 0, "none": None, "poison": _Poison()}
    value = entry.DisabledBootstrapEntryRefusal(E.PAIR_MISMATCH)
    object.__setattr__(value, "reuse_authorized", candidates[kind])
    with pytest.raises(ValueError, match=r"^Invalid disabled bootstrap entry refusal$"):
        value.__post_init__()


@pytest.mark.parametrize("stage,reason", VALID_SOURCE_PAIRS)
def test_all_source_refusal_pairs_are_checked_and_preserved(
    stage: S, reason: R, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = loader.DisabledBootstrapSourceRefusal(stage, reason)
    spy = _Spy(monkeypatch, original)
    result = _bind().diagnose("synthetic-pair")
    assert type(result) is loader.DisabledBootstrapSourceRefusal
    assert result == original and result is not original and result.reuse_authorized is False
    assert len(spy.calls) == 1


@pytest.mark.parametrize("state", tuple(H))
def test_all_handoff_progress_classifications_are_preserved(
    state: H, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = _diagnostic(state)
    spy = _Spy(monkeypatch, original)
    result = _bind().diagnose("synthetic-pair")
    assert result == original and result is not original and result.reuse_authorized is False
    assert len(spy.calls) == 1


@pytest.mark.parametrize("state", tuple(IS))
def test_all_observation_fields_and_negative_evidence_are_copied(
    state: IS, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = _diagnostic(observed=state)
    spy = _Spy(monkeypatch, original)
    result = _bind().diagnose("synthetic-pair")
    assert result == original and result.inspection_result is not original.inspection_result
    assert result.input_result is not original.input_result
    assert result.reuse_authorized is False and result.inspection_result.reuse_authorized is False
    assert {
        item.name: getattr(result.inspection_result, item.name)
        for item in fields(result.inspection_result)
    } == {
        item.name: getattr(original.inspection_result, item.name)
        for item in fields(original.inspection_result)
    }
    assert len(spy.calls) == 1


@pytest.mark.parametrize(
    "kind", ("none", "poison", "entry-refusal", "source-child", "handoff-child")
)
def test_unknown_or_subclass_returns_do_not_become_safe_results(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SourceChild(loader.DisabledBootstrapSourceRefusal):
        pass

    class HandoffChild(handoff.DisabledBootstrapInspectionResult):
        pass

    candidates = {
        "none": None,
        "poison": _Poison(),
        "entry-refusal": entry.DisabledBootstrapEntryRefusal(E.PAIR_MISMATCH),
        "source-child": SourceChild(S.CAPTURE, R.INPUT_UNVERIFIABLE),
        "handoff-child": HandoffChild(H.CAPTURE_REFUSED),
    }
    spy = _Spy(monkeypatch, candidates[kind])
    _refused(_bind().diagnose("synthetic-pair"), E.LOADER_RESULT_UNVERIFIABLE)
    assert len(spy.calls) == 1


@pytest.mark.parametrize("kind", ("source", "handoff"))
@pytest.mark.parametrize(
    "fault", ("true", "zero", "missing-flag", "missing-state", "bad-state", "bad-nested")
)
def test_invalid_return_fields_cannot_be_hidden_by_constructor_defaults(
    kind: str, fault: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate: Any = (
        loader.DisabledBootstrapSourceRefusal(S.CAPTURE, R.INPUT_UNVERIFIABLE)
        if kind == "source"
        else _diagnostic()
    )
    state_field = "stage" if kind == "source" else "state"
    if fault in {"true", "zero"}:
        object.__setattr__(candidate, "reuse_authorized", True if fault == "true" else 0)
    elif fault == "missing-flag":
        object.__delattr__(candidate, "reuse_authorized")
    elif fault == "missing-state":
        object.__delattr__(candidate, state_field)
    elif fault == "bad-state":
        object.__setattr__(candidate, state_field, _Poison())
    else:
        object.__setattr__(
            candidate, "reason" if kind == "source" else "inspection_result", _Poison()
        )
    spy = _Spy(monkeypatch, candidate)
    _refused(_bind().diagnose("synthetic-pair"), E.LOADER_RESULT_UNVERIFIABLE)
    assert len(spy.calls) == 1


@pytest.mark.parametrize("kind", ("source", "handoff"))
def test_lower_result_fields_are_captured_once(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    original: Any = (
        loader.DisabledBootstrapSourceRefusal(S.CAPTURE, R.INPUT_UNVERIFIABLE)
        if kind == "source"
        else _diagnostic()
    )
    expected_fields = (
        ("stage", "reason", "reuse_authorized")
        if kind == "source"
        else ("state", "input_result", "inspection_result", "reuse_authorized")
    )
    cls = type(original)
    real_get = cls.__getattribute__
    reads: list[str] = []

    def get(self: Any, name: str) -> Any:
        if self is original:
            reads.append(name)
        return real_get(self, name)

    spy = _Spy(monkeypatch, original)
    configured = _bind()
    with monkeypatch.context() as scoped:
        scoped.setattr(cls, "__getattribute__", get)
        result = configured.diagnose("synthetic-pair")
    assert reads == list(expected_fields)
    assert result == original and result is not original and len(spy.calls) == 1


def _fixed_error(kind: str) -> Any:
    if kind == "source":
        return loader.DisabledBootstrapSourceResultError()
    result = handoff.DisabledBootstrapInspectionResultError()
    checked = _diagnostic(observed=IS.PREPARATION_CONFLICT)
    result._input_result = checked.input_result
    result._inspection_result = checked.inspection_result
    return result


@pytest.mark.parametrize("kind", ("source", "handoff"))
def test_exact_call_origin_fixed_error_preserves_identity_fields_and_links(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    failure = _fixed_error(kind)
    cause, context = RuntimeError("SAFE_CAUSE"), RuntimeError("SAFE_CONTEXT")
    failure.__cause__, failure.__context__ = cause, context
    failure.add_note("SAFE_NOTE")
    before = (failure.args, failure.__notes__[:])
    spy = _Spy(monkeypatch, failure)
    with pytest.raises(type(failure)) as caught:
        _bind().diagnose("synthetic-pair")
    assert caught.value is failure and failure.__cause__ is cause and failure.__context__ is context
    assert (failure.args, failure.__notes__) == before and failure.reuse_authorized is False
    if kind == "handoff":
        assert failure.inspection_result == _observation(IS.PREPARATION_CONFLICT)
    assert len(spy.calls) == 1


@pytest.mark.parametrize("kind", ("source-child", "handoff-child", "ordinary"))
def test_other_call_exceptions_are_loader_failed(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class SourceChild(loader.DisabledBootstrapSourceResultError):
        pass

    class HandoffChild(handoff.DisabledBootstrapInspectionResultError):
        pass

    failure = {
        "source-child": SourceChild(),
        "handoff-child": HandoffChild(),
        "ordinary": RuntimeError(CANARY),
    }[kind]
    spy = _Spy(monkeypatch, failure)
    _refused(_bind().diagnose("synthetic-pair"), E.LOADER_FAILED)
    assert len(spy.calls) == 1


@pytest.mark.parametrize("kind", ("source", "handoff"))
@pytest.mark.parametrize("failure_kind", ("ordinary", "source", "handoff"))
def test_constructor_faults_are_result_refusal_even_for_lower_fixed_errors(
    kind: str, failure_kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    candidate: Any = (
        loader.DisabledBootstrapSourceRefusal(S.CAPTURE, R.INPUT_UNVERIFIABLE)
        if kind == "source"
        else _diagnostic()
    )
    spy = _Spy(monkeypatch, candidate)
    configured = _bind()
    failure = RuntimeError(CANARY) if failure_kind == "ordinary" else _fixed_error(failure_kind)

    def fail(self: Any) -> None:
        raise failure

    monkeypatch.setattr(type(candidate), "__post_init__", fail)
    _refused(configured.diagnose("synthetic-pair"), E.LOADER_RESULT_UNVERIFIABLE)
    assert len(spy.calls) == 1


@pytest.mark.parametrize("ambient", ("ordinary", "except", "finally"))
def test_new_fixed_error_clears_only_its_own_links(
    ambient: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    original = RuntimeError(CANARY)
    original.add_note(CANARY)
    cause = ValueError("CALLER_CAUSE")
    original.__cause__ = cause
    snapshot = (original.args, original.__notes__[:], original.__cause__, original.__context__)
    failure = RuntimeError(CANARY)

    def fail(self: Any) -> None:
        raise failure

    monkeypatch.setattr(entry.DisabledBootstrapEntryRefusal, "__post_init__", fail)

    def invoke() -> Any:
        with pytest.raises(entry.DisabledBootstrapEntryResultError) as caught:
            entry.SyntheticDisabledBootstrapEntry().diagnose(_Poison())
        return caught.value

    if ambient == "except":
        try:
            raise original
        except RuntimeError:
            result = invoke()
    elif ambient == "finally":
        try:
            try:
                raise original
            finally:
                result = invoke()
        except RuntimeError as caught_original:
            assert caught_original is original
    else:
        result = invoke()
    assert result.args == ("Disabled bootstrap entry result construction failed",)
    assert result.__cause__ is None and result.__context__ is None
    assert result.reuse_authorized is False and not getattr(result, "__notes__", [])
    assert CANARY not in repr(result) and CANARY not in str(result)
    assert (original.args, original.__notes__, original.__cause__, original.__context__) == snapshot
    assert capsys.readouterr() == ("", "")


@pytest.mark.parametrize(
    "stage", ("capture", "entry-construction", "plan", "request", "loader", "result", "refusal")
)
def test_cancellation_is_not_converted_or_mutated(
    stage: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    cancel = _Cancel(CANARY)
    cancel.add_note(CANARY)
    cause = RuntimeError("CANCEL_CAUSE")
    cancel.__cause__ = cause
    before = (cancel.args, cancel.__notes__[:], cancel.__cause__, cancel.__context__)
    configured = _bind()
    spy = _Spy(monkeypatch)

    def fail(*args: Any, **kwargs: Any) -> Any:
        raise cancel

    def diagnose() -> Any:
        return configured.diagnose("synthetic-pair")

    def unconfigured() -> Any:
        return entry.SyntheticDisabledBootstrapEntry().diagnose(_Poison())

    if stage == "capture":
        monkeypatch.setattr(entry, "_capture_plan", fail)
        invoke = _bind
    elif stage == "entry-construction":
        monkeypatch.setattr(entry.SyntheticDisabledBootstrapEntry, "__init__", fail)
        invoke = _bind
    elif stage == "plan":
        monkeypatch.setattr(entry, "_checked_plan", fail)
        invoke = diagnose
    elif stage == "request":
        real_pair = entry._pair_ref
        pair_calls: list[str] = []

        def request_fail(value: object) -> str:
            pair_calls.append("pair")
            if len(pair_calls) == 2:
                raise cancel
            return real_pair(value)

        monkeypatch.setattr(entry, "_pair_ref", request_fail)
        invoke = diagnose
    elif stage == "loader":
        monkeypatch.setattr(entry, "load_synthetic_disabled_bootstrap", fail)
        invoke = diagnose
    elif stage == "result":
        monkeypatch.setattr(entry, "_copy_diagnostic", fail)
        invoke = diagnose
    else:
        monkeypatch.setattr(entry.DisabledBootstrapEntryRefusal, "__post_init__", fail)
        invoke = unconfigured
    with pytest.raises(_Cancel) as caught:
        invoke()
    assert caught.value is cancel
    assert (cancel.args, cancel.__notes__, cancel.__cause__, cancel.__context__) == before
    assert len(spy.calls) == int(stage == "result")


def test_repr_and_public_diagnostics_do_not_disclose_retained_values(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    values = _values()
    for role in ROLES:
        values[role] = "b" * 64 if role == "descriptor_pin" else CANARY + "_" + role
    configured = _bind_values(values)
    spy = _Spy(monkeypatch, RuntimeError(CANARY))
    result = configured.diagnose(values["pair_ref"])
    _refused(result, E.LOADER_FAILED)
    assert all(
        value not in repr(target)
        for value in values.values()
        for target in (configured, configured._plan, configured._plan.expectation, result)
    )
    assert capsys.readouterr() == ("", "") and len(spy.calls) == 1


def _forbid_effects(monkeypatch: pytest.MonkeyPatch, *, direct_only: bool = False) -> list[str]:
    """Deny mutation entry points without breaking legitimate lower reader/lock calls."""
    effects: list[str] = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        effects.append("FORBIDDEN_EFFECT")
        raise _UnexpectedEffect("forbidden synthetic entry effect")

    for name in (
        "read_sensitive_bytes",
        "atomic_write_private_text",
        "atomic_write_private_json",
        "remove_sensitive_file_if_matches",
    ):
        monkeypatch.setattr(sensitive_paths, name, forbidden)
    for name in (
        "prepare_synthetic_enrollment",
        "_preflight",
        "_publish",
        "validate_sensitive_output_path",
    ):
        monkeypatch.setattr(prep, name, forbidden)
    monkeypatch.setattr(prep.private_create, "create_posix_private_bytes", forbidden)
    if direct_only:
        monkeypatch.setattr(loader, "read_private_sensitive_bytes", forbidden)
        monkeypatch.setattr(loader, "_lstat", forbidden)
        monkeypatch.setattr(prep, "_inspection_lstat", forbidden)
        monkeypatch.setattr(prep.private_lock, "acquire_posix_private_directory_lock", forbidden)
    return effects


def test_pure_setup_request_and_mock_delegation_have_zero_forbidden_effects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _forbid_effects(monkeypatch, direct_only=True)
    spy = _Spy(monkeypatch)
    _refused(entry.SyntheticDisabledBootstrapEntry().diagnose(_Poison()), E.CONFIGURATION_REQUIRED)
    configured = _bind()
    _refused(configured.diagnose(_Poison()), E.REQUEST_UNVERIFIABLE)
    _refused(configured.diagnose("wrong-pair"), E.PAIR_MISMATCH)
    result = configured.diagnose("synthetic-pair")
    assert result.reuse_authorized is False and len(spy.calls) == 1 and effects == []


@WINDOWS_ONLY
def test_windows_valid_request_reaches_real_loader_once_without_source_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _forbid_effects(monkeypatch, direct_only=True)
    real = entry.load_synthetic_disabled_bootstrap
    calls: list[str] = []

    def invoke(*args: Any, **kwargs: Any) -> Any:
        calls.append("loader")
        return real(*args, **kwargs)

    monkeypatch.setattr(entry, "load_synthetic_disabled_bootstrap", invoke)
    monkeypatch.setattr(loader, "inspect_synthetic_disabled_bootstrap", _deny)
    configured = _bind()
    assert calls == []
    result = configured.diagnose("synthetic-pair")
    assert type(result) is loader.DisabledBootstrapSourceRefusal
    assert (result.stage, result.reason) == (S.PLATFORM, R.UNSUPPORTED_PLATFORM)
    assert result.reuse_authorized is False and calls == ["loader"] and effects == []


def _private_file(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)


def _native_fixture(
    tmp_path: Path, case: str = "both"
) -> tuple[Path, Path, Path, descriptor.SyntheticEnrollmentExpectation]:
    source, control, pair = (
        tmp_path / name for name in ("entry-source", "entry-control", "entry-pair")
    )
    for root in (source, control, pair):
        root.mkdir(mode=0o700)
        root.chmod(0o700)
    policy, raw, expected = _materials(str(control), str(pair))
    _private_file(source / POLICY, policy)
    _private_file(source / COMPANION, raw)
    if case in {"pending", "both", "conflict"}:
        pending = _wire(
            {
                "format_version": 1,
                "record_kind": "enrollment_preparation",
                "target_revision": "different-revision" if case == "conflict" else "revision-one",
                "target_pin": hashlib.sha256(raw).hexdigest(),
                "outcome": "pending",
            }
        )
        _private_file(control / PENDING, pending)
    if case in {"descriptor", "both", "conflict"}:
        _private_file(control / DESCRIPTOR, raw)
    return source, control, pair, expected


def _fingerprint(root: Path) -> dict[str, tuple[object, ...]]:
    """Only owned synthetic fixtures; atime is intentionally outside the assertion."""
    return {
        path.name: (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
            path.read_bytes() if stat.S_ISREG(info.st_mode) else None,
        )
        for path in root.iterdir()
        for info in (path.lstat(),)
    }


def _native_bind(
    source: Path, control: Path, expected: descriptor.SyntheticEnrollmentExpectation
) -> Any:
    return entry.bind_synthetic_disabled_bootstrap(
        str(source), POLICY, COMPANION, expected, expected_control_root=str(control)
    )


@LINUX_ONLY
@pytest.mark.parametrize(
    "case,state",
    (
        ("empty", IS.ABSENCE_UNVERIFIABLE),
        ("pending", IS.ADMIN_PENDING),
        ("descriptor", IS.ORPHAN_DESCRIPTOR),
        ("both", IS.PREPARATION_RETAINED_UNAPPROVED),
        ("conflict", IS.PREPARATION_CONFLICT),
    ),
)
def test_linux_real_entry_loader_handoff_preserve_owned_sources_and_targets(
    case: str,
    state: IS,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, control, pair, expected = _native_fixture(tmp_path, case)
    before = tuple(_fingerprint(root) for root in (source, control, pair))
    effects = _forbid_effects(monkeypatch)
    calls: list[str] = []
    real_loader = entry.load_synthetic_disabled_bootstrap
    real_read, real_handoff = (
        loader.read_private_sensitive_bytes,
        loader.inspect_synthetic_disabled_bootstrap,
    )

    def read(path: Path, *, max_size: int) -> bytes:
        calls.append("source-read")
        return real_read(path, max_size=max_size)

    def inspect_once(*args: Any, **kwargs: Any) -> Any:
        calls.append("handoff")
        assert calls.count("source-read") == 2
        return real_handoff(*args, **kwargs)

    def invoke(*args: Any, **kwargs: Any) -> Any:
        calls.append("loader")
        return real_loader(*args, **kwargs)

    monkeypatch.setattr(entry, "load_synthetic_disabled_bootstrap", invoke)
    monkeypatch.setattr(loader, "read_private_sensitive_bytes", read)
    monkeypatch.setattr(loader, "inspect_synthetic_disabled_bootstrap", inspect_once)
    configured = _native_bind(source, control, expected)
    assert type(configured) is entry.SyntheticDisabledBootstrapEntry and calls == []
    result = configured.diagnose("synthetic-pair")
    assert result.state is H.INSPECTION_OBSERVED and result.reuse_authorized is False
    assert result.inspection_result.state is state
    assert result.inspection_result.verification_complete
    assert calls == ["loader", "source-read", "source-read", "handoff"]
    assert effects == [] and tuple(_fingerprint(root) for root in (source, control, pair)) == before


@LINUX_ONLY
@pytest.mark.parametrize("kind", ("missing-source", "unsafe-source-mode"))
def test_linux_source_refusal_is_preserved_without_target_observation(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, control, pair, expected = _native_fixture(tmp_path)
    # These are fixture faults before the measured entry call.
    if kind == "missing-source":
        (source / POLICY).unlink()
    else:
        (source / POLICY).chmod(0o644)
    before = tuple(_fingerprint(root) for root in (source, control, pair))
    effects = _forbid_effects(monkeypatch)
    monkeypatch.setattr(loader, "inspect_synthetic_disabled_bootstrap", _deny)
    monkeypatch.setattr(prep, "_inspection_lstat", _deny)
    configured = _native_bind(source, control, expected)
    result = configured.diagnose("synthetic-pair")
    assert type(result) is loader.DisabledBootstrapSourceRefusal
    assert (result.stage, result.reason) == (S.PRECHECK, R.SOURCE_UNVERIFIABLE)
    assert result.reuse_authorized is False and effects == []
    assert tuple(_fingerprint(root) for root in (source, control, pair)) == before


@LINUX_ONLY
@pytest.mark.parametrize("kind", ("invalid", "mismatch"))
def test_linux_bad_requests_do_not_access_even_existing_fixture(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, control, pair, expected = _native_fixture(tmp_path)
    before = tuple(_fingerprint(root) for root in (source, control, pair))
    effects = _forbid_effects(monkeypatch, direct_only=True)
    monkeypatch.setattr(entry, "load_synthetic_disabled_bootstrap", _deny)
    configured = _native_bind(source, control, expected)
    request = _Poison() if kind == "invalid" else "other-pair"
    _refused(
        configured.diagnose(request),
        E.REQUEST_UNVERIFIABLE if kind == "invalid" else E.PAIR_MISMATCH,
    )
    assert effects == [] and tuple(_fingerprint(root) for root in (source, control, pair)) == before


@LINUX_ONLY
def test_linux_explicit_rediagnosis_observes_fixture_fault_without_cached_success(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, control, pair, expected = _native_fixture(tmp_path)
    effects = _forbid_effects(monkeypatch)
    real = entry.load_synthetic_disabled_bootstrap
    calls: list[str] = []

    def invoke(*args: Any, **kwargs: Any) -> Any:
        calls.append("loader")
        return real(*args, **kwargs)

    monkeypatch.setattr(entry, "load_synthetic_disabled_bootstrap", invoke)
    configured = _native_bind(source, control, expected)
    original = configured._plan
    first = configured.diagnose("synthetic-pair")
    assert first.inspection_result.state is IS.PREPARATION_RETAINED_UNAPPROVED
    # Explicit fixture mutation; the entry neither removes nor repairs this file.
    (source / COMPANION).unlink()
    after_injection = tuple(_fingerprint(root) for root in (source, control, pair))
    second = configured.diagnose("synthetic-pair")
    assert type(second) is loader.DisabledBootstrapSourceRefusal
    assert (second.stage, second.reason) == (S.PRECHECK, R.SOURCE_UNVERIFIABLE)
    assert first.reuse_authorized is second.reuse_authorized is False
    assert calls == ["loader", "loader"] and configured._plan is original and effects == []
    assert tuple(_fingerprint(root) for root in (source, control, pair)) == after_injection


@LINUX_ONLY
@pytest.mark.parametrize("case", ("pending", "both"))
def test_linux_fresh_process_binds_independently_supplied_plan(case: str, tmp_path: Path) -> None:
    source, control, pair, _ = _native_fixture(tmp_path, case)
    before = tuple(_fingerprint(root) for root in (source, control, pair))
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(Path(entry.__file__).resolve().parents[1])
    child = subprocess.run(
        [sys.executable, "-B", __file__, "--entry-observe", str(tmp_path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
        check=False,
        env=environment,
    )
    expected = b"ADMIN_PENDING\n" if case == "pending" else b"PREPARATION_RETAINED_UNAPPROVED\n"
    assert child.returncode == 0 and child.stdout == expected and child.stderr == b""
    assert tuple(_fingerprint(root) for root in (source, control, pair)) == before


def _child_main() -> int:
    """Ordinary process setup only, not trusted deployment restart or crash recovery."""
    try:
        if len(sys.argv) != 3 or sys.argv[1] != "--entry-observe" or sys.platform != "linux":
            return 2
        parent = Path(sys.argv[2])
        source, control, pair = (
            parent / name for name in ("entry-source", "entry-control", "entry-pair")
        )
        # Neither source nor observed record supplies configuration to this factory.
        expected = _materials(str(control), str(pair))[2]
        with pytest.MonkeyPatch.context() as scoped:
            effects = _forbid_effects(scoped)
            configured = _native_bind(source, control, expected)
            if type(configured) is not entry.SyntheticDisabledBootstrapEntry:
                return 2
            result = configured.diagnose("synthetic-pair")
            if type(result) is not handoff.DisabledBootstrapInspectionResult:
                return 2
            observed = result.inspection_result
            if (
                effects
                or result.reuse_authorized is not False
                or observed is None
                or not observed.verification_complete
            ):
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


_APPLICATION_IMPORTS = {
    "production_write_token_disabled_bootstrap_source_loading": {
        "load_synthetic_disabled_bootstrap",
        "DisabledBootstrapSourceRefusal",
        "DisabledBootstrapSourceResultError",
    },
    "tridentine_calendar_google_sync.production_write_token_disabled_bootstrap_inspection": {
        "DisabledBootstrapInspectionResult",
        "DisabledBootstrapInspectionResultError",
    },
    "tridentine_calendar_google_sync.production_write_token_enrollment_descriptor": {
        "SyntheticEnrollmentExpectation",
    },
}
_STANDARD_IMPORTS = {
    "__future__": {"annotations"},
    "dataclasses": {"dataclass", "field"},
    "enum": {"StrEnum"},
    "typing": {"Literal"},
}
_NAME_CALLS = {
    "dataclass",
    "field",
    "type",
    "any",
    "ValueError",
    "super",
    "len",
    "getattr",
    "DisabledBootstrapEntryRefusal",
    "DisabledBootstrapEntryResultError",
    "_text",
    "_pair_ref",
    "_pin",
    "SyntheticEnrollmentExpectation",
    "_Plan",
    "_capture_plan",
    "_checked_plan",
    "_copy_diagnostic",
    "_refuse",
    "DisabledBootstrapSourceRefusal",
    "DisabledBootstrapInspectionResult",
    "SyntheticDisabledBootstrapEntry",
    "load_synthetic_disabled_bootstrap",
}
_PARAMETERS = {
    "DisabledBootstrapEntryRefusal.__post_init__": (("self",), ()),
    "DisabledBootstrapEntryResultError.__init__": (("self",), ()),
    "DisabledBootstrapEntryResultError.reuse_authorized": (("self",), ()),
    "_refuse": (("state",), ()),
    "_text": (("value", "limit"), ()),
    "_pair_ref": (("value",), ()),
    "_pin": (("value",), ()),
    "_capture_plan": (
        (
            "source_root",
            "policy_leaf",
            "expected_descriptor_leaf",
            "expectation",
            "expected_control_root",
        ),
        (),
    ),
    "_checked_plan": (("value",), ()),
    "_copy_diagnostic": (("value",), ()),
    "SyntheticDisabledBootstrapEntry.__init__": (("self",), ()),
    "SyntheticDisabledBootstrapEntry.reuse_authorized": (("self",), ()),
    "SyntheticDisabledBootstrapEntry.diagnose": (("self", "requested_pair_ref"), ()),
    "bind_synthetic_disabled_bootstrap": (
        ("source_root", "policy_leaf", "expected_descriptor_leaf", "expectation"),
        ("expected_control_root",),
    ),
}
_ASSIGNMENTS = {
    "_refuse": (
        "failure = DisabledBootstrapEntryResultError()",
        "failure.__cause__ = None",
        "failure.__context__ = None",
    ),
    "_pair_ref": ("text = _text(value, 96)",),
    "_pin": ("text = _text(value, 64)",),
    "_capture_plan": (
        "root = _text(source_root, 1024)",
        "policy = _text(policy_leaf, 96)",
        "companion = _text(expected_descriptor_leaf, 96)",
        "control = _text(expected_control_root, 1024)",
        (
            "values: dict[str, object] = {name: getattr(expectation, name) fo"
            "r name in _EXPECTATION_FIELDS}"
        ),
        (
            'checked = {name: _text(value, 1024 if name == "artifact_director'
            'y" else 96) for name, value in values.items()}'
        ),
        "retained = SyntheticEnrollmentExpectation(**checked)",
    ),
    "_checked_plan": (
        (
            "root, policy, companion, expected, control = (value.source_root,"
            " value.policy_leaf, value.expected_descriptor_leaf, value.expect"
            "ation, value.expected_control_root)"
        ),
    ),
    "_copy_diagnostic": (
        "stage, reason, authorized = value.stage, value.reason, value.reuse_authorized",
        (
            "state, inputs, observation, authorized = (value.state, value.inp"
            "ut_result, value.inspection_result, value.reuse_authorized)"
        ),
    ),
    "SyntheticDisabledBootstrapEntry.diagnose": (
        'held: object = object.__getattribute__(self, "_plan")',
        "held = None",
        "plan = _checked_plan(held)",
        "requested = _pair_ref(requested_pair_ref)",
        (
            "result = load_synthetic_disabled_bootstrap(plan.source_root, pla"
            "n.policy_leaf, plan.expected_descriptor_leaf, plan.expectation, "
            "expected_control_root=plan.expected_control_root)"
        ),
    ),
    "bind_synthetic_disabled_bootstrap": (
        (
            "plan = _capture_plan(source_root, policy_leaf, expected_descript"
            "or_leaf, expectation, expected_control_root)"
        ),
        "entry = SyntheticDisabledBootstrapEntry()",
    ),
}
_COMPREHENSIONS = {
    "DisabledBootstrapEntryRefusal.__post_init__": (
        "(self.state is member for member in DisabledBootstrapEntryState)",
    ),
    "_pair_ref": ('(not (char.isalnum() or char in "._-") for char in text)',),
    "_pin": ('(char not in "0123456789abcdef" for char in text)',),
    "_capture_plan": (
        "{name: getattr(expectation, name) for name in _EXPECTATION_FIELDS}",
        "(type(value) is not str for value in values.values())",
        (
            '{name: _text(value, 1024 if name == "artifact_directory" else 96'
            ") for name, value in values.items()}"
        ),
    ),
}
_DATA_CALLS = {
    "_pair_ref": ("_text(value, 96)",),
    "_pin": ("_text(value, 64)",),
    "_capture_plan": (
        "_text(source_root, 1024)",
        "_text(policy_leaf, 96)",
        "_text(expected_descriptor_leaf, 96)",
        "_text(expected_control_root, 1024)",
        "getattr(expectation, name)",
        '_text(value, 1024 if name == "artifact_directory" else 96)',
        '_pin(checked["descriptor_pin"])',
        '_pair_ref(checked["pair_ref"])',
        "SyntheticEnrollmentExpectation(**checked)",
        "_Plan(root, policy, companion, retained, control)",
    ),
    "_checked_plan": ("_capture_plan(root, policy, companion, expected, control)",),
    "_copy_diagnostic": (
        "DisabledBootstrapSourceRefusal(stage, reason)",
        "DisabledBootstrapInspectionResult(state, inputs, observation)",
    ),
    "SyntheticDisabledBootstrapEntry.diagnose": (
        "_checked_plan(held)",
        "_pair_ref(requested_pair_ref)",
        (
            "load_synthetic_disabled_bootstrap(plan.source_root, plan.policy_"
            "leaf, plan.expected_descriptor_leaf, plan.expectation, expected_"
            "control_root=plan.expected_control_root)"
        ),
        "_copy_diagnostic(result)",
    ),
    "bind_synthetic_disabled_bootstrap": (
        (
            "_capture_plan(source_root, policy_leaf, expected_descriptor_leaf"
            ", expectation, expected_control_root)"
        ),
        "SyntheticDisabledBootstrapEntry()",
    ),
}
_ATTRIBUTE_CALLS = {
    "DisabledBootstrapEntryResultError.__init__": (
        'super().__init__("Disabled bootstrap entry result construction failed")',
    ),
    "_text": ('value.encode("utf-8")',),
    "_pair_ref": ("text.isascii()", "text[0].isalnum()", "char.isalnum()"),
    "_capture_plan": ("values.values()", "values.items()"),
    "SyntheticDisabledBootstrapEntry.__init__": (
        'object.__getattribute__(self, "_plan")',
        'object.__setattr__(self, "_plan", None)',
    ),
    "SyntheticDisabledBootstrapEntry.diagnose": ('object.__getattribute__(self, "_plan")',),
    "bind_synthetic_disabled_bootstrap": ('object.__setattr__(entry, "_plan", plan)',),
}


_ATTRIBUTE_LOADS = {
    "DisabledBootstrapEntryRefusal.__post_init__": (
        "self.state",
        "self.state",
        "self.reuse_authorized",
    ),
    "DisabledBootstrapEntryResultError.__init__": ("super().__init__",),
    "_text": ("value.encode",),
    "_pair_ref": ("text.isascii", "text[0].isalnum", "char.isalnum"),
    "_capture_plan": ("values.values", "values.items"),
    "_checked_plan": (
        "value.source_root",
        "value.policy_leaf",
        "value.expected_descriptor_leaf",
        "value.expectation",
        "value.expected_control_root",
    ),
    "_copy_diagnostic": (
        "value.stage",
        "value.reason",
        "value.reuse_authorized",
        "value.state",
        "value.input_result",
        "value.inspection_result",
        "value.reuse_authorized",
    ),
    "SyntheticDisabledBootstrapEntry.__init__": (
        "object.__getattribute__",
        "object.__setattr__",
    ),
    "SyntheticDisabledBootstrapEntry.diagnose": (
        "object.__getattribute__",
        "plan.expectation.pair_ref",
        "plan.expectation",
        "plan.source_root",
        "plan.policy_leaf",
        "plan.expected_descriptor_leaf",
        "plan.expectation",
        "plan.expected_control_root",
        "DisabledBootstrapEntryState.CONFIGURATION_UNVERIFIABLE",
        "DisabledBootstrapEntryState.CONFIGURATION_UNVERIFIABLE",
        "DisabledBootstrapEntryState.CONFIGURATION_UNVERIFIABLE",
        "DisabledBootstrapEntryState.CONFIGURATION_REQUIRED",
        "DisabledBootstrapEntryState.REQUEST_UNVERIFIABLE",
        "DisabledBootstrapEntryState.PAIR_MISMATCH",
        "DisabledBootstrapEntryState.LOADER_FAILED",
        "DisabledBootstrapEntryState.LOADER_FAILED",
        "DisabledBootstrapEntryState.LOADER_RESULT_UNVERIFIABLE",
    ),
    "bind_synthetic_disabled_bootstrap": (
        "object.__setattr__",
        "DisabledBootstrapEntryState.CONFIGURATION_UNVERIFIABLE",
    ),
}


_PURE_CALLS = {
    "": (
        "dataclass(frozen=True, slots=True)",
        "dataclass(frozen=True, slots=True)",
        "dataclass(frozen=True, slots=True, init=False)",
        "field(default=False, init=False)",
        "field(repr=False)",
        "field(repr=False)",
        "field(repr=False)",
        "field(repr=False)",
        "field(repr=False)",
        "field(init=False, repr=False)",
    ),
    "DisabledBootstrapEntryRefusal.__post_init__": (
        'ValueError("Invalid disabled bootstrap entry refusal")',
        "type(self.state)",
        "any(self.state is member for member in DisabledBootstrapEntryState)",
    ),
    "DisabledBootstrapEntryResultError.__init__": ("super()",),
    "_refuse": (
        "DisabledBootstrapEntryRefusal(state)",
        "DisabledBootstrapEntryResultError()",
    ),
    "_text": (
        "type(value)",
        "len(value)",
        'len(value.encode("utf-8"))',
        'ValueError("Invalid synthetic entry configuration")',
        'ValueError("Invalid synthetic entry configuration")',
    ),
    "_pair_ref": (
        'any(not (char.isalnum() or char in "._-") for char in text)',
        'ValueError("Invalid synthetic entry pair reference")',
    ),
    "_pin": (
        "len(text)",
        'any(char not in "0123456789abcdef" for char in text)',
        'ValueError("Invalid synthetic entry pin")',
    ),
    "_capture_plan": (
        "type(expectation)",
        "type(value)",
        "any(type(value) is not str for value in values.values())",
        'ValueError("Invalid synthetic entry expectation")',
        'ValueError("Invalid synthetic entry expectation")',
    ),
    "_checked_plan": (
        "type(value)",
        'ValueError("Invalid retained synthetic entry plan")',
    ),
    "_copy_diagnostic": (
        "type(value)",
        "type(value)",
        'ValueError("Invalid synthetic entry diagnostic")',
        'ValueError("Invalid synthetic entry diagnostic")',
        'ValueError("Invalid synthetic entry diagnostic")',
    ),
    "SyntheticDisabledBootstrapEntry.__init__": (
        "type(self)",
        'ValueError("Invalid synthetic disabled bootstrap entry")',
        'ValueError("Synthetic disabled bootstrap entry is already initialized")',
    ),
    "SyntheticDisabledBootstrapEntry.diagnose": (
        "type(self)",
        "type(error)",
        "type(error)",
        "_refuse(DisabledBootstrapEntryState.CONFIGURATION_UNVERIFIABLE)",
        "_refuse(DisabledBootstrapEntryState.CONFIGURATION_UNVERIFIABLE)",
        "_refuse(DisabledBootstrapEntryState.CONFIGURATION_UNVERIFIABLE)",
        "_refuse(DisabledBootstrapEntryState.CONFIGURATION_REQUIRED)",
        "_refuse(DisabledBootstrapEntryState.REQUEST_UNVERIFIABLE)",
        "_refuse(DisabledBootstrapEntryState.PAIR_MISMATCH)",
        "_refuse(DisabledBootstrapEntryState.LOADER_FAILED)",
        "_refuse(DisabledBootstrapEntryState.LOADER_FAILED)",
        "_refuse(DisabledBootstrapEntryState.LOADER_RESULT_UNVERIFIABLE)",
    ),
    "bind_synthetic_disabled_bootstrap": (
        "_refuse(DisabledBootstrapEntryState.CONFIGURATION_UNVERIFIABLE)",
    ),
}
_SUBSCRIPTS = {
    "": ("Literal[False]",),
    "DisabledBootstrapEntryResultError.reuse_authorized": ("Literal[False]",),
    "SyntheticDisabledBootstrapEntry.reuse_authorized": ("Literal[False]",),
    "_pair_ref": ("text[0]",),
    "_capture_plan": (
        "dict[str, object]",
        'checked["descriptor_pin"]',
        'checked["pair_ref"]',
    ),
}


def _expression(value: str) -> str:
    return ast.dump(ast.parse(value, mode="eval").body, include_attributes=False)


def _statement(value: str) -> str:
    return ast.dump(ast.parse(value).body[0], include_attributes=False)


def _check_closed_entry(source: str) -> set[str]:
    """Close this entry's reviewed syntax and effect origins, not arbitrary Python."""
    tree = ast.parse(source)
    top_level = {id(node) for node in tree.body}
    imports: dict[str, set[str]] = {}
    imported: set[str] = set()
    for node in ast.walk(tree):
        assert not isinstance(node, ast.Import)
        if isinstance(node, ast.ImportFrom):
            assert id(node) in top_level and node.module is not None
            assert node.level == int(
                node.module == "production_write_token_disabled_bootstrap_source_loading"
            )
            assert node.module not in imports
            assert all(item.asname is None and item.name != "*" for item in node.names)
            names = {item.name for item in node.names}
            assert len(names) == len(node.names) and not imported.intersection(names)
            imported.update(names)
            imports[node.module] = names
    assert imports == _APPLICATION_IMPORTS | _STANDARD_IMPORTS

    classes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    class_specs = {
        "DisabledBootstrapEntryState": (
            "StrEnum",
            (),
            tuple(f'{state.name} = "{state.value}"' for state in E),
        ),
        "DisabledBootstrapEntryRefusal": (
            None,
            ("dataclass(frozen=True, slots=True)",),
            (
                "state: DisabledBootstrapEntryState",
                "reuse_authorized: Literal[False] = field(default=False, init=False)",
            ),
        ),
        "DisabledBootstrapEntryResultError": ("RuntimeError", (), ("__slots__ = ()",)),
        "_Plan": (
            None,
            ("dataclass(frozen=True, slots=True)",),
            (
                "source_root: str = field(repr=False)",
                "policy_leaf: str = field(repr=False)",
                "expected_descriptor_leaf: str = field(repr=False)",
                "expectation: SyntheticEnrollmentExpectation = field(repr=False)",
                "expected_control_root: str = field(repr=False)",
            ),
        ),
        "SyntheticDisabledBootstrapEntry": (
            None,
            ("dataclass(frozen=True, slots=True, init=False)",),
            ("_plan: _Plan | None = field(init=False, repr=False)",),
        ),
    }
    assert len(classes) == len(class_specs) and {node.name for node in classes} == set(class_specs)
    declaration_stores: set[int] = set()
    functions: dict[str, ast.FunctionDef] = {}
    scopes: dict[int, str] = {}
    for node in classes:
        assert id(node) in top_level and not node.keywords and not node.type_params
        base, decorators, declarations = class_specs[node.name]
        assert [ast.dump(value, include_attributes=False) for value in node.bases] == (
            [] if base is None else [_expression(base)]
        )
        assert [ast.dump(value, include_attributes=False) for value in node.decorator_list] == [
            _expression(value) for value in decorators
        ]
        actual = [child for child in node.body if isinstance(child, (ast.Assign, ast.AnnAssign))]
        assert [ast.dump(value, include_attributes=False) for value in actual] == [
            _statement(value) for value in declarations
        ]
        declaration_stores.update(
            id(child)
            for value in actual
            for child in ast.walk(value)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
        )
        assert all(
            isinstance(child, (ast.Assign, ast.AnnAssign, ast.FunctionDef))
            or (
                isinstance(child, ast.Expr)
                and isinstance(child.value, ast.Constant)
                and type(child.value.value) is str
            )
            for child in node.body
        )
    for owner in (tree, *classes):
        prefix = "" if isinstance(owner, ast.Module) else owner.name + "."
        for node in owner.body:
            if isinstance(node, ast.FunctionDef):
                key = prefix + node.name
                assert key not in functions
                functions[key] = node
                scopes.update((id(child), key) for child in ast.walk(node))
    assert set(functions) == set(_PARAMETERS)
    assert len(functions) == sum(isinstance(node, ast.FunctionDef) for node in ast.walk(tree))
    for scope, node in functions.items():
        assert not node.type_params and not node.args.posonlyargs
        assert node.args.vararg is None and node.args.kwarg is None and not node.args.defaults
        assert all(value is None for value in node.args.kw_defaults)
        assert (
            tuple(value.arg for value in node.args.args),
            tuple(value.arg for value in node.args.kwonlyargs),
        ) == _PARAMETERS[scope]
        assert [ast.dump(value, include_attributes=False) for value in node.decorator_list] == (
            [_expression("property")] if scope.endswith(".reuse_authorized") else []
        )

    assignments = [node for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))]
    assert len(assignments) == 1
    assert isinstance(assignments[0], ast.Assign)
    assert [ast.dump(value, include_attributes=False) for value in assignments[0].targets] == [
        _expression("_EXPECTATION_FIELDS").replace("Load()", "Store()")
    ]
    assert ast.literal_eval(assignments[0].value) == EXPECTATION_FIELDS
    declaration_stores.update(
        id(node)
        for node in ast.walk(assignments[0])
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store)
    )
    assert all(
        isinstance(node, (ast.ImportFrom, ast.ClassDef, ast.FunctionDef, ast.Assign))
        or (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and type(node.value.value) is str
        )
        for node in tree.body
    )

    permitted_stores = set(declaration_stores)
    for scope, fn in functions.items():
        actual = [node for node in ast.walk(fn) if isinstance(node, (ast.Assign, ast.AnnAssign))]
        assert sorted(ast.dump(node, include_attributes=False) for node in actual) == sorted(
            _statement(value) for value in _ASSIGNMENTS.get(scope, ())
        )
        permitted_stores.update(
            id(child)
            for node in actual
            for child in ast.walk(node)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
        )
        comprehensions = [
            node
            for node in ast.walk(fn)
            if isinstance(node, (ast.GeneratorExp, ast.DictComp, ast.ListComp, ast.SetComp))
        ]
        assert sorted(
            ast.dump(node, include_attributes=False) for node in comprehensions
        ) == sorted(_expression(value) for value in _COMPREHENSIONS.get(scope, ()))
        permitted_stores.update(
            id(child)
            for node in comprehensions
            for child in ast.walk(node)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
        )

    protected = (
        imported
        | _NAME_CALLS
        | {node.name for node in classes}
        | {"object", "Exception", "AttributeError", "_EXPECTATION_FIELDS"}
    )
    blocked = (
        ast.AsyncFunctionDef,
        ast.AsyncFor,
        ast.AsyncWith,
        ast.Await,
        ast.Yield,
        ast.YieldFrom,
        ast.Lambda,
        ast.Global,
        ast.Nonlocal,
        ast.With,
        ast.While,
        ast.For,
        ast.TryStar,
        ast.NamedExpr,
        ast.Delete,
        ast.AugAssign,
        ast.Match,
        ast.JoinedStr,
        ast.FormattedValue,
    )
    calls: set[str] = set()
    data_names = {
        ast.parse(value, mode="eval").body.func.id
        for values in _DATA_CALLS.values()
        for value in values
    }
    data_calls: list[tuple[str, str]] = []
    pure_calls: list[tuple[str, str]] = []
    subscripts: list[tuple[str, str]] = []
    attribute_calls: list[tuple[str, str]] = []
    attribute_loads: list[tuple[str, str]] = []
    for node in ast.walk(tree):
        scope = scopes.get(id(node), "")
        assert not isinstance(node, blocked)
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            assert id(node) in permitted_stores
            assert node.id not in protected or id(node) in declaration_stores
        if isinstance(node, ast.arg):
            assert node.arg not in protected
        if isinstance(node, ast.ExceptHandler):
            if node.name is not None:
                assert scope == "SyntheticDisabledBootstrapEntry.diagnose" and node.name == "error"
                assert ast.dump(node.type, include_attributes=False) == _expression(
                    "(DisabledBootstrapSourceResultError, DisabledBootstrapInspectionResultError)"
                )
            else:
                assert isinstance(node.type, ast.Name)
                assert node.type.id in {
                    "Exception",
                    "AttributeError",
                    "DisabledBootstrapEntryResultError",
                }
        if isinstance(node, ast.comprehension):
            assert node.is_async == 0
        if isinstance(node, ast.Subscript):
            assert isinstance(node.ctx, ast.Load)
            subscripts.append((scope, ast.dump(node, include_attributes=False)))
        if isinstance(node, ast.Attribute):
            if isinstance(node.ctx, ast.Store):
                assert scope == "_refuse" and isinstance(node.value, ast.Name)
                assert node.value.id == "failure" and node.attr in {"__cause__", "__context__"}
            else:
                assert isinstance(node.ctx, ast.Load)
                attribute_loads.append((scope, ast.dump(node, include_attributes=False)))
                if node.attr.startswith("__"):
                    assert ast.dump(node, include_attributes=False) in {
                        _expression("object.__getattribute__"),
                        _expression("object.__setattr__"),
                        _expression("super().__init__"),
                    }
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                assert node.func.id in _NAME_CALLS
                calls.add(node.func.id)
                if node.func.id in data_names:
                    data_calls.append((scope, ast.dump(node, include_attributes=False)))
                else:
                    pure_calls.append((scope, ast.dump(node, include_attributes=False)))
            else:
                assert isinstance(node.func, ast.Attribute)
                attribute_calls.append((scope, ast.dump(node, include_attributes=False)))
    assert calls == _NAME_CALLS
    assert sorted(pure_calls) == sorted(
        (scope, _expression(value)) for scope, values in _PURE_CALLS.items() for value in values
    )
    assert sorted(subscripts) == sorted(
        (scope, _expression(value)) for scope, values in _SUBSCRIPTS.items() for value in values
    )
    assert sorted(attribute_loads) == sorted(
        (scope, _expression(value))
        for scope, values in _ATTRIBUTE_LOADS.items()
        for value in values
    )
    assert sorted(data_calls) == sorted(
        (scope, _expression(value)) for scope, values in _DATA_CALLS.items() for value in values
    )
    assert sorted(attribute_calls) == sorted(
        (scope, _expression(value))
        for scope, values in _ATTRIBUTE_CALLS.items()
        for value in values
    )
    diagnose = functions["SyntheticDisabledBootstrapEntry.diagnose"]
    assert any(
        isinstance(node, ast.Compare)
        and ast.dump(node, include_attributes=False)
        == _expression("requested != plan.expectation.pair_ref")
        for node in ast.walk(diagnose)
    )
    assert any(
        isinstance(node, ast.Compare)
        and ast.dump(node, include_attributes=False) == _expression("held is None")
        for node in ast.walk(diagnose)
    )
    return calls


def test_closed_entry_dependencies_bindings_effect_arguments_and_no_runtime_consumer() -> None:
    source = Path(entry.__file__).read_text(encoding="utf-8")
    assert _check_closed_entry(source) == _NAME_CALLS
    package = Path(entry.__file__).parent
    consumers = {
        path.name
        for path in package.rglob("*.py")
        if path.name != Path(entry.__file__).name
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, (ast.Import, ast.ImportFrom))
        and (
            (
                isinstance(node, ast.ImportFrom)
                and "production_write_token_disabled_bootstrap_entry" in (node.module or "")
            )
            or any(
                "production_write_token_disabled_bootstrap_entry" in value.name
                for value in node.names
            )
        )
    }
    assert consumers == set()


def _mutant(case: str) -> str:
    """Transform an AST copy only; never compile/execute it or mutate a dependency."""
    tree = ast.parse(Path(entry.__file__).read_text(encoding="utf-8"))
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    cls = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "SyntheticDisabledBootstrapEntry"
    )
    diagnose = next(
        node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "diagnose"
    )
    additions = {
        "protected-assign": "load_synthetic_disabled_bootstrap = print",
        "protected-annassign": "load_synthetic_disabled_bootstrap: object = print",
        "protected-unpack": "load_synthetic_disabled_bootstrap, extra = (print, None)",
        "protected-for": "for load_synthetic_disabled_bootstrap in ():\n    pass",
        "protected-comprehension": "[value for load_synthetic_disabled_bootstrap in ()]",
        ("protected-except"): (
            "try:\n    pass\nexcept Exception as load_synthetic_disabled_bootstrap:\n    pass"
        ),
        "match-binding": "match None:\n    case load_synthetic_disabled_bootstrap:\n        pass",
        ("direct-namespace"): (
            'load_synthetic_disabled_bootstrap.__globals__["read_private_sensitive_bytes"] = print'
        ),
        ("alias-namespace"): (
            "namespace = load_synthetic_disabled_bootstrap.__globals__\nnamesp"
            'ace["read_private_sensitive_bytes"] = print'
        ),
        "item-store": 'values["pair_ref"] = "other"',
        "item-delete": 'del values["pair_ref"]',
        "attribute-store": "plan.expectation = expectation",
        "dynamic-dispatch": 'getattr(load_synthetic_disabled_bootstrap, "__globals__")',
        "constructor-hidden-call": "print(value)",
        "hidden-attribute-read": "plan.expectation.secret",
        ("extra-loader-call"): (
            "load_synthetic_disabled_bootstrap(plan.source_root, plan.policy_"
            "leaf, plan.expected_descriptor_leaf, plan.expectation, expected_"
            "control_root=plan.expected_control_root)"
        ),
    }
    if case in additions:
        destination = functions["_capture_plan"] if case == "constructor-hidden-call" else diagnose
        destination.body[1:1] = ast.parse(additions[case]).body
    elif case == "protected-argument":
        diagnose.args.args.append(ast.arg(arg="load_synthetic_disabled_bootstrap"))
    elif case == "duplicate-import":
        tree.body.append(ast.parse("from typing import Literal").body[0])
    elif case == "nested-import":
        diagnose.body.insert(0, ast.parse("from typing import Literal").body[0])
    elif case == "aliased-import":
        next(
            node
            for node in tree.body
            if isinstance(node, ast.ImportFrom) and node.module == "typing"
        ).names[0].asname = "Different"
    elif case == "duplicate-class":
        tree.body.insert(0, ast.parse("@print\nclass _Plan:\n    pass").body[0])
    elif case == "duplicate-function":
        tree.body.append(ast.parse("def _pin(value):\n    return value").body[0])
    elif case == "decorator":
        diagnose.decorator_list.append(ast.Name(id="print", ctx=ast.Load()))
    elif case == "capture-field-list":
        assignment = next(node for node in tree.body if isinstance(node, ast.Assign))
        assignment.value = ast.parse("('__globals__',)", mode="eval").body
    elif case == "capture-receiver":
        getter = next(
            node
            for node in ast.walk(functions["_capture_plan"])
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
        )
        getter.args[0] = ast.Name(id="load_synthetic_disabled_bootstrap", ctx=ast.Load())
    elif case == "duplicate-getter":
        functions["_capture_plan"].body.insert(
            0,
            ast.parse("{name: getattr(expectation, name) for name in _EXPECTATION_FIELDS}").body[0],
        )
    elif case in {"wrong-plan-target", "wrong-plan-value", "wrong-plan-field"}:
        setter = next(
            node
            for node in ast.walk(functions["bind_synthetic_disabled_bootstrap"])
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "__setattr__"
        )
        index = {"wrong-plan-target": 0, "wrong-plan-field": 1, "wrong-plan-value": 2}[case]
        setter.args[index] = ast.parse('"other"' if index == 1 else "expectation", mode="eval").body
    elif case == "wrong-exception-owner":
        assignment = next(
            node
            for node in ast.walk(functions["_refuse"])
            if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Attribute)
        )
        assignment.targets[0].value = ast.Name(id="error", ctx=ast.Load())
    elif case == "wrong-loader-origin":
        call = next(
            node
            for node in ast.walk(diagnose)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "load_synthetic_disabled_bootstrap"
        )
        call.args[0] = ast.Name(id="requested_pair_ref", ctx=ast.Load())
    elif case == "wrong-pair-origin":
        compare = next(
            node
            for node in ast.walk(diagnose)
            if isinstance(node, ast.Compare)
            and ast.dump(node, include_attributes=False)
            == _expression("requested != plan.expectation.pair_ref")
        )
        compare.comparators[0] = ast.Name(id="requested", ctx=ast.Load())
    else:
        raise AssertionError("unknown synthetic entry mutation")
    return ast.unparse(tree)


@pytest.mark.parametrize(
    "case",
    (
        "protected-assign",
        "protected-annassign",
        "protected-unpack",
        "protected-for",
        "protected-comprehension",
        "protected-except",
        "match-binding",
        "direct-namespace",
        "alias-namespace",
        "item-store",
        "item-delete",
        "attribute-store",
        "dynamic-dispatch",
        "constructor-hidden-call",
        "hidden-attribute-read",
        "extra-loader-call",
        "protected-argument",
        "duplicate-import",
        "nested-import",
        "aliased-import",
        "duplicate-class",
        "duplicate-function",
        "decorator",
        "capture-field-list",
        "capture-receiver",
        "duplicate-getter",
        "wrong-plan-target",
        "wrong-plan-value",
        "wrong-plan-field",
        "wrong-exception-owner",
        "wrong-loader-origin",
        "wrong-pair-origin",
    ),
)
def test_closed_checker_refuses_binding_namespace_dispatch_and_origin_escapes(case: str) -> None:
    with pytest.raises(AssertionError):
        _check_closed_entry(_mutant(case))


def test_closed_checker_preserves_loads_and_exact_reviewed_call_set() -> None:
    source = Path(entry.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    loads = [node for node in ast.walk(tree) if isinstance(node, ast.Subscript)]
    assert loads and all(isinstance(node.ctx, ast.Load) for node in loads)
    assert _check_closed_entry(ast.unparse(tree)) == _NAME_CALLS


@pytest.mark.parametrize("kind", ("source", "handoff"))
def test_fixed_error_subclass_metaclass_equality_hook_is_never_called(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class HostileType(type):
        __eq__ = _deny

    parent = (
        loader.DisabledBootstrapSourceResultError
        if kind == "source"
        else handoff.DisabledBootstrapInspectionResultError
    )

    class Child(parent, metaclass=HostileType):
        pass

    spy = _Spy(monkeypatch, Child())
    _refused(_bind().diagnose("synthetic-pair"), E.LOADER_FAILED)
    assert len(spy.calls) == 1


@pytest.mark.parametrize(
    "statement",
    (
        "requested_pair_ref[0]",
        'f"{requested_pair_ref}"',
        "len(requested_pair_ref)",
        "raise ValueError(requested_pair_ref)",
    ),
    ids=("unknown-subscript", "input-formatting", "unknown-length", "input-exception-payload"),
)
def test_closed_checker_rejects_implicit_input_hooks(statement: str) -> None:
    """Only an AST copy is changed; no unknown input hook is actually invoked."""
    tree = ast.parse(Path(entry.__file__).read_text(encoding="utf-8"))
    cls = next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "SyntheticDisabledBootstrapEntry"
    )
    diagnose = next(
        node for node in cls.body if isinstance(node, ast.FunctionDef) and node.name == "diagnose"
    )
    diagnose.body[0:0] = ast.parse(statement).body
    with pytest.raises(AssertionError):
        _check_closed_entry(ast.unparse(tree))


if __name__ == "__main__":
    raise SystemExit(_child_main())
