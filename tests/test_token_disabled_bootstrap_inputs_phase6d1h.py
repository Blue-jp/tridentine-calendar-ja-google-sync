"""Pure synthetic policy comparisons never establish deployment or use authority."""

from __future__ import annotations

import ast
import builtins
import hashlib
import inspect
import json
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tridentine_calendar_google_sync import (
    production_write_token_disabled_bootstrap_inputs as model,
)
from tridentine_calendar_google_sync import (
    production_write_token_enrollment_descriptor as descriptor,
)

S = model.DisabledBootstrapInputState
D = descriptor.EnrollmentDescriptorState
ROOT = "/synthetic/control"
EXPECTED_RAW = (
    b'{"active_intent_slot":"intent.json","administrative_state":"PREPARING",'
    b'"artifact_directory":"/synthetic/pair","enrollment_revision":"revision-one",'
    b'"format_version":1,"pair_ref":"pair-one","record_kind":"enrollment_descriptor",'
    b'"record_slot":"production-write-operation-start-v1.json","role":"production_write",'
    b'"state_slot":"state.json","storage_ref":"store-one","token_slot":"token.json"}\n'
)
PIN = hashlib.sha256(EXPECTED_RAW).hexdigest()
POLICY_RAW = (
    b'{"administrative_pending_slot":"pending.json","control_root":"/synthetic/control",'
    b'"descriptor_pin":"'
    + PIN.encode("ascii")
    + b'","descriptor_slot":"descriptor.json","entry_mode":"disabled",'
    b'"expected_revision":"revision-one","expected_state":"PREPARING",'
    b'"format_version":1,"policy_kind":"enrollment_bootstrap"}\n'
)
VARIABLES = (
    "enrollment_revision",
    "administrative_state",
    "storage_ref",
    "pair_ref",
    "artifact_directory",
    "token_slot",
    "state_slot",
    "active_intent_slot",
)
EXPECTATION_FIELDS = (
    *VARIABLES,
    "descriptor_pin",
    "descriptor_slot",
    "administrative_pending_slot",
)
POLICY_KEYS = (
    "format_version",
    "policy_kind",
    "control_root",
    "descriptor_slot",
    "administrative_pending_slot",
    "expected_revision",
    "descriptor_pin",
    "expected_state",
    "entry_mode",
)
_UNSET = object()


def _wire(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _metadata() -> dict[str, Any]:
    return json.loads(EXPECTED_RAW)


def _expect(data: dict[str, Any] | None = None) -> descriptor.SyntheticEnrollmentExpectation:
    supplied = _metadata() if data is None else data
    return descriptor.SyntheticEnrollmentExpectation(
        **{name: supplied[name] for name in VARIABLES},
        descriptor_pin=hashlib.sha256(_wire(supplied)).hexdigest(),
        descriptor_slot="descriptor.json",
        administrative_pending_slot="pending.json",
    )


def _policy(
    expectation: descriptor.SyntheticEnrollmentExpectation | None = None, root: str = ROOT
) -> dict[str, Any]:
    expected = _expect() if expectation is None else expectation
    return {
        "format_version": 1,
        "policy_kind": "enrollment_bootstrap",
        "control_root": root,
        "descriptor_slot": expected.descriptor_slot,
        "administrative_pending_slot": expected.administrative_pending_slot,
        "expected_revision": expected.enrollment_revision,
        "descriptor_pin": expected.descriptor_pin,
        "expected_state": expected.administrative_state,
        "entry_mode": "disabled",
    }


def _call(
    *,
    policy: object = POLICY_RAW,
    raw: object = EXPECTED_RAW,
    expectation: object = _UNSET,
    root: object = ROOT,
) -> model.DisabledBootstrapInputResult:
    retained = _expect() if expectation is _UNSET else expectation
    return model.validate_disabled_bootstrap_inputs(
        policy, raw, retained, expected_control_root=root
    )


def _check(state: S, **kwargs: Any) -> model.DisabledBootstrapInputResult:
    result = _call(**kwargs)
    assert type(result) is model.DisabledBootstrapInputResult
    assert result.state is state and result.reuse_authorized is False
    assert {item.name for item in fields(result)} == {"state", "reuse_authorized"}
    assert not hasattr(result, "__dict__")
    return result


class _UnexpectedHook(BaseException):
    pass


def _deny(*args: object, **kwargs: object) -> Any:
    raise _UnexpectedHook("unexpected synthetic input hook or effect")


class _Poison:
    __str__ = __repr__ = __bytes__ = __len__ = __iter__ = __eq__ = __hash__ = _deny
    __getattribute__ = _deny


class _Bytes(bytes):
    pass


class _String(str):
    pass


def _bad_raw(case: str, value: bytes) -> object:
    return {
        "none": lambda: None,
        "poison": _Poison,
        "string": lambda: value.decode(),
        "subclass": lambda: _Bytes(value),
        "bytearray": lambda: bytearray(value),
        "memoryview": lambda: memoryview(value),
        "empty": lambda: b"",
        "oversized": lambda: b" " * 8193,
    }[case]()


def test_independent_fixtures_and_exact_public_contract() -> None:
    assert _wire(_metadata()) == EXPECTED_RAW
    assert _wire(_policy()) == POLICY_RAW
    assert set(_policy()) == set(POLICY_KEYS) and len(_policy()) == 9
    assert hashlib.sha256(EXPECTED_RAW).hexdigest() == PIN
    assert hashlib.sha256(EXPECTED_RAW[:-1]).hexdigest() != PIN
    assert _expect().artifact_directory != ROOT
    signature = inspect.signature(model.validate_disabled_bootstrap_inputs)
    assert tuple(signature.parameters) == (
        "policy_raw",
        "expected_raw",
        "expectation",
        "expected_control_root",
    )
    assert all(p.default is inspect.Parameter.empty for p in signature.parameters.values())
    assert signature.parameters["expected_control_root"].kind is inspect.Parameter.KEYWORD_ONLY
    assert {state.value for state in S} == {
        "POLICY_UNVERIFIABLE",
        "INPUTS_UNVERIFIABLE",
        "ENTRY_MODE_REFUSED",
        "INPUTS_MISMATCH",
        "STATE_OUT_OF_SCOPE",
        "INPUTS_MATCHED_UNAPPROVED",
    }
    _check(S.INPUTS_MATCHED_UNAPPROVED)


@pytest.mark.parametrize(
    "case",
    ("none", "poison", "string", "subclass", "bytearray", "memoryview", "empty", "oversized"),
)
def test_policy_envelope_precedes_capture_and_every_other_input(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(model, "_capture_inputs", _deny)
    monkeypatch.setattr(model, "_parse_policy", _deny)
    monkeypatch.setattr(model, "validate_enrollment_descriptor", _deny)
    _check(
        S.POLICY_UNVERIFIABLE,
        policy=_bad_raw(case, POLICY_RAW),
        raw=_Poison(),
        expectation=_Poison(),
        root=_Poison(),
    )


@pytest.mark.parametrize(
    "case",
    ("none", "poison", "string", "subclass", "bytearray", "memoryview", "empty", "oversized"),
)
def test_expected_envelope_precedes_root_fields_and_policy_parse(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(model, "_parse_policy", _deny)
    monkeypatch.setattr(model, "validate_enrollment_descriptor", _deny)
    _check(
        S.INPUTS_UNVERIFIABLE,
        policy=b"{",
        raw=_bad_raw(case, EXPECTED_RAW),
        expectation=_Poison(),
        root=_Poison(),
    )


@pytest.mark.parametrize("size", (1, 8191, 8192))
def test_in_bound_bytes_do_not_bypass_policy_or_descriptor_schema(size: int) -> None:
    _check(S.POLICY_UNVERIFIABLE, policy=b" " * size)
    _check(S.INPUTS_UNVERIFIABLE, raw=b" " * size)


@pytest.mark.parametrize("key", POLICY_KEYS)
def test_every_policy_key_is_required(key: str) -> None:
    policy = _policy()
    del policy[key]
    _check(S.POLICY_UNVERIFIABLE, policy=_wire(policy))


@pytest.mark.parametrize("key", POLICY_KEYS)
@pytest.mark.parametrize("case", ("same", "changed", "escaped"))
def test_every_policy_duplicate_key_is_refused(key: str, case: str) -> None:
    value = _policy()[key] if case != "changed" else "synthetic-other"
    spelling = json.dumps(key)
    if case == "escaped":
        spelling = '"\\u' + f"{ord(key[0]):04x}" + key[1:] + '"'
    raw = ("{" + spelling + ":" + json.dumps(value) + ",").encode() + POLICY_RAW[1:]
    _check(S.POLICY_UNVERIFIABLE, policy=raw)


@pytest.mark.parametrize("key", POLICY_KEYS)
@pytest.mark.parametrize(
    "value", (None, True, 1.0, [], {}), ids=("null", "bool", "float", "list", "dict")
)
def test_every_policy_field_rejects_wrong_json_types(key: str, value: object) -> None:
    _check(S.POLICY_UNVERIFIABLE, policy=_wire(_policy() | {key: value}))


@pytest.mark.parametrize(
    "case",
    (
        "extra",
        "version",
        "kind",
        "array",
        "scalar",
        "null",
        "broken",
        "utf8",
        "bom",
        "surrogate",
        "leading",
        "trailing",
        "no-lf",
        "two-lf",
        "crlf",
        "order",
        "escape",
        "two-objects",
        "nan",
        "infinity",
        "negative-infinity",
    ),
)
def test_policy_schema_encoding_and_canonical_refusals(case: str) -> None:
    variants = {
        "extra": _wire(_policy() | {"active_intent_slot": "intent.json"}),
        "version": _wire(_policy() | {"format_version": 2}),
        "kind": _wire(_policy() | {"policy_kind": "other"}),
        "array": b"[]\n",
        "scalar": b"1\n",
        "null": b"null\n",
        "broken": b"{\n",
        "utf8": b"\xff\n",
        "bom": b"\xef\xbb\xbf" + POLICY_RAW,
        "surrogate": _wire(_policy() | {"entry_mode": "\ud800"}),
        "leading": b" " + POLICY_RAW,
        "trailing": POLICY_RAW + b" ",
        "no-lf": POLICY_RAW[:-1],
        "two-lf": POLICY_RAW + b"\n",
        "crlf": POLICY_RAW[:-1] + b"\r\n",
        "order": (
            json.dumps(dict(reversed(tuple(_policy().items()))), separators=(",", ":")) + "\n"
        ).encode(),
        "escape": POLICY_RAW.replace(b"disabled", b"dis\\u0061bled"),
        "two-objects": POLICY_RAW + POLICY_RAW,
        "nan": POLICY_RAW.replace(b'"disabled"', b"NaN"),
        "infinity": POLICY_RAW.replace(b'"disabled"', b"Infinity"),
        "negative-infinity": POLICY_RAW.replace(b'"disabled"', b"-Infinity"),
    }
    _check(S.POLICY_UNVERIFIABLE, policy=variants[case])


@pytest.mark.parametrize("field", ("policy", "independent"))
@pytest.mark.parametrize(
    "value",
    (
        "",
        "relative",
        "/",
        "/a//b",
        "/a/",
        "/a\\b",
        "/a:b",
        "/a/.",
        "/a/../b",
        "/a/.git/b",
        "/a /b",
        "/a./b",
        "/a\x00b",
        "/a\x85b",
        "/a\x9fb",
        "/a\ud800b",
        "/" + "a" * 1024,
        "/" + "é" * 512,
    ),
    ids=range(18),
)
def test_root_lexical_constraints_apply_independently(field: str, value: str) -> None:
    if field == "policy":
        _check(S.POLICY_UNVERIFIABLE, policy=_wire(_policy() | {"control_root": value}))
    else:
        _check(S.INPUTS_UNVERIFIABLE, root=value)


@pytest.mark.parametrize("case", ("none", "poison", "subclass", "bytes", "integer"))
def test_independent_root_exact_type_precedes_expectation_and_parse(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = {
        "none": lambda: None,
        "poison": _Poison,
        "subclass": lambda: _String(ROOT),
        "bytes": lambda: ROOT.encode(),
        "integer": lambda: 1,
    }[case]()
    monkeypatch.setattr(model, "_parse_policy", _deny)
    _check(S.INPUTS_UNVERIFIABLE, policy=b"{", root=value, expectation=_Poison())


@pytest.mark.parametrize(
    "root",
    (
        "/" + "a" * 1023,
        "/" + "é" * 511 + "a",
        "/a/.GIT/b",
        "/a/é",
        "/a/e\u0301",
        "/a/\u200d",
        "/a/ leading",
    ),
    ids=range(7),
)
def test_valid_roots_retain_exact_spelling_without_os_normalization(root: str) -> None:
    _check(S.INPUTS_MATCHED_UNAPPROVED, policy=_wire(_policy(root=root)), root=root)
    _check(S.INPUTS_MISMATCH, policy=_wire(_policy(root=root)))


@pytest.mark.parametrize(
    "value",
    ("", "a" * 97, "_first", ".first", "-first", "has space", "é", "a/b", "a:b", "a\\b", "a\n"),
    ids=range(11),
)
def test_policy_revision_grammar(value: str) -> None:
    _check(S.POLICY_UNVERIFIABLE, policy=_wire(_policy() | {"expected_revision": value}))


@pytest.mark.parametrize("field", ("descriptor_slot", "administrative_pending_slot"))
@pytest.mark.parametrize(
    "value",
    (
        "",
        "a" * 97,
        "leaf.",
        "a/b",
        "_first",
        "CON",
        "prn.ext",
        "Aux",
        "nul.json",
        *(f"{base}{number}.json" for base in ("COM", "lpt") for number in range(1, 10)),
    ),
    ids=range(27),
)
def test_policy_slots_reject_unsafe_or_reserved_leaves(field: str, value: str) -> None:
    _check(S.POLICY_UNVERIFIABLE, policy=_wire(_policy() | {field: value}))


@pytest.mark.parametrize(
    "value", ("a", "a" * 96, "COM0", "COM10", "LPT0", "LPT10", "CONSOLE"), ids=range(7)
)
def test_valid_slot_boundaries_do_not_change_the_stored_value(value: str) -> None:
    expectation = replace(_expect(), descriptor_slot=value)
    _check(S.INPUTS_MATCHED_UNAPPROVED, policy=_wire(_policy(expectation)), expectation=expectation)


def test_control_slot_collisions_and_case_sensitive_layout() -> None:
    _check(S.POLICY_UNVERIFIABLE, policy=_wire(_policy() | {"descriptor_slot": "pending.json"}))
    expectation = replace(_expect(), descriptor_slot="PENDING.json")
    _check(S.INPUTS_MATCHED_UNAPPROVED, policy=_wire(_policy(expectation)), expectation=expectation)
    _check(S.INPUTS_MISMATCH, policy=_wire(_policy() | {"descriptor_slot": "Descriptor.json"}))
    expectation = replace(_expect(), descriptor_slot="intent.json")
    _check(S.INPUTS_UNVERIFIABLE, policy=_wire(_policy(expectation)), expectation=expectation)


@pytest.mark.parametrize("pin", ("", "a" * 63, "a" * 65, "A" * 64, "g" * 64), ids=range(5))
def test_policy_pin_is_exact_lowercase_hex(pin: str) -> None:
    _check(S.POLICY_UNVERIFIABLE, policy=_wire(_policy() | {"descriptor_pin": pin}))


@pytest.mark.parametrize("state", ("", "preparing", "UNKNOWN", "ACTIVE "))
def test_policy_state_has_closed_syntax(state: str) -> None:
    _check(S.POLICY_UNVERIFIABLE, policy=_wire(_policy() | {"expected_state": state}))


@pytest.mark.parametrize("state", ("PREPARING", "ACTIVE", "REVOKED"))
@pytest.mark.parametrize("mode", ("disabled", "enabled", "DISABLED", "", "disabled ", "disabled\n"))
def test_coherent_mode_and_state_combinations_remain_unapproved(state: str, mode: str) -> None:
    data = _metadata() | {"administrative_state": state}
    expectation = _expect(data)
    expected = (
        S.ENTRY_MODE_REFUSED
        if mode != "disabled"
        else (S.INPUTS_MATCHED_UNAPPROVED if state == "PREPARING" else S.STATE_OUT_OF_SCOPE)
    )
    _check(
        expected,
        policy=_wire(_policy(expectation) | {"entry_mode": mode}),
        raw=_wire(data),
        expectation=expectation,
    )


@pytest.mark.parametrize("field", EXPECTATION_FIELDS)
@pytest.mark.parametrize("case", ("poison", "subclass", "none", "integer"))
def test_all_expectation_fields_require_exact_strings_before_policy_parse(
    field: str, case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = {
        "poison": _Poison,
        "subclass": lambda: _String("synthetic"),
        "none": lambda: None,
        "integer": lambda: 1,
    }[case]()
    expectation = replace(_expect(), **{field: value})
    monkeypatch.setattr(model, "_parse_policy", _deny)
    _check(S.INPUTS_UNVERIFIABLE, policy=b"{", expectation=expectation)


@pytest.mark.parametrize("field", EXPECTATION_FIELDS)
def test_each_missing_expectation_slot_is_unverifiable(field: str) -> None:
    complete = _expect()
    incomplete = object.__new__(descriptor.SyntheticEnrollmentExpectation)
    for name in EXPECTATION_FIELDS:
        if name != field:
            object.__setattr__(incomplete, name, getattr(complete, name))
    _check(S.INPUTS_UNVERIFIABLE, expectation=incomplete)


@pytest.mark.parametrize("case", ("none", "dict", "poison", "subclass"))
def test_expectation_exact_type_is_not_coerced(case: str) -> None:
    class Derived(descriptor.SyntheticEnrollmentExpectation):
        pass

    expectation = (
        Derived(**{name: getattr(_expect(), name) for name in EXPECTATION_FIELDS})
        if case == "subclass"
        else {"none": lambda: None, "dict": dict, "poison": _Poison}[case]()
    )
    _check(S.INPUTS_UNVERIFIABLE, expectation=expectation)


@pytest.mark.parametrize(
    "field,value",
    (
        ("descriptor_pin", "0" * 64),
        ("enrollment_revision", "changed-revision"),
        ("pair_ref", "changed-pair"),
        ("administrative_state", "UNKNOWN"),
    ),
)
def test_expected_metadata_must_be_internally_consistent(field: str, value: str) -> None:
    _check(S.INPUTS_UNVERIFIABLE, expectation=replace(_expect(), **{field: value}))


@pytest.mark.parametrize("field", VARIABLES)
def test_well_formed_other_descriptor_is_not_used_to_rebuild_expectations(field: str) -> None:
    value = (
        "ACTIVE"
        if field == "administrative_state"
        else ("/synthetic/other-pair" if field == "artifact_directory" else "other-value")
    )
    _check(S.INPUTS_MISMATCH, raw=_wire(_metadata() | {field: value}))


@pytest.mark.parametrize(
    "field,value",
    (
        ("control_root", "/synthetic/other-control"),
        ("descriptor_slot", "other-descriptor.json"),
        ("administrative_pending_slot", "other-pending.json"),
        ("expected_revision", "other-revision"),
        ("descriptor_pin", "0" * 64),
        ("expected_state", "ACTIVE"),
    ),
)
def test_every_cross_input_field_is_compared_even_when_descriptor_matches(
    field: str, value: str
) -> None:
    _check(S.INPUTS_MISMATCH, policy=_wire(_policy() | {field: value}))


def test_control_root_and_pair_root_are_distinct_and_not_normalized() -> None:
    _check(S.INPUTS_MATCHED_UNAPPROVED)
    _check(S.INPUTS_MISMATCH, root=_expect().artifact_directory)
    for policy_root, expected_root in (
        ("/synthetic/Control", ROOT),
        ("/synthetic/é", "/synthetic/e\u0301"),
    ):
        _check(S.INPUTS_MISMATCH, policy=_wire(_policy(root=policy_root)), root=expected_root)


@pytest.mark.parametrize(
    "case,state",
    (
        ("bad-policy-envelope", S.POLICY_UNVERIFIABLE),
        ("bad-input-capture", S.INPUTS_UNVERIFIABLE),
        ("bad-policy-schema", S.POLICY_UNVERIFIABLE),
        ("bad-policy-canonical", S.POLICY_UNVERIFIABLE),
        ("mode-before-descriptor", S.ENTRY_MODE_REFUSED),
        ("mode-before-pin", S.ENTRY_MODE_REFUSED),
        ("expected-before-cross", S.INPUTS_UNVERIFIABLE),
        ("mismatch-before-purpose", S.INPUTS_MISMATCH),
    ),
)
def test_first_refusal_priority_for_simultaneous_defects(case: str, state: S) -> None:
    kwargs: dict[str, Any] = {}
    if case == "bad-policy-envelope":
        kwargs = {"policy": b"", "raw": _Poison(), "root": _Poison(), "expectation": _Poison()}
    elif case == "bad-input-capture":
        kwargs = {"policy": b"{", "expectation": None}
    elif case == "bad-policy-schema":
        kwargs = {
            "policy": _wire(_policy() | {"entry_mode": "enabled", "format_version": True}),
            "raw": b"{",
        }
    elif case == "bad-policy-canonical":
        kwargs = {"policy": _wire(_policy() | {"entry_mode": "enabled"}) + b" ", "raw": b"{"}
    elif case == "mode-before-descriptor":
        kwargs = {"policy": _wire(_policy() | {"entry_mode": "enabled"}), "raw": b"{"}
    elif case == "mode-before-pin":
        kwargs = {
            "policy": _wire(_policy() | {"entry_mode": "enabled"}),
            "expectation": replace(_expect(), descriptor_pin="bad"),
        }
    elif case == "expected-before-cross":
        kwargs = {"policy": _wire(_policy() | {"control_root": "/synthetic/other"}), "raw": b"{"}
    else:
        data = _metadata() | {"administrative_state": "ACTIVE"}
        expected = _expect(data)
        kwargs = {
            "policy": _wire(_policy(expected) | {"control_root": "/synthetic/other"}),
            "raw": _wire(data),
            "expectation": expected,
        }
    _check(state, **kwargs)


def test_snapshot_and_same_input_bytes_survive_original_object_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = _expect()
    parse = model._parse_policy
    validate = model.validate_enrollment_descriptor
    matches = model._policy_matches
    seen: dict[str, object] = {}

    def parse_once(raw: bytes) -> Any:
        assert raw is POLICY_RAW
        for name in EXPECTATION_FIELDS:
            object.__setattr__(original, name, _Poison())
        seen["policy"] = parse(raw)
        return seen["policy"]

    def validate_once(raw: object, retained: object) -> Any:
        assert raw is EXPECTED_RAW and retained is not original
        assert type(retained) is descriptor.SyntheticEnrollmentExpectation
        assert all(type(getattr(retained, name)) is str for name in EXPECTATION_FIELDS)
        seen["retained"] = retained
        return validate(raw, retained)

    def compare_once(policy: object, inputs: Any) -> bool:
        assert policy is seen["policy"] and inputs.expectation is seen["retained"]
        assert inputs.policy_raw is POLICY_RAW and inputs.expected_raw is EXPECTED_RAW
        assert inputs.expected_control_root is ROOT
        assert ROOT not in repr(inputs) and PIN not in repr(inputs) and ROOT not in repr(policy)
        return matches(policy, inputs)

    monkeypatch.setattr(model, "_parse_policy", parse_once)
    monkeypatch.setattr(model, "validate_enrollment_descriptor", validate_once)
    monkeypatch.setattr(model, "_policy_matches", compare_once)
    _check(S.INPUTS_MATCHED_UNAPPROVED, expectation=original)
    assert set(seen) == {"policy", "retained"}


@pytest.mark.parametrize(
    "state,expected",
    (
        (D.EXPECTATION_UNVERIFIABLE, S.INPUTS_UNVERIFIABLE),
        (D.DESCRIPTOR_UNVERIFIABLE, S.INPUTS_UNVERIFIABLE),
        (D.ENROLLMENT_MISMATCH, S.INPUTS_MISMATCH),
        (D.DESCRIPTOR_MATCHED_UNAPPROVED, S.INPUTS_MATCHED_UNAPPROVED),
    ),
)
def test_public_validator_classifications_are_explicitly_mapped(
    state: D, expected: S, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(
        model,
        "validate_enrollment_descriptor",
        lambda *args: descriptor.EnrollmentDescriptorResult(state),
    )
    _check(expected)


@pytest.mark.parametrize(
    "case",
    (
        "none",
        "dict",
        "missing-state",
        "missing-reuse",
        "string-state",
        "unknown-state",
        "poison-state",
        "true-reuse",
        "integer-reuse",
        "poison-reuse",
    ),
)
def test_malformed_public_validator_results_fail_closed(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    invalid = {
        "none": lambda: None,
        "dict": dict,
        "missing-state": lambda: SimpleNamespace(reuse_authorized=False),
        "missing-reuse": lambda: SimpleNamespace(state=D.DESCRIPTOR_MATCHED_UNAPPROVED),
        "string-state": lambda: SimpleNamespace(
            state="DESCRIPTOR_MATCHED_UNAPPROVED", reuse_authorized=False
        ),
        "unknown-state": lambda: SimpleNamespace(state=object(), reuse_authorized=False),
        "poison-state": lambda: SimpleNamespace(state=_Poison(), reuse_authorized=False),
        "true-reuse": lambda: SimpleNamespace(
            state=D.DESCRIPTOR_MATCHED_UNAPPROVED, reuse_authorized=True
        ),
        "integer-reuse": lambda: SimpleNamespace(
            state=D.DESCRIPTOR_MATCHED_UNAPPROVED, reuse_authorized=0
        ),
        "poison-reuse": lambda: SimpleNamespace(
            state=D.DESCRIPTOR_MATCHED_UNAPPROVED, reuse_authorized=_Poison()
        ),
    }[case]()
    monkeypatch.setattr(model, "validate_enrollment_descriptor", lambda *args: invalid)
    _check(S.INPUTS_UNVERIFIABLE)


@pytest.mark.parametrize("case", ("none", "integer", "poison"))
def test_cross_comparison_requires_an_exact_boolean(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = {"none": lambda: None, "integer": lambda: 1, "poison": _Poison}[case]()
    monkeypatch.setattr(model, "_policy_matches", lambda *args: value)
    _check(S.INPUTS_UNVERIFIABLE)


@pytest.mark.parametrize(
    "helper,state",
    (
        ("_capture_inputs", S.INPUTS_UNVERIFIABLE),
        ("_parse_policy", S.POLICY_UNVERIFIABLE),
        ("_canonical_policy", S.POLICY_UNVERIFIABLE),
        ("validate_enrollment_descriptor", S.INPUTS_UNVERIFIABLE),
        ("_policy_matches", S.INPUTS_UNVERIFIABLE),
    ),
)
@pytest.mark.parametrize("failure", ("ordinary", "interrupt", "exit"))
def test_failures_keep_stage_and_cancellation_without_diagnostics(
    helper: str,
    state: S,
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = 0
    exception = {"ordinary": RuntimeError, "interrupt": KeyboardInterrupt, "exit": SystemExit}[
        failure
    ]

    def injected(*args: object, **kwargs: object) -> Any:
        nonlocal calls
        calls += 1
        raise exception("synthetic-private-detail")

    monkeypatch.setattr(model, helper, injected)
    if failure == "ordinary":
        result = _check(state)
        assert "synthetic-private-detail" not in repr(result)
    else:
        with pytest.raises(exception):
            _call()
    assert calls == 1 and capsys.readouterr() == ("", "")


def test_policy_encoding_output_bound_is_checked(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        model, "json", SimpleNamespace(loads=json.loads, dumps=lambda *args, **kwargs: " " * 8192)
    )
    _check(S.POLICY_UNVERIFIABLE)


def test_matching_coherent_old_inputs_are_never_authority_or_history_clearance() -> None:
    data = _metadata() | {"enrollment_revision": "old-revision", "pair_ref": "other-pair"}
    expected = _expect(data)
    for _ in range(2):
        _check(
            S.INPUTS_MATCHED_UNAPPROVED,
            policy=_wire(_policy(expected)),
            raw=_wire(data),
            expectation=expected,
        )


def test_result_is_exact_frozen_two_fields_without_input_in_repr() -> None:
    with pytest.raises(ValueError, match=r"^Invalid disabled bootstrap input result$"):
        model.DisabledBootstrapInputResult(_Poison())
    with pytest.raises(ValueError, match=r"^Invalid disabled bootstrap input result$"):
        model.DisabledBootstrapInputResult("INPUTS_MATCHED_UNAPPROVED")
    for state in S:
        result = model.DisabledBootstrapInputResult(state)
        assert result.state is state and result.reuse_authorized is False
        assert {item.name for item in fields(result)} == {"state", "reuse_authorized"}
        assert not fields(result)[1].init and not hasattr(result, "__dict__")
        assert all(value not in repr(result) for value in (ROOT, PIN, "revision-one", "pair-one"))
        with pytest.raises(TypeError):
            model.DisabledBootstrapInputResult(state, reuse_authorized=True)
        with pytest.raises(FrozenInstanceError):
            result.reuse_authorized = True


def test_no_io_or_output_during_validation_call(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    expectation = _expect()
    with monkeypatch.context() as scoped:
        scoped.setattr(builtins, "open", _deny)
        scoped.setattr(builtins, "print", _deny)
        scoped.setattr(Path, "open", _deny)
        _check(S.INPUTS_MATCHED_UNAPPROVED, expectation=expectation)
        _check(S.POLICY_UNVERIFIABLE, policy=_Poison(), expectation=expectation)
        _check(S.INPUTS_UNVERIFIABLE, expectation=_Poison())
    assert capsys.readouterr() == ("", "")


def test_closed_public_dependencies_no_effects_and_exact_consumers() -> None:
    """Reading repository source is test inspection, not validator runtime I/O."""
    source = Path(inspect.getfile(model))
    tree = ast.parse(source.read_text(encoding="utf-8"))
    allowed_stdlib = {"__future__", "dataclasses", "enum", "json", "typing", "unicodedata"}
    application = "tridentine_calendar_google_sync.production_write_token_enrollment_descriptor"
    imported: set[str] = set()
    forbidden = {
        "open",
        "print",
        "input",
        "exec",
        "eval",
        "compile",
        "__import__",
        "vars",
        "globals",
        "locals",
        "setattr",
        "delattr",
        "read",
        "read_bytes",
        "read_text",
        "write",
        "write_bytes",
        "write_text",
        "load",
        "dump",
        "stat",
        "lstat",
        "resolve",
        "unlink",
        "mkdir",
        "chmod",
        "replace",
        "remove",
        "getenv",
        "system",
        "run",
        "Popen",
        "start",
        "acquire",
        "socket",
        "connect",
        "request",
        "sleep",
        "refresh",
        "authorize",
        "sha256",
        "sha1",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name in allowed_stdlib for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            if node.module == application:
                imported.update(alias.name for alias in node.names)
            else:
                assert node.module in allowed_stdlib
        elif isinstance(node, ast.Call):
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else ""
            )
            assert name not in forbidden
        assert not isinstance(node, (ast.Global, ast.Nonlocal, ast.AsyncFunctionDef, ast.While))
    assert imported == {
        "SyntheticEnrollmentExpectation",
        "EnrollmentDescriptorState",
        "validate_enrollment_descriptor",
    }
    getters = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
    ]
    capture = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_capture_inputs"
    )
    assert len(getters) == 1 and getters[0] in tuple(ast.walk(capture))
    assert not getters[0].keywords
    assert [ast.unparse(arg) for arg in getters[0].args] == ["expectation", "name"]
    assert any(
        isinstance(node, ast.comprehension)
        and ast.unparse(node.target) == "name"
        and ast.unparse(node.iter) == "_EXPECTATION_FIELDS"
        for node in ast.walk(capture)
    )
    assert model._EXPECTATION_FIELDS == EXPECTATION_FIELDS
    package = source.parent
    assert {
        other.relative_to(package).as_posix()
        for other in package.rglob("*.py")
        if other != source and source.stem in other.read_text(encoding="utf-8")
    } == set()
    descriptor_source = Path(inspect.getfile(descriptor))
    assert {
        other.relative_to(package).as_posix()
        for other in package.rglob("*.py")
        if other != descriptor_source
        and descriptor_source.stem in other.read_text(encoding="utf-8")
    } == {
        "production_write_token_enrollment_preparation.py",
        "production_write_token_disabled_bootstrap_inputs.py",
    }


@pytest.mark.parametrize("case", ("missing-lf", "bom", "utf8", "schema"))
def test_invalid_expected_bytes_are_delegated_to_public_validator(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing = _metadata()
    del missing["pair_ref"]
    raw = {
        "missing-lf": EXPECTED_RAW[:-1],
        "bom": b"\xef\xbb\xbf" + EXPECTED_RAW,
        "utf8": b"\xff\n",
        "schema": _wire(missing),
    }[case]
    expected = _expect()
    validate = model.validate_enrollment_descriptor
    calls = 0

    def delegated(value: object, retained: object) -> Any:
        nonlocal calls
        calls += 1
        assert value is raw and retained is not expected
        return validate(value, retained)

    monkeypatch.setattr(model, "validate_enrollment_descriptor", delegated)
    _check(S.INPUTS_UNVERIFIABLE, raw=raw, expectation=expected)
    assert calls == 1


@pytest.mark.parametrize("revision", ("r", "r" * 96), ids=("minimum", "maximum"))
def test_valid_revision_boundaries_use_independent_updated_metadata(revision: str) -> None:
    data = _metadata() | {"enrollment_revision": revision}
    raw = _wire(data)
    expected = _expect(data)
    assert expected.descriptor_pin == hashlib.sha256(raw).hexdigest()
    _check(
        S.INPUTS_MATCHED_UNAPPROVED,
        policy=_wire(_policy(expected)),
        raw=raw,
        expectation=expected,
    )


@pytest.mark.parametrize("field", ("state", "reuse_authorized"))
def test_dependency_property_failure_is_a_fixed_unverifiable_result(
    field: str, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    accessed: list[str] = []

    class BrokenResult:
        @property
        def state(self) -> D:
            accessed.append("state")
            if field == "state":
                raise RuntimeError("synthetic-private-property-detail")
            return D.DESCRIPTOR_MATCHED_UNAPPROVED

        @property
        def reuse_authorized(self) -> bool:
            accessed.append("reuse_authorized")
            raise RuntimeError("synthetic-private-property-detail")

    monkeypatch.setattr(model, "validate_enrollment_descriptor", lambda *args: BrokenResult())
    result = _check(S.INPUTS_UNVERIFIABLE)
    assert accessed == (["state"] if field == "state" else ["state", "reuse_authorized"])
    assert "synthetic-private-property-detail" not in repr(result)
    assert capsys.readouterr() == ("", "")
