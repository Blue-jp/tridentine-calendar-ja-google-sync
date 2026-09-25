"""Synthetic comparison only: no bootstrap authority, freshness or state clearance."""

from __future__ import annotations

import ast
import builtins
import hashlib
import inspect
import json
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from typing import Any

import pytest

from tridentine_calendar_google_sync import production_write_token_enrollment_descriptor as model

S = model.EnrollmentDescriptorState
RAW = (
    b'{"active_intent_slot":"intent.json","administrative_state":"PREPARING",'
    b'"artifact_directory":"/synthetic/pair","enrollment_revision":"revision-one",'
    b'"format_version":1,"pair_ref":"pair-one","record_kind":"enrollment_descriptor",'
    b'"record_slot":"production-write-operation-start-v1.json","role":"production_write",'
    b'"state_slot":"state.json","storage_ref":"store-one","token_slot":"token.json"}\n'
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


def _data() -> dict[str, Any]:
    return json.loads(RAW)


def _wire(data: dict[str, Any]) -> bytes:
    return (
        json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode("utf-8")


def _expect(data: dict[str, Any] | None = None) -> model.SyntheticEnrollmentExpectation:
    values = _data() if data is None else data
    return model.SyntheticEnrollmentExpectation(
        **{name: values[name] for name in VARIABLES},
        descriptor_pin=hashlib.sha256(_wire(values)).hexdigest(),
        descriptor_slot="descriptor.json",
        administrative_pending_slot="pending.json",
    )


def _check(raw: object, expectation: object, state: S) -> model.EnrollmentDescriptorResult:
    result = model.validate_enrollment_descriptor(raw, expectation)
    assert type(result) is model.EnrollmentDescriptorResult
    assert result.state is state
    assert result.reuse_authorized is False
    assert not hasattr(result, "__dict__")
    assert {field.name for field in fields(result)} == {"state", "reuse_authorized"}
    return result


class _PoisonHookCalled(BaseException):
    pass


class _Poison:
    def _called(self, *args: object, **kwargs: object) -> Any:
        raise _PoisonHookCalled("unexpected input hook")

    __str__ = __repr__ = __bytes__ = __len__ = __iter__ = __eq__ = __hash__ = _called
    __getattribute__ = _called


class _String(str):
    pass


class _Bytes(bytes):
    pass


def test_independent_canonical_fixture_and_complete_public_contract() -> None:
    assert _wire(_data()) == RAW
    assert len(_data()) == 12
    assert _data()["format_version"] == 1
    assert _data()["record_kind"] == "enrollment_descriptor"
    assert _data()["role"] == "production_write"
    assert _data()["record_slot"] == "production-write-operation-start-v1.json"
    assert set(field.name for field in fields(model.SyntheticEnrollmentExpectation)) == set(
        EXPECTATION_FIELDS
    )
    assert all(
        parameter.default is inspect.Parameter.empty
        for parameter in inspect.signature(model.SyntheticEnrollmentExpectation).parameters.values()
    )
    assert {state.value for state in S} == {
        "EXPECTATION_UNVERIFIABLE",
        "DESCRIPTOR_UNVERIFIABLE",
        "ENROLLMENT_MISMATCH",
        "DESCRIPTOR_MATCHED_UNAPPROVED",
    }
    _check(RAW, _expect(), S.DESCRIPTOR_MATCHED_UNAPPROVED)
    without_lf = replace(_expect(), descriptor_pin=hashlib.sha256(RAW[:-1]).hexdigest())
    _check(RAW, without_lf, S.EXPECTATION_UNVERIFIABLE)


@pytest.mark.parametrize("state", ("PREPARING", "ACTIVE", "REVOKED"))
def test_administrative_matches_never_authorize_or_clear_upper_policy(state: str) -> None:
    """Matching cannot clear ADMIN_REVOKED, ADMIN_PENDING or ADMIN_COMMIT_UNCERTAIN."""
    data = _data() | {"administrative_state": state}
    result = _check(_wire(data), _expect(data), S.DESCRIPTOR_MATCHED_UNAPPROVED)
    assert set(field.name for field in fields(result)) == {"state", "reuse_authorized"}
    _check(
        _wire(data),
        _expect(),
        S.DESCRIPTOR_MATCHED_UNAPPROVED if state == "PREPARING" else S.ENROLLMENT_MISMATCH,
    )


@pytest.mark.parametrize("field", VARIABLES)
def test_each_well_formed_variable_change_is_mismatch(field: str) -> None:
    new = (
        "ACTIVE"
        if field == "administrative_state"
        else ("/synthetic/other" if field == "artifact_directory" else "other-value")
    )
    _check(_wire(_data() | {field: new}), _expect(), S.ENROLLMENT_MISMATCH)


@pytest.mark.parametrize(
    "case",
    (
        "missing",
        "extra",
        "version",
        "boolean-version",
        "float-version",
        "kind",
        "role",
        "record-slot",
        "unknown-state",
        "null",
        "nested-list",
        "nested-object",
    ),
)
def test_schema_defects_are_unverifiable(case: str) -> None:
    data = _data()
    if case == "missing":
        del data["pair_ref"]
    else:
        updates: dict[str, dict[str, Any]] = {
            "extra": {"note": "synthetic"},
            "version": {"format_version": 2},
            "boolean-version": {"format_version": True},
            "float-version": {"format_version": 1.0},
            "kind": {"record_kind": "other"},
            "role": {"role": "other"},
            "record-slot": {"record_slot": "other.json"},
            "unknown-state": {"administrative_state": "UNKNOWN"},
            "null": {"pair_ref": None},
            "nested-list": {"pair_ref": []},
            "nested-object": {"pair_ref": {}},
        }
        data.update(updates[case])
    _check(_wire(data), _expect(), S.DESCRIPTOR_UNVERIFIABLE)


@pytest.mark.parametrize("field", tuple(_data()))
def test_each_descriptor_key_is_required(field: str) -> None:
    data = _data()
    del data[field]
    _check(_wire(data), _expect(), S.DESCRIPTOR_UNVERIFIABLE)


@pytest.mark.parametrize("field", tuple(_data()))
@pytest.mark.parametrize("value", (None, True, [], {}), ids=("null", "bool", "list", "object"))
def test_each_descriptor_field_rejects_invalid_json_types(field: str, value: object) -> None:
    _check(_wire(_data() | {field: value}), _expect(), S.DESCRIPTOR_UNVERIFIABLE)


@pytest.mark.parametrize("field", EXPECTATION_FIELDS)
@pytest.mark.parametrize("case", ("poison", "str-subclass", "none", "integer"))
def test_expectation_fields_require_exact_strings_before_hooks(field: str, case: str) -> None:
    bad: object = {
        "poison": _Poison,
        "str-subclass": lambda: _String("synthetic"),
        "none": lambda: None,
        "integer": lambda: 1,
    }[case]()
    _check(_Poison(), replace(_expect(), **{field: bad}), S.EXPECTATION_UNVERIFIABLE)


@pytest.mark.parametrize("case", ("none", "dict", "poison", "subclass", "missing-field"))
def test_expectation_exact_type_and_missing_slots_precede_candidate(case: str) -> None:
    class Derived(model.SyntheticEnrollmentExpectation):
        pass

    if case == "subclass":
        expectation: object = Derived(
            **{field.name: getattr(_expect(), field.name) for field in fields(_expect())}
        )
    elif case == "missing-field":
        expectation = object.__new__(model.SyntheticEnrollmentExpectation)
    else:
        expectation = {"none": lambda: None, "dict": dict, "poison": _Poison}[case]()
    _check(_Poison(), expectation, S.EXPECTATION_UNVERIFIABLE)


@pytest.mark.parametrize("case", ("short", "uppercase", "not-hex", "stale", "metadata", "enum"))
def test_expectation_pin_and_metadata_must_be_self_consistent(case: str) -> None:
    updates = {
        "short": {"descriptor_pin": "a" * 63},
        "uppercase": {"descriptor_pin": "A" * 64},
        "not-hex": {"descriptor_pin": "g" * 64},
        "stale": {"descriptor_pin": "0" * 64},
        "metadata": {"enrollment_revision": "revision-two"},
        "enum": {"administrative_state": "UNKNOWN"},
    }
    _check(_Poison(), replace(_expect(), **updates[case]), S.EXPECTATION_UNVERIFIABLE)


@pytest.mark.parametrize("case", ("poison", "str", "bytearray", "memoryview", "subclass", "none"))
def test_raw_requires_exact_bytes_without_conversion_hooks(case: str) -> None:
    raw = {
        "poison": _Poison,
        "str": lambda: RAW.decode(),
        "bytearray": lambda: bytearray(RAW),
        "memoryview": lambda: memoryview(RAW),
        "subclass": lambda: _Bytes(RAW),
        "none": lambda: None,
    }[case]()
    _check(raw, _expect(), S.DESCRIPTOR_UNVERIFIABLE)


@pytest.mark.parametrize(
    "case",
    (
        "duplicate",
        "escaped-duplicate",
        "changed-duplicate",
        "nan",
        "infinity",
        "negative-infinity",
        "array",
        "scalar",
        "null",
        "invalid-json",
        "utf8",
        "bom",
        "surrogate",
        "leading-space",
        "trailing-space",
        "no-lf",
        "two-lf",
        "crlf",
        "key-order",
        "escape",
        "two-objects",
    ),
)
def test_invalid_serialization_and_noncanonical_forms(case: str) -> None:
    cases = {
        "duplicate": RAW.replace(b"{", b'{"pair_ref":"pair-one",', 1),
        "escaped-duplicate": RAW.replace(b"{", b'{"pair_\\u0072ef":"pair-one",', 1),
        "changed-duplicate": RAW.replace(b"{", b'{"pair_ref":"other",', 1),
        "nan": RAW.replace(b'"pair-one"', b"NaN"),
        "infinity": RAW.replace(b'"pair-one"', b"Infinity"),
        "negative-infinity": RAW.replace(b'"pair-one"', b"-Infinity"),
        "array": b"[]\n",
        "scalar": b"1\n",
        "null": b"null\n",
        "invalid-json": b"{\n",
        "utf8": b"\xff\n",
        "bom": b"\xef\xbb\xbf" + RAW,
        "surrogate": RAW.replace(b"/synthetic/pair", b"/synthetic/\\ud800"),
        "leading-space": b" " + RAW,
        "trailing-space": RAW + b" ",
        "no-lf": RAW[:-1],
        "two-lf": RAW + b"\n",
        "crlf": RAW[:-1] + b"\r\n",
        "key-order": (
            json.dumps(dict(reversed(tuple(_data().items()))), separators=(",", ":")) + "\n"
        ).encode(),
        "escape": RAW.replace(b"pair-one", b"pair\\u002done"),
        "two-objects": RAW + RAW,
    }
    _check(cases[case], _expect(), S.DESCRIPTOR_UNVERIFIABLE)


@pytest.mark.parametrize("size", (0, 8193))
def test_raw_size_is_checked_before_json_parse(size: int, monkeypatch: pytest.MonkeyPatch) -> None:
    expectation = _expect()
    calls = 0

    def forbidden(*args: object, **kwargs: object) -> Any:
        nonlocal calls
        calls += 1
        raise AssertionError("parser reached before size refusal")

    monkeypatch.setattr(model.json, "loads", forbidden)
    _check(b" " * size, expectation, S.DESCRIPTOR_UNVERIFIABLE)
    assert calls == 0


@pytest.mark.parametrize("size", (1, 8191, 8192))
def test_in_bound_size_never_bypasses_schema(size: int) -> None:
    _check(b" " * size, _expect(), S.DESCRIPTOR_UNVERIFIABLE)


@pytest.mark.parametrize("field", ("enrollment_revision", "storage_ref", "pair_ref"))
@pytest.mark.parametrize(
    "value",
    (
        "",
        "a" * 97,
        "_first",
        ".first",
        "-first",
        "has space",
        "trailing ",
        "é",
        "a/b",
        "a:b",
        "a\\b",
        "a\n",
        "a\x7f",
        "\uff11",
    ),
    ids=range(14),
)
def test_invalid_reference_grammar_rejects_candidate_and_expectation(
    field: str, value: str
) -> None:
    data = _data() | {field: value}
    _check(_wire(data), _expect(), S.DESCRIPTOR_UNVERIFIABLE)
    _check(_Poison(), _expect(data), S.EXPECTATION_UNVERIFIABLE)


@pytest.mark.parametrize("value", ("a", "Z9._-", "a" * 96), ids=("minimum", "alphabet", "maximum"))
def test_reference_boundaries_are_accepted(value: str) -> None:
    data = _data() | dict.fromkeys(("enrollment_revision", "storage_ref", "pair_ref"), value)
    _check(_wire(data), _expect(data), S.DESCRIPTOR_MATCHED_UNAPPROVED)


@pytest.mark.parametrize(
    "value",
    (
        "CON",
        "prn.ext",
        "Aux",
        "nul.json",
        "COM1",
        "com9.txt",
        "LPT1",
        "lpt9.ext",
        "leaf.",
        "../leaf",
        "a/b",
    ),
    ids=range(11),
)
@pytest.mark.parametrize(
    "field",
    (
        "token_slot",
        "state_slot",
        "active_intent_slot",
        "descriptor_slot",
        "administrative_pending_slot",
    ),
)
def test_slot_grammar_and_reserved_bases(field: str, value: str) -> None:
    if field in VARIABLES:
        _check(_wire(_data() | {field: value}), _expect(), S.DESCRIPTOR_UNVERIFIABLE)
    _check(_Poison(), replace(_expect(), **{field: value}), S.EXPECTATION_UNVERIFIABLE)


@pytest.mark.parametrize(
    "field,value",
    (
        ("token_slot", "state.json"),
        ("state_slot", "token.json"),
        ("token_slot", "production-write-operation-start-v1.json"),
        ("state_slot", "production-write-operation-start-v1.json"),
    ),
)
def test_pair_slot_collisions_are_schema_defects(field: str, value: str) -> None:
    data = _data() | {field: value}
    _check(_wire(data), _expect(), S.DESCRIPTOR_UNVERIFIABLE)
    _check(_Poison(), _expect(data), S.EXPECTATION_UNVERIFIABLE)


@pytest.mark.parametrize(
    "field,value",
    (
        ("descriptor_slot", "pending.json"),
        ("descriptor_slot", "intent.json"),
        ("administrative_pending_slot", "intent.json"),
    ),
)
def test_expected_control_layout_collisions_precede_candidate(field: str, value: str) -> None:
    _check(_Poison(), replace(_expect(), **{field: value}), S.EXPECTATION_UNVERIFIABLE)


@pytest.mark.parametrize("slot", ("descriptor.json", "pending.json"))
def test_candidate_control_layout_collision_is_mismatch(slot: str) -> None:
    _check(_wire(_data() | {"active_intent_slot": slot}), _expect(), S.ENROLLMENT_MISMATCH)


@pytest.mark.parametrize(
    "value",
    (
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
    ids=range(17),
)
def test_linux_path_lexical_defects_and_utf8_limit(value: str) -> None:
    data = _data() | {"artifact_directory": value}
    _check(_wire(data), _expect(), S.DESCRIPTOR_UNVERIFIABLE)
    _check(_Poison(), _expect(data), S.EXPECTATION_UNVERIFIABLE)


@pytest.mark.parametrize(
    "value",
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
def test_valid_linux_strings_are_compared_without_os_or_unicode_normalization(value: str) -> None:
    data = _data() | {"artifact_directory": value}
    _check(_wire(data), _expect(data), S.DESCRIPTOR_MATCHED_UNAPPROVED)
    _check(_wire(data), _expect(), S.ENROLLMENT_MISMATCH)


def test_case_and_directory_names_are_not_normalized_or_assumed_identical() -> None:
    data = _data() | {"token_slot": "STATE.json", "active_intent_slot": "state.json"}
    expectation = replace(_expect(data), descriptor_slot="State.json")
    _check(_wire(data), expectation, S.DESCRIPTOR_MATCHED_UNAPPROVED)
    changed = data | {"token_slot": "state.JSON"}
    _check(_wire(changed), expectation, S.ENROLLMENT_MISMATCH)
    composed = _data() | {"artifact_directory": "/synthetic/é"}
    decomposed = composed | {"artifact_directory": "/synthetic/e\u0301"}
    _check(_wire(decomposed), _expect(composed), S.ENROLLMENT_MISMATCH)


def test_controlling_both_inputs_proves_neither_authenticity_nor_freshness() -> None:
    old = _data() | {"enrollment_revision": "old-revision", "pair_ref": "other-pair"}
    _check(_wire(old), _expect(), S.ENROLLMENT_MISMATCH)
    for _ in range(2):
        _check(_wire(old), _expect(old), S.DESCRIPTOR_MATCHED_UNAPPROVED)


def test_result_and_expectation_are_frozen_slots_with_no_input_in_repr() -> None:
    expectation = _expect()
    assert not hasattr(expectation, "__dict__")
    for field in fields(expectation):
        assert getattr(expectation, field.name) not in repr(expectation)
    with pytest.raises(FrozenInstanceError):
        expectation.pair_ref = "other"
    assert repr(replace(expectation, pair_ref=_Poison())) == "SyntheticEnrollmentExpectation()"
    with pytest.raises(ValueError, match=r"^Invalid enrollment comparison result$"):
        model.EnrollmentDescriptorResult(_Poison())
    for state in S:
        result = model.EnrollmentDescriptorResult(state)
        assert result.reuse_authorized is False
        assert not fields(result)[1].init
        with pytest.raises(FrozenInstanceError):
            result.reuse_authorized = True
        with pytest.raises(TypeError):
            model.EnrollmentDescriptorResult(state, reuse_authorized=True)
        assert "synthetic" not in repr(result)


@pytest.mark.parametrize(
    "helper,occurrence,phase",
    (
        ("_canonical", 1, "expectation"),
        ("_digest", 1, "expectation"),
        ("_canonical", 2, "candidate"),
        ("_digest", 2, "candidate"),
        ("_parse_descriptor", 1, "candidate"),
    ),
)
@pytest.mark.parametrize("failure", ("ordinary", "interrupt", "exit"))
def test_failures_are_phase_specific_and_cancellation_propagates(
    helper: str,
    occurrence: int,
    phase: str,
    failure: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    original = getattr(model, helper)
    calls = 0
    exception = {"ordinary": RuntimeError, "interrupt": KeyboardInterrupt, "exit": SystemExit}[
        failure
    ]

    def inject(*args: object, **kwargs: object) -> Any:
        nonlocal calls
        calls += 1
        if calls == occurrence:
            raise exception("synthetic-private-diagnostic")
        return original(*args, **kwargs)

    monkeypatch.setattr(model, helper, inject)
    if failure == "ordinary":
        result = _check(
            RAW,
            _expect(),
            S.EXPECTATION_UNVERIFIABLE if phase == "expectation" else S.DESCRIPTOR_UNVERIFIABLE,
        )
        assert "synthetic-private-diagnostic" not in repr(result)
    else:
        with pytest.raises(exception):
            model.validate_enrollment_descriptor(RAW, _expect())
    assert calls == occurrence
    assert capsys.readouterr() == ("", "")


def test_validation_calls_do_not_read_files_or_print(monkeypatch: pytest.MonkeyPatch) -> None:
    expectation = _expect()

    def forbidden(*args: object, **kwargs: object) -> Any:
        raise _PoisonHookCalled("unexpected external effect")

    with monkeypatch.context() as scoped:
        scoped.setattr(builtins, "open", forbidden)
        scoped.setattr(builtins, "print", forbidden)
        scoped.setattr(Path, "open", forbidden)
        _check(RAW, expectation, S.DESCRIPTOR_MATCHED_UNAPPROVED)
        _check(_Poison(), expectation, S.DESCRIPTOR_UNVERIFIABLE)
        _check(RAW, _Poison(), S.EXPECTATION_UNVERIFIABLE)


def test_only_pure_standard_library_dependencies_and_only_approved_runtime_consumer() -> None:
    """Source reads belong to tests, never to the validator's runtime."""
    source = Path(inspect.getfile(model))
    tree = ast.parse(source.read_text(encoding="utf-8"))
    allowed = {"__future__", "dataclasses", "enum", "hashlib", "json", "typing", "unicodedata"}
    forbidden = {
        "open",
        "print",
        "input",
        "eval",
        "exec",
        "compile",
        "__import__",
        "setattr",
        "delattr",
        "globals",
        "locals",
    }
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            assert all(alias.name in allowed for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0 and node.module in allowed
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id not in forbidden
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            assert node.func.attr not in {
                "open",
                "read",
                "write",
                "load",
                "dump",
                "stat",
                "resolve",
                "unlink",
                "mkdir",
                "getenv",
                "system",
                "run",
                "start",
                "acquire",
            }
        assert not isinstance(node, (ast.Global, ast.Nonlocal, ast.AsyncFunctionDef))
    consumers = {
        other.relative_to(source.parent).as_posix()
        for other in source.parent.rglob("*.py")
        if other != source and source.stem in other.read_text(encoding="utf-8")
    }
    assert consumers == {
        "production_write_token_enrollment_preparation.py",
        "production_write_token_disabled_bootstrap_inputs.py",
    }


@pytest.mark.parametrize("base", ("COM", "LPT"))
@pytest.mark.parametrize("number", range(1, 10))
def test_every_numbered_reserved_leaf_is_rejected(base: str, number: int) -> None:
    data = _data() | {"token_slot": f"{base}{number}.json"}
    _check(_wire(data), _expect(), S.DESCRIPTOR_UNVERIFIABLE)


@pytest.mark.parametrize("leaf", ("COM0", "COM10", "LPT0", "LPT10", "CONSOLE"))
def test_near_reserved_leaf_names_are_not_overrejected(leaf: str) -> None:
    data = _data() | {"token_slot": leaf}
    _check(_wire(data), _expect(data), S.DESCRIPTOR_MATCHED_UNAPPROVED)
