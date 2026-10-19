"""Test-owned source acquisition only; no deployment, startup, or use authority."""

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
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

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

S = loader.DisabledBootstrapSourceStage
R = loader.DisabledBootstrapSourceReason
H = handoff.DisabledBootstrapInspectionState
B = inputs.DisabledBootstrapInputState
IS = prep.InspectionState
P = prep.Presence
C = prep.ContentStatus
T = prep.TargetRelation
F = prep.InspectionFailure
SOURCE = "/synthetic-loader-source"
CONTROL = "/synthetic-loader-control"
PAIR = "/synthetic-loader-pair"
POLICY = "policy.json"
COMPANION = "expected.json"
PENDING = "pending.json"
DESCRIPTOR = "descriptor.json"
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
STAT_FIELDS = (
    "st_dev",
    "st_ino",
    "st_mode",
    "st_uid",
    "st_gid",
    "st_nlink",
    "st_size",
    "st_mtime_ns",
    "st_ctime_ns",
)
VALID_PAIRS = (
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
LINUX_ONLY = pytest.mark.skipif(
    sys.platform != "linux", reason="native Linux synthetic source loading"
)
WINDOWS_ONLY = pytest.mark.skipif(
    sys.platform != "win32", reason="native Windows source loading gate"
)


def _wire(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


def _materials(
    control: str = CONTROL, pair: str = PAIR, revision: str = "revision-one"
) -> tuple[bytes, bytes, descriptor.SyntheticEnrollmentExpectation]:
    """Independently declared fixture values, never learned from source/target reads."""
    raw = _wire(
        {
            "format_version": 1,
            "record_kind": "enrollment_descriptor",
            "role": "production_write",
            "record_slot": "production-write-operation-start-v1.json",
            "enrollment_revision": revision,
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
        revision,
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
            "expected_revision": revision,
            "descriptor_pin": expectation.descriptor_pin,
            "expected_state": "PREPARING",
            "entry_mode": "disabled",
        }
    )
    return policy, raw, expectation


def _pending(raw: bytes, revision: str = "revision-one") -> bytes:
    return _wire(
        {
            "format_version": 1,
            "record_kind": "enrollment_preparation",
            "target_revision": revision,
            "target_pin": hashlib.sha256(raw).hexdigest(),
            "outcome": "pending",
        }
    )


class _UnexpectedEffect(BaseException):
    pass


def _deny(*args: object, **kwargs: object) -> Any:
    raise _UnexpectedEffect("unexpected synthetic source-loading effect")


class _Poison:
    __repr__ = __str__ = __bytes__ = __len__ = __iter__ = __eq__ = __hash__ = _deny
    __getattribute__ = __fspath__ = _deny


class _String(str):
    pass


class _Bytes(bytes):
    pass


def _call(
    *,
    root: object = SOURCE,
    policy: object = POLICY,
    companion: object = COMPANION,
    expectation: object = None,
    control: object = CONTROL,
) -> Any:
    if expectation is None:
        expectation = _materials()[2]
    return loader.load_synthetic_disabled_bootstrap(
        root, policy, companion, expectation, expected_control_root=control
    )


def _refused(result: Any, stage: S, reason: R) -> None:
    assert type(result) is loader.DisabledBootstrapSourceRefusal
    assert (result.stage, result.reason) == (stage, reason)
    assert result.reuse_authorized is False
    assert tuple(item.name for item in fields(result)) == (
        "stage",
        "reason",
        "reuse_authorized",
    )
    assert not hasattr(result, "__dict__")


def _observation(case: str) -> prep.PreparationInspection:
    absent = prep.LeafObservation(P.ABSENT)
    match = prep.LeafObservation(P.PRESENT, C.SCHEMA_VALID, T.MATCH)
    mismatch = prep.LeafObservation(P.PRESENT, C.SCHEMA_VALID, T.MISMATCH)
    if case == "platform":
        return prep.PreparationInspection(IS.UNSUPPORTED_PLATFORM)
    if case == "busy":
        return prep.PreparationInspection(IS.LOCK_BUSY, first_failure=F.ACQUIRE)
    if case == "unavailable":
        return prep.PreparationInspection(
            IS.LOCK_UNAVAILABLE, first_failure=F.ENTRY, exit_failure_observed=True
        )
    if case == "pending":
        return prep.PreparationInspection(
            IS.ADMIN_PENDING, match, absent, verification_complete=True
        )
    if case == "both":
        return prep.PreparationInspection(
            IS.PREPARATION_RETAINED_UNAPPROVED, match, match, T.MATCH, verification_complete=True
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
    raise AssertionError("unknown synthetic observation case")


def _diagnostic(case: str = "pending") -> handoff.DisabledBootstrapInspectionResult:
    return handoff.DisabledBootstrapInspectionResult(
        H.INSPECTION_OBSERVED,
        inputs.DisabledBootstrapInputResult(B.INPUTS_MATCHED_UNAPPROVED),
        _observation(case),
    )


def _info(index: int, size: int) -> SimpleNamespace:
    return SimpleNamespace(
        st_dev=11,
        st_ino=20 + index,
        st_mode=(stat.S_IFDIR | 0o700) if index == 0 else (stat.S_IFREG | 0o600),
        st_uid=1001,
        st_gid=1001,
        st_nlink=2 if index == 0 else 1,
        st_size=size,
        st_mtime_ns=100,
        st_ctime_ns=200,
        st_atime_ns=300,
    )


class _Boundaries:
    """Replace only loader-local boundaries; never patch global OS implementation."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.policy, self.raw, self.expectation = _materials()
        self.metadata: list[Any] = [
            _info(0, 4096),
            _info(1, len(self.policy)),
            _info(2, len(self.raw)),
        ]
        self.metadata += [SimpleNamespace(**vars(item)) for item in self.metadata]
        self.reads: list[Any] = [self.policy, self.raw]
        self.result: Any = _diagnostic()
        self.events: list[str] = []
        self.paths: list[Path] = []
        self.read_paths: list[Path] = []
        self.arguments: list[tuple[tuple[Any, ...], dict[str, Any]]] = []
        self.uid: Any = 1001
        self.platform: Any = True
        monkeypatch.setattr(loader, "_linux_supported", self.supported)
        monkeypatch.setattr(loader, "_effective_uid", self.effective_uid)
        monkeypatch.setattr(loader, "_lstat", self.lstat)
        monkeypatch.setattr(loader, "read_private_sensitive_bytes", self.read)
        monkeypatch.setattr(loader, "inspect_synthetic_disabled_bootstrap", self.handoff)

    def supported(self) -> bool:
        self.events.append("platform")
        if issubclass(type(self.platform), BaseException):
            raise self.platform
        return self.platform

    def effective_uid(self) -> int:
        self.events.append("uid")
        if issubclass(type(self.uid), BaseException):
            raise self.uid
        return self.uid

    def lstat(self, path: Path) -> Any:
        self.events.append("lstat")
        self.paths.append(path)
        item = self.metadata[len(self.paths) - 1]
        if issubclass(type(item), BaseException):
            raise item
        return item

    def read(self, path: Path, *, max_size: int) -> Any:
        self.events.append("read")
        self.read_paths.append(path)
        assert max_size == 8192
        item = self.reads[len(self.read_paths) - 1]
        if issubclass(type(item), BaseException):
            raise item
        return item

    def handoff(self, *args: Any, **kwargs: Any) -> Any:
        self.events.append("handoff")
        self.arguments.append((args, kwargs))
        if issubclass(type(self.result), BaseException):
            raise self.result
        return self.result

    def counts(self, metadata: int, reads: int, calls: int) -> None:
        assert (len(self.paths), len(self.read_paths), len(self.arguments)) == (
            metadata,
            reads,
            calls,
        )


def test_api_has_exact_five_required_inputs_and_keyword_only_control_root() -> None:
    signature = inspect.signature(loader.load_synthetic_disabled_bootstrap)
    assert tuple(signature.parameters) == (
        "source_root",
        "policy_leaf",
        "expected_descriptor_leaf",
        "expectation",
        "expected_control_root",
    )
    assert all(item.default is inspect.Parameter.empty for item in signature.parameters.values())
    assert signature.parameters["expected_control_root"].kind is inspect.Parameter.KEYWORD_ONLY
    with pytest.raises(TypeError):
        loader.load_synthetic_disabled_bootstrap(SOURCE, POLICY, COMPANION, _materials()[2])
    with pytest.raises(TypeError):
        loader.load_synthetic_disabled_bootstrap(
            SOURCE, POLICY, COMPANION, _materials()[2], CONTROL
        )


@pytest.mark.parametrize("argument", ("root", "policy", "companion", "control"))
@pytest.mark.parametrize("kind", ("none", "integer", "poison", "subclass", "path", "bytes"))
def test_capture_rejects_nonexact_strings_without_hooks_or_io(
    argument: str, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    value = {
        "none": None,
        "integer": 7,
        "poison": _Poison(),
        "subclass": _String("synthetic"),
        "path": Path("synthetic"),
        "bytes": b"synthetic",
    }[kind]
    _refused(_call(**{argument: value}), S.CAPTURE, R.INPUT_UNVERIFIABLE)
    assert boundary.events == []


@pytest.mark.parametrize("field", EXPECTATION_FIELDS)
@pytest.mark.parametrize("kind", ("missing", "poison", "subclass", "integer"))
def test_expectation_requires_all_eleven_exact_fields_without_unknown_hooks(
    field: str, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    expected = _materials()[2]
    if kind == "missing":
        object.__delattr__(expected, field)
    else:
        object.__setattr__(
            expected, field, {"poison": _Poison(), "subclass": _String("x"), "integer": 3}[kind]
        )
    _refused(_call(expectation=expected), S.CAPTURE, R.INPUT_UNVERIFIABLE)
    assert boundary.events == []


@pytest.mark.parametrize("kind", ("unknown", "subclass", "none"))
def test_expectation_exact_type_is_required(kind: str, monkeypatch: pytest.MonkeyPatch) -> None:
    boundary = _Boundaries(monkeypatch)

    class Derived(descriptor.SyntheticEnrollmentExpectation):
        pass

    expected = _materials()[2]
    value = (
        Derived(*(getattr(expected, field) for field in EXPECTATION_FIELDS))
        if kind == "subclass"
        else (_Poison() if kind == "unknown" else None)
    )
    result = loader.load_synthetic_disabled_bootstrap(
        SOURCE, POLICY, COMPANION, value, expected_control_root=CONTROL
    )
    _refused(result, S.CAPTURE, R.INPUT_UNVERIFIABLE)
    assert boundary.events == []


@pytest.mark.parametrize("argument", ("root", "control", "pair"))
@pytest.mark.parametrize(
    "value",
    (
        "",
        "relative",
        "/",
        "//name",
        "/name/",
        "/a//b",
        "/a/./b",
        "/a/../b",
        "/a/.git/b",
        "/a\\b",
        "/a:b",
        "/a\x00b",
        "/a\nb",
        "/a\ud800b",
        "/a /b",
        "/a./b",
        "/" + "x" * 1024,
        "/" + "é" * 512,
    ),
    ids=lambda value: "invalid-path",
)
def test_linux_path_lexical_refusal_is_pure_on_every_platform(
    argument: str, value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    kwargs: dict[str, Any] = {}
    if argument == "pair":
        kwargs["expectation"] = replace(_materials()[2], artifact_directory=value)
    else:
        kwargs[argument] = value
    _refused(_call(**kwargs), S.CAPTURE, R.INPUT_UNVERIFIABLE)
    assert boundary.events == []


@pytest.mark.parametrize("argument", ("policy", "companion"))
@pytest.mark.parametrize(
    "value",
    (
        "",
        ".",
        "..",
        "_name",
        "-name",
        "/name",
        "a/b",
        "a\\b",
        "a:b",
        "a ",
        "a.",
        "é",
        "a\n",
        "x" * 97,
        "CON",
        "con.json",
        "PrN.txt",
        "AUX",
        "nul.bin",
        "COM1",
        "com9.json",
        "LPT1",
        "lpt9.txt",
    ),
    ids=lambda value: "invalid-leaf",
)
def test_leaf_bounds_and_device_names_are_rejected_without_normalization(
    argument: str, value: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    _refused(_call(**{argument: value}), S.CAPTURE, R.INPUT_UNVERIFIABLE)
    assert boundary.events == []


@pytest.mark.parametrize("leaf", ("A", "a" * 96, "COM0.json", "LPT10", "NULish", "Ab.C_d-1"))
def test_valid_leaf_bytes_are_retained_without_case_or_unicode_normalization(
    leaf: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    result = _call(policy=leaf)
    assert type(result) is handoff.DisabledBootstrapInspectionResult
    assert boundary.read_paths[0] == Path(SOURCE) / leaf
    boundary.counts(6, 2, 1)


@pytest.mark.parametrize("root", ("/" + "x" * 1023, "/" + "é" * 511 + "a", "/e\u0301"))
def test_path_length_boundary_and_unicode_spelling_are_retained(
    root: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    _call(root=root)
    assert boundary.paths[0] == Path(root)
    boundary.counts(6, 2, 1)


@pytest.mark.parametrize("target", ("control", "pair"))
@pytest.mark.parametrize("relation", ("equal", "source-parent", "source-child"))
def test_component_overlap_refuses_before_platform(
    target: str, relation: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    value = (
        SOURCE
        if relation == "equal"
        else (SOURCE + "/child" if relation == "source-parent" else "/synthetic")
    )
    root = SOURCE if relation != "source-child" else "/synthetic/child"
    kwargs = (
        {"control": value}
        if target == "control"
        else {"expectation": replace(_materials()[2], artifact_directory=value)}
    )
    _refused(_call(root=root, **kwargs), S.CAPTURE, R.SOURCE_OVERLAP)
    assert boundary.events == []


def test_adjacent_component_names_are_not_overlap(monkeypatch: pytest.MonkeyPatch) -> None:
    boundary = _Boundaries(monkeypatch)
    _call(
        control=SOURCE + "-neighbor",
        expectation=replace(_materials()[2], artifact_directory=SOURCE + "-pair"),
    )
    boundary.counts(6, 2, 1)


def test_format_refusal_precedes_overlap_and_expectation_fields_are_read_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boundary = _Boundaries(monkeypatch)
    original = descriptor.SyntheticEnrollmentExpectation.__getattribute__
    expected = _materials()[2]
    accesses: list[str] = []

    def get(self: Any, name: str) -> Any:
        if self is expected and name in EXPECTATION_FIELDS:
            accesses.append(name)
        return original(self, name)

    monkeypatch.setattr(descriptor.SyntheticEnrollmentExpectation, "__getattribute__", get)
    _refused(
        _call(policy=COMPANION, expectation=expected, control="bad"),
        S.CAPTURE,
        R.INPUT_UNVERIFIABLE,
    )
    assert accesses == [] and boundary.events == []
    _refused(_call(policy=COMPANION, expectation=expected), S.CAPTURE, R.SOURCE_OVERLAP)
    assert accesses == list(EXPECTATION_FIELDS) and boundary.events == []


def test_capture_reads_each_declared_field_once_before_checking_field_types(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boundary = _Boundaries(monkeypatch)
    expected = _materials()[2]
    accesses: list[str] = []
    original = descriptor.SyntheticEnrollmentExpectation.__getattribute__

    def get(self: Any, name: str) -> Any:
        if self is expected and name in EXPECTATION_FIELDS:
            accesses.append(name)
        return original(self, name)

    monkeypatch.setattr(descriptor.SyntheticEnrollmentExpectation, "__getattribute__", get)
    object.__setattr__(expected, "artifact_directory", _Poison())
    _refused(_call(expectation=expected), S.CAPTURE, R.INPUT_UNVERIFIABLE)
    assert accesses == list(EXPECTATION_FIELDS)
    assert boundary.events == []


def test_platform_gate_precedes_path_construction_metadata_and_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boundary = _Boundaries(monkeypatch)
    boundary.platform = False
    monkeypatch.setattr(loader, "Path", _deny)
    _refused(_call(), S.PLATFORM, R.UNSUPPORTED_PLATFORM)
    assert boundary.events == ["platform"]
    boundary.counts(0, 0, 0)


def test_normal_schedule_and_retained_bytes_are_exact(monkeypatch: pytest.MonkeyPatch) -> None:
    boundary = _Boundaries(monkeypatch)
    result = _call(expectation=boundary.expectation)
    assert result == boundary.result and result is not boundary.result
    assert result.reuse_authorized is False
    assert boundary.events == [
        "platform",
        "uid",
        "lstat",
        "lstat",
        "lstat",
        "read",
        "read",
        "lstat",
        "lstat",
        "lstat",
        "handoff",
    ]
    assert boundary.paths == [Path(SOURCE), Path(SOURCE) / POLICY, Path(SOURCE) / COMPANION] * 2
    assert boundary.read_paths == [Path(SOURCE) / POLICY, Path(SOURCE) / COMPANION]
    args, kwargs = boundary.arguments[0]
    assert args[0] is boundary.policy and args[1] is boundary.raw
    assert args[2] == boundary.expectation and args[2] is not boundary.expectation
    assert kwargs == {"expected_control_root": CONTROL}
    boundary.counts(6, 2, 1)


def test_caller_mutation_after_capture_cannot_replace_retained_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boundary = _Boundaries(monkeypatch)
    expected = _materials()[2]
    retained_values = tuple(getattr(expected, field) for field in EXPECTATION_FIELDS)
    original = boundary.supported

    def supported() -> bool:
        for field in EXPECTATION_FIELDS:
            object.__setattr__(expected, field, "SYNTHETIC_CALLER_CHANGED")
        return original()

    monkeypatch.setattr(loader, "_linux_supported", supported)
    _call(expectation=expected)
    captured = boundary.arguments[0][0][2]
    assert tuple(getattr(captured, field) for field in EXPECTATION_FIELDS) == retained_values
    assert captured is not expected


@pytest.mark.parametrize("value", (OSError("SYNTHETIC_UID_FAILURE"), None, True, -1, "1001"))
def test_effective_owner_is_never_assumed(value: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    boundary = _Boundaries(monkeypatch)
    boundary.uid = value
    _refused(_call(), S.PRECHECK, R.SOURCE_UNVERIFIABLE)
    boundary.counts(0, 0, 0)


@pytest.mark.parametrize("position", range(6))
@pytest.mark.parametrize("failure", ("missing", "ordinary", "invalid-field"))
def test_each_metadata_failure_stops_without_later_calls(
    position: int, failure: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    if failure == "invalid-field":
        boundary.metadata[position].st_ino = True
    else:
        boundary.metadata[position] = (FileNotFoundError if failure == "missing" else OSError)(
            "SYNTHETIC_METADATA_FAILURE"
        )
    _refused(_call(), S.PRECHECK if position < 3 else S.RECHECK, R.SOURCE_UNVERIFIABLE)
    boundary.counts(position + 1, 0 if position < 3 else 2, 0)


@pytest.mark.parametrize("field", STAT_FIELDS)
@pytest.mark.parametrize("kind", ("missing", "bool", "poison", "string"))
def test_required_metadata_fields_must_be_present_exact_integers(
    field: str, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    value = boundary.metadata[0]
    if kind == "missing":
        delattr(value, field)
    else:
        setattr(value, field, {"bool": True, "poison": _Poison(), "string": "1"}[kind])
    _refused(_call(), S.PRECHECK, R.SOURCE_UNVERIFIABLE)
    boundary.counts(1, 0, 0)


@pytest.mark.parametrize(
    "position,field,value",
    (
        (0, "st_mode", stat.S_IFREG | 0o700),
        (0, "st_mode", stat.S_IFLNK | 0o700),
        (0, "st_mode", stat.S_IFDIR | 0o750),
        (0, "st_uid", 1002),
        (1, "st_mode", stat.S_IFDIR | 0o600),
        (1, "st_mode", stat.S_IFLNK | 0o600),
        (1, "st_mode", stat.S_IFIFO | 0o600),
        (1, "st_mode", stat.S_IFREG | 0o640),
        (1, "st_uid", 1002),
        (1, "st_nlink", 2),
        (1, "st_size", 0),
        (1, "st_size", -1),
        (1, "st_size", 8193),
        (2, "st_uid", 1002),
        (2, "st_nlink", 0),
        (2, "st_mode", stat.S_IFREG | 0o604),
    ),
)
def test_root_and_leaf_private_conditions_refuse_at_first_unsafe_object(
    position: int, field: str, value: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    setattr(boundary.metadata[position], field, value)
    _refused(_call(), S.PRECHECK, R.SOURCE_UNVERIFIABLE)
    boundary.counts(position + 1, 0, 0)


@pytest.mark.parametrize("mode", (0o400, 0o600))
def test_owner_readable_leaf_modes_are_accepted(mode: int, monkeypatch: pytest.MonkeyPatch) -> None:
    boundary = _Boundaries(monkeypatch)
    for position in (1, 2, 4, 5):
        boundary.metadata[position].st_mode = stat.S_IFREG | mode
    _call()
    boundary.counts(6, 2, 1)


def test_equal_leaf_identity_is_precheck_overlap(monkeypatch: pytest.MonkeyPatch) -> None:
    boundary = _Boundaries(monkeypatch)
    boundary.metadata[2].st_ino = boundary.metadata[1].st_ino
    _refused(_call(), S.PRECHECK, R.SOURCE_OVERLAP)
    boundary.counts(3, 0, 0)


@pytest.mark.parametrize("position", (3, 4, 5))
@pytest.mark.parametrize("field", STAT_FIELDS)
def test_every_comparable_signature_change_stops_recheck_immediately(
    position: int, field: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    setattr(boundary.metadata[position], field, getattr(boundary.metadata[position], field) + 1)
    _refused(_call(), S.RECHECK, R.SOURCE_CHANGED)
    boundary.counts(position + 1, 2, 0)


def test_leaf_alias_introduced_during_recheck_is_changed_not_overlap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boundary = _Boundaries(monkeypatch)
    boundary.metadata[5].st_ino = boundary.metadata[4].st_ino
    _refused(_call(), S.RECHECK, R.SOURCE_CHANGED)
    boundary.counts(6, 2, 0)


def test_atime_changes_are_not_part_of_signature(monkeypatch: pytest.MonkeyPatch) -> None:
    boundary = _Boundaries(monkeypatch)
    for value in boundary.metadata[3:]:
        value.st_atime_ns += 999
    _call()
    boundary.counts(6, 2, 1)


@pytest.mark.parametrize("position", (3, 4, 5))
def test_recheck_private_verification_failure_is_unverifiable_and_terminal(
    position: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    original = loader._require_private
    checks = 0

    def check(value: Any, uid: int, *, root: bool) -> None:
        nonlocal checks
        checks += 1
        if checks == position + 1:
            raise RuntimeError("SYNTHETIC_PRIVATE_CHECK_FAILURE")
        original(value, uid, root=root)

    monkeypatch.setattr(loader, "_require_private", check)
    _refused(_call(), S.RECHECK, R.SOURCE_UNVERIFIABLE)
    assert checks == position + 1
    boundary.counts(position + 1, 2, 0)


@pytest.mark.parametrize("position", (0, 1))
@pytest.mark.parametrize(
    "kind", ("exception", "poison", "subclass", "bytearray", "none", "empty", "oversize")
)
def test_each_reader_failure_stops_without_fallback_or_handoff(
    position: int, kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    boundary.reads[position] = {
        "exception": OSError("SYNTHETIC_READ_CANARY"),
        "poison": _Poison(),
        "subclass": _Bytes(b"x"),
        "bytearray": bytearray(b"x"),
        "none": None,
        "empty": b"",
        "oversize": b"x" * 8193,
    }[kind]
    _refused(_call(), S.POLICY_READ if position == 0 else S.COMPANION_READ, R.SOURCE_UNVERIFIABLE)
    boundary.counts(3, position + 1, 0)


@pytest.mark.parametrize("size", (1, 8192))
def test_payload_byte_bounds_are_accepted_without_parsing_in_loader(
    size: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    boundary.reads = [b"p" * size, b"d" * size]
    for position in (1, 2, 4, 5):
        boundary.metadata[position].st_size = size
    _call()
    assert boundary.arguments[0][0][:2] == tuple(boundary.reads)
    boundary.counts(6, 2, 1)


@pytest.mark.parametrize("position", (0, 1))
def test_bytes_size_mismatch_is_changed_not_read_refusal(
    position: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    boundary.reads[position] += b" "
    _refused(_call(), S.RECHECK, R.SOURCE_CHANGED)
    boundary.counts(5 + position, 2, 0)


@pytest.mark.parametrize("case", ("policy-invalid", "mixed", "enabled", "coherent-old"))
def test_real_handoff_semantics_follow_both_source_reads(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    calls: list[tuple[Any, ...]] = []
    expected = boundary.expectation
    if case == "policy-invalid":
        boundary.reads[0] = b"{}\n"
    elif case == "mixed":
        boundary.reads[1] = _materials(revision="revision-two")[1]
    elif case == "enabled":
        boundary.reads[0] = boundary.policy.replace(b'"disabled"', b'"enabled"')
    else:
        policy, raw, expected = _materials(revision="coherent-old")
        boundary.reads = [policy, raw]
    for position in (1, 2, 4, 5):
        boundary.metadata[position].st_size = len(boundary.reads[(position - 1) % 3])

    def invoke(*args: Any, **kwargs: Any) -> Any:
        calls.append(args)
        return handoff.inspect_synthetic_disabled_bootstrap(*args, **kwargs)

    monkeypatch.setattr(loader, "inspect_synthetic_disabled_bootstrap", invoke)
    observed: list[str] = []

    def observe(*args: Any, **kwargs: Any) -> Any:
        observed.append("inspect")
        return _observation("pending")

    monkeypatch.setattr(handoff, "inspect_synthetic_enrollment_preparation", observe)
    result = _call(expectation=expected)
    assert len(calls) == 1 and len(boundary.read_paths) == 2
    assert result.reuse_authorized is False
    if case == "coherent-old":
        assert result.state is H.INSPECTION_OBSERVED and observed == ["inspect"]
        assert result.inspection_result.state is IS.ADMIN_PENDING
    else:
        assert result.state is H.VALIDATION_REFUSED and observed == []


@pytest.mark.parametrize("stage,reason", VALID_PAIRS)
def test_all_eleven_source_refusals_are_immutable_nonauthorizing(stage: S, reason: R) -> None:
    result = loader.DisabledBootstrapSourceRefusal(stage, reason)
    _refused(result, stage, reason)
    with pytest.raises(FrozenInstanceError):
        result.reason = R.SOURCE_CHANGED
    with pytest.raises(TypeError):
        loader.DisabledBootstrapSourceRefusal(stage, reason, True)


@pytest.mark.parametrize("stage", tuple(S))
@pytest.mark.parametrize("reason", tuple(R))
def test_source_refusal_combinations_are_closed(stage: S, reason: R) -> None:
    if (stage, reason) in VALID_PAIRS:
        _refused(loader.DisabledBootstrapSourceRefusal(stage, reason), stage, reason)
    else:
        with pytest.raises(ValueError) as caught:
            loader.DisabledBootstrapSourceRefusal(stage, reason)
        assert "SOURCE" not in str(caught.value)


def _counterfeit(member: Any) -> Any:
    value = str.__new__(type(member), member.value)
    object.__setattr__(value, "_name_", member.name)
    object.__setattr__(value, "_value_", member.value)
    return value


@pytest.mark.parametrize("field", ("stage", "reason", "reuse_authorized"))
@pytest.mark.parametrize("kind", ("string", "poison", "counterfeit", "zero"))
def test_refusal_rejects_forged_members_and_nonfalse_authorization(field: str, kind: str) -> None:
    result = loader.DisabledBootstrapSourceRefusal(S.CAPTURE, R.INPUT_UNVERIFIABLE)
    original = getattr(result, field)
    value = (
        (_counterfeit(original) if field != "reuse_authorized" else True)
        if kind == "counterfeit"
        else (
            0 if kind == "zero" else (_Poison() if kind == "poison" else "SYNTHETIC_FORGED_CANARY")
        )
    )
    object.__setattr__(result, field, value)
    with pytest.raises(ValueError) as caught:
        result.__post_init__()
    assert "CANARY" not in str(caught.value) and "CANARY" not in repr(caught.value)


@pytest.mark.parametrize(
    "case", ("platform", "busy", "unavailable", "pending", "both", "changed", "failed-conflict")
)
def test_handoff_diagnostic_copy_preserves_all_negative_observation_fields(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    boundary.result = _diagnostic(case)
    result = _call()
    assert result == boundary.result and result is not boundary.result
    assert result.input_result is not boundary.result.input_result
    assert result.inspection_result is not boundary.result.inspection_result
    assert result.inspection_result.pending is not boundary.result.inspection_result.pending
    assert result.reuse_authorized is False
    boundary.counts(6, 2, 1)


@pytest.mark.parametrize(
    "state",
    (
        H.CAPTURE_REFUSED,
        H.VALIDATION_UNVERIFIABLE,
        H.VALIDATION_REFUSED,
        H.INSPECTION_FAILED,
        H.INSPECTION_RESULT_UNVERIFIABLE,
    ),
)
def test_valid_handoff_refusal_states_remain_handoff_diagnostics(
    state: H, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    input_result = None
    if state is H.VALIDATION_REFUSED:
        input_result = inputs.DisabledBootstrapInputResult(B.POLICY_UNVERIFIABLE)
    elif state in {H.INSPECTION_FAILED, H.INSPECTION_RESULT_UNVERIFIABLE}:
        input_result = inputs.DisabledBootstrapInputResult(B.INPUTS_MATCHED_UNAPPROVED)
    boundary.result = handoff.DisabledBootstrapInspectionResult(state, input_result)
    result = _call()
    assert type(result) is handoff.DisabledBootstrapInspectionResult
    assert result == boundary.result and result is not boundary.result
    assert result.state is state and result.reuse_authorized is False
    assert result.inspection_result is None
    boundary.counts(6, 2, 1)


@pytest.mark.parametrize(
    "case", ("unknown", "true", "zero", "fake-state", "nested-true", "missing", "exception")
)
def test_unverifiable_handoff_return_is_not_a_success_or_partial_diagnostic(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    if case == "unknown":
        boundary.result = _Poison()
    elif case == "exception":
        boundary.result = RuntimeError("SYNTHETIC_HANDOFF_CANARY")
    elif case == "missing":
        object.__delattr__(boundary.result, "input_result")
    elif case in {"true", "zero"}:
        object.__setattr__(boundary.result, "reuse_authorized", True if case == "true" else 0)
    elif case == "fake-state":
        object.__setattr__(boundary.result, "state", _counterfeit(H.INSPECTION_OBSERVED))
    else:
        object.__setattr__(boundary.result.inspection_result, "reuse_authorized", True)
    _refused(
        _call(),
        S.HANDOFF,
        R.HANDOFF_FAILED if case == "exception" else R.HANDOFF_RESULT_UNVERIFIABLE,
    )
    boundary.counts(6, 2, 1)


def test_handoff_return_fields_are_captured_once(monkeypatch: pytest.MonkeyPatch) -> None:
    boundary = _Boundaries(monkeypatch)
    value = boundary.result
    counts: list[str] = []
    original = handoff.DisabledBootstrapInspectionResult.__getattribute__

    def access(self: Any, name: str) -> Any:
        if self is value and name in {
            "state",
            "input_result",
            "inspection_result",
            "reuse_authorized",
        }:
            counts.append(name)
        return original(self, name)

    monkeypatch.setattr(handoff.DisabledBootstrapInspectionResult, "__getattribute__", access)
    _call()
    assert counts == ["state", "input_result", "inspection_result", "reuse_authorized"]


@pytest.mark.parametrize("kind", ("subclass", "revalidation"))
def test_fixed_exception_class_is_special_only_when_exact_and_from_handoff_call(
    kind: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)

    class Derived(handoff.DisabledBootstrapInspectionResultError):
        pass

    if kind == "subclass":
        boundary.result = Derived()
    else:

        def fail(self: Any) -> None:
            raise handoff.DisabledBootstrapInspectionResultError()

        monkeypatch.setattr(handoff.DisabledBootstrapInspectionResult, "__post_init__", fail)
    _refused(
        _call(),
        S.HANDOFF,
        R.HANDOFF_FAILED if kind == "subclass" else R.HANDOFF_RESULT_UNVERIFIABLE,
    )


def test_genuine_handoff_fixed_error_identity_checked_negatives_and_links_survive(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    boundary = _Boundaries(monkeypatch)
    observed = _observation("failed-conflict")
    monkeypatch.setattr(
        handoff, "inspect_synthetic_enrollment_preparation", lambda *a, **k: observed
    )
    original = handoff.DisabledBootstrapInspectionResult.__post_init__
    captured: list[handoff.DisabledBootstrapInspectionResultError] = []

    def fail(self: Any) -> None:
        raise RuntimeError("SYNTHETIC_HANDOFF_CONSTRUCTOR_CANARY")

    def invoke(*args: Any, **kwargs: Any) -> Any:
        monkeypatch.setattr(handoff.DisabledBootstrapInspectionResult, "__post_init__", fail)
        try:
            return handoff.inspect_synthetic_disabled_bootstrap(*args, **kwargs)
        except handoff.DisabledBootstrapInspectionResultError as error:
            captured.append(error)
            raise
        finally:
            monkeypatch.setattr(
                handoff.DisabledBootstrapInspectionResult, "__post_init__", original
            )

    monkeypatch.setattr(loader, "inspect_synthetic_disabled_bootstrap", invoke)
    with pytest.raises(handoff.DisabledBootstrapInspectionResultError) as caught:
        _call()
    assert caught.value is captured[0]
    assert caught.value.inspection_result == observed
    assert caught.value.input_result.state is B.INPUTS_MATCHED_UNAPPROVED
    assert caught.value.reuse_authorized is False
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert "CANARY" not in str(caught.value)
    assert len(boundary.read_paths) == 2


@pytest.mark.parametrize("caller_state", ("ordinary", "except", "finally"))
def test_source_constructor_failure_has_fixed_message_no_links_or_input_and_preserves_caller(
    caller_state: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    boundary.platform = False
    original = RuntimeError("SYNTHETIC_ORIGINAL_CANARY")
    original.add_note("SYNTHETIC_ORIGINAL_NOTE")
    caller = ValueError("SYNTHETIC_CALLER_CANARY")
    caller.add_note("SYNTHETIC_CALLER_NOTE")
    caller.__cause__ = LookupError("SYNTHETIC_CALLER_CAUSE")
    before = (caller.args, caller.__cause__, caller.__context__, tuple(caller.__notes__))

    def fail(self: Any) -> None:
        raise original

    monkeypatch.setattr(loader.DisabledBootstrapSourceRefusal, "__post_init__", fail)
    with pytest.raises(loader.DisabledBootstrapSourceResultError) as caught:
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
    assert error.args == ("Disabled bootstrap source result construction failed",)
    assert error.reuse_authorized is False
    assert error.__cause__ is None and error.__context__ is None
    assert not hasattr(error, "__notes__") and not vars(error)
    assert "CANARY" not in repr(error)
    assert (caller.args, caller.__cause__, caller.__context__, tuple(caller.__notes__)) == before
    assert original.args == ("SYNTHETIC_ORIGINAL_CANARY",)
    assert original.__notes__ == ["SYNTHETIC_ORIGINAL_NOTE"]
    boundary.counts(0, 0, 0)


@pytest.mark.parametrize(
    "phase",
    ("capture", "metadata", "recheck", "policy", "companion", "handoff", "result", "refusal"),
)
@pytest.mark.parametrize(
    "cancel_type", (KeyboardInterrupt, SystemExit), ids=lambda kind: kind.__name__
)
def test_cancellation_propagates_original_without_retries_or_rewriting(
    phase: str, cancel_type: type[BaseException], monkeypatch: pytest.MonkeyPatch
) -> None:
    boundary = _Boundaries(monkeypatch)
    cancel = cancel_type("SYNTHETIC_CANCEL")
    cancel.add_note("SYNTHETIC_CANCEL_NOTE")

    def cancelled(*args: Any, **kwargs: Any) -> Any:
        raise cancel

    if phase == "capture":
        monkeypatch.setattr(loader, "_capture_inputs", cancelled)
    elif phase == "metadata":
        boundary.metadata[1] = cancel
    elif phase == "recheck":
        boundary.metadata[4] = cancel
    elif phase in {"policy", "companion"}:
        boundary.reads[0 if phase == "policy" else 1] = cancel
    elif phase == "handoff":
        boundary.result = cancel
    elif phase == "result":
        monkeypatch.setattr(handoff.DisabledBootstrapInspectionResult, "__post_init__", cancelled)
    else:
        boundary.platform = False
        monkeypatch.setattr(loader.DisabledBootstrapSourceRefusal, "__post_init__", cancelled)
    with pytest.raises(cancel_type) as caught:
        _call()
    assert caught.value is cancel and cancel.args == ("SYNTHETIC_CANCEL",)
    assert cancel.__notes__ == ["SYNTHETIC_CANCEL_NOTE"] and cancel.__cause__ is None
    expected = {
        "capture": (0, 0, 0),
        "metadata": (2, 0, 0),
        "recheck": (5, 2, 0),
        "policy": (3, 1, 0),
        "companion": (3, 2, 0),
        "handoff": (6, 2, 1),
        "result": (6, 2, 1),
        "refusal": (0, 0, 0),
    }[phase]
    boundary.counts(*expected)


def test_private_capture_is_frozen_slotted_and_all_fields_are_hidden() -> None:
    captured = loader._capture_inputs(SOURCE, POLICY, COMPANION, _materials()[2], CONTROL)
    assert all(not item.repr for item in fields(captured))
    assert not hasattr(captured, "__dict__") and "synthetic" not in repr(captured)
    with pytest.raises(FrozenInstanceError):
        captured.source_root = "changed"
    assert not hasattr(loader, "snapshot") and not hasattr(loader, "export_snapshot")


def _forbid_effects(monkeypatch: pytest.MonkeyPatch, *, direct_only: bool = False) -> list[str]:
    effects: list[str] = []

    def forbidden(*args: Any, **kwargs: Any) -> Any:
        effects.append("FORBIDDEN_EFFECT")
        raise _UnexpectedEffect("forbidden synthetic source-loading effect")

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
        monkeypatch.setattr(prep.private_lock, "acquire_posix_private_directory_lock", forbidden)
    return effects


def test_mock_loading_has_no_writer_generic_reader_lock_or_secret_diagnostic(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    boundary = _Boundaries(monkeypatch)
    effects = _forbid_effects(monkeypatch, direct_only=True)
    boundary.reads[1] = OSError("SYNTHETIC_SOURCE_SECRET_CANARY")
    result = _call(root="/SYNTHETIC_ROOT_CANARY")
    _refused(result, S.COMPANION_READ, R.SOURCE_UNVERIFIABLE)
    assert "CANARY" not in repr(result) and "CANARY" not in str(result)
    captured = capsys.readouterr()
    assert captured.out == captured.err == "" and effects == []
    boundary.counts(3, 2, 0)


@WINDOWS_ONLY
def test_native_windows_source_gate_rejects_without_any_source_or_handoff_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "_effective_uid",
        "_lstat",
        "read_private_sensitive_bytes",
        "inspect_synthetic_disabled_bootstrap",
    ):
        monkeypatch.setattr(loader, name, _deny)
    effects = _forbid_effects(monkeypatch, direct_only=True)
    _refused(_call(), S.PLATFORM, R.UNSUPPORTED_PLATFORM)
    assert effects == []


_APPLICATION_IMPORTS = {
    "tridentine_calendar_google_sync.production_write_token_disabled_bootstrap_inspection": {
        "DisabledBootstrapInspectionResult",
        "DisabledBootstrapInspectionResultError",
        "inspect_synthetic_disabled_bootstrap",
    },
    "tridentine_calendar_google_sync.production_write_token_enrollment_descriptor": {
        "SyntheticEnrollmentExpectation",
    },
    "tridentine_calendar_google_sync.sensitive_paths": {"read_private_sensitive_bytes"},
}
_STANDARD_IMPORTS = {
    "__future__": {"annotations"},
    "dataclasses": {"dataclass", "field"},
    "enum": {"StrEnum"},
    "pathlib": {"Path"},
    "typing": {"Literal", "cast"},
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
    "cast",
    "DisabledBootstrapSourceRefusal",
    "DisabledBootstrapSourceResultError",
    "SyntheticEnrollmentExpectation",
    "DisabledBootstrapInspectionResult",
    "_CapturedInputs",
    "_Signature",
    "_path_text",
    "_leaf_text",
    "_signature",
    "_lstat",
    "_require_private",
    "_capture_inputs",
    "_overlaps",
    "_linux_supported",
    "_refuse",
    "Path",
    "_effective_uid",
    "read_private_sensitive_bytes",
    "_require_bytes",
    "_recheck",
    "inspect_synthetic_disabled_bootstrap",
    "_copy_handoff",
}


def _syntax(value: str) -> str:
    return ast.dump(ast.parse(value), include_attributes=False)


def _expression(value: str) -> str:
    return ast.dump(ast.parse(value, mode="eval").body, include_attributes=False)


def _check_loader_bindings_and_headers(tree: ast.Module) -> set[int]:
    """Close this source's declaration and binding forms, including implicit calls."""
    functions = {node.name: node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    parameters = {
        "__post_init__": (("self",), ()),
        "__init__": (("self",), ()),
        "reuse_authorized": (("self",), ()),
        "_refuse": (("stage", "reason"), ()),
        "_path_text": (("value",), ()),
        "_leaf_text": (("value",), ()),
        "_capture_inputs": (
            (
                "source_root",
                "policy_leaf",
                "expected_descriptor_leaf",
                "expectation",
                "expected_control_root",
            ),
            (),
        ),
        "_overlaps": (("left", "right"), ()),
        "_linux_supported": ((), ()),
        "_effective_uid": ((), ()),
        "_lstat": (("path",), ()),
        "_signature": (("value",), ()),
        "_require_private": (("value", "uid"), ("root",)),
        "_require_bytes": (("value",), ()),
        "_recheck": (("path", "previous", "uid"), ("root", "payload")),
        "_copy_handoff": (("value",), ()),
        "load_synthetic_disabled_bootstrap": (
            ("source_root", "policy_leaf", "expected_descriptor_leaf", "expectation"),
            ("expected_control_root",),
        ),
    }
    assert set(functions) == set(parameters)
    for name, node in functions.items():
        assert not node.type_params
        assert not node.args.posonlyargs and node.args.vararg is None and node.args.kwarg is None
        assert not node.args.defaults
        assert (
            tuple(item.arg for item in node.args.args),
            tuple(item.arg for item in node.args.kwonlyargs),
        ) == parameters[name]
        assert all(value is None for value in node.args.kw_defaults) or (
            name == "_recheck"
            and len(node.args.kw_defaults) == 2
            and node.args.kw_defaults[0] is None
            and isinstance(node.args.kw_defaults[1], ast.Constant)
            and node.args.kw_defaults[1].value is None
        )
        assert [ast.dump(value, include_attributes=False) for value in node.decorator_list] == (
            [_expression("property")] if name == "reuse_authorized" else []
        )

    class_specs = {
        "DisabledBootstrapSourceStage": (
            "StrEnum",
            (),
            (
                'CAPTURE = "CAPTURE"',
                'PLATFORM = "PLATFORM"',
                'PRECHECK = "PRECHECK"',
                'POLICY_READ = "POLICY_READ"',
                'COMPANION_READ = "COMPANION_READ"',
                'RECHECK = "RECHECK"',
                'HANDOFF = "HANDOFF"',
            ),
        ),
        "DisabledBootstrapSourceReason": (
            "StrEnum",
            (),
            (
                'INPUT_UNVERIFIABLE = "INPUT_UNVERIFIABLE"',
                'UNSUPPORTED_PLATFORM = "UNSUPPORTED_PLATFORM"',
                'SOURCE_OVERLAP = "SOURCE_OVERLAP"',
                'SOURCE_UNVERIFIABLE = "SOURCE_UNVERIFIABLE"',
                'SOURCE_CHANGED = "SOURCE_CHANGED"',
                'HANDOFF_FAILED = "HANDOFF_FAILED"',
                'HANDOFF_RESULT_UNVERIFIABLE = "HANDOFF_RESULT_UNVERIFIABLE"',
            ),
        ),
        "DisabledBootstrapSourceRefusal": (
            None,
            ("__post_init__",),
            (
                "stage: DisabledBootstrapSourceStage",
                "reason: DisabledBootstrapSourceReason",
                "reuse_authorized: Literal[False] = field(default=False, init=False)",
            ),
        ),
        "DisabledBootstrapSourceResultError": (
            "RuntimeError",
            ("__init__", "reuse_authorized"),
            ("__slots__ = ()",),
        ),
        "_CapturedInputs": (
            None,
            (),
            (
                "source_root: str = field(repr=False)",
                "policy_leaf: str = field(repr=False)",
                "expected_descriptor_leaf: str = field(repr=False)",
                "expectation: SyntheticEnrollmentExpectation = field(repr=False)",
                "expected_control_root: str = field(repr=False)",
            ),
        ),
        "_Signature": (
            None,
            (),
            tuple(
                name + ": int = field(repr=False)"
                for name in (
                    "dev",
                    "ino",
                    "mode",
                    "uid",
                    "gid",
                    "nlink",
                    "size",
                    "mtime_ns",
                    "ctime_ns",
                )
            ),
        ),
    }
    class_nodes = [node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)]
    classes = {node.name: node for node in class_nodes}
    assert len(classes) == len(class_nodes)
    assert set(classes) == set(class_specs)
    stores: set[int] = set()

    def record(node: ast.AST) -> None:
        stores.update(
            id(child)
            for child in ast.walk(node)
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Store)
        )

    for name, node in classes.items():
        assert node in tree.body and not node.type_params and not node.keywords
        base, methods, declarations = class_specs[name]
        assert [ast.dump(value, include_attributes=False) for value in node.bases] == (
            [] if base is None else [_expression(base)]
        )
        assert [ast.dump(value, include_attributes=False) for value in node.decorator_list] == (
            [_expression("dataclass(frozen=True, slots=True)")] if base is None else []
        )
        actual = []
        found_methods = []
        for child in node.body:
            if isinstance(child, ast.FunctionDef):
                found_methods.append(child.name)
            elif isinstance(child, (ast.Assign, ast.AnnAssign)):
                actual.append(_syntax(ast.unparse(child)))
                record(child)
            else:
                assert isinstance(child, ast.Expr) and isinstance(child.value, ast.Constant)
                assert type(child.value.value) is str
        assert tuple(found_methods) == methods
        assert actual == [_syntax(value) for value in declarations]

    allowed_reasons = (
        "{"
        + ",".join(
            "DisabledBootstrapSourceStage."
            + stage.name
            + ":("
            + ",".join(
                "DisabledBootstrapSourceReason." + reason.name
                for candidate, reason in VALID_PAIRS
                if candidate is stage
            )
            + ",)"
            for stage in S
        )
        + "}"
    )
    constants = {
        "_EXPECTATION_FIELDS": _expression(repr(EXPECTATION_FIELDS)),
        "_ALLOWED_REASONS": _expression(allowed_reasons),
    }
    found_constants: set[str] = set()
    module_functions = set(functions) - {"__post_init__", "__init__", "reuse_authorized"}
    for node in tree.body:
        if isinstance(node, ast.Assign):
            assert len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
            name = node.targets[0].id
            assert name in constants and name not in found_constants
            assert ast.dump(node.value, include_attributes=False) == constants[name]
            found_constants.add(name)
            record(node)
        elif isinstance(node, ast.FunctionDef):
            assert node.name in module_functions
            module_functions.remove(node.name)
        elif isinstance(node, (ast.ClassDef, ast.Import, ast.ImportFrom)):
            pass
        else:
            assert node is tree.body[0] and isinstance(node, ast.Expr)
            assert isinstance(node.value, ast.Constant) and type(node.value.value) is str
    assert found_constants == set(constants) and not module_functions

    bindings = {
        "_refuse": (
            "failure = DisabledBootstrapSourceResultError()",
            "failure.__cause__ = None",
            "failure.__context__ = None",
        ),
        "_capture_inputs": (
            "root = _path_text(source_root)",
            "policy = _leaf_text(policy_leaf)",
            "companion = _leaf_text(expected_descriptor_leaf)",
            "control = _path_text(expected_control_root)",
            "values: dict[str, object] = {name: getattr(expectation, name) "
            "for name in _EXPECTATION_FIELDS}",
            "retained = SyntheticEnrollmentExpectation("
            "**{name: cast(str, value) for name, value in values.items()})",
        ),
        "_signature": (
            "values = (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid, "
            "value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)",
        ),
        "_require_private": (
            "valid = stat.S_ISDIR(value.mode) and stat.S_IMODE(value.mode) == 0o700",
            "valid = (stat.S_ISREG(value.mode) and value.nlink == 1 "
            "and not stat.S_IMODE(value.mode) & 0o077 and 1 <= value.size <= 8192)",
        ),
        "_recheck": ("current = _signature(_lstat(path))",),
        "_copy_handoff": (
            "state, inputs, observation, authorized = (value.state, value.input_result, "
            "value.inspection_result, value.reuse_authorized)",
        ),
    }
    comprehensions = {
        "__post_init__": (
            "(self.stage is member for member in DisabledBootstrapSourceStage)",
            "(self.reason is member for member in DisabledBootstrapSourceReason)",
        ),
        "_path_text": (
            '(char in value for char in "\\\\:")',
            '(unicodedata.category(char) in {"Cc", "Cs"} for char in value)',
            '(part in {".", "..", ".git"} or part.endswith((" ", ".")) '
            'for part in value.split("/")[1:])',
        ),
        "_leaf_text": ('(not (char.isalnum() or char in "._-") for char in value)',),
        "_capture_inputs": (
            "{name: getattr(expectation, name) for name in _EXPECTATION_FIELDS}",
            "(type(value) is not str for value in values.values())",
            "{name: cast(str, value) for name, value in values.items()}",
        ),
        "_signature": (
            "(type(item) is not int for item in values)",
            "(item < 0 for item in values[:7])",
        ),
    }
    for name, node in functions.items():
        declarations = [
            child for child in ast.walk(node) if isinstance(child, (ast.Assign, ast.AnnAssign))
        ]
        if name == "load_synthetic_disabled_bootstrap":
            # Exact entry Assign shapes are checked separately below; no other form is allowed.
            assert all(isinstance(child, ast.Assign) for child in declarations)
        else:
            assert sorted(_syntax(ast.unparse(child)) for child in declarations) == sorted(
                _syntax(value) for value in bindings.get(name, ())
            )
        for child in declarations:
            record(child)
        expressions = [
            child
            for child in ast.walk(node)
            if isinstance(child, (ast.GeneratorExp, ast.DictComp, ast.ListComp, ast.SetComp))
        ]
        assert sorted(ast.dump(child, include_attributes=False) for child in expressions) == sorted(
            _expression(value) for value in comprehensions.get(name, ())
        )
        for child in expressions:
            record(child)
    return stores


def _check_closed_loader(source: str) -> set[str]:
    """Closed checks for this loader's finite effects, not a general Python analyzer."""
    tree = ast.parse(source)
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    getters = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
    ]
    assert len(getters) == 1
    functions = [node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)]
    scopes = {id(child): node.name for node in functions for child in ast.walk(node)}
    assert len({node.name for node in functions}) == len(functions)
    permitted_stores = _check_loader_bindings_and_headers(tree)
    top_level = {id(node) for node in tree.body}
    found_imports: dict[str, set[str]] = {}
    bare_imports: set[str] = set()
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            assert id(node) in top_level
            assert node.level == 0 and node.module is not None
            assert node.module not in found_imports
            assert all(item.asname is None and item.name != "*" for item in node.names)
            assert len({item.name for item in node.names}) == len(node.names)
            assert not imported.intersection(item.name for item in node.names)
            found_imports[node.module] = {item.name for item in node.names}
            imported.update(item.name for item in node.names)
        elif isinstance(node, ast.Import):
            assert id(node) in top_level
            assert all(item.asname is None for item in node.names)
            assert len({item.name for item in node.names}) == len(node.names)
            assert not imported.intersection(item.name for item in node.names)
            bare_imports.update(item.name for item in node.names)
            imported.update(item.name for item in node.names)
    assert found_imports == _APPLICATION_IMPORTS | _STANDARD_IMPORTS
    assert bare_imports == {"os", "stat", "sys", "unicodedata"}
    protected = (
        imported
        | _NAME_CALLS
        | {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
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
    )
    attribute_calls = {
        "__init__": {"super().__init__"},
        "_path_text": {
            "value.startswith",
            "value.endswith",
            "value.encode",
            "value.split",
            "part.endswith",
            "unicodedata.category",
        },
        "_leaf_text": {
            "value.isascii",
            "value[0].isalnum",
            "char.isalnum",
            "value.endswith",
            "value.split",
            "value.split('.', 1)[0].upper",
        },
        "_capture_inputs": {"values.values", "values.items"},
        "_overlaps": {"left.startswith", "right.startswith"},
        "_effective_uid": {"os.geteuid"},
        "_lstat": {"path.lstat"},
        "_require_private": {"stat.S_ISDIR", "stat.S_ISREG", "stat.S_IMODE"},
    }
    attribute_shapes = {
        scope: {_expression(value) for value in values} for scope, values in attribute_calls.items()
    }
    calls: set[str] = set()
    for node in ast.walk(tree):
        scope = scopes.get(id(node), "")
        assert not isinstance(node, blocked)
        if isinstance(node, ast.comprehension):
            assert node.is_async == 0
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            assert node.id not in protected
            assert id(node) in permitted_stores
        if isinstance(node, ast.arg):
            assert node.arg not in protected
        if isinstance(node, ast.ExceptHandler):
            assert isinstance(node.type, ast.Name)
            assert node.type.id in {
                "Exception",
                "DisabledBootstrapSourceResultError",
                "DisabledBootstrapInspectionResultError",
            }
            if node.name is not None:
                assert scope == "load_synthetic_disabled_bootstrap"
                assert (
                    node.name == "error"
                    and node.type.id == "DisabledBootstrapInspectionResultError"
                )
        if isinstance(node, ast.Subscript):
            assert isinstance(node.ctx, ast.Load)
        if isinstance(node, ast.Attribute):
            if isinstance(node.ctx, ast.Store):
                assert scope == "_refuse"
                assert isinstance(node.value, ast.Name) and node.value.id == "failure"
                assert node.attr in {"__cause__", "__context__"}
            else:
                assert isinstance(node.ctx, ast.Load)
                assert not node.attr.startswith("__") or (
                    scope == "__init__"
                    and ast.dump(node, include_attributes=False) == _expression("super().__init__")
                )
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                assert node.func.id in _NAME_CALLS
                calls.add(node.func.id)
                if node.func.id == "getattr":
                    assert scope == "_capture_inputs"
                    assert _expression(ast.unparse(node)) == _expression(
                        "getattr(expectation, name)"
                    )
                    comprehension = parents[node]
                    assert isinstance(comprehension, ast.DictComp)
                    assert comprehension.value is node
                    assert _expression(ast.unparse(comprehension)) == _expression(
                        "{name: getattr(expectation, name) for name in _EXPECTATION_FIELDS}"
                    )
                    binding = parents[comprehension]
                    assert isinstance(binding, ast.AnnAssign)
                    assert isinstance(binding.target, ast.Name) and binding.target.id == "values"
                    assert binding.value is comprehension
            else:
                assert isinstance(node.func, ast.Attribute)
                assert ast.dump(node.func, include_attributes=False) in attribute_shapes.get(
                    scope, set()
                )
    assert calls == _NAME_CALLS
    entry = next(node for node in functions if node.name == "load_synthetic_disabled_bootstrap")
    expected_bindings = (
        "inputs = _capture_inputs(source_root, policy_leaf, expected_descriptor_leaf, "
        "expectation, expected_control_root)",
        "root_path = Path(inputs.source_root)",
        "policy_path = root_path / inputs.policy_leaf",
        "companion_path = root_path / inputs.expected_descriptor_leaf",
        "uid = _effective_uid()",
        "before_root = _signature(_lstat(root_path))",
        "before_policy = _signature(_lstat(policy_path))",
        "before_companion = _signature(_lstat(companion_path))",
        "policy_raw = _require_bytes(read_private_sensitive_bytes(policy_path, max_size=8192))",
        "expected_raw = _require_bytes("
        "read_private_sensitive_bytes(companion_path, max_size=8192))",
        "reason = _recheck(root_path, before_root, uid, root=True)",
        "reason = _recheck(policy_path, before_policy, uid, root=False, payload=policy_raw)",
        "reason = _recheck(companion_path, before_companion, uid, "
        "root=False, payload=expected_raw)",
        "result = inspect_synthetic_disabled_bootstrap(policy_raw, expected_raw, "
        "inputs.expectation, expected_control_root=inputs.expected_control_root)",
    )
    expected = [_syntax(value) for value in expected_bindings]
    actual = [
        _syntax(ast.unparse(node)) for node in ast.walk(entry) if isinstance(node, ast.Assign)
    ]
    # ast.walk groups by nesting depth; exact multiset closes extra/alternate bindings.
    assert sorted(actual) == sorted(expected)
    effects = {
        "Path",
        "_lstat",
        "read_private_sensitive_bytes",
        "_recheck",
        "inspect_synthetic_disabled_bootstrap",
    }
    observed = [
        (scopes[id(node)], _expression(ast.unparse(node)))
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in effects
    ]
    permitted = [
        ("_recheck", "_lstat(path)"),
        ("load_synthetic_disabled_bootstrap", "Path(inputs.source_root)"),
        ("load_synthetic_disabled_bootstrap", "_lstat(root_path)"),
        ("load_synthetic_disabled_bootstrap", "_lstat(policy_path)"),
        ("load_synthetic_disabled_bootstrap", "_lstat(companion_path)"),
        (
            "load_synthetic_disabled_bootstrap",
            "read_private_sensitive_bytes(policy_path, max_size=8192)",
        ),
        (
            "load_synthetic_disabled_bootstrap",
            "read_private_sensitive_bytes(companion_path, max_size=8192)",
        ),
        ("load_synthetic_disabled_bootstrap", "_recheck(root_path, before_root, uid, root=True)"),
        (
            "load_synthetic_disabled_bootstrap",
            "_recheck(policy_path, before_policy, uid, root=False, payload=policy_raw)",
        ),
        (
            "load_synthetic_disabled_bootstrap",
            "_recheck(companion_path, before_companion, uid, root=False, payload=expected_raw)",
        ),
        (
            "load_synthetic_disabled_bootstrap",
            "inspect_synthetic_disabled_bootstrap(policy_raw, expected_raw, "
            "inputs.expectation, expected_control_root=inputs.expected_control_root)",
        ),
    ]
    assert sorted(observed) == sorted((scope, _expression(value)) for scope, value in permitted)
    recheck = next(node for node in functions if node.name == "_recheck")
    lstat = next(node for node in functions if node.name == "_lstat")
    assert [
        _expression(ast.unparse(node)) for node in ast.walk(lstat) if isinstance(node, ast.Call)
    ] == [_expression("path.lstat()")]
    assert any(
        isinstance(node, ast.Compare)
        and _expression(ast.unparse(node)) == _expression("current != previous")
        for node in ast.walk(recheck)
    )
    refuse = next(node for node in functions if node.name == "_refuse")
    assignments = [node for node in ast.walk(refuse) if isinstance(node, ast.Assign)]
    assert sorted(_syntax(ast.unparse(node)) for node in assignments) == sorted(
        _syntax(value)
        for value in (
            "failure = DisabledBootstrapSourceResultError()",
            "failure.__cause__ = None",
            "failure.__context__ = None",
        )
    )
    return calls


def test_closed_loader_dependencies_effect_arguments_receivers_and_external_consumers() -> None:
    source = Path(loader.__file__).read_text(encoding="utf-8")
    assert _check_closed_loader(source) == _NAME_CALLS
    package = Path(loader.__file__).parent
    consumers = {
        path.name
        for path in package.rglob("*.py")
        if path.name != Path(loader.__file__).name
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, (ast.Import, ast.ImportFrom))
        and (
            (
                isinstance(node, ast.ImportFrom)
                and "production_write_token_disabled_bootstrap_source_loading"
                in (node.module or "")
            )
            or any(
                "production_write_token_disabled_bootstrap_source_loading" in item.name
                for item in node.names
            )
        )
    }
    assert consumers == {"production_write_token_disabled_bootstrap_entry.py"}


def _source_with_statement(statement: str) -> str:
    tree = ast.parse(Path(loader.__file__).read_text(encoding="utf-8"))
    entry = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "load_synthetic_disabled_bootstrap"
    )
    entry.body[1:1] = ast.parse(statement).body
    return ast.unparse(tree)


@pytest.mark.parametrize(
    "statement",
    (
        'os.unlink("synthetic")',
        "read_private_sensitive_bytes = Path.unlink",
        "alias = read_private_sensitive_bytes.__globals__",
        'read_private_sensitive_bytes.__globals__["Path"] = Path',
        'items = {}\nitems["synthetic"] = None',
        'items = {}\ndel items["synthetic"]',
        "alias = _lstat\nalias(expected_control_root)",
        "_lstat(expected_control_root)",
        "Path(expected_control_root)",
        'inputs.expected_control_root = "/synthetic-other"',
        "read_private_sensitive_bytes(policy_leaf, max_size=8192)",
        "failure.__context__ = None",
    ),
    ids=(
        "writer",
        "protected-name",
        "namespace",
        "dependency-item",
        "item-store",
        "item-delete",
        "alias-call",
        "target-metadata",
        "target-path",
        "captured-write",
        "unbound-read",
        "wrong-scope-clear",
    ),
)
def test_closed_checker_rejects_dangerous_synthetic_ast_without_executing_it(
    statement: str,
) -> None:
    with pytest.raises(AssertionError):
        _check_closed_loader(_source_with_statement(statement))


@pytest.mark.parametrize("replacement", ("8193", "True"))
def test_closed_checker_rejects_changed_reader_bound(replacement: str) -> None:
    source = Path(loader.__file__).read_text(encoding="utf-8")
    changed = source.replace("max_size=8192", "max_size=" + replacement, 1)
    assert changed != source
    with pytest.raises(AssertionError):
        _check_closed_loader(changed)


def _binding_mutant(case: str) -> str:
    """Alter syntax as data; these copies are never compiled, imported, or executed."""
    tree = ast.parse(Path(loader.__file__).read_text(encoding="utf-8"))
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}
    entry = functions["load_synthetic_disabled_bootstrap"]
    if case == "annotated-path":
        precheck = next(
            node
            for node in entry.body
            if isinstance(node, ast.Try)
            and any(
                isinstance(statement, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "policy_path"
                    for target in statement.targets
                )
                for statement in node.body
            )
        )
        index = next(
            position
            for position, node in enumerate(precheck.body)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "policy_path"
                for target in node.targets
            )
        )
        precheck.body[index + 1 : index + 1] = ast.parse(
            "policy_path: object = inputs.expected_control_root"
        ).body
    elif case == "annotated-failure":
        refuse = functions["_refuse"]
        index = next(
            position for position, node in enumerate(refuse.body) if isinstance(node, ast.Assign)
        )
        refuse.body[index + 1 : index + 1] = ast.parse(
            "failure: object = DisabledBootstrapSourceResultError()"
        ).body
    elif case == "duplicate-from":
        index = next(
            position
            for position, node in enumerate(tree.body)
            if isinstance(node, ast.ImportFrom)
            and node.module == "tridentine_calendar_google_sync.sensitive_paths"
        )
        tree.body[index:index] = ast.parse(
            "from tridentine_calendar_google_sync.sensitive_paths import read_sensitive_bytes"
        ).body
    elif case == "nested-from":
        entry.body[1:1] = ast.parse(
            "from tridentine_calendar_google_sync.sensitive_paths "
            "import read_private_sensitive_bytes"
        ).body
    elif case == "duplicate-import":
        tree.body[2:2] = ast.parse("import os").body
    elif case == "exception-binding":
        handler = next(
            node
            for node in ast.walk(entry)
            if isinstance(node, ast.ExceptHandler) and node.name is None
        )
        handler.name = "read_private_sensitive_bytes"
    elif case == "match-binding":
        precheck = next(
            node
            for node in entry.body
            if isinstance(node, ast.Try)
            and any(
                isinstance(statement, ast.Assign)
                and any(
                    isinstance(target, ast.Name) and target.id == "policy_path"
                    for target in statement.targets
                )
                for statement in node.body
            )
        )
        precheck.body.extend(
            ast.parse(
                "match inputs.expected_control_root:\n    case policy_path:\n        pass"
            ).body
        )
    elif case == "capture-receiver":
        capture = functions["_capture_inputs"]
        index = next(
            position
            for position, node in enumerate(capture.body)
            if isinstance(node, ast.AnnAssign)
        )
        capture.body[index:index] = ast.parse("expectation = read_private_sensitive_bytes").body
    elif case == "capture-field-list":
        assignment = next(
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "_EXPECTATION_FIELDS"
                for target in node.targets
            )
        )
        assignment.value = ast.parse("('__globals__',)", mode="eval").body
    elif case == "duplicate-capture-getattr":
        functions["_capture_inputs"].body[-1:-1] = ast.parse(
            "[getattr(expectation, name) for name in _EXPECTATION_FIELDS]"
        ).body
    elif case == "namespace-getattr":
        functions["_capture_inputs"].body[1:1] = ast.parse(
            "getattr(read_private_sensitive_bytes, '__globals__')"
        ).body
    elif case == "decorator-call":
        entry.decorator_list.append(ast.Name(id="print", ctx=ast.Load()))
    else:
        raise AssertionError("unknown synthetic binding mutation")
    return ast.unparse(tree)


@pytest.mark.parametrize(
    "case",
    (
        "annotated-path",
        "annotated-failure",
        "duplicate-from",
        "nested-from",
        "duplicate-import",
        "exception-binding",
        "match-binding",
        "capture-receiver",
        "capture-field-list",
        "duplicate-capture-getattr",
        "namespace-getattr",
        "decorator-call",
    ),
)
def test_closed_checker_rejects_binding_import_and_capture_escapes(case: str) -> None:
    with pytest.raises(AssertionError):
        _check_closed_loader(_binding_mutant(case))


def test_closed_checker_rejects_shadowing_duplicate_class() -> None:
    """A prior same-name declaration must not hide an implicit decorator call."""
    tree = ast.parse(Path(loader.__file__).read_text(encoding="utf-8"))
    index = next(
        position
        for position, node in enumerate(tree.body)
        if isinstance(node, ast.ClassDef) and node.name == "_Signature"
    )
    tree.body[index:index] = ast.parse("@print\nclass _Signature:\n    pass\n").body
    with pytest.raises(AssertionError):
        _check_closed_loader(ast.unparse(tree))


def _private_file(path: Path, content: bytes, mode: int = 0o600) -> None:
    path.write_bytes(content)
    path.chmod(mode)


def _native_fixture(
    tmp_path: Path, case: str = "both"
) -> tuple[Path, Path, Path, descriptor.SyntheticEnrollmentExpectation]:
    source, control, pair = (
        tmp_path / name for name in ("loader-source", "loader-control", "loader-pair")
    )
    for root in (source, control, pair):
        root.mkdir(mode=0o700)
        root.chmod(0o700)
    policy, raw, expected = _materials(str(control), str(pair))
    _private_file(source / POLICY, policy)
    _private_file(source / COMPANION, raw)
    if case in {"pending", "both", "conflict"}:
        _private_file(
            control / PENDING,
            _pending(raw, "different-revision" if case == "conflict" else "revision-one"),
        )
    if case in {"descriptor", "both", "conflict"}:
        _private_file(control / DESCRIPTOR, raw)
    return source, control, pair, expected


def _fingerprint(root: Path) -> dict[str, tuple[object, ...]]:
    """Read only this test's own synthetic regular fixtures; exclude OS-managed atime."""
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


def _native_call(
    source: Path, control: Path, expected: descriptor.SyntheticEnrollmentExpectation
) -> Any:
    return loader.load_synthetic_disabled_bootstrap(
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
@pytest.mark.parametrize("mode", (0o400, 0o600))
def test_linux_real_private_reads_and_handoff_preserve_source_target_and_negative_evidence(
    case: str, state: IS, mode: int, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, control, pair, expected = _native_fixture(tmp_path, case)
    (source / POLICY).chmod(mode)
    (source / COMPANION).chmod(mode)
    before = tuple(_fingerprint(root) for root in (source, control, pair))
    effects = _forbid_effects(monkeypatch)
    calls: list[str] = []
    real_lstat, real_read, real_handoff = (
        loader._lstat,
        loader.read_private_sensitive_bytes,
        loader.inspect_synthetic_disabled_bootstrap,
    )

    def lstat(path: Path) -> os.stat_result:
        assert path in {source, source / POLICY, source / COMPANION}
        calls.append("source-lstat")
        return real_lstat(path)

    def read(path: Path, *, max_size: int) -> bytes:
        calls.append("source-read")
        assert max_size == 8192
        return real_read(path, max_size=max_size)

    def invoke(*args: Any, **kwargs: Any) -> Any:
        calls.append("handoff")
        assert calls.count("source-read") == 2
        return real_handoff(*args, **kwargs)

    monkeypatch.setattr(loader, "_lstat", lstat)
    monkeypatch.setattr(loader, "read_private_sensitive_bytes", read)
    monkeypatch.setattr(loader, "inspect_synthetic_disabled_bootstrap", invoke)
    result = _native_call(source, control, expected)
    assert result.state is H.INSPECTION_OBSERVED and result.reuse_authorized is False
    assert result.inspection_result.state is state
    assert result.inspection_result.verification_complete
    assert calls == ["source-lstat"] * 3 + ["source-read"] * 2 + ["source-lstat"] * 3 + ["handoff"]
    assert effects == [] and tuple(_fingerprint(root) for root in (source, control, pair)) == before
    # No source lock/fd is intentionally retained. This does not certify suppressed close errors.
    with prep.private_lock.acquire_posix_private_directory_lock(source):
        pass
    with prep.private_lock.acquire_posix_private_directory_lock(control):
        pass


@LINUX_ONLY
@pytest.mark.parametrize(
    "kind",
    (
        "missing",
        "directory",
        "symlink",
        "hardlink",
        "unsafe-mode",
        "oversize",
        "git-marker",
        "ancestor-symlink",
    ),
)
def test_linux_unsafe_source_never_reaches_observation(
    kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, control, pair, expected = _native_fixture(tmp_path)
    path = source / POLICY
    if kind in {"missing", "directory", "symlink", "hardlink"}:
        path.unlink()
        if kind == "directory":
            path.mkdir(mode=0o700)
        elif kind == "symlink":
            path.symlink_to(source / COMPANION)
        elif kind == "hardlink":
            os.link(source / COMPANION, path)
    elif kind == "unsafe-mode":
        path.chmod(0o644)
    elif kind == "oversize":
        _private_file(path, b"x" * 8193)
    elif kind == "git-marker":
        (source / ".git").mkdir(mode=0o700)
    else:
        alias = tmp_path / "loader-alias"
        alias.symlink_to(tmp_path, target_is_directory=True)
        source = alias / source.name
    before = tuple(_fingerprint(root) for root in (source, control, pair))
    effects = _forbid_effects(monkeypatch)
    monkeypatch.setattr(loader, "inspect_synthetic_disabled_bootstrap", _deny)
    monkeypatch.setattr(prep, "_inspection_lstat", _deny)
    monkeypatch.setattr(prep.private_lock, "acquire_posix_private_directory_lock", _deny)
    result = _native_call(source, control, expected)
    expected_stage = S.POLICY_READ if kind in {"git-marker", "ancestor-symlink"} else S.PRECHECK
    _refused(result, expected_stage, R.SOURCE_UNVERIFIABLE)
    assert effects == [] and tuple(_fingerprint(root) for root in (source, control, pair)) == before


@LINUX_ONLY
@pytest.mark.parametrize(
    "when", ("between-reads", "before-policy-recheck", "missing-before-recheck")
)
def test_linux_detected_fixture_changes_stop_handoff_without_retry(
    when: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, control, pair, expected = _native_fixture(tmp_path)
    target_before = (_fingerprint(control), _fingerprint(pair))
    real_read, real_lstat = loader.read_private_sensitive_bytes, loader._lstat
    calls = {"read": 0, "metadata": 0}
    injected: list[dict[str, tuple[object, ...]]] = []

    def change() -> None:
        # This mutation belongs exclusively to fault-injection fixture setup.
        if when == "missing-before-recheck":
            (source / POLICY).unlink()
        else:
            original = (source / POLICY).read_bytes()
            _private_file(source / POLICY, original + b" ")
        injected.append(_fingerprint(source))

    def read(path: Path, *, max_size: int) -> bytes:
        calls["read"] += 1
        result = real_read(path, max_size=max_size)
        if calls["read"] == 1 and when == "between-reads":
            change()
        return result

    def lstat(path: Path) -> os.stat_result:
        calls["metadata"] += 1
        if calls["metadata"] == 5 and when != "between-reads":
            change()
        return real_lstat(path)

    monkeypatch.setattr(loader, "read_private_sensitive_bytes", read)
    monkeypatch.setattr(loader, "_lstat", lstat)
    monkeypatch.setattr(loader, "inspect_synthetic_disabled_bootstrap", _deny)
    effects = _forbid_effects(monkeypatch)
    result = _native_call(source, control, expected)
    reason = R.SOURCE_UNVERIFIABLE if when == "missing-before-recheck" else R.SOURCE_CHANGED
    _refused(result, S.RECHECK, reason)
    assert calls == {"read": 2, "metadata": 5}
    assert len(injected) == 1 and _fingerprint(source) == injected[0]
    assert (_fingerprint(control), _fingerprint(pair)) == target_before and effects == []


@LINUX_ONLY
def test_linux_real_handoff_keeps_partial_negative_observation_on_internal_reader_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, control, pair, expected = _native_fixture(tmp_path)
    before = tuple(_fingerprint(root) for root in (source, control, pair))
    real_read = prep.read_private_sensitive_bytes

    def read(path: Path, **kwargs: Any) -> bytes:
        if path.name == DESCRIPTOR:
            raise OSError("SYNTHETIC_TARGET_READ_FAILURE")
        return real_read(path, **kwargs)

    monkeypatch.setattr(prep, "read_private_sensitive_bytes", read)
    effects = _forbid_effects(monkeypatch)
    result = _native_call(source, control, expected)
    observed = result.inspection_result
    assert result.state is H.INSPECTION_OBSERVED and result.reuse_authorized is False
    assert observed.state is IS.PREPARATION_UNVERIFIABLE
    assert observed.pending == prep.LeafObservation(P.PRESENT, C.SCHEMA_VALID, T.MATCH)
    assert observed.first_failure is F.DESCRIPTOR_READ and not observed.verification_complete
    assert effects == [] and tuple(_fingerprint(root) for root in (source, control, pair)) == before


@LINUX_ONLY
@pytest.mark.parametrize("case", ("pending", "both"))
def test_linux_fresh_process_acquires_once_from_independent_fixture_plan(
    case: str, tmp_path: Path
) -> None:
    source, control, pair, _ = _native_fixture(tmp_path, case)
    before = tuple(_fingerprint(root) for root in (source, control, pair))
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(Path(loader.__file__).resolve().parents[1])
    child = subprocess.run(
        [sys.executable, "-B", __file__, "--source-loading-observe", str(tmp_path)],
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
    """One ordinary process observation; expected material is not learned from files."""
    try:
        if (
            len(sys.argv) != 3
            or sys.argv[1] != "--source-loading-observe"
            or sys.platform != "linux"
        ):
            return 2
        parent = Path(sys.argv[2])
        source, control, pair = (
            parent / name for name in ("loader-source", "loader-control", "loader-pair")
        )
        expected = _materials(str(control), str(pair))[2]
        with pytest.MonkeyPatch.context() as scoped:
            effects = _forbid_effects(scoped)
            result = _native_call(source, control, expected)
            if (
                type(result) is not handoff.DisabledBootstrapInspectionResult
                or result.reuse_authorized is not False
            ):
                return 2
            observed = result.inspection_result
            if effects or observed is None or not observed.verification_complete:
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
