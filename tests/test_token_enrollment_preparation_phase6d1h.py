"""Synthetic preparation only; retained records never grant enrollment or reuse."""

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
    production_write_token_enrollment_descriptor as validator,
)
from tridentine_calendar_google_sync import production_write_token_enrollment_preparation as prep

S = prep.PreparationState
LINUX_ONLY = pytest.mark.skipif(
    sys.platform != "linux", reason="native Linux synthetic preparation"
)
ROOT = "/synthetic-control"
PENDING = "pending.json"
DESCRIPTOR = "descriptor.json"
RAW = (
    b'{"active_intent_slot":"intent.json","administrative_state":"PREPARING",'
    b'"artifact_directory":"/synthetic-pair","enrollment_revision":"revision-one",'
    b'"format_version":1,"pair_ref":"pair-one","record_kind":"enrollment_descriptor",'
    b'"record_slot":"production-write-operation-start-v1.json","role":"production_write",'
    b'"state_slot":"state.json","storage_ref":"store-one","token_slot":"token.json"}\n'
)


def _wire(data: object) -> bytes:
    return (
        json.dumps(data, sort_keys=True, ensure_ascii=True, separators=(",", ":"), allow_nan=False)
        + "\n"
    ).encode()


def _expect(raw: bytes = RAW) -> validator.SyntheticEnrollmentExpectation:
    data = json.loads(raw)
    return validator.SyntheticEnrollmentExpectation(
        **{
            name: data[name]
            for name in (
                "enrollment_revision",
                "administrative_state",
                "storage_ref",
                "pair_ref",
                "artifact_directory",
                "token_slot",
                "state_slot",
                "active_intent_slot",
            )
        },
        descriptor_pin=hashlib.sha256(raw).hexdigest(),
        descriptor_slot=DESCRIPTOR,
        administrative_pending_slot=PENDING,
    )


def _pending() -> bytes:
    return _wire(
        {
            "format_version": 1,
            "record_kind": "enrollment_preparation",
            "target_revision": "revision-one",
            "target_pin": hashlib.sha256(RAW).hexdigest(),
            "outcome": "pending",
        }
    )


class _UnexpectedEffect(BaseException):
    pass


def _deny(*args: object, **kwargs: object) -> Any:
    raise _UnexpectedEffect("unexpected input hook or effect")


class _Poison:
    __repr__ = __str__ = __bytes__ = __iter__ = __len__ = __eq__ = __fspath__ = _deny
    __getattribute__ = _deny


def _assert_result(
    result: prep.PreparationResult,
    state: S,
    *,
    pending: bool = False,
    pp: bool | None = False,
    descriptor: bool = False,
    dp: bool | None = False,
    exit_failure: bool = False,
) -> None:
    assert type(result) is prep.PreparationResult
    assert result.state is state and result.reuse_authorized is False
    assert result.pending_attempted is pending and result.pending_publication_possible is pp
    assert (
        result.descriptor_attempted is descriptor and result.descriptor_publication_possible is dp
    )
    assert result.exit_failure_observed is exit_failure
    assert not hasattr(result, "__dict__")
    assert {field.name for field in fields(result)} == {
        "state",
        "pending_attempted",
        "pending_publication_possible",
        "descriptor_attempted",
        "descriptor_publication_possible",
        "exit_failure_observed",
        "reuse_authorized",
    }


class _Harness:
    """Only two synthetic leaves exist; every effect must remain under one owner."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.events: list[str] = []
        self.faults: dict[str, BaseException] = {}
        self.outputs: dict[str, bytes] = {}
        self.read_values: dict[str, bytes] = {}
        self.occupied_values: dict[str, bool] = {}
        self.counts: dict[str, int] = {}
        self.owned = False
        self.active = False
        self.invalidated_on_entry = False
        self.close_calls = 0
        self.release_count = 0
        self.mismatch_preflight = False
        monkeypatch.setattr(prep, "_linux_storage_available", lambda: True)
        monkeypatch.setattr(prep.private_lock, "acquire_posix_private_directory_lock", self.acquire)
        monkeypatch.setattr(prep.private_create, "create_posix_private_bytes", self.publish)
        monkeypatch.setattr(prep, "read_private_sensitive_bytes", self.read)
        monkeypatch.setattr(prep, "validate_sensitive_output_path", self.preflight)
        monkeypatch.setattr(prep, "_occupied", self.occupied)

    def hit(self, event: str) -> None:
        self.events.append(event)
        if event in self.faults:
            raise self.faults[event]

    def numbered(self, event: str) -> str:
        self.counts[event] = self.counts.get(event, 0) + 1
        return f"{event}-{self.counts[event]}"

    def leaf(self, path: Path) -> str:
        assert self.active and self.owned
        assert path.parent == Path(ROOT) and path.name in {PENDING, DESCRIPTOR}
        return "pending" if path.name == PENDING else "descriptor"

    def acquire(self, root: Path) -> _Harness:
        assert root == Path(ROOT) and not self.owned
        self.hit("acquire")
        self.owned = True
        return self

    def __enter__(self) -> _Harness:
        assert self.owned
        if self.invalidated_on_entry:
            self.owned = False
            self.release_count += 1
        self.hit("enter")
        self.active = True
        return self

    def __exit__(self, *args: object) -> None:
        assert self.active and self.owned
        self.active = self.owned = False
        self.release_count += 1
        self.hit("exit")

    def close(self) -> None:
        self.close_calls += 1
        if self.owned:
            self.owned = self.active = False
            self.release_count += 1
        self.hit("close")

    def revalidate(self) -> None:
        assert self.active and self.owned
        self.hit(self.numbered("checkpoint"))

    def occupied(self, path: Path) -> bool:
        leaf = self.leaf(path)
        event = self.numbered(f"occupied-{leaf}")
        self.hit(event)
        return self.occupied_values.get(event, path.name in self.outputs)

    def preflight(self, path: Path, *, overwrite: bool = False, **kwargs: object) -> Path:
        leaf = self.leaf(path)
        assert overwrite is False
        self.hit(f"preflight-{leaf}")
        return path.with_name("other.json") if self.mismatch_preflight else path

    def publish(self, path: Path, content: bytes) -> None:
        leaf = self.leaf(path)
        assert path.name not in self.outputs
        self.hit(f"publish-{leaf}")
        assert content is RAW if leaf == "descriptor" else content == _pending()
        self.outputs[path.name] = content

    def read(self, path: Path, *, max_size: int, **kwargs: object) -> bytes:
        leaf = self.leaf(path)
        event = self.numbered(f"read-{leaf}")
        assert max_size == (512 if leaf == "pending" else 8192)
        self.hit(event)
        return self.read_values.get(event, self.outputs[path.name])

    def run(self, expectation: object | None = None) -> prep.PreparationResult:
        return prep.prepare_synthetic_enrollment(
            ROOT, RAW, _expect() if expectation is None else expectation
        )

    def bounded(self) -> None:
        for event in ("acquire", "publish-pending", "publish-descriptor", "enter", "exit"):
            assert self.events.count(event) <= 1
        assert not self.owned and not self.active


def test_platform_refusal_precedes_every_input_hook_and_effect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(prep, "_linux_storage_available", lambda: False)
    for name in ("_valid_root", "_snapshot", "validate_enrollment_descriptor"):
        monkeypatch.setattr(prep, name, _deny)
    monkeypatch.setattr(prep.private_lock, "acquire_posix_private_directory_lock", _deny)
    _assert_result(
        prep.prepare_synthetic_enrollment(_Poison(), _Poison(), _Poison()), S.UNSUPPORTED_PLATFORM
    )


@pytest.mark.parametrize(
    "case",
    (
        "root-object",
        "relative",
        "root-only",
        "slash",
        "dot",
        "parent",
        "git",
        "space",
        "colon",
        "backslash",
        "control",
        "surrogate",
        "oversize",
        "expectation",
        "field",
        "raw",
        "mismatch",
        "pin",
    ),
)
def test_invalid_input_never_reaches_lock_or_io(case: str, monkeypatch: pytest.MonkeyPatch) -> None:
    harness = _Harness(monkeypatch)
    root: object = ROOT
    raw: object = RAW
    expectation: object = _expect()
    roots = {
        "relative": "relative",
        "root-only": "/",
        "slash": "/a//b",
        "dot": "/a/.",
        "parent": "/a/../b",
        "git": "/a/.git/b",
        "space": "/a ",
        "colon": "/a:b",
        "backslash": "/a\\b",
        "control": "/a\x85",
        "surrogate": "/a\ud800",
        "oversize": "/" + "é" * 512,
    }
    if case in roots:
        root = roots[case]
    elif case == "root-object":
        root = _Poison()
    elif case == "expectation":
        expectation = _Poison()
    elif case == "field":
        expectation = replace(_expect(), pair_ref=_Poison())
    elif case == "raw":
        raw = _Poison()
    elif case == "mismatch":
        raw = RAW.replace(b"pair-one", b"pair-two")
    else:
        expectation = replace(_expect(), descriptor_pin="0" * 64)
    _assert_result(prep.prepare_synthetic_enrollment(root, raw, expectation), S.INPUT_UNVERIFIABLE)
    assert harness.events == []


@pytest.mark.parametrize("state", ("ACTIVE", "REVOKED"))
def test_matching_nonpreparing_metadata_remains_refused(
    state: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _Harness(monkeypatch)
    raw = RAW.replace(b"PREPARING", state.encode())
    _assert_result(prep.prepare_synthetic_enrollment(ROOT, raw, _expect(raw)), S.PREPARING_REQUIRED)
    assert harness.events == []


@pytest.mark.parametrize(
    "field", tuple(field.name for field in fields(validator.SyntheticEnrollmentExpectation))
)
def test_every_snapshot_field_is_exact_string_before_storage(
    field: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _Harness(monkeypatch)
    _assert_result(harness.run(replace(_expect(), **{field: _Poison()})), S.INPUT_UNVERIFIABLE)
    assert harness.events == []


@pytest.mark.parametrize(
    "case", ("expectation-subclass", "root-subclass", "raw-subclass", "missing-slot")
)
def test_exact_input_types_and_missing_slots_have_no_coercion(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    class ExpectationSubclass(validator.SyntheticEnrollmentExpectation):
        pass

    class StringSubclass(str):
        pass

    class BytesSubclass(bytes):
        pass

    harness = _Harness(monkeypatch)
    expectation: object = _expect()
    if case == "expectation-subclass":
        expectation = ExpectationSubclass(
            **{field.name: getattr(expectation, field.name) for field in fields(expectation)}
        )
    elif case == "missing-slot":
        expectation = object.__new__(validator.SyntheticEnrollmentExpectation)
    _assert_result(
        prep.prepare_synthetic_enrollment(
            StringSubclass(ROOT) if case == "root-subclass" else ROOT,
            BytesSubclass(RAW) if case == "raw-subclass" else RAW,
            expectation,
        ),
        S.INPUT_UNVERIFIABLE,
    )
    assert harness.events == []


@pytest.mark.parametrize(
    "root,valid",
    (
        ("/" + "a" * 1023, True),
        ("/" + "é" * 511 + "a", True),
        ("/" + "é" * 512, False),
        ("/a/.GIT", True),
        ("/a/e\u0301", True),
        ("/a/é", True),
        ("/a/", False),
        ("/a.", False),
    ),
)
def test_root_lexical_bounds_are_os_independent(root: str, valid: bool) -> None:
    assert prep._valid_root(root) is valid


def test_pending_codec_is_independent_five_field_canonical_data() -> None:
    snapshot = prep._snapshot(ROOT, RAW, _expect())
    expected = _pending()
    assert prep._encode_pending(snapshot.expectation) == expected
    assert snapshot.pending == expected and snapshot.raw is RAW
    assert prep._matches_pending(expected, expected)
    assert len(json.loads(expected)) == 5 and len(expected) <= 512
    assert expected.endswith(b"\n") and not expected.endswith(b"\n\n")
    assert "synthetic" not in repr(snapshot)


@pytest.mark.parametrize(
    "key", ("format_version", "record_kind", "target_revision", "target_pin", "outcome")
)
@pytest.mark.parametrize(
    "case", ("missing", "same-duplicate", "different-duplicate", "bool", "float", "null", "nested")
)
def test_pending_closed_schema_and_duplicate_rejection(key: str, case: str) -> None:
    expected = _pending()
    data = json.loads(expected)
    if case == "missing":
        del data[key]
        raw = _wire(data)
    elif "duplicate" in case:
        extra = _wire({key: data[key] if case == "same-duplicate" else "other"})[1:-2]
        raw = b"{" + extra + b"," + expected[1:]
    else:
        data[key] = {"bool": True, "float": 1.5, "null": None, "nested": {}}[case]
        raw = _wire(data)
    assert not prep._matches_pending(raw, expected)
    assert not prep._matches_pending(raw, raw)


@pytest.mark.parametrize(
    "case",
    (
        "empty",
        "512",
        "513",
        "unknown",
        "extra",
        "revision",
        "pin",
        "escaped-duplicate",
        "nan",
        "infinity",
        "utf8",
        "bom",
        "surrogate",
        "array",
        "whitespace",
        "crlf",
        "no-lf",
        "two-lf",
        "order",
        "escape",
        "poison",
        "bytearray",
    ),
)
def test_pending_strict_encoding_bounds_and_target_equality(case: str) -> None:
    expected = _pending()
    cases: dict[str, object] = {
        "empty": b"",
        "512": b" " * 512,
        "513": b" " * 513,
        "unknown": expected.replace(b'"format_version":1', b'"format_version":2'),
        "extra": b'{"extra":1,' + expected[1:],
        "revision": expected.replace(b"revision-one", b"revision-two"),
        "pin": _wire(json.loads(expected) | {"target_pin": "0" * 64}),
        "escaped-duplicate": b'{"outc\\u006fme":"pending",' + expected[1:],
        "nan": expected.replace(b'"pending"', b"NaN"),
        "infinity": expected.replace(b'"pending"', b"Infinity"),
        "utf8": b"\xff",
        "bom": b"\xef\xbb\xbf" + expected,
        "surrogate": expected.replace(b"revision-one", b"\\ud800"),
        "array": b"[]\n",
        "whitespace": b" " + expected,
        "crlf": expected[:-1] + b"\r\n",
        "no-lf": expected[:-1],
        "two-lf": expected + b"\n",
        "order": (
            json.dumps(dict(reversed(tuple(json.loads(expected).items()))), separators=(",", ":"))
            + "\n"
        ).encode(),
        "escape": expected.replace(b"pending", b"pend\\u0069ng"),
    }
    raw = (
        _Poison()
        if case == "poison"
        else bytearray(expected)
        if case == "bytearray"
        else cases[case]
    )
    assert not prep._matches_pending(raw, expected)
    if case not in {"revision", "pin"}:
        assert not prep._matches_pending(raw, raw)


def test_pending_size_refusal_precedes_json_parse(monkeypatch: pytest.MonkeyPatch) -> None:
    expected = _pending()
    monkeypatch.setattr(prep.json, "loads", _deny)
    assert not prep._matches_pending(b"x" * 513, expected)


def test_pending_encoder_applies_cap_after_encoding(monkeypatch: pytest.MonkeyPatch) -> None:
    expectation = _expect()
    monkeypatch.setattr(prep.json, "dumps", lambda *args, **kwargs: "x" * 512)
    with pytest.raises(ValueError, match=r"^Invalid synthetic preparation input$"):
        prep._encode_pending(expectation)


@pytest.mark.parametrize(
    "field,value",
    (
        ("target_revision", ""),
        ("target_revision", "a" * 97),
        ("target_revision", "_first"),
        ("target_revision", "nonascii-é"),
        ("target_revision", "a/b"),
        ("target_pin", "A" * 64),
        ("target_pin", "a" * 63),
        ("target_pin", "g" * 64),
        ("record_kind", "other"),
        ("outcome", "complete"),
    ),
)
def test_pending_field_constraints_are_not_just_byte_equality(field: str, value: str) -> None:
    raw = _wire(json.loads(_pending()) | {field: value})
    assert not prep._matches_pending(raw, raw)


def test_one_owned_interval_exact_bytes_snapshot_and_postexit_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(monkeypatch)
    expectation = _expect()
    original_validator = prep.validate_enrollment_descriptor
    seen: list[object] = []

    def validate(raw: object, snapshot: object) -> Any:
        assert raw is RAW and snapshot is not expectation
        seen.append(snapshot)
        return original_validator(raw, snapshot)

    original_acquire = harness.acquire

    def acquire(root: Path) -> _Harness:
        object.__setattr__(expectation, "descriptor_slot", "changed.json")
        return original_acquire(root)

    result_type = prep.PreparationResult

    def result(*args: object, **kwargs: object) -> Any:
        assert harness.events[-1] == "exit" and not harness.owned
        return result_type(*args, **kwargs)

    monkeypatch.setattr(prep, "validate_enrollment_descriptor", validate)
    monkeypatch.setattr(prep.private_lock, "acquire_posix_private_directory_lock", acquire)
    monkeypatch.setattr(prep, "PreparationResult", result)
    observed = harness.run(expectation)
    assert observed.state is S.PREPARATION_OBSERVED_UNAPPROVED
    assert observed.pending_publication_possible is observed.descriptor_publication_possible is True
    assert len(seen) == 2 and seen[0] is seen[1]
    assert harness.outputs == {PENDING: _pending(), DESCRIPTOR: RAW}
    important = [
        event for event in harness.events if not event.startswith(("checkpoint", "occupied"))
    ]
    assert important == [
        "acquire",
        "enter",
        "preflight-pending",
        "publish-pending",
        "read-pending-1",
        "read-pending-2",
        "preflight-descriptor",
        "publish-descriptor",
        "read-descriptor-1",
        "exit",
    ]
    assert harness.close_calls == 0 and harness.release_count == 1
    harness.bounded()


@pytest.mark.parametrize(
    "pending,descriptor,state",
    (
        (True, False, S.PENDING_OCCUPIED),
        (False, True, S.DESCRIPTOR_OCCUPIED),
        (True, True, S.BOTH_OCCUPIED),
    ),
)
def test_initial_occupancy_refuses_without_reading(
    pending: bool, descriptor: bool, state: S, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _Harness(monkeypatch)
    harness.occupied_values = {"occupied-pending-1": pending, "occupied-descriptor-1": descriptor}
    _assert_result(harness.run(), state)
    assert not any(event.startswith(("read-", "publish-")) for event in harness.events)
    harness.bounded()


def test_known_occupancy_survives_later_inspection_and_exit_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(monkeypatch)
    harness.occupied_values["occupied-pending-1"] = True
    harness.faults = {
        "occupied-descriptor-1": RuntimeError("synthetic-private"),
        "exit": RuntimeError("synthetic-cleanup"),
    }
    _assert_result(harness.run(), S.PENDING_OCCUPIED, exit_failure=True)
    assert not any(event.startswith(("read-", "publish-")) for event in harness.events)
    harness.bounded()


@pytest.mark.parametrize(
    "event,state,pending,pp,descriptor,dp",
    (
        ("preflight-pending", S.PREWRITE_UNVERIFIABLE, False, False, False, False),
        ("publish-pending", S.PENDING_PERSISTENCE_UNCERTAIN, True, None, False, False),
        ("read-pending-1", S.PENDING_PERSISTENCE_UNCERTAIN, True, True, False, False),
        ("read-pending-2", S.PENDING_PERSISTENCE_UNCERTAIN, True, True, False, False),
        ("preflight-descriptor", S.PENDING_PERSISTENCE_UNCERTAIN, True, True, False, False),
        ("publish-descriptor", S.DESCRIPTOR_PERSISTENCE_UNCERTAIN, True, True, True, None),
        ("read-descriptor-1", S.DESCRIPTOR_PERSISTENCE_UNCERTAIN, True, True, True, True),
        ("exit", S.DESCRIPTOR_PERSISTENCE_UNCERTAIN, True, True, True, True),
    ),
)
@pytest.mark.parametrize("cleanup_fails", (False, True))
def test_each_storage_failure_retains_per_artifact_evidence(
    event: str,
    state: S,
    pending: bool,
    pp: bool | None,
    descriptor: bool,
    dp: bool | None,
    cleanup_fails: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(monkeypatch)
    harness.faults[event] = RuntimeError("synthetic-private-failure")
    if cleanup_fails:
        harness.faults["exit"] = RuntimeError("synthetic-cleanup")
    result = harness.run()
    _assert_result(
        result,
        state,
        pending=pending,
        pp=pp,
        descriptor=descriptor,
        dp=dp,
        exit_failure=cleanup_fails or event == "exit",
    )
    if not descriptor:
        assert "publish-descriptor" not in harness.events
    assert "synthetic-private" not in repr(result)
    harness.bounded()


@pytest.mark.parametrize("checkpoint", range(1, 9))
@pytest.mark.parametrize("lock_error", (False, True))
def test_every_checkpoint_failure_prevents_next_publication(
    checkpoint: int, lock_error: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _Harness(monkeypatch)
    harness.faults[f"checkpoint-{checkpoint}"] = (
        prep.private_lock.PosixPrivateLockError("posix_directory_lock_unverified")
        if lock_error
        else RuntimeError("synthetic-checkpoint")
    )
    pending, descriptor = checkpoint >= 4, checkpoint == 8
    state = (
        S.DESCRIPTOR_PERSISTENCE_UNCERTAIN
        if descriptor
        else S.PENDING_PERSISTENCE_UNCERTAIN
        if pending
        else S.LOCK_UNAVAILABLE
        if lock_error
        else S.PREWRITE_UNVERIFIABLE
    )
    _assert_result(
        harness.run(), state, pending=pending, pp=pending, descriptor=descriptor, dp=descriptor
    )
    assert ("publish-descriptor" in harness.events) is descriptor
    harness.bounded()


@pytest.mark.parametrize("case", ("refusal", "exception"))
def test_final_validator_refusal_never_returns_success(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _Harness(monkeypatch)
    original = prep.validate_enrollment_descriptor
    calls = 0

    def validate(raw: object, expectation: object) -> Any:
        nonlocal calls
        calls += 1
        if calls == 2:
            if case == "exception":
                raise RuntimeError("synthetic-final-comparison")
            return validator.EnrollmentDescriptorResult(
                validator.EnrollmentDescriptorState.ENROLLMENT_MISMATCH
            )
        return original(raw, expectation)

    monkeypatch.setattr(prep, "validate_enrollment_descriptor", validate)
    _assert_result(
        harness.run(),
        S.DESCRIPTOR_PERSISTENCE_UNCERTAIN,
        pending=True,
        pp=True,
        descriptor=True,
        dp=True,
    )
    assert calls == 2 and harness.outputs == {PENDING: _pending(), DESCRIPTOR: RAW}
    harness.bounded()


@pytest.mark.parametrize("leaf", ("pending", "descriptor"))
@pytest.mark.parametrize(
    "evidence", (False, True, None, 1), ids=("false", "true", "none", "integer")
)
def test_formal_publisher_evidence_requires_exact_boolean(
    leaf: str, evidence: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _Harness(monkeypatch)
    error = prep.private_create.PosixPrivateCreateError("synthetic", publication_possible=False)
    error.publication_possible = evidence
    harness.faults[f"publish-{leaf}"] = error
    publication = evidence if type(evidence) is bool else None
    _assert_result(
        harness.run(),
        S.PENDING_PERSISTENCE_UNCERTAIN
        if leaf == "pending"
        else S.DESCRIPTOR_PERSISTENCE_UNCERTAIN,
        pending=True,
        pp=publication if leaf == "pending" else True,
        descriptor=leaf == "descriptor",
        dp=publication if leaf == "descriptor" else False,
    )
    harness.bounded()


@pytest.mark.parametrize("event", ("read-pending-1", "read-pending-2", "read-descriptor-1"))
def test_changed_readback_cannot_replace_original_expectations(
    event: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _Harness(monkeypatch)
    harness.read_values[event] = b"{}\n"
    descriptor = event == "read-descriptor-1"
    _assert_result(
        harness.run(),
        S.DESCRIPTOR_PERSISTENCE_UNCERTAIN if descriptor else S.PENDING_PERSISTENCE_UNCERTAIN,
        pending=True,
        pp=True,
        descriptor=descriptor,
        dp=descriptor,
    )
    assert ("publish-descriptor" in harness.events) is descriptor
    harness.bounded()


def test_late_descriptor_occupancy_keeps_pending_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = _Harness(monkeypatch)
    harness.occupied_values["occupied-descriptor-2"] = True
    _assert_result(harness.run(), S.DESCRIPTOR_OCCUPIED, pending=True, pp=True)
    assert harness.outputs == {PENDING: _pending()} and "publish-descriptor" not in harness.events
    harness.bounded()


def test_changed_preflight_destination_stops_before_publication(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(monkeypatch)
    harness.mismatch_preflight = True
    _assert_result(harness.run(), S.PREWRITE_UNVERIFIABLE)
    assert not harness.outputs


@pytest.mark.parametrize(
    "code,state",
    (
        ("posix_directory_lock_busy", S.LOCK_BUSY),
        ("posix_directory_lock_unavailable", S.LOCK_UNAVAILABLE),
    ),
)
def test_acquire_failure_has_no_owned_resource_or_fallback(
    code: str, state: S, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _Harness(monkeypatch)
    harness.faults["acquire"] = prep.private_lock.PosixPrivateLockError(code)
    _assert_result(harness.run(), state)
    assert harness.events == ["acquire"] and harness.close_calls == 0
    harness.bounded()


@pytest.mark.parametrize("invalidated", (False, True))
@pytest.mark.parametrize("cleanup_fails", (False, True))
def test_failed_entry_closes_acquired_owner_once(
    invalidated: bool, cleanup_fails: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _Harness(monkeypatch)
    harness.invalidated_on_entry = invalidated
    harness.faults["enter"] = prep.private_lock.PosixPrivateLockError(
        "posix_directory_lock_unverified"
    )
    if cleanup_fails:
        harness.faults["close"] = RuntimeError("synthetic-cleanup")
    result = harness.run()
    _assert_result(result, S.LOCK_UNAVAILABLE, exit_failure=cleanup_fails)
    assert harness.events == ["acquire", "enter", "close"]
    assert harness.close_calls == harness.release_count == 1
    harness.bounded()


@pytest.mark.parametrize(
    "event",
    (
        "acquire",
        "enter",
        "preflight-pending",
        "checkpoint-1",
        "publish-pending",
        "read-pending-1",
        "checkpoint-4",
        "read-pending-2",
        "checkpoint-8",
        "publish-descriptor",
        "read-descriptor-1",
        "exit",
    ),
)
@pytest.mark.parametrize("cancel_type", (KeyboardInterrupt, SystemExit))
def test_cancellation_propagates_and_owned_resources_unwind(
    event: str, cancel_type: type[BaseException], monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _Harness(monkeypatch)
    cancellation = cancel_type("synthetic-cancel")
    harness.faults[event] = cancellation
    if event not in {"acquire", "exit"}:
        harness.faults["close" if event == "enter" else "exit"] = RuntimeError("synthetic-cleanup")
    with pytest.raises(cancel_type) as caught:
        harness.run()
    assert caught.value is cancellation
    harness.bounded()


def test_later_exit_cancellation_is_not_hidden_by_earlier_ordinary_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(monkeypatch)
    harness.faults = {"publish-pending": RuntimeError("synthetic"), "exit": KeyboardInterrupt()}
    with pytest.raises(KeyboardInterrupt):
        harness.run()
    assert "publish-descriptor" not in harness.events
    harness.bounded()


@pytest.mark.parametrize("state", tuple(S), ids=lambda state: state.name)
def test_every_result_state_is_frozen_slotted_and_unapproved(state: S) -> None:
    pending = state in {
        S.PENDING_PERSISTENCE_UNCERTAIN,
        S.DESCRIPTOR_PERSISTENCE_UNCERTAIN,
        S.PREPARATION_OBSERVED_UNAPPROVED,
    }
    descriptor = state in {S.DESCRIPTOR_PERSISTENCE_UNCERTAIN, S.PREPARATION_OBSERVED_UNAPPROVED}
    result = prep.PreparationResult(state, pending, pending, descriptor, descriptor)
    _assert_result(result, state, pending=pending, pp=pending, descriptor=descriptor, dp=descriptor)
    with pytest.raises(FrozenInstanceError):
        result.state = S.INPUT_UNVERIFIABLE
    with pytest.raises(TypeError):
        prep.PreparationResult(state, reuse_authorized=True)
    assert "synthetic" not in repr(result)
    assert len(S) == 12


@pytest.mark.parametrize(
    "field",
    (
        "state",
        "pending_attempted",
        "pending_publication_possible",
        "descriptor_attempted",
        "descriptor_publication_possible",
        "exit_failure_observed",
    ),
)
@pytest.mark.parametrize("case", ("poison", "integer", "string"))
def test_result_constructor_rejects_hooks_and_wrong_types(field: str, case: str) -> None:
    value = _Poison() if case == "poison" else 1 if case == "integer" else "synthetic-private"
    values: dict[str, object] = {"state": S.INPUT_UNVERIFIABLE, field: value}
    with pytest.raises(ValueError) as caught:
        prep.PreparationResult(**values)
    assert str(caught.value) == "Invalid preparation result"


@pytest.mark.parametrize(
    "case",
    (
        "pending-without-attempt",
        "descriptor-without-attempt",
        "descriptor-without-pending",
        "descriptor-after-unconfirmed-pending",
        "success-without-pending",
        "success-without-descriptor",
        "success-unknown-publication",
        "success-exit-failure",
        "uncertainty-without-attempt",
        "input-exit-failure",
    ),
)
def test_result_constructor_rejects_inconsistent_progress(case: str) -> None:
    cases: dict[str, dict[str, Any]] = {
        "pending-without-attempt": {"pending_publication_possible": None},
        "descriptor-without-attempt": {"descriptor_publication_possible": True},
        "descriptor-without-pending": {
            "descriptor_attempted": True,
            "descriptor_publication_possible": None,
        },
        "descriptor-after-unconfirmed-pending": {
            "pending_attempted": True,
            "pending_publication_possible": None,
            "descriptor_attempted": True,
            "descriptor_publication_possible": None,
        },
        "success-without-pending": {"state": S.PREPARATION_OBSERVED_UNAPPROVED},
        "success-without-descriptor": {
            "state": S.PREPARATION_OBSERVED_UNAPPROVED,
            "pending_attempted": True,
            "pending_publication_possible": True,
        },
        "success-unknown-publication": {
            "state": S.PREPARATION_OBSERVED_UNAPPROVED,
            "pending_attempted": True,
            "pending_publication_possible": True,
            "descriptor_attempted": True,
            "descriptor_publication_possible": None,
        },
        "success-exit-failure": {
            "state": S.PREPARATION_OBSERVED_UNAPPROVED,
            "pending_attempted": True,
            "pending_publication_possible": True,
            "descriptor_attempted": True,
            "descriptor_publication_possible": True,
            "exit_failure_observed": True,
        },
        "uncertainty-without-attempt": {"state": S.PENDING_PERSISTENCE_UNCERTAIN},
        "input-exit-failure": {"exit_failure_observed": True},
    }
    with pytest.raises(ValueError, match=r"^Invalid preparation result$"):
        prep.PreparationResult(**({"state": S.INPUT_UNVERIFIABLE} | cases[case]))


def _private(tmp_path: Path) -> Path:
    root = tmp_path / "control"
    root.mkdir(mode=0o700)
    return root


@LINUX_ONLY
def test_native_success_retains_private_records_and_refuses_new_call(tmp_path: Path) -> None:
    root = _private(tmp_path)
    _assert_result(
        prep.prepare_synthetic_enrollment(str(root), RAW, _expect()),
        S.PREPARATION_OBSERVED_UNAPPROVED,
        pending=True,
        pp=True,
        descriptor=True,
        dp=True,
    )
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    for leaf, content in ((PENDING, _pending()), (DESCRIPTOR, RAW)):
        assert (root / leaf).read_bytes() == content
        assert stat.S_IMODE((root / leaf).stat().st_mode) == 0o600
    _assert_result(prep.prepare_synthetic_enrollment(str(root), RAW, _expect()), S.BOTH_OCCUPIED)
    assert (root / PENDING).read_bytes() == _pending() and (root / DESCRIPTOR).read_bytes() == RAW


@LINUX_ONLY
@pytest.mark.parametrize("leaf", (PENDING, DESCRIPTOR))
@pytest.mark.parametrize("kind", ("same", "corrupt", "directory", "symlink", "dangling"))
def test_native_occupied_entry_never_reads_overwrites_or_deletes(
    leaf: str, kind: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private(tmp_path)
    target = root / leaf
    if kind == "directory":
        target.mkdir(mode=0o700)
    elif kind in {"symlink", "dangling"}:
        destination = root / "test-owned-target"
        if kind == "symlink":
            destination.write_bytes(b"synthetic-sentinel")
        target.symlink_to(destination)
    else:
        target.write_bytes(
            (_pending() if leaf == PENDING else RAW) if kind == "same" else b"broken"
        )
        target.chmod(0o600)
    before = target.lstat()
    monkeypatch.setattr(prep, "read_private_sensitive_bytes", _deny)
    monkeypatch.setattr(prep.private_create, "create_posix_private_bytes", _deny)
    _assert_result(
        prep.prepare_synthetic_enrollment(str(root), RAW, _expect()),
        S.PENDING_OCCUPIED if leaf == PENDING else S.DESCRIPTOR_OCCUPIED,
    )
    assert target.lstat() == before


@LINUX_ONLY
@pytest.mark.parametrize("case", ("unsafe", "worktree", "symlink", "missing"))
def test_native_root_guards_refuse_without_repair(case: str, tmp_path: Path) -> None:
    root = _private(tmp_path)
    if case == "unsafe":
        root.chmod(0o755)
    elif case == "worktree":
        (root / ".git").mkdir(mode=0o700)
    elif case == "symlink":
        link = tmp_path / "control-link"
        link.symlink_to(root, target_is_directory=True)
        root = link
    else:
        root = root / "missing"
    result = prep.prepare_synthetic_enrollment(str(root), RAW, _expect())
    assert result.state is S.LOCK_UNAVAILABLE and not result.pending_attempted
    assert not (root / PENDING).exists() and not (root / DESCRIPTOR).exists()
    if case == "unsafe":
        assert stat.S_IMODE(root.stat().st_mode) == 0o755


@LINUX_ONLY
@pytest.mark.parametrize("failed_leaf", (PENDING, DESCRIPTOR))
def test_native_failures_retain_residue_and_separate_observer_never_resumes(
    failed_leaf: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private(tmp_path)
    reader = prep.read_private_sensitive_bytes

    def fail_read(path: Path, **kwargs: Any) -> bytes:
        if path.name == failed_leaf:
            raise RuntimeError("synthetic-readback-failure")
        return reader(path, **kwargs)

    with monkeypatch.context() as scoped:
        scoped.setattr(prep, "read_private_sensitive_bytes", fail_read)
        result = prep.prepare_synthetic_enrollment(str(root), RAW, _expect())
    descriptor = failed_leaf == DESCRIPTOR
    _assert_result(
        result,
        S.DESCRIPTOR_PERSISTENCE_UNCERTAIN if descriptor else S.PENDING_PERSISTENCE_UNCERTAIN,
        pending=True,
        pp=True,
        descriptor=descriptor,
        dp=descriptor,
    )
    assert (root / PENDING).read_bytes() == _pending()
    assert (root / DESCRIPTOR).exists() is descriptor
    _assert_result(
        prep.prepare_synthetic_enrollment(str(root), RAW, _expect()),
        S.BOTH_OCCUPIED if descriptor else S.PENDING_OCCUPIED,
    )
    _observe_child(root, b"BOTH_RETAINED_UNAPPROVED\n" if descriptor else b"PENDING_RETAINED\n")


@LINUX_ONLY
def test_native_one_lock_blocks_contenders_through_all_writes_and_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private(tmp_path)
    publisher = prep.private_create.create_posix_private_bytes
    reader = prep.read_private_sensitive_bytes
    checks: list[str] = []

    def contend(label: str) -> None:
        with pytest.raises(prep.private_lock.PosixPrivateLockError) as caught:
            prep.private_lock.acquire_posix_private_directory_lock(root)
        assert caught.value.code == "posix_directory_lock_busy"
        checks.append(label)

    def publish(path: Path, content: bytes) -> None:
        contend("publish")
        publisher(path, content)

    def read(path: Path, **kwargs: Any) -> bytes:
        contend("read")
        return reader(path, **kwargs)

    monkeypatch.setattr(prep.private_create, "create_posix_private_bytes", publish)
    monkeypatch.setattr(prep, "read_private_sensitive_bytes", read)
    _assert_result(
        prep.prepare_synthetic_enrollment(str(root), RAW, _expect()),
        S.PREPARATION_OBSERVED_UNAPPROVED,
        pending=True,
        pp=True,
        descriptor=True,
        dp=True,
    )
    assert checks == ["publish", "read", "read", "publish", "read"]
    with prep.private_lock.acquire_posix_private_directory_lock(root):
        pass
    _observe_child(root, b"BOTH_RETAINED_UNAPPROVED\n")


def _observe_child(root: Path, expected: bytes) -> None:
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(Path(prep.__file__).resolve().parents[1])
    child = subprocess.run(
        [sys.executable, "-B", __file__, "--observe", str(root)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
        check=False,
        env=environment,
    )
    assert child.returncode == 0 and child.stdout == expected and not child.stderr


def _observer_main() -> int:
    """An orderly fresh-process observation is not a crash or power-loss test."""
    try:
        if len(sys.argv) != 3 or sys.argv[1] != "--observe":
            return 2
        root = Path(sys.argv[2])
        pending = prep.read_private_sensitive_bytes(root / PENDING, max_size=512)
        try:
            (root / DESCRIPTOR).lstat()
        except FileNotFoundError:
            raw = None
        else:
            raw = prep.read_private_sensitive_bytes(root / DESCRIPTOR, max_size=8192)
        if not prep._matches_pending(pending, _pending()):
            return 2
        if raw is None:
            print("PENDING_RETAINED")
        elif raw == RAW:
            print("BOTH_RETAINED_UNAPPROVED")
        else:
            return 2
        return 0
    except BaseException:
        return 2


def test_component_imports_exact_public_boundaries_and_has_no_runtime_consumer() -> None:
    source = Path(inspect.getfile(prep))
    tree = ast.parse(source.read_text(encoding="utf-8"))
    package_imports: set[str] = set()
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.ImportFrom)
            and node.module
            and node.module.startswith("tridentine_calendar_google_sync")
        ):
            if node.module == "tridentine_calendar_google_sync":
                package_imports.update(alias.name for alias in node.names)
            else:
                package_imports.add(node.module.rsplit(".", 1)[-1])
                if node.module.endswith("production_write_token_enrollment_descriptor"):
                    assert {alias.name for alias in node.names} == {
                        "validate_enrollment_descriptor",
                        "SyntheticEnrollmentExpectation",
                        "EnrollmentDescriptorState",
                    }
        if isinstance(node, ast.Call):
            name = (
                node.func.id
                if isinstance(node.func, ast.Name)
                else node.func.attr
                if isinstance(node.func, ast.Attribute)
                else ""
            )
            assert name not in {
                "open",
                "write_bytes",
                "write_text",
                "chmod",
                "mkdir",
                "unlink",
                "replace",
                "remove",
                "rmdir",
                "rename",
                "exec",
                "eval",
                "__import__",
                "print",
                "sleep",
                "run",
                "Popen",
                "Thread",
                "Process",
                "resolve",
            }
        assert not isinstance(node, (ast.While, ast.Global))
    assert package_imports == {
        "_posix_private_lock",
        "_posix_private_create",
        "sensitive_paths",
        "production_write_token_enrollment_descriptor",
    }
    for other in source.parent.rglob("*.py"):
        if other != source:
            assert source.stem not in other.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "platform,name,available",
    (
        ("linux", "posix", True),
        ("linux", "nt", False),
        ("win32", "nt", False),
        ("darwin", "posix", False),
    ),
)
def test_platform_dispatch_requires_both_linux_and_posix(
    platform: str,
    name: str,
    available: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(prep, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(prep, "os", SimpleNamespace(name=name))
    assert prep._linux_storage_available() is available
    if not available:
        _assert_result(
            prep.prepare_synthetic_enrollment(_Poison(), _Poison(), _Poison()),
            S.UNSUPPORTED_PLATFORM,
        )


@pytest.mark.parametrize("failure", (RuntimeError, KeyboardInterrupt, SystemExit))
def test_input_encoding_failure_precedes_acquisition(
    failure: type[BaseException],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _Harness(monkeypatch)
    error = failure("synthetic-encoding")

    def fail(expectation: object) -> bytes:
        raise error

    monkeypatch.setattr(prep, "_encode_pending", fail)
    if failure is RuntimeError:
        _assert_result(harness.run(), S.INPUT_UNVERIFIABLE)
    else:
        with pytest.raises(failure) as caught:
            harness.run()
        assert caught.value is error
    assert harness.events == []


def test_known_occupancy_does_not_swallow_cancellation(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = _Harness(monkeypatch)
    harness.occupied_values["occupied-pending-1"] = True
    error = KeyboardInterrupt("synthetic-occupancy")
    harness.faults["occupied-descriptor-1"] = error
    with pytest.raises(KeyboardInterrupt) as caught:
        harness.run()
    assert caught.value is error
    assert not harness.outputs
    harness.bounded()


def test_preflight_return_hook_is_not_invoked(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = _Harness(monkeypatch)
    monkeypatch.setattr(prep, "validate_sensitive_output_path", lambda *args, **kwargs: _Poison())
    _assert_result(harness.run(), S.PREWRITE_UNVERIFIABLE)
    assert not harness.outputs
    harness.bounded()


if __name__ == "__main__":
    raise SystemExit(_observer_main())
