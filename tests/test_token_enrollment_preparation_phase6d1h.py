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


IS = prep.InspectionState
P = prep.Presence
C = prep.ContentStatus
T = prep.TargetRelation
F = prep.InspectionFailure
_INSPECTION_FORBIDDEN = (
    "prepare_synthetic_enrollment",
    "_Progress",
    "PreparationResult",
    "_occupied",
    "_read_pending",
    "_preflight",
    "_publish",
    "_run_owned",
    "validate_sensitive_output_path",
)


def _inspection_forbid(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> Any:
        calls.append("FORBIDDEN_EFFECT")
        raise _UnexpectedEffect("inspection reached a writer boundary")

    for name in _INSPECTION_FORBIDDEN:
        monkeypatch.setattr(prep, name, forbidden)
    monkeypatch.setattr(prep.private_create, "create_posix_private_bytes", forbidden)
    return calls


def _inspection_metadata(
    *,
    size: int = 1,
    inode: int = 1,
    mode: int = stat.S_IFREG | 0o600,
    links: int = 1,
    stamp: int = 1,
    atime: int = 1,
) -> os.stat_result:
    return os.stat_result(
        (mode, inode, 1, links, 1, 1, size, atime, stamp, stamp),
        {"st_atime_ns": atime, "st_mtime_ns": stamp, "st_ctime_ns": stamp},
    )


class _InspectionHarness:
    """Independent reader owner; no writer fixture or publisher is involved."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.events: list[str] = []
        self.calls: dict[str, int] = {}
        self.contents: dict[str, object] = {PENDING: _pending(), DESCRIPTOR: RAW}
        self.metadata_values: dict[str, object] = {}
        self.faults: dict[str, BaseException] = {}
        self.owned = False
        self.active = False
        self.invalidated = False
        self.releases = 0
        self.closes = 0
        self.exit_errors: list[object] = []
        self.forbidden = _inspection_forbid(monkeypatch)
        monkeypatch.setattr(prep, "_linux_storage_available", lambda: True)
        monkeypatch.setattr(prep, "_inspection_lstat", self.metadata)
        monkeypatch.setattr(prep, "read_private_sensitive_bytes", self.read)
        monkeypatch.setattr(prep.private_lock, "acquire_posix_private_directory_lock", self.acquire)

    def hit(self, label: str) -> None:
        self.events.append(label)
        if label in self.faults:
            raise self.faults[label]

    def numbered(self, label: str) -> str:
        self.calls[label] = self.calls.get(label, 0) + 1
        return f"{label}-{self.calls[label]}"

    def leaf(self, path: Path) -> str:
        assert self.active and self.owned
        assert path.parent == Path(ROOT) and path.name in {PENDING, DESCRIPTOR}
        return "pending" if path.name == PENDING else "descriptor"

    def acquire(self, path: Path) -> _InspectionHarness:
        assert path == Path(ROOT) and not self.owned
        self.hit("acquire")
        self.owned = True
        return self

    def __enter__(self) -> _InspectionHarness:
        assert self.owned
        if self.invalidated:
            self.owned = False
            self.releases += 1
        self.hit("enter")
        self.active = True
        return self

    def __exit__(self, kind: object, error: object, traceback: object) -> None:
        self.exit_errors.append(error)
        assert self.active
        self.owned = self.active = False
        self.releases += 1
        self.hit("exit")

    def close(self) -> None:
        self.closes += 1
        if self.owned:
            self.owned = self.active = False
            self.releases += 1
        self.hit("close")

    def revalidate(self) -> None:
        assert self.owned and self.active
        self.hit(self.numbered("K"))

    def metadata(self, path: Path) -> object:
        leaf = self.leaf(path)
        event = self.numbered(f"stat-{leaf}")
        self.hit(event)
        default = _inspection_metadata() if path.name in self.contents else None
        return self.metadata_values.get(event, default)

    def read(self, path: Path, *, max_size: int, **kwargs: object) -> object:
        leaf = self.leaf(path)
        assert max_size == (512 if leaf == "pending" else 8192)
        self.hit(self.numbered(f"read-{leaf}"))
        return self.contents[path.name]

    def bounded(self) -> None:
        assert not self.forbidden and not self.owned and not self.active
        assert self.events.count("acquire") <= 1 and self.events.count("enter") <= 1
        assert self.events.count("exit") <= 1 and self.closes <= 1
        assert self.calls.get("K", 0) <= 4
        for leaf in ("pending", "descriptor"):
            assert self.calls.get(f"stat-{leaf}", 0) <= 2
            assert self.calls.get(f"read-{leaf}", 0) <= 1

    def run(
        self, *, root: object = ROOT, raw: object = RAW, expectation: object | None = None
    ) -> prep.PreparationInspection:
        try:
            return prep.inspect_synthetic_enrollment_preparation(
                root, raw, _expect() if expectation is None else expectation
            )
        finally:
            self.bounded()


def _inspection_check(
    result: prep.PreparationInspection,
    state: IS,
    *,
    complete: bool = False,
    failure: F = F.NONE,
    exit_failure: bool = False,
) -> None:
    assert type(result) is prep.PreparationInspection and result.state is state
    assert result.verification_complete is complete and result.first_failure is failure
    assert result.exit_failure_observed is exit_failure and result.reuse_authorized is False
    assert not hasattr(result, "__dict__")
    assert {field.name for field in fields(result)} == {
        "state",
        "pending",
        "descriptor",
        "target_relation",
        "non_preparing_observed",
        "verification_complete",
        "first_failure",
        "exit_failure_observed",
        "reuse_authorized",
    }
    assert "synthetic" not in repr(result)


@pytest.mark.parametrize(
    "case",
    ("unsupported", "root", "expectation", "field", "raw", "pin", "metadata", "active", "revoked"),
)
def test_inspection_gate_refuses_before_input_hooks_or_io(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _InspectionHarness(monkeypatch)
    root: object = _Poison() if case in {"unsupported", "root"} else ROOT
    raw: object = _Poison() if case in {"unsupported", "raw"} else RAW
    expectation: object = _expect()
    state, failure = IS.INPUT_UNVERIFIABLE, F.INPUT
    if case == "unsupported":
        monkeypatch.setattr(prep, "_linux_storage_available", lambda: False)
        monkeypatch.setattr(prep, "_snapshot", _deny)
        expectation = _Poison()
        state, failure = IS.UNSUPPORTED_PLATFORM, F.NONE
    elif case == "expectation":
        expectation = _Poison()
    elif case == "field":
        expectation = replace(_expect(), pair_ref=_Poison())
    elif case == "pin":
        expectation = replace(_expect(), descriptor_pin="0" * 64)
    elif case == "metadata":
        raw = RAW.replace(b"pair-one", b"other-pair")
    elif case in {"active", "revoked"}:
        raw = RAW.replace(b"PREPARING", case.upper().encode())
        expectation = _expect(raw)
        state = IS.PREPARING_REQUIRED
    result = harness.run(root=root, raw=raw, expectation=expectation)
    _inspection_check(result, state, failure=failure)
    assert harness.events == []
    assert result.pending == result.descriptor == prep.LeafObservation()


@pytest.mark.parametrize("pending", ("present", "absent", "unknown"))
@pytest.mark.parametrize("descriptor", ("present", "absent", "unknown"))
def test_inspection_presence_combinations_never_guess_absence(
    pending: str, descriptor: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _InspectionHarness(monkeypatch)
    for leaf, presence in (("pending", pending), ("descriptor", descriptor)):
        if presence != "present":
            del harness.contents[PENDING if leaf == "pending" else DESCRIPTOR]
        if presence == "unknown":
            harness.faults[f"stat-{leaf}-1"] = RuntimeError("synthetic-metadata")
    stable = "unknown" not in {pending, descriptor}
    states = {
        ("absent", "absent"): IS.ABSENCE_UNVERIFIABLE,
        ("present", "absent"): IS.ADMIN_PENDING,
        ("absent", "present"): IS.ORPHAN_DESCRIPTOR,
        ("present", "present"): IS.PREPARATION_RETAINED_UNAPPROVED,
    }
    first = (
        F.PENDING_ENTRY
        if pending == "unknown"
        else F.DESCRIPTOR_ENTRY
        if descriptor == "unknown"
        else F.NONE
    )
    result = harness.run()
    _inspection_check(
        result,
        states.get((pending, descriptor), IS.PREPARATION_UNVERIFIABLE),
        complete=stable,
        failure=first,
    )
    for observed, source in ((result.pending, pending), (result.descriptor, descriptor)):
        assert (
            observed.presence
            is {"present": P.PRESENT, "absent": P.ABSENT, "unknown": P.UNKNOWN}[source]
        )
        assert observed.content is (C.SCHEMA_VALID if source == "present" else C.NOT_READ)


def test_inspection_schedule_retains_snapshot_and_constructs_result_after_exit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _InspectionHarness(monkeypatch)
    expectation = _expect()
    original_acquire, original_validator = harness.acquire, prep.validate_enrollment_descriptor
    snapshots: list[object] = []

    def acquire(path: Path) -> _InspectionHarness:
        object.__setattr__(expectation, "descriptor_slot", "changed.json")
        object.__setattr__(expectation, "descriptor_pin", "0" * 64)
        return original_acquire(path)

    def compare(raw: object, retained: object) -> Any:
        assert retained is not expectation
        snapshots.append(retained)
        return original_validator(raw, retained)

    result_type = prep.PreparationInspection

    def result(*args: object, **kwargs: object) -> Any:
        assert harness.events[-1] == "exit" and not harness.owned
        return result_type(*args, **kwargs)

    monkeypatch.setattr(prep.private_lock, "acquire_posix_private_directory_lock", acquire)
    monkeypatch.setattr(prep, "validate_enrollment_descriptor", compare)
    monkeypatch.setattr(prep, "PreparationInspection", result)
    observed = harness.run(expectation=expectation)
    assert observed.state is IS.PREPARATION_RETAINED_UNAPPROVED and observed.verification_complete
    assert snapshots[0] is snapshots[1] and len(snapshots) == 2
    assert harness.events == [
        "acquire",
        "enter",
        "K-1",
        "stat-pending-1",
        "stat-descriptor-1",
        "K-2",
        "read-pending-1",
        "K-3",
        "read-descriptor-1",
        "stat-pending-2",
        "stat-descriptor-2",
        "K-4",
        "exit",
    ]
    assert harness.releases == 1 and harness.closes == 0 and harness.exit_errors == [None]


def _inspection_foreign_pair() -> tuple[bytes, bytes]:
    raw = RAW.replace(b"revision-one", b"revision-other")
    pending = _wire(
        json.loads(_pending())
        | {"target_revision": "revision-other", "target_pin": hashlib.sha256(raw).hexdigest()}
    )
    return pending, raw


@pytest.mark.parametrize("case", ("pending", "descriptor", "both", "active", "revoked"))
def test_inspection_well_formed_mismatch_is_complete_conflict(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _InspectionHarness(monkeypatch)
    pending, raw = _inspection_foreign_pair()
    if case in {"pending", "both"}:
        harness.contents[PENDING] = pending
    if case in {"descriptor", "both"}:
        harness.contents[DESCRIPTOR] = raw
    if case in {"active", "revoked"}:
        harness.contents[DESCRIPTOR] = RAW.replace(b"PREPARING", case.upper().encode())
    result = harness.run()
    _inspection_check(result, IS.PREPARATION_CONFLICT, complete=True)
    assert result.pending.content is result.descriptor.content is C.SCHEMA_VALID
    assert result.pending.target is (T.MISMATCH if case in {"pending", "both"} else T.MATCH)
    assert result.descriptor.target is (T.MATCH if case == "pending" else T.MISMATCH)
    assert result.target_relation is (T.MATCH if case == "both" else T.MISMATCH)
    assert result.non_preparing_observed is (case in {"active", "revoked"})
    assert harness.exit_errors == [None]


@pytest.mark.parametrize("leaf", (PENDING, DESCRIPTOR))
@pytest.mark.parametrize(
    "case",
    (
        "empty",
        "oversize",
        "bom",
        "utf8",
        "duplicate",
        "escaped",
        "extra",
        "missing",
        "bool",
        "nan",
        "surrogate",
        "noncanonical",
        "poison",
    ),
)
def test_inspection_schema_failure_is_not_target_mismatch(
    leaf: str, case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _InspectionHarness(monkeypatch)
    original = _pending() if leaf == PENDING else RAW
    data = json.loads(original)
    key = "outcome" if leaf == PENDING else "role"
    modified = dict(data)
    del modified[key]
    malformed: dict[str, object] = {
        "empty": b"",
        "oversize": b"x" * (513 if leaf == PENDING else 8193),
        "bom": b"\xef\xbb\xbf" + original,
        "utf8": b"\xff",
        "duplicate": _wire({key: data[key]})[:-2] + b"," + original[1:],
        "escaped": b'{"format_\\u0076ersion":1,' + original[1:],
        "extra": _wire(data | {"unknown": 1}),
        "missing": _wire(modified),
        "bool": _wire(data | {"format_version": True}),
        "nan": original.replace(b'"format_version":1', b'"format_version":NaN'),
        "surrogate": _wire(data | {key: "\ud800"}),
        "noncanonical": original + b"\n",
    }
    harness.contents[leaf] = _Poison() if case == "poison" else malformed[case]
    result = harness.run()
    read_failure = case in {"oversize", "poison"}
    _inspection_check(
        result,
        IS.PREPARATION_UNVERIFIABLE,
        failure=(F.PENDING_READ if leaf == PENDING else F.DESCRIPTOR_READ)
        if read_failure
        else F.PENDING_SCHEMA
        if leaf == PENDING
        else F.DESCRIPTOR_COMPARE,
    )
    observed = result.pending if leaf == PENDING else result.descriptor
    assert observed.presence is P.PRESENT
    assert observed.content is (C.READ_UNVERIFIABLE if read_failure else C.SCHEMA_UNVERIFIABLE)
    assert observed.target is T.NOT_COMPARED and result.target_relation is T.NOT_COMPARED


@pytest.mark.parametrize("leaf", ("pending", "descriptor"))
@pytest.mark.parametrize(
    "case", ("symlink", "directory", "hardlink", "oversize", "unknown-signature")
)
def test_inspection_unsafe_metadata_keeps_presence_without_read(
    leaf: str, case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _InspectionHarness(monkeypatch)
    kwargs = {
        "symlink": {"mode": stat.S_IFLNK | 0o777},
        "directory": {"mode": stat.S_IFDIR | 0o700},
        "hardlink": {"links": 2},
        "oversize": {"size": 513 if leaf == "pending" else 8193},
        "unknown-signature": {},
    }
    metadata = _inspection_metadata(**kwargs[case])
    if case == "unknown-signature":
        original = prep._inspection_signature

        def signature(value: os.stat_result) -> Any:
            if value is metadata:
                raise RuntimeError("synthetic-signature")
            return original(value)

        monkeypatch.setattr(prep, "_inspection_signature", signature)
    harness.metadata_values[f"stat-{leaf}-1"] = metadata
    harness.metadata_values[f"stat-{leaf}-2"] = metadata
    result = harness.run()
    _inspection_check(
        result,
        IS.PREPARATION_UNVERIFIABLE,
        failure=F.PENDING_ENTRY if leaf == "pending" else F.DESCRIPTOR_ENTRY,
    )
    observed = result.pending if leaf == "pending" else result.descriptor
    assert observed.presence is P.PRESENT and observed.content is not C.SCHEMA_VALID
    assert harness.calls.get(f"read-{leaf}", 0) == 0


@pytest.mark.parametrize(
    "event,failure",
    (
        ("stat-pending-1", F.PENDING_ENTRY),
        ("stat-descriptor-1", F.DESCRIPTOR_ENTRY),
        ("read-pending-1", F.PENDING_READ),
        ("read-descriptor-1", F.DESCRIPTOR_READ),
        ("stat-pending-2", F.PENDING_ENTRY),
        ("stat-descriptor-2", F.DESCRIPTOR_ENTRY),
        ("exit", F.EXIT),
    ),
)
@pytest.mark.parametrize("conflict", (False, True))
def test_inspection_known_evidence_survives_later_failures(
    event: str, failure: F, conflict: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _InspectionHarness(monkeypatch)
    if conflict:
        harness.contents[PENDING], harness.contents[DESCRIPTOR] = _inspection_foreign_pair()
    harness.faults[event] = RuntimeError("synthetic-inspection-failure")
    result = harness.run()
    _inspection_check(
        result,
        IS.PREPARATION_CONFLICT if conflict else IS.PREPARATION_UNVERIFIABLE,
        failure=failure,
        exit_failure=event == "exit",
    )
    if event in {"stat-pending-2", "stat-descriptor-2", "exit"}:
        assert result.pending.content is result.descriptor.content is C.SCHEMA_VALID
        assert result.target_relation is T.MATCH
    if event == "read-pending-1":
        assert (
            result.pending.presence is P.PRESENT and result.pending.content is C.READ_UNVERIFIABLE
        )
        assert result.descriptor.content is C.SCHEMA_VALID


@pytest.mark.parametrize("checkpoint", range(1, 5))
@pytest.mark.parametrize("conflict", (False, True))
def test_inspection_root_failure_stops_all_further_leaf_access(
    checkpoint: int, conflict: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _InspectionHarness(monkeypatch)
    if conflict:
        harness.contents[PENDING], harness.contents[DESCRIPTOR] = _inspection_foreign_pair()
    harness.faults[f"K-{checkpoint}"] = prep.private_lock.PosixPrivateLockError("synthetic-root")
    result = harness.run()
    known_conflict = conflict and checkpoint >= 3
    _inspection_check(
        result,
        IS.PREPARATION_CONFLICT if known_conflict else IS.PREPARATION_UNVERIFIABLE,
        failure=F.ROOT_CHECK,
    )
    stopped = harness.events.index(f"K-{checkpoint}")
    assert harness.events[stopped + 1 :] == ["exit"]
    if checkpoint >= 3:
        assert result.pending.content is C.SCHEMA_VALID
    if checkpoint == 4:
        assert result.descriptor.content is C.SCHEMA_VALID


@pytest.mark.parametrize(
    "case", ("disappear", "appear", "signature", "atime", "unknown-then-present")
)
def test_inspection_presence_is_sticky_and_atime_is_excluded(
    case: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _InspectionHarness(monkeypatch)
    if case == "disappear":
        harness.metadata_values["stat-pending-2"] = None
    elif case == "appear":
        harness.metadata_values["stat-pending-1"] = None
    elif case == "signature":
        harness.metadata_values["stat-pending-2"] = _inspection_metadata(inode=2)
    elif case == "atime":
        harness.metadata_values["stat-pending-2"] = _inspection_metadata(atime=2)
    else:
        harness.faults["stat-pending-1"] = RuntimeError("synthetic-unknown")
    result = harness.run()
    _inspection_check(
        result,
        IS.PREPARATION_RETAINED_UNAPPROVED if case == "atime" else IS.PREPARATION_UNVERIFIABLE,
        complete=case == "atime",
        failure=F.NONE
        if case == "atime"
        else F.PENDING_ENTRY
        if case == "unknown-then-present"
        else F.ENTRY_CHANGED,
    )
    assert result.pending.presence is P.PRESENT
    assert result.pending.changed is (case in {"disappear", "appear", "signature"})
    if case in {"appear", "unknown-then-present"}:
        assert result.pending.content is C.NOT_READ and harness.calls.get("read-pending", 0) == 0


@pytest.mark.parametrize("mismatch", (False, True))
@pytest.mark.parametrize("helper", ("_inspection_extract_descriptor", "_inspection_digest"))
def test_inspection_extraction_failure_keeps_schema_and_prior_target(
    mismatch: bool, helper: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _InspectionHarness(monkeypatch)
    if mismatch:
        harness.contents[DESCRIPTOR] = _inspection_foreign_pair()[1]

    def fail(raw: bytes) -> Any:
        raise RuntimeError("synthetic-extraction")

    monkeypatch.setattr(prep, helper, fail)
    result = harness.run()
    _inspection_check(
        result,
        IS.PREPARATION_CONFLICT if mismatch else IS.PREPARATION_UNVERIFIABLE,
        failure=F.TARGET_EXTRACTION,
    )
    assert result.descriptor.content is C.SCHEMA_VALID
    assert result.descriptor.target is (T.MISMATCH if mismatch else T.MATCH)
    assert result.target_relation is T.NOT_COMPARED


def test_inspection_unvalidated_descriptor_never_reaches_extraction_or_hash(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _InspectionHarness(monkeypatch)
    harness.contents[DESCRIPTOR] = b"{}\n"
    monkeypatch.setattr(prep, "_inspection_extract_descriptor", _deny)
    monkeypatch.setattr(prep, "_inspection_digest", _deny)
    _inspection_check(harness.run(), IS.PREPARATION_UNVERIFIABLE, failure=F.DESCRIPTOR_COMPARE)


def test_inspection_unexpected_validator_expectation_refusal_keeps_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _InspectionHarness(monkeypatch)
    original = prep.validate_enrollment_descriptor
    snapshots: list[object] = []

    def compare(raw: object, expectation: object) -> Any:
        snapshots.append(expectation)
        if len(snapshots) == 2:
            return validator.EnrollmentDescriptorResult(
                validator.EnrollmentDescriptorState.EXPECTATION_UNVERIFIABLE
            )
        return original(raw, expectation)

    monkeypatch.setattr(prep, "validate_enrollment_descriptor", compare)
    result = harness.run()
    _inspection_check(result, IS.PREPARATION_UNVERIFIABLE, failure=F.DESCRIPTOR_COMPARE)
    assert snapshots[0] is snapshots[1] and result.pending.content is C.SCHEMA_VALID


@pytest.mark.parametrize("stage", ("acquire", "enter"))
@pytest.mark.parametrize("busy", (False, True))
def test_inspection_acquire_entry_stages_have_distinct_cleanup(
    stage: str, busy: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _InspectionHarness(monkeypatch)
    code = "posix_directory_lock_busy" if busy else "posix_directory_lock_unverified"
    harness.faults[stage] = prep.private_lock.PosixPrivateLockError(code)
    result = harness.run()
    _inspection_check(
        result,
        IS.LOCK_BUSY if stage == "acquire" and busy else IS.LOCK_UNAVAILABLE,
        failure=F.ACQUIRE if stage == "acquire" else F.ENTRY,
    )
    assert harness.events == (["acquire"] if stage == "acquire" else ["acquire", "enter", "close"])


@pytest.mark.parametrize("invalidated", (False, True))
def test_inspection_failed_entry_closes_once_even_after_backend_invalidation(
    invalidated: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _InspectionHarness(monkeypatch)
    harness.invalidated = invalidated
    harness.faults = {
        "enter": RuntimeError("synthetic-entry"),
        "close": RuntimeError("synthetic-close"),
    }
    _inspection_check(harness.run(), IS.LOCK_UNAVAILABLE, failure=F.ENTRY, exit_failure=True)
    assert harness.closes == harness.releases == 1


@pytest.mark.parametrize(
    "event",
    (
        "acquire",
        "enter",
        "K-1",
        "stat-pending-1",
        "read-pending-1",
        "read-descriptor-1",
        "stat-descriptor-2",
        "exit",
    ),
)
@pytest.mark.parametrize("cancel", (KeyboardInterrupt, SystemExit))
def test_inspection_cancellation_survives_ordinary_cleanup(
    event: str, cancel: type[BaseException], monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = _InspectionHarness(monkeypatch)
    error = cancel("synthetic-cancellation")
    harness.faults[event] = error
    if event not in {"acquire", "exit"}:
        harness.faults["close" if event == "enter" else "exit"] = RuntimeError("synthetic-cleanup")
    with pytest.raises(cancel) as caught:
        harness.run()
    assert caught.value is error
    if event not in {"acquire", "enter", "exit"}:
        assert harness.exit_errors == [error]


def test_inspection_first_failure_survives_root_exit_and_later_cancel_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    harness = _InspectionHarness(monkeypatch)
    harness.faults = {
        "read-pending-1": RuntimeError("synthetic-read"),
        "K-3": RuntimeError("synthetic-root"),
        "exit": RuntimeError("synthetic-exit"),
    }
    _inspection_check(
        harness.run(), IS.PREPARATION_UNVERIFIABLE, failure=F.PENDING_READ, exit_failure=True
    )
    harness = _InspectionHarness(monkeypatch)
    harness.faults = {"read-pending-1": RuntimeError("synthetic-read"), "exit": KeyboardInterrupt()}
    with pytest.raises(KeyboardInterrupt):
        harness.run()


def _inspection_leaf(
    *,
    presence: P = P.PRESENT,
    content: C = C.SCHEMA_VALID,
    target: T = T.MATCH,
    changed: bool = False,
) -> prep.LeafObservation:
    return prep.LeafObservation(presence, content, target, changed)


def test_inspection_result_types_are_closed_frozen_and_nonauthorizing() -> None:
    leaf = _inspection_leaf(target=T.MISMATCH)
    result = prep.PreparationInspection(
        IS.PREPARATION_CONFLICT, leaf, leaf, T.MATCH, False, True, F.NONE, False
    )
    _inspection_check(result, IS.PREPARATION_CONFLICT, complete=True)
    assert result.target_relation is T.MATCH
    assert len(IS) == 11 and len(P) == 3 and len(C) == 4 and len(T) == 3 and len(F) == 14
    assert {field.name for field in fields(leaf)} == {"presence", "content", "target", "changed"}
    for value in (leaf, result):
        assert not hasattr(value, "__dict__") and "synthetic" not in repr(value)
        with pytest.raises(FrozenInstanceError):
            setattr(value, "changed" if value is leaf else "state", True)
    with pytest.raises(TypeError):
        prep.PreparationInspection(IS.UNSUPPORTED_PLATFORM, reuse_authorized=True)


@pytest.mark.parametrize(
    "case",
    (
        "unknown-content",
        "absent-target",
        "target-unread",
        "changed-absent",
        "wrong-presence",
        "wrong-content",
        "wrong-target",
        "wrong-bool",
        "poison",
    ),
)
def test_inspection_leaf_constructor_rejects_inconsistent_or_hostile_values(case: str) -> None:
    values: dict[str, object] = {
        "presence": P.PRESENT,
        "content": C.SCHEMA_VALID,
        "target": T.MATCH,
    }
    changes: dict[str, dict[str, object]] = {
        "unknown-content": {"presence": P.UNKNOWN},
        "absent-target": {"presence": P.ABSENT},
        "target-unread": {"content": C.NOT_READ},
        "changed-absent": {
            "presence": P.ABSENT,
            "content": C.NOT_READ,
            "target": T.NOT_COMPARED,
            "changed": True,
        },
        "wrong-presence": {"presence": "PRESENT"},
        "wrong-content": {"content": "SCHEMA_VALID"},
        "wrong-target": {"target": "MATCH"},
        "wrong-bool": {"changed": 1},
    }
    values.update({"presence": _Poison()} if case == "poison" else changes[case])
    with pytest.raises(ValueError):
        prep.LeafObservation(**values)


@pytest.mark.parametrize(
    "case",
    (
        "state",
        "leaf-subclass",
        "poison",
        "relation",
        "boolean",
        "complete-failure",
        "complete-changed",
        "complete-read-failure",
        "relation-absent",
        "nonpreparing-absent",
        "wrong-summary",
        "complete-exit",
    ),
)
def test_inspection_result_constructor_rejects_inconsistent_observations(case: str) -> None:
    leaf = _inspection_leaf()
    values: dict[str, object] = {
        "state": IS.PREPARATION_RETAINED_UNAPPROVED,
        "pending": leaf,
        "descriptor": leaf,
        "target_relation": T.MATCH,
        "verification_complete": True,
    }

    class LeafSubclass(prep.LeafObservation):
        pass

    cases: dict[str, dict[str, object]] = {
        "state": {"state": "PREPARATION_RETAINED_UNAPPROVED"},
        "leaf-subclass": {"pending": object.__new__(LeafSubclass)},
        "relation": {"target_relation": "MATCH"},
        "boolean": {"verification_complete": 1},
        "complete-failure": {"first_failure": F.EXIT},
        "complete-changed": {"pending": _inspection_leaf(changed=True)},
        "complete-read-failure": {
            "pending": _inspection_leaf(content=C.READ_UNVERIFIABLE, target=T.NOT_COMPARED)
        },
        "relation-absent": {"pending": prep.LeafObservation(P.ABSENT)},
        "nonpreparing-absent": {
            "descriptor": prep.LeafObservation(P.ABSENT),
            "non_preparing_observed": True,
        },
        "wrong-summary": {"state": IS.ADMIN_PENDING},
        "complete-exit": {"exit_failure_observed": True},
    }
    values.update({"pending": _Poison()} if case == "poison" else cases[case])
    with pytest.raises(ValueError):
        prep.PreparationInspection(**values)


@pytest.mark.parametrize(
    "field",
    (
        "state",
        "pending",
        "descriptor",
        "target_relation",
        "non_preparing_observed",
        "verification_complete",
        "first_failure",
        "exit_failure_observed",
    ),
)
@pytest.mark.parametrize("case", ("poison", "integer", "string"))
def test_inspection_result_exact_types_precede_input_hooks(field: str, case: str) -> None:
    values: dict[str, object] = {"state": IS.UNSUPPORTED_PLATFORM}
    values[field] = (
        _Poison() if case == "poison" else 1 if case == "integer" else "synthetic-private"
    )
    with pytest.raises(ValueError) as error:
        prep.PreparationInspection(**values)
    assert str(error.value) == "Invalid preparation inspection"


@pytest.mark.parametrize("failure", (F.NONE, F.INPUT, F.ACQUIRE, F.ENTRY, F.EXIT))
def test_inspection_postentry_result_rejects_gate_causes_and_unobserved_exit(failure: F) -> None:
    with pytest.raises(ValueError, match=r"^Invalid preparation inspection$"):
        prep.PreparationInspection(IS.PREPARATION_UNVERIFIABLE, first_failure=failure)


_INSPECTION_LOCAL_CALLS = {
    "inspect_synthetic_enrollment_preparation",
    "_linux_storage_available",
    "_valid_root",
    "_snapshot",
    "_valid_pending",
    "_canonical_pending",
    "_encode_pending",
    "_unique_object",
    "_reject_constant",
    "_PreparationFormatError",
    "_InputRefusal",
    "_Inputs",
    "LeafObservation",
    "PreparationInspection",
    "_InspectionLeaf",
    "_InspectionWork",
    "_inspection_leaf_consistent",
    "_inspection_leaf_complete",
    "_inspection_summary",
    "_inspection_lstat",
    "_inspection_signature",
    "_inspection_entry",
    "_inspection_checkpoint",
    "_inspection_read",
    "_inspection_pending",
    "_inspection_extract_descriptor",
    "_inspection_digest",
    "_inspection_descriptor",
    "_inspection_body",
}
_INSPECTION_EXTERNAL_CALLS = {
    "validate_enrollment_descriptor",
    "SyntheticEnrollmentExpectation",
    "read_private_sensitive_bytes",
    "Path",
    "type",
    "len",
    "any",
    "all",
    "isinstance",
    "ValueError",
    "super",
    "getattr",
}
_INSPECTION_EXTERNAL_ATTRIBUTES = {
    "private_lock.acquire_posix_private_directory_lock",
    "json.loads",
    "json.dumps",
    "unicodedata.category",
    "stat.S_ISREG",
    "hashlib.sha256",
}


def _inspection_reachable_calls(source: str, entry: str) -> set[str]:
    """Closed syntax regression check, not general Python alias or process analysis."""
    tree = ast.parse(source)
    definitions = {
        node.name: node for node in tree.body if isinstance(node, (ast.FunctionDef, ast.ClassDef))
    }
    assert len(definitions) == sum(
        isinstance(node, (ast.FunctionDef, ast.ClassDef)) for node in tree.body
    )
    protected = (
        _INSPECTION_LOCAL_CALLS
        | _INSPECTION_EXTERNAL_CALLS
        | {value.split(".", 1)[0] for value in _INSPECTION_EXTERNAL_ATTRIBUTES}
    )
    import_origins = {
        **{name: name for name in ("json", "unicodedata", "stat", "hashlib")},
        "Path": "pathlib.Path",
        "private_lock": "tridentine_calendar_google_sync._posix_private_lock",
        "read_private_sensitive_bytes": (
            "tridentine_calendar_google_sync.sensitive_paths.read_private_sensitive_bytes"
        ),
        **{
            name: "tridentine_calendar_google_sync.production_write_token_enrollment_descriptor."
            + name
            for name in ("SyntheticEnrollmentExpectation", "validate_enrollment_descriptor")
        },
    }

    def binding_target(target: ast.AST) -> None:
        assert not any(
            isinstance(item, ast.Name) and item.id in protected for item in ast.walk(target)
        ), "callee or namespace rebound"
        assert not any(
            isinstance(item, ast.Attribute)
            and item.attr
            in {
                "fail",
                "result",
                "observation",
                "__post_init__",
                "__enter__",
                "__exit__",
                "close",
                "revalidate",
                "lstat",
            }
            for item in ast.walk(target)
        ), "method rebound"

    for node in tree.body:
        assert isinstance(
            node,
            (ast.FunctionDef, ast.ClassDef, ast.Import, ast.ImportFrom, ast.Assign, ast.AnnAssign),
        ) or (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)), (
            "unreviewed module binding or dispatch"
        )
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            assert node.name not in protected - _INSPECTION_LOCAL_CALLS, (
                "boundary shadowed by module definition"
            )
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                assert alias.name != "*", "wildcard import"
                bound = alias.asname or alias.name.split(".", 1)[0]
                if bound in protected:
                    origin = (
                        alias.name
                        if isinstance(node, ast.Import)
                        else f"{node.module}.{alias.name}"
                    )
                    assert origin == import_origins.get(bound), "callee import substituted"
                    assert not isinstance(node, ast.ImportFrom) or node.level == 0
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            for target in node.targets if isinstance(node, ast.Assign) else [node.target]:
                binding_target(target)
    visited: set[str] = set()
    pending = [entry]

    def local(name: str) -> None:
        assert name in _INSPECTION_LOCAL_CALLS and name in definitions, "unreviewed local callee"
        pending.append(name)

    def owner_valid(function: ast.FunctionDef, receiver: str) -> bool:
        annotations = {
            arg.arg: ast.unparse(arg.annotation) if arg.annotation else ""
            for arg in function.args.args
        }
        required = {"owned": "private_lock._PrivateDirectoryLock", "work": "_InspectionWork"}[
            receiver
        ]
        origins = [
            value
            for node in ast.walk(function)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
            if isinstance(target, ast.Name) and target.id == receiver
            for value in [node.value]
        ]
        expected = (
            "private_lock.acquire_posix_private_directory_lock"
            if receiver == "owned"
            else "_InspectionWork"
        )
        return (annotations.get(receiver) == required or bool(origins)) and all(
            isinstance(value, ast.Call) and ast.unparse(value.func) == expected for value in origins
        )

    def scan(function: ast.FunctionDef, class_name: str = "") -> None:
        receiver_factories = {
            "owned": "private_lock.acquire_posix_private_directory_lock",
            "work": "_InspectionWork",
        }
        receiver_targets = {
            id(target)
            for node in ast.walk(function)
            if isinstance(node, (ast.Assign, ast.AnnAssign))
            for target in (node.targets if isinstance(node, ast.Assign) else [node.target])
            if isinstance(target, ast.Name)
            and target.id in receiver_factories
            and isinstance(node.value, ast.Call)
            and ast.unparse(node.value.func) == receiver_factories[target.id]
        }
        for node in ast.walk(function):
            assert not isinstance(
                node,
                (
                    ast.Global,
                    ast.Nonlocal,
                    ast.Lambda,
                    ast.Import,
                    ast.ImportFrom,
                    ast.AsyncFunctionDef,
                    ast.AsyncFor,
                    ast.AsyncWith,
                    ast.With,
                    ast.Match,
                    ast.TypeAlias,
                ),
            ), "dynamic local dispatch"
            assert node is function or not isinstance(node, (ast.FunctionDef, ast.ClassDef)), (
                "unreviewed local definition"
            )
            if isinstance(node, ast.arg):
                assert node.arg not in protected, "callee parameter shadowed"
                if node in (function.args.vararg, function.args.kwarg):
                    assert node.arg not in receiver_factories, "variadic receiver"
            if isinstance(node, ast.ExceptHandler):
                assert node.name not in protected | receiver_factories.keys(), (
                    "exception binding shadowed"
                )
            if isinstance(node, ast.comprehension):
                assert not node.is_async, "async comprehension"
            if isinstance(getattr(node, "ctx", None), (ast.Store, ast.Del)):
                binding_target(node)
                if isinstance(node, ast.Name) and node.id in receiver_factories:
                    assert id(node) in receiver_targets, "receiver rebound"
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)):
                value = node.value
                assert not (isinstance(value, ast.Name) and value.id in definitions), (
                    "hidden function alias"
                )
                assert not (
                    isinstance(value, ast.Attribute)
                    and ast.unparse(value) in _INSPECTION_EXTERNAL_ATTRIBUTES
                ), "hidden boundary alias"
            if not isinstance(node, ast.Call):
                continue
            for keyword in node.keywords:
                if keyword.arg in {"object_pairs_hook", "parse_constant"}:
                    assert isinstance(keyword.value, ast.Name), "dynamic JSON callback"
                    assert (
                        keyword.value.id
                        == {
                            "object_pairs_hook": "_unique_object",
                            "parse_constant": "_reject_constant",
                        }[keyword.arg]
                    )
                    local(keyword.value.id)
            if isinstance(node.func, ast.Name):
                name = node.func.id
                if name in definitions:
                    local(name)
                else:
                    assert name in _INSPECTION_EXTERNAL_CALLS, "unknown external callee"
                if name == "type":
                    assert len(node.args) == 1 and not node.keywords, "dynamic type construction"
                if name == "getattr":
                    assert function.name == "_snapshot" and len(node.args) == 2
                    assert (
                        ast.unparse(node.args[0]) == "expectation"
                        and ast.unparse(node.args[1]) == "name"
                    )
                    assert any(
                        isinstance(item, ast.comprehension)
                        and ast.unparse(item.target) == "name"
                        and ast.unparse(item.iter) == "_EXPECTATION_FIELDS"
                        for item in ast.walk(function)
                    )
            elif isinstance(node.func, ast.Attribute):
                spelling = ast.unparse(node.func)
                if spelling in _INSPECTION_EXTERNAL_ATTRIBUTES:
                    if spelling in {"json.loads", "json.dumps"}:
                        allowed_keywords = (
                            {"object_pairs_hook", "parse_constant"}
                            if spelling == "json.loads"
                            else {"sort_keys", "ensure_ascii", "separators", "allow_nan"}
                        )
                        assert all(keyword.arg in allowed_keywords for keyword in node.keywords), (
                            "unreviewed JSON callback or option"
                        )
                    continue
                if spelling in {
                    "owned.__enter__",
                    "owned.__exit__",
                    "owned.close",
                    "owned.revalidate",
                }:
                    assert owner_valid(function, "owned"), "unknown lock receiver"
                elif spelling in {"work.fail", "work.result"}:
                    assert owner_valid(function, "work"), "unknown work receiver"
                    local("_InspectionWork")
                elif spelling in {"self.pending.observation", "self.descriptor.observation"}:
                    assert class_name == "_InspectionWork"
                    local("_InspectionLeaf")
                elif spelling == "path.lstat":
                    assert function.name == "_inspection_lstat"
                elif spelling == "super().__init__":
                    assert class_name in {"_PreparationFormatError", "_InputRefusal"}
                else:
                    primitives = {
                        "_valid_root": {
                            "value.startswith",
                            "value.endswith",
                            "value.encode",
                            "value.split",
                            "part.endswith",
                        },
                        "_valid_pending": {
                            "data.keys",
                            "data.items",
                            "revision.isascii",
                            "revision[0].isalnum",
                            "char.isalnum",
                        },
                        "_snapshot": {"values.values"},
                        "_inspection_pending": {"raw.startswith", "raw.decode"},
                        "_inspection_extract_descriptor": {"raw.decode"},
                    }
                    if function.name == "_canonical_pending" and node.func.attr == "encode":
                        value = node.func.value
                        assert isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add)
                        assert (
                            isinstance(value.left, ast.Call)
                            and ast.unparse(value.left.func) == "json.dumps"
                        )
                        assert isinstance(value.right, ast.Constant) and value.right.value == "\n"
                    elif function.name == "_inspection_digest" and node.func.attr == "hexdigest":
                        assert isinstance(node.func.value, ast.Call)
                        assert ast.unparse(node.func.value.func) == "hashlib.sha256"
                    else:
                        assert spelling in primitives.get(function.name, set()), "unreviewed method"
            else:
                raise AssertionError("dynamic callee")

    while pending:
        name = pending.pop()
        if name in visited:
            continue
        visited.add(name)
        definition = definitions[name]
        if isinstance(definition, ast.FunctionDef):
            scan(definition)
        else:
            assert all(
                isinstance(base, ast.Name) and base.id == "ValueError" for base in definition.bases
            )
            for decorator in definition.decorator_list:
                assert (
                    isinstance(decorator, ast.Call) and ast.unparse(decorator.func) == "dataclass"
                )
                assert not decorator.args and all(
                    isinstance(keyword.value, ast.Constant) for keyword in decorator.keywords
                )
            for item in definition.body:
                if isinstance(item, ast.FunctionDef):
                    scan(item, name)
                elif isinstance(item, ast.AnnAssign) and isinstance(item.value, ast.Call):
                    assert isinstance(item.value.func, ast.Name) and item.value.func.id == "field"
                    for keyword in item.value.keywords:
                        if keyword.arg == "default_factory":
                            assert isinstance(keyword.value, ast.Name)
                            local(keyword.value.id)
                        else:
                            assert not any(
                                isinstance(value, ast.Call) for value in ast.walk(keyword.value)
                            )
    return visited


def test_inspection_transitive_entry_excludes_writer_and_checks_constructors() -> None:
    source = Path(inspect.getfile(prep)).read_text(encoding="utf-8")
    visited = _inspection_reachable_calls(source, "inspect_synthetic_enrollment_preparation")
    assert visited == _INSPECTION_LOCAL_CALLS
    assert not visited.intersection(_INSPECTION_FORBIDDEN)


@pytest.mark.parametrize(
    "body",
    (
        "_publish()",
        "alias = _publish\n    alias()",
        "getattr(work, 'fail')()",
        "table['writer']()",
        "private_create.create_posix_private_bytes()",
        "validate_sensitive_output_path()",
        "owned = other\n    owned.close()",
        "work = other\n    work.fail()",
        "unknown()",
        "work.result = other",
        "json = other\n    json.loads('{}')",
        "private_lock = other\n    private_lock.acquire_posix_private_directory_lock()",
        "read_private_sensitive_bytes, item = other\n    read_private_sensitive_bytes()",
    ),
)
def test_inspection_reachability_checker_rejects_synthetic_writer_dispatch(body: str) -> None:
    source = "def inspect_synthetic_enrollment_preparation():\n    " + body + "\n"
    with pytest.raises(AssertionError):
        _inspection_reachable_calls(source, "inspect_synthetic_enrollment_preparation")


@pytest.mark.parametrize(
    "body",
    (
        "json.loads(raw, object_hook=_publish)",
        "json.loads(raw, parse_float=_publish)",
        "json.dumps(raw, default=_publish)",
        "type('Injected', (), {'__len__': _publish})",
    ),
)
def test_inspection_reachability_rejects_hidden_callbacks(body: str) -> None:
    source = "def inspect_synthetic_enrollment_preparation(raw):\n    " + body + "\n"
    with pytest.raises(AssertionError):
        _inspection_reachable_calls(source, "inspect_synthetic_enrollment_preparation")


def test_inspection_reachability_follows_post_init_and_nested_helpers() -> None:
    source = """
def inspect_synthetic_enrollment_preparation():
    return PreparationInspection()
class PreparationInspection:
    def __post_init__(self):
        _inspection_summary()
def _inspection_summary():
    private_create.create_posix_private_bytes()
"""
    with pytest.raises(AssertionError):
        _inspection_reachable_calls(source, "inspect_synthetic_enrollment_preparation")


@pytest.mark.parametrize("failure", (F.NONE, F.ROOT_CHECK, F.EXIT))
def test_inspection_constructor_rejects_foreign_pending_equal_to_expected_descriptor(
    failure: F,
) -> None:
    with pytest.raises(ValueError, match=r"^Invalid preparation inspection$"):
        prep.PreparationInspection(
            IS.PREPARATION_CONFLICT,
            _inspection_leaf(target=T.MISMATCH),
            _inspection_leaf(target=T.MATCH),
            T.MATCH,
            False,
            failure is F.NONE,
            failure,
            failure is F.EXIT,
        )


def _inspection_binding_statement(form: str, shape: str) -> str:
    """Build syntax only; no synthetic writer or modified module is executed."""
    target, value = {
        "name": ("read_private_sensitive_bytes", "prepare_synthetic_enrollment"),
        "tuple": ("(item, read_private_sensitive_bytes)", "(0, prepare_synthetic_enrollment)"),
        "nested-list": (
            "[item, [read_private_sensitive_bytes]]",
            "[0, [prepare_synthetic_enrollment]]",
        ),
        "starred": ("[item, *read_private_sensitive_bytes]", "[0, prepare_synthetic_enrollment]"),
    }[shape]
    call = "read_private_sensitive_bytes(control_root, expected_raw, expectation)"
    clause = f"for {target} in [{value}]"
    return {
        "for": f"{clause}:\n    {call}",
        "list": f"[{call} {clause}]",
        "set": f"{{{call} {clause}}}",
        "dict": f"{{0: {call} {clause}}}",
        "generator": f"({call} {clause})",
    }[form]


@pytest.mark.parametrize("source_kind", ("minimal", "real-ast-copy"))
@pytest.mark.parametrize("form", ("for", "list", "set", "dict", "generator"))
@pytest.mark.parametrize("shape", ("name", "tuple", "nested-list", "starred"))
def test_inspection_reachability_rejects_loop_bound_reader(
    source_kind: str, form: str, shape: str
) -> None:
    source = (
        Path(inspect.getfile(prep)).read_text(encoding="utf-8")
        if source_kind == "real-ast-copy"
        else "def inspect_synthetic_enrollment_preparation("
        "control_root, expected_raw, expectation):"
        "\n    pass\n"
    )
    tree = ast.parse(source)
    entry = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "inspect_synthetic_enrollment_preparation"
    )
    entry.body[:0] = ast.parse(_inspection_binding_statement(form, shape)).body
    with pytest.raises(AssertionError):
        _inspection_reachable_calls(ast.unparse(tree), entry.name)


@pytest.mark.parametrize("failure", (F.NONE, F.ROOT_CHECK, F.EXIT))
@pytest.mark.parametrize(
    "pending,descriptor,relation",
    (
        (T.MATCH, T.MATCH, T.MATCH),
        (T.MISMATCH, T.MISMATCH, T.MATCH),
        (T.MISMATCH, T.MATCH, T.MISMATCH),
        (T.MATCH, T.MISMATCH, T.MATCH),
        (T.MATCH, T.MISMATCH, T.MISMATCH),
        (T.MISMATCH, T.MISMATCH, T.MISMATCH),
    ),
)
def test_inspection_constructor_preserves_representable_target_relations(
    pending: T, descriptor: T, relation: T, failure: F
) -> None:
    conflict = T.MISMATCH in (pending, descriptor, relation)
    state = (
        IS.PREPARATION_CONFLICT
        if conflict
        else IS.PREPARATION_RETAINED_UNAPPROVED
        if failure is F.NONE
        else IS.PREPARATION_UNVERIFIABLE
    )
    result = prep.PreparationInspection(
        state,
        _inspection_leaf(target=pending),
        _inspection_leaf(target=descriptor),
        relation,
        False,
        failure is F.NONE,
        failure,
        failure is F.EXIT,
    )
    assert result.pending.target is pending and result.descriptor.target is descriptor
    assert result.target_relation is relation
    assert result.verification_complete is (failure is F.NONE)
    assert result.first_failure is failure and result.reuse_authorized is False


@pytest.mark.parametrize("failure", (F.NONE, F.ROOT_CHECK, F.EXIT))
def test_inspection_constructor_still_rejects_equal_targets_with_mutual_mismatch(
    failure: F,
) -> None:
    with pytest.raises(ValueError, match=r"^Invalid preparation inspection$"):
        prep.PreparationInspection(
            IS.PREPARATION_CONFLICT,
            _inspection_leaf(),
            _inspection_leaf(),
            T.MISMATCH,
            False,
            failure is F.NONE,
            failure,
            failure is F.EXIT,
        )


@pytest.mark.parametrize(
    "body",
    (
        "read_private_sensitive_bytes = other",
        "read_private_sensitive_bytes: object = other",
        "(read_private_sensitive_bytes := other)",
        "read_private_sensitive_bytes += other",
        "del read_private_sensitive_bytes",
        "del json.loads",
        "json.loads = other",
        "json.__dict__['loads'] = other",
        "for json.loads in values:\n    pass",
        "for owned.close in values:\n    pass",
        "with marker as read_private_sensitive_bytes:\n    pass",
        "try:\n    pass\nexcept ValueError as read_private_sensitive_bytes:\n    pass",
        "import synthetic as read_private_sensitive_bytes",
        "from synthetic import writer as read_private_sensitive_bytes",
        "def read_private_sensitive_bytes():\n    pass",
        "class read_private_sensitive_bytes:\n    pass",
        "match value:\n    case read_private_sensitive_bytes:\n        pass",
        "type read_private_sensitive_bytes = object",
        "async for read_private_sensitive_bytes in values:\n    pass",
        "[item async for item in values]",
    ),
)
def test_inspection_reachability_rejects_other_binding_and_dispatch_forms(body: str) -> None:
    source = "def inspect_synthetic_enrollment_preparation():\n" + "\n".join(
        "    " + line for line in body.splitlines()
    )
    with pytest.raises(AssertionError):
        _inspection_reachable_calls(source, "inspect_synthetic_enrollment_preparation")


@pytest.mark.parametrize(
    "arguments",
    (
        "read_private_sensitive_bytes, /",
        "read_private_sensitive_bytes",
        "*, read_private_sensitive_bytes",
        "*read_private_sensitive_bytes",
        "**read_private_sensitive_bytes",
        "**json",
        "*owned",
        "**work",
    ),
)
def test_inspection_reachability_rejects_shadowing_parameters(arguments: str) -> None:
    source = f"def inspect_synthetic_enrollment_preparation({arguments}):\n    pass\n"
    with pytest.raises(AssertionError):
        _inspection_reachable_calls(source, "inspect_synthetic_enrollment_preparation")


@pytest.mark.parametrize("receiver", ("owned", "work"))
@pytest.mark.parametrize(
    "body",
    (
        "for {name} in values:\n    pass",
        "[item for {name} in values]",
        "try:\n    pass\nexcept ValueError as {name}:\n    pass",
        "del {name}",
        "({name}, item) = values",
        "({name} := other)",
    ),
)
def test_inspection_reachability_rejects_alternate_receiver_bindings(
    receiver: str, body: str
) -> None:
    annotation, method = {
        "owned": ("private_lock._PrivateDirectoryLock", "close"),
        "work": ("_InspectionWork", "result"),
    }[receiver]
    source = (
        f"def inspect_synthetic_enrollment_preparation({receiver}: {annotation}):\n"
        + "\n".join("    " + line for line in body.format(name=receiver).splitlines())
        + f"\n    {receiver}.{method}()\n"
    )
    with pytest.raises(AssertionError):
        _inspection_reachable_calls(source, "inspect_synthetic_enrollment_preparation")


@pytest.mark.parametrize(
    "prefix",
    (
        "import synthetic as json",
        "from synthetic import writer as read_private_sensitive_bytes",
        "from .sensitive_paths import read_private_sensitive_bytes",
        "from synthetic import *",
        "for read_private_sensitive_bytes in values:\n    pass",
        "class json:\n    pass",
        "def json():\n    pass",
        "class private_lock:\n    pass",
        "def read_private_sensitive_bytes():\n    pass",
        "class Path:\n    pass",
    ),
)
def test_inspection_reachability_rejects_module_binding_substitution(prefix: str) -> None:
    source = prefix + "\ndef inspect_synthetic_enrollment_preparation():\n    pass\n"
    with pytest.raises(AssertionError):
        _inspection_reachable_calls(source, "inspect_synthetic_enrollment_preparation")


@pytest.mark.parametrize(
    "namespace,method",
    (("json", "loads"), ("private_lock", "acquire_posix_private_directory_lock")),
)
def test_inspection_reachability_rejects_namespace_class_in_real_ast_copy(
    namespace: str, method: str
) -> None:
    tree = ast.parse(Path(inspect.getfile(prep)).read_text(encoding="utf-8"))
    tree.body.extend(
        ast.parse(
            f"class {namespace}:\n    def {method}(self):\n        prepare_synthetic_enrollment()\n"
        ).body
    )
    with pytest.raises(AssertionError):
        _inspection_reachable_calls(ast.unparse(tree), "inspect_synthetic_enrollment_preparation")


@pytest.mark.parametrize("form", ("for", "list", "set", "dict", "generator"))
def test_inspection_reachability_preserves_safe_local_iteration(form: str) -> None:
    body = _inspection_binding_statement(form, "nested-list").replace(
        "read_private_sensitive_bytes", "item_value"
    )
    body = body.replace("prepare_synthetic_enrollment", "0").replace(
        "item_value(control_root, expected_raw, expectation)", "item_value"
    )
    source = "def inspect_synthetic_enrollment_preparation():\n" + "\n".join(
        "    " + line for line in body.splitlines()
    )
    assert _inspection_reachable_calls(source, "inspect_synthetic_enrollment_preparation") == {
        "inspect_synthetic_enrollment_preparation"
    }


def _inspection_fixture(root: Path, contents: dict[str, bytes]) -> None:
    for leaf, raw in contents.items():
        path = root / leaf
        path.write_bytes(raw)
        path.chmod(0o600)


def _inspection_fingerprint(root: Path) -> dict[str, tuple[object, ...]]:
    result: dict[str, tuple[object, ...]] = {}
    for path in root.iterdir():
        metadata = path.lstat()
        content = path.read_bytes() if stat.S_ISREG(metadata.st_mode) else None
        result[path.name] = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_mode,
            metadata.st_uid,
            metadata.st_gid,
            metadata.st_nlink,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
            content,
        )
    return result


def _inspection_native(root: Path, monkeypatch: pytest.MonkeyPatch) -> prep.PreparationInspection:
    with monkeypatch.context() as scoped:
        calls = _inspection_forbid(scoped)
        try:
            return prep.inspect_synthetic_enrollment_preparation(str(root), RAW, _expect())
        finally:
            assert not calls


@LINUX_ONLY
@pytest.mark.parametrize(
    "case,state",
    (
        ("empty", IS.ABSENCE_UNVERIFIABLE),
        ("pending", IS.ADMIN_PENDING),
        ("descriptor", IS.ORPHAN_DESCRIPTOR),
        ("both", IS.PREPARATION_RETAINED_UNAPPROVED),
        ("foreign", IS.PREPARATION_CONFLICT),
        ("cross", IS.PREPARATION_CONFLICT),
        ("active", IS.PREPARATION_CONFLICT),
        ("revoked", IS.PREPARATION_CONFLICT),
        ("broken", IS.PREPARATION_UNVERIFIABLE),
    ),
)
def test_native_inspection_fixture_contents_identity_and_modes_remain_unchanged(
    case: str, state: IS, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private(tmp_path)
    contents = {PENDING: _pending(), DESCRIPTOR: RAW}
    if case == "empty":
        contents = {}
    elif case in {"pending", "descriptor"}:
        contents = {
            (PENDING if case == "pending" else DESCRIPTOR): (
                _pending() if case == "pending" else RAW
            )
        }
    elif case == "foreign":
        contents[PENDING], contents[DESCRIPTOR] = _inspection_foreign_pair()
    elif case == "cross":
        contents[PENDING] = _inspection_foreign_pair()[0]
    elif case in {"active", "revoked"}:
        contents[DESCRIPTOR] = RAW.replace(b"PREPARING", case.upper().encode())
    elif case == "broken":
        contents[PENDING] = b"{}\n"
    _inspection_fixture(root, contents)
    before = _inspection_fingerprint(root)
    result = _inspection_native(root, monkeypatch)
    _inspection_check(
        result,
        state,
        complete=case != "broken",
        failure=F.PENDING_SCHEMA if case == "broken" else F.NONE,
    )
    assert _inspection_fingerprint(root) == before


@LINUX_ONLY
@pytest.mark.parametrize(
    "case",
    (
        "symlink",
        "dangling",
        "directory",
        "hardlink",
        "unsafe-file",
        "oversize",
        "owner-read-only",
        "unsafe-root",
        "worktree",
    ),
)
def test_native_inspection_private_guards_preserve_artifacts(
    case: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private(tmp_path)
    target = root / PENDING
    if case in {"symlink", "dangling"}:
        destination = root / "synthetic-target"
        if case == "symlink":
            _inspection_fixture(root, {destination.name: _pending()})
        target.symlink_to(destination)
    elif case == "directory":
        target.mkdir(mode=0o700)
    else:
        _inspection_fixture(root, {PENDING: b"x" * 513 if case == "oversize" else _pending()})
        if case == "hardlink":
            os.link(target, root / "synthetic-link")
        elif case == "unsafe-file":
            target.chmod(0o644)
        elif case == "owner-read-only":
            target.chmod(0o400)
        elif case == "unsafe-root":
            root.chmod(0o755)
        elif case == "worktree":
            (root / ".git").mkdir(mode=0o700)
    before = _inspection_fingerprint(root)
    result = _inspection_native(root, monkeypatch)
    if case == "owner-read-only":
        _inspection_check(result, IS.ADMIN_PENDING, complete=True)
    else:
        assert result.state in {IS.PREPARATION_UNVERIFIABLE, IS.LOCK_UNAVAILABLE}
        assert not result.verification_complete
    assert _inspection_fingerprint(root) == before


@LINUX_ONLY
def test_native_inspection_continuous_lock_and_fault_leave_both_records(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private(tmp_path)
    _inspection_fixture(root, {PENDING: _pending(), DESCRIPTOR: RAW})
    before = _inspection_fingerprint(root)
    reader = prep.read_private_sensitive_bytes
    calls: list[str] = []

    def read(path: Path, **kwargs: Any) -> bytes:
        with pytest.raises(prep.private_lock.PosixPrivateLockError) as error:
            prep.private_lock.acquire_posix_private_directory_lock(root)
        assert error.value.code == "posix_directory_lock_busy"
        calls.append(path.name)
        if path.name == DESCRIPTOR:
            raise RuntimeError("synthetic-read")
        return reader(path, **kwargs)

    monkeypatch.setattr(prep, "read_private_sensitive_bytes", read)
    _inspection_check(
        _inspection_native(root, monkeypatch),
        IS.PREPARATION_UNVERIFIABLE,
        failure=F.DESCRIPTOR_READ,
    )
    assert calls == [PENDING, DESCRIPTOR] and _inspection_fingerprint(root) == before
    with prep.private_lock.acquire_posix_private_directory_lock(root):
        pass


@LINUX_ONLY
@pytest.mark.parametrize("both", (False, True))
def test_inspection_fresh_process_uses_independent_fixture_expectations(
    both: bool, tmp_path: Path
) -> None:
    root = _private(tmp_path)
    contents = {PENDING: _pending()}
    if both:
        contents[DESCRIPTOR] = RAW
    _inspection_fixture(root, contents)
    before = _inspection_fingerprint(root)
    environment = os.environ.copy()
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONPATH"] = str(Path(prep.__file__).resolve().parents[1])
    child = subprocess.run(
        [sys.executable, "-B", __file__, "--inspect", str(root)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
        check=False,
        env=environment,
    )
    expected = b"PREPARATION_RETAINED_UNAPPROVED\n" if both else b"ADMIN_PENDING\n"
    assert child.returncode == 0 and child.stdout == expected and not child.stderr
    assert _inspection_fingerprint(root) == before


def _inspection_observer_main() -> int:
    """The expected fixture is independent of disk; this does not resume anything."""
    try:
        if len(sys.argv) != 3 or sys.argv[1] != "--inspect":
            return 2
        with pytest.MonkeyPatch.context() as scoped:
            calls = _inspection_forbid(scoped)
            result = prep.inspect_synthetic_enrollment_preparation(sys.argv[2], RAW, _expect())
            if calls or not result.verification_complete or result.reuse_authorized is not False:
                return 2
        if result.state is IS.ADMIN_PENDING:
            print("ADMIN_PENDING")
        elif result.state is IS.PREPARATION_RETAINED_UNAPPROVED:
            print("PREPARATION_RETAINED_UNAPPROVED")
        else:
            return 2
        return 0
    except BaseException:
        return 2


if __name__ == "__main__":
    raise SystemExit(
        _inspection_observer_main()
        if len(sys.argv) > 1 and sys.argv[1] == "--inspect"
        else _observer_main()
    )
