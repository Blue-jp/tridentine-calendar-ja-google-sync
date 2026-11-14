"""Memory-only interruption checks for the actual START-record held body.

The simulated record backend establishes neither native lock ownership nor
durability. Existing conftest socket restrictions remain in force.
"""

from __future__ import annotations

import ast
import inspect
import json
import os
import socket
import sys
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from types import FrameType, ModuleType, TracebackType
from typing import Literal, Never

import pytest

from tridentine_calendar_google_sync import production_write_token as tokens
from tridentine_calendar_google_sync import production_write_token_io as token_io
from tridentine_calendar_google_sync import production_write_token_operation_record as records

_EFFECT_TARGETS: tuple[tuple[str, ModuleType, str], ...] = (
    ("credential", token_io, "load_production_write_authorized_user_token"),
    ("credential", token_io, "load_production_write_token_generation_state"),
    ("credential", token_io, "persist_refreshed_production_write_token"),
    ("credential", token_io, "write_production_write_token_bundle"),
    ("provider_entry", tokens, "authorize_production_write_token"),
    ("provider_entry", tokens, "authorize_production_write_token_mock"),
    ("provider_entry", tokens, "prepare_production_write_rehearsal_credential_session"),
    ("provider_entry", tokens, "prepare_production_write_rehearsal_credential_session_mock"),
    ("network", socket, "socket"),
    ("network", socket, "create_connection"),
    ("network", socket, "getaddrinfo"),
)


def _effect_entry(target: tuple[str, ModuleType, str]) -> str:
    return f"{target[1].__name__}.{target[2]}"


class _ExternalEffectBlocked(BaseException):
    """A fixed test-local refusal, outside ordinary Exception classification."""


class _UnexpectedDelegation(BaseException):
    """Calibration must never reach even the protective underlying probe."""


class _EffectMonitor:
    """Count and refuse only the explicit current module attributes above."""

    def __init__(self) -> None:
        self.category_counts = {"credential": 0, "provider_entry": 0, "network": 0}
        self.entry_counts = {_effect_entry(target): 0 for target in _EFFECT_TARGETS}
        self.sentinel = _ExternalEffectBlocked()
        self.restored = False

    def _block(self, category: str, entry: str) -> Callable[..., Never]:
        def blocked(*_args: object, **_kwargs: object) -> Never:
            self.category_counts[category] += 1
            self.entry_counts[entry] += 1
            raise self.sentinel

        return blocked

    @contextmanager
    def installed(self, patch: pytest.MonkeyPatch) -> Iterator[None]:
        originals = tuple(getattr(module, symbol) for _, module, symbol in _EFFECT_TARGETS)
        callbacks = tuple(
            self._block(target[0], _effect_entry(target)) for target in _EFFECT_TARGETS
        )
        try:
            with patch.context() as isolated:
                for (_, module, symbol), callback in zip(_EFFECT_TARGETS, callbacks, strict=True):
                    isolated.setattr(module, symbol, callback)
                assert all(
                    getattr(module, symbol) is callback
                    for (_, module, symbol), callback in zip(
                        _EFFECT_TARGETS, callbacks, strict=True
                    )
                )
                yield
        finally:
            self.restored = all(
                getattr(module, symbol) is original
                for (_, module, symbol), original in zip(_EFFECT_TARGETS, originals, strict=True)
            )
            assert self.restored

    def observation(self, case: str) -> dict[str, object]:
        return {
            "case": case,
            "category_counts": self.category_counts.copy(),
            "entry_counts": self.entry_counts.copy(),
            "restored": self.restored,
        }

    def assert_clear(self) -> None:
        # Inspect counts outside the public API even if it consumed a sentinel.
        assert self.restored
        assert self.category_counts == {"credential": 0, "provider_entry": 0, "network": 0}
        assert self.entry_counts == {_effect_entry(target): 0 for target in _EFFECT_TARGETS}


class _Cancellation(BaseException):
    """A synthetic cancellation that ordinary record classification must not consume."""


class _MemoryRecord:
    """One synthetic slot; counters separate fixture codec work from record effects."""

    def __init__(self, *, create: bool) -> None:
        directory = Path(
            "C:/synthetic-record-busy" if os.name == "nt" else "/synthetic-record-busy"
        )
        self.binding = records.SyntheticBinding(
            directory, "busy-store", "busy-pair", "token-label", "state-label"
        )
        self.operation = records.RecordOperation(
            "busy-operation", "prior-operation", records.OperationKind.REFRESH
        )
        self.path = directory / records.RECORD_LEAF
        self.events: Counter[str] = Counter()
        self.owner: records._RecordScopeContext | None = None
        self.active = False
        self.raw: bytes | None = None
        self.fixture_codec = 0
        if not create:
            self.raw = records._encode_start_record(self.binding, self.operation)
            self.fixture_codec = 1

    def acquire(self, path: Path) -> _MemoryLock:
        assert path == self.binding.directory and not self.active
        self.events["acquisition"] += 1
        return _MemoryLock(self)

    def lstat(self, path: Path) -> object:
        assert path == self.path and self.active
        self.events["lstat"] += 1
        if self.raw is None:
            raise FileNotFoundError("Synthetic absent record")
        return object()

    def preflight(self, path: Path, *, overwrite: bool) -> Path:
        assert path == self.path and self.active and overwrite is False
        self.events["preflight"] += 1
        return path

    def publish(self, path: Path, raw: bytes) -> None:
        assert path == self.path and self.active and self.raw is None
        self.events["publisher"] += 1
        self.raw = raw

    def read(self, path: Path, *, max_size: int) -> bytes:
        assert path == self.path and self.active and max_size == records.MAX_RECORD_BYTES
        self.events["reader"] += 1
        if self.raw is None:
            raise FileNotFoundError("Synthetic absent record")
        return self.raw


class _MemoryLock:
    def __init__(self, memory: _MemoryRecord) -> None:
        self.memory = memory

    def __enter__(self) -> _MemoryLock:
        assert not self.memory.active
        self.memory.events["entry"] += 1
        self.memory.active = True
        return self

    def revalidate(self) -> None:
        assert self.memory.active
        self.memory.events["body_checkpoint"] += 1

    def __exit__(
        self,
        _kind: type[BaseException] | None,
        _error: BaseException | None,
        _traceback: TracebackType | None,
    ) -> Literal[False]:
        assert self.memory.active
        assert self.memory.owner is not None
        assert self.memory.owner._phase is records._ScopePhase.CLOSED
        self.memory.events["exit"] += 1
        self.memory.active = False
        return False


@contextmanager
def _installed(patch: pytest.MonkeyPatch, memory: _MemoryRecord) -> Iterator[None]:
    original_scope = records._record_scope
    original_codec = records._encode_start_record
    original_acquire = records.private_lock.acquire_posix_private_directory_lock
    original_publish = records.private_create.create_posix_private_bytes
    original_read = records.read_private_sensitive_bytes
    original_preflight = records.validate_sensitive_output_path
    original_linux = records._linux_storage_available
    original_lstat = Path.lstat

    def scope(
        binding: object, operation: object, *, revision_ref: object = None
    ) -> records._RecordScopeContext:
        memory.events["factory"] += 1
        owner = original_scope(binding, operation, revision_ref=revision_ref)
        assert memory.owner is None
        memory.owner = owner
        return owner

    def codec(binding: object, operation: object) -> bytes:
        memory.events["runtime_codec"] += 1
        return original_codec(binding, operation)

    def lstat(path: Path) -> object:
        return memory.lstat(path)

    try:
        with patch.context() as isolated:
            isolated.setattr(records, "_record_scope", scope)
            isolated.setattr(records, "_encode_start_record", codec)
            isolated.setattr(records, "_linux_storage_available", lambda: True)
            isolated.setattr(
                records.private_lock, "acquire_posix_private_directory_lock", memory.acquire
            )
            isolated.setattr(records.private_create, "create_posix_private_bytes", memory.publish)
            isolated.setattr(records, "read_private_sensitive_bytes", memory.read)
            isolated.setattr(records, "validate_sensitive_output_path", memory.preflight)
            isolated.setattr(Path, "lstat", lstat)
            yield
    finally:
        assert records._record_scope is original_scope
        assert records._encode_start_record is original_codec
        assert records._linux_storage_available is original_linux
        assert records.private_lock.acquire_posix_private_directory_lock is original_acquire
        assert records.private_create.create_posix_private_bytes is original_publish
        assert records.read_private_sensitive_bytes is original_read
        assert records.validate_sensitive_output_path is original_preflight
        assert Path.lstat is original_lstat


def _busy_assignment_line() -> int:
    """Find the actual assignment in the running function, without a fixed line number."""

    lines, start = inspect.getsourcelines(records._held_record_io)
    tree = ast.parse("".join(lines))
    assignments = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Attribute)
        and isinstance(node.targets[0].value, ast.Name)
        and node.targets[0].value.id == "owner"
        and node.targets[0].attr == "_busy"
        and isinstance(node.value, ast.Constant)
        and node.value.value is True
    ]
    assert len(assignments) == 1
    return start + assignments[0].lineno - 1


class _BusyInjection:
    """Raise once in the actual held frame; ownership fields are observation-only."""

    def __init__(self, memory: _MemoryRecord, boundary: str, failure: BaseException) -> None:
        assert boundary in ("before_busy", "after_busy")
        self.memory = memory
        self.boundary = boundary
        self.failure = failure
        self.code = records._held_record_io.__code__
        self.assignment_line = _busy_assignment_line()
        self.injections = 0
        self.line: int | None = None
        self.owner: records._RecordScopeContext | None = None
        self.scope: records._HeldRecordScope | None = None
        self.busy_at_injection: bool | None = None

    def __call__(self, frame: FrameType, event: str, _argument: object) -> _BusyInjection | None:
        if frame.f_code is not self.code:
            return None
        if event != "line" or self.injections:
            return self
        # Read only the two issued references; do not copy or retain frame locals.
        owner = frame.f_locals.get("owner")
        scope = frame.f_locals.get("scope")
        if type(owner) is not records._RecordScopeContext:
            return self
        matched = (
            frame.f_lineno == self.assignment_line and owner._busy is False
            if self.boundary == "before_busy"
            else owner._busy is True
        )
        if not matched:
            return self
        assert owner is self.memory.owner
        assert owner._factory_identity is owner
        assert type(scope) is records._HeldRecordScope
        assert owner._scope is scope and scope._owner is owner
        assert owner._phase is records._ScopePhase.ACTIVE
        assert self.memory.active
        assert self.memory.events["factory"] == 1
        assert self.memory.events["acquisition"] == 1
        assert self.memory.events["entry"] == 1
        assert self.memory.events["exit"] == 0
        assert all(
            self.memory.events[name] == 0
            for name in ("body_checkpoint", "lstat", "preflight", "reader", "publisher")
        )
        self.owner = owner
        self.scope = scope
        self.line = frame.f_lineno
        self.busy_at_injection = owner._busy
        self.injections += 1
        raise self.failure


def _assert_terminal(memory: _MemoryRecord) -> None:
    owner = memory.owner
    assert owner is not None and owner._scope is not None
    assert owner._phase is records._ScopePhase.CLOSED
    assert owner._busy is False
    assert owner._held is None and owner._stack is None
    assert owner._cancellation is None
    assert not memory.active
    assert memory.events["factory"] == 1
    assert memory.events["acquisition"] == 1
    assert memory.events["entry"] == 1
    assert memory.events["exit"] == 1
    before = memory.events.copy()
    with pytest.raises(records._ScopeUseError):
        owner.__enter__()
    with pytest.raises(records._ScopeUseError):
        records._read_start_record_held(owner._scope, memory.binding, memory.operation)
    assert memory.events == before


@pytest.mark.parametrize("create", (True, False), ids=("create", "read"))
@pytest.mark.parametrize("boundary", ("before_busy", "after_busy"))
@pytest.mark.parametrize("cancel", (False, True), ids=("runtime", "cancel"))
def test_busy_transition_preserves_public_contract_and_releases_owner(
    monkeypatch: pytest.MonkeyPatch,
    create: bool,
    boundary: str,
    cancel: bool,
    record_property: Callable[[str, object], None],
) -> None:
    memory = _MemoryRecord(create=create)
    failure = (
        _Cancellation("Synthetic cancellation") if cancel else RuntimeError("Synthetic failure")
    )
    injection = _BusyInjection(memory, boundary, failure)
    effects = _EffectMonitor()
    result: records.RecordResult | None = None
    outer: BaseException | None = None
    with _installed(monkeypatch, memory):
        previous_trace = sys.gettrace()
        if previous_trace is not None:
            pytest.fail("Record busy-transition checks require an inactive trace")
        try:
            sys.settrace(injection)
            try:
                api = records.create_start_record if create else records.read_start_record
                with effects.installed(monkeypatch):
                    result = api(memory.binding, memory.operation)
            except BaseException as caught:
                outer = caught
        finally:
            sys.settrace(previous_trace)
        restored = sys.gettrace() is previous_trace
        owner = memory.owner
        observation = {
            "api": "create" if create else "read",
            "boundary": boundary,
            "kind": "cancel" if cancel else "runtime",
            "injections": injection.injections,
            "line": injection.line,
            "assignment_line": injection.assignment_line,
            "busy_at_injection": injection.busy_at_injection,
            "owner_issued": injection.owner is owner and owner is not None,
            "ordinary_classification": (
                "NONE"
                if result is None
                else (
                    "UNVERIFIABLE" if result.state is records.RecordState.UNVERIFIABLE else "OTHER"
                )
            ),
            "publication_possible": None if result is None else result.publication_possible,
            "reuse_authorized": None if result is None else result.reuse_authorized,
            "cancel_identity": outer is failure,
            "returned_result": result is not None,
            "factory": memory.events["factory"],
            "acquisition": memory.events["acquisition"],
            "entry": memory.events["entry"],
            "exit": memory.events["exit"],
            "held": memory.active,
            "scope_phase": "NOT_OBSERVED" if owner is None else owner._phase.name,
            "busy": None if owner is None else owner._busy,
            "body_checkpoints": memory.events["body_checkpoint"],
            "lstat": memory.events["lstat"],
            "preflight": memory.events["preflight"],
            "reader": memory.events["reader"],
            "publisher": memory.events["publisher"],
            "fixture_codec": memory.fixture_codec,
            "runtime_codec": memory.events["runtime_codec"],
            "trace_restored": restored,
            "external_effects": "BOUNDED_ENTRY_COUNTERS_RECORDED_SEPARATELY",
            "native_ownership_measured": False,
        }
        record_property("record_busy_observation", json.dumps(observation, sort_keys=True))
        case = f"{'create' if create else 'read'}:{boundary}:{'cancel' if cancel else 'runtime'}"
        record_property(
            "record_external_effect_observation",
            json.dumps(effects.observation(case), sort_keys=True),
        )
        effects.assert_clear()
        assert restored
        assert injection.injections == 1 and injection.line is not None
        assert injection.busy_at_injection is (boundary == "after_busy")
        assert injection.owner is owner and injection.scope is not None
        assert memory.events["runtime_codec"] == 1
        assert all(
            memory.events[name] == 0
            for name in ("body_checkpoint", "lstat", "preflight", "reader", "publisher")
        )
        if cancel:
            assert outer is failure
            assert result is None
        else:
            assert outer is None
            assert result is not None
            assert result.state is records.RecordState.UNVERIFIABLE
            assert result.publication_possible is False
            assert result.reuse_authorized is False
        _assert_terminal(memory)
        assert sys.gettrace() is previous_trace


@pytest.mark.parametrize("create", (True, False), ids=("create", "read"))
def test_normal_public_record_path_uses_codec_and_exits_before_success(
    monkeypatch: pytest.MonkeyPatch,
    create: bool,
    record_property: Callable[[str, object], None],
) -> None:
    memory = _MemoryRecord(create=create)
    with _installed(monkeypatch, memory):
        api = records.create_start_record if create else records.read_start_record
        effects = _EffectMonitor()
        try:
            with effects.installed(monkeypatch):
                result = api(memory.binding, memory.operation)
        finally:
            record_property(
                "record_external_effect_observation",
                json.dumps(
                    effects.observation("create:normal" if create else "read:normal"),
                    sort_keys=True,
                ),
            )
            effects.assert_clear()
        assert result.state is (
            records.RecordState.START_CONFIRMED if create else records.RecordState.START_OBSERVED
        )
        assert result.publication_possible is create
        assert result.reuse_authorized is False
        assert memory.raw is not None
        assert memory.events["runtime_codec"] == (3 if create else 2)
        assert memory.events["body_checkpoint"] == (3 if create else 2)
        assert memory.events["lstat"] == int(create)
        assert memory.events["preflight"] == int(create)
        assert memory.events["publisher"] == int(create)
        assert memory.events["reader"] == 1
        assert memory.fixture_codec == int(not create)
        _assert_terminal(memory)


@pytest.mark.parametrize("target", _EFFECT_TARGETS, ids=tuple(map(_effect_entry, _EFFECT_TARGETS)))
def test_each_external_effect_guard_counts_refuses_without_delegation_and_restores(
    monkeypatch: pytest.MonkeyPatch,
    target: tuple[str, ModuleType, str],
    record_property: Callable[[str, object], None],
) -> None:
    category, module, symbol = target
    key = _effect_entry(target)
    effects = _EffectMonitor()
    originals = tuple(getattr(mod, name) for _, mod, name in _EFFECT_TARGETS)
    underlying_calls = 0
    raised: BaseException | None = None

    def underlying(*_args: object, **_kwargs: object) -> Never:
        nonlocal underlying_calls
        underlying_calls += 1
        raise _UnexpectedDelegation()

    # A protective probe makes even a broken forwarding guard safe to calibrate.
    # The real product/socket implementation is never invoked by calibration.
    with monkeypatch.context() as protected:
        protected.setattr(module, symbol, underlying)
        with effects.installed(monkeypatch):
            try:
                getattr(module, symbol)()
            except BaseException as caught:
                raised = caught
        assert getattr(module, symbol) is underlying
    restored = all(
        getattr(mod, name) is original
        for (_, mod, name), original in zip(_EFFECT_TARGETS, originals, strict=True)
    )
    observation = effects.observation("calibration")
    observation.update(
        {
            "target": key,
            "sentinel_identity": raised is effects.sentinel,
            "underlying_calls": underlying_calls,
            "original_identities_restored": restored,
        }
    )
    record_property("record_external_effect_calibration", json.dumps(observation, sort_keys=True))
    assert raised is effects.sentinel
    assert underlying_calls == 0
    assert effects.category_counts == {
        name: int(name == category) for name in ("credential", "provider_entry", "network")
    }
    assert effects.entry_counts == {
        _effect_entry(candidate): int(candidate == target) for candidate in _EFFECT_TARGETS
    }
    assert effects.restored and restored
