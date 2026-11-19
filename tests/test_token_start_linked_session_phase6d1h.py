"""START-linked acceptance with isolated synthetic inputs and Linux-native cases."""

from __future__ import annotations

import copy
import os
import pickle
import socket
import subprocess
import sys
import threading
import webbrowser
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import timedelta, timezone
from pathlib import Path
from types import ModuleType, TracebackType
from typing import Literal, Never

import pytest
from phase6d0_auth_helpers import (
    ISSUED_AT,
    FakeRefresher,
    artifact_paths,
    oauth_credentials,
    production_target,
    production_token,
)

from tridentine_calendar_google_sync import production_write_token as tokens
from tridentine_calendar_google_sync import production_write_token_io as token_io
from tridentine_calendar_google_sync import production_write_token_operation_record as records
from tridentine_calendar_google_sync import production_write_token_rehearsal as rehearsal
from tridentine_calendar_google_sync.production_write_token_models import (
    PRODUCTION_WRITE_SCOPES,
    ProductionWriteAuthorizedUserToken,
    ProductionWriteCredentialSession,
    ProductionWriteGrantEvidenceOrigin,
    ProductionWriteOAuthCredentials,
    ProductionWriteTokenGenerationState,
)

NOW = ISSUED_AT + timedelta(seconds=2)
LINUX = pytest.mark.skipif(sys.platform != "linux", reason="native Linux directory ownership")
WINDOWS = pytest.mark.skipif(sys.platform != "win32", reason="native Windows preflight refusal")
_DENIED: tuple[tuple[ModuleType, str], ...] = (
    (tokens, "authorize_production_write_token"),
    (tokens, "authorize_production_write_token_mock"),
    (tokens, "prepare_production_write_rehearsal_credential_session"),
    (tokens, "prepare_production_write_rehearsal_credential_session_mock"),
    (tokens, "load_desktop_client_config"),
    (tokens, "_production_write_session_lock"),
    (socket, "socket"),
    (socket, "create_connection"),
    (socket, "getaddrinfo"),
    (webbrowser, "open"),
    (webbrowser, "open_new"),
    (webbrowser, "open_new_tab"),
)


class _Cancel(BaseException):
    pass


class _Denied(BaseException):
    pass


class _Effects:
    def __init__(self) -> None:
        self.calls: Counter[str] = Counter()

    def forbid(self, name: str) -> Callable[..., Never]:
        def blocked(*_args: object, **_kwargs: object) -> Never:
            self.calls[name] += 1
            raise _Denied("Unexpected synthetic test effect")

        return blocked

    @contextmanager
    def installed(self, patch: pytest.MonkeyPatch) -> Iterator[None]:
        originals = [(module, name, getattr(module, name)) for module, name in _DENIED]
        with patch.context() as local:
            for module, name, _ in originals:
                local.setattr(module, name, self.forbid(f"{module.__name__}.{name}"))
            yield
        for module, name, original in originals:
            assert getattr(module, name) is original


def test_forbidden_effect_monitor_calibrates_every_entry_and_restores(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    effects = _Effects()
    delegated: list[str] = []

    def tripwire(*_args: object, **_kwargs: object) -> None:
        delegated.append("called")

    with monkeypatch.context() as local:
        for module, name in _DENIED:
            local.setattr(module, name, tripwire)
        with effects.installed(local):
            for module, name in _DENIED:
                with pytest.raises(_Denied):
                    getattr(module, name)()
        assert all(getattr(module, name) is tripwire for module, name in _DENIED)
    assert delegated == []
    assert effects.calls == Counter({f"{module.__name__}.{name}": 1 for module, name in _DENIED})


class _Refresher(FakeRefresher):
    def __init__(self, trial: _Trial) -> None:
        super().__init__(
            oauth_credentials(
                expiry=NOW + timedelta(hours=1),
                evidence_origin=ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
                evidence_observed_at=NOW,
            )
        )
        self.trial = trial

    def refresh(
        self, token: ProductionWriteAuthorizedUserToken, scopes: tuple[str, ...]
    ) -> ProductionWriteOAuthCredentials:
        assert token == self.trial.old_token and scopes == PRODUCTION_WRITE_SCOPES
        self.trial.effect("refresh")
        return super().refresh(token, scopes)


class _Trial:
    def __init__(self, *, expired: bool = False, directory: Path | None = None) -> None:
        if directory is None:
            directory = Path(
                "C:/synthetic-linked-session" if os.name == "nt" else "/synthetic-linked-session"
            )
        self.directory = directory
        self.paths = artifact_paths(directory)
        self.target = production_target()
        self.confirmation = rehearsal.production_write_token_rehearsal_challenge(self.target)
        self.state = tokens.build_initial_production_write_token_generation_state(
            self.target, issued_at=ISSUED_AT
        )
        self.old_token = production_token(
            self.state, expiry=ISSUED_AT + (timedelta(seconds=1) if expired else timedelta(hours=1))
        )
        self.token = self.old_token
        self.binding = records.SyntheticBinding(
            directory,
            "linked-store",
            "linked-pair",
            self.paths["write"].name,
            self.paths["generation"].name,
        )
        self.operation = records.RecordOperation(
            "linked-refresh-attempt", "independent-predecessor", records.OperationKind.REFRESH
        )
        self.refresher = _Refresher(self)
        self.events: list[str] = []
        self.calls: Counter[str] = Counter()
        self.faults: dict[str, BaseException] = {}
        self.active = False
        self.raw: bytes | None = None
        self.corrupt_readback = False
        self.changed_token = False
        self.contexts: list[tokens._StartLinkedSessionContext] = []
        self.effects = _Effects()
        self.exit_triples: list[records._LinkedTriple] = []
        self.published = 0

    def event(self, key: str) -> None:
        self.events.append(key)
        self.calls[key] += 1
        if key in self.faults:
            raise self.faults[key]

    def effect(self, key: str) -> None:
        assert self.active
        self.event(key)

    def _acquire(self, directory: Path) -> _MemoryLock:
        assert directory == self.directory and not self.active
        self.event("acquire")
        return _MemoryLock(self)

    def _publish(self, path: Path, data: bytes) -> None:
        assert path == self.directory / records.RECORD_LEAF and self.raw is None
        self.effect("publish")
        self.raw = data

    def _read_record(self, path: Path, *, max_size: int) -> bytes:
        assert path == self.directory / records.RECORD_LEAF
        assert max_size == records.MAX_RECORD_BYTES and self.raw is not None
        self.effect("read_record")
        return b"{}" if self.corrupt_readback else self.raw

    def _read_state(self, path: str | Path) -> ProductionWriteTokenGenerationState:
        assert path == self.paths["generation"] and self.raw is not None
        self.effect("read_state")
        if self.calls["read_state"] == 2:
            self.effect("reread_state")
        return self.state

    def _read_token(self, path: str | Path) -> ProductionWriteAuthorizedUserToken:
        assert path == self.paths["write"] and self.raw is not None
        self.effect("read_token")
        if self.calls["read_token"] == 2:
            self.effect("reread_token")
            if self.changed_token:
                return self.token.model_copy(
                    update={"expiry": self.token.expiry + timedelta(seconds=1)}
                )
        return self.token

    def _save(
        self,
        token: ProductionWriteAuthorizedUserToken,
        path: str | Path,
        *,
        expected_token: ProductionWriteAuthorizedUserToken,
    ) -> Path:
        assert path == self.paths["write"] and expected_token is self.old_token
        self.effect("writer")
        self.token = token
        self.published += 1
        return self.paths["write"]

    def _path_set(
        self,
        *,
        production_write_token_path: str | Path,
        generation_state_path: str | Path,
        production_read_token_path: str | Path,
        test_write_token_path: str | Path,
        client_config_path: str | Path | None,
        write_token_exists: bool,
        generation_state_exists: bool,
    ) -> tuple[Path, Path, Path, Path, None]:
        assert not self.active and client_config_path is None
        assert write_token_exists and generation_state_exists
        self.event("path_set")
        return (
            Path(production_write_token_path),
            Path(generation_state_path),
            Path(production_read_token_path),
            Path(test_write_token_path),
            None,
        )

    @contextmanager
    def installed(self, patch: pytest.MonkeyPatch) -> Iterator[pytest.MonkeyPatch]:
        original_context = tokens._start_linked_session_context
        original_construct = tokens.ProductionWriteCredentialSession
        original_lstat = Path.lstat

        def factory(*args: object, **kwargs: object) -> tokens._StartLinkedSessionContext:
            context = original_context(*args, **kwargs)
            self.contexts.append(context)
            self.event("sealed")
            return context

        def lstat(path: Path) -> os.stat_result:
            if path != self.directory / records.RECORD_LEAF:
                return original_lstat(path)
            self.effect("lstat")
            if self.raw is None:
                raise FileNotFoundError("Synthetic absent START")
            return os.stat_result((0,) * 10)

        def record_preflight(path: Path, *, overwrite: bool) -> Path:
            assert path == self.directory / records.RECORD_LEAF and not overwrite
            self.effect("record_preflight")
            return path

        def constructor(
            *,
            token: ProductionWriteAuthorizedUserToken,
            generation_state: ProductionWriteTokenGenerationState,
            refresh_count: Literal[0, 1],
        ) -> ProductionWriteCredentialSession:
            self.effect("constructor")
            return original_construct(
                token=token, generation_state=generation_state, refresh_count=refresh_count
            )

        with patch.context() as local, self.effects.installed(local):
            local.setattr(tokens, "_start_linked_session_context", factory)
            local.setattr(tokens, "ProductionWriteCredentialSession", constructor)
            local.setattr(records, "_linux_storage_available", lambda: True)
            local.setattr(
                records.private_lock, "acquire_posix_private_directory_lock", self._acquire
            )
            local.setattr(records.private_create, "create_posix_private_bytes", self._publish)
            local.setattr(records, "read_private_sensitive_bytes", self._read_record)
            local.setattr(records, "validate_sensitive_output_path", record_preflight)
            local.setattr(Path, "lstat", lstat)
            local.setattr(token_io, "validate_production_write_token_path_set", self._path_set)
            local.setattr(
                token_io, "load_production_write_token_generation_state", self._read_state
            )
            local.setattr(token_io, "load_production_write_authorized_user_token", self._read_token)
            local.setattr(token_io, "persist_refreshed_production_write_token", self._save)
            yield local
        assert not self.effects.calls

    def prepare(self, **overrides: object) -> ProductionWriteCredentialSession:
        kwargs = dict(
            now=NOW, refresher=self.refresher, binding=self.binding, operation=self.operation
        )
        kwargs.update(overrides)
        return tokens._prepare_start_linked_session_mock(
            str(self.paths["write"]),
            str(self.paths["generation"]),
            self.paths["read"],
            self.paths["test"],
            self.target,
            self.confirmation,
            **kwargs,
        )

    def context(self) -> tokens._StartLinkedSessionContext:
        return tokens._start_linked_session_context(
            self.paths["write"],
            self.paths["generation"],
            self.paths["read"],
            self.paths["test"],
            self.target,
            self.confirmation,
            now=NOW,
            refresher=self.refresher,
            binding=self.binding,
            operation=self.operation,
        )

    def snapshot(self) -> records._LinkedDiagnosticsSnapshot:
        association = self.contexts[-1]._association
        assert association is not None
        snapshot = records._read_linked_diagnostics(
            association.parent,
            association.request,
            expected_parent=association.parent,
            expected=association.expected,
        )
        state = association.attempt_state
        assert (
            state.primary,
            state.first_cancel,
            state.session_body_triple,
            state.phase_exit_triple,
            state.record_exit_triple,
            state.writer_error,
            state.writer_diagnostic,
        ) == (None,) * 7
        return snapshot


class _MemoryLock:
    def __init__(self, trial: _Trial) -> None:
        self.trial = trial

    def __enter__(self) -> _MemoryLock:
        self.trial.event("entry")
        assert not self.trial.active
        self.trial.active = True
        return self

    def revalidate(self) -> None:
        self.trial.effect("checkpoint")
        number = self.trial.calls["checkpoint"]
        if f"checkpoint_{number}" in self.trial.faults:
            raise self.trial.faults[f"checkpoint_{number}"]

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        tb: TracebackType | None,
    ) -> Literal[False]:
        assert self.trial.active
        self.trial.active = False
        self.trial.exit_triples.append((kind, error, tb))
        self.trial.event("exit")
        return False


@pytest.mark.parametrize("expired", [False, True], ids=["unexpired", "expired"])
def test_normal_retains_start_and_returns_only_after_exit(
    monkeypatch: pytest.MonkeyPatch, expired: bool
) -> None:
    trial = _Trial(expired=expired)
    with trial.installed(monkeypatch):
        result = trial.prepare()
        trial.event("returned")
        snapshot = trial.snapshot()
        assert trial.events[:4] == ["path_set", "sealed", "acquire", "entry"]
        assert trial.events[-4:] == ["constructor", "checkpoint", "exit", "returned"]
        assert trial.events.index("read_record") < trial.events.index("read_state")
        assert trial.calls["acquire"] == trial.calls["entry"] == trial.calls["exit"] == 1
        assert trial.calls["publish"] == trial.calls["read_record"] == 1
        assert trial.calls["checkpoint"] == (9 if expired else 6)
        assert trial.calls["read_state"] == trial.calls["read_token"] == (2 if expired else 1)
        assert trial.calls["refresh"] == trial.calls["writer"] == trial.published == int(expired)
        assert result.refresh_count == int(expired) and result.token is trial.token
        assert snapshot.record_observation is records._HeldCheckpoint.HELD_START_CHECKPOINT
        assert snapshot.record_publication is True
        assert snapshot.credential_publication is expired
        assert (
            snapshot.delivery == "return_path_selected" and snapshot.diagnostic_status == "complete"
        )
        assert trial.exit_triples == [(None, None, None)]
        raw = trial.raw
        assert raw is not None and records._matches_start_record(
            raw, trial.binding, trial.operation
        )
        assert trial.operation.kind is records.OperationKind.REFRESH
        with pytest.raises(records._ScopeFailure) as occupied:
            trial.prepare()
        assert occupied.value.result.state is records.RecordState.SLOT_OCCUPIED
        assert trial.raw == raw and trial.calls["publish"] == 1 and trial.calls["returned"] == 1
        assert trial.calls["acquire"] == trial.calls["exit"] == 2
        assert trial.calls["read_state"] == (2 if expired else 1)


@pytest.mark.parametrize(
    "case",
    [
        "target",
        "confirmation",
        "utc",
        "path_set",
        "directory",
        "storage",
        "pair",
        "swap",
        "record_collision",
        "new_pair",
        "same_predecessor",
        "missing_predecessor",
        "unsafe_refresher",
    ],
)
def test_preflight_rejects_before_start(monkeypatch: pytest.MonkeyPatch, case: str) -> None:
    trial = _Trial()
    overrides: dict[str, object] = {}
    if case == "target":
        trial.target = None
    elif case == "confirmation":
        trial.confirmation += " "
    elif case == "utc":
        overrides["now"] = NOW.astimezone(timezone(timedelta(hours=1)))
    elif case == "path_set":
        trial.faults["path_set"] = ValueError("synthetic path refusal")
    elif case == "directory":
        trial.binding = replace(trial.binding, directory=trial.directory / "other")
    elif case == "storage":
        trial.binding = replace(trial.binding, storage_ref="")
    elif case == "pair":
        trial.binding = replace(trial.binding, pair_ref="")
    elif case == "swap":
        trial.binding = replace(
            trial.binding, token_slot=trial.binding.state_slot, state_slot=trial.binding.token_slot
        )
    elif case == "record_collision":
        trial.binding = replace(trial.binding, token_slot=records.RECORD_LEAF)
    elif case == "new_pair":
        trial.operation = replace(
            trial.operation, kind=records.OperationKind.NEW_PAIR, predecessor_id=None
        )
    elif case == "same_predecessor":
        trial.operation = replace(trial.operation, predecessor_id=trial.operation.operation_id)
    elif case == "missing_predecessor":
        trial.operation = replace(trial.operation, predecessor_id=None)
    else:
        trial.refresher.live_capable = True
    with trial.installed(monkeypatch), pytest.raises(ValueError):
        trial.prepare(**overrides)
    assert trial.calls == (
        Counter() if case in {"target", "confirmation", "utc"} else Counter(path_set=1)
    )
    assert trial.raw is None and not trial.contexts


@WINDOWS
def test_real_windows_gate_precedes_preflight_and_standalone_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    trial = _Trial()
    effects = trial.effects
    with effects.installed(monkeypatch):
        monkeypatch.setattr(
            token_io, "validate_production_write_token_path_set", effects.forbid("path_set")
        )
        monkeypatch.setattr(records, "_record_scope", effects.forbid("record_factory"))
        with pytest.raises(records._ScopeFailure) as refused:
            trial.prepare()
        assert refused.value.result.state is records.RecordState.UNSUPPORTED_PLATFORM
        assert (
            records.create_start_record(trial.binding, trial.operation).state
            is records.RecordState.UNSUPPORTED_PLATFORM
        )
    assert not effects.calls


@pytest.mark.parametrize(
    "case,publication",
    [
        ("occupied", False),
        ("publish", None),
        ("readback", True),
        ("checkpoint_3", True),
        ("forged_result", False),
        ("after_latch", True),
        ("owner_mismatch", True),
    ],
)
def test_start_failure_never_reaches_credential_reads(
    monkeypatch: pytest.MonkeyPatch, case: str, publication: bool | None
) -> None:
    trial = _Trial()
    failure = RuntimeError("synthetic START boundary fault")
    if case == "occupied":
        trial.raw = records._encode_start_record(trial.binding, trial.operation)
    elif case in {"publish", "checkpoint_3"}:
        trial.faults[case] = failure
    elif case == "readback":
        trial.corrupt_readback = True
    original_create = records._create_start_record_held

    def forged(*args: object, **kwargs: object) -> records._HeldResult:
        if case != "forged_result":
            result = original_create(*args, **kwargs)
            if case == "after_latch":
                raise failure
            association = trial.contexts[-1]._association
            assert association is not None
            association.parent._record._scope = None
            return result
        return records._HeldResult(checkpoint=records._HeldCheckpoint.HELD_START_CHECKPOINT)

    with trial.installed(monkeypatch) as local:
        if case in {"forged_result", "after_latch", "owner_mismatch"}:
            local.setattr(records, "_create_start_record_held", forged)
        with pytest.raises(
            (records._ScopeFailure, records._ScopeUseError, RuntimeError)
        ) as refused:
            trial.prepare()
        if case == "after_latch":
            assert refused.value is failure
        assert trial.snapshot().record_publication is publication
    assert trial.calls["exit"] == 1 and not trial.active
    assert not any(
        trial.calls[key] for key in ("read_state", "read_token", "refresh", "writer", "constructor")
    )
    if publication is True:
        assert trial.raw is not None


@pytest.mark.parametrize(
    "field",
    [
        "directory",
        "storage_ref",
        "pair_ref",
        "token_slot",
        "state_slot",
        "operation_id",
        "predecessor_id",
        "kind",
        "token_path",
        "state_path",
        "swapped_paths",
    ],
)
def test_exact_parent_checks_independent_field_without_consuming(
    monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    trial = _Trial()
    original_issue = tokens._issue_start_linked_session_owner

    def issue(context, child):
        a = context._association
        assert a is not None
        expected = a.expected
        binding, operation = expected.binding, expected.operation
        if field == "directory":
            other = trial.directory / "other"
            bad = replace(
                expected,
                binding=replace(binding, directory=other),
                checked_token_path=other / binding.token_slot,
                checked_state_path=other / binding.state_slot,
            )
        elif field in {"storage_ref", "pair_ref"}:
            bad = replace(expected, binding=replace(binding, **{field: "different"}))
        elif field == "token_slot":
            bad = replace(
                expected,
                binding=replace(binding, token_slot="other-token"),
                checked_token_path=trial.directory / "other-token",
            )
        elif field == "state_slot":
            bad = replace(
                expected,
                binding=replace(binding, state_slot="other-state"),
                checked_state_path=trial.directory / "other-state",
            )
        elif field in {"operation_id", "predecessor_id"}:
            bad = replace(expected, operation=replace(operation, **{field: "different"}))
        elif field == "kind":
            bad = replace(
                expected, operation=replace(operation, kind=records.OperationKind.NEW_PAIR)
            )
        elif field == "token_path":
            bad = replace(expected, checked_token_path=trial.directory / "other-token")
        elif field == "state_path":
            bad = replace(expected, checked_state_path=trial.directory / "other-state")
        else:
            bad = replace(
                expected,
                checked_token_path=expected.checked_state_path,
                checked_state_path=expected.checked_token_path,
            )
        with pytest.raises(records._ScopeUseError):
            records._require_linked_child(child, a.request, expected_parent=a.parent, expected=bad)
        assert a.parent._current_child is child and child._active
        assert a.parent._phase is records._LinkedPhase.SESSION_RUNNING
        assert context._owner is None and not context._used and trial.active
        assert trial.calls["exit"] == 0
        return original_issue(context, child)

    with trial.installed(monkeypatch) as local:
        local.setattr(tokens, "_issue_start_linked_session_owner", issue)
        assert trial.prepare().refresh_count == 0
        assert trial.snapshot().delivery == "return_path_selected"
    assert trial.calls["exit"] == 1


@pytest.mark.parametrize("case", ["equal_metadata", "foreign_directory"])
def test_genuine_foreign_child_is_refused_before_owner_issuance(monkeypatch, case):
    trial = _Trial()
    other = _Trial(
        directory=trial.directory if case == "equal_metadata" else trial.directory / "other"
    )
    original_issue = tokens._issue_start_linked_session_owner

    def issue(context, child):
        a = context._association
        assert a is not None
        other_expected = records._LinkedExpected(
            other.binding, other.operation, other.paths["write"], other.paths["generation"]
        )
        with other.installed(monkeypatch):
            foreign = records._shared_start_session_scope(
                other.binding,
                other.operation,
                a.request,
                token_path=other.paths["write"],
                state_path=other.paths["generation"],
            )
            with pytest.raises(_Cancel), foreign:
                records._create_linked_start(
                    foreign, a.request, expected_parent=foreign, expected=other_expected
                )
                with records._linked_session_phase(
                    foreign, a.request, expected_parent=foreign, expected=other_expected
                ) as foreign_child:
                    assert (a.expected == other_expected) is (case == "equal_metadata")
                    with pytest.raises(tokens._CredentialSessionUseError):
                        original_issue(context, foreign_child)
                    assert context._owner is None and not context._used
                    assert trial.active and other.active and trial.calls["exit"] == 0
                    assert a.parent._current_child is child and child._active
                    raise _Cancel()
        return original_issue(context, child)

    with trial.installed(monkeypatch) as local:
        local.setattr(tokens, "_issue_start_linked_session_owner", issue)
        trial.prepare()
    assert trial.calls["exit"] == other.calls["exit"] == 1


def test_misuse_does_not_revoke_valid_actor_and_closed_child_cannot_resume(monkeypatch):
    trial = _Trial()
    held = tokens._load_production_write_credential_session_held
    retained = []

    def probe(owner, request):
        context, child = owner._issuer, owner._child
        a = context._association
        assert a is not None
        parent = a.parent
        kwargs = {"expected_parent": parent, "expected": a.expected}
        retained.extend((owner, request, child, parent, kwargs))
        with pytest.raises(tokens._CredentialSessionUseError):
            tokens._seal_start_linked_parent(context, request, parent, a.expected, a.attempt_state)
        for make in (copy.copy, copy.deepcopy, pickle.dumps):
            for item in (parent, child, owner, request, context, a):
                with pytest.raises((records._ScopeUseError, tokens._CredentialSessionUseError)):
                    make(item)
        for cls in (
            tokens._StartLinkedSessionOwner,
            tokens._StartLinkedSessionRequest,
            tokens._StartLinkedSessionContext,
            records._LinkedSessionChild,
            records._SharedStartSessionContext,
        ):
            with pytest.raises((records._ScopeUseError, tokens._CredentialSessionUseError)):
                cls()
        for forged in (object(), object.__new__(tokens._StartLinkedSessionOwner)):
            with pytest.raises(tokens._CredentialSessionUseError):
                held(forged, request)
        with pytest.raises(tokens._CredentialSessionUseError):
            held(owner, object.__new__(tokens._StartLinkedSessionRequest))
        with pytest.raises(records._ScopeUseError):
            records._require_linked_child(
                object.__new__(records._LinkedSessionChild), request, **kwargs
            )
        fake_child = object.__new__(records._LinkedSessionChild)
        fake_child._factory_identity, fake_child._parent, fake_child._active = (
            fake_child,
            parent,
            True,
        )
        with pytest.raises(records._ScopeUseError):
            records._require_linked_child(fake_child, request, **kwargs)
        with pytest.raises(records._ScopeUseError):
            parent.__enter__()
        with pytest.raises(records._ScopeUseError):
            parent.__exit__(None, None, None)
        with pytest.raises(records._ScopeUseError):
            parent._record.__exit__(None, None, None)
        with pytest.raises(records._ScopeUseError):
            records._read_start_record_held(parent._record._scope, trial.binding, trial.operation)
        with (
            pytest.raises(records._ScopeUseError),
            records._linked_session_phase(parent, request, **kwargs),
        ):
            pytest.fail("Session phase reentered")

        with monkeypatch.context() as actor:
            actor.setattr(tokens, "getpid", lambda: context._pid + 1)
            with pytest.raises(tokens._CredentialSessionUseError):
                held(owner, request)
        with monkeypatch.context() as actor:
            actor.setattr(parent._record, "_pid", os.getpid() + 1)
            with pytest.raises(records._ScopeUseError):
                records._require_linked_child(child, request, **kwargs)
        foreign_errors = []

        def use_from_thread():
            for use in (lambda: held(owner, request), lambda: parent.__exit__(None, None, None)):
                try:
                    use()
                except (records._ScopeUseError, tokens._CredentialSessionUseError) as refused:
                    foreign_errors.append(type(refused))

        thread = threading.Thread(target=use_from_thread)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive() and len(foreign_errors) == 2
        assert trial.active and child._active and not context._used and trial.calls["exit"] == 0
        result = held(owner, request)
        with pytest.raises(tokens._CredentialSessionUseError):
            held(owner, request)
        assert context._phase is tokens._CredentialSessionPhase.USED
        assert trial.calls["read_state"] == trial.calls["read_token"] == 1 and trial.active
        return result

    original_final = records._final_linked_checkpoint

    def final(parent, request, **kwargs):
        assert parent._phase is records._LinkedPhase.CONSUMED
        assert trial.active
        with pytest.raises(records._ScopeUseError):
            records._require_linked_child(parent._current_child, request, **kwargs)
        return original_final(parent, request, **kwargs)

    with trial.installed(monkeypatch) as local:
        local.setattr(tokens, "_load_production_write_credential_session_held", probe)
        local.setattr(records, "_final_linked_checkpoint", final)
        trial.prepare()
        owner, request, child, parent, kwargs = retained
        with pytest.raises(records._ScopeUseError):
            records._require_linked_child(child, request, **kwargs)
        with pytest.raises(tokens._CredentialSessionUseError):
            held(owner, request)
        assert parent._phase is records._LinkedPhase.CLOSED
        assert trial.snapshot().delivery == "return_path_selected"
    assert trial.calls["exit"] == 1


def test_legacy_held_read_does_not_issue_shared_child(monkeypatch):
    trial = _Trial()
    with trial.installed(monkeypatch):
        with records._record_scope(trial.binding, trial.operation) as owner:
            assert (
                records._create_start_record_held(owner, trial.binding, trial.operation).checkpoint
                is records._HeldCheckpoint.HELD_START_CHECKPOINT
            )
            assert (
                records._read_start_record_held(owner, trial.binding, trial.operation).checkpoint
                is records._HeldCheckpoint.HELD_START_OBSERVED
            )
        context = trial.context()
        a = context._association
        assert a is not None
        parent = a.parent
        kwargs = {"expected_parent": parent, "expected": a.expected}
        with pytest.raises(_Cancel), parent:
            with pytest.raises(records._ScopeUseError):
                records._issue_linked_child(parent, a.request, **kwargs)
            with (
                pytest.raises(records._ScopeUseError),
                records._linked_session_phase(parent, a.request, **kwargs),
            ):
                pytest.fail("Read observation issued a child")
            assert trial.active and parent._phase is records._LinkedPhase.RECORD_HELD
            raise _Cancel()
    assert trial.calls["exit"] == 2 and trial.calls["read_state"] == 0


@pytest.mark.parametrize(
    "boundary,domain,kind,refreshes,writes,constructed",
    [
        ("read_state", "session", "session_other", 0, 0, False),
        ("read_token", "session", "session_other", 0, 0, False),
        ("validation", "session", "session_other", 0, 0, False),
        ("refresh", "session", "refresh", 1, 0, False),
        ("prewrite", "session", "prewrite", 1, 0, False),
        ("checkpoint_4", "session", "lock", 0, 0, False),
        ("writer", "session", "persistence", 1, 1, False),
        ("checkpoint_9", "final_checkpoint", None, 1, 1, True),
        ("phase_exit", "phase_exit", None, 1, 1, True),
        ("exit", "exit", None, 1, 1, True),
    ],
)
def test_failure_boundaries_preserve_primary_and_withhold_candidate(
    monkeypatch, boundary, domain, kind, refreshes, writes, constructed
):
    trial = _Trial(expired=True)
    failure = RuntimeError("Synthetic boundary fault")
    held_errors = []
    actual_held = tokens._load_production_write_credential_session_held
    actual_phase = records._linked_session_phase

    def hold(*args):
        try:
            return actual_held(*args)
        except BaseException as error:
            held_errors.append(error)
            raise

    @contextmanager
    def phase(*args, **kwargs):
        with actual_phase(*args, **kwargs) as child:
            yield child
        raise failure

    with trial.installed(monkeypatch) as local:
        local.setattr(tokens, "_load_production_write_credential_session_held", hold)
        if boundary == "phase_exit":
            local.setattr(records, "_linked_session_phase", phase)
        elif boundary == "prewrite":
            trial.changed_token = True
        elif boundary == "validation":
            trial.token = trial.old_token.model_copy(update={"scopes": ()})
        else:
            trial.faults[boundary] = failure
        with pytest.raises((ValueError, RuntimeError)) as refused:
            trial.prepare()
        snapshot = trial.snapshot()
        if kind:
            assert refused.value is held_errors[0]
            assert snapshot.session_failure == kind
        if boundary in {"read_state", "read_token", "phase_exit", "exit"}:
            assert refused.value is failure
        if boundary == "checkpoint_9":
            assert type(refused.value) is records._LinkedCheckpointFailure
        assert snapshot.first_ordinary_domain == domain
        assert snapshot.record_publication is True and snapshot.delivery == "withheld"
        assert snapshot.candidate_constructed is constructed
        assert snapshot.credential_publication is (None if boundary == "writer" else bool(writes))
        assert snapshot.cleanup_failure == ("ordinary" if boundary == "exit" else None)
        assert snapshot.phase_exit_failure == ("ordinary" if boundary == "phase_exit" else None)
        assert snapshot.selected_outcome == "failure"
    assert trial.calls["refresh"] == refreshes and trial.calls["writer"] == writes
    assert trial.calls["exit"] == 1 and not trial.active and trial.raw is not None


@pytest.mark.parametrize("boundary", ["acquire", "entry"])
def test_failed_entry_does_not_finalize_an_unentered_backend(monkeypatch, boundary):
    trial = _Trial()
    trial.faults[boundary] = RuntimeError("Synthetic entry failure")
    with trial.installed(monkeypatch), pytest.raises(records._ScopeFailure) as refused:
        trial.prepare()
    assert refused.value.result.state is records.RecordState.UNVERIFIABLE
    assert trial.snapshot().record_publication is False
    assert trial.calls["exit"] == trial.calls["read_state"] == trial.calls["publish"] == 0


@pytest.mark.parametrize(
    "case,writer_phase,publication,cancel_phase,step,kind",
    [
        ("initial", "raised", True, None, "initial", "session_other"),
        ("classification", "raised", True, None, "classification", "session_other"),
        ("refinement", "raised", True, None, "refinement", "persistence"),
        ("pre_writer", "not_called", False, None, "pre_writer", "persistence"),
        ("writer_raised", "raised", True, None, "writer_raised", "persistence"),
        ("writer_raised_false", "raised", False, None, "writer_raised", "persistence"),
        ("writer_raised_unknown", "raised", None, None, "writer_raised", "persistence"),
        ("writer_returned", "returned", True, None, "writer_returned", "persistence"),
        ("p_then_cancel", "raised", True, "annotation", "initial", "session_other"),
        ("w_then_cancel", "raised", True, "annotation", "writer_raised", None),
        ("pre_writer_cancel", "not_called", False, "annotation", "pre_writer", None),
        ("writer_returned_cancel", "returned", True, "annotation", "writer_returned", None),
        ("cancel_then_ordinary", "raised", None, "writer", "writer_raised", None),
        ("cancel_then_cancel", "raised", None, "writer", "writer_raised", None),
        ("snapshot_after_p", "raised", True, None, "snapshot", "persistence"),
        ("snapshot_after_success", "returned", True, None, "snapshot", None),
        ("snapshot_cancel_after_p", "raised", True, "snapshot", "snapshot", "persistence"),
        ("snapshot_cancel_after_cancel", "raised", None, "writer", "snapshot", None),
    ],
)
def test_diagnostic_fault_matrix(
    monkeypatch, case, writer_phase, publication, cancel_phase, step, kind
):
    trial = _Trial(expired=True)
    ordinary = RuntimeError("Synthetic ordinary diagnostic fault")
    first_cancel, later_cancel = _Cancel("first"), _Cancel("later")
    evidence = False if case.endswith("_false") else None if case.endswith("_unknown") else True
    writer_failure = token_io.ProductionWriteTokenIOError(
        "synthetic_writer",
        "Synthetic writer fault",
        publication_possible=evidence,
    )
    if case.startswith("cancel_then") or case == "snapshot_cancel_after_cancel":
        trial.faults["writer"] = first_cancel
    elif writer_phase == "raised":
        trial.faults["writer"] = writer_failure
    old_copy = records._copy_linked_failure_annotations
    old_publication = records._copy_linked_publication_annotations
    old_persist = tokens._persist_linked
    old_held = tokens._load_production_write_credential_session_held
    adapter_errors, held_errors = [], []

    def copy_failure(*args, classification=None, **kwargs):
        if case == "initial" or (case == "refinement" and classification is not None):
            raise ordinary
        if case == "p_then_cancel":
            raise first_cancel
        old_copy(*args, classification=classification, **kwargs)

    def copy_publication(parent, *args, **kwargs):
        current = parent._attempt.facts.writer_phase
        if current == writer_phase and step in {"pre_writer", "writer_raised", "writer_returned"}:
            if case == "cancel_then_cancel":
                raise later_cancel
            if case in {"w_then_cancel", "pre_writer_cancel", "writer_returned_cancel"}:
                raise first_cancel
            raise ordinary
        old_publication(parent, *args, **kwargs)

    def classify(_error):
        raise ordinary

    def snapshot(_facts, _notes):
        if case.startswith("snapshot_cancel"):
            raise later_cancel if case.endswith("_cancel") else first_cancel
        raise ordinary

    def persist(*args, **kwargs):
        try:
            return old_persist(*args, **kwargs)
        except BaseException as error:
            adapter_errors.append(error)
            raise

    def hold(*args):
        try:
            return old_held(*args)
        except BaseException as error:
            held_errors.append(error)
            raise

    with trial.installed(monkeypatch) as local:
        local.setattr(records, "_copy_linked_failure_annotations", copy_failure)
        local.setattr(records, "_copy_linked_publication_annotations", copy_publication)
        local.setattr(tokens, "_persist_linked", persist)
        local.setattr(tokens, "_load_production_write_credential_session_held", hold)
        if case == "classification":
            local.setattr(tokens, "_classify_linked_session_failure", classify)
        if step == "snapshot":
            local.setattr(records, "_build_linked_diagnostics", snapshot)
        with pytest.raises(
            (tokens.ProductionWriteTokenRefreshPersistenceError, _Cancel, RuntimeError)
        ) as refused:
            trial.prepare()
        result = trial.snapshot()
        assert result.diagnostic_status == "incomplete" and result.first_diagnostic_step == step
        assert result.record_publication is True and result.credential_publication is publication
        assert result.logical_save_called and result.writer_phase == writer_phase
        assert result.session_failure == kind and result.delivery == "withheld"
        assert result.first_cancel_phase == cancel_phase
        assert result.candidate_constructed is (case == "snapshot_after_success")
        assert result.selected_outcome == ("cancellation" if cancel_phase else "failure")
        if cancel_phase:
            assert refused.value is first_cancel
        elif case == "snapshot_after_success":
            assert refused.value is ordinary
        else:
            assert refused.value is held_errors[0]
            assert refused.value.persistence_attempted
            assert refused.value.publication_possible is publication
        if writer_phase == "raised" and not cancel_phase:
            assert adapter_errors == [writer_failure]
        if writer_phase == "raised":
            assert result.writer_failure_kind == (
                "cancellation" if trial.faults["writer"] is first_cancel else "ordinary"
            )
        if step == "snapshot":
            assert result.annotations.publication is None
    assert trial.calls["writer"] == (writer_phase != "not_called")
    assert trial.published == (writer_phase == "returned")
    assert trial.calls["refresh"] == trial.calls["exit"] == 1 and not trial.active
    assert trial.raw is not None


@pytest.mark.parametrize(
    "first,cleanup",
    [
        ("ordinary", "ordinary"),
        ("ordinary", "cancel"),
        ("cancel", "ordinary"),
        ("cancel", "cancel"),
        ("healthy", "cancel"),
    ],
)
def test_backend_receives_original_triple_and_cancellation_precedes_cleanup(
    monkeypatch, first, cleanup
):
    trial = _Trial()
    original = _Cancel("first") if first == "cancel" else RuntimeError("first")
    closing = _Cancel("cleanup") if cleanup == "cancel" else RuntimeError("cleanup")
    if first != "healthy":
        trial.faults["read_state"] = original
    trial.faults["exit"] = closing
    expected = original if first == "cancel" or cleanup == "ordinary" else closing
    with trial.installed(monkeypatch), pytest.raises(type(expected)) as refused:
        trial.prepare()
    assert refused.value is expected
    triple = trial.exit_triples[0]
    if first == "healthy":
        assert triple == (None, None, None)
    else:
        assert triple[0] is type(original) and triple[1] is original and triple[2] is not None
    snapshot = trial.snapshot()
    assert snapshot.cleanup_failure == ("cancellation" if cleanup == "cancel" else "ordinary")
    assert snapshot.first_cancel_phase == (
        "session" if first == "cancel" else "exit" if cleanup == "cancel" else None
    )
    assert snapshot.session_failure == ("session_other" if first == "ordinary" else None)
    assert snapshot.record_publication is True and snapshot.credential_publication is False
    assert snapshot.delivery == "withheld" and trial.calls["exit"] == 1
    assert trial.calls["refresh"] == trial.calls["writer"] == 0 and trial.raw is not None


def test_real_preflight_order_precedes_parent_factory(monkeypatch):
    trial = _Trial()
    check_target = tokens.validate_production_write_target_config
    check_confirmation = rehearsal.verify_production_write_token_rehearsal_confirmation
    create_parent = records._shared_start_session_scope

    def target(value):
        if not trial.active:
            trial.event("target")
        check_target(value)

    def confirmation(value, exact):
        trial.event("confirmation")
        check_confirmation(value, exact)

    def platform():
        if not trial.active:
            trial.event("platform")
        return True

    def parent(*args, **kwargs):
        trial.event("parent_factory")
        return create_parent(*args, **kwargs)

    with trial.installed(monkeypatch) as local:
        local.setattr(tokens, "validate_production_write_target_config", target)
        local.setattr(
            rehearsal, "verify_production_write_token_rehearsal_confirmation", confirmation
        )
        local.setattr(records, "_linux_storage_available", platform)
        local.setattr(records, "_shared_start_session_scope", parent)
        trial.prepare()
    assert trial.events[:9] == [
        "target",
        "confirmation",
        "platform",
        "path_set",
        "parent_factory",
        "sealed",
        "platform",
        "acquire",
        "entry",
    ]


@pytest.mark.parametrize("boundary", ["shared_initialization", "issued_child"])
def test_interruption_unwinds_a_real_entered_scope_once(monkeypatch, boundary):
    trial = _Trial()
    cancel = _Cancel("Synthetic interruption")
    require_record = records._require_linked_record
    issue_child = records._issue_linked_child
    issued = []

    def initialize(parent, *args, **kwargs):
        record = require_record(parent, *args, **kwargs)
        assert record._stack is not None and trial.active
        raise cancel

    def issue(*args, **kwargs):
        child = issue_child(*args, **kwargs)
        assert child._active and trial.active
        issued.append(child)
        raise cancel

    with trial.installed(monkeypatch) as local:
        if boundary == "shared_initialization":
            local.setattr(records, "_require_linked_record", initialize)
        else:
            local.setattr(records, "_issue_linked_child", issue)
        with pytest.raises(_Cancel) as refused:
            trial.prepare()
        assert refused.value is cancel
        snapshot = trial.snapshot()
    assert snapshot.selected_outcome == "cancellation" and snapshot.delivery == "withheld"
    assert snapshot.record_publication is (boundary == "issued_child")
    assert trial.calls["entry"] == trial.calls["exit"] == 1
    assert trial.calls["read_state"] == trial.calls["writer"] == 0 and not trial.active
    assert trial.exit_triples[0][1] is cancel
    if boundary == "issued_child":
        assert len(issued) == 1 and not issued[0]._active


@pytest.mark.parametrize(
    "first,phase_fault",
    [
        ("persistence", "ordinary"),
        ("persistence", "cancellation"),
        ("cancellation", "ordinary"),
        ("cancellation", "cancellation"),
    ],
)
def test_phase_exit_failure_retains_prior_session_and_original_backend_triple(
    monkeypatch, first, phase_fault
):
    trial = _Trial(expired=True)
    primary_cancel = _Cancel("Synthetic body cancellation")
    closing = (
        _Cancel("Synthetic phase cancellation")
        if phase_fault == "cancellation"
        else RuntimeError("Synthetic phase fault")
    )
    writer = token_io.ProductionWriteTokenIOError(
        "synthetic_writer", "Synthetic writer fault", publication_possible=True
    )
    trial.faults["writer"] = primary_cancel if first == "cancellation" else writer
    old_phase = records._linked_session_phase
    old_hold = tokens._load_production_write_credential_session_held
    observed = []

    @contextmanager
    def phase(*args, **kwargs):
        try:
            with old_phase(*args, **kwargs) as child:
                yield child
        finally:
            raise closing

    def hold(*args):
        try:
            return old_hold(*args)
        except BaseException as error:
            observed.append(error)
            raise

    with trial.installed(monkeypatch) as local:
        local.setattr(records, "_linked_session_phase", phase)
        local.setattr(tokens, "_load_production_write_credential_session_held", hold)
        with pytest.raises(
            (tokens.ProductionWriteTokenRefreshPersistenceError, _Cancel)
        ) as refused:
            trial.prepare()
        snapshot = trial.snapshot()
    assert refused.value is (
        primary_cancel
        if first == "cancellation"
        else closing
        if phase_fault == "cancellation"
        else observed[0]
    )
    assert trial.exit_triples[0][1] is closing
    assert snapshot.phase_exit_failure == phase_fault and snapshot.cleanup_failure is None
    assert snapshot.session_failure == ("persistence" if first == "persistence" else None)
    assert snapshot.record_publication is True
    assert snapshot.credential_publication is (True if first == "persistence" else None)
    assert snapshot.first_cancel_phase == (
        "writer"
        if first == "cancellation"
        else "phase_exit"
        if phase_fault == "cancellation"
        else None
    )
    assert snapshot.delivery == "withheld" and not snapshot.candidate_constructed
    assert trial.calls["refresh"] == trial.calls["writer"] == trial.calls["exit"] == 1


def _child_lock_probe(directory: Path, *, busy: bool) -> None:
    script = """\
import sys
from pathlib import Path
from tridentine_calendar_google_sync import production_write_token_operation_record as records
try:
    with records.private_lock.acquire_posix_private_directory_lock(Path(sys.argv[1])):
        outcome = "acquired"
except records.private_lock.PosixPrivateLockError as error:
    outcome = "busy" if error.code == "posix_directory_lock_busy" else "unavailable"
except BaseException:
    outcome = "error"
raise SystemExit(0 if outcome == sys.argv[2] else 1)
"""
    try:
        result = subprocess.run(
            [sys.executable, "-B", "-c", script, str(directory), "busy" if busy else "acquired"],
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pytest.fail("Synthetic competitor failed or timed out", pytrace=False)
    assert (result.returncode, result.stdout, result.stderr) == (0, b"", b"")


@LINUX
@pytest.mark.parametrize("end", ["success", "writer_fault", "cancel"])
def test_native_lock_excludes_competitor_until_exit_and_retains_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, end: str
) -> None:
    directory = tmp_path / "private-linked"
    directory.mkdir(mode=0o700)
    trial = _Trial(expired=True, directory=directory)
    token_io.write_production_write_token_bundle(
        trial.old_token,
        trial.paths["write"],
        trial.state,
        trial.paths["generation"],
    )
    acquire = records.private_lock.acquire_posix_private_directory_lock
    load_state = token_io.load_production_write_token_generation_state
    persist = token_io.persist_refreshed_production_write_token
    cancel = _Cancel("Synthetic native cancellation")
    writer_fault = token_io.ProductionWriteTokenIOError(
        "synthetic_native_double", "Synthetic native writer fault", publication_possible=False
    )

    @contextmanager
    def counted_acquire(path):
        trial.event("acquire")
        assert path == directory
        with acquire(path) as held:
            trial.active = True
            trial.event("entry")
            try:
                yield held
            finally:
                trial.active = False
        trial.event("normal_backend_exit")

    def verify_competitor():
        with pytest.raises(records.private_lock.PosixPrivateLockError) as refused:
            acquire(directory)
        assert refused.value.code == "posix_directory_lock_busy"
        trial.event("competitor_refused")

    def read_state(path):
        assert trial.active
        if trial.calls["competitor_refused"] == 0:
            raw = records.read_private_sensitive_bytes(
                directory / records.RECORD_LEAF, max_size=records.MAX_RECORD_BYTES
            )
            assert records._matches_start_record(raw, trial.binding, trial.operation)
            _child_lock_probe(directory, busy=True)
        verify_competitor()
        if end == "cancel":
            raise cancel
        return load_state(path)

    def writer(token, path, *, expected_token):
        trial.effect("writer")
        verify_competitor()
        if end == "writer_fault":
            raise writer_fault
        return persist(token, path, expected_token=expected_token)

    with monkeypatch.context() as local, trial.effects.installed(local):
        local.setattr(records.private_lock, "acquire_posix_private_directory_lock", counted_acquire)
        local.setattr(token_io, "load_production_write_token_generation_state", read_state)
        local.setattr(token_io, "persist_refreshed_production_write_token", writer)
        if end == "success":
            result = trial.prepare()
            assert result.refresh_count == 1 and trial.calls["normal_backend_exit"] == 1
            trial.event("returned")
        elif end == "writer_fault":
            with pytest.raises(tokens.ProductionWriteTokenRefreshPersistenceError) as refused:
                trial.prepare()
            assert refused.value.publication_possible is False
        else:
            with pytest.raises(_Cancel) as refused:
                trial.prepare()
            assert refused.value is cancel
    assert not trial.effects.calls and not trial.active
    assert trial.calls["acquire"] == trial.calls["entry"] == 1
    assert trial.calls["competitor_refused"] == (1 if end == "cancel" else 3)
    assert trial.calls["writer"] == trial.refresher.calls == (end != "cancel")
    _child_lock_probe(directory, busy=False)
    with acquire(directory) as held:
        held.revalidate()
    after = token_io.load_production_write_authorized_user_token(trial.paths["write"])
    assert (after != trial.old_token) is (end == "success")
    assert (
        records.read_start_record(trial.binding, trial.operation).state
        is records.RecordState.START_OBSERVED
    )
    assert (
        records.create_start_record(trial.binding, trial.operation).state
        is records.RecordState.SLOT_OCCUPIED
    )


@contextmanager
def _actor_phase(trial: _Trial):
    context = trial.context()
    association = context._association
    assert association is not None
    parent, request = association.parent, association.request
    expected = {"expected_parent": parent, "expected": association.expected}
    with parent:
        records._create_linked_start(parent, request, **expected)
        yield context, association, records._linked_session_phase(parent, request, **expected)


def _finish_actor_phase(context, association, manager, child):
    parent, request = association.parent, association.request
    expected = {"expected_parent": parent, "expected": association.expected}
    owner = tokens._issue_start_linked_session_owner(context, child)
    candidate = tokens._load_production_write_credential_session_held(owner, request)
    association.attempt_state.facts.candidate_constructed = True
    records._note_linked_candidate(parent, request, **expected)
    assert manager.__exit__(None, None, None) is False
    assert parent._phase is records._LinkedPhase.CONSUMED and not child._active
    records._final_linked_checkpoint(parent, request, **expected)
    return candidate


def _foreign_phase_call(monkeypatch, parent, actor, call):
    outcomes = []

    def invoke():
        try:
            call()
        except BaseException as error:
            outcomes.append(type(error))
        else:
            outcomes.append(None)

    if actor == "thread":
        worker = threading.Thread(target=invoke, daemon=True)
        worker.start()
        worker.join(timeout=5)
        assert not worker.is_alive(), "Synthetic foreign actor did not finish"
    else:
        with monkeypatch.context() as wrong_pid:
            wrong_pid.setattr(parent._record, "_pid", os.getpid() + 1)
            invoke()
    assert len(outcomes) == 1
    return outcomes[0]


def _phase_actor_state(trial, context, association, child):
    parent, state = association.parent, association.attempt_state
    record = parent._record
    return (
        parent._phase,
        parent._current_child is child,
        child._active if child is not None else None,
        parent._issuing,
        context._phase,
        context._owner,
        context._busy,
        context._used,
        parent._candidate_noted,
        parent._final_checked,
        record._busy,
        record._create_attempted,
        record._creation_publication,
        state.primary,
        state.first_cancel,
        state.phase_exit_triple,
        state.facts.record_publication,
        state.facts.credential_publication,
        state.facts.first_ordinary_domain,
        state.facts.first_cancel_phase,
        state.facts.candidate_constructed,
        trial.active,
        trial.raw,
        trial.published,
    )


def _actor_exit_triple(kind) -> records._LinkedTriple:
    if kind == "normal":
        return None, None, None
    error = RuntimeError("Synthetic foreign phase failure") if kind == "ordinary" else _Cancel()
    try:
        raise error
    except (RuntimeError, _Cancel) as caught:
        return type(caught), caught, caught.__traceback__


@pytest.mark.parametrize("actor", ["thread", "pid"])
@pytest.mark.parametrize("triple", ["normal", "ordinary", "cancel"])
def test_phase_actor_foreign_exit_preserves_the_same_manager(monkeypatch, actor, triple):
    trial = _Trial()
    rejected_triple = _actor_exit_triple(triple)
    abort = _Cancel("Synthetic RED cleanup")
    candidate = None
    observation = ""
    try:
        with trial.installed(monkeypatch), _actor_phase(trial) as (context, association, manager):
            parent = association.parent
            child = manager.__enter__()
            before = _phase_actor_state(trial, context, association, child)
            calls = trial.calls.copy()
            refusal = _foreign_phase_call(
                monkeypatch, parent, actor, lambda: manager.__exit__(*rejected_triple)
            )
            after = _phase_actor_state(trial, context, association, child)
            state = association.attempt_state
            added_effects = (trial.calls - calls).total()
            added_exits = trial.calls["exit"] - calls["exit"]
            publication_same = before[12] == after[12] and before[16:18] == after[16:18]
            observation = (
                f"PHASE_ACTOR_RED exit actor={actor} triple={triple} "
                f"refusal={'none' if refusal is None else refusal.__name__} "
                f"phase={parent._phase.name} child_same={parent._current_child is child} "
                f"child_active={child._active} issuing={parent._issuing} "
                f"primary={state.primary is not None} cancel={state.first_cancel is not None} "
                f"publication_same={publication_same} effects={added_effects} exits={added_exits}"
            )
            if refusal is not records._ScopeUseError or before != after or trial.calls != calls:
                if parent._phase is records._LinkedPhase.SESSION_RUNNING:
                    manager.__exit__(type(abort), abort, None)
                raise abort
            candidate = _finish_actor_phase(context, association, manager, child)
    except _Cancel as error:
        assert error is abort or error is rejected_triple[1]
    assert trial.calls["exit"] == 1 and not trial.active and not trial.effects.calls
    if candidate is None:
        pytest.fail(observation + f" owner_exit={trial.calls['exit']}", pytrace=False)
    assert candidate.refresh_count == 0
    assert trial.calls["publish"] == trial.calls["read_record"] == 1
    assert trial.calls["read_state"] == trial.calls["read_token"] == 1
    assert trial.calls["refresh"] == trial.calls["writer"] == 0
    assert trial.snapshot().delivery == "return_path_selected"


@pytest.mark.parametrize("actor", ["thread", "pid"])
def test_phase_actor_foreign_entry_leaves_same_manager_usable(monkeypatch, actor):
    trial = _Trial()
    abort = _Cancel("Synthetic RED cleanup")
    candidate = None
    observation = ""
    try:
        with trial.installed(monkeypatch), _actor_phase(trial) as (context, association, manager):
            parent = association.parent
            before = _phase_actor_state(trial, context, association, None)
            calls = trial.calls.copy()
            refusal = _foreign_phase_call(monkeypatch, parent, actor, manager.__enter__)
            after = _phase_actor_state(trial, context, association, None)
            observation = (
                f"PHASE_ACTOR_RED entry actor={actor} "
                f"refusal={'none' if refusal is None else refusal.__name__} "
                f"phase={parent._phase.name} state_same={before == after} "
                f"effects={(trial.calls - calls).total()} "
                f"exits={trial.calls['exit'] - calls['exit']}"
            )
            if refusal is not records._ScopeUseError or before != after or trial.calls != calls:
                if parent._phase is records._LinkedPhase.SESSION_RUNNING:
                    manager.__exit__(type(abort), abort, None)
                raise abort
            try:
                child = manager.__enter__()
            except (AttributeError, records._ScopeUseError) as error:
                observation += f" owner_retry={type(error).__name__}"
                raise abort from error
            candidate = _finish_actor_phase(context, association, manager, child)
    except _Cancel as error:
        assert error is abort
    assert trial.calls["exit"] == 1 and not trial.active and not trial.effects.calls
    if candidate is None:
        pytest.fail(observation + f" owner_exit={trial.calls['exit']}", pytrace=False)
    assert candidate.refresh_count == 0
    assert trial.calls["read_state"] == trial.calls["read_token"] == 1
    assert trial.calls["refresh"] == trial.calls["writer"] == 0
    assert trial.snapshot().delivery == "return_path_selected"


def test_phase_manager_cannot_be_duplicated_reentered_or_reused(monkeypatch):
    trial = _Trial()
    with trial.installed(monkeypatch), _actor_phase(trial) as (context, association, manager):
        before = _phase_actor_state(trial, context, association, None)
        calls = trial.calls.copy()
        for duplicate in (copy.copy, copy.deepcopy, pickle.dumps):
            with pytest.raises(records._ScopeUseError):
                duplicate(manager)
        with pytest.raises(records._ScopeUseError):
            type(manager)()
        partial = object.__new__(type(manager))
        with pytest.raises(records._ScopeUseError):
            partial.__enter__()
        with pytest.raises(records._ScopeUseError):
            partial.__exit__(None, None, None)
        with pytest.raises(records._ScopeUseError):
            manager.__exit__(None, None, None)
        assert _phase_actor_state(trial, context, association, None) == before
        assert trial.calls == calls

        child = manager.__enter__()
        before = _phase_actor_state(trial, context, association, child)
        calls = trial.calls.copy()
        with pytest.raises(records._ScopeUseError):
            manager.__enter__()
        assert _phase_actor_state(trial, context, association, child) == before
        assert trial.calls == calls
        candidate = _finish_actor_phase(context, association, manager, child)

        before = _phase_actor_state(trial, context, association, child)
        calls = trial.calls.copy()
        with pytest.raises(records._ScopeUseError):
            manager.__exit__(None, None, None)
        with pytest.raises(records._ScopeUseError):
            manager.__enter__()
        assert _phase_actor_state(trial, context, association, child) == before
        assert trial.calls == calls and trial.calls["exit"] == 0
    with pytest.raises(records._ScopeUseError):
        manager.__exit__(None, None, None)
    with pytest.raises(records._ScopeUseError):
        manager.__enter__()
    assert candidate.refresh_count == 0
    assert trial.calls["exit"] == 1 and not trial.active
    assert trial.snapshot().delivery == "return_path_selected"


@pytest.mark.parametrize("kind", ["ordinary", "cancel"])
def test_phase_manager_owner_failure_retains_identity_until_parent_exit(monkeypatch, kind):
    trial = _Trial()
    failure = RuntimeError("Synthetic held failure") if kind == "ordinary" else _Cancel()
    trial.faults["read_state"] = failure
    with (
        trial.installed(monkeypatch),
        pytest.raises(type(failure)) as escaped,
        _actor_phase(trial) as (context, association, manager),
    ):
        try:
            with manager as child:
                owner = tokens._issue_start_linked_session_owner(context, child)
                tokens._load_production_write_credential_session_held(owner, association.request)
        except (RuntimeError, _Cancel) as error:
            parent, state = association.parent, association.attempt_state
            assert error is failure
            assert parent._phase is records._LinkedPhase.FAILED
            assert parent._current_child is child and not child._active and not parent._issuing
            assert state.phase_exit_triple is not None and state.phase_exit_triple[1] is failure
            retained = state.primary if kind == "ordinary" else state.first_cancel
            assert retained is failure
            assert trial.active and trial.calls["exit"] == 0
            raise
    assert escaped.value is failure
    assert trial.exit_triples[0][:2] == (type(failure), failure)
    snapshot = trial.snapshot()
    assert snapshot.delivery == "withheld"
    assert snapshot.selected_outcome == ("failure" if kind == "ordinary" else "cancellation")
    assert snapshot.record_publication is True and snapshot.credential_publication is False
    assert trial.calls["read_state"] == trial.calls["exit"] == 1 and not trial.active
    assert trial.calls["read_token"] == trial.calls["refresh"] == trial.calls["writer"] == 0


class _PhaseHandoffInjection:
    def __init__(self, trial, point, failure):
        self.trial = trial
        self.point = point
        self.failure = failure
        operation = "__exit__" if point == "exit" else "__enter__"
        self.code = getattr(records._LinkedSessionPhaseContext, operation).__code__
        self.manager = None
        self.hits = 0
        self.calls = Counter()
        self.initial_primary = None
        self.initial_cancel = None
        self.incoming = None

    def __call__(self, frame, event, _arg):
        if frame.f_code is not self.code:
            return None
        if event != "line" or self.hits:
            return self
        manager = frame.f_locals["self"]
        parent = manager._parent
        child = parent._current_child
        if self.point == "exit":
            at_handoff = (
                manager._lifecycle == "exiting"
                and parent._phase is records._LinkedPhase.SESSION_RUNNING
                and parent._issuing
                and child is manager._child
                and child is not None
                and child._active
            )
        elif self.point == "entry":
            at_handoff = (
                manager._lifecycle == "entering"
                and parent._phase is records._LinkedPhase.SESSION_RUNNING
                and parent._issuing
                and child is not None
                and child is frame.f_locals.get("child")
                and child._active
                and manager._child is None
            )
        else:
            at_handoff = (
                manager._lifecycle == "entering"
                and parent._phase is records._LinkedPhase.START_READY
                and not parent._issuing
                and child is None
            )
        if at_handoff:
            assert parent._record._thread is threading.current_thread()
            assert parent._record._pid == os.getpid()
            self.hits += 1
            self.manager = manager
            self.calls = self.trial.calls.copy()
            self.initial_primary = parent._attempt.primary
            self.initial_cancel = parent._attempt.first_cancel
            self.incoming = frame.f_locals.get("exc")
            raise self.failure
        return self


def _exercise_phase_handoff(monkeypatch, trial, injection):
    previous = sys.gettrace()
    assert previous is None, "Existing tracer is incompatible with this one-shot trace"
    caught = result = None
    with trial.installed(monkeypatch):
        try:
            sys.settrace(injection)
            try:
                result = trial.prepare()
            except BaseException as error:
                caught = error
        finally:
            sys.settrace(previous)
        assert sys.gettrace() is previous
        assert injection.hits == 1, "Expected phase handoff was not injected"
        manager = injection.manager
        assert manager is not None
        parent = manager._parent
        child = parent._current_child
        production_exits = trial.calls["exit"]
        added = trial.calls - injection.calls
        added.pop("exit", None)
        observed = {
            "caught": caught,
            "returned": result is not None,
            "phase": parent._phase,
            "issuing": parent._issuing,
            "child_active": child is not None and child._active,
            "issued": child is not None,
            "lifecycle": manager._lifecycle,
            "active": trial.active,
            "exits": production_exits,
            "added": added.total(),
        }
        if trial.active:
            # Clean up the test double only after freezing the product observation.
            failure = injection.failure
            original = (type(failure), failure, failure.__traceback__)
            body = getattr(manager, "_body", None)
            if body is not None and parent._issuing:
                body.__exit__(*original)
                parent.__exit__(*original)
            else:
                stack = parent._record._stack
                assert stack is not None
                stack.__exit__(*original)
        observed["harness_exits"] = trial.calls["exit"] - production_exits
        assert not trial.active
    return observed


def _assert_phase_handoff(trial, injection, observed, expected):
    if not (
        observed["caught"] is expected
        and not observed["returned"]
        and observed["phase"] is records._LinkedPhase.CLOSED
        and not observed["issuing"]
        and not observed["child_active"]
        and observed["issued"] is (injection.point != "before_entry")
        and observed["lifecycle"] == "closed"
        and not observed["active"]
        and observed["exits"] == 1
        and observed["harness_exits"] == 0
        and observed["added"] == 0
    ):
        error = observed["caught"]
        pytest.fail(
            f"PHASE_HANDOFF_RED point={injection.point} "
            f"injected={type(injection.failure).__name__} caught={type(error).__name__} "
            f"same={error is expected} manager={observed['lifecycle']} "
            f"phase={observed['phase'].name} issuing={observed['issuing']} "
            f"child_active={observed['child_active']} held={observed['active']} "
            f"backend_exit={observed['exits']} extra_effects={observed['added']} "
            f"harness_exit={observed['harness_exits']}",
            pytrace=False,
        )
    manager = injection.manager
    with pytest.raises(records._ScopeUseError):
        manager.__enter__()
    with pytest.raises(records._ScopeUseError):
        manager.__exit__(None, None, None)
    assert trial.raw is not None and records._matches_start_record(
        trial.raw, trial.binding, trial.operation
    )
    assert trial.calls["publish"] == trial.calls["read_record"] == 1
    assert trial.exit_triples[0][1] is injection.failure
    return trial.snapshot()


@pytest.mark.parametrize("point", ["before_entry", "entry", "exit"])
@pytest.mark.parametrize("kind", ["ordinary", "cancel"])
def test_accepted_phase_handoff_interruption(monkeypatch, point, kind):
    trial = _Trial(expired=True)
    error = RuntimeError("Synthetic handoff interruption") if kind == "ordinary" else _Cancel()
    injection = _PhaseHandoffInjection(trial, point, error)
    observed = _exercise_phase_handoff(monkeypatch, trial, injection)
    expected_effects = (2, 2, 1, 1) if point == "exit" else (0, 0, 0, 0)
    assert tuple(injection.calls[k] for k in ("read_state", "read_token", "refresh", "writer")) == (
        expected_effects
    )
    snapshot = _assert_phase_handoff(trial, injection, observed, error)
    assert injection.incoming is None
    assert snapshot.delivery == "withheld" and snapshot.record_publication is True
    assert snapshot.credential_publication is (point == "exit")
    assert snapshot.candidate_constructed is (point == "exit")
    assert trial.published == (point == "exit")
    assert snapshot.selected_outcome == ("cancellation" if kind == "cancel" else "failure")


@pytest.mark.parametrize("prior", ["persistence", "cancel"])
@pytest.mark.parametrize("during_exit", ["ordinary", "cancel"])
def test_accepted_phase_exit_interruption_preserves_first_failure(monkeypatch, prior, during_exit):
    trial = _Trial(expired=True)
    original_cancel = _Cancel("Synthetic first cancellation")
    if prior == "cancel":
        trial.faults["read_state"] = original_cancel
    else:
        trial.faults["writer"] = token_io.ProductionWriteTokenIOError(
            "synthetic_handoff_writer", "Synthetic writer failure", publication_possible=True
        )
    interruption = (
        _Cancel("Synthetic exit cancellation")
        if during_exit == "cancel"
        else (RuntimeError("Synthetic exit interruption"))
    )
    injection = _PhaseHandoffInjection(trial, "exit", interruption)
    observed = _exercise_phase_handoff(monkeypatch, trial, injection)
    if prior == "cancel":
        first = original_cancel
        assert injection.initial_cancel is first
        expected = first
    else:
        first = injection.initial_primary
        assert type(first) is tokens.ProductionWriteTokenRefreshPersistenceError
        expected = interruption if during_exit == "cancel" else first
    assert injection.incoming is first
    snapshot = _assert_phase_handoff(trial, injection, observed, expected)
    assert snapshot.phase_exit_failure == (
        "cancellation" if during_exit == "cancel" else "ordinary"
    )
    assert snapshot.cleanup_failure is None
    assert snapshot.delivery == "withheld" and not snapshot.candidate_constructed
    assert snapshot.record_publication is True
    assert snapshot.credential_publication is (prior == "persistence")
    assert snapshot.session_failure == ("persistence" if prior == "persistence" else None)
    assert trial.published == 0
    assert trial.calls["writer"] == trial.calls["refresh"] == (prior == "persistence")
