"""Test-owned START ordering and later refusal; no production session enforcement.

Real Linux record I/O ends before the separately authorized memory credential
experiment. The unlocked gap and fake credential lock are intentional limits.
Normal return does not retire START. The child exercises ordinary process-local
reconstruction, not crash durability, deployment restart or reconciliation.
"""

from __future__ import annotations

import json
import os
import socket
import stat
import subprocess
import sys
import webbrowser
from collections.abc import Callable, Iterator
from dataclasses import replace
from pathlib import Path
from typing import Any, NoReturn

import pytest
import test_token_session_failure_reentry_phase6d1h as memory
from phase6d0_auth_helpers import FakeRefresher

from tridentine_calendar_google_sync import production_write_token as tokens
from tridentine_calendar_google_sync import production_write_token_io as token_io
from tridentine_calendar_google_sync import production_write_token_operation_record as records
from tridentine_calendar_google_sync.production_write_token_models import (
    PRODUCTION_WRITE_SCOPES,
    ProductionWriteAuthorizedUserToken,
    ProductionWriteCredentialSession,
    ProductionWriteOAuthCredentials,
)

LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="real Linux START composition")
WINDOWS_ONLY = pytest.mark.skipif(sys.platform != "win32", reason="native Windows record refusal")
CREDENTIAL_KEYS = (
    "path_checks",
    "state_reads",
    "token_reads",
    "refresh",
    "save",
    "simulated_publications",
    "session_returns",
    "lock_contexts",
    "lock_enters",
    "lock_checkpoints",
    "lock_exits",
)


class _ForbiddenEffect(BaseException):
    """Do not let ordinary product Exception handlers hide forbidden effects."""


class _Cancelled(BaseException):
    """One synthetic cancellation object, never a successful observation."""


def _forbidden(*_args: Any, **_kwargs: Any) -> NoReturn:
    raise _ForbiddenEffect("Forbidden test composition effect")


def _deny_external_effects(patch: pytest.MonkeyPatch) -> None:
    """Leave record I/O available; block these preimported credential/network paths."""
    patch.setattr(socket, "socket", _forbidden)
    patch.setattr(socket, "create_connection", _forbidden)
    patch.setattr(os, "system", _forbidden)
    for name in ("open", "open_new", "open_new_tab", "get"):
        patch.setattr(webbrowser, name, _forbidden)
    patch.setattr(tokens, "load_desktop_client_config", _forbidden)
    for name in (
        "write_production_write_authorized_user_token",
        "write_production_write_token_generation_state",
        "write_production_write_token_bundle",
        "atomic_write_private_text",
        "create_private_text",
        "read_private_sensitive_bytes",
        "read_sensitive_bytes",
        "remove_sensitive_file_if_matches",
        "_remove_exact_new_artifact",
    ):
        patch.setattr(token_io, name, _forbidden)
    patch.setattr(token_io.posix_replace, "replace_posix_private_bytes", _forbidden)


@pytest.fixture(autouse=True)
def _external_effect_tripwires(monkeypatch: pytest.MonkeyPatch) -> None:
    _deny_external_effects(monkeypatch)


def _binding(directory: Path | None = None) -> records.SyntheticBinding:
    if directory is None:
        directory = Path(
            "C:/synthetic-start-session-never-opened"
            if os.name == "nt"
            else "/synthetic-start-session-never-opened"
        )
    return records.SyntheticBinding(
        directory, "synthetic-store", "synthetic-pair", "memory-token", "memory-state"
    )


def _operation() -> records.RecordOperation:
    # Independent references: not generation-derived or evidence of predecessor success.
    return records.RecordOperation(
        "synthetic-refresh-current", "synthetic-refresh-predecessor", records.OperationKind.REFRESH
    )


def _credential_boundaries() -> tuple[tuple[Any, str], ...]:
    return (
        (token_io, "validate_production_write_token_path_set"),
        (token_io, "load_production_write_token_generation_state"),
        (token_io, "load_production_write_authorized_user_token"),
        (token_io, "persist_refreshed_production_write_token"),
        (tokens, "_production_write_session_lock"),
    )


class _Audit:
    """Fixed counts and actual results; never a permission or persisted envelope."""

    def __init__(self) -> None:
        self.calls = {
            "fixture_directories": 0,
            "fixture_creates": 0,
            "fixture_byte_writes": 0,
            "snapshot_reads": 0,
            "record_creates": 0,
            "record_reads": 0,
            "record_internal_reads": 0,
            "injected_readbacks": 0,
            "session_api": 0,
        }
        self.credential = dict.fromkeys(CREDENTIAL_KEYS, 0)
        self.trace: list[str] = []
        self.preparing_fixture = False
        self._patch: pytest.MonkeyPatch | None = None
        self.initial_result: records.RecordResult | None = None
        self.observation: records.RecordResult | None = None

    def install(self, patch: pytest.MonkeyPatch) -> None:
        assert self._patch is None
        self._patch = patch
        create = records.create_start_record
        read = records.read_start_record
        reader = records.read_private_sensitive_bytes
        session = tokens.prepare_production_write_rehearsal_credential_session_mock

        def created(binding: object, operation: object) -> records.RecordResult:
            key = "fixture_creates" if self.preparing_fixture else "record_creates"
            self.calls[key] += 1
            self.trace.append("fixture_create_enter" if self.preparing_fixture else "create_enter")
            result = create(binding, operation)
            self.trace.append(
                "fixture_create_return" if self.preparing_fixture else "create_return"
            )
            return result

        def read_record(binding: object, operation: object) -> records.RecordResult:
            self.calls["record_reads"] += 1
            self.trace.append("read_enter")
            result = read(binding, operation)
            self.trace.append("read_return")
            return result

        def read_bytes(*args: Any, **kwargs: Any) -> bytes:
            self.calls["record_internal_reads"] += 1
            return reader(*args, **kwargs)

        def session_call(*args: Any, **kwargs: Any) -> ProductionWriteCredentialSession:
            self.calls["session_api"] += 1
            self.trace.append("session_enter")
            result = session(*args, **kwargs)
            self.trace.append("session_return")
            return result

        patch.setattr(records, "create_start_record", created)
        patch.setattr(records, "read_start_record", read_record)
        patch.setattr(records, "read_private_sensitive_bytes", read_bytes)
        patch.setattr(
            tokens, "prepare_production_write_rehearsal_credential_session_mock", session_call
        )
        # Outside the credential phase these are transparent counters, not I/O doubles.
        for (owner, name), key in zip(
            _credential_boundaries(),
            ("path_checks", "state_reads", "token_reads", "save", "lock_contexts"),
            strict=True,
        ):
            native = getattr(owner, name)

            def counted(*args: Any, _native: Any = native, _key: str = key, **kwargs: Any) -> Any:
                self.credential[_key] += 1
                return _native(*args, **kwargs)

            patch.setattr(owner, name, counted)

    def restore(self) -> None:
        assert self._patch is not None
        self._patch.undo()
        self._patch = None


@pytest.fixture
def audit() -> Iterator[_Audit]:
    with pytest.MonkeyPatch.context() as observed_patch:
        observed = _Audit()
        observed.install(observed_patch)
        yield observed


def _private(tmp_path: Path, audit: _Audit) -> records.SyntheticBinding:
    directory = tmp_path / "synthetic-start-session"
    directory.mkdir(mode=0o700)
    audit.calls["fixture_directories"] += 1
    return _binding(directory)


def _assert_record(
    result: records.RecordResult | None,
    state: records.RecordState,
    publication: bool | None = False,
) -> None:
    assert type(result) is records.RecordResult
    assert result.state is state
    assert result.publication_possible is publication
    assert result.reuse_authorized is False


def _snapshot(binding: records.SyntheticBinding, audit: _Audit) -> tuple[bytes, int, int, int, int]:
    path = binding.directory / records.RECORD_LEAF
    raw = path.read_bytes()
    metadata = path.stat()
    audit.calls["snapshot_reads"] += 1
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1
    document = json.loads(raw)
    assert document["phase"] == "started" and document["outcome"] == "incomplete"
    return raw, metadata.st_mode, metadata.st_dev, metadata.st_ino, metadata.st_nlink


def _first_trial(
    binding: records.SyntheticBinding,
    operation: records.RecordOperation,
    pair: memory._MemoryPair,
    refresher: FakeRefresher,
    audit: _Audit,
) -> ProductionWriteCredentialSession | None:
    # Explicit fixture/test authorization, never a supplied observation or permit.
    assert audit.initial_result is None and audit.observation is None
    assert audit.calls["record_creates"] == audit.calls["record_reads"] == 0
    assert audit.calls["session_api"] == 0
    assert pair.call == 0 and pair.trace == []
    result = records.create_start_record(binding, operation)
    audit.initial_result = result
    if not (
        type(result) is records.RecordResult
        and result.state is records.RecordState.START_CONFIRMED
        and result.reuse_authorized is False
    ):
        audit.trace.append("initial_refused")
        return None
    audit.trace.append("record_returned_unlocked_gap")
    before = _snapshot(binding, audit)
    originals = tuple(
        (owner, name, getattr(owner, name)) for owner, name in _credential_boundaries()
    )
    try:
        with pytest.MonkeyPatch.context() as credential:
            pair.install(credential)
            memory._deny_real_effects(credential)
            audit.trace.append("memory_credential_phase")
            pair.begin(1)
            try:
                session = tokens.prepare_production_write_rehearsal_credential_session_mock(
                    memory.TOKEN_PATH,
                    memory.STATE_PATH,
                    memory.READ_PATH,
                    memory.TEST_PATH,
                    pair.target,
                    pair.confirmation,
                    now=memory.NOW,
                    refresher=refresher,
                )
                pair.note("session_return")
                return session
            finally:
                for key, count in pair.counts(1).items():
                    audit.credential[key] += count
    finally:
        assert all(getattr(owner, name) is native for owner, name, native in originals)
        audit.trace.append("credential_patches_restored")
        unchanged = _snapshot(binding, audit) == before
        assert unchanged, "START snapshot changed during memory credential phase"


def _followup(
    binding: records.SyntheticBinding,
    expected_operation: records.RecordOperation | None,
    audit: _Audit,
) -> records.RecordResult | None:
    # Shared by the parent and ordinary child. No prior result/error/session input.
    assert audit.initial_result is audit.observation is None
    assert audit.calls["record_creates"] == audit.calls["record_reads"] == 0
    assert audit.calls["session_api"] == 0
    if expected_operation is None:
        audit.trace.append("independent_operation_missing")
        return None
    result = records.read_start_record(binding, expected_operation)
    audit.observation = result
    audit.trace.append("followup_refused_before_session")
    return result


def _assert_no_session(audit: _Audit) -> None:
    assert audit.calls["session_api"] == 0
    assert audit.credential == dict.fromkeys(CREDENTIAL_KEYS, 0)


def _evidence(
    audit: _Audit, result: records.RecordResult | None, classification: str
) -> dict[str, object]:
    # Only callers' fixed classifications, closed states, booleans and counters.
    return {
        "classification": classification,
        "state": None if result is None else result.state.name,
        "publication_possible": None if result is None else result.publication_possible,
        "reuse_authorized": False,
        "calls": dict(audit.calls),
        "credential": dict(audit.credential),
        "trace": list(audit.trace),
    }


def _fixture_start(binding: records.SyntheticBinding, audit: _Audit) -> None:
    audit.preparing_fixture = True
    try:
        _assert_record(
            records.create_start_record(binding, _operation()),
            records.RecordState.START_CONFIRMED,
            True,
        )
    finally:
        audit.preparing_fixture = False


def _new_followup(
    binding: records.SyntheticBinding,
    operation: records.RecordOperation,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[records.RecordResult | None, _Audit]:
    # The old audit/exception/session are deliberately absent from this interface.
    later = _Audit()
    with monkeypatch.context() as observed:
        later.install(observed)
        result = _followup(replace(binding), replace(operation), later)
    _assert_no_session(later)
    assert later.calls["record_reads"] == 1 and later.calls["record_creates"] == 0
    return result, later


def test_missing_independent_operation_stops_before_record_or_session(
    audit: _Audit, record_property: Callable[[str, object], None]
) -> None:
    result = _followup(_binding(), None, audit)
    assert result is None and audit.initial_result is audit.observation is None
    assert all(count == 0 for count in audit.calls.values())
    _assert_no_session(audit)
    assert audit.trace == ["independent_operation_missing"]
    record_property(
        "start_boundary_evidence",
        json.dumps(_evidence(audit, result, "INDEPENDENT_OPERATION_MISSING"), sort_keys=True),
    )


@WINDOWS_ONLY
@pytest.mark.parametrize("initial", (True, False), ids=("initial", "followup"))
def test_windows_actual_platform_refusal_precedes_all_record_and_credential_io(
    monkeypatch: pytest.MonkeyPatch,
    audit: _Audit,
    record_property: Callable[[str, object], None],
    initial: bool,
) -> None:
    hits: list[str] = []

    def denied(*_args: Any, **_kwargs: Any) -> NoReturn:
        hits.append("forbidden_record_effect")
        raise _ForbiddenEffect("Windows record I/O was attempted")

    with monkeypatch.context() as gated:
        gated.setattr(records, "read_private_sensitive_bytes", denied)
        gated.setattr(records.private_lock, "acquire_posix_private_directory_lock", denied)
        gated.setattr(records.private_create, "create_posix_private_bytes", denied)
        if initial:
            pair = memory._MemoryPair()
            assert _first_trial(_binding(), _operation(), pair, FakeRefresher(None), audit) is None
            result = audit.initial_result
            assert pair.call == 0 and pair.trace == []
        else:
            result = _followup(_binding(), _operation(), audit)
    _assert_record(result, records.RecordState.UNSUPPORTED_PLATFORM)
    _assert_no_session(audit)
    assert hits == []
    assert audit.calls["record_creates"] == int(initial)
    assert audit.calls["record_reads"] == int(not initial)
    assert audit.calls["record_internal_reads"] == audit.calls["snapshot_reads"] == 0
    record_property(
        "start_boundary_evidence",
        json.dumps(_evidence(audit, result, "NATIVE_WINDOWS_REFUSAL"), sort_keys=True),
    )


@LINUX_ONLY
def test_real_start_precedes_memory_publication_failure_and_independent_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, audit: _Audit
) -> None:
    binding, operation = _private(tmp_path, audit), _operation()
    pair = memory._MemoryPair()
    refresher = memory._ObservedRefresher(pair)
    with pytest.raises(tokens.ProductionWriteTokenRefreshPersistenceError) as caught:
        _first_trial(binding, operation, pair, refresher, audit)
    pair.note("caller_caught_persistence_error")
    memory._assert_first_refusal(pair, refresher, caught.value)
    _assert_record(audit.initial_result, records.RecordState.START_CONFIRMED, True)
    assert audit.calls["record_creates"] == audit.calls["session_api"] == 1
    assert audit.calls["record_internal_reads"] == 1 and audit.calls["snapshot_reads"] == 2
    assert audit.credential == {
        "path_checks": 1,
        "state_reads": 2,
        "token_reads": 2,
        "refresh": 1,
        "save": 1,
        "simulated_publications": 1,
        "session_returns": 0,
        "lock_contexts": 1,
        "lock_enters": 1,
        "lock_checkpoints": 4,
        "lock_exits": 1,
    }
    assert audit.trace == [
        "create_enter",
        "create_return",
        "record_returned_unlocked_gap",
        "memory_credential_phase",
        "session_enter",
        "credential_patches_restored",
    ]
    first_diagnosis = (
        caught.value.refresh_completed,
        caught.value.persistence_attempted,
        caught.value.publication_possible,
    )
    audit.restore()  # End first-call spies before independent later accounting.
    observation, later = _new_followup(binding, operation, monkeypatch)
    _assert_record(observation, records.RecordState.START_OBSERVED)
    assert later.calls["record_internal_reads"] == 1
    assert first_diagnosis == (True, True, True)
    assert caught.value.publication_possible is True
    assert observation is not None and observation.publication_possible is False


@LINUX_ONLY
def test_normal_session_return_leaves_started_incomplete_and_later_refuses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, audit: _Audit
) -> None:
    binding, operation = _private(tmp_path, audit), _operation()
    pair = memory._MemoryPair(expired=False)
    refresher = FakeRefresher(None)
    session = _first_trial(binding, operation, pair, refresher, audit)
    assert type(session) is ProductionWriteCredentialSession
    assert session.token is pair.old_token and session.generation_state is pair.original_state
    assert (
        session.refresh_count
        == session.calendar_api_call_count
        == session.browser_fallback_count
        == 0
    )
    assert refresher.calls == refresher.refresh_attempt_count == 0
    assert audit.calls["session_api"] == audit.calls["record_creates"] == 1
    assert audit.calls["snapshot_reads"] == 2
    assert audit.credential["refresh"] == audit.credential["save"] == 0
    assert audit.credential["session_returns"] == 1
    assert tuple(pair.trace) == tuple((1, event) for event in memory.UNEXPIRED_EVENTS)
    _assert_record(audit.initial_result, records.RecordState.START_CONFIRMED, True)
    audit.restore()  # End first-call spies before independent later accounting.
    observation, _later = _new_followup(binding, operation, monkeypatch)
    _assert_record(observation, records.RecordState.START_OBSERVED)


@LINUX_ONLY
@pytest.mark.parametrize("fixture", ("absent", "mismatched-operation", "malformed"))
def test_real_observation_contrasts_never_fall_back_to_initial_use(
    tmp_path: Path, audit: _Audit, fixture: str
) -> None:
    binding, expected = _private(tmp_path, audit), _operation()
    if fixture == "mismatched-operation":
        _fixture_start(binding, audit)
        expected = records.RecordOperation(
            "independently-declared-other-operation",
            "independently-declared-other-predecessor",
            records.OperationKind.REFRESH,
        )
    elif fixture == "malformed":
        path = binding.directory / records.RECORD_LEAF
        with path.open("xb") as stream:
            stream.write(b"{synthetic-malformed-start\n")
        path.chmod(0o600)
        audit.calls["fixture_byte_writes"] += 1
    result = _followup(binding, expected, audit)
    _assert_record(result, records.RecordState.UNVERIFIABLE)
    _assert_no_session(audit)
    assert audit.calls["record_reads"] == 1 and audit.calls["record_creates"] == 0
    assert audit.calls["fixture_creates"] == int(fixture == "mismatched-operation")
    assert audit.calls["fixture_byte_writes"] == int(fixture == "malformed")
    assert audit.calls["record_internal_reads"] == 1 + int(fixture == "mismatched-operation")
    # UNVERIFIABLE is not a decoded cause, authenticated absence or clean history.


@LINUX_ONLY
def test_existing_same_start_refuses_initial_trial_without_recreation(
    tmp_path: Path, audit: _Audit
) -> None:
    binding = _private(tmp_path, audit)
    _fixture_start(binding, audit)
    before = _snapshot(binding, audit)
    pair = memory._MemoryPair()
    assert _first_trial(binding, _operation(), pair, FakeRefresher(None), audit) is None
    _assert_record(audit.initial_result, records.RecordState.SLOT_OCCUPIED)
    _assert_no_session(audit)
    assert audit.calls["fixture_creates"] == audit.calls["record_creates"] == 1
    assert pair.trace == [] and pair.call == 0
    unchanged = _snapshot(binding, audit) == before
    assert unchanged, "Occupied START changed"


@LINUX_ONLY
@pytest.mark.parametrize("cancel", (False, True), ids=("oserror", "cancellation"))
def test_create_readback_fault_never_continues_and_later_observation_does_not_clear_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, audit: _Audit, cancel: bool
) -> None:
    binding, operation = _private(tmp_path, audit), _operation()
    pair = memory._MemoryPair()
    problem = (
        _Cancelled("Synthetic record cancellation") if cancel else OSError("Synthetic readback")
    )
    reader_before = records.read_private_sensitive_bytes

    def failed_readback(path: Path, *, max_size: int) -> NoReturn:
        assert path == binding.directory / records.RECORD_LEAF
        assert max_size == records.MAX_RECORD_BYTES
        audit.calls["injected_readbacks"] += 1
        assert audit.calls["injected_readbacks"] == 1
        # Only this create readback is injected: the actual reader is not delegated.
        raise problem

    with monkeypatch.context() as injected:
        injected.setattr(records, "read_private_sensitive_bytes", failed_readback)
        if cancel:
            with pytest.raises(_Cancelled) as caught:
                _first_trial(binding, operation, pair, FakeRefresher(None), audit)
            assert caught.value is problem
            assert audit.initial_result is None
        else:
            assert _first_trial(binding, operation, pair, FakeRefresher(None), audit) is None
            _assert_record(audit.initial_result, records.RecordState.PERSISTENCE_UNCERTAIN, True)
    assert records.read_private_sensitive_bytes is reader_before
    assert audit.calls["injected_readbacks"] == audit.calls["record_creates"] == 1
    assert audit.calls["record_internal_reads"] == 0
    _assert_no_session(audit)
    assert pair.call == 0 and pair.trace == []
    before = _snapshot(binding, audit)
    audit.restore()  # End first-call spies before independent later accounting.
    observation, later = _new_followup(binding, operation, monkeypatch)
    _assert_record(observation, records.RecordState.START_OBSERVED)
    assert later.calls["record_internal_reads"] == 1
    unchanged = _snapshot(binding, audit) == before
    assert unchanged, "Readback-fault START changed"
    if cancel:
        assert caught.value is problem and audit.initial_result is None
    else:
        _assert_record(audit.initial_result, records.RecordState.PERSISTENCE_UNCERTAIN, True)


class _CancellingRefresher(FakeRefresher):
    def __init__(self, pair: memory._MemoryPair, problem: _Cancelled) -> None:
        super().__init__(None)
        self.pair = pair
        self.problem = problem

    def refresh(
        self, token: ProductionWriteAuthorizedUserToken, scopes: tuple[str, ...]
    ) -> ProductionWriteOAuthCredentials:
        assert token is self.pair.old_token and scopes == PRODUCTION_WRITE_SCOPES
        assert self.pair.active is not None and self.pair.call == 1
        self.calls += 1
        self.refresh_attempt_count += 1
        self.pair.note("refresh")
        raise self.problem


@LINUX_ONLY
def test_refresher_cancellation_preserves_identity_and_start_before_later_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, audit: _Audit
) -> None:
    binding, operation = _private(tmp_path, audit), _operation()
    pair = memory._MemoryPair()
    problem = _Cancelled("Synthetic refresher cancellation")
    refresher = _CancellingRefresher(pair, problem)
    with pytest.raises(_Cancelled) as caught:
        _first_trial(binding, operation, pair, refresher, audit)
    assert caught.value is problem and pair.contexts[0].error is problem
    assert pair.contexts[0].exited and pair.active is None
    assert refresher.calls == refresher.refresh_attempt_count == 1
    assert refresher.calendar_api_call_count == refresher.browser_fallback_count == 0
    _assert_record(audit.initial_result, records.RecordState.START_CONFIRMED, True)
    assert audit.calls["record_creates"] == audit.calls["session_api"] == 1
    assert audit.credential["state_reads"] == audit.credential["token_reads"] == 1
    assert audit.credential["refresh"] == 1
    assert audit.credential["save"] == audit.credential["session_returns"] == 0
    assert audit.credential["simulated_publications"] == 0
    assert audit.calls["snapshot_reads"] == 2
    audit.restore()  # End first-call spies before independent later accounting.
    observation, _later = _new_followup(binding, operation, monkeypatch)
    _assert_record(observation, records.RecordState.START_OBSERVED)
    assert caught.value is problem


def _child_followup() -> int:
    """Explicit test-only child entry; no pytest run, raw errors or record-derived IDs."""
    try:
        if sys.platform != "linux" or len(sys.argv) != 2 or sys.argv[1] != "--test-child-followup":
            raise ValueError("Invalid child entry")
        source = Path(__file__).resolve().parents[1] / "src" / "tridentine_calendar_google_sync"
        assert (
            Path(records.__file__).resolve()
            == source / "production_write_token_operation_record.py"
        )
        assert Path(tokens.__file__).resolve() == source / "production_write_token.py"
        request = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        if type(request) is not dict or set(request) != {
            "directory",
            "storage_ref",
            "pair_ref",
            "token_slot",
            "state_slot",
            "operation_id",
            "predecessor_id",
        }:
            raise ValueError("Invalid child input")
        if not all(type(value) is str for value in request.values()):
            raise ValueError("Invalid child input")
        binding = records.SyntheticBinding(
            Path(request["directory"]),
            request["storage_ref"],
            request["pair_ref"],
            request["token_slot"],
            request["state_slot"],
        )
        operation = records.RecordOperation(
            request["operation_id"], request["predecessor_id"], records.OperationKind.REFRESH
        )
        audit = _Audit()
        with pytest.MonkeyPatch.context() as isolated:
            _deny_external_effects(isolated)
            audit.install(isolated)
            result = _followup(binding, operation, audit)
        _assert_record(result, records.RecordState.START_OBSERVED)
        _assert_no_session(audit)
        assert audit.calls["record_reads"] == audit.calls["record_internal_reads"] == 1
        assert audit.calls["record_creates"] == 0
        output = _evidence(audit, result, "CHILD_START_OBSERVED_REFUSED")
    except BaseException:
        print(json.dumps({"classification": "CHILD_FAILED_DETAILS_WITHHELD"}, sort_keys=True))
        return 1
    print(json.dumps(output, sort_keys=True))
    return 0


@LINUX_ONLY
def test_one_ordinary_new_process_uses_same_independent_followup(
    tmp_path: Path, audit: _Audit
) -> None:
    binding, operation = _private(tmp_path, audit), _operation()
    _fixture_start(binding, audit)
    before = _snapshot(binding, audit)
    request = {
        "directory": str(binding.directory),
        "storage_ref": binding.storage_ref,
        "pair_ref": binding.pair_ref,
        "token_slot": binding.token_slot,
        "state_slot": binding.state_slot,
        "operation_id": operation.operation_id,
        "predecessor_id": operation.predecessor_id,
    }
    # Only independently prepared fixture inputs cross the boundary, never prior results.
    try:
        completed = subprocess.run(
            [sys.executable, "-B", str(Path(__file__)), "--test-child-followup"],
            input=json.dumps(request).encode("utf-8"),
            capture_output=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pytest.fail("Ordinary child execution failed; details withheld", pytrace=False)
    if completed.returncode != 0 or completed.stderr:
        pytest.fail("Ordinary child returned failure; details withheld", pytrace=False)
    try:
        output = json.loads(completed.stdout)
    except (ValueError, UnicodeError):
        pytest.fail("Ordinary child output invalid; details withheld", pytrace=False)
    expected_calls = dict.fromkeys(audit.calls, 0)
    expected_calls.update(record_reads=1, record_internal_reads=1)
    expected = {
        "classification": "CHILD_START_OBSERVED_REFUSED",
        "state": "START_OBSERVED",
        "publication_possible": False,
        "reuse_authorized": False,
        "calls": expected_calls,
        "credential": dict.fromkeys(CREDENTIAL_KEYS, 0),
        "trace": ["read_enter", "read_return", "followup_refused_before_session"],
    }
    matches = output == expected
    assert matches, "Ordinary child did not provide the exact fixed observation"
    assert audit.calls["fixture_creates"] == 1
    assert audit.calls["record_creates"] == audit.calls["record_reads"] == 0
    _assert_no_session(audit)
    unchanged = _snapshot(binding, audit) == before
    assert unchanged, "Ordinary child changed START"


if __name__ == "__main__":
    raise SystemExit(_child_followup())
