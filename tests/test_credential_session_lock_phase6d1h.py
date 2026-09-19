"""Synthetic session serialization; no live OAuth, Calendar calls or recovery approval."""

from __future__ import annotations

import ast
import errno
import os
import subprocess
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from threading import Event
from types import SimpleNamespace
from typing import Any

import pytest
from phase6d0_auth_helpers import (
    ISSUED_AT,
    FakeRefresher,
    artifact_paths,
    oauth_credentials,
    production_target,
    production_token,
)

from tridentine_calendar_google_sync import _posix_private_lock as locking
from tridentine_calendar_google_sync import production_write_token as tokens
from tridentine_calendar_google_sync import production_write_token_io as token_io
from tridentine_calendar_google_sync import production_write_token_rehearsal as rehearsal
from tridentine_calendar_google_sync.production_write_token_models import (
    ProductionWriteGrantEvidenceOrigin,
)

LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="real Linux session flock")
NOW = ISSUED_AT + timedelta(seconds=2)


def _stored(
    tmp_path: Path, *, split: bool = False, expired: bool = True
) -> tuple[Any, dict[str, Path]]:
    root = tmp_path / "private-session"
    root.mkdir(mode=0o700)
    paths = artifact_paths(root)
    if split:
        other = tmp_path / "private-state"
        other.mkdir(mode=0o700)
        paths["generation"] = other / "generation.json"
    target = production_target()
    state = tokens.build_initial_production_write_token_generation_state(
        target, issued_at=ISSUED_AT
    )
    token = production_token(
        state, expiry=ISSUED_AT + (timedelta(seconds=1) if expired else timedelta(hours=1))
    )
    token_io.write_production_write_token_bundle(token, paths["write"], state, paths["generation"])
    return target, paths


def _refresher() -> FakeRefresher:
    return FakeRefresher(
        oauth_credentials(
            expiry=NOW + timedelta(hours=1),
            evidence_origin=ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
            evidence_observed_at=NOW,
            access_token="unit4n-synthetic-new-access",
            refresh_token="unit4n-synthetic-new-refresh",
        )
    )


def _prepare(target: Any, paths: dict[str, Path], refresher: Any = None) -> Any:
    return tokens.prepare_production_write_rehearsal_credential_session_mock(
        paths["write"],
        paths["generation"],
        paths["read"],
        paths["test"],
        target,
        rehearsal.production_write_token_rehearsal_challenge(target),
        now=NOW,
        refresher=refresher,
    )


def _forbidden(*_args: Any, **_kwargs: Any) -> Any:
    raise AssertionError("unexpected content read, refresh, save or cleanup")


def _assert_safe(error: Any, paths: dict[str, Path], *, busy: bool = False) -> None:
    assert type(error) is tokens.ProductionWriteTokenSessionLockError
    assert isinstance(error, tokens.ProductionWriteTokenRefreshError)
    assert error.code == (
        "production_write_token_session_busy"
        if busy
        else "production_write_token_session_lock_unverified"
    )
    text = "".join(traceback.format_exception(error))
    assert error.__cause__ is None and error.__suppress_context__
    assert "PRIVATE_LOCK_MARKER" not in text
    assert all(str(path) not in text for path in paths.values())
    assert "retry, remove, or restore files automatically" in text
    assert not hasattr(error, "publication_possible")  # No false claim about pre/post-save state.


class _Held:
    def __init__(self, parent: Path, active: list[Path], trace: list[str]) -> None:
        self.parent, self.active, self.trace = parent, active, trace

    def __enter__(self) -> _Held:
        self.active.append(self.parent)
        self.trace.append("enter")
        return self

    def __exit__(self, *_args: Any) -> None:
        self.trace.append("exit")
        self.active.remove(self.parent)

    def revalidate(self) -> None:
        assert self.parent in self.active
        self.trace.append("check")


def _instrument(monkeypatch: pytest.MonkeyPatch) -> tuple[list[Path], list[Path], list[str]]:
    acquired: list[Path] = []
    active: list[Path] = []
    trace: list[str] = []
    monkeypatch.setattr(tokens, "os", SimpleNamespace(name="posix", fspath=os.fspath))

    def acquire(parent: Path) -> _Held:
        acquired.append(parent)
        return _Held(parent, active, trace)

    monkeypatch.setattr(locking, "acquire_posix_private_directory_lock", acquire)
    return acquired, active, trace


@pytest.mark.parametrize("split", (False, True))
@pytest.mark.parametrize("expired", (False, True))
def test_both_parents_held_before_reads_until_session_return(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, split: bool, expired: bool
) -> None:
    target, paths = _stored(tmp_path, split=split, expired=expired)
    acquired, active, trace = _instrument(monkeypatch)
    expected = sorted({paths["write"].parent, paths["generation"].parent}, key=os.fspath)
    for name in (
        "load_production_write_authorized_user_token",
        "load_production_write_token_generation_state",
        "persist_refreshed_production_write_token",
    ):
        native = getattr(token_io, name)

        def recorded(*args: Any, _name: str = name, _native: Any = native, **kw: Any) -> Any:
            assert active == expected
            trace.append(_name)
            return _native(*args, **kw)

        monkeypatch.setattr(token_io, name, recorded)
    refresher = _refresher()
    native_refresh = refresher.refresh

    def refresh(*args: Any, **kw: Any) -> Any:
        assert active == expected
        trace.append("refresh")
        return native_refresh(*args, **kw)

    monkeypatch.setattr(refresher, "refresh", refresh)
    session = _prepare(target, paths, refresher)
    assert acquired == expected and active == []
    assert session.refresh_count == int(expired)
    assert trace[-len(expected) :] == ["exit"] * len(expected)
    if expired:
        assert trace.index("refresh") < trace.index("persist_refreshed_production_write_token")


@pytest.mark.parametrize("failure", ("busy", "unavailable", "unexpected", "cancel"))
def test_second_parent_failure_releases_first_before_content_or_refresh(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    target, paths = _stored(tmp_path, split=True)
    acquired, active, trace = _instrument(monkeypatch)
    native_acquire = locking.acquire_posix_private_directory_lock
    calls: list[Path] = []

    def acquire(parent: Path) -> Any:
        calls.append(parent)
        if len(calls) == 2:
            if failure == "cancel":
                raise KeyboardInterrupt
            if failure == "unexpected":
                raise OSError(errno.EIO, "PRIVATE_LOCK_MARKER", str(parent))
            raise locking.PosixPrivateLockError("posix_directory_lock_" + failure)
        return native_acquire(parent)

    monkeypatch.setattr(locking, "acquire_posix_private_directory_lock", acquire)
    monkeypatch.setattr(token_io, "load_production_write_authorized_user_token", _forbidden)
    monkeypatch.setattr(token_io, "load_production_write_token_generation_state", _forbidden)
    refresher = _refresher()
    expected_error = (
        KeyboardInterrupt if failure == "cancel" else tokens.ProductionWriteTokenSessionLockError
    )
    with pytest.raises(expected_error) as caught:
        _prepare(target, paths, refresher)
    if failure != "cancel":
        _assert_safe(caught.value, paths, busy=failure == "busy")
    assert len(calls) == 2 and len(acquired) == 1 and active == []
    assert trace[-1] == "exit" and refresher.calls == 0


@pytest.mark.parametrize("stage", ("read", "refresh", "save"))
@pytest.mark.parametrize("cancel", (False, True))
def test_body_exceptions_and_cancellation_release_locks_without_masking(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str, cancel: bool
) -> None:
    target, paths = _stored(tmp_path)
    _, active, trace = _instrument(monkeypatch)
    refresher = _refresher()
    error = KeyboardInterrupt() if cancel else ValueError("PRIVATE_LOCK_MARKER")

    def fail(*_args: Any, **_kw: Any) -> Any:
        assert active
        raise error

    if stage == "read":
        monkeypatch.setattr(token_io, "load_production_write_token_generation_state", fail)
    elif stage == "refresh":
        monkeypatch.setattr(refresher, "refresh", fail)
    else:
        monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", fail)
    expected_error: type[BaseException]
    if cancel:
        expected_error = KeyboardInterrupt
    elif stage == "read":
        expected_error = ValueError
    elif stage == "save":
        expected_error = tokens.ProductionWriteTokenRefreshPersistenceError
    else:
        expected_error = tokens.ProductionWriteTokenRefreshError
    with pytest.raises(expected_error) as caught:
        _prepare(target, paths, refresher)
    assert active == [] and trace[-1] == "exit"
    if cancel or stage == "read":
        assert caught.value is error
    elif stage == "save":
        assert isinstance(caught.value, tokens.ProductionWriteTokenRefreshPersistenceError)
        assert caught.value.persistence_attempted is True
    else:
        assert type(caught.value) is tokens.ProductionWriteTokenRefreshError


@pytest.mark.parametrize("after", ("read", "refresh", "save"))
def test_failed_checkpoint_blocks_further_progress_and_preserves_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after: str
) -> None:
    target, paths = _stored(tmp_path)
    _, active, trace = _instrument(monkeypatch)
    changed: list[str] = []
    before = {k: paths[k].read_bytes() for k in ("write", "generation")}
    method = (
        "load_production_write_authorized_user_token"
        if after == "read"
        else "persist_refreshed_production_write_token"
    )
    refresher = _refresher()
    owner, method = (refresher, "refresh") if after == "refresh" else (token_io, method)
    native = getattr(owner, method)

    def recorded(*args: Any, **kw: Any) -> Any:
        result = native(*args, **kw)
        changed.append(after)
        return result

    def revalidate(self: _Held) -> None:
        if changed:
            raise locking.PosixPrivateLockError("posix_directory_lock_unverified")
        assert self.parent in self.active

    monkeypatch.setattr(owner, method, recorded)
    monkeypatch.setattr(_Held, "revalidate", revalidate)
    with pytest.raises(tokens.ProductionWriteTokenSessionLockError) as caught:
        _prepare(target, paths, refresher)
    _assert_safe(caught.value, paths)
    assert active == [] and trace[-1] == "exit"
    assert paths["generation"].read_bytes() == before["generation"]
    assert (paths["write"].read_bytes() != before["write"]) is (after == "save")
    assert refresher.calls == (0 if after == "read" else 1)


def test_windows_bypasses_lock_without_altering_existing_session_flow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, paths = _stored(tmp_path, expired=False)
    monkeypatch.setattr(tokens, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(locking, "acquire_posix_private_directory_lock", _forbidden)
    assert _prepare(target, paths).refresh_count == 0


@pytest.mark.parametrize("platform", ("darwin", "freebsd14"))
def test_other_posix_has_no_unlocked_session_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    target, paths = _stored(tmp_path, expired=False)
    monkeypatch.setattr(tokens, "os", SimpleNamespace(name="posix", fspath=os.fspath))
    monkeypatch.setattr(locking, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(token_io, "load_production_write_token_generation_state", _forbidden)
    with pytest.raises(tokens.ProductionWriteTokenSessionLockError) as caught:
        _prepare(target, paths)
    _assert_safe(caught.value, paths)


@pytest.mark.parametrize(
    "value", ("relative/token.json", "/bad/../token.json", "/bad/\x00token.json")
)
def test_invalid_lock_paths_rejected_before_acquisition(
    monkeypatch: pytest.MonkeyPatch, value: str
) -> None:
    monkeypatch.setattr(tokens, "os", SimpleNamespace(name="posix", fspath=os.fspath))
    monkeypatch.setattr(locking, "acquire_posix_private_directory_lock", _forbidden)
    with (
        pytest.raises(tokens.ProductionWriteTokenSessionLockError),
        tokens._production_write_session_lock(value, "/synthetic/state.json"),
    ):
        pytest.fail("invalid input entered context")


@LINUX_ONLY
@pytest.mark.parametrize("split", (False, True))
def test_native_parallel_sessions_have_one_refresh_winner_and_busy_contender(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, split: bool
) -> None:
    target, paths = _stored(tmp_path, split=split)
    entered, release = Event(), Event()
    first, second = _refresher(), _refresher()
    native = first.refresh

    def paused(*args: Any, **kw: Any) -> Any:
        entered.set()
        assert release.wait(5)
        return native(*args, **kw)

    monkeypatch.setattr(first, "refresh", paused)
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(_prepare, target, paths, first)
        try:
            assert entered.wait(5)
            with pytest.raises(tokens.ProductionWriteTokenSessionLockError) as caught:
                _prepare(target, paths, second)
            _assert_safe(caught.value, paths, busy=True)
            assert second.calls == 0
        finally:
            release.set()
        assert pending.result(timeout=5).refresh_count == 1
    assert first.calls == 1 and second.calls == 0
    # A separate subsequent call, not a retry by the implementation, sees the new token.
    assert _prepare(target, paths, second).refresh_count == 0 and second.calls == 0


@LINUX_ONLY
@pytest.mark.parametrize("held_role", ("write", "generation"))
def test_lock_on_either_parent_blocks_before_reads_even_when_parents_differ(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, held_role: str
) -> None:
    target, paths = _stored(tmp_path, split=True)
    monkeypatch.setattr(token_io, "load_production_write_token_generation_state", _forbidden)
    with locking.acquire_posix_private_directory_lock(paths[held_role].parent):
        with pytest.raises(tokens.ProductionWriteTokenSessionLockError) as caught:
            _prepare(target, paths, _refresher())
        _assert_safe(caught.value, paths, busy=True)
    for role in ("write", "generation"):
        with locking.acquire_posix_private_directory_lock(paths[role].parent):
            pass


@LINUX_ONLY
def test_separate_process_session_observes_existing_lock(tmp_path: Path) -> None:
    target, paths = _stored(tmp_path, expired=False)
    del target
    code = """
import sys
from pathlib import Path
from phase6d0_auth_helpers import ISSUED_AT, production_target
from tridentine_calendar_google_sync import production_write_token as t
from tridentine_calendar_google_sync.production_write_token_rehearsal import (
    production_write_token_rehearsal_challenge,
)
x = production_target()
try:
    t.prepare_production_write_rehearsal_credential_session_mock(
        *[Path(p) for p in sys.argv[1:]],
        x,
        production_write_token_rehearsal_challenge(x),
        now=ISSUED_AT,
    )
except t.ProductionWriteTokenSessionLockError as e:
    sys.exit(0 if e.code == 'production_write_token_session_busy' else 2)
sys.exit(3)
"""
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Explicit synthetic source/helper search path; no runtime credential discovery.
    env["PYTHONPATH"] = os.pathsep.join(
        (
            str(Path(tokens.__file__).resolve().parents[1]),
            str(Path(__import__("phase6d0_auth_helpers").__file__).parent),
        )
    )
    with locking.acquire_posix_private_directory_lock(paths["write"].parent):
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                code,
                *(str(paths[k]) for k in ("write", "generation", "read", "test")),
            ],
            env=env,
            check=False,
            capture_output=True,
            timeout=10,
        )
    assert result.returncode == 0


@LINUX_ONLY
def test_parent_replacement_during_refresh_stops_without_saving_or_deleting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, paths = _stored(tmp_path)
    root = paths["write"].parent
    moved = root.with_name("retained-old-parent")
    old_bytes = paths["write"].read_bytes()
    refresher = _refresher()
    native = refresher.refresh

    def replaced(*args: Any, **kw: Any) -> Any:
        result = native(*args, **kw)
        root.rename(moved)  # Noncooperating synthetic actor.
        root.mkdir(mode=0o700)
        return result

    monkeypatch.setattr(refresher, "refresh", replaced)
    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", _forbidden)
    with pytest.raises(tokens.ProductionWriteTokenSessionLockError) as caught:
        _prepare(target, paths, refresher)
    _assert_safe(caught.value, paths)
    assert (moved / paths["write"].name).read_bytes() == old_bytes
    assert list(root.iterdir()) == [] and refresher.calls == 1


@LINUX_ONLY
@pytest.mark.parametrize("mode", (0o755, 0o750))
def test_unexpired_session_also_requires_private_parent_without_repair(
    tmp_path: Path, mode: int
) -> None:
    target, paths = _stored(tmp_path, expired=False)
    paths["write"].parent.chmod(mode)
    before = paths["write"].read_bytes()
    try:
        with pytest.raises(tokens.ProductionWriteTokenSessionLockError):
            _prepare(target, paths)
        assert paths["write"].read_bytes() == before
        assert paths["write"].parent.stat().st_mode & 0o777 == mode
    finally:
        paths["write"].parent.chmod(0o700)  # Only synthetic fixture cleanup.


def test_confirmation_failure_precedes_lock_and_content_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths = artifact_paths(tmp_path)
    monkeypatch.setattr(tokens, "_production_write_session_lock", _forbidden)
    with pytest.raises(rehearsal.ProductionWriteTokenRehearsalError):
        tokens.prepare_production_write_rehearsal_credential_session_mock(
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            production_target(),
            "wrong synthetic challenge",
            now=NOW,
        )


def test_loader_lexically_holds_locks_over_reads_refresh_save_and_both_returns() -> None:
    tree = ast.parse(Path(tokens.__file__).read_text(encoding="utf-8"))
    fn = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_load_production_write_credential_session"
    )
    guarded = [n for n in fn.body if isinstance(n, ast.With)]
    assert len(guarded) == 1
    assert not any(isinstance(n, ast.Return) for n in fn.body)
    calls = {
        n.func.id
        for n in ast.walk(guarded[0])
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert {
        "load_production_write_authorized_user_token",
        "load_production_write_token_generation_state",
        "persist_refreshed_production_write_token",
        "revalidate_session_lock",
    } <= calls
    assert sum(isinstance(n, ast.Return) for n in ast.walk(guarded[0])) == 2
    helper = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_production_write_session_lock"
    )
    attrs = {
        n.func.attr
        for n in ast.walk(helper)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert not attrs & {"unlink", "remove", "replace", "rename", "chmod", "sleep", "write_bytes"}
    assert not any(isinstance(n, ast.While) for n in ast.walk(helper))


@pytest.mark.parametrize("attempts", (0, 1))
def test_mock_rehearsal_classifies_safe_lock_error_before_calendar_transport(attempts: int) -> None:
    from tridentine_calendar_google_sync.production_write_token_rehearsal_models import (
        ProductionWriteTokenRehearsalResultState,
    )
    from tridentine_calendar_google_sync.production_write_token_rehearsal_transport import (
        FakeProductionWriteCredentialSessionProvider,
        FakeProductionWriteTokenReadOnlyTransport,
        FakeProductionWriteTokenReadOnlyTransportProvider,
    )

    target = production_target()
    error = tokens.ProductionWriteTokenSessionLockError(busy=attempts == 0)
    provider = FakeProductionWriteCredentialSessionProvider(error, refresh_attempt_count=attempts)
    transport = FakeProductionWriteTokenReadOnlyTransport(collections=(), get_events=())
    transport_provider = FakeProductionWriteTokenReadOnlyTransportProvider(transport)
    result = rehearsal.run_production_write_token_readonly_rehearsal_mock(
        credential_session_provider=provider,
        transport_provider=transport_provider,
        target=target,
        manifest=None,
        accepted_profile=None,
        accepted_source=None,
        trusted_baseline=None,
        confirmation=rehearsal.production_write_token_rehearsal_challenge(target),
    )
    assert (
        result.report.result_state is ProductionWriteTokenRehearsalResultState.TOKEN_REFRESH_FAILED
    )
    assert result.report.token_refresh_count == attempts
    assert result.report.calendar_api_call_count == 0 and transport_provider.build_count == 0
    assert result.snapshot is None and transport.call_log == ()


@LINUX_ONLY
def test_native_cancellation_releases_both_directory_locks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, paths = _stored(tmp_path, split=True)
    refresher = _refresher()

    def interrupted(*_args: Any, **_kw: Any) -> Any:
        raise KeyboardInterrupt

    before = {k: paths[k].read_bytes() for k in ("write", "generation")}
    monkeypatch.setattr(refresher, "refresh", interrupted)
    with pytest.raises(KeyboardInterrupt):
        _prepare(target, paths, refresher)
    for role in ("write", "generation"):
        with locking.acquire_posix_private_directory_lock(paths[role].parent):
            assert paths[role].read_bytes() == before[role]
