"""Synthetic bundle/session cooperation; no live authorization or recovery approval."""

from __future__ import annotations

import ast
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
from phase6d0_auth_helpers import ISSUED_AT, production_target, production_token

from tridentine_calendar_google_sync import _posix_private_lock as locking
from tridentine_calendar_google_sync import production_write_token as tokens
from tridentine_calendar_google_sync import production_write_token_io as token_io

LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="real Linux bundle/session flock")


def _pair() -> tuple[Any, Any]:
    state = tokens.build_initial_production_write_token_generation_state(
        production_target(), issued_at=ISSUED_AT
    )
    return production_token(state), state


def _paths(tmp_path: Path, *, split: bool = False) -> tuple[Path, Path]:
    first = tmp_path / "a-private"
    first.mkdir(mode=0o700)
    second = tmp_path / "b-private" if split else first
    if split:
        second.mkdir(mode=0o700)
    return second / "token.json", first / "state.json"


def _write(token_path: Path, state_path: Path) -> tuple[Path, Path]:
    token, state = _pair()
    return token_io.write_production_write_token_bundle(token, token_path, state, state_path)


def _forbidden(*_a: Any, **_kw: Any) -> Any:
    raise AssertionError("unexpected reader, writer, legacy rollback or retry")


def _safe(error: token_io.ProductionWriteTokenIOError, root: Path) -> None:
    assert error.__cause__ is None and error.__suppress_context__
    text = "".join(traceback.format_exception(error))
    assert str(root) not in text and "PRIVATE_LOCK_MARKER" not in text


def _instrument(
    monkeypatch: pytest.MonkeyPatch,
    *,
    acquisition_failure: int = -1,
    busy: bool = False,
    checkpoint_after: int = -1,
) -> tuple[list[Path], list[Path], list[str]]:
    acquired: list[Path] = []
    held: list[Path] = []
    trace: list[str] = []
    monkeypatch.setattr(tokens, "os", SimpleNamespace(name="posix", fspath=os.fspath))
    monkeypatch.setattr(token_io, "os", SimpleNamespace(name="posix"))

    class Held:
        def __init__(self, parent: Path) -> None:
            self.parent = parent

        def __enter__(self) -> Held:
            held.append(self.parent)
            trace.append("enter")
            return self

        def __exit__(self, *_a: Any) -> None:
            held.remove(self.parent)
            trace.append("exit")

        def revalidate(self) -> None:
            assert self.parent in held
            if trace.count("state") + trace.count("token") == checkpoint_after:
                raise locking.PosixPrivateLockError("PRIVATE_LOCK_MARKER")
            trace.append("check")

    def acquire(parent: Path) -> Held:
        acquired.append(parent)
        if len(acquired) - 1 == acquisition_failure:
            raise locking.PosixPrivateLockError(
                "posix_directory_lock_busy" if busy else "PRIVATE_LOCK_MARKER"
            )
        return Held(parent)

    monkeypatch.setattr(locking, "acquire_posix_private_directory_lock", acquire)
    return acquired, held, trace


@pytest.mark.parametrize("split", (False, True))
def test_locks_cover_state_token_and_final_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, split: bool
) -> None:
    token_path, state_path = _paths(tmp_path, split=split)
    acquired, held, trace = _instrument(monkeypatch)
    expected = sorted({token_path.parent, state_path.parent}, key=os.fspath)

    def writer(_value: Any, path: Path, **kw: Any) -> Path:
        assert held == expected
        role = "state" if path == state_path else "token"
        assert kw == ({} if role == "state" else {"overwrite": False})
        trace.append(role)
        return path

    monkeypatch.setattr(token_io, "write_production_write_token_generation_state", writer)
    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", writer)
    monkeypatch.setattr(token_io, "_remove_exact_new_artifact", _forbidden)
    assert _write(token_path, state_path) == (token_path, state_path)
    assert acquired == expected and held == []
    assert trace.count("state") == trace.count("token") == 1
    assert trace.index("state") < trace.index("token")
    assert "check" in trace[trace.index("state") + 1 : trace.index("token")]
    assert "check" in trace[trace.index("token") + 1 : trace.index("exit")]


@pytest.mark.parametrize("failure", (0, 1))
@pytest.mark.parametrize("busy", (False, True))
def test_acquisition_error_closes_prior_locks_and_does_not_enter_writers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: int, busy: bool
) -> None:
    token_path, state_path = _paths(tmp_path, split=True)
    acquired, held, trace = _instrument(monkeypatch, acquisition_failure=failure, busy=busy)
    monkeypatch.setattr(token_io, "write_production_write_token_generation_state", _forbidden)
    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", _forbidden)
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        _write(token_path, state_path)
    error = caught.value
    assert error.code == (
        "production_write_token_bundle_busy"
        if busy
        else "production_write_token_bundle_lock_unverified"
    )
    assert error.publication_possible is False and error.completed_output_count == 0
    assert len(acquired) == failure + 1 and held == []
    assert trace.count("exit") == failure
    assert not token_path.exists() and not state_path.exists()
    assert "Do not proceed unlocked" in str(error)
    _safe(error, tmp_path)


@pytest.mark.parametrize("completed", (0, 1, 2))
def test_failed_checkpoint_never_claims_absence_after_completed_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, completed: int
) -> None:
    token_path, state_path = _paths(tmp_path)
    _, held, trace = _instrument(monkeypatch, checkpoint_after=completed)

    def writer(_value: Any, path: Path, **_kw: Any) -> Path:
        trace.append("state" if path == state_path else "token")
        path.write_bytes(b"retained synthetic output")
        return path

    monkeypatch.setattr(token_io, "write_production_write_token_generation_state", writer)
    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", writer)
    monkeypatch.setattr(token_io, "_remove_exact_new_artifact", _forbidden)
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        _write(token_path, state_path)
    error = caught.value
    assert error.code == "production_write_token_bundle_lock_unverified"
    assert error.publication_possible is (completed > 0)
    assert error.completed_output_count == completed and held == []
    assert state_path.exists() is (completed >= 1)
    assert token_path.exists() is (completed == 2)
    _safe(error, tmp_path)


@pytest.mark.parametrize("index", (0, 1))
@pytest.mark.parametrize(
    "evidence", (False, True, None, "invalid"), ids=("before", "after", "unknown", "invalid")
)
def test_writer_error_retains_evidence_and_prior_outputs_without_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, index: int, evidence: bool | str | None
) -> None:
    token_path, state_path = _paths(tmp_path)
    _, held, trace = _instrument(monkeypatch)
    writes: list[Path] = []

    def writer(_value: Any, path: Path, **_kw: Any) -> Path:
        count = len(writes)
        writes.append(path)
        if count != index or evidence is not False:
            path.write_bytes(b"retained synthetic output")
        if count == index:
            error = token_io.ProductionWriteTokenIOError(
                "synthetic", "PRIVATE_LOCK_MARKER", publication_possible=None
            )
            error.publication_possible = evidence
            raise error
        trace.append("state")
        return path

    monkeypatch.setattr(token_io, "write_production_write_token_generation_state", writer)
    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", writer)
    monkeypatch.setattr(token_io, "_remove_exact_new_artifact", _forbidden)
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        _write(token_path, state_path)
    error = caught.value
    assert error.code == "production_write_token_bundle_write_failed"
    expected = True if index else evidence if type(evidence) is bool else None
    assert error.publication_possible is expected
    assert error.completed_output_count == index and held == []
    assert writes == [state_path, token_path][: index + 1]
    assert state_path.exists() is (index > 0 or evidence is not False)
    assert token_path.exists() is (index == 1 and evidence is not False)
    _safe(error, tmp_path)


@pytest.mark.parametrize("index", (0, 1))
@pytest.mark.parametrize("interrupt", (KeyboardInterrupt, SystemExit))
def test_base_exception_is_not_converted_and_locks_are_released(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, index: int, interrupt: type[BaseException]
) -> None:
    token_path, state_path = _paths(tmp_path, split=True)
    _, held, _ = _instrument(monkeypatch)
    calls: list[Path] = []
    problem = interrupt()

    def writer(_value: Any, path: Path, **_kw: Any) -> Path:
        calls.append(path)
        if len(calls) == index + 1:
            raise problem
        path.write_bytes(b"retained synthetic state")
        return path

    monkeypatch.setattr(token_io, "write_production_write_token_generation_state", writer)
    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", writer)
    monkeypatch.setattr(token_io, "_remove_exact_new_artifact", _forbidden)
    with pytest.raises(interrupt) as caught:
        _write(token_path, state_path)
    assert caught.value is problem and held == []
    assert state_path.exists() is (index == 1) and not token_path.exists()


def test_windows_does_not_enter_new_bundle_lock_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    token_path, state_path = _paths(tmp_path)
    calls: list[Path] = []
    monkeypatch.setattr(token_io, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(token_io, "_production_write_session_lock", _forbidden)
    monkeypatch.setattr(token_io, "_write_posix_token_bundle", _forbidden)

    def writer(_value: Any, path: Path, **_kw: Any) -> Path:
        calls.append(path)
        return path

    monkeypatch.setattr(token_io, "write_production_write_token_generation_state", writer)
    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", writer)
    assert _write(token_path, state_path) == (token_path, state_path)
    assert calls == [state_path, token_path]


@LINUX_ONLY
@pytest.mark.parametrize("split", (False, True))
def test_native_pair_roundtrip_and_held_locks_release(tmp_path: Path, split: bool) -> None:
    token_path, state_path = _paths(tmp_path, split=split)
    token, state = _pair()
    assert _write(token_path, state_path) == (token_path, state_path)
    assert token_io.load_production_write_authorized_user_token(token_path) == token
    assert token_io.load_production_write_token_generation_state(state_path) == state
    for parent in {token_path.parent, state_path.parent}:
        with locking.acquire_posix_private_directory_lock(parent):
            assert all(not p.name.startswith(".private") for p in parent.iterdir())


@LINUX_ONLY
@pytest.mark.parametrize("parent_index", (0, 1))
def test_native_busy_is_before_any_publication(tmp_path: Path, parent_index: int) -> None:
    token_path, state_path = _paths(tmp_path, split=True)
    parents = sorted({token_path.parent, state_path.parent}, key=os.fspath)
    with locking.acquire_posix_private_directory_lock(parents[parent_index]):
        with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
            _write(token_path, state_path)
        assert caught.value.code == "production_write_token_bundle_busy"
        assert caught.value.publication_possible is False
        assert not token_path.exists() and not state_path.exists()
        if parent_index:
            with locking.acquire_posix_private_directory_lock(parents[0]):
                pass


@LINUX_ONLY
@pytest.mark.parametrize("split", (False, True))
def test_native_bundle_blocks_existing_session_during_state_first_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, split: bool
) -> None:
    token_path, state_path = _paths(tmp_path, split=split)
    _write(token_path, state_path)
    new_token = token_path.with_name("new-token.json")
    new_state = state_path.with_name("new-state.json")
    ready, release = Event(), Event()
    original = token_io.write_production_write_token_generation_state

    def paused(*args: Any, **kw: Any) -> Path:
        result = original(*args, **kw)
        ready.set()
        assert release.wait(10)
        return result

    monkeypatch.setattr(token_io, "write_production_write_token_generation_state", paused)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_write, new_token, new_state)
        try:
            assert ready.wait(10)
            assert new_state.exists() and not new_token.exists()
            with monkeypatch.context() as scoped:
                scoped.setattr(token_io, "load_production_write_authorized_user_token", _forbidden)
                scoped.setattr(token_io, "load_production_write_token_generation_state", _forbidden)
                with pytest.raises(tokens.ProductionWriteTokenSessionLockError) as caught:
                    tokens._load_production_write_credential_session(
                        token_path,
                        state_path,
                        token_path.with_name("read.json"),
                        token_path.with_name("test.json"),
                        production_target(),
                        now=ISSUED_AT + timedelta(seconds=2),
                        evidence_mode="test",
                    )
                assert caught.value.code == "production_write_token_session_busy"
        finally:
            release.set()
        assert future.result(timeout=10) == (new_token, new_state)
    session = tokens._load_production_write_credential_session(
        token_path,
        state_path,
        token_path.with_name("read.json"),
        token_path.with_name("test.json"),
        production_target(),
        now=ISSUED_AT + timedelta(seconds=2),
        evidence_mode="test",
    )
    assert session.refresh_count == 0


@LINUX_ONLY
def test_native_separate_process_cannot_publish_under_held_session_protocol(tmp_path: Path) -> None:
    token_path, state_path = _paths(tmp_path, split=True)
    code = """
import sys
from pathlib import Path
from phase6d0_auth_helpers import ISSUED_AT, production_target, production_token
from tridentine_calendar_google_sync import production_write_token as t
from tridentine_calendar_google_sync import production_write_token_io as io
state = t.build_initial_production_write_token_generation_state(
    production_target(), issued_at=ISSUED_AT)
try:
    io.write_production_write_token_bundle(
        production_token(state), Path(sys.argv[1]), state, Path(sys.argv[2]))
except io.ProductionWriteTokenIOError as exc:
    sys.exit(0 if exc.code == 'production_write_token_bundle_busy' else 2)
sys.exit(3)
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join(
        [str(Path(tokens.__file__).resolve().parents[1]), str(Path(__file__).resolve().parent)]
    )
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    with tokens._production_write_session_lock(token_path, state_path):
        result = subprocess.run(
            [sys.executable, "-c", code, str(token_path), str(state_path)],
            env=env,
            capture_output=True,
            stdin=subprocess.DEVNULL,
            check=False,
            timeout=10,
        )
    assert result.returncode == 0
    assert not token_path.exists() and not state_path.exists()


def test_only_bundle_wrapper_newly_acquires_shared_lock_and_never_cleans() -> None:
    tree = ast.parse(Path(token_io.__file__).read_text(encoding="utf-8"))
    consumers = []
    for fn in tree.body:
        if not isinstance(fn, ast.FunctionDef):
            continue
        calls = {
            n.func.id
            for n in ast.walk(fn)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        }
        if "_production_write_session_lock" in calls:
            consumers.append(fn.name)
            assert not calls & {"_remove_exact_new_artifact", "remove_sensitive_file_if_matches"}
            assert not any(isinstance(n, ast.While) for n in ast.walk(fn))
            assert not {
                n.func.attr
                for n in ast.walk(fn)
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
            } & {"unlink", "remove", "rename", "replace", "chmod"}
    assert consumers == ["_write_posix_token_bundle"]
