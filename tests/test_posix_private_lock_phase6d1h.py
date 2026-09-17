"""Synthetic nonblocking advisory-lock checks; no refresh or operational approval."""

from __future__ import annotations

import ast
import errno
import os
import subprocess
import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tridentine_calendar_google_sync import _posix_private_lock as locking
from tridentine_calendar_google_sync import _posix_sensitive_directory as directory

LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="real Linux advisory flock")


def _private(tmp_path: Path) -> Path:
    root = tmp_path / "private-lock-fixture"
    root.mkdir(mode=0o700)
    return root


def _safe(error: BaseException, path: Path) -> None:
    text = "".join(traceback.format_exception(error))
    assert str(path) not in text and "PRIVATE_LOCK_MARKER" not in text
    assert "do not proceed unlocked" in str(error)


def _probe(path: Path) -> str:
    code = """
import sys
from pathlib import Path
from tridentine_calendar_google_sync._posix_private_lock import (
    PosixPrivateLockError, acquire_posix_private_directory_lock,
)
try:
    with acquire_posix_private_directory_lock(Path(sys.argv[1])) as held:
        held.revalidate()
except PosixPrivateLockError as exc:
    print(exc.code)
else:
    print('acquired')
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(locking.__file__).resolve().parents[1])
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-S", "-c", code, str(path)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=env,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0 and not result.stderr
    return result.stdout.decode().strip()


@LINUX_ONLY
def test_lock_roundtrip_has_no_files_permission_repair_or_directory_mutation(
    tmp_path: Path,
) -> None:
    root = _private(tmp_path)
    before = root.stat()
    with locking.acquire_posix_private_directory_lock(root) as held:
        held.revalidate()
        during = root.stat()
        assert list(root.iterdir()) == []
        assert (before.st_ino, before.st_mode, before.st_mtime_ns, before.st_ctime_ns) == (
            during.st_ino,
            during.st_mode,
            during.st_mtime_ns,
            during.st_ctime_ns,
        )
        assert _probe(root) == "posix_directory_lock_busy"
    assert _probe(root) == "acquired"
    assert list(root.iterdir()) == []
    held.close()
    with pytest.raises(locking.PosixPrivateLockError) as caught:
        held.revalidate()
    assert caught.value.code == "posix_directory_lock_closed"


@LINUX_ONLY
def test_second_open_in_same_process_and_other_thread_are_busy(tmp_path: Path) -> None:
    root = _private(tmp_path)

    def contender() -> str:
        try:
            with locking.acquire_posix_private_directory_lock(root):
                return "acquired"
        except locking.PosixPrivateLockError as exc:
            return exc.code

    with locking.acquire_posix_private_directory_lock(root):
        assert contender() == "posix_directory_lock_busy"
        with ThreadPoolExecutor(max_workers=2) as executor:
            assert list(executor.map(lambda _: contender(), (0, 1))) == [
                "posix_directory_lock_busy",
                "posix_directory_lock_busy",
            ]
    assert contender() == "acquired"


@LINUX_ONLY
def test_distinct_directories_do_not_contend(tmp_path: Path) -> None:
    first = _private(tmp_path)
    second = tmp_path / "second"
    second.mkdir(mode=0o700)
    with locking.acquire_posix_private_directory_lock(first):
        assert _probe(second) == "acquired"
        assert _probe(first) == "posix_directory_lock_busy"


@LINUX_ONLY
@pytest.mark.parametrize("failure", (RuntimeError, KeyboardInterrupt))
def test_context_closes_on_body_error_and_cancellation(
    tmp_path: Path, failure: type[BaseException]
) -> None:
    root = _private(tmp_path)
    original = failure("synthetic body exception")
    with pytest.raises(failure) as caught, locking.acquire_posix_private_directory_lock(root):
        raise original
    assert caught.value is original
    assert _probe(root) == "acquired"


@LINUX_ONLY
def test_nested_reuse_rejected_without_releasing_outer_lock(tmp_path: Path) -> None:
    root = _private(tmp_path)
    held = locking.acquire_posix_private_directory_lock(root)
    with held:
        with pytest.raises(locking.PosixPrivateLockError) as caught, held:
            pytest.fail("nested reuse must not enter")
        assert caught.value.code == "posix_directory_lock_not_reentrant"
        held.revalidate()
        assert _probe(root) == "posix_directory_lock_busy"
    assert _probe(root) == "acquired"


@LINUX_ONLY
@pytest.mark.parametrize("change", ("mode", "marker", "rename"))
def test_revalidation_failure_closes_without_repair_or_deletion(
    tmp_path: Path, change: str
) -> None:
    root = _private(tmp_path)
    held = locking.acquire_posix_private_directory_lock(root)
    probe_path = root
    if change == "mode":
        root.chmod(0o750)
    elif change == "marker":
        (root / ".git").mkdir()
    else:
        probe_path = tmp_path / "moved"
        root.rename(probe_path)
        root.mkdir(mode=0o700)
    with pytest.raises(locking.PosixPrivateLockError) as caught:
        held.revalidate()
    _safe(caught.value, root)
    with pytest.raises(locking.PosixPrivateLockError) as closed:
        held.revalidate()
    assert closed.value.code == "posix_directory_lock_closed"
    if change == "mode":
        assert root.stat().st_mode & 0o777 == 0o750
        root.chmod(0o700)  # Restore only this synthetic fixture after verifying no repair.
    elif change == "marker":
        assert (root / ".git").is_dir()
        (root / ".git").rmdir()  # Synthetic marker; the implementation never removes it.
    assert _probe(probe_path) == "acquired"


@LINUX_ONLY
@pytest.mark.parametrize("kind", ("missing", "mode", "marker", "symlink"))
def test_unsafe_directory_stops_before_lock_syscall(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    root = _private(tmp_path)
    if kind == "missing":
        root = root / "absent"
    elif kind == "mode":
        root.chmod(0o755)
    elif kind == "marker":
        (root / ".git").write_text("unread marker")
    else:
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
        root = alias
    calls: list[int] = []
    monkeypatch.setattr(locking, "_lock_once", lambda fd: calls.append(fd))
    with pytest.raises(locking.PosixPrivateLockError) as caught:
        locking.acquire_posix_private_directory_lock(root)
    _safe(caught.value, root)
    assert calls == []


@LINUX_ONLY
@pytest.mark.parametrize(
    "failure", ("busy", "denied", "unsupported", "acquired_then_error", "cancel")
)
def test_failed_acquisition_closes_all_opened_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    root = _private(tmp_path)
    descriptors: list[int] = []
    native = locking._lock_once
    real_open = os.open
    proxy = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})

    def opened(*args: Any, **kwargs: Any) -> int:
        fd = real_open(*args, **kwargs)
        descriptors.append(fd)
        return fd

    def failed(fd: int) -> None:
        if failure == "cancel":
            raise KeyboardInterrupt
        if failure == "acquired_then_error":
            native(fd)
        number = (
            errno.EAGAIN
            if failure == "busy"
            else errno.ENOSYS
            if failure == "unsupported"
            else errno.EACCES
        )
        raise OSError(number, "PRIVATE_LOCK_MARKER", str(root))

    proxy.open = opened
    monkeypatch.setattr(directory, "os", proxy)
    monkeypatch.setattr(locking, "_lock_once", failed)
    if failure == "cancel":
        with pytest.raises(KeyboardInterrupt):
            locking.acquire_posix_private_directory_lock(root)
    else:
        with pytest.raises(locking.PosixPrivateLockError) as caught:
            locking.acquire_posix_private_directory_lock(root)
        _safe(caught.value, root)
        assert caught.value.code == (
            "posix_directory_lock_busy" if failure == "busy" else "posix_directory_lock_unverified"
        )
    assert descriptors
    for fd in descriptors:
        with pytest.raises(OSError) as closed:
            os.fstat(fd)
        assert closed.value.errno == errno.EBADF
    assert _probe(root) == "acquired"


@LINUX_ONLY
def test_directory_change_during_acquire_is_rechecked_and_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _private(tmp_path)
    moved = tmp_path / "moved"
    native = locking._lock_once

    def replaced(fd: int) -> None:
        native(fd)
        root.rename(moved)
        root.mkdir(mode=0o700)

    monkeypatch.setattr(locking, "_lock_once", replaced)
    with pytest.raises(locking.PosixPrivateLockError):
        locking.acquire_posix_private_directory_lock(root)
    assert _probe(root) == _probe(moved) == "acquired"


@LINUX_ONLY
def test_advisory_lock_does_not_prevent_noncooperating_write(tmp_path: Path) -> None:
    root = _private(tmp_path)
    with locking.acquire_posix_private_directory_lock(root) as held:
        # This documents the limitation: ordinary I/O ignores the lock.
        (root / "noncooperating.txt").write_text("synthetic competitor")
        held.revalidate()
        assert _probe(root) == "posix_directory_lock_busy"
    assert (root / "noncooperating.txt").read_text() == "synthetic competitor"


@LINUX_ONLY
def test_renamed_directory_keeps_its_inode_lock_but_new_inode_has_different_lock(
    tmp_path: Path,
) -> None:
    root = _private(tmp_path)
    moved = tmp_path / "moved"
    held = locking.acquire_posix_private_directory_lock(root)
    try:
        root.rename(moved)
        root.mkdir(mode=0o700)
        assert _probe(root) == "acquired"  # Name reuse does not preserve the lock identity.
        assert _probe(moved) == "posix_directory_lock_busy"
        with pytest.raises(locking.PosixPrivateLockError):
            held.revalidate()
    finally:
        held.close()
    assert _probe(moved) == "acquired"


@LINUX_ONLY
def test_abrupt_subprocess_exit_releases_its_unshared_descriptors(tmp_path: Path) -> None:
    root = _private(tmp_path)
    code = """
import os, sys
from pathlib import Path
from tridentine_calendar_google_sync._posix_private_lock import acquire_posix_private_directory_lock
held = acquire_posix_private_directory_lock(Path(sys.argv[1]))
print('held', flush=True)
sys.stdin.buffer.read(1)
os._exit(0)
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(locking.__file__).resolve().parents[1])
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    process = subprocess.Popen(
        [sys.executable, "-S", "-c", code, str(root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    try:
        assert process.stdout is not None and process.stdin is not None
        # Bound the handshake without a sleeps/timing race in the lock assertions.
        with ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(process.stdout.readline)
            try:
                assert future.result(timeout=10) == b"held\n"
            except BaseException:
                process.kill()
                raise
        assert _probe(root) == "posix_directory_lock_busy"
        stdout, stderr = process.communicate(b"x", timeout=10)
        assert process.returncode == 0 and stdout == stderr == b""
        assert _probe(root) == "acquired"
    finally:
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=10)


@LINUX_ONLY
def test_fork_child_revalidation_closes_only_child_copy_and_does_not_unlock_parent(
    tmp_path: Path,
) -> None:
    root = _private(tmp_path)
    code = """
import os, sys
from pathlib import Path
from tridentine_calendar_google_sync._posix_private_lock import (
    PosixPrivateLockError, acquire_posix_private_directory_lock,
)
p = Path(sys.argv[1])
held = acquire_posix_private_directory_lock(p)
child = os.fork()
if child == 0:
    try:
        held.revalidate()
    except PosixPrivateLockError as exc:
        os._exit(0 if exc.code == 'posix_directory_lock_process_changed' else 2)
    os._exit(3)
_, status = os.waitpid(child, 0)
assert os.waitstatus_to_exitcode(status) == 0
try:
    contender = acquire_posix_private_directory_lock(p)
except PosixPrivateLockError as exc:
    assert exc.code == 'posix_directory_lock_busy'
else:
    contender.close()
    raise AssertionError('child improperly released parent lock')
held.close()
with acquire_posix_private_directory_lock(p):
    pass
print('fork-check-ok')
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(locking.__file__).resolve().parents[1])
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-S", "-c", code, str(root)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=env,
        timeout=10,
        check=False,
    )
    assert result.returncode == 0 and result.stdout == b"fork-check-ok\n" and not result.stderr


@pytest.mark.parametrize("platform", ("win32", "darwin", "freebsd14"))
def test_unsupported_platform_has_no_fallback_or_directory_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    monkeypatch.setattr(locking, "sys", SimpleNamespace(platform=platform))

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("unavailable platform must not open or lock")

    monkeypatch.setattr(directory, "open_posix_private_directory", forbidden)
    monkeypatch.setattr(locking, "_lock_once", forbidden)
    with pytest.raises(locking.PosixPrivateLockError) as caught:
        locking.acquire_posix_private_directory_lock(tmp_path)
    assert caught.value.code == "posix_directory_lock_unavailable"


def test_component_has_no_artifact_write_no_wait_loop_and_no_runtime_consumer() -> None:
    source_path = Path(locking.__file__)
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    attributes = {
        n.func.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert not attributes & {
        "mkdir",
        "unlink",
        "remove",
        "rename",
        "replace",
        "write",
        "write_text",
        "write_bytes",
        "chmod",
        "fchmod",
        "sleep",
        "dup",
        "dup2",
        "fork",
    }
    assert not any(isinstance(n, (ast.While, ast.For)) for n in ast.walk(tree))
    for path in source_path.parent.glob("*.py"):
        if path != source_path:
            assert "_posix_private_lock" not in path.read_text(encoding="utf-8")


@LINUX_ONLY
def test_native_acquisition_uses_one_exclusive_nonblocking_flock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[int, int]] = []
    import fcntl

    monkeypatch.setattr(fcntl, "flock", lambda fd, op: calls.append((fd, op)))
    locking._lock_once(123)
    assert calls == [(123, fcntl.LOCK_EX | fcntl.LOCK_NB)]
