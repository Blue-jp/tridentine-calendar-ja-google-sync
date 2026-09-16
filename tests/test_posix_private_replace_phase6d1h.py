"""Synthetic independent replacement tests; not refresh, CAS or recovery approval."""

from __future__ import annotations

import ast
import errno
import os
import stat
import traceback
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tridentine_calendar_google_sync import _posix_private_replace as replacement
from tridentine_calendar_google_sync import sensitive_paths

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="real POSIX private replacement")
OLD = b"SYNTHETIC_PRIVATE_OLD"
NEW = b"SYNTHETIC_PRIVATE_NEW"


def _stored(tmp_path: Path, content: bytes = OLD) -> Path:
    parent = tmp_path / "private-replacement"
    parent.mkdir(mode=0o700)
    path = parent / "token.json"
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def _proxy(**updates: Any) -> SimpleNamespace:
    values = {name: getattr(os, name) for name in dir(os)}
    values.update(updates)
    return SimpleNamespace(**values)


def _call(path: Path, content: bytes = NEW, expected: bytes = OLD) -> None:
    replacement.replace_posix_private_bytes(path, content, expected_content=expected)


def _safe(error: replacement.PosixPrivateReplaceError, path: Path, attempted: bool) -> None:
    assert error.publication_possible is attempted
    assert error.__cause__ is None and error.__suppress_context__
    text = "".join(traceback.format_exception(error))
    for secret in (str(path), OLD.decode(), NEW.decode(), "PRIVATE_OS_MARKER"):
        assert secret not in text
    assert "do not retry, remove, or restore" in text


def _closed(fds: list[int]) -> None:
    for fd in fds:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF


@POSIX_ONLY
@pytest.mark.parametrize(
    "prior,after",
    ((OLD, NEW), (b"", NEW), (OLD, b""), (OLD, OLD), (OLD, b"x" * 131073)),
    ids=("changed", "empty-old", "empty-new", "identical", "large-131073"),
)
def test_roundtrip_is_new_private_single_link_file_without_temporary(
    tmp_path: Path, prior: bytes, after: bytes
) -> None:
    path = _stored(tmp_path, prior)
    before = path.stat()
    _call(path, after, prior)
    result = path.stat()
    assert (result.st_dev, result.st_ino) != (before.st_dev, before.st_ino)
    assert path.read_bytes() == after
    assert result.st_uid == os.geteuid() and stat.S_IMODE(result.st_mode) == 0o600
    assert result.st_nlink == 1 and list(path.parent.iterdir()) == [path]


@POSIX_ONLY
@pytest.mark.parametrize(
    "kind", ("missing", "directory", "symlink", "dangling", "fifo", "hardlink")
)
def test_unsafe_or_missing_target_is_not_replaced_created_or_removed(
    tmp_path: Path, kind: str
) -> None:
    path = _stored(tmp_path)
    if kind != "hardlink":
        path.unlink()  # Synthetic setup only.
    if kind == "directory":
        path.mkdir(mode=0o700)
    elif kind in ("symlink", "dangling"):
        other = path.parent / "other"
        if kind == "symlink":
            other.write_bytes(OLD)
        path.symlink_to(other)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    elif kind == "hardlink":
        os.link(path, path.parent / "alias")
    names = sorted(p.name for p in path.parent.iterdir())
    with pytest.raises(replacement.PosixPrivateReplaceError) as caught:
        _call(path)
    _safe(caught.value, path, False)
    assert sorted(p.name for p in path.parent.iterdir()) == names


@POSIX_ONLY
@pytest.mark.parametrize("mode", (0o400, 0o640, 0o606, 0o4600))
def test_existing_permissions_rejected_without_repair(tmp_path: Path, mode: int) -> None:
    path = _stored(tmp_path)
    path.chmod(mode)
    with pytest.raises(replacement.PosixPrivateReplaceError) as caught:
        _call(path)
    _safe(caught.value, path, False)
    assert path.read_bytes() == OLD and stat.S_IMODE(path.stat().st_mode) == mode
    assert list(path.parent.iterdir()) == [path]


@POSIX_ONLY
@pytest.mark.parametrize("expected", (b"different", b"Z" * len(OLD)), ids=("size", "same-size"))
def test_expected_mismatch_stops_before_any_temporary(tmp_path: Path, expected: bytes) -> None:
    path = _stored(tmp_path)
    with pytest.raises(replacement.PosixPrivateReplaceError) as caught:
        _call(path, expected=expected)
    _safe(caught.value, path, False)
    assert path.read_bytes() == OLD and list(path.parent.iterdir()) == [path]


@POSIX_ONLY
def test_relative_syscalls_keep_old_and_new_descriptors_and_sync_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _stored(tmp_path)
    calls: list[str] = []
    fds: list[int] = []

    def opened(name: str, flags: int, *args: Any, **kwargs: Any) -> int:
        assert "/" not in name and kwargs["dir_fd"] >= 0
        assert flags & os.O_NOFOLLOW and flags & os.O_CLOEXEC
        fd = os.open(name, flags, *args, **kwargs)
        assert not os.get_inheritable(fd)
        fds.append(fd)
        calls.append("new" if flags & os.O_CREAT else "old")
        return fd

    def synced(fd: int) -> None:
        calls.append("directory-fsync" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file-fsync")
        os.fsync(fd)

    def replaced(src: str, dst: str, **kwargs: Any) -> None:
        assert len(fds) == 2 and all(os.fstat(fd).st_nlink == 1 for fd in fds)
        assert kwargs["src_dir_fd"] == kwargs["dst_dir_fd"]
        assert "/" not in src and dst == path.name
        calls.append("replace")
        os.replace(src, dst, **kwargs)
        assert os.fstat(fds[0]).st_nlink == 0 and os.fstat(fds[1]).st_nlink == 1

    monkeypatch.setattr(replacement, "os", _proxy(open=opened, fsync=synced, replace=replaced))
    _call(path)
    assert calls == ["old", "new", "file-fsync", "replace", "directory-fsync"]
    _closed(fds)


@POSIX_ONLY
def test_short_writes_and_reads_are_handled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _stored(tmp_path)
    monkeypatch.setattr(replacement, "os", _proxy(write=lambda fd, b: os.write(fd, b[:2])))
    native = replacement.create.os
    proxy = SimpleNamespace(**{name: getattr(native, name) for name in dir(native)})
    proxy.pread = lambda fd, size, offset: os.pread(fd, min(size, 3), offset)
    monkeypatch.setattr(replacement.create, "os", proxy)
    _call(path)
    assert path.read_bytes() == NEW


@POSIX_ONLY
@pytest.mark.parametrize("failure", ("prepare", "write", "zero", "oversize", "file_fsync"))
def test_pre_replace_failure_retains_old_target_and_private_temporary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    path = _stored(tmp_path)

    def failed(*_a: Any, **_kw: Any) -> Any:
        raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(path))

    def never_replace(*_a: Any, **_kw: Any) -> None:
        raise AssertionError("must stop before replace")

    options: dict[str, Any] = {"replace": never_replace}
    if failure == "prepare":
        monkeypatch.setattr(replacement, "_prepare_posix_private_output_fd", failed)
    elif failure == "zero":
        options["write"] = lambda *_a: 0
    elif failure == "oversize":
        options["write"] = lambda _fd, b: len(b) + 1
    else:
        options["fsync" if failure == "file_fsync" else "write"] = failed
    monkeypatch.setattr(replacement, "os", _proxy(**options))
    with pytest.raises(replacement.PosixPrivateReplaceError) as caught:
        _call(path)
    _safe(caught.value, path, False)
    assert path.read_bytes() == OLD
    temps = list(path.parent.glob(".private-replace-*"))
    assert len(temps) == 1 and stat.S_IMODE(temps[0].stat().st_mode) == 0o600


@POSIX_ONLY
@pytest.mark.parametrize(
    "failure", ("before", "after", "unexpected-after", "dirsync", "post-content")
)
def test_after_replace_attempt_always_uncertain_and_no_automatic_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    path = _stored(tmp_path)
    attempts: list[int] = []

    def replaced(src: str, dst: str, **kwargs: Any) -> None:
        attempts.append(1)
        if failure == "before":
            raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(path))
        os.replace(src, dst, **kwargs)
        if failure == "after":
            raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(path))
        if failure == "unexpected-after":
            raise RuntimeError("PRIVATE_OS_MARKER")
        if failure == "post-content":
            path.write_bytes(b"competitor remains")

    def synced(fd: int) -> None:
        if failure == "dirsync" and stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(path))
        os.fsync(fd)

    monkeypatch.setattr(replacement, "os", _proxy(replace=replaced, fsync=synced))
    with pytest.raises(replacement.PosixPrivateReplaceError) as caught:
        _call(path)
    _safe(caught.value, path, True)
    assert attempts == [1]
    expected = (
        OLD if failure == "before" else b"competitor remains" if failure == "post-content" else NEW
    )
    assert path.read_bytes() == expected


@POSIX_ONLY
@pytest.mark.parametrize(
    "change", ("content", "same-content-new-inode", "permissions", "parent", "temporary")
)
def test_observed_change_before_rename_stops_and_preserves_competitor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    path = _stored(tmp_path)
    moved = tmp_path / "moved-private"
    renamed: list[int] = []

    def synced(fd: int) -> None:
        os.fsync(fd)
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            return
        if change == "content":
            path.write_bytes(b"observed competitor")
        elif change == "same-content-new-inode":
            path.rename(path.with_name("old-inode"))
            path.write_bytes(OLD)
            path.chmod(0o600)
        elif change == "permissions":
            path.chmod(0o640)
        elif change == "parent":
            path.parent.rename(moved)
            path.parent.mkdir(mode=0o700)
        else:
            temporary = next(path.parent.glob(".private-replace-*"))
            temporary.rename(path.parent / "retained-original-temporary")
            temporary.write_bytes(b"temporary competitor")
            temporary.chmod(0o600)

    monkeypatch.setattr(
        replacement, "os", _proxy(fsync=synced, replace=lambda *_a, **_kw: renamed.append(1))
    )
    with pytest.raises(replacement.PosixPrivateReplaceError) as caught:
        _call(path)
    _safe(caught.value, path, False)
    assert renamed == []
    if change == "parent":
        assert (moved / path.name).read_bytes() == OLD and not path.exists()
    else:
        assert path.read_bytes() == (b"observed competitor" if change == "content" else OLD)
    if change == "temporary":
        assert next(path.parent.glob(".private-replace-*")).read_bytes() == b"temporary competitor"


@POSIX_ONLY
def test_leaf_rebound_between_stat_and_open_is_rejected_without_temporary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _stored(tmp_path)
    fds: list[int] = []

    def opened(name: str, flags: int, *args: Any, **kwargs: Any) -> int:
        if name == path.name:
            path.rename(path.with_name("held-prior"))
            path.write_bytes(OLD)
            path.chmod(0o600)
        fd = os.open(name, flags, *args, **kwargs)
        fds.append(fd)
        return fd

    monkeypatch.setattr(replacement, "os", _proxy(open=opened))
    with pytest.raises(replacement.PosixPrivateReplaceError) as caught:
        _call(path)
    assert caught.value.code == "posix_replace_original_changed"
    _safe(caught.value, path, False)
    _closed(fds)
    assert not list(path.parent.glob(".private-replace-*"))


@POSIX_ONLY
def test_same_uid_last_moment_race_is_not_misrepresented_as_compare_and_swap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _stored(tmp_path)

    def raced(src: str, dst: str, **kwargs: Any) -> None:
        # This is deliberately outside the guarantee: checks and rename are not CAS.
        path.unlink()
        path.write_bytes(b"last-moment-competitor")
        path.chmod(0o600)
        os.replace(src, dst, **kwargs)

    monkeypatch.setattr(replacement, "os", _proxy(replace=raced))
    _call(path)
    assert path.read_bytes() == NEW  # No false promise of preserving all same-UID races.


@POSIX_ONLY
@pytest.mark.parametrize("missing", ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK", "pread", "replace"))
def test_missing_primitive_stops_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, missing: str
) -> None:
    path = _stored(tmp_path)
    monkeypatch.setattr(
        replacement, "os", _proxy(**{missing: 0 if missing.startswith("O_") else None})
    )
    with pytest.raises(replacement.PosixPrivateReplaceError) as caught:
        _call(path)
    _safe(caught.value, path, False)
    assert caught.value.code == "posix_replace_unavailable"
    assert list(path.parent.iterdir()) == [path] and path.read_bytes() == OLD


@POSIX_ONLY
def test_cancel_closes_retained_descriptors_without_deleting_names(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _stored(tmp_path)
    fds: list[int] = []

    def opened(*args: Any, **kwargs: Any) -> int:
        fd = os.open(*args, **kwargs)
        fds.append(fd)
        return fd

    def interrupted(*_a: Any, **_kw: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(replacement, "os", _proxy(open=opened, write=interrupted))
    with pytest.raises(KeyboardInterrupt):
        _call(path)
    _closed(fds)
    assert path.read_bytes() == OLD and len(list(path.parent.glob(".private-replace-*"))) == 1


@POSIX_ONLY
@pytest.mark.parametrize("invalid", ("relative", "parent", "double-anchor", "root", "git", "nul"))
def test_invalid_paths_do_not_mutate(tmp_path: Path, invalid: str) -> None:
    paths = {
        "relative": Path("relative"),
        "parent": tmp_path / "x" / ".." / "y",
        "double-anchor": Path("//server/path"),
        "root": Path("/"),
        "git": tmp_path / ".git",
        "nul": tmp_path / "bad\x00name",
    }
    with pytest.raises(replacement.PosixPrivateReplaceError) as caught:
        _call(paths[invalid])
    assert not caught.value.publication_possible


@POSIX_ONLY
@pytest.mark.parametrize("which", ("content", "expected"))
@pytest.mark.parametrize("invalid", ("type", "size"))
def test_invalid_content_is_bounded_before_any_io(tmp_path: Path, which: str, invalid: str) -> None:
    path = _stored(tmp_path)
    value = (
        "not bytes" if invalid == "type" else b"x" * (sensitive_paths.MAX_SENSITIVE_FILE_BYTES + 1)
    )
    with pytest.raises(replacement.PosixPrivateReplaceError) as caught:
        _call(
            path,
            content=value if which == "content" else NEW,
            expected=value if which == "expected" else OLD,
        )
    assert caught.value.code == "posix_replace_content_invalid"
    assert list(path.parent.iterdir()) == [path]


def test_non_posix_never_enters_filesystem_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_a: Any, **_kw: Any) -> Any:
        raise AssertionError("Windows must not enter independent POSIX backend")

    monkeypatch.setattr(replacement, "os", SimpleNamespace(name="nt", open=forbidden))
    with pytest.raises(replacement.PosixPrivateReplaceError) as caught:
        _call(Path("unused"))
    assert (
        caught.value.code == "posix_replace_unavailable" and not caught.value.publication_possible
    )


def test_backend_is_independent_and_has_no_cleanup_or_path_permission_repair() -> None:
    tree = ast.parse(Path(replacement.__file__).read_text(encoding="utf-8"))
    calls = {
        n.func.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert "replace" in calls
    assert not calls & {
        "unlink",
        "remove",
        "rename",
        "chmod",
        "chown",
        "mkdir",
        "mkstemp",
        "run",
        "Popen",
    }
    for module in Path(replacement.__file__).parent.glob("*.py"):
        if module.name != "_posix_private_replace.py":
            assert "_posix_private_replace" not in module.read_text(encoding="utf-8")
