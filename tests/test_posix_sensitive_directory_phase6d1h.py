"""Synthetic directory binding tests, not writer/cleanup approval or live access."""

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

from tridentine_calendar_google_sync import _posix_sensitive_directory as directory

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="real POSIX directory descriptors")


def _proxy(**updates: Any) -> SimpleNamespace:
    names = (
        "name",
        "stat",
        "fstat",
        "open",
        "close",
        "geteuid",
        "O_RDONLY",
        "O_NOFOLLOW",
        "O_DIRECTORY",
        "O_CLOEXEC",
    )
    values = {name: getattr(os, name, None) for name in names}
    values.update(updates)
    return SimpleNamespace(**values)


def _private(tmp_path: Path) -> Path:
    parent = tmp_path / "private-directory"
    parent.mkdir(mode=0o700)
    return parent


def _assert_closed(descriptors: list[int]) -> None:
    for descriptor in descriptors:
        with pytest.raises(OSError) as captured:
            os.fstat(descriptor)
        assert captured.value.errno == errno.EBADF


def _record_opens(monkeypatch: pytest.MonkeyPatch, **updates: Any) -> list[int]:
    descriptors: list[int] = []

    def recorded_open(*args: Any, **kwargs: Any) -> int:
        descriptor = os.open(*args, **kwargs)
        descriptors.append(descriptor)
        return descriptor

    monkeypatch.setattr(directory, "os", _proxy(open=recorded_open, **updates))
    return descriptors


@POSIX_ONLY
def test_private_directory_revalidates_and_closes_every_ancestor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = _private(tmp_path)
    descriptors = _record_opens(monkeypatch)
    with directory.open_posix_private_directory(parent) as bound:
        assert (os.fstat(bound.descriptor).st_dev, os.fstat(bound.descriptor).st_ino) == (
            parent.stat().st_dev,
            parent.stat().st_ino,
        )
        bound.revalidate()
        assert not os.get_inheritable(bound.descriptor)
        assert len(descriptors) == len(parent.parts)
    _assert_closed(descriptors)
    bound.close()
    with pytest.raises(directory.PosixSensitiveDirectoryError) as captured:
        _ = bound.descriptor
    assert captured.value.code == "posix_directory_binding_closed"
    assert list(parent.iterdir()) == []


@POSIX_ONLY
def test_all_child_opens_are_relative_no_follow_and_directory_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = _private(tmp_path)
    calls: list[tuple[str, int, int | None]] = []

    def recorded_open(path: str, flags: int, *, dir_fd: int | None = None) -> int:
        calls.append((path, flags, dir_fd))
        return os.open(path, flags, dir_fd=dir_fd)

    monkeypatch.setattr(directory, "os", _proxy(open=recorded_open))
    with directory.open_posix_private_directory(parent):
        pass
    assert calls[0][0] == "/" and calls[0][2] is None
    for name, flags, parent_fd in calls[1:]:
        assert "/" not in name and name not in (".", "..")
        assert parent_fd is not None
        assert flags & os.O_NOFOLLOW and flags & os.O_DIRECTORY and flags & os.O_CLOEXEC


@POSIX_ONLY
@pytest.mark.parametrize("mode", (0o777, 0o775, 0o750, 0o755, 0o770, 0o500, 0o1700))
def test_final_parent_must_be_private_writable_and_is_not_repaired(
    tmp_path: Path, mode: int
) -> None:
    parent = _private(tmp_path)
    parent.chmod(mode)
    before = parent.stat()
    with pytest.raises(directory.PosixSensitiveDirectoryError) as captured:
        directory.open_posix_private_directory(parent)
    assert captured.value.code == "posix_directory_private_parent_unsafe"
    assert parent.stat().st_mode == before.st_mode
    assert list(parent.iterdir()) == []


@POSIX_ONLY
@pytest.mark.parametrize("mode", (0o775, 0o757, 0o777))
def test_writable_nonsticky_ancestor_is_rejected(tmp_path: Path, mode: int) -> None:
    ancestor = tmp_path / "broad-ancestor"
    ancestor.mkdir(mode=0o700)
    parent = _private(ancestor)
    ancestor.chmod(mode)
    try:
        with pytest.raises(directory.PosixSensitiveDirectoryError) as captured:
            directory.open_posix_private_directory(parent)
        assert captured.value.code == "posix_directory_ancestor_writable"
        assert stat.S_IMODE(ancestor.stat().st_mode) == mode
    finally:
        ancestor.chmod(0o700)  # Restore only this synthetic fixture for pytest cleanup.


@pytest.mark.parametrize("private_parent", (False, True))
def test_foreign_owner_metadata_is_rejected(private_parent: bool) -> None:
    info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=12346)
    with pytest.raises(directory.PosixSensitiveDirectoryError) as captured:
        directory._check_policy(info, effective_uid=12345, private_parent=private_parent)
    assert captured.value.code == "posix_directory_owner_or_type_unsafe"


@pytest.mark.parametrize("private_parent", (False, True))
def test_non_directory_metadata_is_rejected(private_parent: bool) -> None:
    info = SimpleNamespace(st_mode=stat.S_IFREG | 0o700, st_uid=12345)
    with pytest.raises(directory.PosixSensitiveDirectoryError):
        directory._check_policy(info, effective_uid=12345, private_parent=private_parent)


def test_root_owned_sticky_exception_is_for_ancestors_only() -> None:
    info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o1777, st_uid=0)
    directory._check_policy(info, effective_uid=12345, private_parent=False)
    with pytest.raises(directory.PosixSensitiveDirectoryError):
        directory._check_policy(info, effective_uid=12345, private_parent=True)
    info.st_uid = 12345
    with pytest.raises(directory.PosixSensitiveDirectoryError):
        directory._check_policy(info, effective_uid=12345, private_parent=False)


@POSIX_ONLY
@pytest.mark.parametrize("marker_kind", ("directory", "gitfile", "malformed", "dangling"))
@pytest.mark.parametrize("location", ("parent", "ancestor"))
def test_all_git_markers_block_without_reading_contents(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, marker_kind: str, location: str
) -> None:
    parent = _private(tmp_path)
    marker = (parent if location == "parent" else tmp_path) / ".git"
    if marker_kind == "directory":
        marker.mkdir()
    elif marker_kind == "dangling":
        marker.symlink_to("missing-synthetic-administration")
    else:
        marker.write_text("gitdir: untrusted" if marker_kind == "gitfile" else "malformed")

    def no_content_reads(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Marker contents must not be read")

    monkeypatch.setattr(Path, "read_text", no_content_reads)
    monkeypatch.setattr(Path, "read_bytes", no_content_reads)
    descriptors = _record_opens(monkeypatch)
    with pytest.raises(directory.PosixSensitiveDirectoryError) as captured:
        directory.open_posix_private_directory(parent)
    assert captured.value.code == "posix_directory_git_marker"
    assert marker.lstat()
    _assert_closed(descriptors)


@POSIX_ONLY
@pytest.mark.parametrize("error_number", (errno.EACCES, errno.EIO, errno.ENOTDIR))
def test_marker_inspection_failure_is_closed_and_path_free(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error_number: int
) -> None:
    parent = _private(tmp_path)

    def fail_marker(path: str, **kwargs: Any) -> os.stat_result:
        if path == ".git":
            raise OSError(error_number, "PRIVATE_DIRECTORY_DIAGNOSTIC", str(parent))
        return os.stat(path, **kwargs)

    descriptors = _record_opens(monkeypatch, stat=fail_marker)
    with pytest.raises(directory.PosixSensitiveDirectoryError) as captured:
        directory.open_posix_private_directory(parent)
    assert captured.value.code == "posix_directory_inspection_failed"
    assert captured.value.__suppress_context__ is True
    rendered = "".join(traceback.format_exception(captured.value))
    assert str(parent) not in rendered and "PRIVATE_DIRECTORY_DIAGNOSTIC" not in rendered
    _assert_closed(descriptors)


@POSIX_ONLY
@pytest.mark.parametrize("location", ("parent", "ancestor"))
def test_symlink_traversal_is_rejected(tmp_path: Path, location: str) -> None:
    real = tmp_path / "real"
    real.mkdir(mode=0o700)
    parent = _private(real)
    alias = tmp_path / "alias"
    alias.symlink_to(parent if location == "parent" else real, target_is_directory=True)
    candidate = alias if location == "parent" else alias / parent.name
    with pytest.raises(directory.PosixSensitiveDirectoryError):
        directory.open_posix_private_directory(candidate)
    assert alias.is_symlink() and list(parent.iterdir()) == []


@POSIX_ONLY
def test_replacement_between_stat_and_open_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = _private(tmp_path)
    moved = tmp_path / "original-private-directory"
    descriptors: list[int] = []

    def substitute(path: str, flags: int, *, dir_fd: int | None = None) -> int:
        if path == parent.name:
            parent.rename(moved)
            parent.mkdir(mode=0o700)
        fd = os.open(path, flags, dir_fd=dir_fd)
        descriptors.append(fd)
        return fd

    monkeypatch.setattr(directory, "os", _proxy(open=substitute))
    with pytest.raises(directory.PosixSensitiveDirectoryError) as captured:
        directory.open_posix_private_directory(parent)
    assert captured.value.code == "posix_directory_identity_mismatch"
    _assert_closed(descriptors)
    assert moved.is_dir() and parent.is_dir()


@POSIX_ONLY
@pytest.mark.parametrize("change", ("rename_parent", "rename_ancestor", "mode", "marker", "euid"))
def test_revalidate_detects_changes_and_invalidates_all_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    ancestor = tmp_path / "ancestor"
    ancestor.mkdir(mode=0o700)
    parent = _private(ancestor)
    descriptors = _record_opens(monkeypatch)
    bound = directory.open_posix_private_directory(parent)
    if change == "rename_parent":
        parent.rename(ancestor / "moved")
        parent.mkdir(mode=0o700)
    elif change == "rename_ancestor":
        ancestor.rename(tmp_path / "moved-ancestor")
        ancestor.mkdir(mode=0o700)
    elif change == "mode":
        parent.chmod(0o755)
    elif change == "marker":
        (ancestor / ".git").mkdir()
    else:
        uid = os.geteuid()
        monkeypatch.setattr(directory.os, "geteuid", lambda: uid + 1)
    with pytest.raises(directory.PosixSensitiveDirectoryError):
        bound.revalidate()
    _assert_closed(descriptors)
    with pytest.raises(directory.PosixSensitiveDirectoryError):
        _ = bound.descriptor
    bound.close()


@POSIX_ONLY
@pytest.mark.parametrize("failure", ("fstat", "open_unsupported", "flag_missing"))
def test_unavailable_operations_fail_without_leaking_descriptors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    parent = _private(tmp_path)
    if failure == "flag_missing":
        descriptors = _record_opens(monkeypatch, O_NOFOLLOW=0)
    elif failure == "open_unsupported":

        def unavailable_open(*_args: object, **_kwargs: object) -> int:
            raise NotImplementedError("PRIVATE_UNSUPPORTED_MARKER")

        monkeypatch.setattr(directory, "os", _proxy(open=unavailable_open))
        descriptors = []
    else:

        def failed_fstat(_fd: int) -> os.stat_result:
            raise OSError(errno.EIO, "PRIVATE_FSTAT_MARKER")

        descriptors = _record_opens(monkeypatch, fstat=failed_fstat)
    with pytest.raises(directory.PosixSensitiveDirectoryError) as captured:
        directory.open_posix_private_directory(parent)
    assert "PRIVATE_" not in "".join(traceback.format_exception(captured.value))
    _assert_closed(descriptors)


@POSIX_ONLY
@pytest.mark.parametrize(
    "path",
    (
        Path("relative"),
        Path("/"),
        Path("//host/share"),
        Path("/tmp/a/../b"),
        Path("/").joinpath(*(["deep"] * 129)),
    ),
)
def test_invalid_paths_rejected_before_open(monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("Invalid paths must not cause a filesystem open")

    monkeypatch.setattr(directory, "os", _proxy(open=forbidden))
    with pytest.raises(directory.PosixSensitiveDirectoryError) as captured:
        directory.open_posix_private_directory(path)
    assert captured.value.code == "posix_directory_path_invalid"


@POSIX_ONLY
def test_package_repository_is_rejected_without_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("Package repository must be rejected before lookup")

    monkeypatch.setattr(directory, "os", _proxy(stat=forbidden, open=forbidden))
    with pytest.raises(directory.PosixSensitiveDirectoryError) as captured:
        directory.open_posix_private_directory(directory._PACKAGE_REPOSITORY_ROOT / "private")
    assert captured.value.code == "posix_directory_git_marker"


def test_windows_has_no_posix_open_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    def forbidden(*_args: object, **_kwargs: object) -> int:
        raise AssertionError("Non-POSIX runtime must not open directories")

    monkeypatch.setattr(directory, "os", SimpleNamespace(name="nt", open=forbidden))
    with pytest.raises(directory.PosixSensitiveDirectoryError) as captured:
        directory.open_posix_private_directory(Path("unused"))
    assert captured.value.code == "posix_directory_binding_unavailable"


def test_directory_foundation_only_has_the_reviewed_create_backend_consumer() -> None:
    source = Path(directory.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    forbidden = {
        "write",
        "unlink",
        "remove",
        "rename",
        "replace",
        "mkdir",
        "chmod",
        "fchmod",
        "chown",
        "system",
        "run",
        "Popen",
    }
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not (calls & forbidden)
    for module in Path(directory.__file__).parent.glob("*.py"):
        if module.name in ("_posix_sensitive_directory.py", "_posix_private_create.py"):
            continue
        other = ast.parse(module.read_text(encoding="utf-8"))
        for node in ast.walk(other):
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").endswith("._posix_sensitive_directory")
            elif isinstance(node, ast.Import):
                assert not any(
                    alias.name.endswith("._posix_sensitive_directory") for alias in node.names
                )

    backend = Path(directory.__file__).with_name("_posix_private_create.py")
    backend_tree = ast.parse(backend.read_text(encoding="utf-8"))
    assert any(
        isinstance(node, ast.ImportFrom)
        and node.module == "tridentine_calendar_google_sync"
        and any(alias.name == "_posix_sensitive_directory" for alias in node.names)
        for node in ast.walk(backend_tree)
    )
    for module in Path(directory.__file__).parent.glob("*.py"):
        if module.name in ("_posix_private_create.py", "_private_create_io.py"):
            continue
        # Only the reviewed planning adapter may import the publisher.
        assert "_posix_private_create" not in module.read_text(encoding="utf-8")
