"""Synthetic-only checks for fd-bound temporary-output mode, not full writer safety."""

from __future__ import annotations

import ast
import errno
import os
import stat
import sys
import traceback
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import tridentine_calendar_google_sync.sensitive_paths as paths

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="real POSIX descriptor permissions")


def _call_writer(path: Path, kind: str, *, overwrite: bool = False) -> None:
    if kind == "json":
        paths.atomic_write_private_json(path, {"synthetic": "value"}, overwrite=overwrite)
    elif kind == "integrity":
        paths.atomic_write_integrity_text(path, "synthetic bytes", overwrite=overwrite)
    else:
        paths.atomic_write_private_text(path, "synthetic bytes", overwrite=overwrite)


@POSIX_ONLY
@pytest.mark.parametrize("kind", ("text", "json", "integrity"))
@pytest.mark.parametrize("overwrite", (False, True))
def test_writer_prepares_empty_descriptor_without_path_chmod(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, overwrite: bool
) -> None:
    output = tmp_path / "synthetic-output.txt"
    if overwrite:
        output.write_bytes(b"previous synthetic bytes")
        output.chmod(0o600)
    original_fchmod = os.fchmod
    calls: list[tuple[int, int]] = []

    def track_fchmod(descriptor: int, mode: int) -> None:
        calls.append((os.fstat(descriptor).st_size, mode))
        original_fchmod(descriptor, mode)

    def forbidden_chmod(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Private writer must not chmod a pathname")

    monkeypatch.setattr(paths.os, "fchmod", track_fchmod)
    monkeypatch.setattr(paths.os, "chmod", forbidden_chmod)
    _call_writer(output, kind, overwrite=overwrite)
    assert calls == [(0, 0o600)]
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    expected = b'{"synthetic":"value"}\n' if kind == "json" else b"synthetic bytes"
    assert output.read_bytes() == expected
    assert sorted(item.name for item in tmp_path.iterdir()) == [output.name]


@POSIX_ONLY
@pytest.mark.parametrize("kind", ("text", "json", "integrity"))
def test_existing_output_not_overwritten_or_repermissioned(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    output = tmp_path / "existing.txt"
    output.write_bytes(b"existing synthetic bytes")
    output.chmod(0o640)
    before = output.stat()

    def forbidden_prepare(*_args: object) -> None:
        raise AssertionError("Existing output must be rejected before temp preparation")

    monkeypatch.setattr(paths, "_prepare_posix_private_output_fd", forbidden_prepare)
    with pytest.raises(paths.SensitivePathError) as captured:
        _call_writer(output, kind)
    assert captured.value.code == "sensitive_output_exists"
    assert output.read_bytes() == b"existing synthetic bytes"
    after = output.stat()
    assert (before.st_ino, before.st_mode) == (after.st_ino, after.st_mode)


@POSIX_ONLY
@pytest.mark.parametrize("kind", ("text", "json", "integrity"))
@pytest.mark.parametrize("failure", ("oserror", "unsupported", "missing"))
def test_permission_failure_stops_before_content_write_or_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, failure: str
) -> None:
    output = tmp_path / "must-not-publish.txt"
    created: list[tuple[int, Path]] = []
    original_mkstemp = paths.tempfile.mkstemp

    def record_temp(*args: Any, **kwargs: Any) -> tuple[int, str]:
        descriptor, name = original_mkstemp(*args, **kwargs)
        created.append((descriptor, Path(name)))
        return descriptor, name

    def fail_fchmod(*_args: object) -> None:
        if failure == "unsupported":
            raise NotImplementedError("PRIVATE_FCHMOD_FAILURE_MARKER")
        raise OSError(errno.EIO, "PRIVATE_FCHMOD_FAILURE_MARKER", str(output))

    def forbidden_io(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Content I/O or publication occurred after failed mode check")

    monkeypatch.setattr(paths.tempfile, "mkstemp", record_temp)
    if failure == "missing":
        monkeypatch.delattr(paths.os, "fchmod")
    else:
        monkeypatch.setattr(paths.os, "fchmod", fail_fchmod)
    monkeypatch.setattr(paths.os, "fdopen", forbidden_io)
    monkeypatch.setattr(paths.os, "link", forbidden_io)
    monkeypatch.setattr(paths.os, "replace", forbidden_io)
    monkeypatch.setattr(paths.os, "chmod", forbidden_io)
    with pytest.raises(paths.SensitivePathError) as captured:
        _call_writer(output, kind)
    assert captured.value.code == "sensitive_write_failed"
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True
    rendered = "".join(traceback.format_exception(captured.value))
    assert "PRIVATE_FCHMOD_FAILURE_MARKER" not in rendered
    assert str(output) not in rendered
    assert len(created) == 1
    assert not output.exists() and not created[0][1].exists()
    with pytest.raises(OSError) as closed:
        os.fstat(created[0][0])
    assert closed.value.errno == errno.EBADF


@POSIX_ONLY
def test_permission_change_follows_descriptor_not_rebound_name(tmp_path: Path) -> None:
    original = tmp_path / "original-empty.txt"
    moved = tmp_path / "moved-empty.txt"
    descriptor = os.open(original, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(descriptor, 0)
        original.rename(moved)
        original.write_bytes(b"unrelated synthetic bytes")
        original.chmod(0o640)
        unrelated = original.stat()
        paths._prepare_posix_private_output_fd(descriptor)
        assert stat.S_IMODE(os.fstat(descriptor).st_mode) == 0o600
        assert stat.S_IMODE(moved.stat().st_mode) == 0o600
        assert original.read_bytes() == b"unrelated synthetic bytes"
        assert original.stat().st_mode == unrelated.st_mode
        assert original.stat().st_ino == unrelated.st_ino
    finally:
        os.close(descriptor)


@POSIX_ONLY
def test_after_check_rejects_ineffective_permission_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output = tmp_path / "empty.txt"
    descriptor = os.open(output, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(descriptor, 0)
        monkeypatch.setattr(paths.os, "fchmod", lambda *_args: None)
        with pytest.raises(paths.SensitivePathError) as captured:
            paths._prepare_posix_private_output_fd(descriptor)
        assert captured.value.code == "sensitive_write_failed"
        assert os.fstat(descriptor).st_size == 0
        assert stat.S_IMODE(os.fstat(descriptor).st_mode) == 0
    finally:
        os.close(descriptor)


_BAD_METADATA = ("type", "links", "owner", "size", "permissions", "special_mode")


def _metadata(info: os.stat_result, change: str) -> SimpleNamespace:
    data = {
        name: getattr(info, name)
        for name in ("st_mode", "st_nlink", "st_uid", "st_size", "st_dev", "st_ino")
    }
    if change == "type":
        data["st_mode"] = stat.S_IFIFO | 0o600
    elif change == "links":
        data["st_nlink"] = 2
    elif change == "owner":
        data["st_uid"] += 1
    elif change == "size":
        data["st_size"] = 1
    elif change == "permissions":
        data["st_mode"] = stat.S_IFREG | 0o640
    elif change == "special_mode":
        data["st_mode"] = stat.S_IFREG | 0o4600
    elif change == "device":
        data["st_dev"] += 1
    elif change == "inode":
        data["st_ino"] += 1
    else:
        raise AssertionError("Unknown synthetic metadata change")
    return SimpleNamespace(**data)


@POSIX_ONLY
@pytest.mark.parametrize("change", _BAD_METADATA)
def test_before_check_rejects_unsafe_descriptor_without_permission_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    descriptor = os.open(tmp_path / "empty.txt", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        before = os.fstat(descriptor)
        real_fstat = os.fstat
        calls: list[int] = []
        monkeypatch.setattr(paths.os, "fstat", lambda _fd: _metadata(before, change))
        monkeypatch.setattr(paths.os, "fchmod", lambda _fd, mode: calls.append(mode))
        with pytest.raises(paths.SensitivePathError) as captured:
            paths._prepare_posix_private_output_fd(descriptor)
        assert captured.value.code == "sensitive_write_failed"
        assert calls == []
        assert real_fstat(descriptor).st_size == 0
    finally:
        os.close(descriptor)


@POSIX_ONLY
@pytest.mark.parametrize("change", (*_BAD_METADATA, "device", "inode"))
def test_after_check_rejects_metadata_or_identity_changes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    descriptor = os.open(tmp_path / "empty.txt", os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        before = os.fstat(descriptor)
        samples = iter((before, _metadata(before, change)))
        monkeypatch.setattr(paths.os, "fstat", lambda _fd: next(samples))
        with pytest.raises(paths.SensitivePathError) as captured:
            paths._prepare_posix_private_output_fd(descriptor)
        assert captured.value.code == "sensitive_write_failed"
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("private_acl", (True, False))
@pytest.mark.parametrize("overwrite", (True, False))
def test_windows_writer_dispatch_does_not_enter_posix_permission_code(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, private_acl: bool, overwrite: bool
) -> None:
    recorded: dict[str, object] = {}

    def fake_windows_writer(*_args: object, **kwargs: object) -> None:
        recorded.update(kwargs)

    def forbidden_posix(*_args: object) -> None:
        raise AssertionError("Windows must not enter POSIX descriptor preparation")

    monkeypatch.setattr(paths, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(paths, "atomic_write_windows_sensitive_bytes", fake_windows_writer)
    monkeypatch.setattr(paths, "_prepare_posix_private_output_fd", forbidden_posix)
    paths._atomic_private_write(
        tmp_path / "dispatch-only.txt",
        b"synthetic bytes",
        overwrite=overwrite,
        windows_private_acl=private_acl,
        windows_require_existing_protected_acl=True,
    )
    assert recorded["overwrite"] is overwrite
    assert recorded["private_acl"] is private_acl
    assert recorded["require_existing_protected_acl"] is True


def test_atomic_writer_has_no_path_chmod_and_prepares_before_fdopen() -> None:
    tree = ast.parse(Path(paths.__file__).read_text(encoding="utf-8"))
    writer = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_atomic_private_write"
    )
    calls = [node for node in ast.walk(writer) if isinstance(node, ast.Call)]
    assert not any(
        isinstance(node.func, ast.Attribute) and node.func.attr == "chmod" for node in calls
    )
    prepare = [
        node
        for node in calls
        if isinstance(node.func, ast.Name) and node.func.id == "_prepare_posix_private_output_fd"
    ]
    fdopen = [
        node
        for node in calls
        if isinstance(node.func, ast.Attribute) and node.func.attr == "fdopen"
    ]
    assert len(prepare) == 1 and len(fdopen) == 1
    assert prepare[0].lineno < fdopen[0].lineno


@pytest.mark.skipif(sys.platform != "win32", reason="Windows unavailable POSIX helper")
def test_posix_permission_helper_is_unavailable_on_windows() -> None:
    with pytest.raises(paths.SensitivePathError) as captured:
        paths._prepare_posix_private_output_fd(-1)
    assert captured.value.code == "sensitive_private_io_unavailable"
