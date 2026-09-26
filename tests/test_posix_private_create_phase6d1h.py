"""Synthetic tests for independent create-only backend; not operational approval."""

from __future__ import annotations

import ast
import errno
import os
import stat
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

import tridentine_calendar_google_sync._posix_private_create as create
import tridentine_calendar_google_sync._posix_sensitive_directory as directory
import tridentine_calendar_google_sync.sensitive_paths as sensitive_paths

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="real POSIX create-only backend")


def _parent(tmp_path: Path) -> Path:
    parent = tmp_path / "private"
    parent.mkdir(mode=448)
    return parent


def _proxy(**updates: Any) -> SimpleNamespace:
    names = (
        "name",
        "stat",
        "fstat",
        "open",
        "close",
        "geteuid",
        "write",
        "pread",
        "fsync",
        "link",
        "unlink",
        "O_RDWR",
        "O_CREAT",
        "O_EXCL",
        "O_NOFOLLOW",
        "O_CLOEXEC",
    )
    values = {name: getattr(os, name, None) for name in names}
    values.update(updates)
    return SimpleNamespace(**values)


def _assert_safe(exc: create.PosixPrivateCreateError, path: Path) -> None:
    assert exc.__cause__ is None and exc.__suppress_context__
    assert str(path) not in "".join(traceback.format_exception(exc))
    assert "PRIVATE_FAILURE" not in "".join(traceback.format_exception(exc))


@POSIX_ONLY
@pytest.mark.parametrize(
    "content",
    (b"", b"synthetic", b"x" * 131073, bytes(range(256))),
    ids=("empty", "synthetic", "large-131073-bytes", "all-byte-values"),
)
def test_roundtrip_is_private_single_link_and_leaves_no_temporary(
    tmp_path: Path, content: bytes
) -> None:
    parent = _parent(tmp_path)
    output = parent / "output.dat"
    create.create_posix_private_bytes(output, content)
    assert output.read_bytes() == content
    assert stat.S_IMODE(output.stat().st_mode) == 384
    assert output.stat().st_nlink == 1 and output.stat().st_uid == os.geteuid()
    assert list(parent.iterdir()) == [output]


@POSIX_ONLY
@pytest.mark.parametrize("kind", ("file", "directory", "dangling", "symlink"))
def test_existing_destination_is_not_changed_or_followed(tmp_path: Path, kind: str) -> None:
    parent = _parent(tmp_path)
    output = parent / "output"
    original = parent / "unrelated"
    original.write_bytes(b"preserve")
    original.chmod(416)
    if kind == "file":
        output.write_bytes(b"existing")
        output.chmod(420)
    elif kind == "directory":
        output.mkdir()
    else:
        output.symlink_to(original if kind == "symlink" else parent / "missing")
    before = output.lstat()
    with pytest.raises(create.PosixPrivateCreateError) as caught:
        create.create_posix_private_bytes(output, b"never publish")
    assert caught.value.code == "posix_create_output_exists"
    assert not caught.value.publication_possible
    assert output.lstat() == before
    assert original.read_bytes() == b"preserve" and stat.S_IMODE(original.stat().st_mode) == 416


@POSIX_ONLY
def test_relative_syscalls_retained_descriptors_and_fsync_order(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = _parent(tmp_path)
    output = parent / "output"
    calls: list[tuple[str, Any]] = []
    fds: list[int] = []

    def opened(name: str, flags: int, mode: int, *, dir_fd: int) -> int:
        assert "/" not in name and dir_fd >= 0
        assert flags & os.O_EXCL and flags & os.O_NOFOLLOW and flags & os.O_CLOEXEC
        fd = os.open(name, flags, mode, dir_fd=dir_fd)
        assert not os.get_inheritable(fd)
        fds.append(fd)
        calls.append(("open", fd))
        return fd

    def sync(fd: int) -> None:
        calls.append(("dirsync" if stat.S_ISDIR(os.fstat(fd).st_mode) else "filesync", fd))
        os.fsync(fd)

    def linked(src: str, dst: str, **kwargs: Any) -> None:
        assert "/" not in src and dst == output.name
        assert kwargs["src_dir_fd"] == kwargs["dst_dir_fd"]
        assert kwargs["follow_symlinks"] is False
        calls.append(("link", dst))
        os.link(src, dst, **kwargs)

    def removed(name: str, *, dir_fd: int) -> None:
        assert name.startswith(".private-create-") and "/" not in name
        calls.append(("unlink", name))
        os.unlink(name, dir_fd=dir_fd)

    monkeypatch.setattr(create, "os", _proxy(open=opened, fsync=sync, link=linked, unlink=removed))
    create.create_posix_private_bytes(output, b"synthetic")
    labels = [name for name, _ in calls]
    assert labels == ["open", "filesync", "link", "unlink", "dirsync"]
    for fd in fds:
        with pytest.raises(OSError) as caught:
            os.fstat(fd)
        assert caught.value.errno == errno.EBADF


@POSIX_ONLY
def test_short_write_and_pread_are_handled(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    output = _parent(tmp_path) / "output"
    monkeypatch.setattr(
        create,
        "os",
        _proxy(
            write=lambda fd, data: os.write(fd, data[:3]),
            pread=lambda fd, size, offset: os.pread(fd, min(size, 2), offset),
        ),
    )
    create.create_posix_private_bytes(output, b"synthetic exact data")
    assert output.read_bytes() == b"synthetic exact data"


@POSIX_ONLY
@pytest.mark.parametrize("failure", ("prepare", "write", "zero_write", "readback", "file_fsync"))
def test_prepublication_failure_preserves_destination_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    parent = _parent(tmp_path)
    output = parent / "output"

    def failed(*_args: object, **_kwargs: object) -> Any:
        raise OSError(errno.EIO, "PRIVATE_FAILURE", str(output))

    updates = {}
    if failure == "prepare":
        monkeypatch.setattr(create, "_prepare_posix_private_output_fd", failed)
    elif failure == "zero_write":
        updates["write"] = lambda *_a: 0
    elif failure == "readback":
        updates["pread"] = lambda _fd, size, _offset: b"z" * size
    elif failure == "file_fsync":
        updates["fsync"] = failed
    else:
        updates["write"] = failed
    monkeypatch.setattr(create, "os", _proxy(**updates))
    with pytest.raises(create.PosixPrivateCreateError) as caught:
        create.create_posix_private_bytes(output, b"synthetic")
    assert not caught.value.publication_possible
    _assert_safe(caught.value, output)
    assert list(parent.iterdir()) == []


@POSIX_ONLY
@pytest.mark.parametrize("failure", ("link_before", "link_after", "dir_fsync", "temp_unlink"))
def test_publication_attempt_failure_is_ambiguous_and_never_rolls_back_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    parent = _parent(tmp_path)
    output = parent / "output"

    def linked(*args: Any, **kwargs: Any) -> None:
        if failure != "link_before":
            os.link(*args, **kwargs)
        if failure in ("link_before", "link_after"):
            raise OSError(errno.EIO, "PRIVATE_FAILURE", str(output))

    def synced(fd: int) -> None:
        if failure == "dir_fsync" and stat.S_ISDIR(os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "PRIVATE_FAILURE", str(output))
        os.fsync(fd)

    def removed(name: str, **kwargs: Any) -> None:
        assert name != output.name
        if failure == "temp_unlink":
            raise OSError(errno.EIO, "PRIVATE_FAILURE", str(output))
        os.unlink(name, **kwargs)

    monkeypatch.setattr(create, "os", _proxy(link=linked, fsync=synced, unlink=removed))
    with pytest.raises(create.PosixPrivateCreateError) as caught:
        create.create_posix_private_bytes(output, b"synthetic")
    assert caught.value.publication_possible
    _assert_safe(caught.value, output)
    if failure == "link_before":
        assert not output.exists()
    else:
        assert output.read_bytes() == b"synthetic"


@POSIX_ONLY
def test_destination_created_at_link_is_not_overwritten(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = _parent(tmp_path)
    output = parent / "output"

    def collide(src: str, dst: str, **kwargs: Any) -> None:
        output.write_bytes(b"competitor")
        output.chmod(416)
        os.link(src, dst, **kwargs)

    monkeypatch.setattr(create, "os", _proxy(link=collide))
    with pytest.raises(create.PosixPrivateCreateError) as caught:
        create.create_posix_private_bytes(output, b"new")
    assert caught.value.code == "posix_create_output_exists" and caught.value.publication_possible
    assert output.read_bytes() == b"competitor" and stat.S_IMODE(output.stat().st_mode) == 416
    assert list(parent.iterdir()) == [output]


@POSIX_ONLY
def test_concurrent_create_has_exactly_one_winner(tmp_path: Path) -> None:
    output = _parent(tmp_path) / "output"

    def invoke(content: bytes) -> str:
        try:
            create.create_posix_private_bytes(output, content)
        except create.PosixPrivateCreateError as exc:
            return exc.code
        return "success"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(invoke, (b"first", b"second")))
    assert sorted(results) == ["posix_create_output_exists", "success"]
    assert output.read_bytes() in (b"first", b"second") and output.stat().st_nlink == 1


@POSIX_ONLY
@pytest.mark.parametrize("location", ("before_write", "before_link"))
def test_rebound_temporary_is_not_published_or_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, location: str
) -> None:
    parent = _parent(tmp_path)
    output = parent / "output"
    real_prepare = create._prepare_posix_private_output_fd

    def swap() -> None:
        temp = next(parent.glob(".private-create-*"))
        temp.rename(parent / "retained-original")
        temp.write_bytes(b"unrelated")
        temp.chmod(416)

    def prepare(fd: int) -> None:
        real_prepare(fd)
        if location == "before_write":
            swap()

    def synced(fd: int) -> None:
        os.fsync(fd)
        if location == "before_link":
            swap()

    monkeypatch.setattr(create, "_prepare_posix_private_output_fd", prepare)
    monkeypatch.setattr(create, "os", _proxy(fsync=synced))
    with pytest.raises(create.PosixPrivateCreateError) as caught:
        create.create_posix_private_bytes(output, b"synthetic")
    assert not caught.value.publication_possible and (not output.exists())
    unrelated = next(parent.glob(".private-create-*"))
    assert unrelated.read_bytes() == b"unrelated" and stat.S_IMODE(unrelated.stat().st_mode) == 416
    assert (parent / "retained-original").exists()


@POSIX_ONLY
def test_parent_rename_uses_no_absolute_cleanup_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = _parent(tmp_path)
    output = parent / "output"
    moved = tmp_path / "moved"

    def synced(fd: int) -> None:
        os.fsync(fd)
        parent.rename(moved)
        parent.mkdir(mode=448)
        (parent / "unrelated").write_bytes(b"preserve")

    monkeypatch.setattr(create, "os", _proxy(fsync=synced))
    with pytest.raises(create.PosixPrivateCreateError) as caught:
        create.create_posix_private_bytes(output, b"synthetic")
    assert not caught.value.publication_possible
    assert (parent / "unrelated").read_bytes() == b"preserve"
    assert len(list(moved.glob(".private-create-*"))) == 1
    assert not output.exists()


@POSIX_ONLY
@pytest.mark.parametrize("change", ("content", "mode", "hardlink", "destination"))
def test_post_link_tampering_is_detected_without_final_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    parent = _parent(tmp_path)
    output = parent / "output"

    def linked(src: str, dst: str, **kwargs: Any) -> None:
        os.link(src, dst, **kwargs)
        if change == "content":
            output.write_bytes(b"altered!!")
        elif change == "mode":
            output.chmod(416)
        elif change == "hardlink":
            os.link(output, parent / "extra")
        else:
            output.unlink()
            output.write_bytes(b"unrelated")

    monkeypatch.setattr(create, "os", _proxy(link=linked))
    with pytest.raises(create.PosixPrivateCreateError) as caught:
        create.create_posix_private_bytes(output, b"synthetic")
    assert caught.value.publication_possible and output.exists()


@POSIX_ONLY
@pytest.mark.parametrize("mode", (493, 488, 504))
def test_unsafe_parent_is_not_repaired(tmp_path: Path, mode: int) -> None:
    parent = _parent(tmp_path)
    parent.chmod(mode)
    with pytest.raises(create.PosixPrivateCreateError) as caught:
        create.create_posix_private_bytes(parent / "output", b"synthetic")
    assert not caught.value.publication_possible
    assert stat.S_IMODE(parent.stat().st_mode) == mode and list(parent.iterdir()) == []


@POSIX_ONLY
def test_temp_collisions_are_bounded_and_not_deleted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = _parent(tmp_path)
    collision = parent / (".private-create-" + "a" * 32)
    collision.write_bytes(b"preserve")
    calls = []

    def fixed(_n: int) -> str:
        calls.append(1)
        return "a" * 32

    monkeypatch.setattr(create.secrets, "token_hex", fixed)
    with pytest.raises(create.PosixPrivateCreateError) as caught:
        create.create_posix_private_bytes(parent / "output", b"new")
    assert caught.value.code == "posix_create_name_exhausted" and len(calls) == 16
    assert collision.read_bytes() == b"preserve" and list(parent.iterdir()) == [collision]


@POSIX_ONLY
@pytest.mark.parametrize("primitive", ("O_NOFOLLOW", "O_CLOEXEC", "pread"))
def test_missing_primitive_stops_before_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, primitive: str
) -> None:
    parent = _parent(tmp_path)
    monkeypatch.setattr(create, "os", _proxy(**{primitive: None if primitive == "pread" else 0}))
    with pytest.raises(create.PosixPrivateCreateError) as caught:
        create.create_posix_private_bytes(parent / "output", b"data")
    assert caught.value.code == "posix_create_unavailable" and list(parent.iterdir()) == []


@POSIX_ONLY
@pytest.mark.parametrize(
    "bad",
    (Path("relative"), Path("/"), Path("//host/share/a"), Path("/tmp/a/../b"), Path("/tmp/.git")),
)
def test_invalid_path_has_no_filesystem_activity(
    monkeypatch: pytest.MonkeyPatch, bad: Path
) -> None:

    def forbidden(*_args: object) -> Any:
        raise AssertionError("unexpected directory open")

    monkeypatch.setattr(create.directory, "open_posix_private_directory", forbidden)
    with pytest.raises(create.PosixPrivateCreateError) as caught:
        create.create_posix_private_bytes(bad, b"data")
    assert caught.value.code == "posix_create_path_invalid"


@POSIX_ONLY
def test_git_marker_rejects_before_temp_creation(tmp_path: Path) -> None:
    parent = _parent(tmp_path)
    (parent / ".git").mkdir()
    with pytest.raises(create.PosixPrivateCreateError):
        create.create_posix_private_bytes(parent / "output", b"data")
    assert [p.name for p in parent.iterdir()] == [".git"]


def test_non_posix_has_no_fallback(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(create, "os", SimpleNamespace(name="nt"))
    with pytest.raises(create.PosixPrivateCreateError) as caught:
        create.create_posix_private_bytes(tmp_path / "output", b"data")
    assert caught.value.code == "posix_create_unavailable" and (
        not caught.value.publication_possible
    )


def test_backend_not_wired_to_common_writer_and_no_replace_or_path_chmod() -> None:
    tree = ast.parse(Path(create.__file__).read_text(encoding="utf-8"))
    calls = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not calls & {"replace", "rename", "chmod", "chown", "mkdir", "mkstemp"}
    assert "_posix_private_create" not in Path(sensitive_paths.__file__).read_text(encoding="utf-8")
    assert "_posix_private_create" not in Path(directory.__file__).read_text(encoding="utf-8")
