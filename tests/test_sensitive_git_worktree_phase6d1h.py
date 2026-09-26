from __future__ import annotations

import errno
import subprocess
import traceback
from pathlib import Path

import pytest

from tridentine_calendar_google_sync import sensitive_paths
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_integrity_text,
    atomic_write_private_text,
    read_private_sensitive_bytes,
    read_sensitive_bytes,
    validate_sensitive_input_path,
    validate_sensitive_output_path,
)


@pytest.mark.parametrize("marker_kind", ("directory", "gitfile", "empty", "malformed"))
@pytest.mark.parametrize(
    "operation",
    ("validate_input", "validate_output", "read", "private_read", "write", "integrity_write"),
)
def test_git_marker_blocks_sensitive_io_before_content_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    marker_kind: str,
    operation: str,
) -> None:
    root = tmp_path / "untrusted-tree"
    directory = root / "nested" / "private-inputs"
    directory.mkdir(parents=True)
    source = directory / "existing.txt"
    source.write_bytes(b"synthetic unchanged bytes")
    output = directory / "must-not-create.txt"
    marker = root / ".git"
    if marker_kind == "directory":
        marker.mkdir()
    else:
        marker.write_text(
            {
                "gitfile": "gitdir: ../unresolved-administration\n",
                "empty": "",
                "malformed": "not a valid Git marker\n",
            }[marker_kind],
            encoding="utf-8",
        )

    def forbidden_git(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Sensitive path guard must not execute Git")

    monkeypatch.setattr(subprocess, "run", forbidden_git)
    with pytest.raises(SensitivePathError) as captured:
        if operation == "validate_input":
            validate_sensitive_input_path(source)
        elif operation == "validate_output":
            validate_sensitive_output_path(output)
        elif operation == "read":
            read_sensitive_bytes(source)
        elif operation == "private_read":
            read_private_sensitive_bytes(source)
        elif operation == "write":
            atomic_write_private_text(output, "synthetic output")
        else:
            atomic_write_integrity_text(output, "synthetic output")

    assert captured.value.code == "sensitive_path_in_git_worktree"
    assert str(root) not in str(captured.value)
    assert not output.exists()
    assert source.read_bytes() == b"synthetic unchanged bytes"
    assert sorted(item.name for item in directory.iterdir()) == [source.name]


@pytest.mark.parametrize("git_failure", ("missing", "denied", "timeout", "nonzero"))
def test_git_failure_cannot_turn_marker_into_acceptance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    git_failure: str,
) -> None:
    (tmp_path / ".git").mkdir()
    calls: list[str] = []

    def unavailable_git(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(git_failure)
        if git_failure == "missing":
            raise FileNotFoundError("synthetic Git unavailable")
        if git_failure == "denied":
            raise PermissionError("synthetic Git denied")
        if git_failure == "timeout":
            raise subprocess.TimeoutExpired("synthetic Git", 5)
        return subprocess.CompletedProcess(["git"], 128, "", "")

    monkeypatch.setattr(subprocess, "run", unavailable_git)
    with pytest.raises(SensitivePathError) as captured:
        validate_sensitive_output_path(tmp_path / "must-not-create.txt")
    assert captured.value.code == "sensitive_path_in_git_worktree"
    assert calls == []


def test_git_marker_in_candidate_directory_is_rejected(tmp_path: Path) -> None:
    (tmp_path / ".git").mkdir()
    with pytest.raises(SensitivePathError) as captured:
        sensitive_paths._reject_git_worktree(tmp_path)
    assert captured.value.code == "sensitive_path_in_git_worktree"


def test_dangling_git_marker_is_rejected_without_following_link(tmp_path: Path) -> None:
    marker = tmp_path / ".git"
    try:
        marker.symlink_to(tmp_path / "missing-administration", target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("Symbolic link creation is unavailable")
    with pytest.raises(SensitivePathError) as captured:
        validate_sensitive_output_path(tmp_path / "must-not-create.txt")
    assert captured.value.code == "sensitive_path_in_git_worktree"


@pytest.mark.parametrize("error_number", (errno.EACCES, errno.EIO, errno.ENOTDIR))
@pytest.mark.parametrize("operation", ("read", "write"))
def test_marker_inspection_error_is_fail_closed_and_path_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    error_number: int,
    operation: str,
) -> None:
    path = tmp_path / "candidate.txt"
    if operation == "read":
        path.write_bytes(b"synthetic unchanged bytes")
    marker = tmp_path / ".git"
    original_lstat = Path.lstat
    private_marker = "PRIVATE_GIT_INSPECTION_MARKER"

    def failing_lstat(self: Path) -> object:
        if self == marker:
            raise OSError(error_number, private_marker, str(marker))
        return original_lstat(self)

    monkeypatch.setattr(Path, "lstat", failing_lstat)
    with pytest.raises(SensitivePathError) as captured:
        if operation == "read":
            read_sensitive_bytes(path)
        else:
            atomic_write_private_text(path, "synthetic output")
    assert captured.value.code == "sensitive_path_unavailable"
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True
    rendered = "".join(traceback.format_exception(captured.value))
    assert private_marker not in rendered
    assert str(marker) not in rendered
    if operation == "read":
        assert path.read_bytes() == b"synthetic unchanged bytes"
    else:
        assert not path.exists()


def test_start_directory_inspection_failure_is_path_free(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "candidate.txt"
    original_is_dir = Path.is_dir

    def denied_is_dir(self: Path) -> bool:
        if self == path:
            raise PermissionError(errno.EACCES, "PRIVATE_START_MARKER", str(path))
        return original_is_dir(self)

    monkeypatch.setattr(Path, "is_dir", denied_is_dir)
    with pytest.raises(SensitivePathError) as captured:
        sensitive_paths._reject_git_worktree(path)
    assert captured.value.code == "sensitive_path_unavailable"
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True
    assert "PRIVATE_START_MARKER" not in "".join(traceback.format_exception(captured.value))


def test_gitfile_contents_are_not_read(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    marker = tmp_path / ".git"
    marker.write_text("gitdir: unresolved-synthetic-administration\n", encoding="utf-8")

    def forbidden_read(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Git marker contents must not be read")

    monkeypatch.setattr(Path, "read_text", forbidden_read)
    monkeypatch.setattr(Path, "read_bytes", forbidden_read)
    with pytest.raises(SensitivePathError) as captured:
        sensitive_paths._reject_git_worktree(tmp_path / "candidate.txt")
    assert captured.value.code == "sensitive_path_in_git_worktree"


def test_external_private_file_still_round_trips_without_git(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_git(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("External private I/O must not depend on a Git subprocess")

    monkeypatch.setattr(subprocess, "run", forbidden_git)
    path = tmp_path / "private.txt"
    atomic_write_private_text(path, "synthetic private bytes")
    assert read_private_sensitive_bytes(path) == b"synthetic private bytes"


def test_package_repository_remains_blocked_without_marker_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = sensitive_paths._PACKAGE_REPOSITORY_ROOT / "must-not-create.txt"

    def forbidden_lstat(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Known package repository must be rejected before marker lookup")

    monkeypatch.setattr(Path, "lstat", forbidden_lstat)
    with pytest.raises(SensitivePathError) as captured:
        sensitive_paths._reject_git_worktree(path)
    assert captured.value.code == "sensitive_path_in_git_worktree"
