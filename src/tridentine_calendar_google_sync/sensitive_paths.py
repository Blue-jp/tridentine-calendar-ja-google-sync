"""Privacy-safe local path handling for credentials, tokens, and target config."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path

MAX_SENSITIVE_FILE_BYTES = 4 * 1024 * 1024
_PACKAGE_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]


class SensitivePathError(ValueError):
    """A sensitive-path failure whose text contains neither path nor content."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _reject_nonlocal_text(value: str) -> None:
    lowered = value.casefold()
    if (
        "://" in value
        or lowered.startswith("file:")
        or value.startswith(("\\\\", "//"))
        or "\x00" in value
    ):
        raise SensitivePathError(
            "nonlocal_sensitive_path",
            "sensitive data must use an absolute local filesystem path",
        )


def _absolute_local_path(value: str | Path) -> Path:
    text = os.fspath(value)
    _reject_nonlocal_text(text)
    path = Path(text)
    if not path.is_absolute():
        raise SensitivePathError(
            "relative_sensitive_path",
            "sensitive data must use an explicit absolute path",
        )
    return path


def _reject_symlink_components(path: Path) -> None:
    for component in (path, *path.parents):
        try:
            if component.is_symlink():
                raise SensitivePathError(
                    "sensitive_path_symlink",
                    "symbolic links are not accepted for sensitive data",
                )
        except SensitivePathError:
            raise
        except OSError as exc:
            raise SensitivePathError(
                "sensitive_path_unavailable",
                "sensitive path cannot be safely inspected",
            ) from exc


def _reject_git_worktree(path: Path) -> None:
    """Reject paths beneath a committed worktree without emitting Git output."""

    start = path if path.is_dir() else path.parent
    if path.is_relative_to(_PACKAGE_REPOSITORY_ROOT):
        raise SensitivePathError(
            "sensitive_path_in_git_worktree",
            "sensitive data must be stored outside every Git worktree",
        )
    for ancestor in (start, *start.parents):
        marker = ancestor / ".git"
        try:
            if marker.exists() or marker.is_symlink():
                try:
                    result = subprocess.run(
                        [
                            "git",
                            "-c",
                            "safe.directory=*",
                            "-C",
                            os.fspath(ancestor),
                            "rev-parse",
                            "--verify",
                            "HEAD",
                        ],
                        stdin=subprocess.DEVNULL,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        check=False,
                        timeout=5,
                    )
                except (OSError, subprocess.SubprocessError):
                    continue
                if result.returncode == 0:
                    raise SensitivePathError(
                        "sensitive_path_in_git_worktree",
                        "sensitive data must be stored outside every Git worktree",
                    )
        except SensitivePathError:
            raise
        except OSError as exc:
            raise SensitivePathError(
                "sensitive_path_unavailable",
                "sensitive path cannot be safely inspected",
            ) from exc


def validate_sensitive_input_path(
    value: str | Path,
    *,
    max_size: int = MAX_SENSITIVE_FILE_BYTES,
) -> Path:
    """Return a bounded regular input path outside Git and symlink trees."""

    if max_size <= 0:
        raise ValueError("max_size must be positive")
    path = _absolute_local_path(value)
    _reject_symlink_components(path)
    _reject_git_worktree(path)
    try:
        if not path.is_file():
            raise SensitivePathError(
                "sensitive_input_not_file",
                "sensitive input is not a regular local file",
            )
        if path.stat().st_size > max_size:
            raise SensitivePathError(
                "sensitive_input_too_large",
                "sensitive input exceeds the size limit",
            )
    except SensitivePathError:
        raise
    except OSError as exc:
        raise SensitivePathError(
            "sensitive_input_unavailable",
            "sensitive input is unavailable",
        ) from exc
    return path


def validate_sensitive_output_path(
    value: str | Path,
    *,
    overwrite: bool = False,
) -> Path:
    """Return a safe output path; existing files are rejected by default."""

    path = _absolute_local_path(value)
    _reject_symlink_components(path)
    _reject_git_worktree(path)
    try:
        if not path.parent.is_dir():
            raise SensitivePathError(
                "sensitive_output_parent_missing",
                "sensitive output parent directory does not exist",
            )
        if path.exists():
            if not path.is_file():
                raise SensitivePathError(
                    "sensitive_output_not_file",
                    "sensitive output is not a regular local file",
                )
            if not overwrite:
                raise SensitivePathError(
                    "sensitive_output_exists",
                    "sensitive output already exists and overwrite is disabled",
                )
    except SensitivePathError:
        raise
    except OSError as exc:
        raise SensitivePathError(
            "sensitive_output_unavailable",
            "sensitive output cannot be safely inspected",
        ) from exc
    return path


def read_sensitive_bytes(
    value: str | Path,
    *,
    max_size: int = MAX_SENSITIVE_FILE_BYTES,
) -> bytes:
    """Read bounded bytes without disclosing the input path or content on failure."""

    path = validate_sensitive_input_path(value, max_size=max_size)
    try:
        with path.open("rb") as stream:
            stat_result = os.fstat(stream.fileno())
            if stat_result.st_size > max_size:
                raise SensitivePathError(
                    "sensitive_input_too_large",
                    "sensitive input exceeds the size limit",
                )
            content = stream.read(max_size + 1)
    except SensitivePathError:
        raise
    except OSError as exc:
        raise SensitivePathError(
            "sensitive_input_unavailable",
            "sensitive input is unavailable",
        ) from exc
    if len(content) > max_size:
        raise SensitivePathError(
            "sensitive_input_too_large",
            "sensitive input exceeds the size limit",
        )
    return content


def _fsync_parent(parent: Path) -> None:
    directory_flag = getattr(os, "O_DIRECTORY", 0)
    try:
        descriptor = os.open(parent, os.O_RDONLY | directory_flag)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_private_write(path: Path, content: bytes, *, overwrite: bool) -> None:
    temporary_path: Path | None = None
    descriptor = -1
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".private-write-", dir=path.parent)
        temporary_path = Path(temporary_name)
        os.chmod(temporary_path, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary_path, path)
            temporary_path = None
        else:
            try:
                os.link(temporary_path, path, follow_symlinks=False)
            except FileExistsError as exc:
                raise SensitivePathError(
                    "sensitive_output_exists",
                    "sensitive output already exists and overwrite is disabled",
                ) from exc
            temporary_path.unlink()
            temporary_path = None
        os.chmod(path, 0o600)
        _fsync_parent(path.parent)
    except SensitivePathError:
        raise
    except OSError as exc:
        raise SensitivePathError(
            "sensitive_write_failed",
            "sensitive output could not be written safely",
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            with suppress(OSError):
                temporary_path.unlink(missing_ok=True)


def atomic_write_private_text(
    value: str | Path,
    text: str,
    *,
    overwrite: bool = False,
    max_size: int = MAX_SENSITIVE_FILE_BYTES,
) -> None:
    """Atomically write UTF-8 text with owner-only mode and no overwrite by default."""

    path = validate_sensitive_output_path(value, overwrite=overwrite)
    content = text.encode("utf-8", errors="strict")
    if len(content) > max_size:
        raise SensitivePathError(
            "sensitive_output_too_large",
            "sensitive output exceeds the size limit",
        )
    _atomic_private_write(path, content, overwrite=overwrite)


JsonValue = None | bool | int | float | str | Sequence["JsonValue"] | Mapping[str, "JsonValue"]


def atomic_write_private_json(
    value: str | Path,
    payload: Mapping[str, JsonValue],
    *,
    overwrite: bool = False,
    max_size: int = MAX_SENSITIVE_FILE_BYTES,
) -> None:
    """Atomically write deterministic private JSON without logging its values."""

    try:
        text = (
            json.dumps(
                payload,
                ensure_ascii=False,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        )
    except (TypeError, ValueError) as exc:
        raise SensitivePathError(
            "invalid_sensitive_json",
            "sensitive JSON payload is invalid",
        ) from exc
    atomic_write_private_text(
        value,
        text,
        overwrite=overwrite,
        max_size=max_size,
    )


__all__ = [
    "MAX_SENSITIVE_FILE_BYTES",
    "JsonValue",
    "SensitivePathError",
    "atomic_write_private_json",
    "atomic_write_private_text",
    "read_sensitive_bytes",
    "validate_sensitive_input_path",
    "validate_sensitive_output_path",
]
