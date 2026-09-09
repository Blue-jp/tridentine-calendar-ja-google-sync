"""Privacy-safe local path handling for credentials, tokens, and target config."""

from __future__ import annotations

import hmac
import json
import os
import stat
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from pathlib import Path

from tridentine_calendar_google_sync._windows_sensitive_files import (
    WindowsSensitiveFileError,
    atomic_write_windows_sensitive_bytes,
    read_windows_sensitive_bytes,
    remove_windows_sensitive_file_if_matches,
    validate_windows_sensitive_input,
    validate_windows_sensitive_output,
    windows_sensitive_path_identity,
)

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
    windows_private_acl: bool = False,
    windows_integrity_acl: bool = False,
    windows_require_protected_acl: bool = False,
) -> Path:
    """Return a bounded regular input path outside Git and symlink trees."""

    if max_size <= 0:
        raise ValueError("max_size must be positive")
    if windows_private_acl and windows_integrity_acl:
        raise ValueError("Windows private and integrity ACL policies are mutually exclusive")
    if windows_require_protected_acl and not (windows_private_acl or windows_integrity_acl):
        raise ValueError("protected Windows ACL validation requires an ACL policy")
    path = _absolute_local_path(value)
    _reject_symlink_components(path)
    _reject_git_worktree(path)
    if os.name == "nt":
        try:
            validate_windows_sensitive_input(
                path,
                _PACKAGE_REPOSITORY_ROOT,
                max_size=max_size,
                private_acl=windows_private_acl,
                integrity_acl=windows_integrity_acl,
                require_protected_acl=windows_require_protected_acl,
            )
        except WindowsSensitiveFileError as exc:
            raise SensitivePathError(exc.code, exc.public_message) from exc
        return path
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
    windows_private_acl: bool = True,
    windows_require_existing_protected_acl: bool = False,
) -> Path:
    """Return a safe output path; existing files are rejected by default."""

    path = _absolute_local_path(value)
    _reject_symlink_components(path)
    _reject_git_worktree(path)
    if os.name == "nt":
        try:
            validate_windows_sensitive_output(
                path,
                _PACKAGE_REPOSITORY_ROOT,
                overwrite=overwrite,
                private_acl=windows_private_acl,
                require_existing_protected_acl=windows_require_existing_protected_acl,
            )
        except WindowsSensitiveFileError as exc:
            raise SensitivePathError(exc.code, exc.public_message) from exc
        return path
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
    windows_private_acl: bool = False,
    windows_integrity_acl: bool = False,
    windows_require_protected_acl: bool = False,
) -> bytes:
    """Read bounded bytes without disclosing the input path or content on failure."""

    if max_size <= 0:
        raise ValueError("max_size must be positive")
    if windows_private_acl and windows_integrity_acl:
        raise ValueError("Windows private and integrity ACL policies are mutually exclusive")
    if windows_require_protected_acl and not (windows_private_acl or windows_integrity_acl):
        raise ValueError("protected Windows ACL validation requires an ACL policy")
    path = _absolute_local_path(value)
    _reject_symlink_components(path)
    _reject_git_worktree(path)
    if os.name == "nt":
        try:
            return read_windows_sensitive_bytes(
                path,
                _PACKAGE_REPOSITORY_ROOT,
                max_size=max_size,
                private_acl=windows_private_acl,
                integrity_acl=windows_integrity_acl,
                require_protected_acl=windows_require_protected_acl,
            )
        except WindowsSensitiveFileError as exc:
            raise SensitivePathError(exc.code, exc.public_message) from exc
    path = validate_sensitive_input_path(path, max_size=max_size)
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


if sys.platform != "win32":

    def _read_posix_private_bytes(path: Path, *, max_size: int) -> bytes:
        # Read one owner-only regular file through a no-follow fd chain.
        if os.name != "posix":
            raise SensitivePathError(
                "sensitive_private_io_unavailable",
                "strict private input verification is unavailable",
            )

        no_follow = getattr(os, "O_NOFOLLOW", 0)
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        close_on_exec = getattr(os, "O_CLOEXEC", 0)
        if no_follow == 0 or directory_flag == 0:
            raise SensitivePathError(
                "sensitive_private_io_unavailable",
                "strict private input verification is unavailable",
            )

        parts = path.parts
        if (
            not path.anchor
            or path.name in {"", ".", ".."}
            or any(component in {".", ".."} for component in parts[1:])
        ):
            raise SensitivePathError(
                "sensitive_path_alias",
                "sensitive path uses an unsafe local alias",
            )

        parent_descriptor = -1
        file_descriptor = -1
        try:
            directory_flags = os.O_RDONLY | directory_flag | no_follow | close_on_exec
            parent_descriptor = os.open(path.anchor, directory_flags)

            for component in parts[1:-1]:
                next_descriptor = os.open(
                    component,
                    directory_flags,
                    dir_fd=parent_descriptor,
                )
                os.close(parent_descriptor)
                parent_descriptor = next_descriptor

            file_descriptor = os.open(
                path.name,
                os.O_RDONLY | no_follow | close_on_exec,
                dir_fd=parent_descriptor,
            )
            before = os.fstat(file_descriptor)
            mode = stat.S_IMODE(before.st_mode)
            effective_uid = os.geteuid()

            if not stat.S_ISREG(before.st_mode):
                raise SensitivePathError(
                    "sensitive_input_not_file",
                    "sensitive input is not a regular local file",
                )
            if before.st_nlink != 1:
                raise SensitivePathError(
                    "sensitive_path_hardlink",
                    "hard-linked files are not accepted for sensitive data",
                )
            if before.st_uid != effective_uid:
                raise SensitivePathError(
                    "sensitive_input_owner_unsafe",
                    "sensitive input owner is unsafe",
                )
            if mode & 0o077:
                raise SensitivePathError(
                    "sensitive_input_permissions_unsafe",
                    "sensitive input permissions are unsafe",
                )
            if before.st_size < 0 or before.st_size > max_size:
                raise SensitivePathError(
                    "sensitive_input_too_large",
                    "sensitive input exceeds the size limit",
                )

            content = bytearray()
            while len(content) <= max_size:
                request_size = min(1024 * 1024, max_size + 1 - len(content))
                if request_size <= 0:
                    break
                chunk = os.read(file_descriptor, request_size)
                if not chunk:
                    break
                content.extend(chunk)

            if len(content) > max_size:
                raise SensitivePathError(
                    "sensitive_input_too_large",
                    "sensitive input exceeds the size limit",
                )

            after = os.fstat(file_descriptor)
            after_mode = stat.S_IMODE(after.st_mode)
            if (
                after.st_dev != before.st_dev
                or after.st_ino != before.st_ino
                or after.st_nlink != 1
                or after.st_uid != effective_uid
                or after_mode & 0o077
                or after.st_size != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
                or len(content) != before.st_size
            ):
                raise SensitivePathError(
                    "sensitive_input_changed",
                    "sensitive input changed during verification",
                )
            return bytes(content)
        except SensitivePathError:
            raise
        except (OSError, ValueError):
            raise SensitivePathError(
                "sensitive_input_unavailable",
                "sensitive input is unavailable",
            ) from None
        finally:
            if file_descriptor >= 0:
                with suppress(OSError):
                    os.close(file_descriptor)
            if parent_descriptor >= 0:
                with suppress(OSError):
                    os.close(parent_descriptor)

else:

    def _read_posix_private_bytes(path: Path, *, max_size: int) -> bytes:
        del path, max_size
        raise SensitivePathError(
            "sensitive_private_io_unavailable",
            "strict private input verification is unavailable",
        )


def read_private_sensitive_bytes(
    value: str | Path,
    *,
    max_size: int = MAX_SENSITIVE_FILE_BYTES,
) -> bytes:
    """Read one strictly private local file without repairing its permissions."""

    if max_size <= 0:
        raise ValueError("max_size must be positive")
    path = _absolute_local_path(value)
    _reject_symlink_components(path)
    _reject_git_worktree(path)
    if os.name == "nt":
        try:
            return read_windows_sensitive_bytes(
                path,
                _PACKAGE_REPOSITORY_ROOT,
                max_size=max_size,
                private_acl=True,
                integrity_acl=False,
                require_protected_acl=True,
            )
        except WindowsSensitiveFileError as exc:
            raise SensitivePathError(exc.code, exc.public_message) from exc
    return _read_posix_private_bytes(path, max_size=max_size)


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


def _atomic_private_write(
    path: Path,
    content: bytes,
    *,
    overwrite: bool,
    windows_private_acl: bool,
    windows_require_existing_protected_acl: bool,
) -> None:
    if os.name == "nt":
        try:
            atomic_write_windows_sensitive_bytes(
                path,
                _PACKAGE_REPOSITORY_ROOT,
                content,
                overwrite=overwrite,
                private_acl=windows_private_acl,
                require_existing_protected_acl=windows_require_existing_protected_acl,
            )
        except WindowsSensitiveFileError as exc:
            raise SensitivePathError(exc.code, exc.public_message) from exc
        return
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
    windows_require_existing_protected_acl: bool = False,
) -> None:
    """Atomically write UTF-8 text with owner-only mode and no overwrite by default."""

    path = validate_sensitive_output_path(
        value,
        overwrite=overwrite,
        windows_private_acl=True,
        windows_require_existing_protected_acl=windows_require_existing_protected_acl,
    )
    content = text.encode("utf-8", errors="strict")
    if len(content) > max_size:
        raise SensitivePathError(
            "sensitive_output_too_large",
            "sensitive output exceeds the size limit",
        )
    _atomic_private_write(
        path,
        content,
        overwrite=overwrite,
        windows_private_acl=True,
        windows_require_existing_protected_acl=windows_require_existing_protected_acl,
    )


def atomic_write_integrity_text(
    value: str | Path,
    text: str,
    *,
    overwrite: bool = False,
    max_size: int = MAX_SENSITIVE_FILE_BYTES,
) -> None:
    """Atomically write sanitized evidence with path integrity on Windows.

    POSIX retains the existing owner-only mode.  Windows binds the operation to
    a non-reparse parent and rejects broad parent mutation rights, while the
    sanitized leaf may inherit read access because it contains no secret data.
    """

    path = validate_sensitive_output_path(
        value,
        overwrite=overwrite,
        windows_private_acl=False,
        windows_require_existing_protected_acl=False,
    )
    content = text.encode("utf-8", errors="strict")
    if len(content) > max_size:
        raise SensitivePathError(
            "sensitive_output_too_large",
            "sensitive output exceeds the size limit",
        )
    _atomic_private_write(
        path,
        content,
        overwrite=overwrite,
        windows_private_acl=False,
        windows_require_existing_protected_acl=False,
    )


def sensitive_path_identity(
    value: str | Path,
    *,
    exists: bool,
    windows_private_acl: bool = False,
    windows_integrity_acl: bool = False,
    windows_require_protected_acl: bool = False,
) -> object:
    """Return a path-free identity token for role/collision comparisons."""

    path = (
        validate_sensitive_input_path(
            value,
            windows_private_acl=windows_private_acl,
            windows_integrity_acl=windows_integrity_acl,
            windows_require_protected_acl=windows_require_protected_acl,
        )
        if exists
        else validate_sensitive_output_path(
            value,
            overwrite=False,
            windows_private_acl=windows_private_acl,
        )
    )
    if os.name == "nt":
        try:
            return windows_sensitive_path_identity(
                path,
                _PACKAGE_REPOSITORY_ROOT,
                private_acl=windows_private_acl,
                integrity_acl=windows_integrity_acl,
                require_protected_acl=windows_require_protected_acl,
            )
        except WindowsSensitiveFileError as exc:
            raise SensitivePathError(exc.code, exc.public_message) from exc
    try:
        if exists:
            stat_result = path.stat()
            return ("existing", stat_result.st_dev, stat_result.st_ino)
        parent_stat = path.parent.stat()
        return ("missing", parent_stat.st_dev, parent_stat.st_ino, path.name)
    except OSError as exc:
        raise SensitivePathError(
            "sensitive_path_unavailable",
            "sensitive path cannot be safely inspected",
        ) from exc


def remove_sensitive_file_if_matches(
    value: str | Path,
    expected: bytes,
    *,
    max_size: int = MAX_SENSITIVE_FILE_BYTES,
    windows_private_acl: bool = False,
    windows_integrity_acl: bool = False,
    windows_require_protected_acl: bool = False,
) -> bool:
    """Remove only one verified regular file with exact expected content."""

    path = _absolute_local_path(value)
    if os.name == "nt":
        try:
            return remove_windows_sensitive_file_if_matches(
                path,
                _PACKAGE_REPOSITORY_ROOT,
                expected,
                max_size=max_size,
                private_acl=windows_private_acl,
                integrity_acl=windows_integrity_acl,
                require_protected_acl=windows_require_protected_acl,
            )
        except WindowsSensitiveFileError as exc:
            raise SensitivePathError(exc.code, exc.public_message) from exc
    try:
        if not path.exists():
            return True
        actual = read_sensitive_bytes(path, max_size=max_size)
        if not hmac.compare_digest(actual, expected):
            return False
        path.unlink()
        return not path.exists()
    except OSError as exc:
        raise SensitivePathError(
            "sensitive_cleanup_failed",
            "sensitive artifact cleanup failed",
        ) from exc


JsonValue = None | bool | int | float | str | Sequence["JsonValue"] | Mapping[str, "JsonValue"]


def atomic_write_private_json(
    value: str | Path,
    payload: Mapping[str, JsonValue],
    *,
    overwrite: bool = False,
    max_size: int = MAX_SENSITIVE_FILE_BYTES,
    windows_require_existing_protected_acl: bool = False,
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
        windows_require_existing_protected_acl=windows_require_existing_protected_acl,
    )


__all__ = [
    "MAX_SENSITIVE_FILE_BYTES",
    "JsonValue",
    "SensitivePathError",
    "atomic_write_integrity_text",
    "atomic_write_private_json",
    "atomic_write_private_text",
    "read_private_sensitive_bytes",
    "read_sensitive_bytes",
    "remove_sensitive_file_if_matches",
    "sensitive_path_identity",
    "validate_sensitive_input_path",
    "validate_sensitive_output_path",
]
