"""Read-only POSIX private-directory binding foundation; not yet a writer backend.

This module does not create, publish, remove, or re-permission artifacts. Callers
must use relative names with the retained descriptor and revalidate at operation
boundaries. It is not a lock or a complete publication/cleanup protocol.
"""

from __future__ import annotations

import os
import stat
from contextlib import suppress
from pathlib import Path
from types import TracebackType
from typing import Never, Self

_PACKAGE_REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
_MAX_COMPONENTS = 128


class PosixSensitiveDirectoryError(ValueError):
    """An error containing neither the private path nor raw operating-system text."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _reject(code: str) -> Never:
    raise PosixSensitiveDirectoryError(code, "private directory binding could not be verified")


def _effective_uid() -> int:
    getter = getattr(os, "geteuid", None)
    if not callable(getter):
        _reject("posix_directory_binding_unavailable")
    uid = getter()
    if not isinstance(uid, int) or uid < 0:
        _reject("posix_directory_binding_unavailable")
    return uid


def _same_directory(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        stat.S_ISDIR(first.st_mode)
        and stat.S_ISDIR(second.st_mode)
        and (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino)
    )


def _check_policy(info: os.stat_result, *, effective_uid: int, private_parent: bool) -> None:
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, effective_uid):
        _reject("posix_directory_owner_or_type_unsafe")
    mode = stat.S_IMODE(info.st_mode)
    if private_parent:
        # Only the final writable parent is required to be exactly private.
        if info.st_uid != effective_uid or mode != 0o700:
            _reject("posix_directory_private_parent_unsafe")
    elif mode & 0o022 and (info.st_uid != 0 or not mode & stat.S_ISVTX):
        # A root-owned sticky ancestor (e.g. /tmp) protects owned descendants
        # from removal by a different unprivileged user. Never allow it as the
        # final private parent; each next child must also have a trusted owner.
        _reject("posix_directory_ancestor_writable")


def _check_marker(descriptor: int) -> None:
    try:
        os.stat(".git", dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    _reject("posix_directory_git_marker")


class _BoundPrivateDirectory:
    """Own the retained root-to-parent descriptors until exit or failed validation."""

    def __init__(self, effective_uid: int) -> None:
        self._effective_uid = effective_uid
        self._entries: list[tuple[str, int, os.stat_result]] = []
        self._closed = False

    @property
    def descriptor(self) -> int:
        if self._closed or not self._entries:
            _reject("posix_directory_binding_closed")
        return self._entries[-1][1]

    def __enter__(self) -> Self:
        self.revalidate()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            for _, descriptor, _ in reversed(self._entries):
                # Do not retry a close: a failed close can already have released
                # its descriptor, and retrying could close a reused descriptor.
                with suppress(OSError):
                    os.close(descriptor)
            self._entries.clear()

    def _revalidate(self) -> None:
        if self._closed or not self._entries:
            _reject("posix_directory_binding_closed")
        if _effective_uid() != self._effective_uid:
            _reject("posix_directory_effective_owner_changed")
        for index, (name, descriptor, original) in enumerate(self._entries):
            current = os.fstat(descriptor)
            if not _same_directory(original, current):
                _reject("posix_directory_identity_mismatch")
            _check_policy(
                current,
                effective_uid=self._effective_uid,
                private_parent=index == len(self._entries) - 1,
            )
            if index == 0:
                named = os.stat("/", follow_symlinks=False)
            else:
                named = os.stat(
                    name,
                    dir_fd=self._entries[index - 1][1],
                    follow_symlinks=False,
                )
            if not _same_directory(current, named):
                _reject("posix_directory_identity_mismatch")
            _check_marker(descriptor)

    def revalidate(self) -> None:
        """Recheck retained identity, authority, names and markers; invalidate on error."""
        try:
            self._revalidate()
        except PosixSensitiveDirectoryError:
            self.close()
            raise
        except (OSError, AttributeError, NotImplementedError):
            self.close()
            raise PosixSensitiveDirectoryError(
                "posix_directory_inspection_failed",
                "private directory binding could not be verified",
            ) from None
        except BaseException:
            self.close()
            raise


def open_posix_private_directory(path: Path) -> _BoundPrivateDirectory:
    """Open one existing 0700 parent through no-follow relative directory opens.

    Root and intermediate directories must belong to root or the effective user,
    and must not grant group/other write except for root-owned sticky ancestors.
    The final parent must belong to the effective user and have mode exactly 0700.
    No fallback, permission repair, marker content read, or subprocess is provided.
    """
    if os.name != "posix":
        _reject("posix_directory_binding_unavailable")
    if not isinstance(path, Path) or path.anchor != "/" or ".." in path.parts:
        _reject("posix_directory_path_invalid")
    if len(path.parts) > _MAX_COMPONENTS or len(path.parts) < 2:
        _reject("posix_directory_path_invalid")
    if path.is_relative_to(_PACKAGE_REPOSITORY_ROOT):
        _reject("posix_directory_git_marker")
    bound: _BoundPrivateDirectory | None = None
    try:
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        close_on_exec = getattr(os, "O_CLOEXEC", 0)
        if not no_follow or not directory_flag or not close_on_exec:
            _reject("posix_directory_binding_unavailable")
        effective_uid = _effective_uid()
        bound = _BoundPrivateDirectory(effective_uid)
        flags = os.O_RDONLY | no_follow | directory_flag | close_on_exec
        for index, name in enumerate(path.parts):
            # After the root, every lookup is relative to a retained directory.
            parent_fd = None if index == 0 else bound.descriptor
            lookup = "/" if index == 0 else name
            before = os.stat(lookup, dir_fd=parent_fd, follow_symlinks=False)
            _check_policy(
                before,
                effective_uid=effective_uid,
                private_parent=index == len(path.parts) - 1,
            )
            descriptor = os.open(lookup, flags, dir_fd=parent_fd)
            try:
                opened = os.fstat(descriptor)
            except BaseException:
                with suppress(OSError):
                    os.close(descriptor)
                raise
            bound._entries.append((name, descriptor, opened))
            if not _same_directory(before, opened):
                _reject("posix_directory_identity_mismatch")
            _check_policy(
                opened,
                effective_uid=effective_uid,
                private_parent=index == len(path.parts) - 1,
            )
            _check_marker(descriptor)
        bound.revalidate()
        return bound
    except PosixSensitiveDirectoryError:
        if bound is not None:
            bound.close()
        raise
    except (OSError, AttributeError, NotImplementedError):
        if bound is not None:
            bound.close()
        raise PosixSensitiveDirectoryError(
            "posix_directory_inspection_failed",
            "private directory binding could not be verified",
        ) from None
    except BaseException:
        if bound is not None:
            bound.close()
        raise
