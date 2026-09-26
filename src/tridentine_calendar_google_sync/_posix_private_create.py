"""Create-only POSIX byte publisher; selected planning writers opt in via an adapter.

The directory and source descriptors remain open throughout. No overwrite or
final-name rollback is provided. Name checks are not an inode compare-and-swap;
same-UID/privileged mutation and filesystem ACL/mount policy remain assumptions.
"""

from __future__ import annotations

import hmac
import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path

from tridentine_calendar_google_sync import _posix_sensitive_directory as directory
from tridentine_calendar_google_sync.sensitive_paths import (
    MAX_SENSITIVE_FILE_BYTES,
    _prepare_posix_private_output_fd,
)


class PosixPrivateCreateError(ValueError):
    """Safe error; publication_possible forbids assuming failure left no output."""

    def __init__(self, code: str, *, publication_possible: bool = False) -> None:
        self.code = code
        self.publication_possible = publication_possible
        self.public_message = "private create-only output could not be verified"
        super().__init__(self.public_message)


def _check_file(
    descriptor: int, identity: os.stat_result, effective_uid: int, links: int
) -> os.stat_result:
    current = os.fstat(descriptor)
    if (
        not stat.S_ISREG(current.st_mode)
        or (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino)
        or current.st_uid != effective_uid
        or directory._effective_uid() != effective_uid
        or stat.S_IMODE(current.st_mode) != 0o600
        or current.st_nlink != links
    ):
        raise PosixPrivateCreateError("posix_create_file_changed")
    return current


def _check_name(parent_fd: int, name: str, current: os.stat_result) -> None:
    named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISREG(named.st_mode) or (named.st_dev, named.st_ino) != (
        current.st_dev,
        current.st_ino,
    ):
        raise PosixPrivateCreateError("posix_create_name_changed")


def _check_content(
    descriptor: int, identity: os.stat_result, uid: int, content: bytes, links: int
) -> os.stat_result:
    before = _check_file(descriptor, identity, uid, links)
    if before.st_size != len(content):
        raise PosixPrivateCreateError("posix_create_content_changed")
    chunks = bytearray()
    while len(chunks) <= len(content):
        read_at = getattr(os, "pread", None)
        if not callable(read_at):
            raise PosixPrivateCreateError("posix_create_unavailable")
        size = min(65536, len(content) + 1 - len(chunks))
        block = read_at(descriptor, size, len(chunks))
        if not isinstance(block, bytes) or len(block) > size:
            raise PosixPrivateCreateError("posix_create_content_changed")
        if not block:
            break
        chunks.extend(block)
    after = _check_file(descriptor, identity, uid, links)
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ) or not hmac.compare_digest(chunks, content):
        raise PosixPrivateCreateError("posix_create_content_changed")
    return after


def _remove_own_temporary(
    bound: directory._BoundPrivateDirectory,
    name: str,
    descriptor: int,
    identity: os.stat_result,
    uid: int,
) -> None:
    # Never remove the final destination. On unverifiable identity/ancestry, leave
    # the private temporary behind instead of following a different pathname.
    bound.revalidate()
    current = os.fstat(descriptor)
    if current.st_nlink not in (1, 2):
        raise PosixPrivateCreateError("posix_create_file_changed")
    current = _check_file(descriptor, identity, uid, current.st_nlink)
    _check_name(bound.descriptor, name, current)
    bound.revalidate()
    _check_name(bound.descriptor, name, current)
    os.unlink(name, dir_fd=bound.descriptor)
    try:
        os.stat(name, dir_fd=bound.descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise PosixPrivateCreateError("posix_create_temporary_still_present")


def create_posix_private_bytes(path: Path, content: bytes) -> None:
    """Publish bytes under an absent name in a retained, effective-user-owned 0700 parent.

    Only local POSIX semantics supported by dir_fd, no-follow, link and pread are
    used. No path fallback, destination replacement, automatic final rollback,
    permission repair, or generic public-writer dispatch is part of this increment.
    Errors after a link attempt can leave a published artifact and/or private temp.
    """
    if os.name != "posix":
        raise PosixPrivateCreateError("posix_create_unavailable")
    if (
        not isinstance(path, Path)
        or path.anchor != "/"
        or ".." in path.parts
        or path.name in ("", ".", "..", ".git")
        or "\x00" in str(path)
    ):
        raise PosixPrivateCreateError("posix_create_path_invalid")
    if not isinstance(content, bytes) or len(content) > MAX_SENSITIVE_FILE_BYTES:
        raise PosixPrivateCreateError("posix_create_content_invalid")
    bound: directory._BoundPrivateDirectory | None = None
    descriptor = -1
    temporary: str | None = None
    identity: os.stat_result | None = None
    uid = -1
    publication_possible = False
    try:
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        close_on_exec = getattr(os, "O_CLOEXEC", 0)
        if not no_follow or not close_on_exec or not callable(getattr(os, "pread", None)):
            raise PosixPrivateCreateError("posix_create_unavailable")
        bound = directory.open_posix_private_directory(path.parent)
        uid = directory._effective_uid()
        bound.revalidate()
        try:
            os.stat(path.name, dir_fd=bound.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise PosixPrivateCreateError("posix_create_output_exists")
        for _ in range(16):
            name = ".private-create-" + secrets.token_hex(16)
            if name == path.name:
                continue
            bound.revalidate()
            try:
                descriptor = os.open(
                    name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | no_follow | close_on_exec,
                    0o600,
                    dir_fd=bound.descriptor,
                )
            except FileExistsError:
                continue
            temporary = name
            break
        if descriptor < 0 or temporary is None:
            raise PosixPrivateCreateError("posix_create_name_exhausted")
        identity = os.fstat(descriptor)
        _prepare_posix_private_output_fd(descriptor)
        current = _check_file(descriptor, identity, uid, 1)
        _check_name(bound.descriptor, temporary, current)
        bound.revalidate()
        offset = 0
        while offset < len(content):
            amount = os.write(descriptor, content[offset : offset + 65536])
            if amount <= 0 or amount > len(content) - offset:
                raise PosixPrivateCreateError("posix_create_write_failed")
            offset += amount
        os.fsync(descriptor)
        current = _check_content(descriptor, identity, uid, content, 1)
        bound.revalidate()
        _check_name(bound.descriptor, temporary, current)
        publication_possible = True
        try:
            os.link(
                temporary,
                path.name,
                src_dir_fd=bound.descriptor,
                dst_dir_fd=bound.descriptor,
                follow_symlinks=False,
            )
        except FileExistsError:
            # Remain conservative after any publication attempt, including an
            # existence error. The flag is not proof that a destination changed.
            raise PosixPrivateCreateError("posix_create_output_exists") from None
        bound.revalidate()
        current = _check_content(descriptor, identity, uid, content, 2)
        _check_name(bound.descriptor, path.name, current)
        _check_name(bound.descriptor, temporary, current)
        _remove_own_temporary(bound, temporary, descriptor, identity, uid)
        temporary = None
        bound.revalidate()
        os.fsync(bound.descriptor)
        bound.revalidate()
        current = _check_content(descriptor, identity, uid, content, 1)
        _check_name(bound.descriptor, path.name, current)
    except PosixPrivateCreateError as exc:
        raise PosixPrivateCreateError(exc.code, publication_possible=publication_possible) from None
    except (OSError, ValueError, AttributeError, NotImplementedError):
        raise PosixPrivateCreateError(
            "posix_create_unverified", publication_possible=publication_possible
        ) from None
    finally:
        if temporary is not None and bound is not None and identity is not None and descriptor >= 0:
            with suppress(
                OSError,
                directory.PosixSensitiveDirectoryError,
                PosixPrivateCreateError,
                AttributeError,
                NotImplementedError,
            ):
                _remove_own_temporary(bound, temporary, descriptor, identity, uid)
        if descriptor >= 0:
            with suppress(OSError):
                os.close(descriptor)
        if bound is not None:
            bound.close()
