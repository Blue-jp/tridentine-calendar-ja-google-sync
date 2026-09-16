"""Independent descriptor-bound POSIX replacement; not yet used by token refresh.

The expected-content checks and rename are separate operations, NOT a lock or
inode compare-and-swap. Same-UID/privileged races and filesystem ACL/mount rules
remain assumptions. Failures never trigger deletion, rollback or automatic retry.
"""

from __future__ import annotations

import os
import secrets
import stat
from contextlib import suppress
from pathlib import Path

from tridentine_calendar_google_sync import _posix_private_create as create
from tridentine_calendar_google_sync import _posix_sensitive_directory as directory
from tridentine_calendar_google_sync.sensitive_paths import (
    MAX_SENSITIVE_FILE_BYTES,
    _prepare_posix_private_output_fd,
)


class PosixPrivateReplaceError(ValueError):
    """Path/content-free error; a replace attempt always leaves publication uncertain."""

    def __init__(self, code: str, *, publication_possible: bool = False) -> None:
        self.code = code
        self.publication_possible = publication_possible
        self.public_message = (
            "private replacement could not be verified; "
            "do not retry, remove, or restore files automatically"
        )
        super().__init__(self.public_message)


def _check_original(
    bound: directory._BoundPrivateDirectory,
    name: str,
    descriptor: int,
    original: os.stat_result,
    uid: int,
    expected: bytes,
) -> None:
    current = create._check_content(descriptor, original, uid, expected, 1)
    if (current.st_mtime_ns, current.st_ctime_ns) != (
        original.st_mtime_ns,
        original.st_ctime_ns,
    ):
        raise PosixPrivateReplaceError("posix_replace_original_changed")
    create._check_name(bound.descriptor, name, current)


def replace_posix_private_bytes(path: Path, content: bytes, *, expected_content: bytes) -> None:
    """Replace an observed existing private file through a retained 0700 parent.

    Require bounded exact prior bytes, not a hash or a missing-file create. Keep
    both leaf descriptors and the root-to-parent binding until verification ends.
    Before replacement, both names and contents are rechecked. After an attempted
    rename, True evidence never promises the old or new bytes exist at that name.
    Failures may leave a private temporary; no failure cleanup touches any name.
    Existing public writers/refresh are not routed to this function in Unit 4K.
    """
    if os.name != "posix":
        raise PosixPrivateReplaceError("posix_replace_unavailable")
    if (
        not isinstance(path, Path)
        or path.anchor != "/"
        or ".." in path.parts
        or path.name in ("", ".", "..", ".git")
        or "\x00" in str(path)
    ):
        raise PosixPrivateReplaceError("posix_replace_path_invalid")
    if (
        not isinstance(content, bytes)
        or not isinstance(expected_content, bytes)
        or len(content) > MAX_SENSITIVE_FILE_BYTES
        or len(expected_content) > MAX_SENSITIVE_FILE_BYTES
    ):
        raise PosixPrivateReplaceError("posix_replace_content_invalid")

    bound: directory._BoundPrivateDirectory | None = None
    old_fd = -1
    new_fd = -1
    publication_possible = False
    try:
        no_follow = getattr(os, "O_NOFOLLOW", 0)
        close_on_exec = getattr(os, "O_CLOEXEC", 0)
        nonblocking = getattr(os, "O_NONBLOCK", 0)
        if (
            not no_follow
            or not close_on_exec
            or not nonblocking
            or not callable(getattr(os, "pread", None))
            or not callable(getattr(os, "replace", None))
        ):
            raise PosixPrivateReplaceError("posix_replace_unavailable")
        bound = directory.open_posix_private_directory(path.parent)
        uid = directory._effective_uid()
        bound.revalidate()
        named = os.stat(path.name, dir_fd=bound.descriptor, follow_symlinks=False)
        if (
            not stat.S_ISREG(named.st_mode)
            or named.st_uid != uid
            or named.st_nlink != 1
            or stat.S_IMODE(named.st_mode) != 0o600
            or named.st_size != len(expected_content)
        ):
            raise PosixPrivateReplaceError("posix_replace_original_unsafe")
        old_fd = os.open(
            path.name,
            os.O_RDONLY | no_follow | close_on_exec | nonblocking,
            dir_fd=bound.descriptor,
        )
        original = os.fstat(old_fd)
        if (original.st_dev, original.st_ino) != (named.st_dev, named.st_ino):
            raise PosixPrivateReplaceError("posix_replace_original_changed")
        _check_original(bound, path.name, old_fd, original, uid, expected_content)
        bound.revalidate()

        temporary: str | None = None
        for _ in range(16):
            name = ".private-replace-" + secrets.token_hex(16)
            if name == path.name:
                continue
            bound.revalidate()
            try:
                new_fd = os.open(
                    name,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL | no_follow | close_on_exec,
                    0o600,
                    dir_fd=bound.descriptor,
                )
            except FileExistsError:
                continue
            temporary = name
            break
        if new_fd < 0 or temporary is None:
            raise PosixPrivateReplaceError("posix_replace_name_exhausted")
        new_identity = os.fstat(new_fd)
        _prepare_posix_private_output_fd(new_fd)
        current = create._check_file(new_fd, new_identity, uid, 1)
        create._check_name(bound.descriptor, temporary, current)
        bound.revalidate()
        offset = 0
        while offset < len(content):
            chunk = content[offset : offset + 65536]
            amount = os.write(new_fd, chunk)
            if type(amount) is not int or not 0 < amount <= len(chunk):
                raise PosixPrivateReplaceError("posix_replace_write_failed")
            offset += amount
        os.fsync(new_fd)
        current = create._check_content(new_fd, new_identity, uid, content, 1)
        bound.revalidate()
        _check_original(bound, path.name, old_fd, original, uid, expected_content)
        create._check_name(bound.descriptor, temporary, current)
        bound.revalidate()
        # Separate checks cannot make replace conditional on the checked inode.
        # Keep both descriptors open; neither another creator nor a pathname is
        # treated as proof of ownership for rollback or deletion.
        publication_possible = True
        os.replace(
            temporary,
            path.name,
            src_dir_fd=bound.descriptor,
            dst_dir_fd=bound.descriptor,
        )
        bound.revalidate()
        # The old inode stays open but should no longer be linked. Verify it too;
        # any failure here is after an attempted replacement, never a rollback.
        create._check_content(old_fd, original, uid, expected_content, 0)
        current = create._check_content(new_fd, new_identity, uid, content, 1)
        create._check_name(bound.descriptor, path.name, current)
        os.fsync(bound.descriptor)
        bound.revalidate()
        current = create._check_content(new_fd, new_identity, uid, content, 1)
        create._check_name(bound.descriptor, path.name, current)
    except PosixPrivateReplaceError as exc:
        raise PosixPrivateReplaceError(
            exc.code, publication_possible=publication_possible
        ) from None
    except Exception:
        # A nonstandard filesystem/backend exception must also retain attempt
        # evidence. Cancellation/BaseException is not a recovery contract here.
        raise PosixPrivateReplaceError(
            "posix_replace_unverified", publication_possible=publication_possible
        ) from None
    finally:
        # No unlink/chmod/path-repair: leave uncertain private residue alone.
        for descriptor in (new_fd, old_fd):
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
        if bound is not None:
            bound.close()
