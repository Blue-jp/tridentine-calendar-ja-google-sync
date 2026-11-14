"""Linux advisory directory lock; session loaders and new-pair publication cooperate.

Only cooperating users of this same directory inode and flock protocol contend.
This is not a file-content lock, compare-and-swap, or persistent recovery record.
Never fork/duplicate the private descriptors while holding a lock. Close releases
only this object's descriptors; inherited/duplicated descriptions can extend it.
"""

from __future__ import annotations

import errno
import os
import sys
from contextlib import suppress
from pathlib import Path
from types import TracebackType
from typing import Self

from tridentine_calendar_google_sync import _posix_sensitive_directory as directory


class PosixPrivateLockError(ValueError):
    """Path-free stop; busy/unavailable is never permission to proceed unlocked."""

    def __init__(self, code: str) -> None:
        self.code = code
        self.public_message = (
            "private directory lock could not be verified; do not proceed unlocked"
        )
        super().__init__(self.public_message)


if sys.platform == "linux":
    import fcntl

    def _lock_once(descriptor: int) -> None:
        # Exactly one nonblocking acquisition. No polling, sleep, or stale-file removal.
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

else:

    def _lock_once(descriptor: int) -> None:
        del descriptor
        raise PosixPrivateLockError("posix_directory_lock_unavailable")


class _PrivateDirectoryLock:
    """Own one independent directory-open description; use with a context manager."""

    def __init__(self, bound: directory._BoundPrivateDirectory, process_id: int) -> None:
        self._bound: directory._BoundPrivateDirectory | None = bound
        self._process_id = process_id
        self._entered = False

    def __enter__(self) -> Self:
        # Reject nested reuse without releasing the original context's lock.
        if self._entered:
            raise PosixPrivateLockError("posix_directory_lock_not_reentrant")
        self.revalidate()
        self._entered = True
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        if exc_type is None:
            self.close()
        else:
            # Cleanup must not replace the caller's exception/cancellation.
            with suppress(Exception):
                self.close()

    def close(self) -> None:
        bound, self._bound = self._bound, None
        if bound is not None:
            # No LOCK_UN: a post-fork child closing its duplicate must not unlock
            # the parent's shared open-file description. Never retry a close.
            bound.close()

    def revalidate(self) -> None:
        """Recheck the bound name/policy, not contents or a kernel lock attestation."""
        if self._bound is None:
            raise PosixPrivateLockError("posix_directory_lock_closed")
        try:
            if os.getpid() != self._process_id:
                raise PosixPrivateLockError("posix_directory_lock_process_changed")
            self._bound.revalidate()
        except PosixPrivateLockError:
            self.close()
            raise
        except Exception:
            self.close()
            raise PosixPrivateLockError("posix_directory_lock_unverified") from None
        except BaseException:
            self.close()
            raise


def acquire_posix_private_directory_lock(path: Path) -> _PrivateDirectoryLock:
    """Acquire one Linux-native, nonblocking advisory lock on an existing 0700 parent.

    No lock file, PID record, permission repair, content read/write, or fallback.
    Windows/other POSIX systems are explicitly unavailable in this first backend.
    The directory must retain its binding/policy before and after acquisition.
    The returned context exposes revalidation but no descriptor for lock mutation.
    An error or cancellation releases this attempt's descriptors, not any files.
    """
    if sys.platform == "linux":
        if os.name != "posix":
            raise PosixPrivateLockError("posix_directory_lock_unavailable")
        bound: directory._BoundPrivateDirectory | None = None
        try:
            process_id = os.getpid()
            bound = directory.open_posix_private_directory(path)
            bound.revalidate()
            _lock_once(bound.descriptor)
            bound.revalidate()
            if os.getpid() != process_id:
                raise PosixPrivateLockError("posix_directory_lock_process_changed")
            result = _PrivateDirectoryLock(bound, process_id)
            bound = None  # Transfer ownership only after all acquisition checks pass.
            return result
        except PosixPrivateLockError:
            raise
        except OSError as exc:
            code = (
                "posix_directory_lock_busy"
                if exc.errno in (errno.EAGAIN, errno.EWOULDBLOCK)
                else "posix_directory_lock_unverified"
            )
            raise PosixPrivateLockError(code) from None
        except Exception:
            raise PosixPrivateLockError("posix_directory_lock_unverified") from None
        finally:
            if bound is not None:
                bound.close()
    else:
        raise PosixPrivateLockError("posix_directory_lock_unavailable")
