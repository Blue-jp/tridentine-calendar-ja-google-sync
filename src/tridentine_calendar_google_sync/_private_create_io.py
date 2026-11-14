"""Create-only adapter for planning files and rehearsal evidence, not token bundles.

POSIX always uses the private retained-directory publisher. Windows retains its
existing private or integrity writer, according to the caller's artifact role.
No overwrite, automatic retry or rollback is provided.
"""

from __future__ import annotations

import os
from pathlib import Path

from tridentine_calendar_google_sync import _posix_private_create as posix_create
from tridentine_calendar_google_sync.sensitive_paths import (
    MAX_SENSITIVE_FILE_BYTES,
    atomic_write_integrity_text,
    atomic_write_private_text,
    validate_sensitive_output_path,
)


class PrivateCreateIOError(ValueError):
    """Path/content-free adapter error; None means publication state is unknown."""

    def __init__(self, *, publication_possible: bool | None) -> None:
        self.code = "private_create_failed"
        self.publication_possible = publication_possible
        self.public_message = "private create-only output could not be verified"
        super().__init__(self.public_message)


def _create_text(value: str | Path, text: str, *, max_size: int, private: bool) -> None:
    publication_possible: bool | None = False
    try:
        if type(max_size) is not int or not 0 < max_size <= MAX_SENSITIVE_FILE_BYTES:
            raise PrivateCreateIOError(publication_possible=False)
        content = text.encode("utf-8", errors="strict")
        if len(content) > max_size or os.name not in ("nt", "posix"):
            raise PrivateCreateIOError(publication_possible=False)
        path = validate_sensitive_output_path(value, overwrite=False, windows_private_acl=private)
        # Once any writer is entered, unspecified errors must remain uncertain.
        publication_possible = None
        if os.name == "nt":
            writer = atomic_write_private_text if private else atomic_write_integrity_text
            writer(path, text, overwrite=False, max_size=max_size)
        else:
            posix_create.create_posix_private_bytes(path, content)
    except PrivateCreateIOError:
        raise
    except posix_create.PosixPrivateCreateError as exc:
        raise PrivateCreateIOError(publication_possible=exc.publication_possible) from None
    except Exception:
        raise PrivateCreateIOError(publication_possible=publication_possible) from None


def create_private_text(
    value: str | Path, text: str, *, max_size: int = MAX_SENSITIVE_FILE_BYTES
) -> None:
    """Create one private file; uncertain publication never permits automatic retry.

    POSIX requires an existing effective-user-owned 0700 parent. False evidence
    only rules out a final-name publication attempt by this call, not private
    temporary residue or a file written by someone else. Unspecified backend and
    Windows writer errors use None rather than a side-effect-free claim.
    """
    _create_text(value, text, max_size=max_size, private=True)


def create_integrity_text(
    value: str | Path, text: str, *, max_size: int = MAX_SENSITIVE_FILE_BYTES
) -> None:
    """Create one sanitized report without weakening Windows integrity policy.

    POSIX uses the same 0600 publisher and 0700 parent as private outputs; this is
    local private storage for sanitized data, not a request for broad readership.
    Windows retains its existing integrity writer and publication uncertainty.
    """
    _create_text(value, text, max_size=max_size, private=False)
