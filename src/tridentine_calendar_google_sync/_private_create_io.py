"""Opt-in create-only adapter for single-file planning outputs, not token bundles.

POSIX uses the retained-directory publisher; Windows retains the existing private
writer. Uncertainty is evidence for stopping, never permission to retry or delete.
"""

from __future__ import annotations

import os
from pathlib import Path

from tridentine_calendar_google_sync import _posix_private_create as posix_create
from tridentine_calendar_google_sync.sensitive_paths import (
    MAX_SENSITIVE_FILE_BYTES,
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


def create_private_text(
    value: str | Path, text: str, *, max_size: int = MAX_SENSITIVE_FILE_BYTES
) -> None:
    """Create a single planning artifact without overwrite, retry, or rollback.

    A POSIX parent must be effective-user-owned and exactly 0700. False evidence
    only rules out a final-name publication attempt by this call, not private
    temporary residue or a file written by someone else. Unexpected backend and
    Windows writer errors use None (unknown), not a false side-effect-free claim.
    """
    publication_possible: bool | None = False
    try:
        if type(max_size) is not int or not 0 < max_size <= MAX_SENSITIVE_FILE_BYTES:
            raise PrivateCreateIOError(publication_possible=False)
        content = text.encode("utf-8", errors="strict")
        if len(content) > max_size or os.name not in ("nt", "posix"):
            raise PrivateCreateIOError(publication_possible=False)
        path = validate_sensitive_output_path(value, overwrite=False, windows_private_acl=True)
        # Once any writer is entered, unspecified errors must remain uncertain.
        publication_possible = None
        if os.name == "nt":
            atomic_write_private_text(path, text, overwrite=False, max_size=max_size)
        else:
            posix_create.create_posix_private_bytes(path, content)
    except PrivateCreateIOError:
        raise
    except posix_create.PosixPrivateCreateError as exc:
        raise PrivateCreateIOError(publication_possible=exc.publication_possible) from None
    except Exception:
        raise PrivateCreateIOError(publication_possible=publication_possible) from None
