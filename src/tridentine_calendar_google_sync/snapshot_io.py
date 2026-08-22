"""Atomic no-overwrite storage for sensitive sanitized snapshot bytes."""

from __future__ import annotations

from pathlib import Path

from tridentine_calendar_google_sync.google_models import GoogleSnapshot
from tridentine_calendar_google_sync.google_sanitize import render_sanitized_snapshot
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    validate_sensitive_output_path,
)

MAX_SNAPSHOT_OUTPUT_BYTES = 64 * 1024 * 1024


class SnapshotWriteError(OSError):
    """A content-free local snapshot write failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def validate_snapshot_output(output: str | Path) -> Path:
    """Preflight an absolute private output path without creating it."""

    try:
        return validate_sensitive_output_path(output, overwrite=False)
    except SensitivePathError as exc:
        raise SnapshotWriteError(
            exc.code,
            "snapshot output path is unsafe or unavailable",
        ) from exc


def write_snapshot_atomic(
    output: str | Path,
    payload: bytes,
    *,
    repository_root: Path | None = None,
) -> Path:
    """Atomically create a private snapshot outside every committed worktree."""

    del repository_root  # Shared sensitive-path validation discovers committed worktrees.
    if len(payload) > MAX_SNAPSHOT_OUTPUT_BYTES:
        raise SnapshotWriteError("snapshot_output_too_large", "snapshot output exceeds size limit")
    try:
        text = payload.decode("utf-8", errors="strict")
        path = validate_snapshot_output(output)
        atomic_write_private_text(
            path,
            text,
            overwrite=False,
            max_size=MAX_SNAPSHOT_OUTPUT_BYTES,
        )
        return path
    except UnicodeDecodeError as exc:
        raise SnapshotWriteError(
            "invalid_snapshot_output",
            "snapshot output is not valid UTF-8",
        ) from exc
    except SensitivePathError as exc:
        raise SnapshotWriteError(
            exc.code,
            "snapshot could not be written safely",
        ) from exc


def write_google_snapshot(
    snapshot: GoogleSnapshot,
    output: str | Path,
    *,
    repository_root: Path | None = None,
) -> Path:
    """Render and atomically store one sanitized Google snapshot."""

    return write_snapshot_atomic(
        output,
        render_sanitized_snapshot(snapshot),
        repository_root=repository_root,
    )


__all__ = [
    "MAX_SNAPSHOT_OUTPUT_BYTES",
    "SnapshotWriteError",
    "validate_snapshot_output",
    "write_google_snapshot",
    "write_snapshot_atomic",
]
