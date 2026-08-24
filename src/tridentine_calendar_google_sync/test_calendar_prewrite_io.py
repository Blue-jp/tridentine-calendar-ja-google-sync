"""Strict private snapshot I/O and atomic Test prewrite artifact output."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from tridentine_calendar_google_sync.google_sanitize import snapshot_document
from tridentine_calendar_google_sync.google_snapshot import parse_google_snapshot_bytes
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    read_sensitive_bytes,
    validate_sensitive_output_path,
)
from tridentine_calendar_google_sync.snapshot_io import MAX_SNAPSHOT_OUTPUT_BYTES
from tridentine_calendar_google_sync.test_calendar_prewrite import (
    TestCalendarPrewriteError,
    TestCalendarPrewriteResult,
    verify_test_calendar_prewrite_result,
    verify_test_calendar_prewrite_snapshot,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_models import (
    TestCalendarPrewriteSnapshot,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_report import (
    render_test_calendar_prewrite_json_report,
    render_test_calendar_prewrite_text_report,
)

MAX_TEST_PREWRITE_SNAPSHOT_BYTES = MAX_SNAPSHOT_OUTPUT_BYTES


class TestCalendarPrewriteIOError(ValueError):
    """A content-free private prewrite artifact I/O failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


@dataclass(frozen=True, slots=True, repr=False)
class TestCalendarPrewriteOutputPaths:
    """Three prevalidated private outputs hidden from repr and logs."""

    snapshot: Path
    human_report: Path
    json_report: Path

    def __repr__(self) -> str:
        return "TestCalendarPrewriteOutputPaths(configured=True)"


class _DuplicateJsonKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def _verify_snapshot(snapshot: TestCalendarPrewriteSnapshot) -> None:
    try:
        verify_test_calendar_prewrite_snapshot(snapshot)
    except TestCalendarPrewriteError as exc:
        raise TestCalendarPrewriteIOError(
            "test_prewrite_snapshot_integrity_mismatch",
            "Test prewrite snapshot integrity verification failed",
        ) from exc


def test_calendar_prewrite_snapshot_data(
    snapshot: TestCalendarPrewriteSnapshot,
) -> dict[str, object]:
    """Return the complete repository-external private snapshot document."""

    _verify_snapshot(snapshot)
    return {
        "schema_version": snapshot.schema_version,
        "snapshot_type": snapshot.snapshot_type,
        "test_only": snapshot.test_only,
        "production_locked": snapshot.production_locked,
        "target_fingerprint": snapshot.target_fingerprint,
        "target_safe_ref": snapshot.target_safe_ref,
        "complete": snapshot.complete,
        "page_count": snapshot.page_count,
        "api_call_count": snapshot.api_call_count,
        "retry_count": snapshot.retry_count,
        "snapshot": snapshot_document(snapshot.snapshot),
        "snapshot_content_hash": snapshot.snapshot_content_hash,
        "wrapper_content_hash": snapshot.wrapper_content_hash,
    }


def render_test_calendar_prewrite_snapshot(
    snapshot: TestCalendarPrewriteSnapshot,
) -> str:
    """Render deterministic private JSON without Calendar ID or credentials."""

    return (
        json.dumps(
            test_calendar_prewrite_snapshot_data(snapshot),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def parse_test_calendar_prewrite_snapshot_bytes(
    raw_bytes: bytes,
) -> TestCalendarPrewriteSnapshot:
    """Strictly parse, bind, and hash-verify one private snapshot wrapper."""

    if len(raw_bytes) > MAX_TEST_PREWRITE_SNAPSHOT_BYTES:
        raise TestCalendarPrewriteIOError(
            "test_prewrite_snapshot_too_large",
            "Test prewrite snapshot exceeds the size limit",
        )
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict):
            raise TypeError
        normalized = dict(value)
        nested = normalized.get("snapshot")
        if not isinstance(nested, dict):
            raise TypeError
        nested_snapshot = parse_google_snapshot_bytes(
            json.dumps(
                nested,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        )
        normalized["snapshot"] = nested_snapshot
        snapshot = TestCalendarPrewriteSnapshot.model_validate(normalized, strict=True)
        _verify_snapshot(snapshot)
        return snapshot
    except TestCalendarPrewriteIOError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise TestCalendarPrewriteIOError(
            "invalid_test_prewrite_snapshot",
            "Test prewrite snapshot is invalid",
        ) from exc


def load_test_calendar_prewrite_snapshot(
    path: str | Path,
) -> TestCalendarPrewriteSnapshot:
    """Load one bounded repository-external private snapshot wrapper."""

    try:
        return parse_test_calendar_prewrite_snapshot_bytes(
            read_sensitive_bytes(path, max_size=MAX_TEST_PREWRITE_SNAPSHOT_BYTES)
        )
    except TestCalendarPrewriteIOError:
        raise
    except SensitivePathError as exc:
        raise TestCalendarPrewriteIOError(
            "unsafe_test_prewrite_snapshot_path",
            "Test prewrite snapshot path is unsafe or unavailable",
        ) from exc


def validate_test_calendar_prewrite_output_paths(
    snapshot_output: str | Path,
    human_report_output: str | Path,
    json_report_output: str | Path,
) -> TestCalendarPrewriteOutputPaths:
    """Prevalidate three distinct repository-external no-overwrite paths."""

    try:
        paths = TestCalendarPrewriteOutputPaths(
            snapshot=validate_sensitive_output_path(snapshot_output, overwrite=False),
            human_report=validate_sensitive_output_path(
                human_report_output,
                overwrite=False,
            ),
            json_report=validate_sensitive_output_path(json_report_output, overwrite=False),
        )
        resolved = {
            paths.snapshot.resolve(strict=False),
            paths.human_report.resolve(strict=False),
            paths.json_report.resolve(strict=False),
        }
        if len(resolved) != 3:
            raise TestCalendarPrewriteIOError(
                "test_prewrite_output_paths_collide",
                "Test prewrite output paths must be distinct",
            )
        return paths
    except TestCalendarPrewriteIOError:
        raise
    except (SensitivePathError, OSError) as exc:
        raise TestCalendarPrewriteIOError(
            "unsafe_test_prewrite_output_path",
            "Test prewrite output path is unsafe or unavailable",
        ) from exc


def write_test_calendar_prewrite_snapshot(
    snapshot: TestCalendarPrewriteSnapshot,
    path: str | Path,
) -> Path:
    """Atomically create one private snapshot wrapper without overwrite."""

    rendered = render_test_calendar_prewrite_snapshot(snapshot)
    try:
        output = validate_sensitive_output_path(path, overwrite=False)
        atomic_write_private_text(
            output,
            rendered,
            overwrite=False,
            max_size=MAX_TEST_PREWRITE_SNAPSHOT_BYTES,
        )
        return output
    except SensitivePathError as exc:
        raise TestCalendarPrewriteIOError(
            "test_prewrite_snapshot_write_failed",
            "Test prewrite snapshot could not be written safely",
        ) from exc


def _cleanup_created(paths: list[Path]) -> None:
    for path in reversed(paths):
        try:
            if path.is_file() and not path.is_symlink():
                path.unlink()
        except OSError:
            continue


def write_test_calendar_prewrite_outputs(
    result: TestCalendarPrewriteResult,
    *,
    snapshot_output: str | Path,
    human_report_output: str | Path,
    json_report_output: str | Path,
) -> TestCalendarPrewriteOutputPaths:
    """Render and prevalidate all three artifacts before any atomic creation."""

    verify_test_calendar_prewrite_result(result)
    snapshot_text = render_test_calendar_prewrite_snapshot(result.snapshot)
    human_text = render_test_calendar_prewrite_text_report(result)
    json_text = render_test_calendar_prewrite_json_report(result)
    paths = validate_test_calendar_prewrite_output_paths(
        snapshot_output,
        human_report_output,
        json_report_output,
    )
    created: list[Path] = []
    try:
        atomic_write_private_text(
            paths.snapshot,
            snapshot_text,
            overwrite=False,
            max_size=MAX_TEST_PREWRITE_SNAPSHOT_BYTES,
        )
        created.append(paths.snapshot)
        atomic_write_private_text(paths.human_report, human_text, overwrite=False)
        created.append(paths.human_report)
        atomic_write_private_text(paths.json_report, json_text, overwrite=False)
        created.append(paths.json_report)
        return paths
    except (SensitivePathError, OSError) as exc:
        _cleanup_created(created)
        raise TestCalendarPrewriteIOError(
            "test_prewrite_output_write_failed",
            "Test prewrite outputs could not be written safely",
        ) from exc
    except TestCalendarPrewriteError:
        _cleanup_created(created)
        raise


__all__ = [
    "MAX_TEST_PREWRITE_SNAPSHOT_BYTES",
    "TestCalendarPrewriteIOError",
    "TestCalendarPrewriteOutputPaths",
    "load_test_calendar_prewrite_snapshot",
    "parse_test_calendar_prewrite_snapshot_bytes",
    "render_test_calendar_prewrite_snapshot",
    "test_calendar_prewrite_snapshot_data",
    "validate_test_calendar_prewrite_output_paths",
    "write_test_calendar_prewrite_outputs",
    "write_test_calendar_prewrite_snapshot",
]
