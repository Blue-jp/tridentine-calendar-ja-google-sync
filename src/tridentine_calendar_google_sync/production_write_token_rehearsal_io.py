"""Atomic repository-external output for Phase 6D.0 rehearsal evidence."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from tridentine_calendar_google_sync.production_write_token_rehearsal_models import (
    ProductionWriteTokenRehearsalReport,
    ProductionWriteTokenRehearsalSnapshot,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_report import (
    render_production_write_token_rehearsal_report_json,
    render_production_write_token_rehearsal_report_text,
    render_production_write_token_rehearsal_snapshot_json,
)
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    validate_sensitive_output_path,
)

PRODUCTION_REHEARSAL_SNAPSHOT_FILENAME = "production-write-token-readonly-rehearsal-snapshot.json"
PRODUCTION_REHEARSAL_TEXT_REPORT_FILENAME = "production-write-token-readonly-rehearsal-report.txt"
PRODUCTION_REHEARSAL_JSON_REPORT_FILENAME = "production-write-token-readonly-rehearsal-report.json"
MAX_PRODUCTION_REHEARSAL_OUTPUT_BYTES = 4 * 1024 * 1024


class ProductionWriteTokenRehearsalIOError(ValueError):
    """A content- and path-free rehearsal output failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


@dataclass(frozen=True)
class ProductionWriteTokenRehearsalOutputPaths:
    """Private caller-only output locations; never part of a public report."""

    snapshot: Path | None
    text_report: Path
    json_report: Path


def _output_paths(
    directory: str | Path,
    *,
    include_snapshot: bool,
) -> ProductionWriteTokenRehearsalOutputPaths:
    path = Path(directory)
    if not path.is_absolute():
        raise ProductionWriteTokenRehearsalIOError(
            "relative_production_rehearsal_output_directory",
            "Production rehearsal output directory must be an explicit absolute path",
        )
    paths = ProductionWriteTokenRehearsalOutputPaths(
        snapshot=(path / PRODUCTION_REHEARSAL_SNAPSHOT_FILENAME if include_snapshot else None),
        text_report=path / PRODUCTION_REHEARSAL_TEXT_REPORT_FILENAME,
        json_report=path / PRODUCTION_REHEARSAL_JSON_REPORT_FILENAME,
    )
    try:
        outputs = [paths.text_report, paths.json_report]
        if paths.snapshot is not None:
            outputs.insert(0, paths.snapshot)
        for output in outputs:
            validate_sensitive_output_path(output, overwrite=False)
    except SensitivePathError as exc:
        raise ProductionWriteTokenRehearsalIOError(
            "unsafe_production_rehearsal_output",
            "Production rehearsal output directory is unsafe or unavailable",
        ) from exc
    return paths


def write_production_write_token_rehearsal_outputs(
    directory: str | Path,
    snapshot: ProductionWriteTokenRehearsalSnapshot | None,
    report: ProductionWriteTokenRehearsalReport,
) -> ProductionWriteTokenRehearsalOutputPaths:
    """Atomically create reports and, on success, exact snapshot evidence."""

    paths = _output_paths(directory, include_snapshot=snapshot is not None)
    payloads: tuple[tuple[Path, str], ...] = (
        (
            paths.text_report,
            render_production_write_token_rehearsal_report_text(report, snapshot),
        ),
        (
            paths.json_report,
            render_production_write_token_rehearsal_report_json(report, snapshot),
        ),
    )
    if snapshot is not None:
        assert paths.snapshot is not None
        payloads = (
            (
                paths.snapshot,
                render_production_write_token_rehearsal_snapshot_json(snapshot),
            ),
            *payloads,
        )
    try:
        for path, text in payloads:
            atomic_write_private_text(
                path,
                text,
                overwrite=False,
                max_size=MAX_PRODUCTION_REHEARSAL_OUTPUT_BYTES,
            )
    except SensitivePathError as exc:
        raise ProductionWriteTokenRehearsalIOError(
            "production_rehearsal_output_write_failed",
            "Production rehearsal output could not be written safely",
        ) from exc
    return paths


__all__ = [
    "MAX_PRODUCTION_REHEARSAL_OUTPUT_BYTES",
    "PRODUCTION_REHEARSAL_JSON_REPORT_FILENAME",
    "PRODUCTION_REHEARSAL_SNAPSHOT_FILENAME",
    "PRODUCTION_REHEARSAL_TEXT_REPORT_FILENAME",
    "ProductionWriteTokenRehearsalIOError",
    "ProductionWriteTokenRehearsalOutputPaths",
    "write_production_write_token_rehearsal_outputs",
]
