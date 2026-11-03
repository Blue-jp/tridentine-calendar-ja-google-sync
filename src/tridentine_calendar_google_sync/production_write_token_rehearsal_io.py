"""Create-only rehearsal evidence; a batch is not an atomic transaction."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from tridentine_calendar_google_sync._private_create_io import (
    PrivateCreateIOError,
    create_integrity_text,
    create_private_text,
)
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
    validate_sensitive_output_path,
)

PRODUCTION_REHEARSAL_SNAPSHOT_FILENAME = "production-write-token-readonly-rehearsal-snapshot.json"
PRODUCTION_REHEARSAL_TEXT_REPORT_FILENAME = "production-write-token-readonly-rehearsal-report.txt"
PRODUCTION_REHEARSAL_JSON_REPORT_FILENAME = "production-write-token-readonly-rehearsal-report.json"
MAX_PRODUCTION_REHEARSAL_OUTPUT_BYTES = 4 * 1024 * 1024


class ProductionWriteTokenRehearsalIOError(ValueError):
    """A content- and path-free rehearsal output failure."""

    def __init__(
        self,
        code: str,
        public_message: str,
        *,
        publication_possible: bool | None = None,
        completed_output_count: int = 0,
    ) -> None:
        self.code = code
        self.public_message = public_message
        self.publication_possible = publication_possible
        # Count of writer calls that returned, not a persistent transaction record.
        self.completed_output_count = completed_output_count
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
            publication_possible=False,
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
            validate_sensitive_output_path(
                output,
                overwrite=False,
                windows_private_acl=(paths.snapshot is not None and output == paths.snapshot),
            )
    except SensitivePathError:
        raise ProductionWriteTokenRehearsalIOError(
            "unsafe_production_rehearsal_output",
            "Production rehearsal output directory is unsafe or unavailable",
            publication_possible=False,
        ) from None
    return paths


def write_production_write_token_rehearsal_outputs(
    directory: str | Path,
    snapshot: ProductionWriteTokenRehearsalSnapshot | None,
    report: ProductionWriteTokenRehearsalReport,
) -> ProductionWriteTokenRehearsalOutputPaths:
    """Create each evidence file once, stopping on error without batch rollback.

    All outputs are rendered before any writer runs. A later write failure does
    not erase earlier outputs or imply that the failed output is absent. A success
    return is not a three-file atomic commit or a crash-recovery protocol.
    """

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
    completed_output_count = 0
    try:
        for path, text in payloads:
            writer = (
                create_private_text
                if paths.snapshot is not None and path == paths.snapshot
                else create_integrity_text
            )
            writer(
                path,
                text,
                max_size=MAX_PRODUCTION_REHEARSAL_OUTPUT_BYTES,
            )
            completed_output_count += 1
    except Exception as exc:
        publication_possible = (
            True
            if completed_output_count
            else exc.publication_possible
            if isinstance(exc, PrivateCreateIOError)
            else None
        )
        message = "Production rehearsal output could not be written safely."
        if publication_possible is not False:
            message += " Outputs may exist; do not retry or remove them automatically."
        raise ProductionWriteTokenRehearsalIOError(
            "production_rehearsal_output_write_failed",
            message,
            publication_possible=publication_possible,
            completed_output_count=completed_output_count,
        ) from None
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
