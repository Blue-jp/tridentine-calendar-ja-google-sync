"""Offline command-line interface for Accepted ICS source inspection."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Never

from tridentine_calendar_google_sync.profiles import ProfileError, load_profile
from tridentine_calendar_google_sync.source_ics import SourceInputError, inspect_source
from tridentine_calendar_google_sync.source_report import render_json_report, render_text_report

EXIT_VALID = 0
EXIT_CLI_ERROR = 2
EXIT_INVALID_SOURCE = 3
EXIT_FATAL_GUARD = 5
EXIT_INTERNAL_ERROR = 8


class SafeArgumentParser(argparse.ArgumentParser):
    """Argument parser that raises a safe exception instead of exiting early."""

    def error(self, message: str) -> Never:
        raise argparse.ArgumentError(None, message)


def build_parser() -> argparse.ArgumentParser:
    """Build the Phase 1 offline-only argument parser."""

    parser = SafeArgumentParser(
        prog="tridentine-calendar-google-sync",
        description="Offline validation of an Accepted HTML ICS local file.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command_name, help_text in (
        ("inspect-source", "inspect and validate a local Accepted HTML ICS file"),
        ("validate-source", "strictly validate a local Accepted HTML ICS file"),
    ):
        command = subparsers.add_parser(command_name, help=help_text)
        command.add_argument("--source", required=True, help="local ICS path")
        command.add_argument("--profile", required=True, help="Accepted source profile ID")
        command.add_argument(
            "--profiles-dir",
            help="optional local directory containing source profiles",
        )
        command.add_argument(
            "--format",
            choices=("text", "json"),
            default="text",
            dest="report_format",
        )
        command.add_argument("--output", help="optional local report output path")
        command.add_argument(
            "--redact-content",
            action="store_true",
            help="retain the default content-redacted report policy",
        )
    return parser


def _safe_output_path(output: str) -> Path:
    lowered = output.casefold()
    if "://" in output or lowered.startswith("file:") or output.startswith(("\\\\", "//")):
        raise SourceInputError("nonlocal_output", "output must be a local filesystem path")
    if "\x00" in output:
        raise SourceInputError("invalid_output_path", "output path is invalid")
    path = Path(output)
    try:
        if path.is_symlink():
            raise SourceInputError("output_symlink", "symbolic-link output files are not accepted")
    except OSError as exc:
        raise SourceInputError("output_unavailable", "output path is unavailable") from exc
    return path


def _write_report(output: str, rendered: str) -> None:
    path = _safe_output_path(output)
    try:
        with path.open("x", encoding="utf-8", newline="\n") as report_file:
            report_file.write(rendered)
    except FileExistsError as exc:
        raise SourceInputError("output_exists", "output file already exists") from exc
    except OSError as exc:
        raise SourceInputError("output_unavailable", "output file cannot be written") from exc


def _inspection_exit_code(fatal_codes: set[str]) -> int:
    if not fatal_codes:
        return EXIT_VALID
    if fatal_codes == {"malformed_ics"}:
        return EXIT_INVALID_SOURCE
    return EXIT_FATAL_GUARD


def main(argv: Sequence[str] | None = None) -> int:
    """Run the offline CLI and return a documented process exit code.

    Expected validation and configuration failures are converted to short safe
    messages.  Unexpected errors also suppress tracebacks and input details.
    """

    parser = build_parser()
    try:
        effective_argv = list(argv) if argv is not None else sys.argv[1:]
        if not effective_argv:
            parser.print_help(sys.stdout)
            return EXIT_CLI_ERROR
        args = parser.parse_args(effective_argv)
        profile = load_profile(args.profile, args.profiles_dir)
        inspection = inspect_source(args.source, profile)
        rendered = (
            render_json_report(inspection, profile)
            if args.report_format == "json"
            else render_text_report(inspection, profile)
        )
        if args.output:
            _write_report(args.output, rendered)
        else:
            sys.stdout.write(rendered)
        fatal_codes = {
            finding.code for finding in inspection.findings if finding.severity == "fatal"
        }
        return _inspection_exit_code(fatal_codes)
    except argparse.ArgumentError as exc:
        parser.print_usage(sys.stderr)
        sys.stderr.write(f"error: {exc}\n")
        return EXIT_CLI_ERROR
    except (ProfileError, SourceInputError) as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_CLI_ERROR
    except Exception:
        sys.stderr.write("error: internal failure; no source content was reported\n")
        return EXIT_INTERNAL_ERROR


__all__ = [
    "EXIT_CLI_ERROR",
    "EXIT_FATAL_GUARD",
    "EXIT_INTERNAL_ERROR",
    "EXIT_INVALID_SOURCE",
    "EXIT_VALID",
    "build_parser",
    "main",
]
