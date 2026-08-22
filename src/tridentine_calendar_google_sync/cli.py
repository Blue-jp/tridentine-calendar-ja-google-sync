"""Offline command-line interface for Accepted ICS source inspection."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Never

from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.diff_models import CalendarDiff, ManagedScope
from tridentine_calendar_google_sync.diff_report import (
    render_diff_json_report,
    render_diff_text_report,
)
from tridentine_calendar_google_sync.google_auth import (
    GoogleAuthConfigError,
    GoogleAuthError,
    GoogleCredentialRefreshError,
    authorize_google_readonly,
    load_readonly_credentials,
    persist_authorized_user_credentials,
)
from tridentine_calendar_google_sync.google_client import build_read_only_calendar_client
from tridentine_calendar_google_sync.google_errors import SafeGoogleError
from tridentine_calendar_google_sync.google_fetch import fetch_google_event_pages
from tridentine_calendar_google_sync.google_optional import (
    GoogleOptionalDependencyError,
    load_google_optional_bindings,
)
from tridentine_calendar_google_sync.google_sanitize import sanitize_fetched_pages
from tridentine_calendar_google_sync.google_snapshot import (
    GoogleSnapshotError,
    load_google_snapshot,
)
from tridentine_calendar_google_sync.google_target import (
    GoogleTargetError,
    TargetConfigError,
    TargetIdentityError,
    TargetMetadataObservation,
    load_target_config,
    short_target_reference,
    verify_target_fingerprint,
    verify_target_metadata,
)
from tridentine_calendar_google_sync.profiles import ProfileError, load_profile
from tridentine_calendar_google_sync.snapshot_io import (
    SnapshotWriteError,
    validate_snapshot_output,
    write_google_snapshot,
)
from tridentine_calendar_google_sync.source_ics import SourceInputError, inspect_source
from tridentine_calendar_google_sync.source_report import render_json_report, render_text_report

EXIT_VALID = 0
EXIT_DIFFERENCES = 1
EXIT_CLI_ERROR = 2
EXIT_INVALID_SOURCE = 3
EXIT_INVALID_SNAPSHOT = 4
EXIT_FATAL_GUARD = 5
EXIT_GOOGLE_READ_ERROR = 6
EXIT_INTERNAL_ERROR = 8


class SafeArgumentParser(argparse.ArgumentParser):
    """Argument parser that raises a safe exception instead of exiting early."""

    def error(self, message: str) -> Never:
        raise argparse.ArgumentError(None, message)


def build_parser() -> argparse.ArgumentParser:
    """Build the offline-only source and snapshot argument parser."""

    parser = SafeArgumentParser(
        prog="tridentine-calendar-google-sync",
        description="Offline validation and comparison of sanitized calendar files.",
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
    diff_command = subparsers.add_parser(
        "diff-snapshot",
        help="compare a local Accepted HTML ICS with a sanitized Google snapshot",
    )
    diff_command.add_argument("--source", required=True, help="local ICS path")
    diff_command.add_argument("--profile", required=True, help="Accepted source profile ID")
    diff_command.add_argument(
        "--profiles-dir",
        help="optional local directory containing source profiles",
    )
    diff_command.add_argument(
        "--google-snapshot",
        "--snapshot",
        dest="google_snapshot",
        required=True,
        help="local sanitized Google snapshot JSON path",
    )
    diff_command.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="report_format",
    )
    diff_command.add_argument("--output", help="optional local report output path")
    diff_command.add_argument(
        "--redact-content",
        action="store_true",
        help="retain the mandatory content-redacted report policy",
    )
    authorize_command = subparsers.add_parser(
        "authorize-google-readonly",
        help="explicitly authorize the narrow owned-events read-only scope",
    )
    authorize_command.add_argument(
        "--online",
        action="store_true",
        help="allow OAuth network use",
    )
    authorize_command.add_argument(
        "--credentials-file",
        "--client-config",
        dest="credentials_file",
        required=True,
        help="absolute local desktop OAuth client JSON path",
    )
    authorize_command.add_argument(
        "--token-file",
        "--token-output",
        dest="token_file",
        required=True,
        help="absolute local authorized-user token output path",
    )
    authorize_command.add_argument(
        "--overwrite-token",
        action="store_true",
        help="explicitly replace an existing token file",
    )
    fetch_command = subparsers.add_parser(
        "fetch-google-snapshot",
        help="fetch and privately store one full read-only Google snapshot",
    )
    fetch_command.add_argument(
        "--online",
        action="store_true",
        help="allow Google Calendar read network use",
    )
    fetch_command.add_argument(
        "--token-file",
        "--token",
        dest="token_file",
        required=True,
        help="absolute local authorized-user token path",
    )
    fetch_command.add_argument(
        "--target-config",
        required=True,
        help="absolute local private target TOML path",
    )
    fetch_command.add_argument(
        "--output",
        required=True,
        help="absolute local snapshot output path outside every Git worktree",
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


def _diff_exit_code(diff: CalendarDiff) -> int:
    if diff.counts.invalid_source:
        return EXIT_INVALID_SOURCE
    if diff.fatal:
        return EXIT_FATAL_GUARD
    if diff.has_changes:
        return EXIT_DIFFERENCES
    return EXIT_VALID


def _require_online(args: argparse.Namespace) -> None:
    if getattr(args, "online", False) is not True:
        raise argparse.ArgumentError(None, "explicit --online is required")


def _authorize_google_command(args: argparse.Namespace) -> int:
    _require_online(args)
    overwrite_text = "yes" if args.overwrite_token else "no"
    sys.stdout.write(
        "Google read-only authorization confirmation: "
        "scope=calendar.events.owned.readonly; credentials-configured=yes; "
        f"token-output-configured=yes; overwrite={overwrite_text}.\n"
    )
    authorize_google_readonly(
        args.credentials_file,
        args.token_file,
        overwrite=args.overwrite_token,
    )
    sys.stdout.write("Google read-only authorization completed; token content was not displayed.\n")
    return EXIT_VALID


def _fetch_google_command(args: argparse.Namespace) -> int:
    _require_online(args)
    target = load_target_config(args.target_config)
    target_fingerprint = verify_target_fingerprint(target)
    validate_snapshot_output(args.output)
    bindings = load_google_optional_bindings()
    credentials = load_readonly_credentials(args.token_file, bindings=bindings)
    client = build_read_only_calendar_client(
        credentials,
        build_service=bindings.build_service,
    )

    def refresh_credentials() -> None:
        try:
            credentials.refresh(bindings.request_class())
            persist_authorized_user_credentials(credentials, args.token_file, overwrite=True)
        except GoogleAuthError:
            raise
        except Exception as exc:
            raise GoogleCredentialRefreshError(
                "google_credential_refresh_failed",
                "Google read-only credentials could not be refreshed",
            ) from exc

    def validate_metadata(
        summary: str | None,
        time_zone: str | None,
        access_role: str | None,
    ) -> None:
        if not summary or not time_zone or access_role != "owner":
            raise TargetIdentityError(
                "target_metadata_invalid",
                "calendar metadata does not match the configured target",
            )
        verify_target_metadata(
            target,
            TargetMetadataObservation(
                summary=summary,
                access_role="owner",
                timezone=time_zone,
            ),
        )

    fetched = fetch_google_event_pages(
        client,
        calendar_id=target.calendar_id,
        target_fingerprint=target_fingerprint,
        expected_target_fingerprint=target.expected_fingerprint,
        refresh_credentials=refresh_credentials,
        validate_metadata=validate_metadata,
    )
    snapshot = sanitize_fetched_pages(fetched, captured_at=datetime.now(UTC))
    write_google_snapshot(snapshot, args.output)
    target_reference = short_target_reference(target_fingerprint)
    sys.stdout.write(
        "Google snapshot stored privately: "
        f"target={target_reference}; pages={snapshot.page_count}; "
        f"events={snapshot.event_count}; retries={fetched.retry_count}.\n"
    )
    return EXIT_VALID


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
        if args.command == "authorize-google-readonly":
            return _authorize_google_command(args)
        if args.command == "fetch-google-snapshot":
            return _fetch_google_command(args)
        profile = load_profile(args.profile, args.profiles_dir)
        inspection = inspect_source(args.source, profile)
        if args.command == "diff-snapshot":
            snapshot = load_google_snapshot(args.google_snapshot)
            diff = diff_source_to_snapshot(
                inspection,
                snapshot,
                ManagedScope(),
            )
            rendered = (
                render_diff_json_report(diff)
                if args.report_format == "json"
                else render_diff_text_report(diff)
            )
            exit_code = _diff_exit_code(diff)
        else:
            rendered = (
                render_json_report(inspection, profile)
                if args.report_format == "json"
                else render_text_report(inspection, profile)
            )
            fatal_codes = {
                finding.code for finding in inspection.findings if finding.severity == "fatal"
            }
            exit_code = _inspection_exit_code(fatal_codes)
        if args.output:
            _write_report(args.output, rendered)
        else:
            sys.stdout.write(rendered)
        return exit_code
    except argparse.ArgumentError as exc:
        parser.print_usage(sys.stderr)
        sys.stderr.write(f"error: {exc}\n")
        return EXIT_CLI_ERROR
    except (ProfileError, SourceInputError) as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_CLI_ERROR
    except GoogleSnapshotError as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_INVALID_SNAPSHOT
    except (GoogleAuthConfigError, TargetConfigError) as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_CLI_ERROR
    except (TargetIdentityError, GoogleTargetError) as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_FATAL_GUARD
    except GoogleOptionalDependencyError as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_CLI_ERROR
    except (GoogleAuthError, SafeGoogleError) as exc:
        public_message = str(exc) if isinstance(exc, SafeGoogleError) else exc.public_message
        sys.stderr.write(f"error: {public_message}\n")
        return EXIT_GOOGLE_READ_ERROR
    except SnapshotWriteError as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_INVALID_SNAPSHOT
    except Exception:
        sys.stderr.write("error: internal failure; no source content was reported\n")
        return EXIT_INTERNAL_ERROR


__all__ = [
    "EXIT_CLI_ERROR",
    "EXIT_DIFFERENCES",
    "EXIT_FATAL_GUARD",
    "EXIT_GOOGLE_READ_ERROR",
    "EXIT_INTERNAL_ERROR",
    "EXIT_INVALID_SNAPSHOT",
    "EXIT_INVALID_SOURCE",
    "EXIT_VALID",
    "build_parser",
    "main",
]
