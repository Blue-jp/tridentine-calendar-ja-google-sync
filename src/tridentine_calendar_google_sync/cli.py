"""Offline command-line interface for Accepted ICS source inspection."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Never

from tridentine_calendar_google_sync.apply_approval import approve_apply_bundle
from tridentine_calendar_google_sync.apply_bundle import build_apply_bundle
from tridentine_calendar_google_sync.apply_bundle_io import (
    load_apply_bundle,
    write_apply_bundle,
)
from tridentine_calendar_google_sync.apply_models import ApplyEnvironment
from tridentine_calendar_google_sync.apply_policy import (
    ApplyConfirmationError,
    ApplyError,
    ApplyGuardError,
)
from tridentine_calendar_google_sync.apply_report import (
    build_apply_bundle_json_report,
    build_apply_json_report,
    render_apply_bundle_json_report,
    render_apply_bundle_text_report,
    render_apply_json_report,
    render_apply_text_report,
    render_operation_journal_json_report,
    render_operation_journal_text_report,
)
from tridentine_calendar_google_sync.apply_simulation import (
    ApplySimulationError,
    ApplySimulationState,
    run_apply_simulation,
)
from tridentine_calendar_google_sync.baseline_engine import (
    BaselineConfirmationError,
    BaselineError,
    BaselineGuardError,
    baseline_confirmation_phrase,
    baseline_inspection_data,
    build_baseline_candidate,
    render_baseline_inspection_json,
    render_baseline_text,
    trust_baseline,
)
from tridentine_calendar_google_sync.baseline_io import load_baseline, write_baseline
from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.diff_models import CalendarDiff, ManagedScope
from tridentine_calendar_google_sync.diff_report import (
    render_diff_json_report,
    render_diff_text_report,
)
from tridentine_calendar_google_sync.fake_mutation_transport import (
    FakeMutationError,
    FakeMutationTransport,
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
from tridentine_calendar_google_sync.google_test_prewrite_client import (
    TestCalendarPrewriteClientError,
    build_test_calendar_prewrite_list_client,
)
from tridentine_calendar_google_sync.google_test_write_auth import (
    TestWriteAuthConfigError,
    TestWriteAuthError,
    authorize_test_google_write,
    load_test_write_credentials,
)
from tridentine_calendar_google_sync.google_test_write_client import (
    TestWriteClientError,
    build_test_calendar_write_client,
)
from tridentine_calendar_google_sync.operation_journal import (
    OperationJournalError,
    load_operation_journal,
    write_operation_journal,
)
from tridentine_calendar_google_sync.plan_engine import PlanError, build_sync_plan
from tridentine_calendar_google_sync.plan_io import PlanReportError, load_sync_plan_report
from tridentine_calendar_google_sync.plan_models import PlanState, PlanThresholds
from tridentine_calendar_google_sync.plan_report import (
    render_plan_json_report,
    render_plan_text_report,
)
from tridentine_calendar_google_sync.profiles import ProfileError, load_profile
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    validate_sensitive_output_path,
)
from tridentine_calendar_google_sync.snapshot_io import (
    SnapshotWriteError,
    validate_snapshot_output,
    write_google_snapshot,
)
from tridentine_calendar_google_sync.source_ics import SourceInputError, inspect_source
from tridentine_calendar_google_sync.source_report import render_json_report, render_text_report
from tridentine_calendar_google_sync.test_calendar_prewrite import (
    TestCalendarPrewriteError,
    inspect_test_calendar_prewrite,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_io import (
    TestCalendarPrewriteIOError,
    validate_test_calendar_prewrite_output_paths,
    write_test_calendar_prewrite_outputs,
)
from tridentine_calendar_google_sync.test_write_approval import (
    TestWriteApprovalError,
    approve_test_write_run_spec,
)
from tridentine_calendar_google_sync.test_write_journal import (
    TestWriteJournalError,
    write_test_write_journal,
)
from tridentine_calendar_google_sync.test_write_report import (
    render_test_write_json_report,
    render_test_write_text_report,
)
from tridentine_calendar_google_sync.test_write_run_spec import (
    TestWriteRunSpecError,
    build_test_write_run_spec,
    verify_test_write_run_spec,
)
from tridentine_calendar_google_sync.test_write_run_spec_io import (
    TestWriteRunSpecIOError,
    load_test_write_run_spec,
    write_test_write_run_spec,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetConfigError,
    TestWriteTargetError,
    load_test_write_target_config,
    test_write_target_reference,
)
from tridentine_calendar_google_sync.test_write_transport import (
    TestWriteExecutionState,
    TestWriteTransportError,
    run_test_calendar_write,
)

EXIT_VALID = 0
EXIT_DIFFERENCES = 1
EXIT_CLI_ERROR = 2
EXIT_INVALID_SOURCE = 3
EXIT_INVALID_SNAPSHOT = 4
EXIT_FATAL_GUARD = 5
EXIT_GOOGLE_READ_ERROR = 6
EXIT_INTERNAL_ERROR = 8

_APPLY_SAFETY_HELP = (
    "Offline synthetic fake safety only.\n"
    "No live Google Calendar API.\n"
    "Does not write to Google Calendar.\n"
    "Production targets are refused.\n"
    "Delete execution is not implemented."
)

_TEST_WRITE_SAFETY_HELP = (
    "Test Calendar only; Production Calendar targets are refused.\n"
    "Only run-test-calendar-write can perform a Google Calendar write, and it requires "
    "explicit --online plus an exact approval phrase.\n"
    "Each run contains exactly one Add or Update operation. Delete is not implemented.\n"
    "Add uses events.import and Update uses events.patch with an exact If-Match ETag.\n"
    "The Test write token is separate from the Production read-only token.\n"
    "No batch execution and no automatic mutation retry are implemented."
)

_TEST_PREWRITE_SAFETY_HELP = (
    "Test Calendar read-only prewrite inspection using the separate Test write token.\n"
    "Calls events.list only and never calls events.get, events.import, or events.patch.\n"
    "Does not write to Google Calendar, delete events, clear a Calendar, or make an "
    "existing Calendar empty.\n"
    "Production and primary Calendars are refused before client construction.\n"
    "An empty Calendar is write-ready; a nonempty Calendar requires manual review.\n"
    "Stores only a sanitized snapshot and aggregate reports outside every repository."
)


class SafeArgumentParser(argparse.ArgumentParser):
    """Argument parser that raises a safe exception instead of exiting early."""

    def error(self, message: str) -> Never:
        raise argparse.ArgumentError(None, message)


def _nonnegative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a nonnegative integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("value must be a nonnegative integer")
    return parsed


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
    candidate_command = subparsers.add_parser(
        "create-baseline-candidate",
        help="create a private candidate baseline from an exact zero-difference audit",
    )
    candidate_command.add_argument("--source", required=True, help="local ICS path")
    candidate_command.add_argument(
        "--profile",
        required=True,
        help="Accepted source profile ID",
    )
    candidate_command.add_argument(
        "--profiles-dir",
        help="optional local directory containing source profiles",
    )
    candidate_command.add_argument(
        "--google-snapshot",
        required=True,
        help="local sanitized Google snapshot JSON path",
    )
    candidate_command.add_argument(
        "--output",
        required=True,
        help="absolute private candidate baseline output path",
    )
    inspect_baseline_command = subparsers.add_parser(
        "inspect-baseline",
        help="inspect a private baseline without exposing its raw UID inventory",
    )
    inspect_baseline_command.add_argument(
        "--baseline",
        required=True,
        help="absolute private baseline path",
    )
    inspect_baseline_command.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="report_format",
    )
    inspect_baseline_command.add_argument(
        "--output",
        help="optional local safe inspection report path",
    )
    trust_command = subparsers.add_parser(
        "trust-baseline",
        help="explicitly transition a verified candidate into a trusted baseline",
    )
    trust_command.add_argument(
        "--candidate",
        required=True,
        help="absolute private candidate baseline path",
    )
    trust_command.add_argument(
        "--output",
        required=True,
        help="absolute private trusted baseline output path",
    )
    trust_command.add_argument(
        "--confirmation",
        required=True,
        help="exact candidate trust confirmation phrase",
    )
    plan_command = subparsers.add_parser(
        "plan-sync",
        help="build a private non-executable plan from a trusted baseline",
    )
    plan_command.add_argument("--source", required=True, help="local ICS path")
    plan_command.add_argument("--profile", required=True, help="Accepted source profile ID")
    plan_command.add_argument(
        "--profiles-dir",
        help="optional local directory containing source profiles",
    )
    plan_command.add_argument(
        "--google-snapshot",
        required=True,
        help="local sanitized Google snapshot JSON path",
    )
    plan_command.add_argument(
        "--trusted-baseline",
        required=True,
        help="absolute private trusted baseline path",
    )
    plan_command.add_argument(
        "--output",
        required=True,
        help="absolute private non-executable plan output path",
    )
    plan_command.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="report_format",
    )
    plan_command.add_argument("--max-add", type=_nonnegative_int, default=0)
    plan_command.add_argument("--max-update", type=_nonnegative_int, default=0)
    plan_command.add_argument("--max-delete", type=_nonnegative_int, default=0)
    bundle_command = subparsers.add_parser(
        "build-apply-bundle",
        help="build a private non-executable apply bundle from canonical local inputs",
        description=f"Build a private non-executable apply bundle. {_APPLY_SAFETY_HELP}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    bundle_command.add_argument("--source", required=True, help="local ICS path")
    bundle_command.add_argument("--profile", required=True, help="Accepted source profile ID")
    bundle_command.add_argument(
        "--profiles-dir",
        help="optional local directory containing source profiles",
    )
    bundle_command.add_argument(
        "--google-snapshot",
        required=True,
        help="local sanitized Google snapshot JSON path",
    )
    bundle_command.add_argument(
        "--trusted-baseline",
        required=True,
        help="absolute private trusted baseline path",
    )
    bundle_command.add_argument(
        "--plan",
        required=True,
        help="absolute canonical JSON sync plan report path",
    )
    bundle_command.add_argument(
        "--environment",
        required=True,
        choices=(ApplyEnvironment.TEST.value, ApplyEnvironment.PRODUCTION.value),
        help="explicit apply target environment; there is no default",
    )
    bundle_command.add_argument(
        "--target-label",
        required=True,
        help="explicit safe synthetic target label; Production is refused",
    )
    bundle_command.add_argument(
        "--output",
        required=True,
        help="absolute private apply bundle output path",
    )
    inspect_bundle_command = subparsers.add_parser(
        "inspect-apply-bundle",
        help="inspect a private apply bundle through a redacted public report",
        description=f"Inspect a redacted private apply bundle. {_APPLY_SAFETY_HELP}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    inspect_bundle_command.add_argument(
        "--bundle",
        required=True,
        help="absolute private apply bundle path",
    )
    inspect_bundle_command.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="report_format",
    )
    inspect_bundle_command.add_argument(
        "--output",
        help="optional local public inspection report path",
    )
    simulate_command = subparsers.add_parser(
        "simulate-apply",
        help="approve and run one test-only bundle against the offline fake transport",
        description=f"Run a fake in-memory simulation. {_APPLY_SAFETY_HELP}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    simulate_command.add_argument(
        "--bundle",
        required=True,
        help="absolute private approval-required test bundle path",
    )
    simulate_command.add_argument(
        "--plan",
        required=True,
        help="absolute canonical JSON current sync plan report path",
    )
    simulate_command.add_argument(
        "--confirmation",
        required=True,
        help="exact test-only simulation approval phrase",
    )
    simulate_command.add_argument(
        "--journal-output",
        required=True,
        help="absolute private final operation journal output path",
    )
    simulate_command.add_argument(
        "--report-output",
        required=True,
        help="absolute private redacted simulation report output path",
    )
    simulate_command.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="report_format",
    )
    inspect_journal_command = subparsers.add_parser(
        "inspect-operation-journal",
        help="inspect a private journal through a redacted public report",
        description=f"Inspect a redacted fake operation journal. {_APPLY_SAFETY_HELP}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    inspect_journal_command.add_argument(
        "--journal",
        required=True,
        help="absolute private operation journal path",
    )
    inspect_journal_command.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="report_format",
    )
    inspect_journal_command.add_argument(
        "--output",
        help="optional local public inspection report path",
    )

    inspect_test_prewrite = subparsers.add_parser(
        "inspect-test-calendar-prewrite",
        help="inspect one dedicated Test Calendar through events.list only",
        description=_TEST_PREWRITE_SAFETY_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    inspect_test_prewrite.add_argument(
        "--online",
        action="store_true",
        help="explicitly allow the bounded Test Calendar read-only network inspection",
    )
    inspect_test_prewrite.add_argument(
        "--target-config",
        required=True,
        help="absolute repository-external Test target TOML path",
    )
    inspect_test_prewrite.add_argument(
        "--token-file",
        required=True,
        help="absolute repository-external Test write token path",
    )
    inspect_test_prewrite.add_argument(
        "--production-read-token-file",
        required=True,
        help="protected Production read-token path used only for path-separation checks",
    )
    inspect_test_prewrite.add_argument(
        "--snapshot-output",
        required=True,
        help="new repository-external sanitized Test prewrite snapshot path",
    )
    inspect_test_prewrite.add_argument(
        "--human-report-output",
        required=True,
        help="new repository-external aggregate human report path",
    )
    inspect_test_prewrite.add_argument(
        "--json-report-output",
        required=True,
        help="new repository-external aggregate JSON report path",
    )

    authorize_test_write = subparsers.add_parser(
        "authorize-test-google-write",
        help="authorize the exact Test Calendar owned-events write scope",
        description=(
            "Create a separate Test Calendar write token through explicit desktop OAuth. "
            f"{_TEST_WRITE_SAFETY_HELP}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    authorize_test_write.add_argument(
        "--online",
        action="store_true",
        help="explicitly allow the Test-only OAuth flow",
    )
    authorize_test_write.add_argument(
        "--credentials-file",
        required=True,
        help="absolute repository-external desktop OAuth client JSON path",
    )
    authorize_test_write.add_argument(
        "--token-file",
        required=True,
        help="new absolute repository-external Test write token output path",
    )
    authorize_test_write.add_argument(
        "--production-read-token-file",
        required=True,
        help="protected Production read-token path used only for path-separation checks",
    )
    authorize_test_write.add_argument(
        "--target-config",
        required=True,
        help="absolute repository-external Test target TOML path",
    )

    build_test_run = subparsers.add_parser(
        "build-test-write-run-spec",
        help="build one private offline Test Calendar write Run Spec",
        description=(
            "Build one private one-operation Run Spec without OAuth or API access. "
            f"{_TEST_WRITE_SAFETY_HELP}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    build_test_run.add_argument("--source", required=True, help="local ICS path")
    build_test_run.add_argument("--profile", required=True, help="Accepted source profile ID")
    build_test_run.add_argument(
        "--profiles-dir",
        help="optional local directory containing source profiles",
    )
    build_test_run.add_argument(
        "--google-snapshot",
        required=True,
        help="absolute repository-external sanitized Test snapshot path",
    )
    build_test_run.add_argument(
        "--plan",
        required=True,
        help="absolute repository-external canonical one-operation Sync Plan path",
    )
    build_test_run.add_argument(
        "--target-config",
        required=True,
        help="absolute repository-external Test target TOML path",
    )
    build_test_run.add_argument(
        "--trusted-baseline",
        help="absolute repository-external trusted Test baseline path; required for Update",
    )
    build_test_run.add_argument(
        "--output",
        required=True,
        help="new absolute repository-external private Run Spec path",
    )

    inspect_test_run = subparsers.add_parser(
        "inspect-test-write-run-spec",
        help="inspect a private Test Write Run Spec through safe metadata",
        description=(
            "Inspect a redacted Test Calendar Run Spec without revealing event content. "
            f"{_TEST_WRITE_SAFETY_HELP}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    inspect_test_run.add_argument(
        "--run-spec",
        required=True,
        help="absolute repository-external private Run Spec path",
    )
    inspect_test_run.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="report_format",
    )
    inspect_test_run.add_argument(
        "--output",
        help="optional repository-external safe inspection report path",
    )

    run_test_write = subparsers.add_parser(
        "run-test-calendar-write",
        help="run one explicitly approved Test Calendar Add or Update",
        description=(
            "Perform the sole live-write entry point for a dedicated Test Calendar. "
            f"{_TEST_WRITE_SAFETY_HELP}"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    run_test_write.add_argument(
        "--online",
        action="store_true",
        help="explicitly allow the bounded Test Calendar API run",
    )
    run_test_write.add_argument(
        "--run-spec",
        required=True,
        help="absolute repository-external approved private Run Spec path",
    )
    run_test_write.add_argument(
        "--plan",
        required=True,
        help="absolute repository-external canonical current Sync Plan path",
    )
    run_test_write.add_argument(
        "--target-config",
        required=True,
        help="absolute repository-external Test target TOML path",
    )
    run_test_write.add_argument(
        "--token-file",
        required=True,
        help="absolute repository-external Test write token path",
    )
    run_test_write.add_argument(
        "--production-read-token-file",
        required=True,
        help="protected Production read-token path used only for path-separation checks",
    )
    run_test_write.add_argument(
        "--trusted-baseline",
        help="absolute repository-external trusted Test baseline path; required for Update",
    )
    run_test_write.add_argument(
        "--confirmation",
        required=True,
        help="exact Test Calendar write approval phrase",
    )
    run_test_write.add_argument(
        "--journal-output",
        required=True,
        help="new absolute repository-external safe journal path",
    )
    run_test_write.add_argument(
        "--report-output",
        required=True,
        help="new absolute repository-external redacted report path",
    )
    run_test_write.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        dest="report_format",
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


def _test_write_run_spec_inspection_data(run_spec: object) -> dict[str, object]:
    from tridentine_calendar_google_sync.test_write_models import TestWriteRunSpec

    if not isinstance(run_spec, TestWriteRunSpec):
        raise TestWriteRunSpecError(
            "invalid_test_write_run_spec",
            "Test write Run Spec is invalid",
        )
    verify_test_write_run_spec(run_spec)
    data: dict[str, object] = {
        "schema_version": "1.0",
        "report_type": "test-calendar-write-run-spec-inspection-v1",
        "test_only": run_spec.test_only,
        "production_locked": run_spec.production_locked,
        "target_safe_ref": run_spec.target_safe_ref,
        "run_spec_ref": f"R-{run_spec.run_spec_content_hash[:12]}",
        "source_profile": run_spec.source_profile,
        "source_event_count": run_spec.source_event_count,
        "operation_count": run_spec.operation_count,
        "add_count": run_spec.add_count,
        "update_count": run_spec.update_count,
        "operation": run_spec.operation.operation.value,
        "source_ref": run_spec.operation.source_ref,
        "approval_required": run_spec.approval_required,
    }
    canonical = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        **data,
        "report_content_hash": hashlib.sha256(
            b"tridentine-calendar-google-sync:test-write-run-spec-inspection:v1\x00" + canonical
        ).hexdigest(),
    }


def _render_test_write_run_spec_inspection(run_spec: object, report_format: str) -> str:
    data = _test_write_run_spec_inspection_data(run_spec)
    if report_format == "json":
        return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False) + "\n"
    return "\n".join(
        (
            "Test Calendar write Run Spec inspection",
            "Test Calendar only: yes",
            "Production locked: yes",
            f"target reference: {data['target_safe_ref']}",
            f"Run Spec reference: {data['run_spec_ref']}",
            f"source profile: {data['source_profile']}",
            f"source events: {data['source_event_count']}",
            f"operation: {data['operation']}",
            f"operations: {data['operation_count']}",
            f"add: {data['add_count']}",
            f"update: {data['update_count']}",
            f"source reference: {data['source_ref']}",
            "approval required: yes",
            f"report hash: {data['report_content_hash']}",
            "",
        )
    )


def _authorize_test_google_write_command(args: argparse.Namespace) -> int:
    _require_online(args)
    target = load_test_write_target_config(args.target_config)
    authorize_test_google_write(
        args.credentials_file,
        args.token_file,
        args.production_read_token_file,
        target,
    )
    sys.stdout.write(
        "Test Calendar write authorization completed: "
        f"target={test_write_target_reference(target)}; "
        "scope=calendar.events.owned; token-separated=yes; token-content-displayed=no.\n"
    )
    return EXIT_VALID


def _inspect_test_calendar_prewrite_command(args: argparse.Namespace) -> int:
    """Run the dedicated list-only Test Calendar inspection path."""

    _require_online(args)
    target = load_test_write_target_config(args.target_config)
    target_ref = test_write_target_reference(target)
    validate_test_calendar_prewrite_output_paths(
        args.snapshot_output,
        args.human_report_output,
        args.json_report_output,
    )

    # Target, Production, primary-Calendar, and output guards all run before
    # credentials, the optional Google dependency, or an API-capable client.
    bindings = load_google_optional_bindings()
    credentials = load_test_write_credentials(
        args.token_file,
        args.production_read_token_file,
        target,
        bindings=bindings,
    )
    client = build_test_calendar_prewrite_list_client(
        credentials,
        target_config=target,
        build_service=bindings.build_service,
    )
    result = inspect_test_calendar_prewrite(client, target)
    write_test_calendar_prewrite_outputs(
        result,
        snapshot_output=args.snapshot_output,
        human_report_output=args.human_report_output,
        json_report_output=args.json_report_output,
    )
    report = result.report
    sys.stdout.write(
        "Test Calendar read-only prewrite inspection stored: "
        f"target={target_ref}; method=events.list; complete=yes; "
        f"ready={'yes' if report.prewrite_ready else 'no'}; "
        f"events={report.event_count}; pages={report.page_count}; "
        f"API-calls={report.api_call_count}; retries={report.retry_count}; "
        "Google-writes=0; event-changes=0.\n"
    )
    return EXIT_VALID if report.prewrite_ready else EXIT_FATAL_GUARD


def _build_test_write_run_spec_command(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile, args.profiles_dir)
    source = inspect_source(args.source, profile)
    snapshot = load_google_snapshot(args.google_snapshot)
    plan = load_sync_plan_report(args.plan)
    target = load_test_write_target_config(args.target_config)
    baseline = load_baseline(args.trusted_baseline) if args.trusted_baseline else None
    run_spec = build_test_write_run_spec(
        profile,
        source,
        snapshot,
        plan,
        target,
        trusted_baseline=baseline,
    )
    write_test_write_run_spec(run_spec, args.output)
    data = _test_write_run_spec_inspection_data(run_spec)
    sys.stdout.write(
        "Private Test Calendar write Run Spec stored: "
        f"target={data['target_safe_ref']}; run={data['run_spec_ref']}; "
        f"operation={data['operation']}; add={data['add_count']}; "
        f"update={data['update_count']}; approval-required=yes.\n"
    )
    return EXIT_DIFFERENCES


def _inspect_test_write_run_spec_command(args: argparse.Namespace) -> int:
    run_spec = load_test_write_run_spec(args.run_spec)
    rendered = _render_test_write_run_spec_inspection(run_spec, args.report_format)
    if args.output:
        atomic_write_private_text(args.output, rendered, overwrite=False)
    else:
        sys.stdout.write(rendered)
    return EXIT_VALID


def _test_write_output_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    journal_path = validate_sensitive_output_path(args.journal_output, overwrite=False)
    report_path = validate_sensitive_output_path(args.report_output, overwrite=False)
    try:
        if journal_path.resolve(strict=False) == report_path.resolve(strict=False):
            raise TestWriteTransportError(
                "test_write_output_paths_collide",
                "Test write journal and report paths must be different",
            )
    except OSError as exc:
        raise TestWriteTransportError(
            "test_write_output_path_resolution_failed",
            "Test write output paths could not be resolved safely",
        ) from exc
    return journal_path, report_path


def _run_test_calendar_write_command(args: argparse.Namespace) -> int:
    _require_online(args)
    journal_path, report_path = _test_write_output_paths(args)
    target = load_test_write_target_config(args.target_config)
    run_spec = load_test_write_run_spec(args.run_spec)
    plan = load_sync_plan_report(args.plan)
    baseline = load_baseline(args.trusted_baseline) if args.trusted_baseline else None
    baseline_hash = baseline.baseline_content_hash if baseline is not None else None

    # All local Production, integrity, provenance, and approval guards execute
    # before credentials are loaded or an API-capable client can be constructed.
    target_ref = test_write_target_reference(target)
    if run_spec.target_safe_ref != target_ref or not hmac.compare_digest(
        run_spec.target_fingerprint,
        target.expected_target_fingerprint,
    ):
        raise TestWriteTransportError(
            "production_or_mismatched_test_write_target",
            "Production or mismatched Calendar write access is forbidden",
        )
    approve_test_write_run_spec(
        run_spec,
        args.confirmation,
        current_snapshot_hash=run_spec.current_snapshot_hash,
        current_plan_hash=plan.plan_content_hash,
        current_baseline_hash=baseline_hash,
    )

    bindings = load_google_optional_bindings()
    credentials = load_test_write_credentials(
        args.token_file,
        args.production_read_token_file,
        target,
        bindings=bindings,
    )
    client = build_test_calendar_write_client(
        credentials,
        target_config=target,
        build_service=bindings.build_service,
    )
    result = run_test_calendar_write(
        run_spec,
        target,
        client,
        args.confirmation,
        current_snapshot_hash=run_spec.current_snapshot_hash,
        current_plan_hash=plan.plan_content_hash,
        current_baseline_hash=baseline_hash,
    )
    rendered = (
        render_test_write_json_report(result)
        if args.report_format == "json"
        else render_test_write_text_report(result)
    )
    write_test_write_journal(result.journal, journal_path)
    atomic_write_private_text(report_path, rendered, overwrite=False)
    report = json.loads(render_test_write_json_report(result))
    sys.stdout.write(
        "Test Calendar write run stored: "
        f"target={report['target_safe_ref']}; run={report['run_spec_ref']}; "
        f"operation={report['operation']}; state={report['state']}; "
        f"success={'yes' if report['success'] else 'no'}; "
        f"API-calls={report['api_call_count']}; "
        f"mutation-attempts={report['mutation_attempt_count']}; "
        "mutation-retries=0.\n"
    )
    return EXIT_VALID if result.state is TestWriteExecutionState.SUCCEEDED else EXIT_FATAL_GUARD


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


def _baseline_status_line(label: str, baseline: object) -> str:
    from tridentine_calendar_google_sync.baseline_models import TrustedBaseline

    if not isinstance(baseline, TrustedBaseline):
        raise TypeError("baseline is invalid")
    data = baseline_inspection_data(baseline)
    return (
        f"{label}: state={data['state']}; target={data['target_reference']}; "
        f"managed_uid_count={data['managed_uid_count']}; "
        f"baseline_content_hash={data['baseline_content_hash']}.\n"
    )


def _create_baseline_candidate_command(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile, args.profiles_dir)
    source = inspect_source(args.source, profile)
    snapshot = load_google_snapshot(args.google_snapshot)
    diff = diff_source_to_snapshot(source, snapshot, ManagedScope())
    candidate = build_baseline_candidate(profile, source, snapshot, diff)
    write_baseline(candidate, args.output)
    sys.stdout.write(_baseline_status_line("Baseline candidate stored", candidate))
    return EXIT_VALID


def _inspect_baseline_command(args: argparse.Namespace) -> int:
    baseline = load_baseline(args.baseline)
    rendered = (
        render_baseline_inspection_json(baseline)
        if args.report_format == "json"
        else render_baseline_text(baseline)
    )
    if args.output:
        _write_report(args.output, rendered)
    else:
        sys.stdout.write(rendered)
    return EXIT_VALID


def _trust_baseline_command(args: argparse.Namespace) -> int:
    candidate = load_baseline(args.candidate)
    baseline_confirmation_phrase(candidate)
    trusted = trust_baseline(candidate, args.confirmation)
    write_baseline(trusted, args.output)
    sys.stdout.write(_baseline_status_line("Trusted baseline stored", trusted))
    return EXIT_VALID


def _plan_sync_command(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile, args.profiles_dir)
    source = inspect_source(args.source, profile)
    snapshot = load_google_snapshot(args.google_snapshot)
    baseline = load_baseline(args.trusted_baseline)
    thresholds = PlanThresholds(
        max_add=args.max_add,
        max_update=args.max_update,
        max_delete=args.max_delete,
    )
    plan = build_sync_plan(
        profile,
        source,
        snapshot,
        baseline,
        thresholds=thresholds,
    )
    rendered = (
        render_plan_json_report(plan)
        if args.report_format == "json"
        else render_plan_text_report(plan)
    )
    atomic_write_private_text(args.output, rendered, overwrite=False)
    sys.stdout.write(
        "Non-executable sync plan stored: "
        f"state={plan.state.value}; executable=no; "
        f"approval_required={'yes' if plan.approval_required else 'no'}; "
        f"proposed_actions={len(plan.proposed_actions)}; "
        f"safety_guards={len(plan.safety_guards)}; "
        f"plan_content_hash={plan.plan_content_hash}.\n"
    )
    if plan.state is PlanState.DRAFT:
        return EXIT_VALID
    if plan.state is PlanState.REVIEW_REQUIRED:
        return EXIT_DIFFERENCES
    return EXIT_FATAL_GUARD


def _build_apply_bundle_command(args: argparse.Namespace) -> int:
    profile = load_profile(args.profile, args.profiles_dir)
    source = inspect_source(args.source, profile)
    snapshot = load_google_snapshot(args.google_snapshot)
    baseline = load_baseline(args.trusted_baseline)
    plan = load_sync_plan_report(args.plan)
    recomputed = build_sync_plan(
        profile,
        source,
        snapshot,
        baseline,
        thresholds=plan.thresholds,
    )
    if not hmac.compare_digest(
        render_plan_json_report(plan).encode("utf-8"),
        render_plan_json_report(recomputed).encode("utf-8"),
    ):
        raise ApplyGuardError(
            "apply_plan_recomputation_mismatch",
            "apply inputs do not exactly reproduce the supplied plan",
        )
    environment = ApplyEnvironment(args.environment)
    bundle = build_apply_bundle(
        profile,
        source,
        snapshot,
        baseline,
        plan,
        environment=environment,
        target_label=args.target_label,
    )
    write_apply_bundle(bundle, args.output)
    report = build_apply_bundle_json_report(bundle)
    counts = report["operation_counts"]
    assert isinstance(counts, dict)
    sys.stdout.write(
        "Non-executable apply bundle stored: "
        f"environment={report['environment']}; state={report['state']}; "
        f"target={report['target_reference']}; plan={report['plan_reference']}; "
        f"bundle={report['bundle_reference']}; operations={counts['total']}; "
        f"add={counts['add']}; update={counts['update']}; delete={counts['delete']}.\n"
    )
    return EXIT_VALID if bundle.generated_operation_count == 0 else EXIT_DIFFERENCES


def _inspect_apply_bundle_command(args: argparse.Namespace) -> int:
    bundle = load_apply_bundle(args.bundle)
    rendered = (
        render_apply_bundle_json_report(bundle)
        if args.report_format == "json"
        else render_apply_bundle_text_report(bundle)
    )
    if args.output:
        _write_report(args.output, rendered)
    else:
        sys.stdout.write(rendered)
    return EXIT_VALID


def _simulation_output_paths(args: argparse.Namespace) -> tuple[Path, Path]:
    journal_path = validate_sensitive_output_path(args.journal_output, overwrite=False)
    report_path = validate_sensitive_output_path(args.report_output, overwrite=False)
    try:
        paths_collide = journal_path.resolve(strict=False) == report_path.resolve(strict=False)
    except OSError as exc:
        raise ApplyGuardError(
            "simulation_output_path_resolution_failed",
            "simulation output paths could not be safely resolved",
        ) from exc
    if paths_collide:
        raise ApplyGuardError(
            "simulation_output_paths_collide",
            "journal and report outputs must be different files",
        )
    return journal_path, report_path


def _simulate_apply_command(args: argparse.Namespace) -> int:
    journal_path, report_path = _simulation_output_paths(args)
    bundle = load_apply_bundle(args.bundle)
    plan = load_sync_plan_report(args.plan)
    approved = approve_apply_bundle(
        bundle,
        args.confirmation,
        plan.plan_content_hash,
    )
    transport = FakeMutationTransport.from_bundle(approved)
    result = run_apply_simulation(approved, transport)
    rendered = (
        render_apply_json_report(result)
        if args.report_format == "json"
        else render_apply_text_report(result)
    )
    write_operation_journal(result.journal, journal_path)
    atomic_write_private_text(report_path, rendered, overwrite=False)
    report = build_apply_json_report(result)
    sys.stdout.write(
        "Offline fake apply simulation stored: "
        f"state={report['simulation_state']}; target={report['target_reference']}; "
        f"plan={report['plan_reference']}; bundle={report['bundle_reference']}; "
        f"stopped_early={'yes' if report['stopped_early'] else 'no'}; "
        f"fatal_guard={'yes' if report['fatal_guard'] else 'no'}.\n"
    )
    if result.state is ApplySimulationState.COMPLETED:
        return EXIT_VALID
    if result.state is ApplySimulationState.PARTIAL_FAILURE:
        return EXIT_DIFFERENCES
    return EXIT_FATAL_GUARD


def _inspect_operation_journal_command(args: argparse.Namespace) -> int:
    journal = load_operation_journal(args.journal)
    rendered = (
        render_operation_journal_json_report(journal)
        if args.report_format == "json"
        else render_operation_journal_text_report(journal)
    )
    if args.output:
        _write_report(args.output, rendered)
    else:
        sys.stdout.write(rendered)
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
        if args.command == "inspect-test-calendar-prewrite":
            return _inspect_test_calendar_prewrite_command(args)
        if args.command == "authorize-test-google-write":
            return _authorize_test_google_write_command(args)
        if args.command == "build-test-write-run-spec":
            return _build_test_write_run_spec_command(args)
        if args.command == "inspect-test-write-run-spec":
            return _inspect_test_write_run_spec_command(args)
        if args.command == "run-test-calendar-write":
            return _run_test_calendar_write_command(args)
        if args.command == "authorize-google-readonly":
            return _authorize_google_command(args)
        if args.command == "fetch-google-snapshot":
            return _fetch_google_command(args)
        if args.command == "create-baseline-candidate":
            return _create_baseline_candidate_command(args)
        if args.command == "inspect-baseline":
            return _inspect_baseline_command(args)
        if args.command == "trust-baseline":
            return _trust_baseline_command(args)
        if args.command == "plan-sync":
            return _plan_sync_command(args)
        if args.command == "build-apply-bundle":
            return _build_apply_bundle_command(args)
        if args.command == "inspect-apply-bundle":
            return _inspect_apply_bundle_command(args)
        if args.command == "simulate-apply":
            return _simulate_apply_command(args)
        if args.command == "inspect-operation-journal":
            return _inspect_operation_journal_command(args)
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
    except (TestWriteAuthConfigError, TestWriteTargetConfigError) as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_CLI_ERROR
    except TestWriteApprovalError as exc:
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
    except TestWriteAuthError as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_GOOGLE_READ_ERROR
    except SnapshotWriteError as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_INVALID_SNAPSHOT
    except BaselineConfirmationError as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_CLI_ERROR
    except BaselineGuardError as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_FATAL_GUARD
    except BaselineError as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_INVALID_SNAPSHOT
    except ApplyConfirmationError as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_CLI_ERROR
    except (ApplyGuardError, ApplySimulationError, FakeMutationError) as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_FATAL_GUARD
    except (PlanReportError, OperationJournalError) as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_INVALID_SNAPSHOT
    except (TestWriteRunSpecIOError, TestWriteJournalError) as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_INVALID_SNAPSHOT
    except TestCalendarPrewriteIOError as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_INVALID_SNAPSHOT
    except ApplyError as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_INVALID_SNAPSHOT
    except PlanError as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_FATAL_GUARD
    except (TestWriteTargetError, TestWriteRunSpecError, TestWriteTransportError) as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_FATAL_GUARD
    except (TestCalendarPrewriteClientError, TestCalendarPrewriteError) as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_FATAL_GUARD
    except TestWriteClientError as exc:
        sys.stderr.write(f"error: {exc.public_message}\n")
        return EXIT_FATAL_GUARD
    except SensitivePathError as exc:
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
