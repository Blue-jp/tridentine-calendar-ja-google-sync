from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import write_profile_directory
from phase5a1_helpers import prewrite_page
from phase5a_helpers import SYNTHETIC_EVENT_ID
from phase5c0_helpers import build_bootstrap_bundle, write_test_target_config
from test_test_bootstrap_add_transport_phase5c0 import _inputs as bootstrap_inputs
from test_test_write_transport_phase5a import _Client

import tridentine_calendar_google_sync.cli as cli
from tridentine_calendar_google_sync.google_errors import SafeGoogleError
from tridentine_calendar_google_sync.test_bootstrap_plan_io import (
    load_test_bootstrap_add_plan,
    write_test_bootstrap_add_plan,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec_io import (
    load_test_bootstrap_add_run_spec,
    write_test_bootstrap_add_run_spec,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_io import (
    write_test_calendar_prewrite_snapshot,
)
from tridentine_calendar_google_sync.test_write_journal import (
    TestWriteJournal as WriteJournal,
)
from tridentine_calendar_google_sync.test_write_journal import (
    calculate_test_write_journal_hash,
    load_test_write_journal,
)
from tridentine_calendar_google_sync.test_write_report import verify_test_write_json_report

COMMANDS = (
    "build-test-bootstrap-add-plan",
    "inspect-test-bootstrap-add-plan",
    "build-test-bootstrap-add-run-spec",
)


@pytest.mark.parametrize("command", COMMANDS)
def test_each_bootstrap_command_help_is_offline_test_only_and_safe(
    command: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = cli.build_parser()

    with pytest.raises(SystemExit) as captured:
        parser.parse_args([command, "--help"])

    assert captured.value.code == 0
    help_text = " ".join(capsys.readouterr().out.casefold().split())
    assert "test" in help_text
    if command == "build-test-bootstrap-add-plan":
        for required in (
            "offline",
            "exactly one synthetic all-day add",
            "verified empty test calendar",
            "non-executable plan",
            "does not change normal sync plan guards",
            "production targets are refused",
            "update, delete, google api use, and writes are unavailable",
        ):
            assert required in help_text
    elif command == "inspect-test-bootstrap-add-plan":
        assert "safe metadata only" in help_text
        assert "raw uid and event content are never displayed" in help_text
        assert "non-executable" in help_text
    else:
        for required in (
            "offline test-only initial add run spec",
            "trusted baseline is omitted only for this first empty-calendar add",
            "exactly one add",
            "update and delete are structurally unavailable",
            "production is refused",
            "exact approval phrase",
        ):
            assert required in help_text


def test_bootstrap_cli_contracts_have_no_online_token_or_credentials_argument() -> None:
    parser = cli.build_parser()
    common = [
        "--source",
        "source.ics",
        "--profile",
        "synthetic-test-profile",
        "--profiles-dir",
        "profiles",
        "--prewrite-snapshot",
        "snapshot.json",
        "--target-config",
        "target.toml",
        "--output",
        "output.json",
    ]
    plan = parser.parse_args(["build-test-bootstrap-add-plan", *common])
    run_spec = parser.parse_args(
        [
            "build-test-bootstrap-add-run-spec",
            *common[:-2],
            "--bootstrap-plan",
            "plan.json",
            *common[-2:],
        ]
    )
    inspect = parser.parse_args(
        ["inspect-test-bootstrap-add-plan", "--plan", "plan.json", "--format", "json"]
    )

    assert plan.command == "build-test-bootstrap-add-plan"
    assert run_spec.bootstrap_plan == "plan.json"
    assert inspect.report_format == "json"
    for parsed in (plan, run_spec, inspect):
        assert not hasattr(parsed, "online")
        assert not hasattr(parsed, "token_file")
        assert not hasattr(parsed, "credentials_file")


def test_bootstrap_plan_inspect_and_run_spec_cli_roundtrip_is_offline_and_redacted(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = build_bootstrap_bundle(tmp_path)
    profiles_dir = write_profile_directory(bundle.profile, tmp_path / "profiles")
    snapshot_path = tmp_path / "fixture.test-calendar-prewrite-snapshot.json"
    write_test_calendar_prewrite_snapshot(bundle.prewrite_snapshot, snapshot_path)
    target_path = write_test_target_config(bundle.target, tmp_path / "fixture-target.toml")
    plan_path = tmp_path / "fixture.test-bootstrap-add-plan.json"
    run_spec_path = tmp_path / "fixture.test-bootstrap-add-run-spec.json"

    common = [
        "--source",
        str(bundle.source_path),
        "--profile",
        bundle.profile.profile_id,
        "--profiles-dir",
        str(profiles_dir),
        "--prewrite-snapshot",
        str(snapshot_path),
        "--target-config",
        str(target_path),
    ]
    build_plan = cli.main(["build-test-bootstrap-add-plan", *common, "--output", str(plan_path)])
    plan_output = capsys.readouterr()
    inspect_plan = cli.main(
        ["inspect-test-bootstrap-add-plan", "--plan", str(plan_path), "--format", "json"]
    )
    inspect_output = capsys.readouterr()
    build_run_spec = cli.main(
        [
            "build-test-bootstrap-add-run-spec",
            *common,
            "--bootstrap-plan",
            str(plan_path),
            "--output",
            str(run_spec_path),
        ]
    )
    run_output = capsys.readouterr()

    plan = load_test_bootstrap_add_plan(plan_path)
    run_spec = load_test_bootstrap_add_run_spec(run_spec_path)
    assert (build_plan, inspect_plan, build_run_spec) == (
        cli.EXIT_DIFFERENCES,
        cli.EXIT_VALID,
        cli.EXIT_DIFFERENCES,
    )
    assert plan.operation_count == 1
    assert run_spec.add_count == 1
    assert run_spec.update_count == 0
    assert run_spec.delete_count == 0
    combined = (
        plan_output.out
        + plan_output.err
        + inspect_output.out
        + inspect_output.err
        + run_output.out
        + run_output.err
    )
    assert "AUTHORIZE TEST CALENDAR WRITE" in combined
    for forbidden in (
        bundle.source.events[0].uid,
        bundle.source.events[0].summary,
        bundle.source.events[0].description,
        bundle.target.calendar_id,
        bundle.target.expected_target_fingerprint,
        str(tmp_path),
    ):
        assert forbidden not in combined


def test_production_target_rejects_plan_before_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = build_bootstrap_bundle(tmp_path)
    profiles_dir = write_profile_directory(bundle.profile, tmp_path / "profiles")
    snapshot_path = tmp_path / "fixture.test-calendar-prewrite-snapshot.json"
    write_test_calendar_prewrite_snapshot(bundle.prewrite_snapshot, snapshot_path)
    target_path = write_test_target_config(bundle.target, tmp_path / "fixture-target.toml")
    content = target_path.read_text(encoding="utf-8").replace(
        'target_environment = "test"',
        'target_environment = "production"',
    )
    target_path.write_text(content, encoding="utf-8", newline="\n")
    output = tmp_path / "must-not-create.test-bootstrap-add-plan.json"

    result = cli.main(
        [
            "build-test-bootstrap-add-plan",
            "--source",
            str(bundle.source_path),
            "--profile",
            bundle.profile.profile_id,
            "--profiles-dir",
            str(profiles_dir),
            "--prewrite-snapshot",
            str(snapshot_path),
            "--target-config",
            str(target_path),
            "--output",
            str(output),
        ]
    )
    captured = capsys.readouterr()

    assert result != cli.EXIT_VALID
    assert not output.exists()
    assert "traceback" not in (captured.out + captured.err).casefold()
    assert str(tmp_path) not in captured.out + captured.err


def test_existing_plan_output_and_normal_plan_missing_baseline_remain_rejected(
    tmp_path: Path,
) -> None:
    bundle = build_bootstrap_bundle(tmp_path)
    profiles_dir = write_profile_directory(bundle.profile, tmp_path / "profiles")
    snapshot_path = tmp_path / "fixture.test-calendar-prewrite-snapshot.json"
    write_test_calendar_prewrite_snapshot(bundle.prewrite_snapshot, snapshot_path)
    target_path = write_test_target_config(bundle.target, tmp_path / "fixture-target.toml")
    output = tmp_path / "existing.test-bootstrap-add-plan.json"
    output.write_text("existing", encoding="utf-8")

    bootstrap_result = cli.main(
        [
            "build-test-bootstrap-add-plan",
            "--source",
            str(bundle.source_path),
            "--profile",
            bundle.profile.profile_id,
            "--profiles-dir",
            str(profiles_dir),
            "--prewrite-snapshot",
            str(snapshot_path),
            "--target-config",
            str(target_path),
            "--output",
            str(output),
        ]
    )
    normal_result = cli.main(
        [
            "plan-sync",
            "--source",
            str(bundle.source_path),
            "--profile",
            bundle.profile.profile_id,
            "--google-snapshot",
            str(snapshot_path),
            "--output",
            str(tmp_path / "normal-plan.json"),
        ]
    )

    assert bootstrap_result != cli.EXIT_VALID
    assert normal_result == cli.EXIT_CLI_ERROR
    assert output.read_text(encoding="utf-8") == "existing"


def _run_stopped_write_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, client: _Client
) -> tuple[WriteJournal, dict[str, object]]:
    bundle, spec, confirmation = bootstrap_inputs(tmp_path)
    spec_path = write_test_bootstrap_add_run_spec(spec, tmp_path / "spec.json")
    plan_path = write_test_bootstrap_add_plan(bundle.plan, tmp_path / "plan.json")
    target_path = write_test_target_config(bundle.target, tmp_path / "target.toml")
    journal_path, report_path = tmp_path / "journal.json", tmp_path / "report.json"
    monkeypatch.setattr(
        cli, "load_google_optional_bindings", lambda: SimpleNamespace(build_service=None)
    )
    monkeypatch.setattr(cli, "load_test_write_credentials", lambda *a, **kw: object())
    monkeypatch.setattr(cli, "build_test_calendar_write_client", lambda *a, **kw: client)

    exit_code = cli.main(
        [
            "run-test-calendar-write",
            "--online",
            "--run-spec",
            str(spec_path),
            "--plan",
            str(plan_path),
            "--target-config",
            str(target_path),
            "--token-file",
            str(tmp_path / "unused-write.json"),
            "--production-read-token-file",
            str(tmp_path / "unused-read.json"),
            "--confirmation",
            confirmation,
            "--journal-output",
            str(journal_path),
            "--report-output",
            str(report_path),
            "--format",
            "json",
        ]
    )

    assert exit_code == cli.EXIT_FATAL_GUARD
    journal = load_test_write_journal(journal_path)
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["journal_hash"] == journal.journal_content_hash
    return journal, report


@pytest.mark.google_test_write
def test_write_cli_persists_preflight_budget_stop(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _Client(
        list_queue=[prewrite_page(next_page_token=f"page-{i}") for i in range(8)]
        + [prewrite_page()]
    )
    journal, report = _run_stopped_write_cli(tmp_path, monkeypatch, client)
    assert [method for method, _ in client.calls] == ["list"] * 9
    assert len(journal.entries) == 1
    entry = journal.entries[0]
    assert (entry.phase.value, entry.status.value) == ("preflight", "failed")
    assert entry.safe_error_code == "test_write_api_call_budget_exceeded"
    assert journal.state.value == report["state"] == "failed"
    assert journal.api_call_count == report["api_call_count"] == 9
    assert journal.mutation_attempt_count == report["mutation_attempt_count"] == 0
    assert report["mutation_retry_count"] == 0 and report["read_back_verified"] is False


@pytest.mark.google_test_write
def test_write_cli_persists_failed_verification_get_after_acknowledged_import(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _Client(
        list_queue=[prewrite_page()],
        import_queue=[{"id": SYNTHETIC_EVENT_ID}],
        get_queue=[
            SafeGoogleError(
                status=412,
                reason="etag_conflict",
                retryable=False,
                attempt=1,
                operation="events.get",
            )
        ],
    )
    journal, report = _run_stopped_write_cli(tmp_path, monkeypatch, client)
    assert [method for method, _ in client.calls] == ["list", "import", "get"]
    assert [
        (entry.phase.value, entry.status.value, entry.api_call_count) for entry in journal.entries
    ] == [("preflight", "succeeded", 1), ("mutation", "succeeded", 2), ("read_back", "failed", 3)]
    assert journal.entries[-1].safe_error_code == "test_write_guard_failed"
    assert journal.state.value == report["state"] == "failed"
    assert journal.api_call_count == report["api_call_count"] == 3
    assert journal.mutation_attempt_count == report["mutation_attempt_count"] == 1
    assert journal.mutation_retry_count == report["mutation_retry_count"] == 0
    assert report["safe_findings"] == ["test_write_guard_failed"]
    assert report["stopped"] is True
    assert report["success"] is False and report["read_back_verified"] is False


@pytest.mark.google_test_write
def test_write_cli_persists_v2_only_for_acknowledged_import_without_id(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _Client(list_queue=[prewrite_page()], import_queue=[{}])
    journal, report = _run_stopped_write_cli(tmp_path, monkeypatch, client)
    verify_test_write_json_report(report, journal)
    assert [method for method, _ in client.calls] == ["list", "import"]
    assert journal.schema_version == report["schema_version"] == "2.0"
    assert journal.journal_type == "test-write-operation-journal-v2"
    assert report["report_type"] == "test-calendar-write-report-v2"
    assert [
        (entry.phase.value, entry.status.value, entry.api_call_count) for entry in journal.entries
    ] == [("preflight", "succeeded", 1), ("mutation", "succeeded", 2), ("read_back", "failed", 2)]
    assert journal.entries[-1].safe_error_code == "test_write_read_back_identity_missing"
    assert journal.state.value == report["state"] == "failed"
    assert journal.api_call_count == report["api_call_count"] == 2
    assert journal.read_retry_count == report["read_retry_count"] == 0
    assert journal.mutation_attempt_count == report["mutation_attempt_count"] == 1
    assert journal.mutation_retry_count == report["mutation_retry_count"] == 0
    assert report["safe_findings"] == ["test_write_read_back_identity_missing"]
    assert report["stopped"] is True and report["success"] is False
    assert report["read_back_verified"] is False and report["recovered_after_uncertain"] is False
    assert report["journal_hash"] == calculate_test_write_journal_hash(journal)


def test_generic_apply_sync_execute_aliases_remain_absent() -> None:
    help_text = cli.build_parser().format_help()
    for alias in ("apply", "sync", "execute"):
        assert f"{{{alias}}}" not in help_text
