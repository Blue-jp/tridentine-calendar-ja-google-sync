from __future__ import annotations

from pathlib import Path

import pytest
from conftest import write_profile_directory
from phase5c0_helpers import build_bootstrap_bundle, write_test_target_config

import tridentine_calendar_google_sync.cli as cli
from tridentine_calendar_google_sync.test_bootstrap_plan_io import (
    load_test_bootstrap_add_plan,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec_io import (
    load_test_bootstrap_add_run_spec,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_io import (
    write_test_calendar_prewrite_snapshot,
)

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


def test_generic_apply_sync_execute_aliases_remain_absent() -> None:
    help_text = cli.build_parser().format_help()
    for alias in ("apply", "sync", "execute"):
        assert f"{{{alias}}}" not in help_text
