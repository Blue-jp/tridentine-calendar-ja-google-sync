from __future__ import annotations

import argparse
from pathlib import Path

import pytest
from conftest import write_profile_directory
from phase5d0_helpers import build_single_update_bundle, write_test_target_config

import tridentine_calendar_google_sync.cli as cli
from tridentine_calendar_google_sync.baseline_io import write_baseline
from tridentine_calendar_google_sync.test_calendar_prewrite_io import (
    write_test_calendar_prewrite_snapshot,
)
from tridentine_calendar_google_sync.test_single_update_plan_io import (
    load_test_single_update_plan,
)
from tridentine_calendar_google_sync.test_single_update_run_spec_io import (
    load_test_single_update_run_spec,
)

COMMANDS = (
    "build-test-single-update-plan",
    "inspect-test-single-update-plan",
    "build-test-single-update-run-spec",
)


@pytest.mark.parametrize("command", COMMANDS)
def test_each_single_update_command_help_is_test_only_and_safe(
    command: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = cli.build_parser()
    with pytest.raises(SystemExit) as captured:
        parser.parse_args([command, "--help"])
    assert captured.value.code == 0
    text = " ".join(capsys.readouterr().out.casefold().split())
    assert "test" in text
    assert "production" in text
    if command == "build-test-single-update-plan":
        for required in (
            "offline",
            "trusted test baseline",
            "exactly one managed event",
            "description-only",
            "normal sync plan guards",
            "google api",
            "add",
            "delete",
        ):
            assert required in text
    elif command == "inspect-test-single-update-plan":
        for required in (
            "safe metadata",
            "non-executable",
            "raw uid",
            "event id",
            "etag",
        ):
            assert required in text
    else:
        for required in (
            "test-only",
            "trusted baseline",
            "description-only",
            "event id",
            "etag",
            "exact approval",
            "add",
            "delete",
        ):
            assert required in text


def test_single_update_cli_contracts_are_offline_and_explicit() -> None:
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
        "--trusted-baseline",
        "baseline.json",
        "--target-config",
        "target.toml",
    ]
    plan = parser.parse_args(["build-test-single-update-plan", *common, "--output", "plan.json"])
    inspect = parser.parse_args(
        ["inspect-test-single-update-plan", "--plan", "plan.json", "--format", "json"]
    )
    run_spec = parser.parse_args(
        [
            "build-test-single-update-run-spec",
            *common,
            "--single-update-plan",
            "plan.json",
            "--output",
            "run-spec.json",
        ]
    )
    assert plan.command == "build-test-single-update-plan"
    assert inspect.report_format == "json"
    assert run_spec.command == "build-test-single-update-run-spec"
    for parsed in (plan, inspect, run_spec):
        assert not hasattr(parsed, "online")
        assert not hasattr(parsed, "token_file")
        assert not hasattr(parsed, "credentials_file")


def test_cli_inventory_adds_only_three_explicit_commands() -> None:
    parser = cli.build_parser()
    subparsers = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    assert len(subparsers.choices) == 31
    assert set(COMMANDS) <= set(subparsers.choices)
    for alias in ("apply", "sync", "execute"):
        assert alias not in subparsers.choices


def test_single_update_cli_plan_inspect_and_run_spec_roundtrip_is_redacted(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    bundle = build_single_update_bundle(tmp_path)
    profiles_dir = write_profile_directory(bundle.updated_profile, tmp_path / "profiles")
    snapshot_path = tmp_path / "fixture.test-calendar-prewrite-snapshot.json"
    baseline_path = tmp_path / "fixture.baseline.json"
    target_path = write_test_target_config(bundle.target, tmp_path / "fixture-target.toml")
    plan_path = tmp_path / "fixture.test-single-update-plan.json"
    run_spec_path = tmp_path / "fixture.test-single-update-run-spec.json"
    write_test_calendar_prewrite_snapshot(bundle.prewrite_snapshot, snapshot_path)
    write_baseline(bundle.baseline, baseline_path)
    common = [
        "--source",
        str(bundle.updated_path),
        "--profile",
        bundle.updated_profile.profile_id,
        "--profiles-dir",
        str(profiles_dir),
        "--prewrite-snapshot",
        str(snapshot_path),
        "--trusted-baseline",
        str(baseline_path),
        "--target-config",
        str(target_path),
    ]

    plan_result = cli.main(["build-test-single-update-plan", *common, "--output", str(plan_path)])
    plan_output = capsys.readouterr()
    inspect_result = cli.main(
        ["inspect-test-single-update-plan", "--plan", str(plan_path), "--format", "json"]
    )
    inspect_output = capsys.readouterr()
    run_result = cli.main(
        [
            "build-test-single-update-run-spec",
            *common,
            "--single-update-plan",
            str(plan_path),
            "--output",
            str(run_spec_path),
        ]
    )
    run_output = capsys.readouterr()

    plan = load_test_single_update_plan(plan_path)
    run_spec = load_test_single_update_run_spec(run_spec_path)
    assert (plan_result, inspect_result, run_result) == (
        cli.EXIT_DIFFERENCES,
        cli.EXIT_VALID,
        cli.EXIT_DIFFERENCES,
    )
    assert plan.changed_fields == ("description",)
    assert run_spec.planning_mode == "test_single_update"
    assert (run_spec.add_count, run_spec.update_count, run_spec.delete_count) == (0, 1, 0)
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
        bundle.updated_source.events[0].uid,
        bundle.updated_source.events[0].summary,
        bundle.updated_source.events[0].description,
        bundle.prewrite_snapshot.snapshot.events[0].event_id,
        bundle.prewrite_snapshot.snapshot.events[0].etag,
        bundle.target.calendar_id,
        bundle.target.expected_target_fingerprint,
        str(tmp_path),
    ):
        assert forbidden not in combined
