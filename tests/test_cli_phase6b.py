from __future__ import annotations

import argparse
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from phase6b_helpers import (
    build_production_planning_inputs,
    write_production_target_config,
    write_profile_directory,
)

from tridentine_calendar_google_sync import cli
from tridentine_calendar_google_sync.accepted_production_source_manifest_io import (
    write_accepted_production_source_manifest,
)
from tridentine_calendar_google_sync.baseline_io import write_baseline
from tridentine_calendar_google_sync.production_single_update_plan import (
    build_production_single_update_plan,
)
from tridentine_calendar_google_sync.production_single_update_plan_io import (
    load_production_single_update_plan,
)
from tridentine_calendar_google_sync.production_single_update_run_spec import (
    build_production_single_update_run_spec,
)
from tridentine_calendar_google_sync.production_single_update_run_spec_io import (
    load_production_single_update_run_spec,
    render_production_single_update_run_spec_json,
)
from tridentine_calendar_google_sync.snapshot_io import write_google_snapshot

COMMANDS = (
    "inspect-accepted-production-source-manifest",
    "build-production-single-update-plan",
    "inspect-production-single-update-plan",
    "build-production-single-update-run-spec",
    "inspect-production-single-update-run-spec",
)
CLI_NOW = datetime(2099, 1, 1, 12, 0, tzinfo=UTC)


class _FixedDateTime(datetime):
    @classmethod
    def now(cls, tz: Any = None) -> datetime:
        return CLI_NOW if tz is not None else CLI_NOW.replace(tzinfo=None)


def _write_cli_inputs(tmp_path: Path) -> tuple[Any, dict[str, Path]]:
    inputs = build_production_planning_inputs(tmp_path / "private-inputs")
    paths = {
        "manifest": tmp_path / "accepted-production-source-manifest.json",
        "profiles": tmp_path / "profiles",
        "snapshot": tmp_path / "production-snapshot.json",
        "baseline": tmp_path / "trusted-production-baseline.json",
        "target": tmp_path / "production-write-target.toml",
        "plan": tmp_path / "production-single-update-plan.json",
        "run_spec": tmp_path / "production-single-update-run-spec.json",
    }
    write_accepted_production_source_manifest(inputs.manifest, paths["manifest"])
    write_profile_directory(inputs.updated.profile, paths["profiles"])
    write_google_snapshot(inputs.snapshot, paths["snapshot"])
    write_baseline(inputs.baseline, paths["baseline"])
    write_production_target_config(inputs.target, paths["target"])
    return inputs, paths


def _plan_arguments(paths: dict[str, Path], profile_id: str) -> list[str]:
    return [
        "--manifest",
        str(paths["manifest"]),
        "--source",
        str(paths["source"]),
        "--profile",
        profile_id,
        "--profiles-dir",
        str(paths["profiles"]),
        "--google-snapshot",
        str(paths["snapshot"]),
        "--trusted-baseline",
        str(paths["baseline"]),
        "--target-config",
        str(paths["target"]),
    ]


@pytest.mark.parametrize("command", COMMANDS)
def test_phase6b_commands_have_safe_offline_help(command: str, capsys: Any) -> None:
    parser = cli.build_parser()
    with pytest.raises(SystemExit) as captured:
        parser.parse_args([command, "--help"])
    assert captured.value.code == 0
    help_text = capsys.readouterr().out.casefold()
    assert "production" in help_text
    assert "offline" in help_text or command.startswith("inspect-")
    assert "executor" in help_text or "never displayed" in help_text


def test_phase6b_parser_contract_has_only_explicit_local_artifact_arguments() -> None:
    parser = cli.build_parser()
    manifest = parser.parse_args(
        [
            "inspect-accepted-production-source-manifest",
            "--manifest",
            "manifest.json",
            "--format",
            "json",
            "--output",
            "report.json",
        ]
    )
    common = [
        "--manifest",
        "manifest.json",
        "--source",
        "accepted.ics",
        "--profile",
        "accepted-20990101",
        "--profiles-dir",
        "profiles",
        "--google-snapshot",
        "snapshot.json",
        "--trusted-baseline",
        "baseline.json",
        "--target-config",
        "target.toml",
    ]
    plan = parser.parse_args(
        ["build-production-single-update-plan", *common, "--output", "plan.json"]
    )
    inspect_plan = parser.parse_args(
        ["inspect-production-single-update-plan", "--plan", "plan.json"]
    )
    run_spec = parser.parse_args(
        [
            "build-production-single-update-run-spec",
            *common,
            "--production-plan",
            "plan.json",
            "--output",
            "run-spec.json",
        ]
    )
    inspect_run_spec = parser.parse_args(
        [
            "inspect-production-single-update-run-spec",
            "--run-spec",
            "run-spec.json",
            "--format",
            "json",
        ]
    )

    assert manifest.report_format == "json"
    assert plan.output == "plan.json"
    assert inspect_plan.report_format == "text"
    assert run_spec.production_plan == "plan.json"
    assert inspect_run_spec.report_format == "json"
    for parsed in (manifest, plan, inspect_plan, run_spec, inspect_run_spec):
        assert not hasattr(parsed, "online")
        assert not hasattr(parsed, "token_file")
        assert not hasattr(parsed, "credentials_file")
        assert not hasattr(parsed, "confirmation")

    with pytest.raises(argparse.ArgumentError):
        parser.parse_args(
            [
                "inspect-production-single-update-plan",
                "--plan",
                "plan.json",
                "--online",
            ]
        )


def test_cli_offline_manifest_plan_and_run_spec_flow_never_loads_google(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    inputs, paths = _write_cli_inputs(tmp_path)
    paths["source"] = inputs.updated.path

    def forbidden_google_boundary(*_args: object, **_kwargs: object) -> Any:
        raise AssertionError("Phase 6B CLI touched an optional Google boundary")

    monkeypatch.setattr(cli, "load_google_optional_bindings", forbidden_google_boundary)
    monkeypatch.setattr(cli, "datetime", _FixedDateTime)

    assert (
        cli.main(
            [
                "inspect-accepted-production-source-manifest",
                "--manifest",
                str(paths["manifest"]),
                "--format",
                "json",
            ]
        )
        == 0
    )
    manifest_output = capsys.readouterr().out
    assert "accepted-production-source-manifest-inspection-v1" in manifest_output
    assert inputs.manifest.repository_identity not in manifest_output

    common = _plan_arguments(paths, inputs.updated.profile.profile_id)
    assert (
        cli.main(
            [
                "build-production-single-update-plan",
                *common,
                "--output",
                str(paths["plan"]),
            ]
        )
        == 1
    )
    assert paths["plan"].is_file()
    plan = load_production_single_update_plan(paths["plan"])
    assert plan.operation_count == plan.update_count == 1
    build_plan_output = capsys.readouterr().out
    assert "executor=no" in build_plan_output
    assert inputs.updated.source.events[-1].description not in build_plan_output

    plan_report = tmp_path / "production-plan-inspection.json"
    assert (
        cli.main(
            [
                "inspect-production-single-update-plan",
                "--plan",
                str(paths["plan"]),
                "--format",
                "json",
                "--output",
                str(plan_report),
            ]
        )
        == 0
    )
    assert "production-single-update-plan-inspection-v1" in plan_report.read_text(encoding="utf-8")

    assert (
        cli.main(
            [
                "build-production-single-update-run-spec",
                *common,
                "--production-plan",
                str(paths["plan"]),
                "--output",
                str(paths["run_spec"]),
            ]
        )
        == 1
    )
    run_spec = load_production_single_update_run_spec(paths["run_spec"], now=CLI_NOW)
    assert run_spec.issued_at == CLI_NOW
    assert run_spec.expires_at == CLI_NOW + timedelta(hours=24)
    build_run_output = capsys.readouterr().out
    assert "executor=no" in build_run_output
    assert inputs.snapshot.events[-1].event_id not in build_run_output
    assert inputs.snapshot.events[-1].etag not in build_run_output

    assert (
        cli.main(
            [
                "inspect-production-single-update-run-spec",
                "--run-spec",
                str(paths["run_spec"]),
                "--format",
                "json",
            ]
        )
        == 0
    )
    inspection = capsys.readouterr().out
    assert "production-single-update-run-spec-inspection-v1" in inspection
    assert '"temporal_state": "current"' in inspection
    assert inputs.updated.source.events[-1].description not in inspection


def test_cli_inspects_expired_run_spec_but_does_not_make_it_current(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    inputs = build_production_planning_inputs(tmp_path / "inputs")
    plan = build_production_single_update_plan(
        inputs.manifest,
        inputs.updated.profile,
        inputs.updated.source,
        inputs.snapshot,
        inputs.baseline,
        inputs.target,
    )
    issued_at = CLI_NOW - timedelta(days=2)
    run_spec = build_production_single_update_run_spec(
        inputs.manifest,
        inputs.updated.profile,
        inputs.updated.source,
        inputs.snapshot,
        plan,
        inputs.baseline,
        inputs.target,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=15),
    )
    path = tmp_path / "expired.production-single-update-run-spec.json"
    path.write_text(
        render_production_single_update_run_spec_json(
            run_spec,
            now=CLI_NOW,
            require_current=False,
        ),
        encoding="utf-8",
        newline="\n",
    )
    monkeypatch.setattr(cli, "datetime", _FixedDateTime)

    assert (
        cli.main(
            [
                "inspect-production-single-update-run-spec",
                "--run-spec",
                str(path),
                "--format",
                "json",
            ]
        )
        == 0
    )
    inspection = capsys.readouterr().out
    assert '"temporal_state": "expired"' in inspection
    assert '"expired": true' in inspection
