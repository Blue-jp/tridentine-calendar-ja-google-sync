from __future__ import annotations

from pathlib import Path

import pytest
from conftest import write_profile_directory
from phase4b_helpers import build_update_apply_bundle

import tridentine_calendar_google_sync.cli as cli
from tridentine_calendar_google_sync.apply_approval import apply_approval_challenge
from tridentine_calendar_google_sync.apply_bundle_io import load_apply_bundle
from tridentine_calendar_google_sync.baseline_io import write_baseline
from tridentine_calendar_google_sync.google_sanitize import render_sanitized_snapshot
from tridentine_calendar_google_sync.operation_journal import load_operation_journal
from tridentine_calendar_google_sync.plan_io import load_sync_plan_report
from tridentine_calendar_google_sync.plan_report import render_plan_json_report


def _private_inputs(
    tmp_path: Path,
    profile_factory: object,
) -> tuple[object, Path, Path, Path, Path, Path]:
    value = build_update_apply_bundle(tmp_path, profile_factory)
    source_path = tmp_path / "source-101.ics"
    profiles_dir = write_profile_directory(value.profile, tmp_path / "profiles")
    snapshot_path = tmp_path / "snapshot.json"
    snapshot_path.write_bytes(render_sanitized_snapshot(value.snapshot))
    baseline_path = tmp_path / "trusted.baseline.json"
    write_baseline(value.baseline, baseline_path)
    plan_path = tmp_path / "review.sync-plan.json"
    plan_path.write_bytes(render_plan_json_report(value.plan).encode("utf-8"))
    assert plan_path.is_file()
    return value, source_path, profiles_dir, snapshot_path, baseline_path, plan_path


def test_phase4b_command_names_and_help_are_registered(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = cli.build_parser()
    for command in (
        "build-apply-bundle",
        "inspect-apply-bundle",
        "simulate-apply",
        "inspect-operation-journal",
    ):
        with pytest.raises(SystemExit) as caught:
            parser.parse_args([command, "--help"])
        assert caught.value.code == 0
        assert command in capsys.readouterr().out


def test_cli_bundle_inspect_simulate_and_journal_round_trip_is_offline_and_redacted(
    tmp_path: Path,
    synthetic_profile_factory: object,
    capsys: pytest.CaptureFixture[str],
) -> None:
    value, source_path, profiles_dir, snapshot_path, baseline_path, plan_path = _private_inputs(
        tmp_path,
        synthetic_profile_factory,
    )
    bundle_path = tmp_path / "private.apply-bundle.json"
    journal_path = tmp_path / "private.operation-journal.json"
    report_path = tmp_path / "simulation-report.json"

    build_result = cli.main(
        [
            "build-apply-bundle",
            "--source",
            str(source_path),
            "--profile",
            "synthetic-test-profile",
            "--profiles-dir",
            str(profiles_dir),
            "--google-snapshot",
            str(snapshot_path),
            "--trusted-baseline",
            str(baseline_path),
            "--plan",
            str(plan_path),
            "--environment",
            "test",
            "--output",
            str(bundle_path),
        ]
    )
    build_console = capsys.readouterr()
    assert build_result == 1, build_console.err
    assert bundle_path.is_file()
    inspect_result = cli.main(
        ["inspect-apply-bundle", "--bundle", str(bundle_path), "--format", "json"]
    )
    inspect_console = capsys.readouterr()
    bundle = load_apply_bundle(bundle_path)
    plan = load_sync_plan_report(plan_path)
    confirmation = apply_approval_challenge(bundle, plan.plan_content_hash)
    simulate_result = cli.main(
        [
            "simulate-apply",
            "--bundle",
            str(bundle_path),
            "--plan",
            str(plan_path),
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
    simulate_console = capsys.readouterr()
    inspect_journal_result = cli.main(
        [
            "inspect-operation-journal",
            "--journal",
            str(journal_path),
            "--format",
            "json",
        ]
    )
    journal_console = capsys.readouterr()

    assert (build_result, inspect_result, simulate_result, inspect_journal_result) == (
        1,
        0,
        0,
        0,
    )
    assert load_operation_journal(journal_path).state.value == "completed"
    assert report_path.exists()
    combined = build_console.out + inspect_console.out + simulate_console.out + journal_console.out
    operation = value.bundle.operations[0]
    for sensitive in (
        operation.source_uid,
        operation.payload.event_id,  # type: ignore[union-attr]
        operation.payload.etag,  # type: ignore[union-attr]
        str(bundle_path),
        str(journal_path),
        str(report_path),
    ):
        assert sensitive not in combined


def test_cli_simulation_wrong_confirmation_writes_no_journal_or_report(
    tmp_path: Path,
    synthetic_profile_factory: object,
    capsys: pytest.CaptureFixture[str],
) -> None:
    value, source_path, profiles_dir, snapshot_path, baseline_path, plan_path = _private_inputs(
        tmp_path,
        synthetic_profile_factory,
    )
    bundle_path = tmp_path / "private.apply-bundle.json"
    build_result = cli.main(
        [
            "build-apply-bundle",
            "--source",
            str(source_path),
            "--profile",
            "synthetic-test-profile",
            "--profiles-dir",
            str(profiles_dir),
            "--google-snapshot",
            str(snapshot_path),
            "--trusted-baseline",
            str(baseline_path),
            "--plan",
            str(plan_path),
            "--environment",
            "test",
            "--output",
            str(bundle_path),
        ]
    )
    build_console = capsys.readouterr()
    assert build_result == 1, build_console.err
    assert bundle_path.is_file()
    journal_path = tmp_path / "must-not-write.operation-journal.json"
    report_path = tmp_path / "must-not-write.report.json"

    result = cli.main(
        [
            "simulate-apply",
            "--bundle",
            str(bundle_path),
            "--plan",
            str(plan_path),
            "--confirmation",
            "wrong synthetic confirmation",
            "--journal-output",
            str(journal_path),
            "--report-output",
            str(report_path),
        ]
    )
    captured = capsys.readouterr()

    assert result == 2
    assert not journal_path.exists()
    assert not report_path.exists()
    assert str(bundle_path) not in captured.out + captured.err
    assert value.bundle.operations[0].source_uid not in captured.out + captured.err


def test_phase4b_cli_help_does_not_touch_online_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def forbidden(*_args: object, **_kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("online boundary must remain unused")

    for name in (
        "authorize_google_readonly",
        "fetch_google_event_pages",
        "build_read_only_calendar_client",
    ):
        monkeypatch.setattr(cli, name, forbidden)
    parser = cli.build_parser()
    assert "simulate-apply" in parser.format_help()
    assert calls == 0
