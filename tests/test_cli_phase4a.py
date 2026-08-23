from __future__ import annotations

import argparse
import json
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import SyntheticBaselineBundle, write_profile_directory
from test_sync_plan import _large_bundle

import tridentine_calendar_google_sync.cli as cli
from tridentine_calendar_google_sync.baseline_engine import baseline_confirmation_phrase
from tridentine_calendar_google_sync.baseline_io import load_baseline, write_baseline
from tridentine_calendar_google_sync.google_snapshot import parse_google_snapshot_bytes
from tridentine_calendar_google_sync.plan_engine import build_sync_plan
from tridentine_calendar_google_sync.plan_models import PlanThresholds

BundleFactory = Callable[..., SyntheticBaselineBundle]


def _bundle(
    valid_source: Path,
    profile_factory: Callable[..., object],
    bundle_factory: BundleFactory,
    snapshots: Path,
) -> SyntheticBaselineBundle:
    return bundle_factory(valid_source, profile_factory, snapshots / "exact_match.json")


def _source_args(
    valid_source: Path,
    profiles_dir: Path,
    snapshot: Path,
) -> list[str]:
    return [
        "--source",
        str(valid_source),
        "--profile",
        "synthetic-test-profile",
        "--profiles-dir",
        str(profiles_dir),
        "--google-snapshot",
        str(snapshot),
    ]


def test_phase4a_command_names_and_primary_options_are_registered() -> None:
    parser = cli.build_parser()

    candidate = parser.parse_args(
        [
            "create-baseline-candidate",
            "--source",
            "source.ics",
            "--profile",
            "accepted-20260814",
            "--google-snapshot",
            "snapshot.json",
            "--output",
            "candidate.json",
        ]
    )
    inspect = parser.parse_args(["inspect-baseline", "--baseline", "candidate.json"])
    trust = parser.parse_args(
        [
            "trust-baseline",
            "--candidate",
            "candidate.json",
            "--output",
            "trusted.json",
            "--confirmation",
            "synthetic-confirmation",
        ]
    )
    plan = parser.parse_args(
        [
            "plan-sync",
            "--source",
            "source.ics",
            "--profile",
            "accepted-20260814",
            "--google-snapshot",
            "snapshot.json",
            "--trusted-baseline",
            "trusted.json",
            "--output",
            "plan.json",
        ]
    )

    assert candidate.command == "create-baseline-candidate"
    assert inspect.command == "inspect-baseline"
    assert trust.command == "trust-baseline"
    assert plan.command == "plan-sync"
    assert plan.max_add == plan.max_update == plan.max_delete == 0


@pytest.mark.parametrize(
    "command",
    (
        "create-baseline-candidate",
        "inspect-baseline",
        "trust-baseline",
        "plan-sync",
    ),
)
def test_phase4a_subcommand_help_exits_zero(
    command: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(SystemExit) as caught:
        cli.build_parser().parse_args([command, "--help"])
    captured = capsys.readouterr()

    assert caught.value.code == 0
    assert command in captured.out


def test_plan_sync_rejects_negative_threshold_at_argument_boundary() -> None:
    with pytest.raises(argparse.ArgumentError):
        cli.build_parser().parse_args(
            [
                "plan-sync",
                "--source",
                "source.ics",
                "--profile",
                "accepted-20260814",
                "--google-snapshot",
                "snapshot.json",
                "--trusted-baseline",
                "trusted.json",
                "--output",
                "plan.json",
                "--max-delete",
                "-1",
            ]
        )


def test_candidate_create_inspect_and_trust_cli_round_trip_is_redacted(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    google_snapshots_dir: Path,
) -> None:
    profile = synthetic_profile_factory(valid_source)
    profiles_dir = write_profile_directory(profile, tmp_path / "profiles")
    candidate_path = tmp_path / "candidate.baseline.json"
    trusted_path = tmp_path / "trusted.baseline.json"
    common = _source_args(
        valid_source,
        profiles_dir,
        google_snapshots_dir / "exact_match.json",
    )

    create_result = cli.main(
        ["create-baseline-candidate", *common, "--output", str(candidate_path)]
    )
    create_output = capsys.readouterr()
    candidate = load_baseline(candidate_path)
    inspect_result = cli.main(
        ["inspect-baseline", "--baseline", str(candidate_path), "--format", "json"]
    )
    inspect_output = capsys.readouterr()
    trust_result = cli.main(
        [
            "trust-baseline",
            "--candidate",
            str(candidate_path),
            "--output",
            str(trusted_path),
            "--confirmation",
            baseline_confirmation_phrase(candidate),
        ]
    )
    trust_output = capsys.readouterr()

    assert (create_result, inspect_result, trust_result) == (0, 0, 0)
    assert trusted_path.exists()
    assert load_baseline(trusted_path).state.value == "trusted"
    assert json.loads(inspect_output.out)["state"] == "candidate"
    combined = create_output.out + inspect_output.out + trust_output.out
    for sensitive in (
        "fixture-valid-001@example.invalid",
        str(candidate_path),
        str(trusted_path),
        candidate.target_fingerprint,
    ):
        assert sensitive not in combined


def test_trust_cli_wrong_confirmation_returns_two_and_writes_nothing(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    candidate_path = tmp_path / "candidate.baseline.json"
    output = tmp_path / "must-not-write.baseline.json"
    write_baseline(bundle.candidate, candidate_path)

    result = cli.main(
        [
            "trust-baseline",
            "--candidate",
            str(candidate_path),
            "--output",
            str(output),
            "--confirmation",
            "wrong synthetic confirmation",
        ]
    )
    captured = capsys.readouterr()

    assert result == 2
    assert not output.exists()
    assert str(candidate_path) not in captured.out + captured.err
    assert "fixture-valid-001@example.invalid" not in captured.out + captured.err


def test_plan_sync_draft_and_blocked_exit_mapping(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    profiles_dir = write_profile_directory(bundle.profile, tmp_path / "profiles")
    baseline_path = tmp_path / "trusted.baseline.json"
    write_baseline(bundle.trusted, baseline_path)
    draft_output = tmp_path / "draft.sync-plan.json"
    blocked_output = tmp_path / "blocked.sync-plan.json"
    common = _source_args(
        valid_source,
        profiles_dir,
        google_snapshots_dir / "exact_match.json",
    )

    draft_result = cli.main(
        [
            "plan-sync",
            *common,
            "--trusted-baseline",
            str(baseline_path),
            "--output",
            str(draft_output),
            "--format",
            "json",
        ]
    )
    draft_console = capsys.readouterr()
    blocked_common = _source_args(
        valid_source,
        profiles_dir,
        google_snapshots_dir / "summary_changed.json",
    )
    blocked_result = cli.main(
        [
            "plan-sync",
            *blocked_common,
            "--trusted-baseline",
            str(baseline_path),
            "--output",
            str(blocked_output),
            "--format",
            "json",
        ]
    )
    blocked_console = capsys.readouterr()

    assert draft_result == 0
    assert blocked_result == 5
    assert json.loads(draft_output.read_text(encoding="utf-8"))["state"] == "draft"
    assert json.loads(blocked_output.read_text(encoding="utf-8"))["state"] == "blocked"
    for output in (draft_console.out, blocked_console.out):
        assert "executable=no" in output
        assert str(baseline_path) not in output
        assert "fixture-valid-001@example.invalid" not in output


def test_plan_sync_review_required_returns_one_with_mocked_safe_plan(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    large_profile, large_source, _snapshot, document, trusted = _large_bundle(
        tmp_path, synthetic_profile_factory
    )
    document["events"][0]["summary"] = "Changed synthetic summary"
    changed_snapshot = parse_google_snapshot_bytes(json.dumps(document).encode("utf-8"))
    review_plan = build_sync_plan(
        large_profile,
        large_source,
        changed_snapshot,
        trusted,
        thresholds=PlanThresholds(max_update=1),
    )
    profiles_dir = write_profile_directory(bundle.profile, tmp_path / "profiles-small")
    baseline_path = tmp_path / "trusted-small.baseline.json"
    write_baseline(bundle.trusted, baseline_path)
    output = tmp_path / "review.sync-plan.json"
    monkeypatch.setattr(cli, "build_sync_plan", lambda *_args, **_kwargs: review_plan)

    result = cli.main(
        [
            "plan-sync",
            *_source_args(
                valid_source,
                profiles_dir,
                google_snapshots_dir / "exact_match.json",
            ),
            "--trusted-baseline",
            str(baseline_path),
            "--output",
            str(output),
            "--format",
            "json",
            "--max-update",
            "1",
        ]
    )
    captured = capsys.readouterr()

    assert result == 1
    assert json.loads(output.read_text(encoding="utf-8"))["state"] == "review_required"
    assert "executable=no" in captured.out


def test_phase4a_cli_commands_do_not_touch_google_online_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def forbidden(*_args: object, **_kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("Google online boundary must remain unused")

    for name in (
        "authorize_google_readonly",
        "fetch_google_event_pages",
        "build_read_only_calendar_client",
    ):
        monkeypatch.setattr(cli, name, forbidden)

    parser = cli.build_parser()
    for command in (
        "create-baseline-candidate",
        "inspect-baseline",
        "trust-baseline",
        "plan-sync",
    ):
        assert command in parser.format_help()
    assert calls == 0
