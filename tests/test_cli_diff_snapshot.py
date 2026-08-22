from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import write_profile_directory

from tridentine_calendar_google_sync.cli import main
from tridentine_calendar_google_sync.models import AcceptedSourceProfile

ProfileFactory = Callable[..., AcceptedSourceProfile]


def _args(
    source: str | Path,
    profiles_dir: Path,
    snapshot: str | Path,
    *,
    output_format: str = "json",
) -> list[str]:
    return [
        "diff-snapshot",
        "--source",
        str(source),
        "--profile",
        "synthetic-test-profile",
        "--profiles-dir",
        str(profiles_dir),
        "--snapshot",
        str(snapshot),
        "--format",
        output_format,
        "--redact-content",
    ]


def test_exact_cli_diff_returns_zero(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    profiles_dir = write_profile_directory(
        synthetic_profile_factory(valid_source), tmp_path / "profiles"
    )

    result = main(_args(valid_source, profiles_dir, google_snapshots_dir / "exact_match.json"))
    captured = capsys.readouterr()

    assert result == 0
    report = json.loads(captured.out)
    assert report["counts"]["unchanged"] == 1
    assert report["fatal"] is False
    assert captured.err == ""


@pytest.mark.parametrize(
    ("fixture_name", "classification"),
    [
        ("summary_changed.json", "update"),
        ("missing_google_event.json", "add"),
        ("extra_unmanaged_event.json", "unmanaged_google_event"),
    ],
)
def test_normal_cli_differences_return_one(
    fixture_name: str,
    classification: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    profiles_dir = write_profile_directory(
        synthetic_profile_factory(valid_source), tmp_path / "profiles"
    )

    result = main(_args(valid_source, profiles_dir, google_snapshots_dir / fixture_name))
    captured = capsys.readouterr()

    assert result == 1
    report = json.loads(captured.out)
    assert report["counts"][classification] >= 1
    assert report["fatal"] is False
    assert captured.err == ""


def test_duplicate_google_identity_returns_fatal_guard_exit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    profiles_dir = write_profile_directory(
        synthetic_profile_factory(valid_source), tmp_path / "profiles"
    )

    result = main(
        _args(valid_source, profiles_dir, google_snapshots_dir / "duplicate_icaluid.json")
    )
    captured = capsys.readouterr()

    assert result == 5
    report = json.loads(captured.out)
    assert report["counts"]["duplicate_google_icaluid"] == 1
    assert report["fatal"] is True
    assert report["proposed_operations"] == []


def test_invalid_source_returns_invalid_source_exit(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    source = fixtures_dir / "missing_uid.ics"
    profile = synthetic_profile_factory(
        source,
        {"first_date": "2026-07-01", "last_date": "2026-07-01"},
    )
    profiles_dir = write_profile_directory(profile, tmp_path / "profiles")

    result = main(_args(source, profiles_dir, google_snapshots_dir / "missing_google_event.json"))
    captured = capsys.readouterr()

    assert result == 3
    report = json.loads(captured.out)
    assert report["counts"]["invalid_source"] == 1
    assert str(source.resolve()) not in captured.out + captured.err


def test_malformed_snapshot_returns_snapshot_exit_without_content_or_path(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    profiles_dir = write_profile_directory(
        synthetic_profile_factory(valid_source), tmp_path / "profiles"
    )
    snapshot = google_snapshots_dir / "malformed_snapshot.json"

    result = main(_args(valid_source, profiles_dir, snapshot))
    captured = capsys.readouterr()

    assert result == 4
    combined = captured.out + captured.err
    assert "valid sanitized snapshot" in combined
    assert str(snapshot.resolve()) not in combined
    assert "target_fingerprint" not in combined
    assert "Traceback" not in combined


@pytest.mark.parametrize(
    "snapshot_value",
    ["https://example.invalid/snapshot.json", "file:///synthetic/snapshot.json"],
)
def test_cli_rejects_nonlocal_snapshot_without_echoing_value(
    snapshot_value: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    profiles_dir = write_profile_directory(
        synthetic_profile_factory(valid_source), tmp_path / "profiles"
    )

    result = main(_args(valid_source, profiles_dir, snapshot_value))
    captured = capsys.readouterr()

    assert result == 4
    combined = captured.out + captured.err
    assert snapshot_value not in combined
    assert "Traceback" not in combined


def test_cli_diff_report_is_redacted_and_writes_no_implicit_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    profiles_dir = write_profile_directory(
        synthetic_profile_factory(valid_source), tmp_path / "profiles"
    )
    output_directory = tmp_path / "output"
    output_directory.mkdir()
    monkeypatch.chdir(output_directory)

    result = main(_args(valid_source, profiles_dir, google_snapshots_dir / "summary_changed.json"))
    captured = capsys.readouterr()

    assert result == 1
    combined = captured.out + captured.err
    for sensitive in (
        "fixture-valid-001@example.invalid",
        "evtfixture001",
        "Synthetic all-day observance",
        "Changed synthetic summary",
        str(valid_source.resolve()),
    ):
        assert sensitive not in combined
    assert list(output_directory.iterdir()) == []


def test_cli_diff_writes_only_explicit_output(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    profiles_dir = write_profile_directory(
        synthetic_profile_factory(valid_source), tmp_path / "profiles"
    )
    output = tmp_path / "diff-report.json"
    args = _args(valid_source, profiles_dir, google_snapshots_dir / "exact_match.json")
    args.extend(["--output", str(output)])

    result = main(args)
    captured = capsys.readouterr()

    assert result == 0
    assert captured.out == ""
    assert json.loads(output.read_text(encoding="utf-8"))["counts"]["unchanged"] == 1
