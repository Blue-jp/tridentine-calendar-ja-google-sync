from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import write_profile_directory

from tridentine_calendar_google_sync.cli import main
from tridentine_calendar_google_sync.models import AcceptedSourceProfile

ProfileFactory = Callable[..., AcceptedSourceProfile]


def _validate_args(source: str | Path, profiles_dir: Path) -> list[str]:
    return [
        "validate-source",
        "--source",
        str(source),
        "--profile",
        "synthetic-test-profile",
        "--profiles-dir",
        str(profiles_dir),
        "--format",
        "json",
        "--redact-content",
    ]


def test_validate_source_returns_zero_for_matching_profile(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    profile = synthetic_profile_factory(valid_source)
    profiles_dir = write_profile_directory(profile, tmp_path / "profiles")

    result = main(_validate_args(valid_source, profiles_dir))
    captured = capsys.readouterr()

    assert result == 0
    assert json.loads(captured.out)["source_valid"] is True
    assert captured.err == ""


def test_validate_source_sha_mismatch_returns_fatal_guard_without_traceback(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    profile = synthetic_profile_factory(valid_source, sha256_override="f" * 64)
    profiles_dir = write_profile_directory(profile, tmp_path / "profiles")

    result = main(_validate_args(valid_source, profiles_dir))
    captured = capsys.readouterr()

    assert result == 5
    combined = captured.out + captured.err
    assert "source_sha256_mismatch" in combined
    assert "Traceback" not in combined
    assert str(valid_source.resolve()) not in combined


def test_validate_source_malformed_content_is_not_echoed(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = fixtures_dir / "malformed.ics"
    profile = synthetic_profile_factory(source)
    profiles_dir = write_profile_directory(profile, tmp_path / "profiles")

    result = main(_validate_args(source, profiles_dir))
    captured = capsys.readouterr()

    assert result == 3
    combined = captured.out + captured.err
    assert "malformed_ics" in combined
    assert "This component is intentionally not closed" not in combined
    assert "fixture-malformed-001@example.invalid" not in combined
    assert str(source.resolve()) not in combined
    assert "Traceback" not in combined


def test_validate_source_missing_required_property_returns_invalid_source(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = fixtures_dir / "missing_uid.ics"
    profile = synthetic_profile_factory(
        source,
        {"first_date": "2026-07-01", "last_date": "2026-07-01"},
    )
    profiles_dir = write_profile_directory(profile, tmp_path / "profiles")

    result = main(_validate_args(source, profiles_dir))
    captured = capsys.readouterr()

    assert result == 5
    combined = captured.out + captured.err
    assert "missing_uid" in combined
    assert str(source.resolve()) not in combined
    assert "Traceback" not in combined


@pytest.mark.parametrize(
    "source_value",
    ["https://example.invalid/calendar.ics", "file:///synthetic/calendar.ics"],
)
def test_validate_source_rejects_url_inputs_safely(
    source_value: str,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    profile = synthetic_profile_factory(valid_source)
    profiles_dir = write_profile_directory(profile, tmp_path / "profiles")

    result = main(_validate_args(source_value, profiles_dir))
    captured = capsys.readouterr()

    assert result in {2, 3}
    combined = captured.out + captured.err
    assert source_value not in combined
    assert "Traceback" not in combined
