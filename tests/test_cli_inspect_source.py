from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from conftest import write_profile_directory

from tridentine_calendar_google_sync.cli import main
from tridentine_calendar_google_sync.models import AcceptedSourceProfile

ProfileFactory = Callable[..., AcceptedSourceProfile]


def _valid_cli_args(
    source: Path,
    profiles_dir: Path,
    *,
    output_format: str = "text",
) -> list[str]:
    return [
        "inspect-source",
        "--source",
        str(source),
        "--profile",
        "synthetic-test-profile",
        "--profiles-dir",
        str(profiles_dir),
        "--format",
        output_format,
    ]


def test_inspect_source_text_is_offline_and_non_destructive(
    tmp_path: Path,
    capsys: object,
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    profile = synthetic_profile_factory(valid_source)
    profiles_dir = write_profile_directory(profile, tmp_path / "profiles")
    original_bytes = valid_source.read_bytes()

    result = main(_valid_cli_args(valid_source, profiles_dir))
    captured = capsys.readouterr()  # type: ignore[attr-defined]

    assert result == 0
    assert "mode: offline" in captured.out
    assert "source valid: yes" in captured.out
    assert captured.err == ""
    assert valid_source.read_bytes() == original_bytes


def test_inspect_source_json_writes_no_implicit_report_file(
    tmp_path: Path,
    monkeypatch: object,
    capsys: object,
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    profile = synthetic_profile_factory(valid_source)
    profiles_dir = write_profile_directory(profile, tmp_path / "profiles")
    output_directory = tmp_path / "empty-output"
    output_directory.mkdir()
    monkeypatch.chdir(output_directory)  # type: ignore[attr-defined]

    result = main(_valid_cli_args(valid_source, profiles_dir, output_format="json"))
    captured = capsys.readouterr()  # type: ignore[attr-defined]

    assert result == 0
    report = json.loads(captured.out)
    assert report["mode"] == "offline"
    assert report["source_valid"] is True
    assert list(output_directory.iterdir()) == []


def test_inspect_source_explicit_output_is_written_only_to_requested_path(
    tmp_path: Path,
    capsys: object,
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    profile = synthetic_profile_factory(valid_source)
    profiles_dir = write_profile_directory(profile, tmp_path / "profiles")
    output = tmp_path / "requested-report.json"
    args = _valid_cli_args(valid_source, profiles_dir, output_format="json")
    args.extend(["--output", str(output)])

    result = main(args)
    captured = capsys.readouterr()  # type: ignore[attr-defined]

    assert result == 0
    assert captured.out == ""
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["source_valid"] is True


def test_subcommand_is_required_and_help_is_safe(capsys: object) -> None:
    result = main([])
    captured = capsys.readouterr()  # type: ignore[attr-defined]
    combined = captured.out + captured.err

    assert result == 2
    assert "inspect-source" in combined
    assert "validate-source" in combined
    assert "Traceback" not in combined
