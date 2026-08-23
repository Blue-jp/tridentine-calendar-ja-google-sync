from __future__ import annotations

from pathlib import Path

import pytest
from conftest import write_profile_directory
from phase4b_helpers import build_add_apply_bundle
from phase5a_helpers import make_test_target_config
from test_test_write_run_spec_phase5a import _add_run_spec

import tridentine_calendar_google_sync.cli as cli
from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.google_sanitize import render_sanitized_snapshot
from tridentine_calendar_google_sync.plan_report import render_plan_json_report
from tridentine_calendar_google_sync.test_write_run_spec_io import load_test_write_run_spec

pytestmark = pytest.mark.google_test_write

COMMANDS = (
    "authorize-test-google-write",
    "build-test-write-run-spec",
    "inspect-test-write-run-spec",
    "run-test-calendar-write",
)


@pytest.mark.parametrize("command", COMMANDS)
def test_each_phase5a_command_help_states_every_write_safety_boundary(
    command: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = cli.build_parser()

    with pytest.raises(SystemExit) as captured:
        parser.parse_args([command, "--help"])

    assert captured.value.code == 0
    help_text = " ".join(capsys.readouterr().out.casefold().split())
    for required in (
        "test calendar only",
        "production calendar targets are refused",
        "only run-test-calendar-write can perform a google calendar write",
        "exact approval phrase",
        "exactly one add or update operation",
        "delete is not implemented",
        "events.import",
        "events.patch",
        "exact if-match etag",
        "separate from the production read-only token",
        "no batch",
        "no automatic mutation retry",
    ):
        assert required in help_text


def test_phase5a_parser_has_exact_commands_and_no_generic_mutation_alias() -> None:
    parser = cli.build_parser()
    help_text = parser.format_help()
    for command in COMMANDS:
        assert command in help_text
    for alias in ("apply", "sync", "execute"):
        assert f"{{{alias}}}" not in help_text


def test_phase5a_command_contract_options_parse_exactly() -> None:
    parser = cli.build_parser()
    authorize = parser.parse_args(
        [
            "authorize-test-google-write",
            "--online",
            "--credentials-file",
            "fixture-credentials.json",
            "--token-file",
            "fixture-test-token.json",
            "--production-read-token-file",
            "fixture-read-token.json",
            "--target-config",
            "fixture-target.toml",
        ]
    )
    build = parser.parse_args(
        [
            "build-test-write-run-spec",
            "--source",
            "fixture.ics",
            "--profile",
            "fixture-profile",
            "--google-snapshot",
            "fixture-snapshot.json",
            "--plan",
            "fixture-plan.json",
            "--target-config",
            "fixture-target.toml",
            "--output",
            "fixture-run-spec.json",
        ]
    )
    inspect = parser.parse_args(
        ["inspect-test-write-run-spec", "--run-spec", "fixture-run-spec.json"]
    )
    run = parser.parse_args(
        [
            "run-test-calendar-write",
            "--online",
            "--run-spec",
            "fixture-run-spec.json",
            "--plan",
            "fixture-plan.json",
            "--target-config",
            "fixture-target.toml",
            "--token-file",
            "fixture-test-token.json",
            "--production-read-token-file",
            "fixture-read-token.json",
            "--confirmation",
            "fixture-exact-confirmation",
            "--journal-output",
            "fixture-journal.json",
            "--report-output",
            "fixture-report.json",
        ]
    )

    assert authorize.online is True
    assert build.trusted_baseline is None
    assert inspect.report_format == "text"
    assert run.online is True
    assert run.report_format == "text"


@pytest.mark.parametrize(
    ("command", "args"),
    (
        (
            "authorize-test-google-write",
            (
                "--credentials-file",
                "never-read.json",
                "--token-file",
                "never-created.json",
                "--production-read-token-file",
                "never-read-production.json",
                "--target-config",
                "never-read.toml",
            ),
        ),
        (
            "run-test-calendar-write",
            (
                "--run-spec",
                "never-read-run.json",
                "--plan",
                "never-read-plan.json",
                "--target-config",
                "never-read.toml",
                "--token-file",
                "never-read-token.json",
                "--production-read-token-file",
                "never-read-production.json",
                "--confirmation",
                "never-used",
                "--journal-output",
                "never-created-journal.json",
                "--report-output",
                "never-created-report.json",
            ),
        ),
    ),
)
def test_online_commands_without_online_fail_before_oauth_api_or_output(
    command: str,
    args: tuple[str, ...],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = 0

    def forbidden(*_args: object, **_kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("online boundary must remain untouched")

    for name in (
        "authorize_test_google_write",
        "load_test_write_credentials",
        "build_test_calendar_write_client",
        "run_test_calendar_write",
    ):
        monkeypatch.setattr(cli, name, forbidden)
    resolved_args = tuple(
        str(tmp_path / value) if value.startswith("never-") else value for value in args
    )

    result = cli.main([command, *resolved_args])
    captured = capsys.readouterr()

    assert result == cli.EXIT_CLI_ERROR
    assert calls == 0
    assert not any(tmp_path.iterdir())
    assert str(tmp_path) not in captured.out + captured.err


def test_build_and_inspect_run_spec_cli_are_offline_and_redacted(
    tmp_path: Path,
    synthetic_profile_factory: object,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import tridentine_calendar_google_sync.test_write_run_spec as run_spec_module

    bundle = build_add_apply_bundle(tmp_path, synthetic_profile_factory)
    source_path = tmp_path / "current-102-False.ics"
    assert source_path.is_file()
    profiles_dir = write_profile_directory(bundle.profile, tmp_path / "profiles")
    snapshot_path = tmp_path / "fixture-snapshot.json"
    snapshot_path.write_bytes(render_sanitized_snapshot(bundle.snapshot))
    plan_path = tmp_path / "fixture.sync-plan.json"
    plan_path.write_bytes(render_plan_json_report(bundle.plan).encode("utf-8"))
    run_spec_path = tmp_path / "fixture.test-write-run-spec.json"
    target_config = make_test_target_config().model_copy(
        update={"expected_target_fingerprint": bundle.snapshot.target_fingerprint}
    )
    reference = f"T-{bundle.snapshot.target_fingerprint[:12]}"
    monkeypatch.setattr(cli, "load_test_write_target_config", lambda _path: target_config)
    monkeypatch.setattr(
        run_spec_module,
        "validate_test_write_target_config",
        lambda _target: bundle.snapshot.target_fingerprint,
    )
    monkeypatch.setattr(
        run_spec_module,
        "test_write_target_reference",
        lambda _target: reference,
    )

    build_result = cli.main(
        [
            "build-test-write-run-spec",
            "--source",
            str(source_path),
            "--profile",
            bundle.profile.profile_id,
            "--profiles-dir",
            str(profiles_dir),
            "--google-snapshot",
            str(snapshot_path),
            "--plan",
            str(plan_path),
            "--target-config",
            str(tmp_path / "synthetic-target.toml"),
            "--output",
            str(run_spec_path),
        ]
    )
    build_output = capsys.readouterr()
    assert build_result == cli.EXIT_DIFFERENCES, build_output.err
    assert run_spec_path.is_file()
    inspect_result = cli.main(
        [
            "inspect-test-write-run-spec",
            "--run-spec",
            str(run_spec_path),
            "--format",
            "json",
        ]
    )
    inspect_output = capsys.readouterr()

    run_spec = load_test_write_run_spec(run_spec_path)
    assert inspect_result == cli.EXIT_VALID
    assert run_spec.operation_count == 1
    assert (run_spec.add_count, run_spec.update_count) == (1, 0)
    combined = build_output.out + build_output.err + inspect_output.out + inspect_output.err
    for sensitive in (
        run_spec.operation.desired_state.ical_uid,
        run_spec.operation.desired_state.summary,
        run_spec.operation.desired_state.description,
        run_spec.target_fingerprint,
        str(source_path),
        str(snapshot_path),
        str(plan_path),
        str(run_spec_path),
    ):
        assert sensitive not in combined


def test_online_run_production_reference_stops_before_credentials_client_or_outputs(
    tmp_path: Path,
    synthetic_profile_factory: object,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    spec = _add_run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    target = make_test_target_config().model_copy(
        update={"expected_target_fingerprint": spec.target_fingerprint}
    )
    online_calls = 0

    def forbidden(*_args: object, **_kwargs: object) -> object:
        nonlocal online_calls
        online_calls += 1
        raise AssertionError("credentials or client must not be reached")

    monkeypatch.setattr(cli, "load_test_write_target_config", lambda _path: target)
    monkeypatch.setattr(cli, "load_test_write_run_spec", lambda _path: spec)
    monkeypatch.setattr(cli, "load_sync_plan_report", lambda _path: object())
    monkeypatch.setattr(
        cli, "test_write_target_reference", lambda _target: PRODUCTION_TARGET_REFERENCE
    )
    monkeypatch.setattr(cli, "load_test_write_credentials", forbidden)
    monkeypatch.setattr(cli, "build_test_calendar_write_client", forbidden)
    journal_path = tmp_path / "must-not-create-journal.json"
    report_path = tmp_path / "must-not-create-report.json"

    result = cli.main(
        [
            "run-test-calendar-write",
            "--online",
            "--run-spec",
            str(tmp_path / "not-read-run-spec.json"),
            "--plan",
            str(tmp_path / "not-read-plan.json"),
            "--target-config",
            str(tmp_path / "not-read-target.toml"),
            "--token-file",
            str(tmp_path / "not-read-write-token.json"),
            "--production-read-token-file",
            str(tmp_path / "not-read-production-token.json"),
            "--confirmation",
            "not-used",
            "--journal-output",
            str(journal_path),
            "--report-output",
            str(report_path),
        ]
    )
    captured = capsys.readouterr()

    assert result == cli.EXIT_FATAL_GUARD
    assert online_calls == 0
    assert not journal_path.exists()
    assert not report_path.exists()
    assert str(tmp_path) not in captured.out + captured.err
