from __future__ import annotations

import argparse
import socket

import pytest

from tridentine_calendar_google_sync.cli import EXIT_FATAL_GUARD, build_parser, main

pytestmark = pytest.mark.google_production_write

AUTH_COMMAND = "authorize-production-write-token"
REHEARSAL_COMMAND = "rehearse-production-write-token-readonly"


def _subparsers() -> argparse._SubParsersAction[argparse.ArgumentParser]:
    parser = build_parser()
    return next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )


def test_phase6d0_cli_inventory_adds_only_two_explicit_commands() -> None:
    action = _subparsers()

    assert len(action.choices) == 31
    assert {AUTH_COMMAND, REHEARSAL_COMMAND} <= set(action.choices)
    assert not {
        "authorize-production",
        "rehearse-production",
        "execute-production",
        "patch-production",
        "apply",
        "sync",
        "execute",
    } & set(action.choices)


@pytest.mark.parametrize(
    ("command", "challenge"),
    (
        (AUTH_COMMAND, "AUTHORIZE PRODUCTION WRITE TOKEN ONLY T-<12>"),
        (
            REHEARSAL_COMMAND,
            "READ PRODUCTION CALENDAR USING DEDICATED WRITE TOKEN T-<12>",
        ),
    ),
)
def test_phase6d0_cli_help_is_explicitly_live_disabled(
    command: str,
    challenge: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = build_parser()
    with pytest.raises(SystemExit) as captured:
        parser.parse_args([command, "--help"])

    assert captured.value.code == 0
    output = capsys.readouterr().out
    assert challenge in output
    assert "hard-off" in output
    assert "--online" not in output
    assert "--calendar-id" not in output


def test_authorization_cli_shape_requires_separate_explicit_paths_and_confirmation() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            AUTH_COMMAND,
            "--credentials-file",
            "credentials.json",
            "--token-file",
            "production-write-token.json",
            "--production-read-token-file",
            "production-read-token.json",
            "--test-write-token-file",
            "test-write-token.json",
            "--token-generation-state",
            "production-write-token-generation.json",
            "--target-config",
            "production-write-target.toml",
            "--confirmation",
            "AUTHORIZE PRODUCTION WRITE TOKEN ONLY T-123456789abc",
        ]
    )

    assert args.command == AUTH_COMMAND
    assert (
        len(
            {
                args.credentials_file,
                args.token_file,
                args.production_read_token_file,
                args.test_write_token_file,
                args.token_generation_state,
            }
        )
        == 5
    )
    assert not hasattr(args, "online")
    assert not hasattr(args, "calendar_id")


def test_rehearsal_cli_shape_requires_all_future_operational_bindings() -> None:
    parser = build_parser()
    args = parser.parse_args(
        [
            REHEARSAL_COMMAND,
            "--target-config",
            "production-write-target.toml",
            "--token-file",
            "production-write-token.json",
            "--production-read-token-file",
            "production-read-token.json",
            "--test-write-token-file",
            "test-write-token.json",
            "--token-generation-state",
            "production-write-token-generation.json",
            "--manifest",
            "manifest.json",
            "--source",
            "source.ics",
            "--profile",
            "accepted-profile",
            "--profiles-dir",
            "profiles",
            "--trusted-baseline",
            "trusted-baseline.json",
            "--output-directory",
            "rehearsal-output",
            "--confirmation",
            "READ PRODUCTION CALENDAR USING DEDICATED WRITE TOKEN T-123456789abc",
        ]
    )

    assert args.command == REHEARSAL_COMMAND
    assert not hasattr(args, "online")
    assert not hasattr(args, "calendar_id")


def test_authorization_command_stops_before_reading_inputs_or_network(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_socket(*args: object, **kwargs: object) -> socket.socket:
        raise AssertionError("Phase 6D.0 authorization attempted real network")

    monkeypatch.setattr(socket, "socket", fail_socket)
    private_values = (
        "private-client-secret-value",
        "private-access-token-value",
        "private-calendar-id@example.invalid",
    )
    result = main(
        [
            AUTH_COMMAND,
            "--credentials-file",
            private_values[0],
            "--token-file",
            private_values[1],
            "--production-read-token-file",
            "never-read-production-read-token.json",
            "--test-write-token-file",
            "never-read-test-write-token.json",
            "--token-generation-state",
            "never-read-generation.json",
            "--target-config",
            private_values[2],
            "--confirmation",
            "wrong challenge that must not be echoed",
        ]
    )

    assert result == EXIT_FATAL_GUARD
    output = capsys.readouterr()
    rendered = output.out + output.err
    assert "production_live_oauth_not_available_in_phase_6d0" in rendered
    assert all(value not in rendered for value in private_values)


def test_rehearsal_command_stops_before_refresh_inputs_or_calendar(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail_socket(*args: object, **kwargs: object) -> socket.socket:
        raise AssertionError("Phase 6D.0 rehearsal attempted real network")

    monkeypatch.setattr(socket, "socket", fail_socket)
    private_values = (
        "private-production-token-value",
        "private-calendar-id@example.invalid",
        "private-event-description",
    )
    result = main(
        [
            REHEARSAL_COMMAND,
            "--target-config",
            private_values[1],
            "--token-file",
            private_values[0],
            "--production-read-token-file",
            "never-read-production-read-token.json",
            "--test-write-token-file",
            "never-read-test-write-token.json",
            "--token-generation-state",
            "never-read-generation.json",
            "--manifest",
            "never-read-manifest.json",
            "--source",
            private_values[2],
            "--profile",
            "never-read-profile",
            "--profiles-dir",
            "never-read-profiles",
            "--trusted-baseline",
            "never-read-baseline.json",
            "--output-directory",
            "never-created-output",
            "--confirmation",
            "wrong challenge that must not be echoed",
        ]
    )

    assert result == EXIT_FATAL_GUARD
    output = capsys.readouterr()
    rendered = output.out + output.err
    assert "production_live_rehearsal_not_available_in_phase_6d0" in rendered
    assert all(value not in rendered for value in private_values)
