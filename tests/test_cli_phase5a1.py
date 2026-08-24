from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
from phase5a1_helpers import (
    SequencePrewriteClient,
    make_prewrite_target_config,
    prewrite_event,
    prewrite_page,
)

import tridentine_calendar_google_sync.cli as cli
from tridentine_calendar_google_sync.google_optional import GoogleOptionalDependencyError

pytestmark = pytest.mark.google_test_write

COMMAND = "inspect-test-calendar-prewrite"
REQUIRED_OPTIONS = (
    "--target-config",
    "--token-file",
    "--production-read-token-file",
    "--snapshot-output",
    "--human-report-output",
    "--json-report-output",
)


def _arguments(tmp_path: Path, *, online: bool = True) -> list[str]:
    values = [
        COMMAND,
        "--target-config",
        str(tmp_path / "synthetic-target.toml"),
        "--token-file",
        str(tmp_path / "synthetic-write-token.json"),
        "--production-read-token-file",
        str(tmp_path / "synthetic-production-read-token.json"),
        "--snapshot-output",
        str(tmp_path / "snapshot.test-calendar-prewrite-snapshot.json"),
        "--human-report-output",
        str(tmp_path / "human.test-calendar-prewrite-report.txt"),
        "--json-report-output",
        str(tmp_path / "report.test-calendar-prewrite-report.json"),
    ]
    if online:
        values.insert(1, "--online")
    return values


def _install_mock_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    client: SequencePrewriteClient,
) -> dict[str, int]:
    calls = {"bindings": 0, "credentials": 0, "client": 0}
    target = make_prewrite_target_config()

    monkeypatch.setattr(cli, "load_test_write_target_config", lambda _path: target)

    def bindings() -> object:
        calls["bindings"] += 1
        return SimpleNamespace(build_service=object())

    def credentials(*_args: object, **_kwargs: object) -> object:
        calls["credentials"] += 1
        return object()

    def build(*_args: object, **_kwargs: object) -> SequencePrewriteClient:
        calls["client"] += 1
        return client

    monkeypatch.setattr(cli, "load_google_optional_bindings", bindings)
    monkeypatch.setattr(cli, "load_test_write_credentials", credentials)
    monkeypatch.setattr(cli, "build_test_calendar_prewrite_list_client", build)
    return calls


def test_help_states_every_read_only_prewrite_safety_boundary(
    capsys: pytest.CaptureFixture[str],
) -> None:
    parser = cli.build_parser()

    with pytest.raises(SystemExit) as captured:
        parser.parse_args([COMMAND, "--help"])

    assert captured.value.code == 0
    help_text = " ".join(capsys.readouterr().out.casefold().split())
    for required in (
        "test calendar read-only prewrite inspection",
        "separate test write token",
        "events.list only",
        "never calls events.get, events.import, or events.patch",
        "does not write to google calendar",
        "delete events",
        "clear a calendar",
        "existing calendar empty",
        "production and primary calendars are refused",
        "empty calendar is write-ready",
        "nonempty calendar requires manual review",
        "outside every repository",
    ):
        assert required in help_text


def test_parser_contract_requires_online_target_tokens_and_three_outputs() -> None:
    parsed = cli.build_parser().parse_args(
        [
            COMMAND,
            "--online",
            "--target-config",
            "target.toml",
            "--token-file",
            "write-token.json",
            "--production-read-token-file",
            "read-token.json",
            "--snapshot-output",
            "snapshot.json",
            "--human-report-output",
            "report.txt",
            "--json-report-output",
            "report.json",
        ]
    )

    assert parsed.online is True
    assert parsed.command == COMMAND
    assert not hasattr(parsed, "confirmation")
    assert not hasattr(parsed, "run_spec")


@pytest.mark.parametrize("missing_option", REQUIRED_OPTIONS)
def test_each_required_option_is_rejected_without_traceback(
    tmp_path: Path,
    missing_option: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    arguments = _arguments(tmp_path)
    index = arguments.index(missing_option)
    del arguments[index : index + 2]

    result = cli.main(arguments)
    output = capsys.readouterr()

    assert result == cli.EXIT_CLI_ERROR
    assert "traceback" not in (output.out + output.err).casefold()
    assert not any(tmp_path.iterdir())


def test_online_is_required_before_target_token_client_or_outputs(
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
        "load_test_write_target_config",
        "load_test_write_credentials",
        "load_google_optional_bindings",
        "build_test_calendar_prewrite_list_client",
        "inspect_test_calendar_prewrite",
        "write_test_calendar_prewrite_outputs",
    ):
        monkeypatch.setattr(cli, name, forbidden)

    result = cli.main(_arguments(tmp_path, online=False))
    output = capsys.readouterr()

    assert result == cli.EXIT_CLI_ERROR
    assert calls == 0
    assert not any(tmp_path.iterdir())
    assert str(tmp_path) not in output.out + output.err


def test_empty_calendar_mock_cli_writes_three_outputs_and_returns_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    client = SequencePrewriteClient([prewrite_page()])
    calls = _install_mock_boundaries(monkeypatch, client)
    arguments = _arguments(tmp_path)

    result = cli.main(arguments)
    output = capsys.readouterr()

    assert result == cli.EXIT_VALID, output.err
    assert calls == {"bindings": 1, "credentials": 1, "client": 1}
    assert client.calls == [(make_prewrite_target_config().calendar_id, None)]
    assert all(
        Path(arguments[arguments.index(option) + 1]).is_file() for option in REQUIRED_OPTIONS[-3:]
    )
    assert "ready=yes" in output.out
    assert "events=0" in output.out
    assert "Google-writes=0" in output.out
    assert "event-changes=0" in output.out
    assert str(tmp_path) not in output.out + output.err


def test_nonempty_calendar_mock_cli_writes_safe_outputs_and_returns_fatal_guard(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    event = prewrite_event()
    client = SequencePrewriteClient([prewrite_page([event])])
    _install_mock_boundaries(monkeypatch, client)
    arguments = _arguments(tmp_path)

    result = cli.main(arguments)
    output = capsys.readouterr()

    assert result == cli.EXIT_FATAL_GUARD
    assert all(
        Path(arguments[arguments.index(option) + 1]).is_file() for option in REQUIRED_OPTIONS[-3:]
    )
    assert "ready=no" in output.out
    assert "events=1" in output.out
    for value in (event["iCalUID"], event["id"], event["summary"], event["description"]):
        assert str(value) not in output.out + output.err


def test_production_target_fails_before_optional_dependency_token_client_and_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = make_prewrite_target_config().model_copy(update={"target_environment": "production"})
    calls = 0

    def forbidden(*_args: object, **_kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("credential or client boundary must not be reached")

    monkeypatch.setattr(cli, "load_test_write_target_config", lambda _path: target)
    for name in (
        "load_google_optional_bindings",
        "load_test_write_credentials",
        "build_test_calendar_prewrite_list_client",
    ):
        monkeypatch.setattr(cli, name, forbidden)

    result = cli.main(_arguments(tmp_path))
    output = capsys.readouterr()

    assert result == cli.EXIT_FATAL_GUARD
    assert calls == 0
    assert not any(tmp_path.iterdir())
    assert str(tmp_path) not in output.out + output.err


def test_existing_output_fails_before_credentials_or_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    arguments = _arguments(tmp_path)
    snapshot_path = Path(arguments[arguments.index("--snapshot-output") + 1])
    snapshot_path.write_text("existing", encoding="utf-8")
    calls = _install_mock_boundaries(monkeypatch, SequencePrewriteClient([prewrite_page()]))

    result = cli.main(arguments)

    assert result == cli.EXIT_INVALID_SNAPSHOT
    assert calls == {"bindings": 0, "credentials": 0, "client": 0}


def test_missing_google_extra_has_safe_test_write_install_guidance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(
        cli,
        "load_test_write_target_config",
        lambda _path: make_prewrite_target_config(),
    )

    def unavailable() -> object:
        raise GoogleOptionalDependencyError

    monkeypatch.setattr(cli, "load_google_optional_bindings", unavailable)

    result = cli.main(_arguments(tmp_path))
    output = capsys.readouterr()
    rendered = output.out + output.err

    assert result != cli.EXIT_VALID
    assert "google-test-write" in rendered
    assert "traceback" not in rendered.casefold()
    assert str(tmp_path) not in rendered
    assert not any(tmp_path.iterdir())


def test_generic_mutation_aliases_remain_absent() -> None:
    help_text = cli.build_parser().format_help()
    for alias in ("apply", "sync", "execute"):
        assert f"{{{alias}}}" not in help_text
