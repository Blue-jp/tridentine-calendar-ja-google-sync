from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from pytest_mock import MockerFixture

from tridentine_calendar_google_sync import cli, google_auth
from tridentine_calendar_google_sync.google_errors import SafeGoogleError
from tridentine_calendar_google_sync.google_optional import GoogleOptionalBindings
from tridentine_calendar_google_sync.google_target import TargetConfig, calendar_id_fingerprint

pytestmark = [
    pytest.mark.google_read,
    pytest.mark.skipif(os.name != "posix", reason="requires real POSIX token I/O"),
]

_REQUEST = object()
_CALENDAR_ID = "synthetic-read-target"
_SUMMARY = "Synthetic read target"
_SCOPES = google_auth.READ_ONLY_GOOGLE_SCOPES


def _token_document(access_token: str) -> dict[str, object]:
    return {
        "type": "authorized_user",
        "token": access_token,
        "refresh_token": "synthetic-refresh-value",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": "synthetic-client-é",
        "client_secret": "synthetic-client-secret",
        "scopes": list(_SCOPES),
    }


def _saved_bytes(access_token: str) -> bytes:
    return (
        json.dumps(
            _token_document(access_token), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        + "\n"
    ).encode()


_ORIGINAL = json.dumps(_token_document("synthetic-access-A"), indent=2).encode()
_COMPETITOR = _saved_bytes("synthetic-access-competitor")


def _page(next_page_token: str | None = None) -> Mapping[str, object]:
    return {
        "items": [],
        "summary": _SUMMARY,
        "timeZone": "UTC",
        "accessRole": "owner",
        "nextPageToken": next_page_token,
    }


def _failure(status: int) -> SafeGoogleError:
    return SafeGoogleError(
        status=status,
        reason="unauthorized" if status == 401 else "backend_error",
        retryable=status == 503,
        attempt=1,
        operation="events.list",
    )


class _MockCredentials:
    scopes = _SCOPES
    granted_scopes = _SCOPES
    refresh_token = "synthetic-refresh-value"

    def __init__(self, trace: list[str]) -> None:
        self.valid = True
        self.expired = False
        self.refresh_count = 0
        self.trace = trace
        self.during_refresh: Callable[[], object] | None = None

    def refresh(self, request: object) -> None:
        assert request is _REQUEST
        self.refresh_count += 1
        self.trace.append("refresh")
        if self.during_refresh is not None:
            self.during_refresh()
        self.valid = True
        self.expired = False

    def to_json(self) -> str:
        return json.dumps(_token_document(f"synthetic-refreshed-{self.refresh_count}"))


@dataclass(repr=False)
class _FetchScenario:
    token: Path
    output: Path
    credentials: _MockCredentials
    trace: list[str]
    listed_pages: list[tuple[str | None, bytes]]
    responses: list[Mapping[str, object] | SafeGoogleError]
    preflight: Mock
    replace: Mock
    read: Mock
    build: Mock
    snapshot: Mock
    before_list: Mock

    def run(self) -> int:
        return cli.main(
            [
                "fetch-google-snapshot",
                "--online",
                "--token-file",
                str(self.token),
                "--target-config",
                "synthetic-target.toml",
                "--output",
                str(self.output),
            ]
        )

    def expire(self) -> None:
        self.credentials.valid = False
        self.credentials.expired = True


@pytest.fixture
def scenario(tmp_path: Path, mocker: MockerFixture) -> _FetchScenario:
    parent = tmp_path.resolve() / "synthetic-private"
    parent.mkdir(mode=0o700)
    token = parent / "synthetic-read-token.json"
    token.write_bytes(_ORIGINAL)
    token.chmod(0o600)
    output = parent / "synthetic-snapshot.json"
    trace: list[str] = []
    listed_pages: list[tuple[str | None, bytes]] = []
    credentials = _MockCredentials(trace)
    responses: list[Mapping[str, object] | SafeGoogleError] = [_page()]
    target = TargetConfig(
        schema_version=1,
        target_label="synthetic",
        calendar_id=_CALENDAR_ID,
        expected_target_fingerprint=calendar_id_fingerprint(_CALENDAR_ID),
        expected_summary=_SUMMARY,
        expected_access_role="owner",
        expected_time_zone="UTC",
    )

    def from_token(info: dict[str, object], *, scopes: list[str]) -> _MockCredentials:
        assert info["token"] == "synthetic-access-A"
        assert tuple(scopes) == _SCOPES
        return credentials

    def list_events(*, calendar_id: str, page_token: str | None) -> Mapping[str, object]:
        assert calendar_id == _CALENDAR_ID
        trace.append("list")
        listed_pages.append((page_token, token.read_bytes()))
        before_list(page_token)
        entry = responses.pop(0)
        if isinstance(entry, SafeGoogleError):
            raise entry
        return entry

    def build_client(current: object, *, build_service: object) -> object:
        assert current is credentials
        trace.append("build")
        return SimpleNamespace(list_events=list_events)

    actual_replace = google_auth.posix_replace.replace_posix_private_bytes

    def verify_save(path: Path, content: bytes, *, expected_content: bytes) -> None:
        actual_replace(path, content, expected_content=expected_content)
        trace.append("saved")

    bindings = GoogleOptionalBindings(
        credentials_class=SimpleNamespace(from_authorized_user_info=from_token),
        installed_app_flow_class=object,
        request_class=lambda: _REQUEST,
        build_service=Mock(),
        http_error_class=RuntimeError,
    )
    before_list = mocker.Mock()
    read = mocker.spy(google_auth, "read_private_sensitive_bytes")
    preflight = mocker.spy(google_auth.posix_replace, "preflight_posix_private_replace")
    replace = mocker.patch.object(
        google_auth.posix_replace, "replace_posix_private_bytes", side_effect=verify_save
    )
    build = mocker.patch.object(cli, "build_read_only_calendar_client", side_effect=build_client)
    snapshot = mocker.patch.object(cli, "write_google_snapshot")
    mocker.patch.object(cli, "load_target_config", return_value=target)
    mocker.patch.object(cli, "load_google_optional_bindings", return_value=bindings)
    mocker.patch.object(
        cli,
        "fetch_google_event_pages",
        partial(cli.fetch_google_event_pages, sleep=lambda _seconds: None, jitter=lambda _: 0.0),
    )
    return _FetchScenario(
        token,
        output,
        credentials,
        trace,
        listed_pages,
        responses,
        preflight,
        replace,
        read,
        build,
        snapshot,
        before_list,
    )


def test_valid_read_does_not_apply_replacement_policy(scenario: _FetchScenario) -> None:
    scenario.token.parent.chmod(0o755)
    scenario.token.chmod(0o400)

    assert scenario.run() == 0

    assert scenario.trace == ["build", "list"]
    assert scenario.credentials.refresh_count == 0
    assert scenario.token.read_bytes() == _ORIGINAL
    assert stat.S_IMODE(scenario.token.stat().st_mode) == 0o400
    scenario.preflight.assert_not_called()
    scenario.replace.assert_not_called()
    scenario.read.assert_called_once()
    scenario.snapshot.assert_called_once()


@pytest.mark.parametrize("stage", ["expiry", "401"])
@pytest.mark.parametrize("unsafe", ["parent", "file"])
def test_unsafe_destination_stops_before_oauth_refresh(
    scenario: _FetchScenario, capsys: pytest.CaptureFixture[str], stage: str, unsafe: str
) -> None:
    if unsafe == "parent":
        scenario.token.parent.chmod(0o755)
    else:
        scenario.token.chmod(0o400)
    if stage == "expiry":
        scenario.expire()
    scenario.responses[:] = [_failure(401)]

    assert scenario.run() == (4 if stage == "expiry" else 6)

    assert scenario.trace == ([] if stage == "expiry" else ["build", "list"])
    assert scenario.credentials.refresh_count == 0
    scenario.preflight.assert_called_once_with(scenario.token, expected_content=_ORIGINAL)
    scenario.replace.assert_not_called()
    scenario.snapshot.assert_not_called()
    assert scenario.token.read_bytes() == _ORIGINAL
    captured = capsys.readouterr()
    assert "before" in captured.err.lower() and "refresh" in captured.err.lower()
    assert str(scenario.token) not in captured.err


@pytest.mark.parametrize("start", ["valid", "expired"])
def test_401_uses_latest_verified_bytes_and_retries_the_same_page_after_save(
    scenario: _FetchScenario, start: str
) -> None:
    if start == "expired":
        scenario.expire()
    scenario.responses[:] = [_page("next"), _failure(401), _page()]
    first_saved = _saved_bytes("synthetic-refreshed-1")
    last_saved = _saved_bytes(f"synthetic-refreshed-{2 if start == 'expired' else 1}")

    assert scenario.run() == 0

    assert scenario.trace == (
        (["refresh", "saved"] if start == "expired" else [])
        + ["build", "list", "list", "refresh", "saved", "list"]
    )
    baselines = [_ORIGINAL, first_saved] if start == "expired" else [_ORIGINAL]
    assert [call.kwargs["expected_content"] for call in scenario.preflight.call_args_list] == (
        baselines
    )
    assert [call.kwargs["expected_content"] for call in scenario.replace.call_args_list] == (
        baselines
    )
    assert [call.args[1] for call in scenario.replace.call_args_list] == (
        [first_saved, last_saved] if start == "expired" else [last_saved]
    )
    first_page_bytes = first_saved if start == "expired" else _ORIGINAL
    assert scenario.listed_pages == [
        (None, first_page_bytes),
        ("next", first_page_bytes),
        ("next", last_saved),
    ]
    assert scenario.token.read_bytes() == last_saved
    assert stat.S_IMODE(scenario.token.stat().st_mode) == 0o600
    scenario.read.assert_called_once()
    scenario.snapshot.assert_called_once()


@pytest.mark.parametrize("stage", ["expiry", "401"])
def test_concurrent_write_during_refresh_is_kept_and_fetch_stops(
    scenario: _FetchScenario, capsys: pytest.CaptureFixture[str], stage: str
) -> None:
    if stage == "expiry":
        scenario.expire()
    scenario.responses[:] = [_failure(401)]
    scenario.credentials.during_refresh = partial(scenario.token.write_bytes, _COMPETITOR)

    assert scenario.run() == (4 if stage == "expiry" else 6)

    assert scenario.trace == (["refresh"] if stage == "expiry" else ["build", "list", "refresh"])
    assert scenario.credentials.refresh_count == 1
    assert scenario.token.read_bytes() == _COMPETITOR
    scenario.preflight.assert_called_once_with(scenario.token, expected_content=_ORIGINAL)
    scenario.replace.assert_called_once()
    scenario.snapshot.assert_not_called()
    captured = capsys.readouterr()
    assert "refresh succeeded" in captured.err.lower()
    assert str(scenario.token) not in captured.err
    assert "synthetic-access" not in captured.err


def test_401_does_not_adopt_bytes_written_between_updates(scenario: _FetchScenario) -> None:
    scenario.expire()
    scenario.responses[:] = [_failure(401)]
    scenario.before_list.side_effect = lambda _page: scenario.token.write_bytes(_COMPETITOR)

    assert scenario.run() == 6

    assert scenario.trace == ["refresh", "saved", "build", "list"]
    assert scenario.token.read_bytes() == _COMPETITOR
    assert scenario.credentials.refresh_count == 1
    assert [call.kwargs["expected_content"] for call in scenario.preflight.call_args_list] == [
        _ORIGINAL,
        _saved_bytes("synthetic-refreshed-1"),
    ]
    scenario.replace.assert_called_once()
    scenario.read.assert_called_once()
    scenario.snapshot.assert_not_called()


@pytest.mark.parametrize("budget", ["exhausted", "second-401"])
def test_401_refresh_does_not_extend_calendar_retry_budget(
    scenario: _FetchScenario, budget: str
) -> None:
    scenario.responses[:] = (
        [_failure(503) for _ in range(4)] + [_failure(401)]
        if budget == "exhausted"
        else [_failure(401), _failure(401)]
    )

    assert scenario.run() == 6

    assert len(scenario.listed_pages) == (5 if budget == "exhausted" else 2)
    assert scenario.credentials.refresh_count == 1
    assert scenario.token.read_bytes() == _saved_bytes("synthetic-refreshed-1")
    scenario.replace.assert_called_once()
    scenario.snapshot.assert_not_called()
