from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

import tridentine_calendar_google_sync.cli as cli
import tridentine_calendar_google_sync.google_auth as auth_module
from tridentine_calendar_google_sync.google_errors import SafeGoogleError
from tridentine_calendar_google_sync.google_fetch import FetchedGooglePages
from tridentine_calendar_google_sync.google_optional import GoogleOptionalDependencyError
from tridentine_calendar_google_sync.google_target import (
    TargetConfig,
    TargetConfigError,
    TargetIdentityError,
    calendar_id_fingerprint,
)
from tridentine_calendar_google_sync.sensitive_paths import atomic_write_private_json
from tridentine_calendar_google_sync.snapshot_io import SnapshotWriteError

pytestmark = pytest.mark.google_read


def _authorize_args(*, online: bool = False, overwrite: bool = False) -> list[str]:
    args = [
        "authorize-google-readonly",
        "--credentials-file",
        "fixture-client.json",
        "--token-file",
        "fixture-token.json",
    ]
    if online:
        args.append("--online")
    if overwrite:
        args.append("--overwrite-token")
    return args


def _fetch_args(*, online: bool = False) -> list[str]:
    args = [
        "fetch-google-snapshot",
        "--token-file",
        "fixture-token.json",
        "--target-config",
        "fixture-target.toml",
        "--output",
        "fixture-snapshot.json",
    ]
    if online:
        args.append("--online")
    return args


def test_google_read_command_help_and_primary_option_names_are_registered() -> None:
    parser = cli.build_parser()

    authorize = parser.parse_args(_authorize_args())
    fetch = parser.parse_args(_fetch_args())

    assert authorize.command == "authorize-google-readonly"
    assert authorize.credentials_file == "fixture-client.json"
    assert authorize.token_file == "fixture-token.json"
    assert authorize.overwrite_token is False
    assert fetch.command == "fetch-google-snapshot"
    assert fetch.token_file == "fixture-token.json"
    assert fetch.target_config == "fixture-target.toml"
    assert fetch.output == "fixture-snapshot.json"


@pytest.mark.parametrize(
    ("args", "boundary_name"),
    [
        (_authorize_args(), "authorize_google_readonly"),
        (_authorize_args(overwrite=True), "_authorize_google_readonly"),
        (_fetch_args(), "load_target_config"),
    ],
)
def test_online_flag_is_required_before_any_oauth_or_api_boundary(
    args: list[str],
    boundary_name: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    calls = 0

    def forbidden_call(*_args: object, **_kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("online boundary must not run")

    monkeypatch.setattr(cli, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(cli, boundary_name, forbidden_call)

    result = cli.main(args)
    captured = capsys.readouterr()

    assert result == 2
    assert calls == 0
    assert "explicit --online is required" in captured.err
    assert "Traceback" not in captured.out + captured.err


@pytest.mark.parametrize("overwrite", [False, True])
@pytest.mark.parametrize("platform", ["posix", "nt"])
def test_authorize_passes_explicit_overwrite_policy_to_mock_boundary(
    overwrite: bool,
    platform: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    authorize = Mock()
    authorize_with_replace = Mock()
    monkeypatch.setattr(cli, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(cli, "authorize_google_readonly", authorize)
    monkeypatch.setattr(cli, "_authorize_google_readonly", authorize_with_replace)

    result = cli.main(_authorize_args(online=True, overwrite=overwrite))
    captured = capsys.readouterr()

    assert result == 0
    if platform == "posix" and overwrite:
        authorize_with_replace.assert_called_once_with(
            "fixture-client.json", "fixture-token.json", overwrite=True, replace_existing=True
        )
        authorize.assert_not_called()
    else:
        authorize.assert_called_once_with(
            "fixture-client.json", "fixture-token.json", overwrite=overwrite
        )
        authorize_with_replace.assert_not_called()
    assert "scope=calendar.events.owned.readonly" in captured.out
    assert "fixture-client.json" not in captured.out + captured.err
    assert "fixture-token.json" not in captured.out + captured.err


def _mock_readonly_oauth(
    monkeypatch: pytest.MonkeyPatch,
    client_path: Path,
    events: list[str],
    *,
    failure: BaseException | None = None,
) -> dict[str, object]:
    client_id = "synthetic-client-id"
    client_secret = "synthetic-client-secret"
    token_uri = "https://oauth2.googleapis.com/token"
    scopes = auth_module.READ_ONLY_GOOGLE_SCOPES
    atomic_write_private_json(
        client_path,
        {
            "installed": {
                "client_id": client_id,
                "client_secret": client_secret,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": token_uri,
                "redirect_uris": ["http://localhost"],
            }
        },
    )
    document: dict[str, object] = {
        "type": "authorized_user",
        "token": "synthetic-new-auth-token",
        "refresh_token": "synthetic-refresh-token",
        "token_uri": token_uri,
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": list(scopes),
    }
    credentials = SimpleNamespace(
        scopes=scopes, granted_scopes=scopes, to_json=lambda: json.dumps(document)
    )

    def run_local_server(**_kwargs: object) -> object:
        events.append("authorize")
        if failure is not None:
            raise failure
        return credentials

    def from_client_config(_config: object, *, scopes: list[str]) -> object:
        events.append("construct")
        assert tuple(scopes) == auth_module.READ_ONLY_GOOGLE_SCOPES
        return SimpleNamespace(run_local_server=run_local_server)

    bindings = SimpleNamespace(
        installed_app_flow_class=SimpleNamespace(from_client_config=from_client_config)
    )
    monkeypatch.setattr(auth_module, "load_google_optional_bindings", lambda: bindings)
    return document


def _authorize_overwrite_args(client_path: Path, token_path: Path) -> list[str]:
    args = _authorize_args(online=True, overwrite=True)
    args[args.index("--credentials-file") + 1] = str(client_path)
    args[args.index("--token-file") + 1] = str(token_path)
    return args


@pytest.mark.parametrize(
    ("phase", "publication_possible", "expected_exit", "outcome"),
    [
        pytest.param("preflight", False, 4, "before", id="preflight"),
        pytest.param("oauth", None, 6, "authorization failed", id="oauth-failure"),
        pytest.param("cancel", None, 6, "authorization was cancelled", id="oauth-cancel"),
        pytest.param("replace", False, 4, "did not attempt", id="unattempted"),
        pytest.param("replace", True, 4, "this call attempted", id="attempted"),
        pytest.param("replace", None, 4, "unknown", id="unknown"),
    ],
)
def test_posix_cli_authorize_reports_safe_overwrite_outcome_and_never_falls_back(
    phase: str,
    publication_possible: bool | None,
    expected_exit: int,
    outcome: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    client_path, token_path = tmp_path / "client.json", tmp_path / "token.json"
    atomic_write_private_json(token_path, {"fixture": "synthetic-old-auth-token"})
    original = token_path.read_bytes()
    raw_error = f"synthetic backend details: {token_path} synthetic-new-auth-token"
    events: list[str] = []
    failure: BaseException | None = None
    if phase == "oauth":
        failure = RuntimeError(raw_error)
    elif phase == "cancel":
        failure = KeyboardInterrupt(raw_error)
    document = _mock_readonly_oauth(monkeypatch, client_path, events, failure=failure)

    def preflight(path: Path, *, expected_content: bytes) -> None:
        events.append("preflight")
        assert path == token_path
        assert expected_content == original
        if phase == "preflight":
            error = auth_module.posix_replace.PosixPrivateReplaceError("synthetic_preflight")
            error.args = (raw_error,)
            raise error

    def replace(path: Path, content: bytes, *, expected_content: bytes) -> None:
        events.append("replace")
        assert path == token_path
        assert expected_content == original
        assert json.loads(content) == document
        if publication_possible is None:
            raise RuntimeError(raw_error)
        error = auth_module.posix_replace.PosixPrivateReplaceError(
            "synthetic_failure", publication_possible=publication_possible
        )
        error.args = (raw_error,)
        raise error

    create, legacy = Mock(), Mock()
    authorize = cli._authorize_google_readonly
    observed_errors: list[auth_module.GoogleReadonlyAuthorizationReplaceError] = []

    def observe_error(
        client: str, token: str, *, overwrite: bool, replace_existing: bool
    ) -> object:
        try:
            return authorize(client, token, overwrite=overwrite, replace_existing=replace_existing)
        except auth_module.GoogleReadonlyAuthorizationReplaceError as error:
            observed_errors.append(error)
            raise

    monkeypatch.setattr(cli, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(cli, "_authorize_google_readonly", observe_error)
    monkeypatch.setattr(auth_module, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(auth_module, "_posix_authorization_destination_exists", lambda _path: True)
    monkeypatch.setattr(auth_module.posix_replace, "preflight_posix_private_replace", preflight)
    monkeypatch.setattr(auth_module.posix_replace, "replace_posix_private_bytes", replace)
    monkeypatch.setattr(auth_module, "create_private_text", create)
    monkeypatch.setattr(auth_module, "persist_authorized_user_credentials", legacy)

    assert cli.main(_authorize_overwrite_args(client_path, token_path)) == expected_exit
    captured = capsys.readouterr()

    expected_events = ["preflight"]
    if phase != "preflight":
        expected_events += ["construct", "authorize"]
    if phase == "replace":
        expected_events.append("replace")
        assert "google authorization may already have issued credentials" in captured.err.lower()
        if publication_possible is not False:
            assert all(
                word in captured.err.lower()
                for word in ("check", "retry", "reauthor", "restor", "delet")
            )
    assert events == expected_events
    assert outcome in captured.err.lower()
    assert "authorization completed" not in captured.out.lower()
    assert token_path.read_bytes() == original
    create.assert_not_called()
    legacy.assert_not_called()
    if phase in ("preflight", "replace"):
        (error,) = observed_errors
        assert error.publication_possible is publication_possible
    else:
        assert not observed_errors
    for forbidden in (
        str(client_path),
        str(token_path),
        "synthetic-old-auth-token",
        "synthetic-new-auth-token",
        "synthetic-refresh-token",
        "synthetic-client-id",
        "synthetic-client-secret",
        "synthetic backend details",
        "Traceback",
    ):
        assert forbidden not in captured.out + captured.err + repr(observed_errors)


@pytest.mark.parametrize(
    ("platform", "existing"), [("posix", False), ("nt", True)], ids=["posix-absent", "windows"]
)
def test_cli_existing_policy_preserves_create_only_and_windows_writer(
    platform: str,
    existing: bool,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client_path, token_path = tmp_path / "client.json", tmp_path / "token.json"
    if existing:
        atomic_write_private_json(token_path, {"fixture": "synthetic-old-auth-token"})
    events: list[str] = []
    document = _mock_readonly_oauth(monkeypatch, client_path, events)
    create_preflight, create, replace_preflight, replace, legacy = (Mock() for _ in range(5))
    monkeypatch.setattr(cli, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(auth_module, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(auth_module, "_posix_authorization_destination_exists", lambda _path: False)
    monkeypatch.setattr(auth_module, "preflight_posix_private_text_create", create_preflight)
    monkeypatch.setattr(auth_module, "create_private_text", create)
    monkeypatch.setattr(
        auth_module.posix_replace, "preflight_posix_private_replace", replace_preflight
    )
    monkeypatch.setattr(auth_module.posix_replace, "replace_posix_private_bytes", replace)
    monkeypatch.setattr(auth_module, "persist_authorized_user_credentials", legacy)

    assert cli.main(_authorize_overwrite_args(client_path, token_path)) == 0
    assert events == ["construct", "authorize"]
    replace_preflight.assert_not_called()
    replace.assert_not_called()
    if existing:
        create_preflight.assert_not_called()
        create.assert_not_called()
        legacy.assert_called_once()
        assert legacy.call_args.args[1] == str(token_path)
        assert legacy.call_args.kwargs == {"overwrite": True}
    else:
        legacy.assert_not_called()
        create_preflight.assert_called_once_with(token_path)
        create.assert_called_once()
        assert create.call_args.args[0] == token_path
        assert json.loads(create.call_args.args[1]) == document


def test_optional_extra_missing_returns_two_with_install_guidance_only(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def missing_extra(*_args: object, **_kwargs: object) -> object:
        raise GoogleOptionalDependencyError

    monkeypatch.setattr(cli, "authorize_google_readonly", missing_extra)

    result = cli.main(_authorize_args(online=True))
    captured = capsys.readouterr()

    assert result == 2
    assert "install the declared google-read extra" in captured.err
    assert "fixture-client.json" not in captured.out + captured.err
    assert "fixture-token.json" not in captured.out + captured.err


def _synthetic_target() -> TargetConfig:
    calendar_id = "fixture-private-target"
    return TargetConfig(
        schema_version=1,
        target_label="synthetic-target",
        calendar_id=calendar_id,
        expected_target_fingerprint=calendar_id_fingerprint(calendar_id),
        expected_summary="Synthetic target calendar",
        expected_access_role="owner",
        expected_time_zone="UTC",
    )


def test_mock_fetch_success_uses_no_live_client_and_prints_no_snapshot_or_path(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    target = _synthetic_target()
    credentials = SimpleNamespace(refresh=lambda _request: None)
    credentials_session = SimpleNamespace(credentials=credentials, refresh=lambda: None)
    bindings = SimpleNamespace(build_service=object(), request_class=object)
    client = object()
    fetched = FetchedGooglePages(
        target_fingerprint=target.expected_fingerprint,
        pages=({"items": []},),
        page_count=1,
        item_count=0,
        retry_count=0,
        refreshed_after_401=False,
        collection_metadata_hash="f" * 64,
    )
    snapshot = SimpleNamespace(page_count=1, event_count=0)
    writes: list[tuple[object, str]] = []

    monkeypatch.setattr(cli, "load_target_config", lambda _path: target)
    monkeypatch.setattr(
        cli,
        "validate_snapshot_output",
        lambda output: Path(output),
    )
    monkeypatch.setattr(cli, "load_google_optional_bindings", lambda: bindings)
    monkeypatch.setattr(
        cli,
        "load_readonly_credentials",
        lambda _path, *, bindings: credentials,
    )
    monkeypatch.setattr(
        cli,
        "_load_posix_readonly_credentials",
        lambda _path, *, bindings: credentials_session,
    )
    monkeypatch.setattr(
        cli,
        "build_read_only_calendar_client",
        lambda _credentials, *, build_service: client,
    )
    monkeypatch.setattr(
        cli,
        "fetch_google_event_pages",
        lambda *_args, **_kwargs: fetched,
    )
    monkeypatch.setattr(
        cli,
        "sanitize_fetched_pages",
        lambda _fetched, *, captured_at: snapshot,
    )
    monkeypatch.setattr(
        cli,
        "write_google_snapshot",
        lambda value, output: writes.append((value, output)),
    )

    result = cli.main(_fetch_args(online=True))
    captured = capsys.readouterr()

    assert result == 0
    assert writes == [(snapshot, "fixture-snapshot.json")]
    assert "target=T-" in captured.out
    assert "pages=1" in captured.out
    assert "events=0" in captured.out
    for forbidden in (
        "fixture-private-target",
        "fixture-target.toml",
        "fixture-token.json",
        "fixture-snapshot.json",
        '{"',
    ):
        assert forbidden not in captured.out + captured.err


@pytest.mark.parametrize(
    ("exception", "expected_exit"),
    [
        (
            TargetConfigError("invalid_target_config", "synthetic safe config error"),
            2,
        ),
        (
            SnapshotWriteError("snapshot_write_failed", "synthetic safe write error"),
            4,
        ),
        (
            TargetIdentityError("target_fingerprint_mismatch", "synthetic safe target error"),
            5,
        ),
        (
            SafeGoogleError(
                status=429,
                reason="rate_limited",
                retryable=True,
                attempt=1,
                operation="events.list",
            ),
            6,
        ),
    ],
)
def test_google_read_cli_safe_exit_mapping(
    exception: BaseException,
    expected_exit: int,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    def fail(_path: str) -> object:
        raise exception

    monkeypatch.setattr(cli, "load_target_config", fail)

    result = cli.main(_fetch_args(online=True))
    captured = capsys.readouterr()

    assert result == expected_exit
    assert "fixture-target.toml" not in captured.out + captured.err
    assert "Traceback" not in captured.out + captured.err


def _install_refresh_boundaries(
    monkeypatch: pytest.MonkeyPatch,
    *,
    credentials: object,
    bindings: object,
    events: list[str],
) -> TargetConfig:
    target = _synthetic_target()
    monkeypatch.setattr(cli, "load_target_config", lambda _path: target)
    monkeypatch.setattr(cli, "validate_snapshot_output", Path)
    monkeypatch.setattr(cli, "load_google_optional_bindings", lambda: bindings)
    monkeypatch.setattr(cli, "write_google_snapshot", lambda *_args: events.append("snapshot"))

    def list_events(*, calendar_id: str, page_token: str | None) -> dict[str, object]:
        assert calendar_id == target.calendar_id
        assert page_token is None
        if "list" not in events:
            events.append("list")
            raise SafeGoogleError(
                status=401,
                reason="unauthorized",
                retryable=False,
                attempt=1,
                operation="events.list",
            )
        events.append("list")
        return {
            "summary": target.expected_summary,
            "timeZone": target.expected_time_zone,
            "accessRole": target.expected_access_role,
            "items": [],
        }

    def build(value: object, *, build_service: object) -> object:
        assert value is credentials
        assert build_service is not None
        events.append("build")
        return SimpleNamespace(list_events=list_events)

    monkeypatch.setattr(cli, "build_read_only_calendar_client", build)
    return target


@pytest.mark.parametrize("expires_at_load", [True, False], ids=["expired-at-load", "calendar-401"])
@pytest.mark.parametrize(
    ("failure", "publication_possible"),
    [
        pytest.param("preflight", False, id="before-request"),
        pytest.param("provider", False, id="request-failed"),
        pytest.param("replace", False, id="unattempted"),
        pytest.param("replace", True, id="attempted"),
        pytest.param("replace", None, id="unknown"),
    ],
)
def test_posix_refresh_failure_preserves_safe_cli_phase_and_stops_fetch(
    expires_at_load: bool,
    failure: str,
    publication_possible: bool | None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    token_path = tmp_path / "synthetic-private-token.json"
    scope = auth_module.READ_ONLY_GOOGLE_SCOPES
    document = {
        "type": "authorized_user",
        "token": "synthetic-previous-token",
        "refresh_token": "synthetic-refresh-token",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": "synthetic-client-id",
        "client_secret": "synthetic-client-secret",
        "scopes": list(scope),
    }
    atomic_write_private_json(token_path, document)
    original = token_path.read_bytes()
    refreshed_value = "synthetic-updated-token"
    unsafe_message = f"synthetic backend details {token_path} {refreshed_value}"
    events: list[str] = []

    def request() -> object:
        events.append("request")
        return object()

    def refresh(_request: object) -> None:
        events.append("provider")
        if failure == "provider":
            raise RuntimeError(unsafe_message)
        credentials.valid = True
        credentials.expired = False

    credentials = SimpleNamespace(
        expired=expires_at_load,
        valid=not expires_at_load,
        refresh_token=document["refresh_token"],
        scopes=scope,
        granted_scopes=scope,
        refresh=refresh,
        to_json=lambda: json.dumps({**document, "token": refreshed_value}),
    )
    bindings = SimpleNamespace(
        build_service=object(),
        request_class=request,
        credentials_class=SimpleNamespace(
            from_authorized_user_info=lambda *_args, **_kwargs: credentials
        ),
    )
    target = _install_refresh_boundaries(
        monkeypatch, credentials=credentials, bindings=bindings, events=events
    )

    def preflight(path: Path, *, expected_content: bytes) -> None:
        events.append("preflight")
        assert path == token_path
        assert expected_content == original
        if failure == "preflight":
            error = auth_module.posix_replace.PosixPrivateReplaceError("synthetic_failure")
            error.args = (unsafe_message,)
            raise error

    def replace(path: Path, content: bytes, *, expected_content: bytes) -> None:
        events.append("replace")
        assert path == token_path
        assert expected_content == original
        assert json.loads(content)["token"] == refreshed_value
        if publication_possible is None:
            raise RuntimeError(unsafe_message)
        error = auth_module.posix_replace.PosixPrivateReplaceError(
            "synthetic_failure", publication_possible=publication_possible
        )
        error.args = (unsafe_message,)
        raise error

    monkeypatch.setattr(auth_module, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(cli, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(auth_module.posix_replace, "preflight_posix_private_replace", preflight)
    monkeypatch.setattr(auth_module.posix_replace, "replace_posix_private_bytes", replace)

    args = _fetch_args(online=True)
    args[args.index("--token-file") + 1] = str(token_path)
    result = cli.main(args)
    captured = capsys.readouterr()
    expected_events = [] if expires_at_load else ["build", "list"]
    expected_events.append("preflight")
    if failure != "preflight":
        expected_events.extend(("request", "provider"))
    if failure == "replace":
        expected_events.append("replace")
    assert events == expected_events
    assert token_path.read_bytes() == original
    assert not captured.out
    assert result == (4 if expires_at_load and failure != "provider" else 6)

    message = captured.err.lower()
    if failure == "preflight":
        assert "before the google refresh request" in message
    elif failure == "provider":
        assert "google read-only credentials could not be refreshed" in message
    else:
        assert "google refresh succeeded" in message
        if publication_possible is False:
            assert "did not attempt" in message
        else:
            assert ("attempted" if publication_possible else "unknown") in message
            assert all(
                word in message for word in ("check", "retry", "reauthor", "restor", "delet")
            )
    for forbidden in (
        "synthetic-previous-token",
        "synthetic-refresh-token",
        "synthetic-client-id",
        "synthetic-client-secret",
        refreshed_value,
        str(token_path),
        target.calendar_id,
        "synthetic backend details",
        "Traceback",
    ):
        assert forbidden not in captured.err


def test_windows_401_keeps_legacy_refresh_and_overwrite(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    credentials = SimpleNamespace(refresh=lambda _request: events.append("provider"))
    bindings = SimpleNamespace(build_service=object(), request_class=object)
    _install_refresh_boundaries(
        monkeypatch, credentials=credentials, bindings=bindings, events=events
    )

    def persist(value: object, path: str, *, overwrite: bool) -> None:
        assert value is credentials
        assert path == "fixture-token.json"
        assert overwrite is True
        events.append("legacy-overwrite")

    monkeypatch.setattr(cli, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(cli, "load_readonly_credentials", lambda *_args, **_kwargs: credentials)
    monkeypatch.setattr(cli, "persist_authorized_user_credentials", persist)

    assert cli.main(_fetch_args(online=True)) == 0
    assert events == ["build", "list", "provider", "legacy-overwrite", "list", "snapshot"]
