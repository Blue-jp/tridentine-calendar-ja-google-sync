from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest
from pytest_mock import MockerFixture

from tridentine_calendar_google_sync import cli
from tridentine_calendar_google_sync import google_auth as auth_module
from tridentine_calendar_google_sync.google_auth import (
    GOOGLE_CALENDAR_EVENTS_OWNED_READONLY_SCOPE,
    READ_ONLY_GOOGLE_SCOPES,
    GoogleAuthConfigError,
    GoogleAuthorizationCancelled,
    GoogleCredentialRefreshError,
    authorize_google_readonly,
    load_authorized_user_token,
    load_desktop_client_config,
    load_readonly_credentials,
    persist_authorized_user_credentials,
    validate_readonly_scopes,
)
from tridentine_calendar_google_sync.google_optional import GoogleOptionalBindings
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
)

pytestmark = pytest.mark.google_read


def _desktop_client_document() -> dict[str, object]:
    return {
        "installed": {
            "client_id": "fixture-client-id",
            "project_id": "fixture-project",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "client_secret": "fixture-client-secret",
            "redirect_uris": ["http://localhost"],
        }
    }


def _token_document(scopes: list[str] | None = None) -> dict[str, object]:
    return {
        "type": "authorized_user",
        "token": "fixture-access-value",
        "refresh_token": "fixture-refresh-value",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": "fixture-client-id",
        "client_secret": "fixture-client-secret",
        "scopes": scopes if scopes is not None else list(READ_ONLY_GOOGLE_SCOPES),
    }


def _write_private_json(path: Path, document: dict[str, object]) -> None:
    """Create a synthetic secret fixture using the runtime private writer."""

    atomic_write_private_text(path, json.dumps(document))


class FakeRequest:
    pass


class FakeCredentials:
    last_authorized_info: dict[str, object] | None = None
    last_authorized_scopes: list[str] | None = None

    def __init__(
        self,
        *,
        valid: bool = True,
        expired: bool = False,
        fail_refresh: bool = False,
    ) -> None:
        self.scopes = READ_ONLY_GOOGLE_SCOPES
        self.granted_scopes = READ_ONLY_GOOGLE_SCOPES
        self.valid = valid
        self.expired = expired
        self.refresh_token = "fixture-refresh-value"
        self.fail_refresh = fail_refresh
        self.refresh_calls: list[object] = []

    @classmethod
    def from_authorized_user_info(
        cls,
        info: dict[str, object],
        *,
        scopes: list[str],
    ) -> FakeCredentials:
        cls.last_authorized_info = info
        cls.last_authorized_scopes = scopes
        return cls()

    def refresh(self, request: object) -> None:
        self.refresh_calls.append(request)
        if self.fail_refresh:
            raise RuntimeError("synthetic raw refresh failure")
        self.valid = True
        self.expired = False

    def to_json(self) -> str:
        return json.dumps(_token_document())


class FakeFlow:
    pass


class FakeInstalledAppFlow:
    calls: ClassVar[list[tuple[dict[str, object], list[str]]]] = []

    @classmethod
    def from_client_config(
        cls,
        config: dict[str, object],
        *,
        scopes: list[str],
    ) -> FakeFlow:
        cls.calls.append((config, scopes))
        return FakeFlow()


def _bindings(credentials_class: type[Any] = FakeCredentials) -> GoogleOptionalBindings:
    return GoogleOptionalBindings(
        credentials_class=credentials_class,
        installed_app_flow_class=FakeInstalledAppFlow,
        request_class=FakeRequest,
        build_service=lambda *args, **kwargs: (args, kwargs),
        http_error_class=RuntimeError,
    )


def test_exact_owned_events_readonly_scope_is_the_only_accepted_scope() -> None:
    assert GOOGLE_CALENDAR_EVENTS_OWNED_READONLY_SCOPE == (
        "https://www.googleapis.com/auth/calendar.events.owned.readonly"
    )
    assert READ_ONLY_GOOGLE_SCOPES == (GOOGLE_CALENDAR_EVENTS_OWNED_READONLY_SCOPE,)
    assert validate_readonly_scopes(READ_ONLY_GOOGLE_SCOPES) == READ_ONLY_GOOGLE_SCOPES


@pytest.mark.parametrize(
    "scopes",
    [
        (),
        ("https://www.googleapis.com/auth/calendar.events",),
        ("https://www.googleapis.com/auth/calendar.events.readonly",),
        (
            GOOGLE_CALENDAR_EVENTS_OWNED_READONLY_SCOPE,
            GOOGLE_CALENDAR_EVENTS_OWNED_READONLY_SCOPE,
        ),
        (GOOGLE_CALENDAR_EVENTS_OWNED_READONLY_SCOPE, "fixture-extra-scope"),
    ],
)
def test_missing_write_broad_duplicate_or_extra_scope_is_rejected(
    scopes: tuple[str, ...],
) -> None:
    with pytest.raises(GoogleAuthConfigError) as caught:
        validate_readonly_scopes(scopes)
    assert caught.value.code == "unsafe_google_scope"


def test_desktop_client_config_requires_installed_loopback_shape(tmp_path: Path) -> None:
    path = tmp_path / "client.json"
    _write_private_json(path, _desktop_client_document())

    config = load_desktop_client_config(path)

    assert config.installed.redirect_uris == ("http://localhost",)
    rendered = repr(config) + json.dumps(config.model_dump(mode="json"))
    for raw_value in ("fixture-client-id", "fixture-client-secret", "fixture-project"):
        assert raw_value not in rendered


def test_web_client_and_nonloopback_redirect_are_rejected(tmp_path: Path) -> None:
    web_path = tmp_path / "web.json"
    _write_private_json(web_path, {"web": _desktop_client_document()["installed"]})
    redirect_path = tmp_path / "redirect.json"
    document = _desktop_client_document()
    document["installed"]["redirect_uris"] = ["http://localhost", "urn:fixture"]  # type: ignore[index]
    _write_private_json(redirect_path, document)

    for path in (web_path, redirect_path):
        with pytest.raises(GoogleAuthConfigError) as caught:
            load_desktop_client_config(path)
        assert str(path) not in str(caught.value)


def test_authorized_user_token_requires_exact_scope_and_redacts_values(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    _write_private_json(path, _token_document())

    token = load_authorized_user_token(path)

    assert token.scopes == READ_ONLY_GOOGLE_SCOPES
    rendered = repr(token) + json.dumps(token.model_dump(mode="json"))
    for raw_value in (
        "fixture-access-value",
        "fixture-refresh-value",
        "fixture-client-id",
        "fixture-client-secret",
    ):
        assert raw_value not in rendered


def test_authorized_user_write_scope_is_rejected_without_echo(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    _write_private_json(
        path,
        _token_document(["https://www.googleapis.com/auth/calendar.events"]),
    )

    with pytest.raises(GoogleAuthConfigError) as caught:
        load_authorized_user_token(path)

    assert "calendar.events" not in str(caught.value)
    assert str(path) not in str(caught.value)


def test_valid_existing_token_constructs_credentials_without_flow(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    _write_private_json(path, _token_document())
    FakeInstalledAppFlow.calls.clear()

    credentials = load_readonly_credentials(path, bindings=_bindings())

    assert credentials.valid is True
    assert FakeCredentials.last_authorized_scopes == list(READ_ONLY_GOOGLE_SCOPES)
    assert FakeInstalledAppFlow.calls == []


def test_expired_token_refreshes_once_with_injected_request_and_persists(
    tmp_path: Path,
) -> None:
    path = tmp_path / "token.json"
    _write_private_json(path, _token_document())
    credentials = FakeCredentials(valid=False, expired=True)

    class ExpiredCredentialsFactory(FakeCredentials):
        @classmethod
        def from_authorized_user_info(
            cls,
            info: dict[str, object],
            *,
            scopes: list[str],
        ) -> FakeCredentials:
            del info, scopes
            return credentials

    result = load_readonly_credentials(path, bindings=_bindings(ExpiredCredentialsFactory))

    assert result is credentials
    assert len(credentials.refresh_calls) == 1
    assert isinstance(credentials.refresh_calls[0], FakeRequest)
    assert json.loads(path.read_text(encoding="utf-8"))["scopes"] == list(READ_ONLY_GOOGLE_SCOPES)


def test_refresh_failure_redacts_raw_exception_and_path(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    _write_private_json(path, _token_document())
    credentials = FakeCredentials(valid=False, expired=True, fail_refresh=True)

    class FailingCredentialsFactory(FakeCredentials):
        @classmethod
        def from_authorized_user_info(
            cls,
            info: dict[str, object],
            *,
            scopes: list[str],
        ) -> FakeCredentials:
            del info, scopes
            return credentials

    with pytest.raises(GoogleCredentialRefreshError) as caught:
        load_readonly_credentials(path, bindings=_bindings(FailingCredentialsFactory))

    assert "synthetic raw refresh failure" not in str(caught.value)
    assert str(path) not in str(caught.value)


def test_authorization_cancellation_stops_before_flow_or_token_write(tmp_path: Path) -> None:
    client_path = tmp_path / "client.json"
    _write_private_json(client_path, _desktop_client_document())
    token_path = tmp_path / "new-token.json"
    flow_calls = 0

    def flow_runner(_flow: object) -> object:
        nonlocal flow_calls
        flow_calls += 1
        return FakeCredentials()

    with pytest.raises(GoogleAuthorizationCancelled):
        authorize_google_readonly(
            client_path,
            token_path,
            bindings=_bindings(),
            flow_runner=flow_runner,
            cancellation_check=lambda: True,
        )

    assert flow_calls == 0
    assert FakeInstalledAppFlow.calls == []
    assert not token_path.exists()


@pytest.fixture
def authorization_paths(tmp_path: Path) -> tuple[Path, Path]:
    if os.name == "posix":
        tmp_path.chmod(0o700)
    client_path = tmp_path / "client.json"
    _write_private_json(client_path, _desktop_client_document())
    return client_path, tmp_path / "new-token.json"


@pytest.mark.parametrize("overwrite", [False, True], ids=["without-flag", "with-flag"])
def test_mocked_authorization_passes_exact_scope_and_persists_atomically(
    authorization_paths: tuple[Path, Path],
    mocker: MockerFixture,
    overwrite: bool,
) -> None:
    client_path, token_path = authorization_paths
    FakeInstalledAppFlow.calls.clear()
    document = _token_document()
    document["token"] = "fixture-opaque-\N{LATIN SMALL LETTER E WITH ACUTE}"
    credentials = FakeCredentials()
    mocker.patch.object(credentials, "to_json", return_value=json.dumps(document))
    flow_runner = mocker.Mock(return_value=credentials)
    preflight = mocker.spy(auth_module, "preflight_posix_private_text_create")
    create = mocker.spy(auth_module, "create_private_text")
    legacy = mocker.spy(auth_module, "atomic_write_private_json")

    result = authorize_google_readonly(
        client_path,
        token_path,
        bindings=_bindings(),
        flow_runner=flow_runner,
        overwrite=overwrite,
    )

    assert result is credentials
    flow_runner.assert_called_once()
    assert isinstance(flow_runner.call_args.args[0], FakeFlow)
    assert len(FakeInstalledAppFlow.calls) == 1
    _config, scopes = FakeInstalledAppFlow.calls[0]
    assert scopes == list(READ_ONLY_GOOGLE_SCOPES)
    expected_text = (
        json.dumps(document, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    )
    assert token_path.read_bytes() == expected_text.encode("utf-8")
    if os.name == "posix":
        preflight.assert_called_once_with(token_path)
        create.assert_called_once()
        legacy.assert_not_called()
        info = token_path.stat()
        assert info.st_uid == os.geteuid()
        assert stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_nlink == 1
    else:
        preflight.assert_not_called()
        create.assert_not_called()
        legacy.assert_called_once()
        assert legacy.call_args.kwargs["overwrite"] is overwrite


def test_existing_token_rejects_authorization_before_flow(
    authorization_paths: tuple[Path, Path],
) -> None:
    client_path, token_path = authorization_paths
    FakeInstalledAppFlow.calls.clear()
    atomic_write_private_text(token_path, "synthetic existing value")
    flow_calls = 0

    def flow_runner(_flow: object) -> FakeCredentials:
        nonlocal flow_calls
        flow_calls += 1
        return FakeCredentials()

    with pytest.raises(SensitivePathError) as caught:
        authorize_google_readonly(
            client_path,
            token_path,
            bindings=_bindings(),
            flow_runner=flow_runner,
        )

    assert flow_calls == 0
    assert FakeInstalledAppFlow.calls == []
    assert caught.value.code == "sensitive_output_exists"
    assert token_path.read_text(encoding="utf-8") == "synthetic existing value"
    assert str(token_path) not in str(caught.value)


@pytest.mark.parametrize("cancelled", [True, False], ids=["cancelled", "unsafe-granted-scope"])
def test_authorization_stops_before_persisting_rejected_credentials(
    authorization_paths: tuple[Path, Path],
    mocker: MockerFixture,
    cancelled: bool,
) -> None:
    client_path, token_path = authorization_paths
    credentials = FakeCredentials()
    if not cancelled:
        credentials.granted_scopes = ("synthetic disallowed scope",)
    flow_completed = False

    def finish_flow(_flow: object) -> FakeCredentials:
        nonlocal flow_completed
        flow_completed = True
        return credentials

    create = mocker.spy(auth_module, "create_private_text")
    legacy = mocker.spy(auth_module, "atomic_write_private_json")
    error = GoogleAuthorizationCancelled if cancelled else GoogleAuthConfigError

    with pytest.raises(error):
        authorize_google_readonly(
            client_path,
            token_path,
            bindings=_bindings(),
            flow_runner=finish_flow,
            cancellation_check=lambda: flow_completed and cancelled,
        )

    assert flow_completed
    create.assert_not_called()
    legacy.assert_not_called()
    assert not token_path.exists()


@pytest.mark.skipif(os.name != "posix", reason="requires real POSIX create-only publication")
@pytest.mark.parametrize("overwrite", [False, True], ids=["without-flag", "with-flag"])
def test_posix_initial_authorization_preserves_token_created_during_flow(
    authorization_paths: tuple[Path, Path],
    mocker: MockerFixture,
    overwrite: bool,
) -> None:
    client_path, token_path = authorization_paths
    existing = b"synthetic token from another invocation"

    def finish_flow(_flow: object) -> FakeCredentials:
        atomic_write_private_text(token_path, existing.decode("ascii"))
        return FakeCredentials()

    legacy = mocker.spy(auth_module, "atomic_write_private_json")
    create = mocker.spy(auth_module, "create_private_text")
    with pytest.raises(auth_module.GoogleReadonlyTokenPersistenceError) as caught:
        authorize_google_readonly(
            client_path,
            token_path,
            bindings=_bindings(),
            flow_runner=finish_flow,
            overwrite=overwrite,
        )

    assert caught.value.publication_possible is False
    assert token_path.read_bytes() == existing
    create.assert_called_once()
    legacy.assert_not_called()


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX parent permissions")
@pytest.mark.parametrize("change_during_flow", [False, True], ids=["preflight", "at-save"])
def test_posix_initial_authorization_rejects_nonprivate_parent(
    authorization_paths: tuple[Path, Path],
    mocker: MockerFixture,
    change_during_flow: bool,
) -> None:
    client_path, token_path = authorization_paths
    FakeInstalledAppFlow.calls.clear()
    parent = token_path.parent
    if not change_during_flow:
        parent.chmod(0o755)
    before = set(parent.iterdir())

    def finish_flow(_flow: object) -> FakeCredentials:
        parent.chmod(0o755)
        return FakeCredentials()

    flow_runner = mocker.Mock(side_effect=finish_flow)
    create = mocker.spy(auth_module, "create_private_text")
    with pytest.raises(auth_module.GoogleReadonlyTokenPersistenceError) as caught:
        authorize_google_readonly(
            client_path,
            token_path,
            bindings=_bindings(),
            flow_runner=flow_runner,
        )

    assert caught.value.publication_possible is False
    expected_calls = int(change_during_flow)
    assert len(FakeInstalledAppFlow.calls) == expected_calls
    assert flow_runner.call_count == expected_calls
    assert create.call_count == expected_calls
    assert set(parent.iterdir()) == before


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX parent permissions")
def test_posix_existing_token_explicit_overwrite_keeps_legacy_parent_policy(
    authorization_paths: tuple[Path, Path],
    mocker: MockerFixture,
) -> None:
    client_path, token_path = authorization_paths
    token_path.parent.chmod(0o755)
    atomic_write_private_text(token_path, "synthetic original file")
    credentials = FakeCredentials()
    preflight = mocker.spy(auth_module, "preflight_posix_private_text_create")
    create = mocker.spy(auth_module, "create_private_text")
    legacy = mocker.spy(auth_module, "atomic_write_private_json")

    assert (
        authorize_google_readonly(
            client_path,
            token_path,
            bindings=_bindings(),
            flow_runner=lambda _flow: credentials,
            overwrite=True,
        )
        is credentials
    )

    assert json.loads(token_path.read_bytes()) == _token_document()
    preflight.assert_not_called()
    create.assert_not_called()
    legacy.assert_called_once()
    assert legacy.call_args.kwargs["overwrite"] is True


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX path inspection")
@pytest.mark.parametrize("kind", ["missing-parent", "directory", "dangling-link", "linked-parent"])
def test_posix_explicit_overwrite_rejects_invalid_destination_before_flow(
    authorization_paths: tuple[Path, Path],
    mocker: MockerFixture,
    kind: str,
) -> None:
    client_path, token_path = authorization_paths
    if kind == "missing-parent":
        token_path = token_path.parent / "absent" / token_path.name
    elif kind == "directory":
        token_path.mkdir()
    elif kind == "dangling-link":
        token_path.symlink_to(token_path.parent / "absent")
    else:
        parent_link = token_path.parent / "linked"
        parent_link.symlink_to(token_path.parent, target_is_directory=True)
        token_path = parent_link / token_path.name
    FakeInstalledAppFlow.calls.clear()
    flow_runner = mocker.Mock()

    with pytest.raises(SensitivePathError) as caught:
        authorize_google_readonly(
            client_path,
            token_path,
            bindings=_bindings(),
            flow_runner=flow_runner,
            overwrite=True,
        )

    assert FakeInstalledAppFlow.calls == []
    flow_runner.assert_not_called()
    assert str(token_path) not in caught.value.public_message


@pytest.mark.parametrize(
    "publication_possible", [False, True, None], ids=["before", "attempted", "unknown"]
)
def test_posix_create_failure_keeps_publication_state_and_cli_exit(
    authorization_paths: tuple[Path, Path],
    mocker: MockerFixture,
    capsys: pytest.CaptureFixture[str],
    publication_possible: bool | None,
) -> None:
    client_path, token_path = authorization_paths
    public_marker = "synthetic private exception detail"
    retained = "synthetic separately written content"
    error = auth_module.PrivateCreateIOError(publication_possible=publication_possible)
    error.args = (f"{token_path}: {public_marker}",)

    def fail_create(*_args: object, **_kwargs: object) -> None:
        if publication_possible is not False:
            atomic_write_private_text(token_path, retained)
        raise error

    mocker.patch.object(auth_module, "os", SimpleNamespace(name="posix"))
    preflight = mocker.patch.object(auth_module, "preflight_posix_private_text_create")
    create = mocker.patch.object(auth_module, "create_private_text", side_effect=fail_create)
    legacy = mocker.spy(auth_module, "atomic_write_private_json")
    flow_runner = mocker.Mock(return_value=FakeCredentials())
    failures: list[auth_module.GoogleReadonlyTokenPersistenceError] = []

    def authorize(client: str, token: str, *, overwrite: bool) -> object:
        try:
            return authorize_google_readonly(
                client,
                token,
                bindings=_bindings(),
                flow_runner=flow_runner,
                overwrite=overwrite,
            )
        except auth_module.GoogleReadonlyTokenPersistenceError as exc:
            failures.append(exc)
            raise

    mocker.patch.object(cli, "authorize_google_readonly", authorize)
    result = cli.main(
        [
            "authorize-google-readonly",
            "--online",
            "--credentials-file",
            str(client_path),
            "--token-file",
            str(token_path),
        ]
    )

    assert result == cli.EXIT_INVALID_SNAPSHOT == 4
    (failure,) = failures
    assert failure.code == "sensitive_write_failed"
    assert failure.publication_possible is publication_possible
    captured = capsys.readouterr()
    assert failure.public_message in captured.err
    assert str(token_path) not in captured.err
    assert public_marker not in captured.err
    assert "authorization completed" not in captured.out
    preflight.assert_called_once_with(token_path)
    create.assert_called_once()
    legacy.assert_not_called()
    flow_runner.assert_called_once()
    if publication_possible is False:
        assert "did not attempt" in captured.err
        assert not token_path.exists()
    else:
        assert "reauthorizing" in captured.err
        assert "retrying" in captured.err
        assert "deleting" in captured.err
        assert token_path.read_text(encoding="utf-8") == retained


def test_runtime_credentials_with_write_scope_are_rejected_before_persist(
    tmp_path: Path,
) -> None:
    path = tmp_path / "must-not-write.json"
    credentials = FakeCredentials()
    credentials.scopes = ("https://www.googleapis.com/auth/calendar.events",)

    with pytest.raises(GoogleAuthConfigError):
        persist_authorized_user_credentials(credentials, path)

    assert not path.exists()
