from __future__ import annotations

import json
from pathlib import Path
from typing import Any, ClassVar

import pytest

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
    path.write_text(json.dumps(_desktop_client_document()), encoding="utf-8")

    config = load_desktop_client_config(path)

    assert config.installed.redirect_uris == ("http://localhost",)
    rendered = repr(config) + json.dumps(config.model_dump(mode="json"))
    for raw_value in ("fixture-client-id", "fixture-client-secret", "fixture-project"):
        assert raw_value not in rendered


def test_web_client_and_nonloopback_redirect_are_rejected(tmp_path: Path) -> None:
    web_path = tmp_path / "web.json"
    web_path.write_text(json.dumps({"web": _desktop_client_document()["installed"]}))
    redirect_path = tmp_path / "redirect.json"
    document = _desktop_client_document()
    document["installed"]["redirect_uris"] = ["http://localhost", "urn:fixture"]  # type: ignore[index]
    redirect_path.write_text(json.dumps(document), encoding="utf-8")

    for path in (web_path, redirect_path):
        with pytest.raises(GoogleAuthConfigError) as caught:
            load_desktop_client_config(path)
        assert str(path) not in str(caught.value)


def test_authorized_user_token_requires_exact_scope_and_redacts_values(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    path.write_text(json.dumps(_token_document()), encoding="utf-8")

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
    path.write_text(
        json.dumps(_token_document(["https://www.googleapis.com/auth/calendar.events"])),
        encoding="utf-8",
    )

    with pytest.raises(GoogleAuthConfigError) as caught:
        load_authorized_user_token(path)

    assert "calendar.events" not in str(caught.value)
    assert str(path) not in str(caught.value)


def test_valid_existing_token_constructs_credentials_without_flow(tmp_path: Path) -> None:
    path = tmp_path / "token.json"
    path.write_text(json.dumps(_token_document()), encoding="utf-8")
    FakeInstalledAppFlow.calls.clear()

    credentials = load_readonly_credentials(path, bindings=_bindings())

    assert credentials.valid is True
    assert FakeCredentials.last_authorized_scopes == list(READ_ONLY_GOOGLE_SCOPES)
    assert FakeInstalledAppFlow.calls == []


def test_expired_token_refreshes_once_with_injected_request_and_persists(
    tmp_path: Path,
) -> None:
    path = tmp_path / "token.json"
    path.write_text(json.dumps(_token_document()), encoding="utf-8")
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
    path.write_text(json.dumps(_token_document()), encoding="utf-8")
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
    client_path.write_text(json.dumps(_desktop_client_document()), encoding="utf-8")
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


def test_mocked_authorization_passes_exact_scope_and_persists_atomically(
    tmp_path: Path,
) -> None:
    client_path = tmp_path / "client.json"
    client_path.write_text(json.dumps(_desktop_client_document()), encoding="utf-8")
    token_path = tmp_path / "new-token.json"
    FakeInstalledAppFlow.calls.clear()
    flow_calls = 0

    def flow_runner(flow: object) -> FakeCredentials:
        nonlocal flow_calls
        flow_calls += 1
        assert isinstance(flow, FakeFlow)
        return FakeCredentials()

    authorize_google_readonly(
        client_path,
        token_path,
        bindings=_bindings(),
        flow_runner=flow_runner,
    )

    assert flow_calls == 1
    assert len(FakeInstalledAppFlow.calls) == 1
    _config, scopes = FakeInstalledAppFlow.calls[0]
    assert scopes == list(READ_ONLY_GOOGLE_SCOPES)
    assert json.loads(token_path.read_text(encoding="utf-8"))["scopes"] == list(
        READ_ONLY_GOOGLE_SCOPES
    )


def test_existing_token_rejects_authorization_before_flow(tmp_path: Path) -> None:
    client_path = tmp_path / "client.json"
    client_path.write_text(json.dumps(_desktop_client_document()), encoding="utf-8")
    token_path = tmp_path / "existing-token.json"
    token_path.write_text("synthetic existing value", encoding="utf-8")
    flow_calls = 0

    def flow_runner(_flow: object) -> FakeCredentials:
        nonlocal flow_calls
        flow_calls += 1
        return FakeCredentials()

    with pytest.raises(Exception) as caught:
        authorize_google_readonly(
            client_path,
            token_path,
            bindings=_bindings(),
            flow_runner=flow_runner,
        )

    assert flow_calls == 0
    assert token_path.read_text(encoding="utf-8") == "synthetic existing value"
    assert str(token_path) not in str(caught.value)


def test_runtime_credentials_with_write_scope_are_rejected_before_persist(
    tmp_path: Path,
) -> None:
    path = tmp_path / "must-not-write.json"
    credentials = FakeCredentials()
    credentials.scopes = ("https://www.googleapis.com/auth/calendar.events",)

    with pytest.raises(GoogleAuthConfigError):
        persist_authorized_user_credentials(credentials, path)

    assert not path.exists()
