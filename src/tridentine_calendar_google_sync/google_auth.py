"""Least-privilege desktop OAuth boundary for future explicit online commands."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Literal, Self, cast

from pydantic import Field, ValidationError, model_validator

from tridentine_calendar_google_sync.google_optional import (
    GoogleOptionalBindings,
    load_google_optional_bindings,
)
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.sensitive_paths import (
    JsonValue,
    SensitivePathError,
    atomic_write_private_json,
    read_sensitive_bytes,
    validate_sensitive_output_path,
)

GOOGLE_CALENDAR_EVENTS_OWNED_READONLY_SCOPE = (
    "https://www.googleapis.com/auth/calendar.events.owned.readonly"
)
READ_ONLY_GOOGLE_SCOPES = (GOOGLE_CALENDAR_EVENTS_OWNED_READONLY_SCOPE,)

_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
_TOKEN_URI = "https://oauth2.googleapis.com/token"
_LOCAL_REDIRECT_URI = "http://localhost"

CancellationCheck = Callable[[], bool]
AuthorizationFlowRunner = Callable[[Any], Any]


class GoogleAuthError(ValueError):
    """Base authentication failure with path- and content-free public text."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class GoogleAuthConfigError(GoogleAuthError):
    """Invalid desktop client or authorized-user configuration."""


class GoogleAuthorizationCancelled(GoogleAuthError):
    """The user cancelled before credentials were persisted."""


class GoogleAuthorizationError(GoogleAuthError):
    """Interactive desktop authorization failed safely."""


class GoogleCredentialRefreshError(GoogleAuthError):
    """Existing read-only credentials could not be refreshed safely."""


class DesktopInstalledClient(StrictFrozenModel):
    """Strict ``installed`` section of a Google desktop OAuth client file."""

    client_id: str = Field(min_length=1, repr=False, exclude=True)
    project_id: str | None = Field(default=None, repr=False, exclude=True)
    auth_uri: Literal["https://accounts.google.com/o/oauth2/auth"]
    token_uri: Literal["https://oauth2.googleapis.com/token"]
    auth_provider_x509_cert_url: str | None = Field(default=None, repr=False, exclude=True)
    client_secret: str = Field(min_length=1, repr=False, exclude=True)
    redirect_uris: tuple[str, ...] = Field(repr=False, exclude=True)

    @model_validator(mode="after")
    def only_loopback_redirect(self) -> Self:
        if self.redirect_uris != (_LOCAL_REDIRECT_URI,):
            raise ValueError("desktop client must use only the localhost redirect")
        return self


class DesktopInstalledClientConfig(StrictFrozenModel):
    """Strict top-level desktop client configuration; web clients are rejected."""

    installed: DesktopInstalledClient = Field(repr=False, exclude=True)


class AuthorizedUserToken(StrictFrozenModel):
    """Strict authorized-user token schema limited to the owned read-only scope."""

    credential_type: Literal["authorized_user"] | None = Field(
        default=None,
        alias="type",
    )
    token: str | None = Field(default=None, repr=False, exclude=True)
    refresh_token: str = Field(min_length=1, repr=False, exclude=True)
    token_uri: Literal["https://oauth2.googleapis.com/token"]
    client_id: str = Field(min_length=1, repr=False, exclude=True)
    client_secret: str = Field(min_length=1, repr=False, exclude=True)
    scopes: tuple[str, ...] = Field(repr=False, exclude=True)
    expiry: str | None = Field(default=None, repr=False, exclude=True)
    rapt_token: str | None = Field(default=None, repr=False, exclude=True)
    universe_domain: str | None = Field(default=None, repr=False, exclude=True)
    account: str | None = Field(default=None, repr=False, exclude=True)

    @model_validator(mode="after")
    def only_owned_readonly_scope(self) -> Self:
        validate_readonly_scopes(self.scopes)
        return self


class _DuplicateJsonKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def _decode_json_object(raw_bytes: bytes, *, kind: str) -> dict[str, Any]:
    try:
        decoded = raw_bytes.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict):
            raise TypeError
        return value
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        TypeError,
        ValueError,
    ) as exc:
        raise GoogleAuthConfigError(
            f"invalid_{kind}",
            f"{kind.replace('_', ' ')} is invalid",
        ) from exc


def validate_readonly_scopes(scopes: Sequence[str]) -> tuple[str, ...]:
    """Reject every broad, write-capable, missing, duplicated, or extra scope."""

    validated = tuple(scopes)
    if validated != READ_ONLY_GOOGLE_SCOPES:
        raise GoogleAuthConfigError(
            "unsafe_google_scope",
            "OAuth scopes must contain only the owned-events read-only scope",
        )
    return validated


def _normalize_client_payload(value: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(value)
    installed = normalized.get("installed")
    if isinstance(installed, dict):
        normalized_installed = dict(installed)
        redirect_uris = normalized_installed.get("redirect_uris")
        if isinstance(redirect_uris, list):
            normalized_installed["redirect_uris"] = tuple(redirect_uris)
        normalized["installed"] = normalized_installed
    return normalized


def _normalize_token_payload(value: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(value)
    scopes = normalized.get("scopes")
    if isinstance(scopes, list):
        normalized["scopes"] = tuple(scopes)
    return normalized


def load_desktop_client_config(path: str | Path) -> DesktopInstalledClientConfig:
    """Load one explicit desktop client JSON file outside every committed worktree."""

    try:
        raw = read_sensitive_bytes(path, windows_private_acl=True)
        value = _normalize_client_payload(_decode_json_object(raw, kind="desktop_client_config"))
        return DesktopInstalledClientConfig.model_validate(value, strict=True)
    except GoogleAuthError:
        raise
    except SensitivePathError as exc:
        raise GoogleAuthConfigError(
            "unsafe_desktop_client_path",
            "desktop client configuration path is unsafe or unavailable",
        ) from exc
    except ValidationError as exc:
        raise GoogleAuthConfigError(
            "invalid_desktop_client_config",
            "desktop client configuration is invalid",
        ) from exc


def load_authorized_user_token(path: str | Path) -> AuthorizedUserToken:
    """Load one explicit authorized-user JSON file and enforce the exact scope."""

    try:
        raw = read_sensitive_bytes(
            path,
            windows_private_acl=True,
        )
        value = _normalize_token_payload(_decode_json_object(raw, kind="authorized_user_token"))
        return AuthorizedUserToken.model_validate(value, strict=True)
    except GoogleAuthError:
        raise
    except SensitivePathError as exc:
        raise GoogleAuthConfigError(
            "unsafe_authorized_user_path",
            "authorized-user token path is unsafe or unavailable",
        ) from exc
    except ValidationError as exc:
        raise GoogleAuthConfigError(
            "invalid_authorized_user_token",
            "authorized-user token is invalid",
        ) from exc


def _client_config_payload(config: DesktopInstalledClientConfig) -> dict[str, object]:
    installed = config.installed
    payload: dict[str, object] = {
        "client_id": installed.client_id,
        "auth_uri": _AUTH_URI,
        "token_uri": _TOKEN_URI,
        "client_secret": installed.client_secret,
        "redirect_uris": list(installed.redirect_uris),
    }
    if installed.project_id is not None:
        payload["project_id"] = installed.project_id
    if installed.auth_provider_x509_cert_url is not None:
        payload["auth_provider_x509_cert_url"] = installed.auth_provider_x509_cert_url
    return {"installed": payload}


def _authorized_user_payload(token: AuthorizedUserToken) -> dict[str, object]:
    payload: dict[str, object] = {
        "token": token.token,
        "refresh_token": token.refresh_token,
        "token_uri": _TOKEN_URI,
        "client_id": token.client_id,
        "client_secret": token.client_secret,
        "scopes": list(token.scopes),
    }
    if token.credential_type is not None:
        payload["type"] = token.credential_type
    if token.expiry is not None:
        payload["expiry"] = token.expiry
    if token.rapt_token is not None:
        payload["rapt_token"] = token.rapt_token
    if token.universe_domain is not None:
        payload["universe_domain"] = token.universe_domain
    if token.account is not None:
        payload["account"] = token.account
    return payload


def _check_cancelled(cancellation_check: CancellationCheck | None) -> None:
    if cancellation_check is not None and cancellation_check():
        raise GoogleAuthorizationCancelled(
            "google_authorization_cancelled",
            "Google authorization was cancelled",
        )


def _validate_runtime_credential_scopes(credentials: Any) -> None:
    scopes = getattr(credentials, "scopes", None)
    if scopes is None or isinstance(scopes, str):
        raise GoogleAuthConfigError(
            "missing_runtime_google_scope",
            "runtime credentials do not declare the required read-only scope",
        )
    validate_readonly_scopes(cast(Sequence[str], scopes))
    granted_scopes = getattr(credentials, "granted_scopes", None)
    if granted_scopes is not None:
        if isinstance(granted_scopes, str):
            raise GoogleAuthConfigError(
                "unsafe_granted_google_scope",
                "runtime credentials contain an unsafe granted scope",
            )
        validate_readonly_scopes(cast(Sequence[str], granted_scopes))


def _credentials_payload(credentials: Any) -> tuple[AuthorizedUserToken, dict[str, Any]]:
    try:
        serialized = credentials.to_json()
        if not isinstance(serialized, str):
            raise TypeError
        value = _normalize_token_payload(
            _decode_json_object(serialized.encode("utf-8"), kind="authorized_user_token")
        )
        token = AuthorizedUserToken.model_validate(value, strict=True)
        return token, value
    except GoogleAuthError:
        raise
    except (AttributeError, TypeError, UnicodeEncodeError, ValidationError) as exc:
        raise GoogleAuthConfigError(
            "invalid_runtime_credentials",
            "runtime credentials cannot be persisted safely",
        ) from exc


def persist_authorized_user_credentials(
    credentials: Any,
    token_path: str | Path,
    *,
    overwrite: bool = False,
) -> AuthorizedUserToken:
    """Validate and atomically persist credentials with owner-only permissions."""

    _validate_runtime_credential_scopes(credentials)
    token, value = _credentials_payload(credentials)
    atomic_write_private_json(
        token_path,
        cast(Mapping[str, JsonValue], value),
        overwrite=overwrite,
    )
    return token


def credentials_from_authorized_user_token(
    token: AuthorizedUserToken,
    *,
    bindings: GoogleOptionalBindings,
) -> Any:
    """Construct official credentials from a previously validated token model."""

    try:
        factory = bindings.credentials_class.from_authorized_user_info
        credentials = factory(
            _authorized_user_payload(token),
            scopes=list(READ_ONLY_GOOGLE_SCOPES),
        )
    except Exception as exc:
        raise GoogleAuthConfigError(
            "authorized_user_credentials_rejected",
            "authorized-user credentials could not be constructed",
        ) from exc
    _validate_runtime_credential_scopes(credentials)
    return credentials


def load_readonly_credentials(
    token_path: str | Path,
    *,
    bindings: GoogleOptionalBindings | None = None,
    cancellation_check: CancellationCheck | None = None,
) -> Any:
    """Load and, only if required, refresh exact-scope credentials.

    Calling this function may perform a token refresh through the injected
    official Request class.  Merely importing this module performs no OAuth or
    network work.
    """

    _check_cancelled(cancellation_check)
    token = load_authorized_user_token(token_path)
    resolved_bindings = bindings or load_google_optional_bindings()
    credentials = credentials_from_authorized_user_token(token, bindings=resolved_bindings)
    if getattr(credentials, "valid", False) is True:
        return credentials
    if getattr(credentials, "expired", False) is not True or not getattr(
        credentials,
        "refresh_token",
        None,
    ):
        raise GoogleCredentialRefreshError(
            "google_credentials_not_refreshable",
            "Google read-only credentials are invalid and cannot be refreshed",
        )
    _check_cancelled(cancellation_check)
    try:
        credentials.refresh(resolved_bindings.request_class())
    except KeyboardInterrupt as exc:
        raise GoogleAuthorizationCancelled(
            "google_refresh_cancelled",
            "Google credential refresh was cancelled",
        ) from exc
    except Exception as exc:
        raise GoogleCredentialRefreshError(
            "google_credential_refresh_failed",
            "Google read-only credentials could not be refreshed",
        ) from exc
    _check_cancelled(cancellation_check)
    _validate_runtime_credential_scopes(credentials)
    if getattr(credentials, "valid", False) is not True:
        raise GoogleCredentialRefreshError(
            "google_credentials_invalid_after_refresh",
            "Google read-only credentials remain invalid after refresh",
        )
    persist_authorized_user_credentials(credentials, token_path, overwrite=True)
    return credentials


def _default_flow_runner(flow: Any) -> Any:
    return flow.run_local_server(
        port=0,
        open_browser=True,
        authorization_prompt_message="Open the local authorization URL in your browser.",
        success_message="Read-only authorization completed. You may close this window.",
    )


def authorize_google_readonly(
    client_config_path: str | Path,
    token_path: str | Path,
    *,
    bindings: GoogleOptionalBindings | None = None,
    flow_runner: AuthorizationFlowRunner = _default_flow_runner,
    cancellation_check: CancellationCheck | None = None,
    overwrite: bool = False,
) -> Any:
    """Run an explicit localhost desktop flow and create a new token atomically.

    Existing tokens are rejected by default.  Replacement requires the caller
    to pass the separate explicit ``overwrite=True`` flag.
    """

    _check_cancelled(cancellation_check)
    validate_sensitive_output_path(token_path, overwrite=overwrite)
    config = load_desktop_client_config(client_config_path)
    resolved_bindings = bindings or load_google_optional_bindings()
    try:
        flow_factory = resolved_bindings.installed_app_flow_class.from_client_config
        flow = flow_factory(
            _client_config_payload(config),
            scopes=list(READ_ONLY_GOOGLE_SCOPES),
        )
        credentials = flow_runner(flow)
    except KeyboardInterrupt as exc:
        raise GoogleAuthorizationCancelled(
            "google_authorization_cancelled",
            "Google authorization was cancelled",
        ) from exc
    except GoogleAuthError:
        raise
    except Exception as exc:
        raise GoogleAuthorizationError(
            "google_authorization_failed",
            "Google read-only authorization failed",
        ) from exc
    _check_cancelled(cancellation_check)
    _validate_runtime_credential_scopes(credentials)
    persist_authorized_user_credentials(credentials, token_path, overwrite=overwrite)
    return credentials


__all__ = [
    "GOOGLE_CALENDAR_EVENTS_OWNED_READONLY_SCOPE",
    "READ_ONLY_GOOGLE_SCOPES",
    "AuthorizationFlowRunner",
    "AuthorizedUserToken",
    "CancellationCheck",
    "DesktopInstalledClient",
    "DesktopInstalledClientConfig",
    "GoogleAuthConfigError",
    "GoogleAuthError",
    "GoogleAuthorizationCancelled",
    "GoogleAuthorizationError",
    "GoogleCredentialRefreshError",
    "authorize_google_readonly",
    "credentials_from_authorized_user_token",
    "load_authorized_user_token",
    "load_desktop_client_config",
    "load_readonly_credentials",
    "persist_authorized_user_credentials",
    "validate_readonly_scopes",
]
