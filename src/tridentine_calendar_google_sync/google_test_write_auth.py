"""Isolated exact-scope desktop OAuth foundation for Test Calendar writes."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any, Literal, Self, cast

from pydantic import Field, ValidationError, model_validator

from tridentine_calendar_google_sync.google_auth import load_desktop_client_config
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
    sensitive_path_identity,
    validate_sensitive_input_path,
    validate_sensitive_output_path,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetConfig,
    validate_test_write_target_config,
)

GOOGLE_TEST_EVENTS_OWNED_WRITE_SCOPE = "https://www.googleapis.com/auth/calendar.events.owned"
TEST_WRITE_GOOGLE_SCOPES = (GOOGLE_TEST_EVENTS_OWNED_WRITE_SCOPE,)

_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
_TOKEN_URI = "https://oauth2.googleapis.com/token"

CancellationCheck = Callable[[], bool]
AuthorizationFlowRunner = Callable[[Any], Any]


class TestWriteAuthError(ValueError):
    """An authentication failure whose public text contains no secret or path."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class TestWriteAuthConfigError(TestWriteAuthError):
    """The Test write token, scope, or token path policy is invalid."""


class TestWriteAuthorizationCancelled(TestWriteAuthError):
    """The user cancelled the isolated Test write authorization flow."""


class TestWriteAuthorizationError(TestWriteAuthError):
    """The isolated Test write authorization flow failed safely."""


class TestWriteCredentialRefreshError(TestWriteAuthError):
    """Existing exact-scope Test write credentials could not be refreshed."""


class TestWriteAuthorizedUserToken(StrictFrozenModel):
    """Strict authorized-user token limited to one Test-write scope."""

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
    def only_exact_test_write_scope(self) -> Self:
        validate_test_write_scopes(self.scopes)
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


def _decode_json_object(raw_bytes: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
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
        raise TestWriteAuthConfigError(
            "invalid_test_write_token",
            "Test write authorized-user token is invalid",
        ) from exc


def validate_test_write_scopes(scopes: Sequence[str]) -> tuple[str, ...]:
    """Reject missing, read-only, broad, duplicated, multiple, or extra scopes."""

    validated = tuple(scopes)
    if validated != TEST_WRITE_GOOGLE_SCOPES:
        raise TestWriteAuthConfigError(
            "unsafe_test_write_scope",
            "OAuth scopes must contain only the owned-events Test write scope",
        )
    return validated


def _normalize_token_payload(value: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(value)
    scopes = normalized.get("scopes")
    if isinstance(scopes, list):
        normalized["scopes"] = tuple(scopes)
    return normalized


def validate_test_write_token_separation(
    test_write_token_path: str | Path,
    production_read_token_path: str | Path,
    *,
    test_token_exists: bool = False,
) -> tuple[Path, Path]:
    """Require distinct repository-external Test-write and Production-read token files."""

    try:
        test_path = (
            validate_sensitive_input_path(
                test_write_token_path,
                windows_private_acl=True,
            )
            if test_token_exists
            else validate_sensitive_output_path(test_write_token_path, overwrite=False)
        )
        production_path = validate_sensitive_input_path(
            production_read_token_path,
            windows_private_acl=True,
        )
        test_identity = sensitive_path_identity(
            test_path,
            exists=test_token_exists,
            windows_private_acl=test_token_exists,
        )
        production_identity = sensitive_path_identity(
            production_path,
            exists=True,
            windows_private_acl=True,
        )
        if test_identity == production_identity:
            raise TestWriteAuthConfigError(
                "test_write_token_reuses_production_token",
                "Test write token must be separate from the Production read-only token",
            )
        return test_path, production_path
    except TestWriteAuthError:
        raise
    except (SensitivePathError, OSError) as exc:
        raise TestWriteAuthConfigError(
            "unsafe_test_write_token_path",
            "Test write token paths are unsafe or unavailable",
        ) from exc


def load_test_write_authorized_user_token(
    path: str | Path,
) -> TestWriteAuthorizedUserToken:
    """Load one explicit repository-external Test-write token with exact scope."""

    try:
        value = _normalize_token_payload(
            _decode_json_object(
                read_sensitive_bytes(
                    path,
                    windows_private_acl=True,
                )
            )
        )
        return TestWriteAuthorizedUserToken.model_validate(value, strict=True)
    except TestWriteAuthError:
        raise
    except SensitivePathError as exc:
        raise TestWriteAuthConfigError(
            "unsafe_test_write_authorized_user_path",
            "Test write authorized-user token path is unsafe or unavailable",
        ) from exc
    except ValidationError as exc:
        raise TestWriteAuthConfigError(
            "invalid_test_write_authorized_user_token",
            "Test write authorized-user token is invalid",
        ) from exc


def _client_config_payload(config: Any) -> dict[str, object]:
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


def _token_payload(token: TestWriteAuthorizedUserToken) -> dict[str, object]:
    payload: dict[str, object] = {
        "token": token.token,
        "refresh_token": token.refresh_token,
        "token_uri": _TOKEN_URI,
        "client_id": token.client_id,
        "client_secret": token.client_secret,
        "scopes": list(token.scopes),
    }
    optional = {
        "type": token.credential_type,
        "expiry": token.expiry,
        "rapt_token": token.rapt_token,
        "universe_domain": token.universe_domain,
        "account": token.account,
    }
    payload.update({key: value for key, value in optional.items() if value is not None})
    return payload


def _check_cancelled(cancellation_check: CancellationCheck | None) -> None:
    if cancellation_check is not None and cancellation_check():
        raise TestWriteAuthorizationCancelled(
            "test_write_authorization_cancelled",
            "Test write authorization was cancelled",
        )


def _validate_runtime_scopes(credentials: Any) -> None:
    scopes = getattr(credentials, "scopes", None)
    if scopes is None or isinstance(scopes, str):
        raise TestWriteAuthConfigError(
            "missing_runtime_test_write_scope",
            "Runtime credentials do not declare the exact Test write scope",
        )
    validate_test_write_scopes(cast(Sequence[str], scopes))
    granted_scopes = getattr(credentials, "granted_scopes", None)
    if granted_scopes is not None:
        if isinstance(granted_scopes, str):
            raise TestWriteAuthConfigError(
                "unsafe_granted_test_write_scope",
                "Runtime credentials contain an unsafe granted scope",
            )
        validate_test_write_scopes(cast(Sequence[str], granted_scopes))


def _credentials_document(credentials: Any) -> tuple[TestWriteAuthorizedUserToken, dict[str, Any]]:
    try:
        serialized = credentials.to_json()
        if not isinstance(serialized, str):
            raise TypeError
        value = _normalize_token_payload(_decode_json_object(serialized.encode("utf-8")))
        token = TestWriteAuthorizedUserToken.model_validate(value, strict=True)
        return token, value
    except TestWriteAuthError:
        raise
    except (AttributeError, TypeError, UnicodeEncodeError, ValidationError) as exc:
        raise TestWriteAuthConfigError(
            "invalid_runtime_test_write_credentials",
            "Runtime Test write credentials cannot be persisted safely",
        ) from exc


def persist_test_write_authorized_user_credentials(
    credentials: Any,
    token_path: str | Path,
    production_read_token_path: str | Path,
    target: TestWriteTargetConfig,
    *,
    overwrite_for_refresh: bool = False,
) -> TestWriteAuthorizedUserToken:
    """Persist only exact-scope Test credentials to the isolated token path."""

    validate_test_write_target_config(target)
    validate_test_write_token_separation(
        token_path,
        production_read_token_path,
        test_token_exists=overwrite_for_refresh,
    )
    _validate_runtime_scopes(credentials)
    token, value = _credentials_document(credentials)
    try:
        atomic_write_private_json(
            token_path,
            cast(Mapping[str, JsonValue], value),
            overwrite=overwrite_for_refresh,
        )
        return token
    except SensitivePathError as exc:
        raise TestWriteAuthConfigError(
            "test_write_token_persistence_failed",
            "Test write credentials could not be persisted safely",
        ) from exc


def credentials_from_test_write_token(
    token: TestWriteAuthorizedUserToken,
    *,
    bindings: GoogleOptionalBindings,
) -> Any:
    """Construct official credentials from a validated Test-write token."""

    try:
        credentials = bindings.credentials_class.from_authorized_user_info(
            _token_payload(token),
            scopes=list(TEST_WRITE_GOOGLE_SCOPES),
        )
    except Exception as exc:
        raise TestWriteAuthConfigError(
            "test_write_credentials_rejected",
            "Test write credentials could not be constructed",
        ) from exc
    _validate_runtime_scopes(credentials)
    return credentials


def load_test_write_credentials(
    token_path: str | Path,
    production_read_token_path: str | Path,
    target: TestWriteTargetConfig,
    *,
    bindings: GoogleOptionalBindings | None = None,
    cancellation_check: CancellationCheck | None = None,
) -> Any:
    """Load and, only when needed, refresh the isolated Test-write token."""

    validate_test_write_target_config(target)
    _check_cancelled(cancellation_check)
    validate_test_write_token_separation(
        token_path,
        production_read_token_path,
        test_token_exists=True,
    )
    token = load_test_write_authorized_user_token(token_path)
    resolved_bindings = bindings or load_google_optional_bindings()
    credentials = credentials_from_test_write_token(token, bindings=resolved_bindings)
    if getattr(credentials, "valid", False) is True:
        return credentials
    if getattr(credentials, "expired", False) is not True or not getattr(
        credentials,
        "refresh_token",
        None,
    ):
        raise TestWriteCredentialRefreshError(
            "test_write_credentials_not_refreshable",
            "Test write credentials are invalid and cannot be refreshed",
        )
    _check_cancelled(cancellation_check)
    try:
        credentials.refresh(resolved_bindings.request_class())
    except KeyboardInterrupt as exc:
        raise TestWriteAuthorizationCancelled(
            "test_write_refresh_cancelled",
            "Test write credential refresh was cancelled",
        ) from exc
    except Exception as exc:
        raise TestWriteCredentialRefreshError(
            "test_write_credential_refresh_failed",
            "Test write credentials could not be refreshed",
        ) from exc
    _check_cancelled(cancellation_check)
    _validate_runtime_scopes(credentials)
    if getattr(credentials, "valid", False) is not True:
        raise TestWriteCredentialRefreshError(
            "test_write_credentials_invalid_after_refresh",
            "Test write credentials remain invalid after refresh",
        )
    persist_test_write_authorized_user_credentials(
        credentials,
        token_path,
        production_read_token_path,
        target,
        overwrite_for_refresh=True,
    )
    return credentials


def _default_flow_runner(flow: Any) -> Any:
    return flow.run_local_server(
        port=0,
        open_browser=True,
        authorization_prompt_message="Open the Test write authorization URL in your browser.",
        success_message="Test write authorization completed. You may close this window.",
    )


def authorize_test_google_write(
    client_config_path: str | Path,
    token_path: str | Path,
    production_read_token_path: str | Path,
    target: TestWriteTargetConfig,
    *,
    bindings: GoogleOptionalBindings | None = None,
    flow_runner: AuthorizationFlowRunner = _default_flow_runner,
    cancellation_check: CancellationCheck | None = None,
) -> Any:
    """Run one explicit exact-scope Test-only desktop flow without overwrite."""

    validate_test_write_target_config(target)
    _check_cancelled(cancellation_check)
    validate_test_write_token_separation(
        token_path,
        production_read_token_path,
        test_token_exists=False,
    )
    config = load_desktop_client_config(client_config_path)
    resolved_bindings = bindings or load_google_optional_bindings()
    try:
        flow = resolved_bindings.installed_app_flow_class.from_client_config(
            _client_config_payload(config),
            scopes=list(TEST_WRITE_GOOGLE_SCOPES),
        )
        credentials = flow_runner(flow)
    except KeyboardInterrupt as exc:
        raise TestWriteAuthorizationCancelled(
            "test_write_authorization_cancelled",
            "Test write authorization was cancelled",
        ) from exc
    except TestWriteAuthError:
        raise
    except Exception as exc:
        raise TestWriteAuthorizationError(
            "test_write_authorization_failed",
            "Test write authorization failed",
        ) from exc
    _check_cancelled(cancellation_check)
    _validate_runtime_scopes(credentials)
    persist_test_write_authorized_user_credentials(
        credentials,
        token_path,
        production_read_token_path,
        target,
        overwrite_for_refresh=False,
    )
    return credentials


__all__ = [
    "GOOGLE_TEST_EVENTS_OWNED_WRITE_SCOPE",
    "TEST_WRITE_GOOGLE_SCOPES",
    "TestWriteAuthConfigError",
    "TestWriteAuthError",
    "TestWriteAuthorizationCancelled",
    "TestWriteAuthorizationError",
    "TestWriteAuthorizedUserToken",
    "TestWriteCredentialRefreshError",
    "authorize_test_google_write",
    "credentials_from_test_write_token",
    "load_test_write_authorized_user_token",
    "load_test_write_credentials",
    "persist_test_write_authorized_user_credentials",
    "validate_test_write_scopes",
    "validate_test_write_token_separation",
]
