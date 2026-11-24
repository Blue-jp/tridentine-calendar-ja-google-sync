"""Least-privilege desktop OAuth boundary for future explicit online commands."""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Callable, Mapping, Sequence
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Self, cast

from pydantic import Field, ValidationError, model_validator

from tridentine_calendar_google_sync import _posix_private_replace as posix_replace
from tridentine_calendar_google_sync._private_create_io import (
    PrivateCreateIOError,
    create_private_text,
    preflight_posix_private_text_create,
)
from tridentine_calendar_google_sync.google_optional import (
    GoogleOptionalBindings,
    load_google_optional_bindings,
)
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.sensitive_paths import (
    MAX_SENSITIVE_FILE_BYTES,
    JsonValue,
    SensitivePathError,
    _absolute_local_path,
    _render_private_json,
    atomic_write_private_json,
    read_private_sensitive_bytes,
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


class GoogleReadonlyRefreshRequestError(GoogleCredentialRefreshError):
    """A POSIX OAuth refresh request failed before local persistence."""


class GoogleReadonlyRefreshPersistenceError(SensitivePathError):
    """A POSIX refresh stopped at local preflight or persistence."""

    def __init__(self, *, publication_possible: bool | None, preflight: bool = False) -> None:
        self.publication_possible = publication_possible
        self.preflight = preflight
        if preflight:
            message = (
                "Read-only token replacement could not be verified "
                "before the Google refresh request."
            )
        else:
            message = (
                "Google refresh succeeded, but local read-only token persistence "
                "could not be verified."
            )
        if publication_possible is False:
            message += " This call did not attempt to replace the final file."
        else:
            state = (
                "This call attempted to replace the final file."
                if publication_possible is True
                else "The final file replacement state is unknown."
            )
            message += (
                f" {state} Check the destination before retrying, reauthorizing, restoring, "
                "or deleting files."
            )
        super().__init__("sensitive_write_failed", message)


class GoogleReadonlyTokenPersistenceError(SensitivePathError):
    """Safe failure of a POSIX create-only authorization save."""

    def __init__(
        self,
        *,
        publication_possible: bool | None,
        preflight: bool = False,
        code: str = "sensitive_write_failed",
        public_message: str = "Google read-only credentials could not be persisted safely",
    ) -> None:
        self.publication_possible = publication_possible
        if preflight:
            message = (
                "Google read-only token destination could not be verified before authorization."
            )
        else:
            message = f"{public_message}. Google authorization may already have issued credentials."
        if publication_possible is False:
            message += " This call did not attempt to create the final file."
        else:
            state = (
                "This call attempted to create the final file."
                if publication_possible is True
                else "The final file creation state is unknown."
            )
            message += (
                f" {state} Output may exist. Check the destination before reauthorizing, retrying, "
                "or deleting files."
            )
        super().__init__(code, message)


class GoogleReadonlyAuthorizationReplaceError(SensitivePathError):
    """Safe failure of local replacement during POSIX CLI authorization."""

    def __init__(self, *, publication_possible: bool | None, preflight: bool = False) -> None:
        self.publication_possible = publication_possible
        if preflight:
            message = "Read-only token replacement could not be verified before authorization."
        else:
            message = (
                "Local read-only token replacement could not be verified. "
                "Google authorization may already have issued credentials."
            )
        if publication_possible is False:
            message += " This call did not attempt to replace the final file."
        else:
            state = (
                "This call attempted to replace the final file."
                if publication_possible is True
                else "The final file replacement state is unknown."
            )
            message += (
                f" {state} Check the destination before reauthorizing, retrying, restoring, "
                "or deleting files."
            )
        super().__init__("sensitive_write_failed", message)


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
        raw = read_private_sensitive_bytes(path, windows_require_protected_acl=False)
        value = _normalize_client_payload(_decode_json_object(raw, kind="desktop_client_config"))
        return DesktopInstalledClientConfig.model_validate(value, strict=True)
    except GoogleAuthError:
        raise
    except SensitivePathError:
        raise GoogleAuthConfigError(
            "unsafe_desktop_client_path",
            "desktop client configuration path is unsafe or unavailable",
        ) from None
    except ValidationError as exc:
        raise GoogleAuthConfigError(
            "invalid_desktop_client_config",
            "desktop client configuration is invalid",
        ) from exc


def _read_authorized_user_token(path: str | Path) -> tuple[AuthorizedUserToken, bytes]:
    try:
        raw = read_private_sensitive_bytes(
            path,
            windows_require_protected_acl=False,
        )
        value = _normalize_token_payload(_decode_json_object(raw, kind="authorized_user_token"))
        return AuthorizedUserToken.model_validate(value, strict=True), raw
    except GoogleAuthError:
        raise
    except SensitivePathError:
        raise GoogleAuthConfigError(
            "unsafe_authorized_user_path",
            "authorized-user token path is unsafe or unavailable",
        ) from None
    except ValidationError as exc:
        raise GoogleAuthConfigError(
            "invalid_authorized_user_token",
            "authorized-user token is invalid",
        ) from exc


def load_authorized_user_token(path: str | Path) -> AuthorizedUserToken:
    """Load one explicit authorized-user JSON file and enforce the exact scope."""

    return _read_authorized_user_token(path)[0]


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


def _require_refreshable(credentials: Any) -> None:
    if getattr(credentials, "expired", False) is not True or not getattr(
        credentials,
        "refresh_token",
        None,
    ):
        raise GoogleCredentialRefreshError(
            "google_credentials_not_refreshable",
            "Google read-only credentials are invalid and cannot be refreshed",
        )


def _request_readonly_refresh(
    credentials: Any,
    bindings: GoogleOptionalBindings,
    *,
    error_type: type[GoogleCredentialRefreshError] = GoogleCredentialRefreshError,
) -> None:
    try:
        credentials.refresh(bindings.request_class())
    except KeyboardInterrupt as exc:
        raise GoogleAuthorizationCancelled(
            "google_refresh_cancelled",
            "Google credential refresh was cancelled",
        ) from (exc if error_type is GoogleCredentialRefreshError else None)
    except Exception as exc:
        raise error_type(
            "google_credential_refresh_failed",
            "Google read-only credentials could not be refreshed",
        ) from (exc if error_type is GoogleCredentialRefreshError else None)


def _check_refreshed_credentials(credentials: Any) -> None:
    _validate_runtime_credential_scopes(credentials)
    if getattr(credentials, "valid", False) is not True:
        raise GoogleCredentialRefreshError(
            "google_credentials_invalid_after_refresh",
            "Google read-only credentials remain invalid after refresh",
        )


@dataclass(repr=False)
class _PosixReadonlyCredentials:
    """Keep the read or last verified saved bytes for this credentials instance."""

    credentials: Any
    _token_path: Path
    _expected_content: bytes
    _bindings: GoogleOptionalBindings
    _cancellation_check: CancellationCheck | None

    def refresh(self) -> None:
        _check_cancelled(self._cancellation_check)
        try:
            posix_replace.preflight_posix_private_replace(
                self._token_path, expected_content=self._expected_content
            )
        except Exception:
            raise GoogleReadonlyRefreshPersistenceError(
                publication_possible=False, preflight=True
            ) from None
        _check_cancelled(self._cancellation_check)
        _request_readonly_refresh(
            self.credentials, self._bindings, error_type=GoogleReadonlyRefreshRequestError
        )
        _check_cancelled(self._cancellation_check)
        _check_refreshed_credentials(self.credentials)
        try:
            _, value = _credentials_payload(self.credentials)
            content = _render_private_json(cast(Mapping[str, JsonValue], value)).encode("utf-8")
        except Exception:
            raise GoogleReadonlyRefreshPersistenceError(publication_possible=False) from None
        try:
            posix_replace.replace_posix_private_bytes(
                self._token_path, content, expected_content=self._expected_content
            )
        except posix_replace.PosixPrivateReplaceError as exc:
            raise GoogleReadonlyRefreshPersistenceError(
                publication_possible=exc.publication_possible,
            ) from None
        except Exception:
            raise GoogleReadonlyRefreshPersistenceError(publication_possible=None) from None
        self._expected_content = content


def _load_posix_readonly_credentials(
    token_path: str | Path,
    *,
    bindings: GoogleOptionalBindings | None = None,
    cancellation_check: CancellationCheck | None = None,
) -> _PosixReadonlyCredentials:
    _check_cancelled(cancellation_check)
    token, original = _read_authorized_user_token(token_path)
    resolved_bindings = bindings or load_google_optional_bindings()
    credentials = credentials_from_authorized_user_token(token, bindings=resolved_bindings)
    state = _PosixReadonlyCredentials(
        credentials, Path(token_path), original, resolved_bindings, cancellation_check
    )
    if getattr(credentials, "valid", False) is not True:
        _require_refreshable(credentials)
        state.refresh()
    return state


def load_readonly_credentials(
    token_path: str | Path,
    *,
    bindings: GoogleOptionalBindings | None = None,
    cancellation_check: CancellationCheck | None = None,
) -> Any:
    """Load and, only if required, refresh exact-scope credentials.

    Calling this function may perform a token refresh through the injected
    official Request class. Merely importing this module performs no network work.
    """

    if os.name == "posix":
        return _load_posix_readonly_credentials(
            token_path, bindings=bindings, cancellation_check=cancellation_check
        ).credentials
    _check_cancelled(cancellation_check)
    token = load_authorized_user_token(token_path)
    resolved_bindings = bindings or load_google_optional_bindings()
    credentials = credentials_from_authorized_user_token(token, bindings=resolved_bindings)
    if getattr(credentials, "valid", False) is True:
        return credentials
    _require_refreshable(credentials)
    _check_cancelled(cancellation_check)
    _request_readonly_refresh(credentials, resolved_bindings)
    _check_cancelled(cancellation_check)
    _check_refreshed_credentials(credentials)
    persist_authorized_user_credentials(credentials, token_path, overwrite=True)
    return credentials


def _default_flow_runner(flow: Any) -> Any:
    return flow.run_local_server(
        port=0,
        open_browser=True,
        authorization_prompt_message="Open the local authorization URL in your browser.",
        success_message="Read-only authorization completed. You may close this window.",
    )


def _posix_authorization_destination_exists(value: str | Path) -> bool:
    path = _absolute_local_path(value)
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    # Search-only descriptors preserve access to searchable but unreadable directories.
    search = getattr(os, "O_SEARCH", getattr(os, "O_PATH", os.O_RDONLY))
    try:
        if not no_follow or not directory:
            raise NotImplementedError
        flags = search | no_follow | directory
        with ExitStack() as directories:
            parent_fd: int | None = None
            for part in path.parent.parts:
                parent_fd = os.open(part, flags, dir_fd=parent_fd)
                directories.callback(os.close, parent_fd)
            try:
                info = os.stat(path.name, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                return False
    except (OSError, NotImplementedError, ValueError):
        raise SensitivePathError(
            "sensitive_output_unavailable",
            "sensitive output cannot be safely inspected",
        ) from None
    if stat.S_ISLNK(info.st_mode):
        raise SensitivePathError(
            "sensitive_path_symlink",
            "symbolic links are not accepted for sensitive data",
        )
    if not stat.S_ISREG(info.st_mode):
        raise SensitivePathError(
            "sensitive_output_not_file",
            "sensitive output is not a regular local file",
        )
    return True


def _create_posix_readonly_token(path: Path, payload: Mapping[str, JsonValue]) -> None:
    try:
        text = _render_private_json(payload)
        if len(text.encode("utf-8", errors="strict")) > MAX_SENSITIVE_FILE_BYTES:
            raise SensitivePathError(
                "sensitive_output_too_large",
                "sensitive output exceeds the size limit",
            )
    except SensitivePathError as exc:
        raise GoogleReadonlyTokenPersistenceError(
            publication_possible=False, code=exc.code, public_message=exc.public_message
        ) from None
    except UnicodeEncodeError:
        raise GoogleReadonlyTokenPersistenceError(publication_possible=False) from None
    try:
        create_private_text(path, text)
    except PrivateCreateIOError as exc:
        raise GoogleReadonlyTokenPersistenceError(
            publication_possible=exc.publication_possible,
        ) from None


def _replace_posix_readonly_token(
    path: Path, payload: Mapping[str, JsonValue], *, expected_content: bytes
) -> None:
    try:
        content = _render_private_json(payload).encode("utf-8")
    except (SensitivePathError, UnicodeEncodeError):
        raise GoogleReadonlyAuthorizationReplaceError(publication_possible=False) from None
    try:
        posix_replace.replace_posix_private_bytes(path, content, expected_content=expected_content)
    except posix_replace.PosixPrivateReplaceError as exc:
        raise GoogleReadonlyAuthorizationReplaceError(
            publication_possible=exc.publication_possible
        ) from None
    except (Exception, KeyboardInterrupt):
        raise GoogleReadonlyAuthorizationReplaceError(publication_possible=None) from None


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

    Existing tokens are rejected by default. On POSIX, ``overwrite=True``
    permits replacement only when a regular file is observed before authorization.
    """

    return _authorize_google_readonly(
        client_config_path,
        token_path,
        bindings=bindings,
        flow_runner=flow_runner,
        cancellation_check=cancellation_check,
        overwrite=overwrite,
        replace_existing=False,
    )


def _authorize_google_readonly(
    client_config_path: str | Path,
    token_path: str | Path,
    *,
    bindings: GoogleOptionalBindings | None = None,
    flow_runner: AuthorizationFlowRunner = _default_flow_runner,
    cancellation_check: CancellationCheck | None = None,
    overwrite: bool,
    replace_existing: bool,
) -> Any:
    _check_cancelled(cancellation_check)
    create_only = os.name == "posix" and (
        not overwrite or not _posix_authorization_destination_exists(token_path)
    )
    path = validate_sensitive_output_path(token_path, overwrite=overwrite and not create_only)
    expected_content: bytes | None = None
    if create_only:
        try:
            preflight_posix_private_text_create(path)
        except PrivateCreateIOError as exc:
            raise GoogleReadonlyTokenPersistenceError(
                publication_possible=exc.publication_possible, preflight=True
            ) from None
    elif replace_existing:
        try:
            expected_content = read_private_sensitive_bytes(path)
            posix_replace.preflight_posix_private_replace(path, expected_content=expected_content)
        except Exception:
            raise GoogleReadonlyAuthorizationReplaceError(
                publication_possible=False, preflight=True
            ) from None
        _check_cancelled(cancellation_check)
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
    if create_only or expected_content is not None:
        _, value = _credentials_payload(credentials)
        payload = cast(Mapping[str, JsonValue], value)
        if expected_content is None:
            _create_posix_readonly_token(path, payload)
        else:
            _replace_posix_readonly_token(path, payload, expected_content=expected_content)
    else:
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
