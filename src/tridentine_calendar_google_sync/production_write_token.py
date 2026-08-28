"""Mock-only Production write-token authorization and refresh foundation."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from tridentine_calendar_google_sync.google_auth import load_desktop_client_config
from tridentine_calendar_google_sync.production_write_target import (
    ProductionWriteTargetConfig,
    calculate_production_write_target_hash,
    production_write_target_reference,
    validate_production_write_target_config,
)
from tridentine_calendar_google_sync.production_write_token_models import (
    PRODUCTION_WRITE_SCOPES,
    ProductionTokenRole,
    ProductionWriteAuthorizedUserToken,
    ProductionWriteCredentialSession,
    ProductionWriteOAuthAuthorizer,
    ProductionWriteOAuthClientMaterial,
    ProductionWriteOAuthCredentials,
    ProductionWriteTokenAuthorizationResult,
    ProductionWriteTokenGenerationState,
    ProductionWriteTokenRefresher,
)

_GENERATION_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:production-write-token-generation:v1\x00"
)


class ProductionWriteTokenError(ValueError):
    """Content- and path-free Production write-token failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class ProductionWriteTokenConfigError(ProductionWriteTokenError):
    """A scope, role, target, generation, or filesystem input is invalid."""


class ProductionWriteTokenAuthorizationError(ProductionWriteTokenError):
    """The mock-only authorization foundation failed safely."""


class ProductionWriteTokenRefreshError(ProductionWriteTokenError):
    """The one permitted mock refresh failed without browser fallback."""


def _is_utc(value: datetime) -> bool:
    offset = value.utcoffset()
    return offset is not None and offset.total_seconds() == 0


def validate_production_write_scopes(scopes: Sequence[str]) -> tuple[str, ...]:
    """Accept exactly one owned-events scope, in canonical order."""

    if isinstance(scopes, (str, bytes)) or not isinstance(scopes, Sequence):
        raise ProductionWriteTokenConfigError(
            "unsafe_production_write_scope",
            "Production write OAuth scope must be the sole owned-events scope",
        )
    validated = tuple(scopes)
    if validated != PRODUCTION_WRITE_SCOPES:
        raise ProductionWriteTokenConfigError(
            "unsafe_production_write_scope",
            "Production write OAuth scope must be the sole owned-events scope",
        )
    return validated


def validate_production_token_role(role: object) -> ProductionTokenRole:
    """Reject generic, Production-read, Test-write, and duck-typed roles."""

    if role is not ProductionTokenRole.PRODUCTION_WRITE:
        raise ProductionWriteTokenConfigError(
            "production_write_token_role_mismatch",
            "The token role must be the dedicated Production write role",
        )
    return ProductionTokenRole.PRODUCTION_WRITE


def production_write_token_authorization_challenge(
    target: ProductionWriteTargetConfig,
) -> str:
    """Return the exact, redacted human confirmation for token authorization."""

    return f"AUTHORIZE PRODUCTION WRITE TOKEN ONLY {production_write_target_reference(target)}"


def verify_production_write_token_authorization_confirmation(
    target: ProductionWriteTargetConfig,
    confirmation: str,
) -> None:
    """Require byte-for-byte, case- and whitespace-sensitive confirmation."""

    if not hmac.compare_digest(
        confirmation,
        production_write_token_authorization_challenge(target),
    ):
        raise ProductionWriteTokenAuthorizationError(
            "production_write_token_confirmation_mismatch",
            "Production write-token authorization confirmation did not match",
        )


def private_production_write_token_generation_state_data(
    state: ProductionWriteTokenGenerationState,
    *,
    include_content_hash: bool = True,
) -> dict[str, object]:
    """Return secret-free canonical generation state data."""

    data: dict[str, object] = {
        "schema_version": state.schema_version,
        "state_type": state.state_type,
        "role": state.role.value,
        "target_safe_ref": state.target_safe_ref,
        "target_config_hash": state.target_config_hash,
        "generation": state.generation,
        "issued_at": state.issued_at.isoformat(),
        "predecessor_state_hash": state.predecessor_state_hash,
    }
    if include_content_hash:
        data["content_hash"] = state.content_hash
    return data


def calculate_production_write_token_generation_state_hash(
    state: ProductionWriteTokenGenerationState,
) -> str:
    """Hash only non-secret opaque state; token and credential bytes never participate."""

    encoded = json.dumps(
        private_production_write_token_generation_state_data(
            state,
            include_content_hash=False,
        ),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_GENERATION_HASH_DOMAIN + encoded).hexdigest()


def verify_production_write_token_generation_state(
    state: ProductionWriteTokenGenerationState,
    *,
    target: ProductionWriteTargetConfig | None = None,
    required_generation: int | None = None,
) -> None:
    """Verify integrity and optional exact Production target/generation binding."""

    try:
        validate_production_token_role(state.role)
    except (AttributeError, ProductionWriteTokenError) as exc:
        raise ProductionWriteTokenConfigError(
            "production_write_token_generation_invalid",
            "Production write-token generation state is invalid",
        ) from exc
    if not hmac.compare_digest(
        calculate_production_write_token_generation_state_hash(state),
        state.content_hash,
    ):
        raise ProductionWriteTokenConfigError(
            "production_write_token_generation_hash_mismatch",
            "Production write-token generation integrity verification failed",
        )
    if required_generation is not None and state.generation != required_generation:
        raise ProductionWriteTokenConfigError(
            "production_write_token_generation_mismatch",
            "Production write-token generation did not match",
        )
    if target is not None:
        validate_production_write_target_config(target)
        target_ref = production_write_target_reference(target)
        target_hash = calculate_production_write_target_hash(target)
        if not (
            hmac.compare_digest(state.target_safe_ref, target_ref)
            and hmac.compare_digest(state.target_config_hash, target_hash)
        ):
            raise ProductionWriteTokenConfigError(
                "production_write_token_generation_target_mismatch",
                "Production write-token generation target did not match",
            )


def build_initial_production_write_token_generation_state(
    target: ProductionWriteTargetConfig,
    *,
    issued_at: datetime,
) -> ProductionWriteTokenGenerationState:
    """Build first issuance state with generation exactly one."""

    validate_production_write_target_config(target)
    if not _is_utc(issued_at):
        raise ProductionWriteTokenConfigError(
            "production_write_token_generation_clock_invalid",
            "Production write-token generation time must be UTC",
        )
    provisional = ProductionWriteTokenGenerationState(
        target_safe_ref=production_write_target_reference(target),
        target_config_hash=calculate_production_write_target_hash(target),
        generation=1,
        issued_at=issued_at,
        predecessor_state_hash=None,
        content_hash="0" * 64,
    )
    state = provisional.model_copy(
        update={"content_hash": calculate_production_write_token_generation_state_hash(provisional)}
    )
    verify_production_write_token_generation_state(state, target=target, required_generation=1)
    return state


def build_next_production_write_token_generation_state(
    previous: ProductionWriteTokenGenerationState,
    target: ProductionWriteTargetConfig,
    *,
    issued_at: datetime,
) -> ProductionWriteTokenGenerationState:
    """Build a future rotation state at exactly predecessor generation plus one."""

    verify_production_write_token_generation_state(previous, target=target)
    if not _is_utc(issued_at) or issued_at <= previous.issued_at:
        raise ProductionWriteTokenConfigError(
            "production_write_token_generation_clock_invalid",
            "Production write-token generation time must increase in UTC",
        )
    provisional = ProductionWriteTokenGenerationState(
        target_safe_ref=previous.target_safe_ref,
        target_config_hash=previous.target_config_hash,
        generation=previous.generation + 1,
        issued_at=issued_at,
        predecessor_state_hash=previous.content_hash,
        content_hash="0" * 64,
    )
    state = provisional.model_copy(
        update={"content_hash": calculate_production_write_token_generation_state_hash(provisional)}
    )
    verify_production_write_token_generation_transition(previous, state, target=target)
    return state


def verify_production_write_token_generation_transition(
    previous: ProductionWriteTokenGenerationState,
    current: ProductionWriteTokenGenerationState,
    *,
    target: ProductionWriteTargetConfig,
) -> None:
    """Require an exact +1 target-bound, hash-linked rotation."""

    verify_production_write_token_generation_state(previous, target=target)
    verify_production_write_token_generation_state(current, target=target)
    if not (
        current.generation == previous.generation + 1
        and current.issued_at > previous.issued_at
        and current.predecessor_state_hash is not None
        and hmac.compare_digest(current.predecessor_state_hash, previous.content_hash)
        and hmac.compare_digest(current.target_safe_ref, previous.target_safe_ref)
        and hmac.compare_digest(current.target_config_hash, previous.target_config_hash)
    ):
        raise ProductionWriteTokenConfigError(
            "production_write_token_generation_transition_mismatch",
            "Production write-token rotation does not match its predecessor",
        )


def _validate_oauth_credentials(
    credentials: ProductionWriteOAuthCredentials,
    *,
    now: datetime,
    client: ProductionWriteOAuthClientMaterial | None = None,
) -> None:
    if not isinstance(credentials, ProductionWriteOAuthCredentials) or any(
        not isinstance(value, str) or not value
        for value in (
            credentials.access_token,
            credentials.refresh_token,
            credentials.client_id,
            credentials.client_secret,
        )
    ):
        raise ProductionWriteTokenConfigError(
            "production_write_token_credentials_invalid",
            "Production write OAuth credentials are invalid",
        )
    if not isinstance(now, datetime) or not _is_utc(now):
        raise ProductionWriteTokenConfigError(
            "production_write_token_clock_invalid",
            "Production write-token validation time must be UTC",
        )
    validate_production_write_scopes(credentials.scopes)
    validate_production_write_scopes(credentials.granted_scopes)
    if not isinstance(credentials.expiry, datetime) or not _is_utc(credentials.expiry):
        raise ProductionWriteTokenConfigError(
            "production_write_token_expiry_invalid",
            "Production write-token expiry metadata is invalid",
        )
    if credentials.expiry <= now:
        raise ProductionWriteTokenConfigError(
            "production_write_token_expiry_invalid",
            "Production write-token expiry metadata is invalid",
        )
    if client is not None and not (
        hmac.compare_digest(credentials.client_id, client.client_id)
        and hmac.compare_digest(credentials.client_secret, client.client_secret)
        and credentials.token_uri == client.token_uri
    ):
        raise ProductionWriteTokenConfigError(
            "production_write_token_client_identity_mismatch",
            "Production write-token client identity did not match",
        )


def _token_from_credentials(
    credentials: ProductionWriteOAuthCredentials,
    state: ProductionWriteTokenGenerationState,
) -> ProductionWriteAuthorizedUserToken:
    return ProductionWriteAuthorizedUserToken(
        target_safe_ref=state.target_safe_ref,
        target_config_hash=state.target_config_hash,
        generation=state.generation,
        access_token=credentials.access_token,
        refresh_token=credentials.refresh_token,
        client_id=credentials.client_id,
        client_secret=credentials.client_secret,
        token_uri=credentials.token_uri,
        scopes=credentials.scopes,
        granted_scopes=credentials.granted_scopes,
        expiry=credentials.expiry,
    )


def verify_production_write_authorized_user_token(
    token: ProductionWriteAuthorizedUserToken,
    state: ProductionWriteTokenGenerationState,
    target: ProductionWriteTargetConfig,
) -> None:
    """Verify role, exact scope, target, and opaque generation without token hashing."""

    validate_production_write_target_config(target)
    validate_production_token_role(token.role)
    validate_production_write_scopes(token.scopes)
    validate_production_write_scopes(token.granted_scopes)
    verify_production_write_token_generation_state(
        state,
        target=target,
        required_generation=token.generation,
    )
    if not (
        hmac.compare_digest(token.target_safe_ref, state.target_safe_ref)
        and hmac.compare_digest(token.target_config_hash, state.target_config_hash)
    ):
        raise ProductionWriteTokenConfigError(
            "production_write_token_target_mismatch",
            "Production write-token target binding did not match",
        )


def _oauth_client_material(path: str | Path) -> ProductionWriteOAuthClientMaterial:
    config = load_desktop_client_config(path)
    installed = config.installed
    return ProductionWriteOAuthClientMaterial(
        client_id=installed.client_id,
        client_secret=installed.client_secret,
        auth_uri=installed.auth_uri,
        token_uri=installed.token_uri,
        redirect_uris=("http://localhost",),
    )


def authorize_production_write_token(
    client_config_path: str | Path,
    production_write_token_path: str | Path,
    generation_state_path: str | Path,
    production_read_token_path: str | Path,
    test_write_token_path: str | Path,
    target: ProductionWriteTargetConfig,
    confirmation: str,
    *,
    authorizer: ProductionWriteOAuthAuthorizer | None,
    issued_at: datetime,
) -> ProductionWriteTokenAuthorizationResult:
    """Run one injected fake flow; the default path is deliberately hard-off."""

    from tridentine_calendar_google_sync.production_write_token_io import (
        validate_production_write_token_path_set,
        write_production_write_token_bundle,
    )

    validate_production_write_target_config(target)
    verify_production_write_token_authorization_confirmation(target, confirmation)
    validate_production_write_token_path_set(
        production_write_token_path=production_write_token_path,
        generation_state_path=generation_state_path,
        production_read_token_path=production_read_token_path,
        test_write_token_path=test_write_token_path,
        client_config_path=client_config_path,
        write_token_exists=False,
        generation_state_exists=False,
    )
    if authorizer is None:
        raise ProductionWriteTokenAuthorizationError(
            "production_live_oauth_disabled_in_phase_6d0",
            "Live Production OAuth is unavailable in Phase 6D.0",
        )
    if authorizer.mock_only is not True or authorizer.live_capable is not False:
        raise ProductionWriteTokenAuthorizationError(
            "production_live_oauth_disabled_in_phase_6d0",
            "Only injected mock OAuth is permitted in Phase 6D.0",
        )
    client = _oauth_client_material(client_config_path)
    try:
        credentials = authorizer.authorize(client, PRODUCTION_WRITE_SCOPES)
    except ProductionWriteTokenError:
        raise
    except Exception as exc:
        raise ProductionWriteTokenAuthorizationError(
            "production_write_token_authorization_failed",
            "Production write-token mock authorization failed safely",
        ) from exc
    if (
        authorizer.browser_launch_count != 1
        or authorizer.oauth_attempt_count != 1
        or authorizer.calendar_api_call_count != 0
    ):
        raise ProductionWriteTokenAuthorizationError(
            "production_write_token_authorization_accounting_invalid",
            "Production write-token mock authorization accounting is invalid",
        )
    _validate_oauth_credentials(credentials, now=issued_at, client=client)
    state = build_initial_production_write_token_generation_state(target, issued_at=issued_at)
    token = _token_from_credentials(credentials, state)
    verify_production_write_authorized_user_token(token, state, target)
    write_production_write_token_bundle(
        token,
        production_write_token_path,
        state,
        generation_state_path,
    )
    return ProductionWriteTokenAuthorizationResult(token=token, generation_state=state)


def _load_production_write_credential_session(
    production_write_token_path: str | Path,
    generation_state_path: str | Path,
    production_read_token_path: str | Path,
    test_write_token_path: str | Path,
    target: ProductionWriteTargetConfig,
    *,
    now: datetime,
    refresher: ProductionWriteTokenRefresher | None = None,
) -> ProductionWriteCredentialSession:
    """Load an exact-role token and perform at most one injected fake refresh."""

    from tridentine_calendar_google_sync.production_write_token_io import (
        load_production_write_authorized_user_token,
        load_production_write_token_generation_state,
        validate_production_write_token_path_set,
        write_production_write_authorized_user_token,
    )

    if not _is_utc(now):
        raise ProductionWriteTokenConfigError(
            "production_write_token_clock_invalid",
            "Production write-token validation time must be UTC",
        )
    validate_production_write_token_path_set(
        production_write_token_path=production_write_token_path,
        generation_state_path=generation_state_path,
        production_read_token_path=production_read_token_path,
        test_write_token_path=test_write_token_path,
        client_config_path=None,
        write_token_exists=True,
        generation_state_exists=True,
    )
    state = load_production_write_token_generation_state(generation_state_path)
    token = load_production_write_authorized_user_token(production_write_token_path)
    verify_production_write_authorized_user_token(token, state, target)
    if token.expiry > now:
        return ProductionWriteCredentialSession(
            token=token,
            generation_state=state,
            refresh_count=0,
        )
    if refresher is None:
        raise ProductionWriteTokenRefreshError(
            "production_write_token_refresh_unavailable",
            "Expired Production write credentials cannot be refreshed",
        )
    if (
        refresher.mock_only is not True
        or refresher.live_capable is not False
        or refresher.browser_fallback_count != 0
    ):
        raise ProductionWriteTokenRefreshError(
            "production_write_token_refresh_adapter_unsafe",
            "Production write-token refresh adapter is unsafe",
        )
    try:
        refreshed = refresher.refresh(token, PRODUCTION_WRITE_SCOPES)
    except Exception as exc:
        raise ProductionWriteTokenRefreshError(
            "production_write_token_refresh_failed",
            "Production write-token refresh failed without browser fallback",
        ) from exc
    if refresher.refresh_attempt_count != 1 or refresher.calendar_api_call_count != 0:
        raise ProductionWriteTokenRefreshError(
            "production_write_token_refresh_accounting_invalid",
            "Production write-token refresh accounting is invalid",
        )
    _validate_oauth_credentials(refreshed, now=now)
    if not (
        hmac.compare_digest(refreshed.client_id, token.client_id)
        and hmac.compare_digest(refreshed.client_secret, token.client_secret)
        and refreshed.token_uri == token.token_uri
    ):
        raise ProductionWriteTokenRefreshError(
            "production_write_token_refresh_identity_mismatch",
            "Refreshed Production write credentials changed authorization identity",
        )
    refreshed_token = _token_from_credentials(refreshed, state)
    verify_production_write_authorized_user_token(refreshed_token, state, target)
    write_production_write_authorized_user_token(
        refreshed_token,
        production_write_token_path,
        overwrite=True,
    )
    return ProductionWriteCredentialSession(
        token=refreshed_token,
        generation_state=state,
        refresh_count=1,
    )


def prepare_production_write_rehearsal_credential_session(
    production_write_token_path: str | Path,
    generation_state_path: str | Path,
    production_read_token_path: str | Path,
    test_write_token_path: str | Path,
    target: ProductionWriteTargetConfig,
    confirmation: str,
    *,
    now: datetime,
    refresher: ProductionWriteTokenRefresher | None = None,
) -> ProductionWriteCredentialSession:
    """Verify exact read confirmation before any token load or refresh capability."""

    from tridentine_calendar_google_sync.production_write_token_rehearsal import (
        verify_production_write_token_rehearsal_confirmation,
    )

    validate_production_write_target_config(target)
    verify_production_write_token_rehearsal_confirmation(target, confirmation)
    return _load_production_write_credential_session(
        production_write_token_path,
        generation_state_path,
        production_read_token_path,
        test_write_token_path,
        target,
        now=now,
        refresher=refresher,
    )


__all__ = [
    "ProductionWriteTokenAuthorizationError",
    "ProductionWriteTokenConfigError",
    "ProductionWriteTokenError",
    "ProductionWriteTokenRefreshError",
    "authorize_production_write_token",
    "build_initial_production_write_token_generation_state",
    "build_next_production_write_token_generation_state",
    "calculate_production_write_token_generation_state_hash",
    "prepare_production_write_rehearsal_credential_session",
    "private_production_write_token_generation_state_data",
    "production_write_token_authorization_challenge",
    "validate_production_token_role",
    "validate_production_write_scopes",
    "verify_production_write_authorized_user_token",
    "verify_production_write_token_authorization_confirmation",
    "verify_production_write_token_generation_state",
    "verify_production_write_token_generation_transition",
]
