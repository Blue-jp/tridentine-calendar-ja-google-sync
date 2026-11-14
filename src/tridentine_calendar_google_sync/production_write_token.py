"""Mock-only Production write-token authorization and refresh foundation."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager, ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from os import getpid
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Literal, NoReturn, Protocol, final

from tridentine_calendar_google_sync import production_write_token_operation_record as records
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
    ProductionWriteGrantedScopeEvidence,
    ProductionWriteGrantEvidenceOrigin,
    ProductionWriteOAuthAuthorizer,
    ProductionWriteOAuthClientMaterial,
    ProductionWriteOAuthCredentials,
    ProductionWriteTokenAuthorizationResult,
    ProductionWriteTokenGenerationState,
    ProductionWriteTokenRefresher,
)

if TYPE_CHECKING:
    from tridentine_calendar_google_sync.production_write_token_io import (
        ProductionWriteTokenIOError,
    )


_GENERATION_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:production-write-token-generation:v1\x00"
)

_PROVIDER_EVIDENCE_ORIGINS = frozenset(
    {
        ProductionWriteGrantEvidenceOrigin.FRESH_AUTHORIZATION_RESPONSE,
        ProductionWriteGrantEvidenceOrigin.FRESH_REFRESH_RESPONSE,
    }
)
_TEST_EVIDENCE_ORIGINS = frozenset(
    {
        ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_AUTHORIZATION_RESPONSE,
        ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
    }
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


class ProductionWriteTokenRefreshPersistenceError(ProductionWriteTokenRefreshError):
    """Validated refresh response could not be stored; no session or recovery approval."""

    def __init__(self, *, publication_possible: bool | None = None) -> None:
        super().__init__(
            "production_write_token_refresh_persistence_failed",
            "Refreshed Production write credentials could not be persisted safely. "
            "Token state may require reconciliation; do not retry or remove files automatically.",
        )
        # These describe this ordinary-exception path, not durable provider/file state.
        self.refresh_completed = True
        self.persistence_attempted = True
        self.publication_possible = (
            publication_possible if type(publication_possible) is bool else None
        )


class ProductionWriteTokenRefreshPrewriteError(ProductionWriteTokenRefreshError):
    """Refresh completed, but reloaded inputs could not be matched before saving."""

    def __init__(self) -> None:
        super().__init__(
            "production_write_token_refresh_prewrite_unverified",
            "Production token/state inputs could not be reverified after refresh. "
            "No persistence was attempted by this call; do not retry, remove, or restore "
            "files automatically. Reconciliation is required.",
        )
        self.refresh_completed = True
        self.persistence_attempted = False
        # This is only evidence that this call did not enter its save function.
        # It says nothing about changes made by the provider or another process.
        self.publication_possible = False


class ProductionWriteTokenSessionLockError(ProductionWriteTokenRefreshError):
    """No session after a lock failure; files/provider state may already have changed."""

    def __init__(self, *, busy: bool = False) -> None:
        super().__init__(
            "production_write_token_session_busy"
            if busy
            else "production_write_token_session_lock_unverified",
            "Production credential session could not retain its directory locks. "
            "Do not proceed unlocked, retry, remove, or restore files automatically. "
            "A refresh or persistence may already have occurred; reconciliation may be required.",
        )


@contextmanager
def _production_write_session_lock(
    token_path: str | Path, state_path: str | Path
) -> Iterator[Callable[[], None]]:
    """Lock both existing parents before content reads; Windows retains its old path.

    Session loaders and new-pair publication share this Linux protocol. No claim
    covers other writers, replaced directories, fork/dup, or post-check changes.
    The yielded checkpoint never catches exceptions from the caller's body.
    """
    if os.name == "nt":
        yield lambda: None

    else:
        from tridentine_calendar_google_sync._posix_private_lock import (
            PosixPrivateLockError,
            _PrivateDirectoryLock,
            acquire_posix_private_directory_lock,
        )

        with ExitStack() as stack:
            held: list[_PrivateDirectoryLock] = []
            try:
                paths = (Path(token_path), Path(state_path))
                if any(
                    not path.is_absolute()
                    or path.anchor == "//"
                    or ".." in path.parts
                    or "\x00" in str(path)
                    for path in paths
                ):
                    raise ValueError
                # One acquisition per distinct lexical parent, at most two. No wait
                # or retry; aliases of an already-locked inode fail rather than skip.
                for parent in sorted({path.parent for path in paths}, key=os.fspath):
                    held.append(stack.enter_context(acquire_posix_private_directory_lock(parent)))
            except Exception as exc:
                busy = (
                    isinstance(exc, PosixPrivateLockError)
                    and exc.code == "posix_directory_lock_busy"
                )
                raise ProductionWriteTokenSessionLockError(busy=busy) from None

            def revalidate() -> None:
                try:
                    for lock in held:
                        lock.revalidate()
                except Exception:
                    raise ProductionWriteTokenSessionLockError() from None

            revalidate()
            yield revalidate
            # No extra exit-time check here: it could mask Unit 4I/4J failures. The
            # session function checks before every normal return. ExitStack closes
            # all acquired contexts on return, ordinary error or cancellation.


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


def _build_production_write_granted_scope_evidence(
    raw_scope_tokens: object,
    *,
    origin: ProductionWriteGrantEvidenceOrigin,
    observed_at: datetime,
) -> ProductionWriteGrantedScopeEvidence:
    """Build evidence only from an explicitly present fresh response scope field."""

    if (
        isinstance(raw_scope_tokens, (str, bytes))
        or not isinstance(raw_scope_tokens, Sequence)
        or any(not isinstance(scope, str) for scope in raw_scope_tokens)
    ):
        raise ProductionWriteTokenConfigError(
            "unsafe_production_write_grant_evidence",
            "Production write granted-scope evidence is missing or malformed",
        )
    tokens = tuple(raw_scope_tokens)
    try:
        return ProductionWriteGrantedScopeEvidence(
            origin=origin,
            response_scope_field_present=True,
            raw_scope_tokens=tokens,
            granted_scopes=tokens,
            observed_at=observed_at,
        )
    except (TypeError, ValueError) as exc:
        raise ProductionWriteTokenConfigError(
            "unsafe_production_write_grant_evidence",
            "Production write granted-scope evidence is missing or malformed",
        ) from exc


def _fresh_authorization_grant_evidence(
    provider_granted_scopes: object,
    *,
    observed_at: datetime,
) -> ProductionWriteGrantedScopeEvidence:
    """Convert the public post-authorization granted-scopes value without fallback."""

    return _build_production_write_granted_scope_evidence(
        provider_granted_scopes,
        origin=ProductionWriteGrantEvidenceOrigin.FRESH_AUTHORIZATION_RESPONSE,
        observed_at=observed_at,
    )


def _fresh_refresh_grant_evidence(
    provider_granted_scopes: object,
    *,
    observed_at: datetime,
) -> ProductionWriteGrantedScopeEvidence:
    """Convert a fresh-instance post-refresh granted-scopes value without fallback."""

    return _build_production_write_granted_scope_evidence(
        provider_granted_scopes,
        origin=ProductionWriteGrantEvidenceOrigin.FRESH_REFRESH_RESPONSE,
        observed_at=observed_at,
    )


def _validate_granted_scope_evidence(
    evidence: object,
    *,
    required_origin: ProductionWriteGrantEvidenceOrigin,
    observed_at: datetime | None = None,
) -> ProductionWriteGrantedScopeEvidence:
    if not isinstance(evidence, ProductionWriteGrantedScopeEvidence) or not (
        evidence.origin is required_origin
        and evidence.response_scope_field_present is True
        and evidence.raw_scope_tokens == PRODUCTION_WRITE_SCOPES
        and evidence.granted_scopes == PRODUCTION_WRITE_SCOPES
        and evidence.raw_scope_tokens == evidence.granted_scopes
        and _is_utc(evidence.observed_at)
        and (observed_at is None or evidence.observed_at == observed_at)
    ):
        raise ProductionWriteTokenConfigError(
            "unsafe_production_write_grant_evidence",
            "Production write granted-scope evidence is missing, stale, or unsafe",
        )
    return evidence


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
    required_evidence_origin: ProductionWriteGrantEvidenceOrigin,
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
    _validate_granted_scope_evidence(
        getattr(credentials, "grant_evidence", None),
        required_origin=required_evidence_origin,
        observed_at=now,
    )
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
        grant_evidence=credentials.grant_evidence,
        expiry=credentials.expiry,
    )


def _verify_production_write_authorized_user_token(
    token: ProductionWriteAuthorizedUserToken,
    state: ProductionWriteTokenGenerationState,
    target: ProductionWriteTargetConfig,
    *,
    allowed_evidence_origins: frozenset[ProductionWriteGrantEvidenceOrigin],
) -> None:
    """Verify role, exact scope, target, and opaque generation without token hashing."""

    validate_production_write_target_config(target)
    validate_production_token_role(token.role)
    validate_production_write_scopes(token.scopes)
    evidence = getattr(token, "grant_evidence", None)
    if (
        not isinstance(evidence, ProductionWriteGrantedScopeEvidence)
        or evidence.origin not in allowed_evidence_origins
    ):
        raise ProductionWriteTokenConfigError(
            "production_write_token_grant_evidence_origin_mismatch",
            "Production write-token grant evidence origin did not match",
        )
    _validate_granted_scope_evidence(
        evidence,
        required_origin=evidence.origin,
    )
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


def verify_production_write_authorized_user_token(
    token: ProductionWriteAuthorizedUserToken,
    state: ProductionWriteTokenGenerationState,
    target: ProductionWriteTargetConfig,
) -> None:
    """Accept only provider-derived authorization or refresh evidence."""

    _verify_production_write_authorized_user_token(
        token,
        state,
        target,
        allowed_evidence_origins=_PROVIDER_EVIDENCE_ORIGINS,
    )


def _verify_mock_production_write_authorized_user_token(
    token: ProductionWriteAuthorizedUserToken,
    state: ProductionWriteTokenGenerationState,
    target: ProductionWriteTargetConfig,
) -> None:
    _verify_production_write_authorized_user_token(
        token,
        state,
        target,
        allowed_evidence_origins=_TEST_EVIDENCE_ORIGINS,
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
    issued_at: datetime,
) -> NoReturn:
    """Keep the operational OAuth entry point hard-off with no injectable trust root."""

    del (
        client_config_path,
        production_write_token_path,
        generation_state_path,
        production_read_token_path,
        test_write_token_path,
        target,
        confirmation,
        issued_at,
    )
    raise ProductionWriteTokenAuthorizationError(
        "production_live_oauth_disabled_in_phase_6d0",
        "Live Production OAuth is unavailable in Phase 6D.0",
    )


def authorize_production_write_token_mock(
    client_config_path: str | Path,
    production_write_token_path: str | Path,
    generation_state_path: str | Path,
    production_read_token_path: str | Path,
    test_write_token_path: str | Path,
    target: ProductionWriteTargetConfig,
    confirmation: str,
    *,
    test_authorizer: ProductionWriteOAuthAuthorizer,
    issued_at: datetime,
) -> ProductionWriteTokenAuthorizationResult:
    """Run one explicit test-only flow with test-origin evidence."""

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
    if (
        getattr(test_authorizer, "mock_only", None) is not True
        or getattr(test_authorizer, "live_capable", None) is not False
    ):
        raise ProductionWriteTokenAuthorizationError(
            "production_live_oauth_disabled_in_phase_6d0",
            "Only injected mock OAuth is permitted in Phase 6D.0",
        )
    client = _oauth_client_material(client_config_path)
    try:
        credentials = test_authorizer.authorize(client, PRODUCTION_WRITE_SCOPES)
    except ProductionWriteTokenError:
        raise
    except Exception as exc:
        raise ProductionWriteTokenAuthorizationError(
            "production_write_token_authorization_failed",
            "Production write-token mock authorization failed safely",
        ) from exc
    if (
        test_authorizer.browser_launch_count != 1
        or test_authorizer.oauth_attempt_count != 1
        or test_authorizer.calendar_api_call_count != 0
    ):
        raise ProductionWriteTokenAuthorizationError(
            "production_write_token_authorization_accounting_invalid",
            "Production write-token mock authorization accounting is invalid",
        )
    _validate_oauth_credentials(
        credentials,
        now=issued_at,
        required_evidence_origin=(
            ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_AUTHORIZATION_RESPONSE
        ),
        client=client,
    )
    state = build_initial_production_write_token_generation_state(target, issued_at=issued_at)
    token = _token_from_credentials(credentials, state)
    _verify_mock_production_write_authorized_user_token(token, state, target)
    write_production_write_token_bundle(
        token,
        production_write_token_path,
        state,
        generation_state_path,
    )
    return ProductionWriteTokenAuthorizationResult(token=token, generation_state=state)


class _CredentialSessionUseError(ValueError):
    """Fixed refusal for an invalid private ownership invocation."""

    def __init__(self) -> None:
        super().__init__("Invalid credential-session ownership")


class _NoCredentialSessionCopy:
    __slots__ = ()

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise _CredentialSessionUseError()

    def __repr__(self) -> str:
        return "<private credential-session ownership>"

    def __copy__(self) -> NoReturn:
        raise _CredentialSessionUseError()

    def __deepcopy__(self, _memo: dict[int, object]) -> NoReturn:
        raise _CredentialSessionUseError()

    def __reduce_ex__(self, _protocol: object, /) -> NoReturn:
        raise _CredentialSessionUseError()


class _CredentialSessionPhase(StrEnum):
    NEW = "new"
    ENTERING = "entering"
    ACTIVE = "active"
    USED = "used"
    CLOSED = "closed"


class _CredentialSessionWriter(Protocol):
    def __call__(
        self,
        token: ProductionWriteAuthorizedUserToken,
        path: str | Path,
        *,
        expected_token: ProductionWriteAuthorizedUserToken,
    ) -> Path: ...


@dataclass(init=False, frozen=True, repr=False, eq=False, slots=True)
class _CredentialSessionRequest(_NoCredentialSessionCopy):
    production_write_token_path: str | Path
    generation_state_path: str | Path
    production_read_token_path: str | Path
    test_write_token_path: str | Path
    target: ProductionWriteTargetConfig
    now: datetime
    evidence_mode: Literal["provider", "test"]
    refresher: ProductionWriteTokenRefresher | None
    _context: _CredentialSessionScopeContext


@dataclass(init=False, repr=False, eq=False, slots=True)
class _CredentialSessionOwner(_NoCredentialSessionCopy):
    _issuer: _CredentialSessionScopeContext


@dataclass(init=False, repr=False, eq=False, slots=True)
class _CredentialSessionScopeContext(
    _NoCredentialSessionCopy, AbstractContextManager[_CredentialSessionOwner]
):
    _factory_identity: _CredentialSessionScopeContext
    _request: _CredentialSessionRequest
    _snapshot: tuple[object, ...]
    _pid: int
    _thread: threading.Thread
    _pid_probe: Callable[[], int]
    _thread_probe: Callable[[], threading.Thread]
    _phase: _CredentialSessionPhase
    _owner: _CredentialSessionOwner | None
    _lock_context: AbstractContextManager[Callable[[], None]] | None
    _checkpoint: Callable[[], None] | None
    _busy: bool
    _used: bool
    _load_state: Callable[[str | Path], ProductionWriteTokenGenerationState]
    _load_token: Callable[[str | Path], ProductionWriteAuthorizedUserToken]
    _persist: _CredentialSessionWriter
    _render_state: Callable[[ProductionWriteTokenGenerationState], str]
    _render_token: Callable[[ProductionWriteAuthorizedUserToken], str]
    _io_error: type[ProductionWriteTokenIOError]

    def _check_identity(self) -> None:
        if type(self) is not _CredentialSessionScopeContext:
            raise _CredentialSessionUseError()
        try:
            # Partial manual construction must fail with the same fixed refusal.
            _ = (
                self._request,
                self._snapshot,
                self._owner,
                self._lock_context,
                self._checkpoint,
            )
            valid = (
                self._factory_identity is self
                and self._pid == getpid()
                and self._thread is threading.current_thread()
                and self._thread.is_alive()
                and type(self._phase) is _CredentialSessionPhase
                and type(self._busy) is bool
                and type(self._used) is bool
            )
        except AttributeError:
            raise _CredentialSessionUseError() from None
        if not valid:
            raise _CredentialSessionUseError()

    def _check_request(self, request: object) -> None:
        if type(request) is not _CredentialSessionRequest:
            raise _CredentialSessionUseError()
        try:
            retained = (
                request.production_write_token_path,
                request.generation_state_path,
                request.production_read_token_path,
                request.test_write_token_path,
                request.target,
                request.now,
                request.evidence_mode,
                request.refresher,
            )
            valid = (
                self._request is request
                and request._context is self
                and len(self._snapshot) == len(retained)
                and all(
                    current is original
                    for current, original in zip(retained, self._snapshot, strict=True)
                )
            )
        except AttributeError:
            raise _CredentialSessionUseError() from None
        if not valid:
            raise _CredentialSessionUseError()

    def __enter__(self) -> _CredentialSessionOwner:
        try:
            self._check_identity()
        except _CredentialSessionUseError:
            # An unaccepted foreign or nested use cannot revoke its genuine owner.
            raise
        except BaseException:
            try:
                first_entry = (
                    type(self) is _CredentialSessionScopeContext
                    and self._factory_identity is self
                    and self._phase is _CredentialSessionPhase.NEW
                )
            except AttributeError:
                raise _CredentialSessionUseError() from None
            if first_entry:
                self._phase = _CredentialSessionPhase.CLOSED
            raise
        if self._phase is not _CredentialSessionPhase.NEW:
            # Foreign or nested entry does not revoke the legitimate owner.
            raise _CredentialSessionUseError()
        self._phase = _CredentialSessionPhase.ENTERING
        entered: AbstractContextManager[Callable[[], None]] | None = None
        try:
            self._check_request(self._request)
            lock_context = _production_write_session_lock(
                self._request.production_write_token_path, self._request.generation_state_path
            )
            checkpoint = lock_context.__enter__()
            entered = lock_context
            self._lock_context = lock_context
            self._checkpoint = checkpoint
            self._check_identity()
            self._check_request(self._request)
            owner = _issue_credential_session_owner(self)
            self._owner = owner
            self._phase = _CredentialSessionPhase.ACTIVE
            return owner
        except BaseException as error:
            # Entry failure is terminal. Only a successful inner entry is ours to unwind.
            self._phase = _CredentialSessionPhase.CLOSED
            self._owner = None
            self._lock_context = None
            self._checkpoint = None
            if entered is not None:
                entered.__exit__(type(error), error, error.__traceback__)
            raise

    def _revalidate(self, owner: object, request: object) -> None:
        if _require_session_owner(owner, request) is not self or not self._busy:
            raise _CredentialSessionUseError()
        checkpoint = self._checkpoint
        if checkpoint is None:
            raise _CredentialSessionUseError()
        checkpoint()

    def _check_exit_actor(self) -> None:
        if type(self) is not _CredentialSessionScopeContext:
            raise _CredentialSessionUseError()
        try:
            valid = (
                self._factory_identity is self
                and self._pid_probe() == self._pid
                and self._thread_probe() is self._thread
                and self._thread.is_alive()
            )
        except AttributeError:
            raise _CredentialSessionUseError() from None
        if not valid:
            raise _CredentialSessionUseError()

    def _exit_owned_context(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        # The internally captured probes also protect direct private cleanup calls.
        self._check_exit_actor()
        try:
            valid = (
                self._phase in {_CredentialSessionPhase.ACTIVE, _CredentialSessionPhase.USED}
                and self._lock_context is not None
                and not self._busy
            )
        except AttributeError:
            raise _CredentialSessionUseError() from None
        if not valid or self._lock_context is None:
            raise _CredentialSessionUseError()
        lock_context, self._lock_context = self._lock_context, None
        self._phase = _CredentialSessionPhase.CLOSED
        self._owner = None
        self._checkpoint = None
        # Delegate the original exception triple and existing cleanup precedence.
        return lock_context.__exit__(exc_type, exc, traceback)

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        try:
            self._check_identity()
        except _CredentialSessionUseError:
            # A fixed foreign/nested misuse refusal must not release its owner.
            raise
        except BaseException:
            # Unexpected local probe failure cannot leave a reusable held owner.
            # Cleanup proceeds only if the captured probes still prove its actor.
            self._exit_owned_context(exc_type, exc, traceback)
            raise
        return self._exit_owned_context(exc_type, exc, traceback)


def _issue_credential_session_owner(
    context: _CredentialSessionScopeContext,
) -> _CredentialSessionOwner:
    context._check_identity()
    context._check_request(context._request)
    if (
        context._phase is not _CredentialSessionPhase.ENTERING
        or context._lock_context is None
        or context._checkpoint is None
        or context._owner is not None
    ):
        raise _CredentialSessionUseError()
    owner = object.__new__(_CredentialSessionOwner)
    owner._issuer = context
    return owner


def _require_session_owner(
    owner: object, request: object
) -> _CredentialSessionScopeContext | _StartLinkedSessionContext:
    if type(owner) is _StartLinkedSessionOwner:
        return _require_start_linked_session_owner(owner, request)
    if type(owner) is not _CredentialSessionOwner:
        raise _CredentialSessionUseError()
    try:
        context = owner._issuer
        if type(context) is not _CredentialSessionScopeContext or context._owner is not owner:
            raise _CredentialSessionUseError()
        context._check_identity()
        context._check_request(request)
        if (
            context._phase is not _CredentialSessionPhase.ACTIVE
            or context._lock_context is None
            or context._checkpoint is None
        ):
            raise _CredentialSessionUseError()
        return context
    except AttributeError:
        raise _CredentialSessionUseError() from None


def _credential_session_scope(
    production_write_token_path: str | Path,
    generation_state_path: str | Path,
    production_read_token_path: str | Path,
    test_write_token_path: str | Path,
    target: ProductionWriteTargetConfig,
    *,
    now: datetime,
    evidence_mode: Literal["provider", "test"],
    refresher: ProductionWriteTokenRefresher | None = None,
) -> _CredentialSessionScopeContext:
    """Bind this call's preflight, retained inputs and one future ownership entry."""

    from tridentine_calendar_google_sync.production_write_token_io import (
        ProductionWriteTokenIOError,
        load_production_write_authorized_user_token,
        load_production_write_token_generation_state,
        persist_refreshed_production_write_token,
        render_production_write_authorized_user_token_json,
        render_production_write_token_generation_state_json,
        validate_production_write_token_path_set,
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
    request = object.__new__(_CredentialSessionRequest)
    context = object.__new__(_CredentialSessionScopeContext)
    object.__setattr__(request, "production_write_token_path", production_write_token_path)
    object.__setattr__(request, "generation_state_path", generation_state_path)
    object.__setattr__(request, "production_read_token_path", production_read_token_path)
    object.__setattr__(request, "test_write_token_path", test_write_token_path)
    object.__setattr__(request, "target", target)
    object.__setattr__(request, "now", now)
    object.__setattr__(request, "evidence_mode", evidence_mode)
    object.__setattr__(request, "refresher", refresher)
    object.__setattr__(request, "_context", context)
    context._factory_identity = context
    context._request = request
    context._snapshot = (
        production_write_token_path,
        generation_state_path,
        production_read_token_path,
        test_write_token_path,
        target,
        now,
        evidence_mode,
        refresher,
    )
    context._pid = getpid()
    context._thread = threading.current_thread()
    context._pid_probe = getpid
    context._thread_probe = threading.current_thread
    context._phase = _CredentialSessionPhase.NEW
    context._owner = None
    context._lock_context = None
    context._checkpoint = None
    context._busy = False
    context._used = False
    # Capture the same delayed-import aliases before preflight/entry as the old loader.
    context._load_state = load_production_write_token_generation_state
    context._load_token = load_production_write_authorized_user_token
    context._persist = persist_refreshed_production_write_token
    context._render_state = render_production_write_token_generation_state_json
    context._render_token = render_production_write_authorized_user_token_json
    context._io_error = ProductionWriteTokenIOError
    return context


def _load_production_write_credential_session_held(
    owner: object, request: object
) -> ProductionWriteCredentialSession:
    """Consume one issued owner before credential effects; never acquire another lock."""

    scope = _require_session_owner(owner, request)
    if scope._busy or scope._used:
        raise _CredentialSessionUseError()

    def revalidate_session_lock() -> None:
        scope._revalidate(owner, request)

    try:
        scope._used = True
        scope._busy = True
        retained = scope._request
        production_write_token_path = retained.production_write_token_path
        generation_state_path = retained.generation_state_path
        target = retained.target
        now = retained.now
        evidence_mode = retained.evidence_mode
        refresher = retained.refresher
        load_production_write_token_generation_state = scope._load_state
        load_production_write_authorized_user_token = scope._load_token
        persist_refreshed_production_write_token = scope._persist
        render_production_write_token_generation_state_json = scope._render_state
        render_production_write_authorized_user_token_json = scope._render_token
        ProductionWriteTokenIOError = scope._io_error
        state = load_production_write_token_generation_state(generation_state_path)
        token = load_production_write_authorized_user_token(production_write_token_path)
        revalidate_session_lock()
        if evidence_mode == "provider":
            verify_production_write_authorized_user_token(token, state, target)
        else:
            _verify_mock_production_write_authorized_user_token(token, state, target)
        if token.expiry > now:
            revalidate_session_lock()
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
            getattr(refresher, "mock_only", None) is not True
            or getattr(refresher, "live_capable", None) is not False
            or getattr(refresher, "browser_fallback_count", None) != 0
        ):
            raise ProductionWriteTokenRefreshError(
                "production_write_token_refresh_adapter_unsafe",
                "Production write-token refresh adapter is unsafe",
            )
        revalidate_session_lock()
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
        required_refresh_origin = (
            ProductionWriteGrantEvidenceOrigin.FRESH_REFRESH_RESPONSE
            if evidence_mode == "provider"
            else ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE
        )
        _validate_oauth_credentials(
            refreshed,
            now=now,
            required_evidence_origin=required_refresh_origin,
        )
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
        if evidence_mode == "provider":
            verify_production_write_authorized_user_token(refreshed_token, state, target)
        else:
            _verify_mock_production_write_authorized_user_token(refreshed_token, state, target)
        revalidate_session_lock()
        # Re-read after refresh, through the existing role-specific loaders. This
        # detects an observed changed/missing/unsafe pair, not an atomic snapshot or
        # an inode/content-conditional replacement. Unit 4L separately binds token replacement.
        try:
            current_state = load_production_write_token_generation_state(generation_state_path)
            current_token = load_production_write_authorized_user_token(production_write_token_path)
            state_matches = hmac.compare_digest(
                render_production_write_token_generation_state_json(current_state).encode("utf-8"),
                render_production_write_token_generation_state_json(state).encode("utf-8"),
            )
            token_matches = hmac.compare_digest(
                render_production_write_authorized_user_token_json(current_token).encode("utf-8"),
                render_production_write_authorized_user_token_json(token).encode("utf-8"),
            )
            if not state_matches or not token_matches:
                raise ProductionWriteTokenRefreshPrewriteError()
        except Exception:
            raise ProductionWriteTokenRefreshPrewriteError() from None
        revalidate_session_lock()
        try:
            persist_refreshed_production_write_token(
                refreshed_token,
                production_write_token_path,
                expected_token=token,
            )
        except Exception as exc:
            # A failed save cannot establish that the previous token still exists,
            # or that a refreshed/rotated credential can safely be requested again.
            # Preserve explicit writer evidence; unspecified failures stay unknown.
            publication_possible = (
                exc.publication_possible if isinstance(exc, ProductionWriteTokenIOError) else None
            )
            raise ProductionWriteTokenRefreshPersistenceError(
                publication_possible=publication_possible
            ) from None
        revalidate_session_lock()
        return ProductionWriteCredentialSession(
            token=refreshed_token,
            generation_state=state,
            refresh_count=1,
        )
    finally:
        scope._busy = False
        scope._phase = _CredentialSessionPhase.USED


def _load_production_write_credential_session(
    production_write_token_path: str | Path,
    generation_state_path: str | Path,
    production_read_token_path: str | Path,
    test_write_token_path: str | Path,
    target: ProductionWriteTargetConfig,
    *,
    now: datetime,
    evidence_mode: Literal["provider", "test"],
    refresher: ProductionWriteTokenRefresher | None = None,
) -> ProductionWriteCredentialSession:
    """Load an exact-role token and perform at most one injected fake refresh."""

    context = _credential_session_scope(
        production_write_token_path,
        generation_state_path,
        production_read_token_path,
        test_write_token_path,
        target,
        now=now,
        evidence_mode=evidence_mode,
        refresher=refresher,
    )
    with context as owner:
        return _load_production_write_credential_session_held(owner, context._request)


def prepare_production_write_rehearsal_credential_session(
    production_write_token_path: str | Path,
    generation_state_path: str | Path,
    production_read_token_path: str | Path,
    test_write_token_path: str | Path,
    target: ProductionWriteTargetConfig,
    confirmation: str,
    *,
    now: datetime,
) -> ProductionWriteCredentialSession:
    """Temporarily refuse provider session preparation pending managed admission."""

    from tridentine_calendar_google_sync.production_write_token_rehearsal import (
        verify_production_write_token_rehearsal_confirmation,
    )

    validate_production_write_target_config(target)
    verify_production_write_token_rehearsal_confirmation(target, confirmation)
    raise ProductionWriteTokenConfigError(
        "production_write_token_provider_session_enforcement_unavailable",
        "Production write-token provider session preparation is unavailable",
    )


def prepare_production_write_rehearsal_credential_session_mock(
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
    """Explicit test-only credential preparation with no operational trust effect."""

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
        evidence_mode="test",
        refresher=refresher,
    )


_START_LINKED_INPUT_FIELDS = (
    "_input_token_path",
    "_input_state_path",
    "production_read_token_path",
    "test_write_token_path",
    "target",
    "now",
    "evidence_mode",
    "refresher",
    "confirmation",
    "binding",
    "operation",
)


@dataclass(init=False, frozen=True, repr=False, eq=False, slots=True)
class _StartLinkedSessionRequest(_NoCredentialSessionCopy):
    _input_token_path: str | Path
    _input_state_path: str | Path
    production_read_token_path: str | Path
    test_write_token_path: str | Path
    target: ProductionWriteTargetConfig
    now: datetime
    evidence_mode: Literal["test"]
    refresher: ProductionWriteTokenRefresher
    confirmation: str
    binding: records.SyntheticBinding
    operation: records.RecordOperation
    _context: _StartLinkedSessionContext
    _association: _LinkedParentAssociation | None

    @property
    def production_write_token_path(self) -> Path:
        return self._context.checked_token_path

    @property
    def generation_state_path(self) -> Path:
        return self._context.checked_state_path


@dataclass(init=False, frozen=True, repr=False, eq=False, slots=True)
class _LinkedParentAssociation(_NoCredentialSessionCopy):
    request: _StartLinkedSessionRequest
    parent: records._SharedStartSessionContext
    expected: records._LinkedExpected
    attempt_state: records._LinkedAttemptState


@dataclass(init=False, repr=False, eq=False, slots=True)
class _StartLinkedSessionOwner(_NoCredentialSessionCopy):
    _issuer: _StartLinkedSessionContext
    _child: records._LinkedSessionChild


@dataclass(init=False, repr=False, eq=False, slots=True)
class _StartLinkedSessionContext(_NoCredentialSessionCopy):
    _factory_identity: _StartLinkedSessionContext
    _request: _StartLinkedSessionRequest
    _snapshot: tuple[object, ...]
    _pid: int
    _thread: threading.Thread
    _association: _LinkedParentAssociation | None
    checked_token_path: Path
    checked_state_path: Path
    _phase: _CredentialSessionPhase
    _owner: _StartLinkedSessionOwner | None
    _busy: bool
    _used: bool
    _load_state: Callable[[str | Path], ProductionWriteTokenGenerationState]
    _load_token: Callable[[str | Path], ProductionWriteAuthorizedUserToken]
    _writer: _CredentialSessionWriter
    _render_state: Callable[[ProductionWriteTokenGenerationState], str]
    _render_token: Callable[[ProductionWriteAuthorizedUserToken], str]
    _io_error: type[ProductionWriteTokenIOError]

    def _revalidate(self, owner: object, request: object) -> None:
        if _require_start_linked_session_owner(owner, request) is not self or not self._busy:
            raise _CredentialSessionUseError()
        if type(owner) is not _StartLinkedSessionOwner:
            raise _CredentialSessionUseError()
        association = _linked_session_association(self, request)
        try:
            records._checkpoint_linked_child(
                owner._child,
                association.request,
                expected_parent=association.parent,
                expected=association.expected,
            )
        except records._ScopeUseError:
            raise _CredentialSessionUseError() from None
        except Exception:
            raise ProductionWriteTokenSessionLockError() from None

    def _persist(
        self,
        token: ProductionWriteAuthorizedUserToken,
        path: str | Path,
        *,
        expected_token: ProductionWriteAuthorizedUserToken,
    ) -> Path:
        return _persist_linked(self, token, path, expected_token=expected_token)


def _check_start_linked_request(
    context: object, request: object
) -> tuple[_StartLinkedSessionContext, _StartLinkedSessionRequest]:
    if (
        type(context) is not _StartLinkedSessionContext
        or type(request) is not _StartLinkedSessionRequest
    ):
        raise _CredentialSessionUseError()
    try:
        retained = tuple(getattr(request, name) for name in _START_LINKED_INPUT_FIELDS)
        valid = (
            context._factory_identity is context
            and context._request is request
            and request._context is context
            and context._pid == getpid()
            and context._thread is threading.current_thread()
            and context._thread.is_alive()
            and type(context._phase) is _CredentialSessionPhase
            and type(context._busy) is bool
            and type(context._used) is bool
            and request.evidence_mode == "test"
            and len(context._snapshot) == len(retained)
            and all(
                current is original
                for current, original in zip(retained, context._snapshot, strict=True)
            )
        )
    except AttributeError:
        raise _CredentialSessionUseError() from None
    if not valid:
        raise _CredentialSessionUseError()
    return context, request


def _linked_session_association(context: object, request: object) -> _LinkedParentAssociation:
    context, request = _check_start_linked_request(context, request)
    try:
        association = context._association
        if (
            type(association) is not _LinkedParentAssociation
            or request._association is not association
            or association.request is not request
            or type(association.parent) is not records._SharedStartSessionContext
            or type(association.expected) is not records._LinkedExpected
            or type(association.attempt_state) is not records._LinkedAttemptState
            or association.attempt_state.parent is not association.parent
            or association.attempt_state.request is not request
            or association.parent._attempt is not association.attempt_state
            or association.expected.checked_token_path is not context.checked_token_path
            or association.expected.checked_state_path is not context.checked_state_path
        ):
            raise _CredentialSessionUseError()
    except AttributeError:
        raise _CredentialSessionUseError() from None
    return association


def _seal_start_linked_parent(
    context: _StartLinkedSessionContext,
    request: _StartLinkedSessionRequest,
    parent: records._SharedStartSessionContext,
    expected: records._LinkedExpected,
    state: records._LinkedAttemptState,
) -> None:
    _check_start_linked_request(context, request)
    try:
        if (
            context._association is not None
            or request._association is not None
            or context._phase is not _CredentialSessionPhase.NEW
            or context._owner is not None
            or context._busy
            or context._used
            or type(expected) is not records._LinkedExpected
            or expected.checked_token_path is not context.checked_token_path
            or expected.checked_state_path is not context.checked_state_path
            or expected.binding != request.binding
            or expected.operation != request.operation
            or records._linked_attempt_state(
                parent, request, expected_parent=parent, expected=expected
            )
            is not state
        ):
            raise _CredentialSessionUseError()
    except (AttributeError, records._ScopeUseError):
        raise _CredentialSessionUseError() from None
    association = object.__new__(_LinkedParentAssociation)
    object.__setattr__(association, "request", request)
    object.__setattr__(association, "parent", parent)
    object.__setattr__(association, "expected", expected)
    object.__setattr__(association, "attempt_state", state)
    object.__setattr__(request, "_association", association)
    context._association = association


def _bound_linked_parent(context: object) -> records._SharedStartSessionContext:
    if type(context) is not _StartLinkedSessionContext:
        raise _CredentialSessionUseError()
    try:
        association = _linked_session_association(context, context._request)
        if context._phase is not _CredentialSessionPhase.NEW:
            raise _CredentialSessionUseError()
        records._verify_linked_parent_binding(
            association.parent, association.request, expected=association.expected
        )
    except (AttributeError, records._ScopeUseError):
        raise _CredentialSessionUseError() from None
    return association.parent


def _issue_start_linked_session_owner(
    context: _StartLinkedSessionContext, child: records._LinkedSessionChild
) -> _StartLinkedSessionOwner:
    if type(context) is not _StartLinkedSessionContext:
        raise _CredentialSessionUseError()
    try:
        association = _linked_session_association(context, context._request)
        if (
            context._phase is not _CredentialSessionPhase.NEW
            or context._owner is not None
            or context._busy
            or context._used
        ):
            raise _CredentialSessionUseError()
        records._require_linked_child(
            child,
            association.request,
            expected_parent=association.parent,
            expected=association.expected,
        )
    except (AttributeError, records._ScopeUseError):
        raise _CredentialSessionUseError() from None
    owner = object.__new__(_StartLinkedSessionOwner)
    owner._issuer = context
    owner._child = child
    context._owner = owner
    context._phase = _CredentialSessionPhase.ACTIVE
    return owner


def _require_start_linked_session_owner(
    owner: object, request: object
) -> _StartLinkedSessionContext:
    if type(owner) is not _StartLinkedSessionOwner:
        raise _CredentialSessionUseError()
    try:
        context = owner._issuer
        association = _linked_session_association(context, request)
        if context._owner is not owner or context._phase is not _CredentialSessionPhase.ACTIVE:
            raise _CredentialSessionUseError()
        records._require_linked_child(
            owner._child, request, expected_parent=association.parent, expected=association.expected
        )
    except (AttributeError, records._ScopeUseError):
        raise _CredentialSessionUseError() from None
    return context


def _start_linked_session_context(
    production_write_token_path: str | Path,
    generation_state_path: str | Path,
    production_read_token_path: str | Path,
    test_write_token_path: str | Path,
    target: ProductionWriteTargetConfig,
    confirmation: str,
    *,
    now: datetime,
    refresher: ProductionWriteTokenRefresher,
    binding: records.SyntheticBinding,
    operation: records.RecordOperation,
) -> _StartLinkedSessionContext:
    from tridentine_calendar_google_sync.production_write_token_io import (
        ProductionWriteTokenIOError,
        load_production_write_authorized_user_token,
        load_production_write_token_generation_state,
        persist_refreshed_production_write_token,
        render_production_write_authorized_user_token_json,
        render_production_write_token_generation_state_json,
        validate_production_write_token_path_set,
    )
    from tridentine_calendar_google_sync.production_write_token_rehearsal import (
        verify_production_write_token_rehearsal_confirmation,
    )

    validate_production_write_target_config(target)
    verify_production_write_token_rehearsal_confirmation(target, confirmation)
    if not records._linux_storage_available():
        raise records._ScopeFailure(records.RecordResult(records.RecordState.UNSUPPORTED_PLATFORM))
    if not _is_utc(now):
        raise ProductionWriteTokenConfigError(
            "production_write_token_clock_invalid",
            "Production write-token validation time must be UTC",
        )
    token_path, state_path, _, _, _ = validate_production_write_token_path_set(
        production_write_token_path=production_write_token_path,
        generation_state_path=generation_state_path,
        production_read_token_path=production_read_token_path,
        test_write_token_path=test_write_token_path,
        client_config_path=None,
        write_token_exists=True,
        generation_state_exists=True,
    )
    browser_count = getattr(refresher, "browser_fallback_count", None)
    if (
        getattr(refresher, "mock_only", None) is not True
        or getattr(refresher, "live_capable", None) is not False
        or type(browser_count) is not int
        or browser_count != 0
        or not callable(getattr(refresher, "refresh", None))
    ):
        raise ProductionWriteTokenRefreshError(
            "production_write_token_refresh_adapter_unsafe",
            "Production write-token refresh adapter is unsafe",
        )
    if not records._valid_binding(binding) or not records._valid_operation(operation):
        raise records._ScopeUseError()
    binding_snapshot = records.SyntheticBinding(
        binding.directory,
        binding.storage_ref,
        binding.pair_ref,
        binding.token_slot,
        binding.state_slot,
    )
    operation_snapshot = records.RecordOperation(
        operation.operation_id, operation.predecessor_id, operation.kind
    )
    expected = records._LinkedExpected(binding_snapshot, operation_snapshot, token_path, state_path)
    if not records._valid_linked_layout(expected):
        raise records._ScopeUseError()

    request = object.__new__(_StartLinkedSessionRequest)
    context = object.__new__(_StartLinkedSessionContext)
    retained = (
        production_write_token_path,
        generation_state_path,
        production_read_token_path,
        test_write_token_path,
        target,
        now,
        "test",
        refresher,
        confirmation,
        binding,
        operation,
    )
    for name, value in zip(_START_LINKED_INPUT_FIELDS, retained, strict=True):
        object.__setattr__(request, name, value)
    object.__setattr__(request, "_context", context)
    object.__setattr__(request, "_association", None)
    context._factory_identity = context
    context._request = request
    context._snapshot = retained
    context._pid = getpid()
    context._thread = threading.current_thread()
    context._association = None
    context.checked_token_path = token_path
    context.checked_state_path = state_path
    context._phase = _CredentialSessionPhase.NEW
    context._owner = None
    context._busy = False
    context._used = False
    context._load_state = load_production_write_token_generation_state
    context._load_token = load_production_write_authorized_user_token
    context._writer = persist_refreshed_production_write_token
    context._render_state = render_production_write_token_generation_state_json
    context._render_token = render_production_write_authorized_user_token_json
    context._io_error = ProductionWriteTokenIOError
    parent = records._shared_start_session_scope(
        binding_snapshot, operation_snapshot, request, token_path=token_path, state_path=state_path
    )
    records._verify_linked_parent_binding(parent, request, expected=expected)
    state = records._linked_attempt_state(
        parent, request, expected_parent=parent, expected=expected
    )
    _seal_start_linked_parent(context, request, parent, expected, state)
    return context


def _classify_linked_session_failure(error: Exception) -> records._SessionFailureClass:
    kind = type(error)
    if kind is ProductionWriteTokenRefreshPersistenceError:
        return records._SessionFailureClass.PERSISTENCE
    if kind is ProductionWriteTokenRefreshPrewriteError:
        return records._SessionFailureClass.PREWRITE
    if kind is ProductionWriteTokenSessionLockError:
        return records._SessionFailureClass.LOCK
    if kind is ProductionWriteTokenRefreshError:
        return records._SessionFailureClass.REFRESH
    return records._SessionFailureClass.SESSION_OTHER


def _raise_linked_cancellation(error: BaseException) -> NoReturn:
    # Preserve the selected object and Python's normal implicit chaining.
    raise error


def _annotate_linked_writer(
    association: _LinkedParentAssociation, step: records._DiagnosticStep
) -> bool:
    state = association.attempt_state
    try:
        records._copy_linked_publication_annotations(
            association.parent,
            association.request,
            expected_parent=association.parent,
            expected=association.expected,
        )
    except Exception as diagnostic:
        state.writer_diagnostic = diagnostic
        records._mark_linked_diagnostic_failure(state.facts, step, "ordinary")
        return False
    except BaseException as diagnostic:
        if state.first_cancel is None:
            state.first_cancel = diagnostic
            state.facts.first_cancel_phase = "annotation"
        records._mark_linked_diagnostic_failure(state.facts, step, "cancellation")
        _raise_linked_cancellation(state.first_cancel)
    return True


def _persist_linked(
    context: _StartLinkedSessionContext,
    token: ProductionWriteAuthorizedUserToken,
    path: str | Path,
    *,
    expected_token: ProductionWriteAuthorizedUserToken,
) -> Path:
    if _require_start_linked_session_owner(context._owner, context._request) is not context:
        raise _CredentialSessionUseError()
    association = _linked_session_association(context, context._request)
    state = association.attempt_state
    facts = state.facts
    if not context._busy or facts.logical_save_called:
        raise _CredentialSessionUseError()
    facts.logical_save_called = True
    facts.writer_phase = "not_called"
    facts.credential_publication = False
    if not _annotate_linked_writer(association, "pre_writer"):
        raise context._io_error(
            "production_write_token_linked_diagnostic_failed",
            "START-linked persistence diagnostics failed",
            publication_possible=False,
        )
    facts.writer_phase = "call_started"
    facts.credential_publication = None
    try:
        result = context._writer(token, path, expected_token=expected_token)
    except BaseException as writer_error:
        state.writer_error = writer_error
        facts.writer_failure_kind = (
            "ordinary" if isinstance(writer_error, Exception) else "cancellation"
        )
        facts.writer_phase = "raised"
        if not isinstance(writer_error, Exception) and state.first_cancel is None:
            state.first_cancel = writer_error
            facts.first_cancel_phase = "writer"
        if isinstance(writer_error, context._io_error):
            publication = writer_error.publication_possible
            facts.credential_publication = publication if type(publication) is bool else None
        _annotate_linked_writer(association, "writer_raised")
        if state.first_cancel is not None and state.first_cancel is not writer_error:
            _raise_linked_cancellation(state.first_cancel)
        raise
    facts.writer_phase = "returned"
    facts.credential_publication = True
    if not _annotate_linked_writer(association, "writer_returned"):
        raise context._io_error(
            "production_write_token_linked_diagnostic_failed",
            "START-linked persistence diagnostics failed",
            publication_possible=True,
        )
    return result


def _prepare_start_linked_session_mock(
    production_write_token_path: str | Path,
    generation_state_path: str | Path,
    production_read_token_path: str | Path,
    test_write_token_path: str | Path,
    target: ProductionWriteTargetConfig,
    confirmation: str,
    *,
    now: datetime,
    refresher: ProductionWriteTokenRefresher,
    binding: records.SyntheticBinding,
    operation: records.RecordOperation,
) -> ProductionWriteCredentialSession:
    """Use one retained START under a shared lock for this synthetic request."""
    context = _start_linked_session_context(
        production_write_token_path,
        generation_state_path,
        production_read_token_path,
        test_write_token_path,
        target,
        confirmation,
        now=now,
        refresher=refresher,
        binding=binding,
        operation=operation,
    )
    parent = _bound_linked_parent(context)
    association = _linked_session_association(context, context._request)
    request, state, expected = association.request, association.attempt_state, association.expected
    facts = state.facts
    candidate: ProductionWriteCredentialSession | None = None
    try:
        with parent:
            records._create_linked_start(parent, request, expected_parent=parent, expected=expected)
            try:
                with records._linked_session_phase(
                    parent, request, expected_parent=parent, expected=expected
                ) as child:
                    owner = _issue_start_linked_session_owner(context, child)
                    try:
                        candidate = _load_production_write_credential_session_held(owner, request)
                    except BaseException as error:
                        state.session_body_triple = (type(error), error, error.__traceback__)
                        if isinstance(error, Exception):
                            if state.primary is None:
                                state.primary = error
                                facts.first_ordinary_domain = "session"
                                facts.session_failure = records._SessionFailureClass.SESSION_OTHER
                        elif state.first_cancel is None:
                            state.first_cancel = error
                            facts.first_cancel_phase = "session"
                        step: records._DiagnosticStep = "initial"
                        try:
                            records._copy_linked_failure_annotations(
                                parent, request, expected_parent=parent, expected=expected
                            )
                            if isinstance(error, Exception) and state.primary is error:
                                step = "classification"
                                classification = _classify_linked_session_failure(error)
                                facts.session_failure = classification
                                step = "refinement"
                                records._copy_linked_failure_annotations(
                                    parent,
                                    request,
                                    expected_parent=parent,
                                    expected=expected,
                                    classification=classification,
                                )
                        except Exception:
                            records._mark_linked_diagnostic_failure(facts, step, "ordinary")
                        except BaseException as diagnostic:
                            if state.first_cancel is None:
                                state.first_cancel = diagnostic
                                facts.first_cancel_phase = "annotation"
                            records._mark_linked_diagnostic_failure(facts, step, "cancellation")
                        if state.first_cancel is not None and state.first_cancel is not error:
                            _raise_linked_cancellation(state.first_cancel)
                        raise
                    facts.candidate_constructed = True
                    try:
                        records._note_linked_candidate(
                            parent, request, expected_parent=parent, expected=expected
                        )
                    except BaseException as diagnostic:
                        if isinstance(diagnostic, Exception):
                            state.primary = diagnostic
                            facts.first_ordinary_domain = "diagnostic"
                            records._mark_linked_diagnostic_failure(facts, "candidate", "ordinary")
                        else:
                            if state.first_cancel is None:
                                state.first_cancel = diagnostic
                                facts.first_cancel_phase = "annotation"
                            records._mark_linked_diagnostic_failure(
                                facts, "candidate", "cancellation"
                            )
                        raise
            except BaseException as error:
                # A failing phase exit may arrive after the body already retained its failure.
                if state.phase_exit_triple is None or state.phase_exit_triple[1] is not error:
                    state.phase_exit_triple = (type(error), error, error.__traceback__)
                    if error is not state.primary and error is not state.first_cancel:
                        facts.phase_exit_failure = (
                            "ordinary" if isinstance(error, Exception) else "cancellation"
                        )
                    if isinstance(error, Exception):
                        if state.primary is None:
                            state.primary = error
                            facts.first_ordinary_domain = "phase_exit"
                    elif state.first_cancel is None:
                        state.first_cancel = error
                        facts.first_cancel_phase = "phase_exit"
                raise
            records._final_linked_checkpoint(
                parent, request, expected_parent=parent, expected=expected
            )
    except BaseException:
        candidate = None
        raise
    if candidate is None:
        raise _CredentialSessionUseError()
    return candidate


@dataclass(frozen=True, slots=True, repr=False)
class _BoundMockRehearsalSnapshot:
    binding: records.SyntheticBinding
    operation: records.RecordOperation
    production_write_token_path: Path
    generation_state_path: Path
    production_read_token_path: Path
    test_write_token_path: Path
    target: ProductionWriteTargetConfig
    target_hash: str
    confirmation: str


def _invalid_bound_mock_provider() -> ProductionWriteTokenConfigError:
    return ProductionWriteTokenConfigError(
        "production_rehearsal_bound_provider_use_invalid",
        "Bound synthetic rehearsal provider use is invalid",
    )


@final
class _BoundMockRehearsalSessionProvider(_NoCredentialSessionCopy):
    """Fixture-configured admission for one synthetic rehearsal pair."""

    __slots__ = (
        "_active",
        "_factory_identity",
        "_make_refresher",
        "_now_utc",
        "_pid",
        "_snapshot",
        "_thread",
        "refresh_attempt_count",
    )
    _active: bool
    _factory_identity: _BoundMockRehearsalSessionProvider
    _make_refresher: Callable[[], ProductionWriteTokenRefresher]
    _now_utc: Callable[[], datetime]
    _pid: int
    _snapshot: _BoundMockRehearsalSnapshot
    _thread: threading.Thread
    refresh_attempt_count: int
    mock_only: Literal[True] = True
    live_capable: Literal[False] = False
    browser_launch_count: Literal[0] = 0

    def __init__(self, *_args: object, **_kwargs: object) -> None:
        raise _invalid_bound_mock_provider()

    def __setattr__(self, _name: str, _value: object) -> NoReturn:
        raise _invalid_bound_mock_provider()

    def __delattr__(self, _name: str) -> NoReturn:
        raise _invalid_bound_mock_provider()

    def _require_initialized(self) -> None:
        try:
            valid = (
                type(self) is _BoundMockRehearsalSessionProvider
                and self._factory_identity is self
                and type(self._snapshot) is _BoundMockRehearsalSnapshot
                and type(self._pid) is int
                and isinstance(self._thread, threading.Thread)
                and type(self._active) is bool
                and type(self.refresh_attempt_count) is int
                and self.refresh_attempt_count in (0, 1)
                and callable(self._now_utc)
                and callable(self._make_refresher)
            )
        except AttributeError:
            raise _invalid_bound_mock_provider() from None
        if not valid:
            raise _invalid_bound_mock_provider()

    def load_session(
        self, *, target: ProductionWriteTargetConfig
    ) -> ProductionWriteCredentialSession:
        self._require_initialized()
        if (
            self._pid != getpid()
            or self._thread is not threading.current_thread()
            or not self._thread.is_alive()
            or self._active
        ):
            raise _invalid_bound_mock_provider()
        if type(target) is not ProductionWriteTargetConfig:
            raise _invalid_bound_mock_provider()
        validate_production_write_target_config(target)
        snapshot = self._snapshot
        if not hmac.compare_digest(
            calculate_production_write_target_hash(target), snapshot.target_hash
        ):
            raise ProductionWriteTokenConfigError(
                "production_rehearsal_bound_target_mismatch",
                "Bound synthetic rehearsal target does not match",
            )

        try:
            object.__setattr__(self, "_active", True)
            object.__setattr__(self, "refresh_attempt_count", 0)
            now = self._now_utc()
            refresher = _BoundMockRehearsalRefresher(self._make_refresher(), self)
            return _prepare_start_linked_session_mock(
                snapshot.production_write_token_path,
                snapshot.generation_state_path,
                snapshot.production_read_token_path,
                snapshot.test_write_token_path,
                snapshot.target,
                snapshot.confirmation,
                now=now,
                refresher=refresher,
                binding=snapshot.binding,
                operation=snapshot.operation,
            )
        finally:
            object.__setattr__(self, "_active", False)


@final
class _BoundMockRehearsalRefresher:
    """Count dispatch while letting the held loader inspect the actual fake."""

    _forwarded = frozenset(
        (
            "mock_only",
            "live_capable",
            "browser_fallback_count",
            "refresh_attempt_count",
            "calendar_api_call_count",
        )
    )
    if TYPE_CHECKING:
        mock_only: Literal[True]
        live_capable: Literal[False]
        browser_fallback_count: Literal[0]
        refresh_attempt_count: int
        calendar_api_call_count: int

    def __init__(
        self,
        refresher: ProductionWriteTokenRefresher,
        provider: _BoundMockRehearsalSessionProvider,
    ) -> None:
        try:
            counts = (
                refresher.browser_fallback_count,
                refresher.refresh_attempt_count,
                refresher.calendar_api_call_count,
            )
            valid = (
                refresher.mock_only is True
                and refresher.live_capable is False
                and all(type(count) is int and count == 0 for count in counts)
                and callable(refresher.refresh)
            )
        except AttributeError:
            raise _invalid_bound_mock_provider() from None
        if not valid:
            raise _invalid_bound_mock_provider()
        self._refresher = refresher
        self._provider = provider

    def __getattr__(self, name: str) -> object:
        if name in self._forwarded:
            return getattr(self._refresher, name)
        raise AttributeError(name)

    def refresh(
        self,
        token: ProductionWriteAuthorizedUserToken,
        scopes: tuple[str, ...],
    ) -> ProductionWriteOAuthCredentials:
        refresh = self._refresher.refresh
        object.__setattr__(self._provider, "refresh_attempt_count", 1)
        return refresh(token, scopes)


def _bind_mock_rehearsal_session_provider(
    *,
    binding: records.SyntheticBinding,
    operation: records.RecordOperation,
    production_write_token_path: Path,
    generation_state_path: Path,
    production_read_token_path: Path,
    test_write_token_path: Path,
    target: ProductionWriteTargetConfig,
    confirmation: str,
    now_utc: Callable[[], datetime],
    make_refresher: Callable[[], ProductionWriteTokenRefresher],
) -> _BoundMockRehearsalSessionProvider:
    from tridentine_calendar_google_sync.production_write_token_rehearsal import (
        verify_production_write_token_rehearsal_confirmation,
    )

    paths = (
        production_write_token_path,
        generation_state_path,
        production_read_token_path,
        test_write_token_path,
    )
    if (
        not all(records._valid_directory(path) for path in paths)
        or len(set(paths)) != len(paths)
        or any(path.name.casefold() == records.RECORD_LEAF.casefold() for path in paths)
        or not records._valid_linked_layout(
            records._LinkedExpected(
                binding, operation, production_write_token_path, generation_state_path
            )
        )
        or production_write_token_path.parent.parts != binding.directory.parts
        or generation_state_path.parent.parts != binding.directory.parts
        or not callable(now_utc)
        or not callable(make_refresher)
        or type(target) is not ProductionWriteTargetConfig
        or type(confirmation) is not str
    ):
        raise _invalid_bound_mock_provider()
    validate_production_write_target_config(target)
    retained_target = ProductionWriteTargetConfig(
        schema_version=target.schema_version,
        target_environment=target.target_environment,
        target_label=target.target_label,
        target_purpose=target.target_purpose,
        calendar_id=target.calendar_id,
        expected_target_fingerprint=target.expected_target_fingerprint,
        expected_summary=target.expected_summary,
        expected_access_role=target.expected_access_role,
        expected_time_zone=target.expected_time_zone,
    )
    verify_production_write_token_rehearsal_confirmation(retained_target, confirmation)
    snapshot = _BoundMockRehearsalSnapshot(
        binding=records.SyntheticBinding(
            binding.directory,
            binding.storage_ref,
            binding.pair_ref,
            binding.token_slot,
            binding.state_slot,
        ),
        operation=records.RecordOperation(
            operation.operation_id, operation.predecessor_id, operation.kind
        ),
        production_write_token_path=production_write_token_path,
        generation_state_path=generation_state_path,
        production_read_token_path=production_read_token_path,
        test_write_token_path=test_write_token_path,
        target=retained_target,
        target_hash=calculate_production_write_target_hash(retained_target),
        confirmation=confirmation,
    )
    provider = object.__new__(_BoundMockRehearsalSessionProvider)
    object.__setattr__(provider, "_snapshot", snapshot)
    object.__setattr__(provider, "_now_utc", now_utc)
    object.__setattr__(provider, "_make_refresher", make_refresher)
    object.__setattr__(provider, "_pid", getpid())
    object.__setattr__(provider, "_thread", threading.current_thread())
    object.__setattr__(provider, "_active", False)
    object.__setattr__(provider, "refresh_attempt_count", 0)
    object.__setattr__(provider, "_factory_identity", provider)
    return provider


__all__ = [
    "ProductionWriteTokenAuthorizationError",
    "ProductionWriteTokenConfigError",
    "ProductionWriteTokenError",
    "ProductionWriteTokenRefreshError",
    "ProductionWriteTokenRefreshPersistenceError",
    "ProductionWriteTokenRefreshPrewriteError",
    "ProductionWriteTokenSessionLockError",
    "authorize_production_write_token",
    "authorize_production_write_token_mock",
    "build_initial_production_write_token_generation_state",
    "build_next_production_write_token_generation_state",
    "calculate_production_write_token_generation_state_hash",
    "prepare_production_write_rehearsal_credential_session",
    "prepare_production_write_rehearsal_credential_session_mock",
    "private_production_write_token_generation_state_data",
    "production_write_token_authorization_challenge",
    "validate_production_token_role",
    "validate_production_write_scopes",
    "verify_production_write_authorized_user_token",
    "verify_production_write_token_authorization_confirmation",
    "verify_production_write_token_generation_state",
    "verify_production_write_token_generation_transition",
]
