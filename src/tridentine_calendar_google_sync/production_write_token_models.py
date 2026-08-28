"""Closed models and injectable mock protocols for a Production write token."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Literal, Protocol

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.models import StrictFrozenModel

PRODUCTION_WRITE_SCOPE = "https://www.googleapis.com/auth/calendar.events.owned"
PRODUCTION_WRITE_SCOPES = (PRODUCTION_WRITE_SCOPE,)


def _is_utc(value: datetime) -> bool:
    offset = value.utcoffset()
    return offset is not None and offset.total_seconds() == 0


class ProductionTokenRole(StrEnum):
    """The three non-interchangeable token roles."""

    PRODUCTION_READ = "production_read"
    TEST_WRITE = "test_write"
    PRODUCTION_WRITE = "production_write"


class ProductionWriteOAuthClientMaterial(StrictFrozenModel):
    """Secret desktop-client material passed only to an injected OAuth adapter."""

    client_id: str = Field(min_length=1, repr=False, exclude=True)
    client_secret: str = Field(min_length=1, repr=False, exclude=True)
    auth_uri: Literal["https://accounts.google.com/o/oauth2/auth"]
    token_uri: Literal["https://oauth2.googleapis.com/token"]
    redirect_uris: tuple[Literal["http://localhost"], ...] = Field(repr=False, exclude=True)

    @model_validator(mode="after")
    def exact_loopback_redirect(self) -> ProductionWriteOAuthClientMaterial:
        if self.redirect_uris != ("http://localhost",):
            raise ValueError("Production OAuth redirect policy is invalid")
        return self


class ProductionWriteOAuthCredentials(StrictFrozenModel):
    """Secret result returned by an injected mock authorization or refresh adapter."""

    access_token: str = Field(min_length=1, repr=False, exclude=True)
    refresh_token: str = Field(min_length=1, repr=False, exclude=True)
    client_id: str = Field(min_length=1, repr=False, exclude=True)
    client_secret: str = Field(min_length=1, repr=False, exclude=True)
    token_uri: Literal["https://oauth2.googleapis.com/token"]
    scopes: tuple[str, ...] = Field(repr=False, exclude=True)
    granted_scopes: tuple[str, ...] = Field(repr=False, exclude=True)
    expiry: datetime = Field(repr=False, exclude=True)

    @model_validator(mode="after")
    def exact_scope_and_expiry_metadata(self) -> ProductionWriteOAuthCredentials:
        if (
            self.scopes != PRODUCTION_WRITE_SCOPES
            or self.granted_scopes != PRODUCTION_WRITE_SCOPES
            or not _is_utc(self.expiry)
        ):
            raise ValueError("Production write OAuth credentials violate policy")
        return self


class ProductionWriteAuthorizedUserToken(StrictFrozenModel):
    """Private repository-external token artifact with exact role and target binding."""

    schema_version: Literal["1.0"] = "1.0"
    token_type: Literal["production-write-authorized-user-token-v1"] = (
        "production-write-authorized-user-token-v1"
    )
    role: Literal[ProductionTokenRole.PRODUCTION_WRITE] = ProductionTokenRole.PRODUCTION_WRITE
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    target_config_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    generation: int = Field(ge=1)
    access_token: str = Field(min_length=1, repr=False, exclude=True)
    refresh_token: str = Field(min_length=1, repr=False, exclude=True)
    client_id: str = Field(min_length=1, repr=False, exclude=True)
    client_secret: str = Field(min_length=1, repr=False, exclude=True)
    token_uri: Literal["https://oauth2.googleapis.com/token"]
    scopes: tuple[str, ...] = Field(repr=False, exclude=True)
    granted_scopes: tuple[str, ...] = Field(repr=False, exclude=True)
    expiry: datetime = Field(repr=False, exclude=True)

    @model_validator(mode="after")
    def exact_production_write_contract(self) -> ProductionWriteAuthorizedUserToken:
        if (
            self.role is not ProductionTokenRole.PRODUCTION_WRITE
            or self.scopes != PRODUCTION_WRITE_SCOPES
            or self.granted_scopes != PRODUCTION_WRITE_SCOPES
            or not _is_utc(self.expiry)
        ):
            raise ValueError("Production write token violates role or scope policy")
        return self


class ProductionWriteTokenGenerationState(StrictFrozenModel):
    """Secret-independent opaque counter bound to one Production target."""

    schema_version: Literal["1.0"] = "1.0"
    state_type: Literal["production-write-token-generation-state-v1"] = (
        "production-write-token-generation-state-v1"
    )
    role: Literal[ProductionTokenRole.PRODUCTION_WRITE] = ProductionTokenRole.PRODUCTION_WRITE
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    target_config_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    generation: int = Field(ge=1)
    issued_at: datetime
    predecessor_state_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def exact_generation_contract(self) -> ProductionWriteTokenGenerationState:
        initial = self.generation == 1 and self.predecessor_state_hash is None
        rotated = self.generation > 1 and self.predecessor_state_hash is not None
        if (
            self.role is not ProductionTokenRole.PRODUCTION_WRITE
            or not _is_utc(self.issued_at)
            or not (initial or rotated)
        ):
            raise ValueError("Production write token generation state is invalid")
        return self


class ProductionWriteCredentialSession(StrictFrozenModel):
    """Validated credential session for read-only rehearsal consumers."""

    token: ProductionWriteAuthorizedUserToken = Field(repr=False, exclude=True)
    generation_state: ProductionWriteTokenGenerationState
    refresh_count: Literal[0, 1]
    browser_fallback_count: Literal[0] = 0
    calendar_api_call_count: Literal[0] = 0


class ProductionWriteTokenAuthorizationResult(StrictFrozenModel):
    """Private fake-authorization result plus safe logical counters."""

    mock_only: Literal[True] = True
    live_oauth: Literal[False] = False
    token: ProductionWriteAuthorizedUserToken = Field(repr=False, exclude=True)
    generation_state: ProductionWriteTokenGenerationState
    browser_launch_count: Literal[1] = 1
    oauth_attempt_count: Literal[1] = 1
    calendar_api_call_count: Literal[0] = 0
    token_written: Literal[True] = True
    generation_state_written: Literal[True] = True


class ProductionWriteOAuthAuthorizer(Protocol):
    """Injected fake-only authorization boundary; no Calendar capability exists."""

    mock_only: Literal[True]
    live_capable: Literal[False]
    browser_launch_count: int
    oauth_attempt_count: int
    calendar_api_call_count: int

    def authorize(
        self,
        client: ProductionWriteOAuthClientMaterial,
        scopes: tuple[str, ...],
    ) -> ProductionWriteOAuthCredentials: ...


class ProductionWriteTokenRefresher(Protocol):
    """Injected fake-only refresh boundary with no browser or Calendar capability."""

    mock_only: Literal[True]
    live_capable: Literal[False]
    browser_fallback_count: Literal[0]
    refresh_attempt_count: int
    calendar_api_call_count: int

    def refresh(
        self,
        token: ProductionWriteAuthorizedUserToken,
        scopes: tuple[str, ...],
    ) -> ProductionWriteOAuthCredentials: ...


__all__ = [
    "PRODUCTION_WRITE_SCOPE",
    "PRODUCTION_WRITE_SCOPES",
    "ProductionTokenRole",
    "ProductionWriteAuthorizedUserToken",
    "ProductionWriteCredentialSession",
    "ProductionWriteOAuthAuthorizer",
    "ProductionWriteOAuthClientMaterial",
    "ProductionWriteOAuthCredentials",
    "ProductionWriteTokenAuthorizationResult",
    "ProductionWriteTokenGenerationState",
    "ProductionWriteTokenRefresher",
]
