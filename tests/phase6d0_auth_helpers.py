"""Synthetic-only helpers for Phase 6D.0 write-token tests."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

from tridentine_calendar_google_sync.google_target import calendar_id_fingerprint
from tridentine_calendar_google_sync.production_write_target import (
    ProductionWriteTargetConfig,
)
from tridentine_calendar_google_sync.production_write_token_models import (
    PRODUCTION_WRITE_SCOPES,
    ProductionWriteAuthorizedUserToken,
    ProductionWriteGrantedScopeEvidence,
    ProductionWriteGrantEvidenceOrigin,
    ProductionWriteOAuthClientMaterial,
    ProductionWriteOAuthCredentials,
    ProductionWriteTokenGenerationState,
)
from tridentine_calendar_google_sync.sensitive_paths import atomic_write_private_text

ISSUED_AT = datetime(2099, 1, 1, 12, 0, tzinfo=UTC)
FAKE_ACCESS_TOKEN = "phase6d0-fake-access-token-never-live"
FAKE_REFRESH_TOKEN = "phase6d0-fake-refresh-token-never-live"
FAKE_CLIENT_ID = "phase6d0-fake-client-id.apps.example.invalid"
FAKE_CLIENT_SECRET = "phase6d0-fake-client-secret-never-live"


def production_target() -> ProductionWriteTargetConfig:
    calendar_id = "phase6d0-production-calendar@calendar.example.invalid"
    return ProductionWriteTargetConfig(
        schema_version=1,
        target_environment="production",
        target_label="production",
        target_purpose="production_calendar_single_update",
        calendar_id=calendar_id,
        expected_target_fingerprint=calendar_id_fingerprint(calendar_id),
        expected_summary="Phase 6D Production Calendar",
        expected_access_role="owner",
        expected_time_zone="Asia/Tokyo",
    )


def write_fake_client_config(path: Path) -> Path:
    """Create a synthetic OAuth client using the runtime private writer."""

    atomic_write_private_text(
        path,
        json.dumps(
            {
                "installed": {
                    "client_id": FAKE_CLIENT_ID,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "client_secret": FAKE_CLIENT_SECRET,
                    "redirect_uris": ["http://localhost"],
                }
            }
        ),
    )
    return path


def oauth_credentials(
    *,
    expiry: datetime = ISSUED_AT + timedelta(hours=1),
    scopes: tuple[str, ...] = PRODUCTION_WRITE_SCOPES,
    granted_scopes: tuple[str, ...] = PRODUCTION_WRITE_SCOPES,
    evidence_origin: ProductionWriteGrantEvidenceOrigin = (
        ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_AUTHORIZATION_RESPONSE
    ),
    evidence_observed_at: datetime = ISSUED_AT,
    scope_field_present: bool = True,
    access_token: str = FAKE_ACCESS_TOKEN,
    refresh_token: str = FAKE_REFRESH_TOKEN,
) -> ProductionWriteOAuthCredentials:
    grant_evidence = ProductionWriteGrantedScopeEvidence.model_construct(
        origin=evidence_origin,
        response_scope_field_present=scope_field_present,
        raw_scope_tokens=granted_scopes,
        granted_scopes=granted_scopes,
        observed_at=evidence_observed_at,
    )
    return ProductionWriteOAuthCredentials.model_construct(
        access_token=access_token,
        refresh_token=refresh_token,
        client_id=FAKE_CLIENT_ID,
        client_secret=FAKE_CLIENT_SECRET,
        token_uri="https://oauth2.googleapis.com/token",
        scopes=scopes,
        grant_evidence=grant_evidence,
        expiry=expiry,
    )


def production_token(
    state: ProductionWriteTokenGenerationState,
    *,
    expiry: datetime = ISSUED_AT + timedelta(hours=1),
    access_token: str = FAKE_ACCESS_TOKEN,
    refresh_token: str = FAKE_REFRESH_TOKEN,
    grant_evidence: ProductionWriteGrantedScopeEvidence | None = None,
) -> ProductionWriteAuthorizedUserToken:
    evidence = grant_evidence or ProductionWriteGrantedScopeEvidence(
        origin=ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_AUTHORIZATION_RESPONSE,
        raw_scope_tokens=PRODUCTION_WRITE_SCOPES,
        granted_scopes=PRODUCTION_WRITE_SCOPES,
        observed_at=ISSUED_AT,
    )
    return ProductionWriteAuthorizedUserToken(
        target_safe_ref=state.target_safe_ref,
        target_config_hash=state.target_config_hash,
        generation=state.generation,
        access_token=access_token,
        refresh_token=refresh_token,
        client_id=FAKE_CLIENT_ID,
        client_secret=FAKE_CLIENT_SECRET,
        token_uri="https://oauth2.googleapis.com/token",
        scopes=PRODUCTION_WRITE_SCOPES,
        grant_evidence=evidence,
        expiry=expiry,
    )


class FakeAuthorizer:
    mock_only: Literal[True] = True
    live_capable: Literal[False] = False

    def __init__(self, credentials: ProductionWriteOAuthCredentials) -> None:
        self.credentials = credentials
        self.calls = 0
        self.browser_launch_count = 0
        self.oauth_attempt_count = 0
        self.calendar_api_call_count = 0
        self.scopes: tuple[str, ...] | None = None
        self.client_seen = False

    def authorize(
        self,
        client: ProductionWriteOAuthClientMaterial,
        scopes: tuple[str, ...],
    ) -> ProductionWriteOAuthCredentials:
        self.calls += 1
        self.browser_launch_count += 1
        self.oauth_attempt_count += 1
        self.scopes = scopes
        self.client_seen = client.client_id == FAKE_CLIENT_ID
        return self.credentials


class FakeRefresher:
    mock_only: Literal[True] = True
    live_capable: Literal[False] = False
    browser_fallback_count: Literal[0] = 0

    def __init__(
        self,
        credentials: ProductionWriteOAuthCredentials | None,
        *,
        fail: bool = False,
    ) -> None:
        self.credentials = credentials
        self.fail = fail
        self.calls = 0
        self.refresh_attempt_count = 0
        self.calendar_api_call_count = 0
        self.scopes: tuple[str, ...] | None = None

    def refresh(
        self,
        token: ProductionWriteAuthorizedUserToken,
        scopes: tuple[str, ...],
    ) -> ProductionWriteOAuthCredentials:
        self.calls += 1
        self.refresh_attempt_count += 1
        self.scopes = scopes
        if self.fail or self.credentials is None:
            raise RuntimeError("synthetic refresh failure")
        assert token.role.value == "production_write"
        return self.credentials


def artifact_paths(root: Path) -> dict[str, Path]:
    return {
        "client": root / "fake-client.json",
        "write": root / "production-write-token.json",
        "generation": root / "production-write-generation.json",
        "read": root / "production-read-token.json",
        "test": root / "test-write-token.json",
    }
