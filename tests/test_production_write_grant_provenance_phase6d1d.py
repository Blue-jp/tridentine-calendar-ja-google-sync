"""Phase 6D.1D provider-granted scope provenance and freshness tests."""

from __future__ import annotations

import inspect
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from phase6d0_auth_helpers import (
    ISSUED_AT,
    FakeAuthorizer,
    FakeRefresher,
    artifact_paths,
    oauth_credentials,
    production_target,
    production_token,
    write_fake_client_config,
)

from tridentine_calendar_google_sync.production_write_target import (
    ProductionWriteTargetConfig,
)
from tridentine_calendar_google_sync.production_write_token import (
    ProductionWriteTokenAuthorizationError,
    ProductionWriteTokenConfigError,
    ProductionWriteTokenRefreshError,
    _fresh_authorization_grant_evidence,
    _fresh_refresh_grant_evidence,
    authorize_production_write_token,
    authorize_production_write_token_mock,
    build_initial_production_write_token_generation_state,
    prepare_production_write_rehearsal_credential_session,
    prepare_production_write_rehearsal_credential_session_mock,
    production_write_token_authorization_challenge,
    verify_production_write_authorized_user_token,
)
from tridentine_calendar_google_sync.production_write_token_io import (
    ProductionWriteTokenIOError,
    parse_production_write_authorized_user_token_bytes,
    render_production_write_authorized_user_token_json,
    write_production_write_authorized_user_token,
    write_production_write_token_generation_state,
)
from tridentine_calendar_google_sync.production_write_token_models import (
    PRODUCTION_WRITE_SCOPE,
    PRODUCTION_WRITE_SCOPES,
    ProductionWriteGrantedScopeEvidence,
    ProductionWriteGrantEvidenceOrigin,
    ProductionWriteOAuthAuthorizer,
    ProductionWriteTokenGenerationState,
    ProductionWriteTokenRefresher,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal import (
    production_write_token_rehearsal_challenge,
)

pytestmark = pytest.mark.google_production_write


def _authorize_mock(root: Path, authorizer: FakeAuthorizer) -> dict[str, Path]:
    paths = artifact_paths(root)
    write_fake_client_config(paths["client"])
    target = production_target()
    authorize_production_write_token_mock(
        paths["client"],
        paths["write"],
        paths["generation"],
        paths["read"],
        paths["test"],
        target,
        production_write_token_authorization_challenge(target),
        test_authorizer=authorizer,
        issued_at=ISSUED_AT,
    )
    return paths


def _stored_test_token(
    root: Path,
    *,
    expiry_offset: timedelta,
) -> tuple[
    dict[str, Path],
    ProductionWriteTargetConfig,
    ProductionWriteTokenGenerationState,
]:
    root.mkdir(parents=True, exist_ok=True)
    paths = artifact_paths(root)
    target = production_target()
    state = build_initial_production_write_token_generation_state(target, issued_at=ISSUED_AT)
    token = production_token(state, expiry=ISSUED_AT + expiry_offset)
    write_production_write_authorized_user_token(token, paths["write"])
    write_production_write_token_generation_state(state, paths["generation"])
    return paths, target, state


def test_exact_fresh_provider_response_evidence_is_separate_from_requested_scope() -> None:
    evidence = _fresh_authorization_grant_evidence(
        PRODUCTION_WRITE_SCOPES,
        observed_at=ISSUED_AT,
    )

    assert evidence.raw_scope_tokens == PRODUCTION_WRITE_SCOPES
    assert evidence.granted_scopes == PRODUCTION_WRITE_SCOPES
    assert evidence.response_scope_field_present is True
    assert evidence.origin is ProductionWriteGrantEvidenceOrigin.FRESH_AUTHORIZATION_RESPONSE

    refresh_evidence = _fresh_refresh_grant_evidence(
        PRODUCTION_WRITE_SCOPES,
        observed_at=ISSUED_AT,
    )
    assert refresh_evidence.origin is ProductionWriteGrantEvidenceOrigin.FRESH_REFRESH_RESPONSE


@pytest.mark.parametrize(
    "raw_scope_tokens",
    (
        None,
        (),
        (PRODUCTION_WRITE_SCOPE, "https://www.googleapis.com/auth/calendar"),
        ("https://www.googleapis.com/auth/calendar",),
        ("https://www.googleapis.com/auth/calendar.events.owned.readonly",),
        (PRODUCTION_WRITE_SCOPE, PRODUCTION_WRITE_SCOPE),
        (f" {PRODUCTION_WRITE_SCOPE}",),
        (f"{PRODUCTION_WRITE_SCOPE} ",),
        ("",),
    ),
)
def test_missing_empty_duplicate_broad_readonly_or_ambiguous_evidence_is_rejected(
    raw_scope_tokens: object,
) -> None:
    with pytest.raises(ProductionWriteTokenConfigError) as captured:
        _fresh_authorization_grant_evidence(
            raw_scope_tokens,
            observed_at=ISSUED_AT,
        )
    assert captured.value.code == "unsafe_production_write_grant_evidence"


@pytest.mark.parametrize(
    "credential_update",
    (
        {"grant_evidence": None},
        {
            "grant_evidence": ProductionWriteGrantedScopeEvidence.model_construct(
                origin=ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_AUTHORIZATION_RESPONSE,
                response_scope_field_present=True,
                raw_scope_tokens=PRODUCTION_WRITE_SCOPES,
                granted_scopes=PRODUCTION_WRITE_SCOPES,
                observed_at=ISSUED_AT - timedelta(seconds=1),
            )
        },
    ),
)
def test_requested_or_stale_scope_without_fresh_evidence_writes_nothing(
    tmp_path: Path,
    credential_update: dict[str, object],
) -> None:
    credentials = oauth_credentials().model_copy(update=credential_update)
    with pytest.raises(ProductionWriteTokenConfigError) as captured:
        _authorize_mock(tmp_path, FakeAuthorizer(credentials))
    assert captured.value.code == "unsafe_production_write_grant_evidence"
    assert not (tmp_path / "production-write-token.json").exists()
    assert not (tmp_path / "production-write-generation.json").exists()


def test_fake_authorizer_cannot_self_attest_provider_origin(tmp_path: Path) -> None:
    provider_evidence = _fresh_authorization_grant_evidence(
        PRODUCTION_WRITE_SCOPES,
        observed_at=ISSUED_AT,
    )
    credentials = oauth_credentials().model_copy(update={"grant_evidence": provider_evidence})

    with pytest.raises(ProductionWriteTokenConfigError) as captured:
        _authorize_mock(tmp_path, FakeAuthorizer(credentials))
    assert captured.value.code == "unsafe_production_write_grant_evidence"
    assert not (tmp_path / "production-write-token.json").exists()
    assert not (tmp_path / "production-write-generation.json").exists()


def test_operational_entry_points_expose_no_arbitrary_authorizer_or_refresher() -> None:
    authorization_parameters = inspect.signature(authorize_production_write_token).parameters
    rehearsal_parameters = inspect.signature(
        prepare_production_write_rehearsal_credential_session
    ).parameters

    assert "authorizer" not in authorization_parameters
    assert "test_authorizer" not in authorization_parameters
    assert "refresher" not in rehearsal_parameters
    assert "test_refresher" not in rehearsal_parameters


def test_unsupported_mock_adapters_fail_before_persistence_or_overwrite(
    tmp_path: Path,
) -> None:
    paths = artifact_paths(tmp_path / "authorization")
    paths["client"].parent.mkdir(parents=True)
    write_fake_client_config(paths["client"])
    target = production_target()
    with pytest.raises(ProductionWriteTokenAuthorizationError) as authorization:
        authorize_production_write_token_mock(
            paths["client"],
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            production_write_token_authorization_challenge(target),
            test_authorizer=cast(ProductionWriteOAuthAuthorizer, object()),
            issued_at=ISSUED_AT,
        )
    assert authorization.value.code == "production_live_oauth_disabled_in_phase_6d0"
    assert not paths["write"].exists()
    assert not paths["generation"].exists()

    refresh_paths, refresh_target, _state = _stored_test_token(
        tmp_path / "refresh",
        expiry_offset=timedelta(seconds=1),
    )
    token_before = refresh_paths["write"].read_bytes()
    with pytest.raises(ProductionWriteTokenRefreshError) as refresh:
        prepare_production_write_rehearsal_credential_session_mock(
            refresh_paths["write"],
            refresh_paths["generation"],
            refresh_paths["read"],
            refresh_paths["test"],
            refresh_target,
            production_write_token_rehearsal_challenge(refresh_target),
            now=ISSUED_AT + timedelta(seconds=2),
            refresher=cast(ProductionWriteTokenRefresher, object()),
        )
    assert refresh.value.code == "production_write_token_refresh_adapter_unsafe"
    assert refresh_paths["write"].read_bytes() == token_before


def test_mock_token_is_persisted_but_rejected_as_operational_provider_evidence(
    tmp_path: Path,
) -> None:
    paths = _authorize_mock(tmp_path, FakeAuthorizer(oauth_credentials()))
    target = production_target()
    state = build_initial_production_write_token_generation_state(target, issued_at=ISSUED_AT)
    token_document = json.loads(paths["write"].read_text(encoding="utf-8"))

    assert token_document["grant_evidence"]["origin"] == (
        ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_AUTHORIZATION_RESPONSE.value
    )
    token = parse_production_write_authorized_user_token_bytes(paths["write"].read_bytes())
    with pytest.raises(ProductionWriteTokenConfigError) as captured:
        verify_production_write_authorized_user_token(token, state, target)
    assert captured.value.code == "production_write_token_grant_evidence_origin_mismatch"


def test_provider_evidence_token_reloads_but_old_or_missing_evidence_does_not(
    tmp_path: Path,
) -> None:
    paths = artifact_paths(tmp_path)
    target = production_target()
    state = build_initial_production_write_token_generation_state(target, issued_at=ISSUED_AT)
    provider_evidence = _fresh_authorization_grant_evidence(
        PRODUCTION_WRITE_SCOPES,
        observed_at=ISSUED_AT,
    )
    token = production_token(state, grant_evidence=provider_evidence)
    write_production_write_authorized_user_token(token, paths["write"])
    write_production_write_token_generation_state(state, paths["generation"])

    session = prepare_production_write_rehearsal_credential_session(
        paths["write"],
        paths["generation"],
        paths["read"],
        paths["test"],
        target,
        production_write_token_rehearsal_challenge(target),
        now=ISSUED_AT,
    )
    assert session.refresh_count == 0
    assert session.token.grant_evidence == provider_evidence

    document = json.loads(render_production_write_authorized_user_token_json(token))
    document.pop("grant_evidence")
    document["granted_scopes"] = list(PRODUCTION_WRITE_SCOPES)
    document["schema_version"] = "1.0"
    document["token_type"] = "production-write-authorized-user-token-v1"
    old_schema_bytes = (json.dumps(document, indent=2, sort_keys=False) + "\n").encode()
    with pytest.raises(ProductionWriteTokenIOError):
        parse_production_write_authorized_user_token_bytes(old_schema_bytes)


def test_test_evidence_token_cannot_enter_operational_reload_path(tmp_path: Path) -> None:
    paths, target, _state = _stored_test_token(
        tmp_path,
        expiry_offset=timedelta(hours=1),
    )
    with pytest.raises(ProductionWriteTokenConfigError) as captured:
        prepare_production_write_rehearsal_credential_session(
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            production_write_token_rehearsal_challenge(target),
            now=ISSUED_AT,
        )
    assert captured.value.code == "production_write_token_grant_evidence_origin_mismatch"


def test_fresh_test_refresh_evidence_succeeds_without_generation_change(
    tmp_path: Path,
) -> None:
    paths, target, state = _stored_test_token(
        tmp_path,
        expiry_offset=timedelta(seconds=1),
    )
    now = ISSUED_AT + timedelta(seconds=2)
    refresher = FakeRefresher(
        oauth_credentials(
            expiry=now + timedelta(hours=1),
            evidence_origin=ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
            evidence_observed_at=now,
        )
    )

    session = prepare_production_write_rehearsal_credential_session_mock(
        paths["write"],
        paths["generation"],
        paths["read"],
        paths["test"],
        target,
        production_write_token_rehearsal_challenge(target),
        now=now,
        refresher=refresher,
    )
    assert session.refresh_count == 1
    assert session.token.generation == state.generation
    assert session.token.grant_evidence.origin is (
        ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE
    )


@pytest.mark.parametrize(
    ("evidence_origin", "observed_at", "granted_scopes"),
    (
        (
            ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_AUTHORIZATION_RESPONSE,
            ISSUED_AT,
            PRODUCTION_WRITE_SCOPES,
        ),
        (
            ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
            ISSUED_AT,
            PRODUCTION_WRITE_SCOPES,
        ),
        (
            ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
            ISSUED_AT + timedelta(seconds=2),
            (),
        ),
        (
            ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
            ISSUED_AT + timedelta(seconds=2),
            (PRODUCTION_WRITE_SCOPE, "https://www.googleapis.com/auth/calendar"),
        ),
        (
            ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
            ISSUED_AT + timedelta(seconds=2),
            ("https://www.googleapis.com/auth/calendar",),
        ),
        (
            ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
            ISSUED_AT + timedelta(seconds=2),
            ("https://www.googleapis.com/auth/calendar.events.owned.readonly",),
        ),
        (
            ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
            ISSUED_AT + timedelta(seconds=2),
            (PRODUCTION_WRITE_SCOPE, PRODUCTION_WRITE_SCOPE),
        ),
        (
            ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
            ISSUED_AT + timedelta(seconds=2),
            (f"{PRODUCTION_WRITE_SCOPE} ",),
        ),
    ),
)
def test_stale_missing_extra_or_wrong_refresh_evidence_never_overwrites_token(
    tmp_path: Path,
    evidence_origin: ProductionWriteGrantEvidenceOrigin,
    observed_at: datetime,
    granted_scopes: tuple[str, ...],
) -> None:
    paths, target, _state = _stored_test_token(
        tmp_path,
        expiry_offset=timedelta(seconds=1),
    )
    token_before = paths["write"].read_bytes()
    now = ISSUED_AT + timedelta(seconds=2)
    refresher = FakeRefresher(
        oauth_credentials(
            expiry=now + timedelta(hours=1),
            granted_scopes=granted_scopes,
            evidence_origin=evidence_origin,
            evidence_observed_at=observed_at,
        )
    )

    with pytest.raises(ProductionWriteTokenConfigError) as captured:
        prepare_production_write_rehearsal_credential_session_mock(
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            production_write_token_rehearsal_challenge(target),
            now=now,
            refresher=refresher,
        )
    assert captured.value.code == "unsafe_production_write_grant_evidence"
    assert paths["write"].read_bytes() == token_before
    assert refresher.browser_fallback_count == 0
    assert refresher.calendar_api_call_count == 0


def test_refresh_requested_scopes_or_old_grant_without_fresh_evidence_fails_closed(
    tmp_path: Path,
) -> None:
    paths, target, _state = _stored_test_token(
        tmp_path,
        expiry_offset=timedelta(seconds=1),
    )
    token_before = paths["write"].read_bytes()
    now = ISSUED_AT + timedelta(seconds=2)
    credentials = oauth_credentials(
        expiry=now + timedelta(hours=1),
        evidence_origin=ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
        evidence_observed_at=now,
    ).model_copy(update={"grant_evidence": None})
    refresher = FakeRefresher(credentials)

    with pytest.raises(ProductionWriteTokenConfigError) as captured:
        prepare_production_write_rehearsal_credential_session_mock(
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            production_write_token_rehearsal_challenge(target),
            now=now,
            refresher=refresher,
        )
    assert captured.value.code == "unsafe_production_write_grant_evidence"
    assert paths["write"].read_bytes() == token_before
    assert refresher.browser_fallback_count == 0
    assert refresher.calendar_api_call_count == 0
