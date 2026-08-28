"""Phase 6D.0 exact-role, one-refresh, no-browser-fallback tests."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from phase6d0_auth_helpers import (
    FAKE_ACCESS_TOKEN,
    FAKE_REFRESH_TOKEN,
    ISSUED_AT,
    FakeRefresher,
    artifact_paths,
    oauth_credentials,
    production_target,
    production_token,
)

from tridentine_calendar_google_sync.production_write_target import ProductionWriteTargetConfig
from tridentine_calendar_google_sync.production_write_token import (
    ProductionWriteTokenConfigError,
    ProductionWriteTokenRefreshError,
    build_initial_production_write_token_generation_state,
    prepare_production_write_rehearsal_credential_session,
)
from tridentine_calendar_google_sync.production_write_token_io import (
    ProductionWriteTokenIOError,
    render_production_write_authorized_user_token_json,
    write_production_write_authorized_user_token,
    write_production_write_token_generation_state,
)
from tridentine_calendar_google_sync.production_write_token_models import (
    PRODUCTION_WRITE_SCOPE,
    PRODUCTION_WRITE_SCOPES,
    ProductionWriteAuthorizedUserToken,
    ProductionWriteOAuthAuthorizer,
    ProductionWriteTokenGenerationState,
    ProductionWriteTokenRefresher,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal import (
    ProductionWriteTokenRehearsalError,
    production_write_token_rehearsal_challenge,
)

pytestmark = pytest.mark.google_production_write


def _stored_token(
    root: Path,
    *,
    expiry: datetime,
) -> tuple[
    ProductionWriteTargetConfig,
    ProductionWriteTokenGenerationState,
    ProductionWriteAuthorizedUserToken,
    dict[str, Path],
]:
    paths = artifact_paths(root)
    target = production_target()
    state = build_initial_production_write_token_generation_state(target, issued_at=ISSUED_AT)
    token = production_token(state, expiry=expiry)
    write_production_write_authorized_user_token(token, paths["write"])
    write_production_write_token_generation_state(state, paths["generation"])
    return target, state, token, paths


def test_unexpired_exact_token_uses_no_refresh_or_browser(tmp_path: Path) -> None:
    target, state, token, paths = _stored_token(
        tmp_path,
        expiry=ISSUED_AT + timedelta(hours=1),
    )
    session = prepare_production_write_rehearsal_credential_session(
        paths["write"],
        paths["generation"],
        paths["read"],
        paths["test"],
        target,
        production_write_token_rehearsal_challenge(target),
        now=ISSUED_AT,
    )
    assert session.token == token
    assert session.generation_state == state
    assert session.refresh_count == 0
    assert session.browser_fallback_count == 0
    assert session.calendar_api_call_count == 0


def test_expired_token_refreshes_exactly_once_without_generation_change(tmp_path: Path) -> None:
    target, state, _token, paths = _stored_token(
        tmp_path,
        expiry=ISSUED_AT + timedelta(seconds=1),
    )
    now = ISSUED_AT + timedelta(seconds=2)
    refresher = FakeRefresher(
        oauth_credentials(
            expiry=now + timedelta(hours=1),
            access_token="phase6d0-refreshed-access-token-never-live",
            refresh_token="phase6d0-rotated-refresh-token-never-live",
        )
    )
    generation_before = paths["generation"].read_bytes()
    session = prepare_production_write_rehearsal_credential_session(
        paths["write"],
        paths["generation"],
        paths["read"],
        paths["test"],
        target,
        production_write_token_rehearsal_challenge(target),
        now=now,
        refresher=refresher,
    )

    assert refresher.calls == 1
    assert refresher.scopes == PRODUCTION_WRITE_SCOPES
    assert session.refresh_count == 1
    assert session.browser_fallback_count == 0
    assert session.calendar_api_call_count == 0
    assert session.token.generation == state.generation == 1
    assert session.generation_state.content_hash == state.content_hash
    assert paths["generation"].read_bytes() == generation_before
    assert session.token.access_token != FAKE_ACCESS_TOKEN
    assert session.token.refresh_token != FAKE_REFRESH_TOKEN


def test_refresh_failure_has_no_browser_api_delete_or_overwrite(tmp_path: Path) -> None:
    target, _state, _token, paths = _stored_token(
        tmp_path,
        expiry=ISSUED_AT + timedelta(seconds=1),
    )
    token_before = paths["write"].read_bytes()
    generation_before = paths["generation"].read_bytes()
    refresher = FakeRefresher(None, fail=True)
    with pytest.raises(ProductionWriteTokenRefreshError) as captured:
        prepare_production_write_rehearsal_credential_session(
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            production_write_token_rehearsal_challenge(target),
            now=ISSUED_AT + timedelta(seconds=2),
            refresher=refresher,
        )
    assert captured.value.code == "production_write_token_refresh_failed"
    assert refresher.calls == 1
    assert refresher.browser_fallback_count == 0
    assert paths["write"].read_bytes() == token_before
    assert paths["generation"].read_bytes() == generation_before


def test_expired_token_without_explicit_refresher_never_starts_authorization(
    tmp_path: Path,
) -> None:
    target, _state, _token, paths = _stored_token(
        tmp_path,
        expiry=ISSUED_AT + timedelta(seconds=1),
    )
    with pytest.raises(ProductionWriteTokenRefreshError) as captured:
        prepare_production_write_rehearsal_credential_session(
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            production_write_token_rehearsal_challenge(target),
            now=ISSUED_AT + timedelta(seconds=2),
            refresher=None,
        )
    assert captured.value.code == "production_write_token_refresh_unavailable"


def test_rehearsal_confirmation_mismatch_precedes_token_load_and_refresh(tmp_path: Path) -> None:
    paths = artifact_paths(tmp_path)
    target = production_target()
    refresher = FakeRefresher(oauth_credentials(expiry=ISSUED_AT + timedelta(hours=1)))
    with pytest.raises(ProductionWriteTokenRehearsalError) as captured:
        prepare_production_write_rehearsal_credential_session(
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            production_write_token_rehearsal_challenge(target) + " ",
            now=ISSUED_AT,
            refresher=refresher,
        )
    assert captured.value.code == "production_rehearsal_confirmation_mismatch"
    assert refresher.calls == 0


@pytest.mark.parametrize(
    ("scopes", "granted_scopes"),
    (
        ((), PRODUCTION_WRITE_SCOPES),
        (PRODUCTION_WRITE_SCOPES, ()),
        ((PRODUCTION_WRITE_SCOPE, "openid"), PRODUCTION_WRITE_SCOPES),
        (PRODUCTION_WRITE_SCOPES, (PRODUCTION_WRITE_SCOPE, "openid")),
    ),
)
def test_refresh_scope_expansion_or_loss_is_rejected_without_overwrite(
    tmp_path: Path,
    scopes: tuple[str, ...],
    granted_scopes: tuple[str, ...],
) -> None:
    target, _state, _token, paths = _stored_token(
        tmp_path,
        expiry=ISSUED_AT + timedelta(seconds=1),
    )
    token_before = paths["write"].read_bytes()
    now = ISSUED_AT + timedelta(seconds=2)
    refresher = FakeRefresher(
        oauth_credentials(
            expiry=now + timedelta(hours=1),
            scopes=scopes,
            granted_scopes=granted_scopes,
        )
    )
    with pytest.raises(ProductionWriteTokenConfigError) as captured:
        prepare_production_write_rehearsal_credential_session(
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            production_write_token_rehearsal_challenge(target),
            now=now,
            refresher=refresher,
        )
    assert captured.value.code == "unsafe_production_write_scope"
    assert refresher.calls == 1
    assert paths["write"].read_bytes() == token_before


def test_wrong_role_token_stops_before_refresh_and_api(tmp_path: Path) -> None:
    target, _state, token, paths = _stored_token(
        tmp_path,
        expiry=ISSUED_AT + timedelta(seconds=1),
    )
    document = json.loads(render_production_write_authorized_user_token_json(token))
    document["role"] = "test_write"
    paths["write"].write_text(
        json.dumps(document, ensure_ascii=False, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    refresher = FakeRefresher(oauth_credentials(expiry=ISSUED_AT + timedelta(hours=1)))
    with pytest.raises(ProductionWriteTokenIOError):
        prepare_production_write_rehearsal_credential_session(
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            production_write_token_rehearsal_challenge(target),
            now=ISSUED_AT + timedelta(seconds=2),
            refresher=refresher,
        )
    assert refresher.calls == 0


def test_generation_mismatch_stops_before_refresh(tmp_path: Path) -> None:
    target, state, token, paths = _stored_token(
        tmp_path,
        expiry=ISSUED_AT + timedelta(seconds=1),
    )
    mismatched = token.model_copy(update={"generation": state.generation + 1})
    write_production_write_authorized_user_token(mismatched, paths["write"], overwrite=True)
    refresher = FakeRefresher(oauth_credentials(expiry=ISSUED_AT + timedelta(hours=1)))
    with pytest.raises(ProductionWriteTokenConfigError) as captured:
        prepare_production_write_rehearsal_credential_session(
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            production_write_token_rehearsal_challenge(target),
            now=ISSUED_AT + timedelta(seconds=2),
            refresher=refresher,
        )
    assert captured.value.code == "production_write_token_generation_mismatch"
    assert refresher.calls == 0


def test_oauth_and_refresh_protocols_expose_no_calendar_or_mutation_methods() -> None:
    forbidden = {
        "list_events",
        "get_event",
        "patch",
        "patch_description",
        "import_event",
        "insert",
        "update",
        "delete",
        "move",
        "batch",
        "calendar_service",
    }
    assert set(ProductionWriteOAuthAuthorizer.__dict__).isdisjoint(forbidden)
    assert set(ProductionWriteTokenRefresher.__dict__).isdisjoint(forbidden)
