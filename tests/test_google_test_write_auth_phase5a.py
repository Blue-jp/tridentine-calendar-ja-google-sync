from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from conftest import REPOSITORY_ROOT
from phase5a_helpers import make_test_target_config

from tridentine_calendar_google_sync.google_test_write_auth import (
    GOOGLE_TEST_EVENTS_OWNED_WRITE_SCOPE,
    TEST_WRITE_GOOGLE_SCOPES,
    authorize_test_google_write,
    load_test_write_authorized_user_token,
    validate_test_write_scopes,
    validate_test_write_token_separation,
)
from tridentine_calendar_google_sync.google_test_write_auth import (
    TestWriteAuthConfigError as AuthConfigError,
)
from tridentine_calendar_google_sync.google_test_write_auth import (
    TestWriteAuthorizationCancelled as AuthorizationCancelled,
)
from tridentine_calendar_google_sync.sensitive_paths import atomic_write_private_text
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetPolicyError as TargetPolicyError,
)

pytestmark = pytest.mark.google_test_write


def _token_document(scopes: list[str]) -> dict[str, object]:
    return {
        "type": "authorized_user",
        "token": "fixture-access-token-never-used",
        "refresh_token": "fixture-refresh-token-never-used",
        "token_uri": "https://oauth2.googleapis.com/token",
        "client_id": "fixture-client-id",
        "client_secret": "fixture-client-secret",
        "scopes": scopes,
    }


def _write_private_json(path: Path, document: dict[str, object]) -> None:
    """Create a synthetic token fixture using the runtime private writer."""

    atomic_write_private_text(path, json.dumps(document))


def test_test_write_scope_is_exactly_one_owned_events_scope() -> None:
    assert GOOGLE_TEST_EVENTS_OWNED_WRITE_SCOPE == (
        "https://www.googleapis.com/auth/calendar.events.owned"
    )
    assert TEST_WRITE_GOOGLE_SCOPES == (GOOGLE_TEST_EVENTS_OWNED_WRITE_SCOPE,)
    assert validate_test_write_scopes(TEST_WRITE_GOOGLE_SCOPES) == TEST_WRITE_GOOGLE_SCOPES


@pytest.mark.parametrize(
    "scopes",
    (
        (),
        ("https://www.googleapis.com/auth/calendar.events.owned.readonly",),
        ("https://www.googleapis.com/auth/calendar.events",),
        ("https://www.googleapis.com/auth/calendar",),
        ("https://www.googleapis.com/auth/calendar.app.created",),
        (
            "https://www.googleapis.com/auth/calendar.events.owned",
            "https://www.googleapis.com/auth/calendar.events.owned.readonly",
        ),
        (
            "https://www.googleapis.com/auth/calendar.events.owned",
            "https://www.googleapis.com/auth/calendar.events.owned",
        ),
    ),
)
def test_every_missing_readonly_broad_multiple_or_duplicate_scope_is_rejected(
    scopes: tuple[str, ...],
) -> None:
    with pytest.raises(AuthConfigError) as captured:
        validate_test_write_scopes(scopes)
    assert captured.value.code == "unsafe_test_write_scope"


def test_synthetic_exact_scope_token_loads_without_exposing_secret(tmp_path: Path) -> None:
    token_path = tmp_path / "fixture-test-write-token.json"
    document = _token_document([GOOGLE_TEST_EVENTS_OWNED_WRITE_SCOPE])
    _write_private_json(token_path, document)

    token = load_test_write_authorized_user_token(token_path)

    assert token.scopes == TEST_WRITE_GOOGLE_SCOPES
    rendered = repr(token)
    for value in (
        document["token"],
        document["refresh_token"],
        document["client_id"],
        document["client_secret"],
    ):
        assert str(value) not in rendered


@pytest.mark.parametrize(
    "scopes",
    (
        ["https://www.googleapis.com/auth/calendar.events.owned.readonly"],
        ["https://www.googleapis.com/auth/calendar.events"],
        ["https://www.googleapis.com/auth/calendar"],
        [
            "https://www.googleapis.com/auth/calendar.events.owned",
            "https://www.googleapis.com/auth/calendar.events.readonly",
        ],
    ),
)
def test_token_loader_rejects_nonexact_scope_without_secret_echo(
    tmp_path: Path,
    scopes: list[str],
) -> None:
    token_path = tmp_path / "fixture-invalid-test-write-token.json"
    document = _token_document(scopes)
    _write_private_json(token_path, document)

    with pytest.raises(AuthConfigError) as captured:
        load_test_write_authorized_user_token(token_path)
    assert document["refresh_token"] not in str(captured.value)
    assert str(token_path) not in str(captured.value)


def test_test_write_and_production_read_token_paths_must_be_distinct(tmp_path: Path) -> None:
    test_token = tmp_path / "fixture-test-write-token.json"
    production_read = tmp_path / "fixture-production-read-token.json"
    _write_private_json(test_token, {})
    _write_private_json(production_read, {})

    validated_test, validated_read = validate_test_write_token_separation(
        test_token,
        production_read,
        test_token_exists=True,
    )
    assert validated_test != validated_read

    with pytest.raises(AuthConfigError):
        validate_test_write_token_separation(
            production_read,
            production_read,
            test_token_exists=True,
        )


def test_new_test_token_refuses_existing_output_repository_path_and_symlink(
    tmp_path: Path,
) -> None:
    production_read = tmp_path / "fixture-production-read-token.json"
    _write_private_json(production_read, {})
    existing = tmp_path / "existing-test-write-token.json"
    _write_private_json(existing, {})
    with pytest.raises(AuthConfigError):
        validate_test_write_token_separation(
            existing,
            production_read,
            test_token_exists=False,
        )
    with pytest.raises(AuthConfigError):
        validate_test_write_token_separation(
            REPOSITORY_ROOT / "test-write-token.json",
            production_read,
            test_token_exists=False,
        )

    link = tmp_path / "linked-test-write-token.json"
    try:
        os.symlink(existing, link)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(AuthConfigError):
        validate_test_write_token_separation(
            link,
            production_read,
            test_token_exists=True,
        )


def test_authorization_cancellation_precedes_path_browser_flow_and_token_creation(
    tmp_path: Path,
) -> None:
    flow_calls = 0

    def forbidden_flow(_flow: object) -> object:
        nonlocal flow_calls
        flow_calls += 1
        raise AssertionError("OAuth flow must not start")

    token_path = tmp_path / "not-created-test-write-token.json"
    with pytest.raises(AuthorizationCancelled):
        authorize_test_google_write(
            tmp_path / "not-read-client.json",
            token_path,
            tmp_path / "not-read-production-token.json",
            make_test_target_config(),
            flow_runner=forbidden_flow,
            cancellation_check=lambda: True,
        )
    assert flow_calls == 0
    assert not token_path.exists()


def test_production_policy_failure_precedes_oauth_flow_and_token_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tridentine_calendar_google_sync.google_test_write_auth as auth_module

    flow_calls = 0

    def reject_target(_target: object) -> str:
        raise TargetPolicyError(
            "production_test_write_target_forbidden",
            "Production Calendar write access is forbidden",
        )

    def forbidden_flow(_flow: object) -> object:
        nonlocal flow_calls
        flow_calls += 1
        raise AssertionError("OAuth flow must not start")

    monkeypatch.setattr(auth_module, "validate_test_write_target_config", reject_target)
    token_path = tmp_path / "not-created-test-write-token.json"
    with pytest.raises(TargetPolicyError):
        authorize_test_google_write(
            tmp_path / "not-read-client.json",
            token_path,
            tmp_path / "not-read-production-token.json",
            make_test_target_config(),
            flow_runner=forbidden_flow,
        )
    assert flow_calls == 0
    assert not token_path.exists()
