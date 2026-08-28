"""Phase 6D.0 mock-only Production write-token authorization tests."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

import jsonschema
import pytest
from phase6d0_auth_helpers import (
    FAKE_ACCESS_TOKEN,
    FAKE_CLIENT_ID,
    FAKE_CLIENT_SECRET,
    FAKE_REFRESH_TOKEN,
    ISSUED_AT,
    FakeAuthorizer,
    artifact_paths,
    oauth_credentials,
    production_target,
    write_fake_client_config,
)

from tridentine_calendar_google_sync.production_write_token import (
    ProductionWriteTokenAuthorizationError,
    ProductionWriteTokenConfigError,
    authorize_production_write_token,
    production_write_token_authorization_challenge,
    validate_production_token_role,
    validate_production_write_scopes,
)
from tridentine_calendar_google_sync.production_write_token_io import (
    ProductionWriteTokenIOError,
    render_production_write_authorized_user_token_json,
    render_production_write_token_generation_state_json,
)
from tridentine_calendar_google_sync.production_write_token_models import (
    PRODUCTION_WRITE_SCOPE,
    PRODUCTION_WRITE_SCOPES,
    ProductionTokenRole,
    ProductionWriteTokenAuthorizationResult,
)
from tridentine_calendar_google_sync.production_write_token_report import (
    build_production_write_token_authorization_report,
    render_production_write_token_authorization_report_json,
    render_production_write_token_authorization_report_text,
)

pytestmark = pytest.mark.google_production_write

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def _authorize(
    root: Path,
    authorizer: FakeAuthorizer,
) -> tuple[ProductionWriteTokenAuthorizationResult, dict[str, Path]]:
    paths = artifact_paths(root)
    write_fake_client_config(paths["client"])
    target = production_target()
    result = authorize_production_write_token(
        paths["client"],
        paths["write"],
        paths["generation"],
        paths["read"],
        paths["test"],
        target,
        production_write_token_authorization_challenge(target),
        authorizer=authorizer,
        issued_at=ISSUED_AT,
    )
    return result, paths


def test_exact_target_challenge_scope_role_and_fake_authorization_are_closed(
    tmp_path: Path,
) -> None:
    target = production_target()
    authorizer = FakeAuthorizer(oauth_credentials())
    result, paths = _authorize(tmp_path, authorizer)

    assert production_write_token_authorization_challenge(target) == (
        f"AUTHORIZE PRODUCTION WRITE TOKEN ONLY {result.token.target_safe_ref}"
    )
    assert PRODUCTION_WRITE_SCOPES == (PRODUCTION_WRITE_SCOPE,)
    assert validate_production_write_scopes(PRODUCTION_WRITE_SCOPES) == (PRODUCTION_WRITE_SCOPE,)
    assert validate_production_token_role(result.token.role) is ProductionTokenRole.PRODUCTION_WRITE
    assert authorizer.calls == 1
    assert authorizer.client_seen is True
    assert authorizer.scopes == PRODUCTION_WRITE_SCOPES
    assert result.browser_launch_count == 1
    assert result.oauth_attempt_count == 1
    assert result.calendar_api_call_count == 0
    assert result.generation_state.generation == 1
    assert paths["write"].is_file()
    assert paths["generation"].is_file()
    assert not paths["read"].exists()
    assert not paths["test"].exists()
    assert set(ProductionTokenRole) == {
        ProductionTokenRole.PRODUCTION_READ,
        ProductionTokenRole.TEST_WRITE,
        ProductionTokenRole.PRODUCTION_WRITE,
    }


@pytest.mark.parametrize(
    "confirmation_transform",
    (
        str.lower,
        lambda value: value + " ",
        lambda value: value.replace(" ", "  ", 1),
    ),
)
def test_confirmation_mismatch_stops_before_oauth_and_file_writes(
    tmp_path: Path,
    confirmation_transform: Callable[[str], str],
) -> None:
    paths = artifact_paths(tmp_path)
    write_fake_client_config(paths["client"])
    target = production_target()
    authorizer = FakeAuthorizer(oauth_credentials())

    with pytest.raises(ProductionWriteTokenAuthorizationError) as captured:
        authorize_production_write_token(
            paths["client"],
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            confirmation_transform(production_write_token_authorization_challenge(target)),
            authorizer=authorizer,
            issued_at=ISSUED_AT,
        )
    assert captured.value.code == "production_write_token_confirmation_mismatch"
    assert authorizer.calls == 0
    assert not paths["write"].exists()
    assert not paths["generation"].exists()


def test_default_live_authorizer_is_hard_off_and_calendar_capability_is_absent(
    tmp_path: Path,
) -> None:
    paths = artifact_paths(tmp_path)
    write_fake_client_config(paths["client"])
    target = production_target()
    with pytest.raises(ProductionWriteTokenAuthorizationError) as captured:
        authorize_production_write_token(
            paths["client"],
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            production_write_token_authorization_challenge(target),
            authorizer=None,
            issued_at=ISSUED_AT,
        )
    assert captured.value.code == "production_live_oauth_disabled_in_phase_6d0"
    assert not paths["write"].exists()
    assert not paths["generation"].exists()


@pytest.mark.parametrize(
    ("target_update", "expected_code"),
    (
        ({"target_environment": "test"}, "production_write_target_policy_mismatch"),
        ({"target_label": "test"}, "production_write_target_policy_mismatch"),
        ({"target_purpose": "test_calendar_write"}, "production_write_target_policy_mismatch"),
        ({"calendar_id": "primary"}, "production_write_target_policy_mismatch"),
    ),
)
def test_test_or_primary_target_is_rejected_before_oauth(
    tmp_path: Path,
    target_update: dict[str, object],
    expected_code: str,
) -> None:
    paths = artifact_paths(tmp_path)
    write_fake_client_config(paths["client"])
    target = production_target().model_copy(update=target_update)
    authorizer = FakeAuthorizer(oauth_credentials())
    with pytest.raises(ValueError) as captured:
        authorize_production_write_token(
            paths["client"],
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            "does-not-matter",
            authorizer=authorizer,
            issued_at=ISSUED_AT,
        )
    assert getattr(captured.value, "code", None) == expected_code
    assert authorizer.calls == 0


@pytest.mark.parametrize(
    ("scopes", "granted_scopes"),
    (
        ((), PRODUCTION_WRITE_SCOPES),
        (
            (PRODUCTION_WRITE_SCOPE, "https://www.googleapis.com/auth/calendar"),
            PRODUCTION_WRITE_SCOPES,
        ),
        (
            ("https://www.googleapis.com/auth/calendar.events.owned.readonly",),
            PRODUCTION_WRITE_SCOPES,
        ),
        (PRODUCTION_WRITE_SCOPES, ()),
        (PRODUCTION_WRITE_SCOPES, (PRODUCTION_WRITE_SCOPE, "openid")),
    ),
)
def test_missing_broad_extra_or_incremental_scope_is_rejected_before_write(
    tmp_path: Path,
    scopes: tuple[str, ...],
    granted_scopes: tuple[str, ...],
) -> None:
    authorizer = FakeAuthorizer(oauth_credentials(scopes=scopes, granted_scopes=granted_scopes))
    with pytest.raises(ProductionWriteTokenConfigError) as captured:
        _authorize(tmp_path, authorizer)
    assert captured.value.code == "unsafe_production_write_scope"
    assert authorizer.calls == 1
    assert not (tmp_path / "production-write-token.json").exists()
    assert not (tmp_path / "production-write-generation.json").exists()


def test_wrong_role_is_rejected_without_generic_or_cross_role_fallback() -> None:
    for role in (
        ProductionTokenRole.PRODUCTION_READ,
        ProductionTokenRole.TEST_WRITE,
        "write",
        "production_write",
    ):
        with pytest.raises(ProductionWriteTokenConfigError) as captured:
            validate_production_token_role(role)
        assert captured.value.code == "production_write_token_role_mismatch"


def test_repository_existing_same_and_symlink_paths_stop_before_oauth(tmp_path: Path) -> None:
    target = production_target()
    challenge = production_write_token_authorization_challenge(target)

    paths = artifact_paths(tmp_path)
    write_fake_client_config(paths["client"])
    authorizer = FakeAuthorizer(oauth_credentials())
    with pytest.raises(ProductionWriteTokenIOError):
        authorize_production_write_token(
            paths["client"],
            REPOSITORY_ROOT / "never-write-token.json",
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            challenge,
            authorizer=authorizer,
            issued_at=ISSUED_AT,
        )
    assert authorizer.calls == 0

    paths["write"].write_text("existing", encoding="utf-8")
    with pytest.raises(ProductionWriteTokenIOError):
        authorize_production_write_token(
            paths["client"],
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            challenge,
            authorizer=authorizer,
            issued_at=ISSUED_AT,
        )
    assert authorizer.calls == 0

    paths["write"].unlink()
    with pytest.raises(ProductionWriteTokenIOError):
        authorize_production_write_token(
            paths["client"],
            paths["write"],
            paths["generation"],
            paths["write"],
            paths["test"],
            target,
            challenge,
            authorizer=authorizer,
            issued_at=ISSUED_AT,
        )
    assert authorizer.calls == 0

    symlink = tmp_path / "token-link.json"
    try:
        symlink.symlink_to(paths["write"])
    except OSError:
        pytest.skip("symlink creation unavailable")
    with pytest.raises(ProductionWriteTokenIOError):
        authorize_production_write_token(
            paths["client"],
            symlink,
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            challenge,
            authorizer=authorizer,
            issued_at=ISSUED_AT,
        )
    assert authorizer.calls == 0


def test_client_credential_symlink_is_rejected_before_oauth(tmp_path: Path) -> None:
    paths = artifact_paths(tmp_path)
    write_fake_client_config(paths["client"])
    client_link = tmp_path / "client-link.json"
    try:
        client_link.symlink_to(paths["client"])
    except OSError:
        pytest.skip("symlink creation unavailable")
    target = production_target()
    authorizer = FakeAuthorizer(oauth_credentials())
    with pytest.raises(ProductionWriteTokenIOError):
        authorize_production_write_token(
            client_link,
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            production_write_token_authorization_challenge(target),
            authorizer=authorizer,
            issued_at=ISSUED_AT,
        )
    assert authorizer.calls == 0


def test_private_files_are_atomic_private_and_public_report_is_redacted(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    result, paths = _authorize(tmp_path, FakeAuthorizer(oauth_credentials()))
    if os.name == "posix":
        assert paths["write"].stat().st_mode & 0o777 == 0o600
        assert paths["generation"].stat().st_mode & 0o777 == 0o600
    assert not list(tmp_path.glob(".private-write-*"))

    report = build_production_write_token_authorization_report(result)
    rendered = (
        render_production_write_token_authorization_report_json(report)
        + render_production_write_token_authorization_report_text(report)
        + repr(result)
        + repr(result.token)
    )
    print(rendered)
    captured = capsys.readouterr()
    exposed = captured.out + captured.err
    for secret in (
        FAKE_ACCESS_TOKEN,
        FAKE_REFRESH_TOKEN,
        FAKE_CLIENT_ID,
        FAKE_CLIENT_SECRET,
    ):
        assert secret not in exposed
    assert "calendar.example.invalid" not in exposed
    assert str(tmp_path) not in exposed
    assert report.calendar_api_call_count == 0

    token_schema = json.loads(
        (
            REPOSITORY_ROOT / "schemas/production-write-authorized-user-token-v1.schema.json"
        ).read_text("utf-8")
    )
    generation_schema = json.loads(
        (
            REPOSITORY_ROOT / "schemas/production-write-token-generation-state-v1.schema.json"
        ).read_text("utf-8")
    )
    report_schema = json.loads(
        (
            REPOSITORY_ROOT / "schemas/production-write-token-authorization-report-v1.schema.json"
        ).read_text("utf-8")
    )
    jsonschema.validate(
        json.loads(render_production_write_authorized_user_token_json(result.token)), token_schema
    )
    jsonschema.validate(
        json.loads(render_production_write_token_generation_state_json(result.generation_state)),
        generation_schema,
    )
    jsonschema.validate(
        json.loads(render_production_write_token_authorization_report_json(report)), report_schema
    )
    assert all(
        schema["additionalProperties"] is False
        for schema in (token_schema, generation_schema, report_schema)
    )


def test_second_bundle_write_failure_removes_only_new_outputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from tridentine_calendar_google_sync import production_write_token_io

    paths = artifact_paths(tmp_path)
    write_fake_client_config(paths["client"])
    target = production_target()
    authorizer = FakeAuthorizer(oauth_credentials())

    def fail_second_write(*_args: object, **_kwargs: object) -> Path:
        raise ProductionWriteTokenIOError(
            "injected_second_write_failure",
            "Injected second bundle write failure",
        )

    monkeypatch.setattr(
        production_write_token_io,
        "write_production_write_authorized_user_token",
        fail_second_write,
    )
    with pytest.raises(ProductionWriteTokenIOError) as captured:
        authorize_production_write_token(
            paths["client"],
            paths["write"],
            paths["generation"],
            paths["read"],
            paths["test"],
            target,
            production_write_token_authorization_challenge(target),
            authorizer=authorizer,
            issued_at=ISSUED_AT,
        )
    assert captured.value.code == "injected_second_write_failure"
    assert authorizer.calls == 1
    assert not paths["write"].exists()
    assert not paths["generation"].exists()


@pytest.mark.parametrize(
    ("access_token", "refresh_token"),
    (("", FAKE_REFRESH_TOKEN), (FAKE_ACCESS_TOKEN, "")),
)
def test_missing_access_or_refresh_token_stops_before_persistence(
    tmp_path: Path,
    access_token: str,
    refresh_token: str,
) -> None:
    authorizer = FakeAuthorizer(
        oauth_credentials(access_token=access_token, refresh_token=refresh_token)
    )
    with pytest.raises(ProductionWriteTokenConfigError) as captured:
        _authorize(tmp_path, authorizer)
    assert captured.value.code == "production_write_token_credentials_invalid"
    assert not (tmp_path / "production-write-token.json").exists()
