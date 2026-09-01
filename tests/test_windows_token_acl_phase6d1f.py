"""Real-Windows Production token and credential ACL integration tests."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from phase6d0_auth_helpers import ISSUED_AT, production_target, production_token
from phase6d0_rehearsal_helpers import build_rehearsal_artifacts, run_rehearsal
from windows_sensitive_fs_helpers import (
    assert_private_file,
    create_acl_directory,
    has_effective_right,
    set_private_file_acl,
)

from tridentine_calendar_google_sync import _windows_sensitive_files as windows_files
from tridentine_calendar_google_sync.google_auth import (
    GoogleAuthConfigError,
    load_desktop_client_config,
)
from tridentine_calendar_google_sync.production_write_token import (
    build_initial_production_write_token_generation_state,
)
from tridentine_calendar_google_sync.production_write_token_io import (
    ProductionWriteTokenIOError,
    load_production_write_authorized_user_token,
    load_production_write_token_generation_state,
    render_production_write_authorized_user_token_json,
    validate_production_write_token_path_set,
    write_production_write_authorized_user_token,
    write_production_write_token_generation_state,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_io import (
    write_production_write_token_rehearsal_outputs,
)
from tridentine_calendar_google_sync.sensitive_paths import atomic_write_private_text

pytestmark = [
    pytest.mark.google_production_write,
    pytest.mark.skipif(sys.platform != "win32", reason="requires real Win32 ACLs"),
]


@pytest.fixture
def safe_root(tmp_path: Path) -> Path:
    return create_acl_directory(tmp_path / "phase6d1f-token-safe")


def test_c7_c11_existing_production_token_requires_private_acl(safe_root: Path) -> None:
    state = build_initial_production_write_token_generation_state(
        production_target(),
        issued_at=ISSUED_AT,
    )
    path = safe_root / "token.json"
    token = production_token(state)
    write_production_write_authorized_user_token(token, path)
    assert load_production_write_authorized_user_token(path) == token

    set_private_file_acl(path, broad_principal="BU")
    with pytest.raises(ProductionWriteTokenIOError) as captured:
        load_production_write_authorized_user_token(path)
    assert captured.value.code == "unsafe_production_write_token_path"


def test_c8_c12_refresh_rewrite_preserves_private_acl_and_generation(
    safe_root: Path,
) -> None:
    state = build_initial_production_write_token_generation_state(
        production_target(),
        issued_at=ISSUED_AT,
    )
    token_path = safe_root / "token.json"
    state_path = safe_root / "generation.json"
    original = production_token(state)
    refreshed = original.model_copy(update={"access_token": "synthetic-refreshed-access"})
    write_production_write_authorized_user_token(original, token_path)
    write_production_write_token_generation_state(state, state_path)
    generation_before = state_path.read_bytes()

    write_production_write_authorized_user_token(refreshed, token_path, overwrite=True)

    assert load_production_write_authorized_user_token(token_path) == refreshed
    assert load_production_write_token_generation_state(state_path) == state
    assert state_path.read_bytes() == generation_before
    assert_private_file(token_path)


@pytest.mark.parametrize("principal", ["BU", "WD", "AU"])
def test_c10_credential_broad_read_is_blocked_before_parse(
    safe_root: Path,
    principal: str,
) -> None:
    credential = safe_root / f"credential-{principal}.json"
    atomic_write_private_text(credential, "{}\n")
    set_private_file_acl(credential, broad_principal=principal)
    with pytest.raises(GoogleAuthConfigError) as captured:
        load_desktop_client_config(credential)
    assert captured.value.code == "unsafe_desktop_client_path"


def test_legacy_unprotected_production_token_requires_recreation(safe_root: Path) -> None:
    state = build_initial_production_write_token_generation_state(
        production_target(),
        issued_at=ISSUED_AT,
    )
    path = safe_root / "legacy-token.json"
    path.write_text(
        render_production_write_authorized_user_token_json(production_token(state)),
        encoding="utf-8",
    )
    # An inherited-but-otherwise private DACL is not accepted for the Production
    # token role; explicit re-authorization/recreation is required.
    with pytest.raises(ProductionWriteTokenIOError) as captured:
        load_production_write_authorized_user_token(path)
    assert captured.value.code == "unsafe_production_write_token_path"


def test_rehearsal_snapshot_is_private_but_sanitized_reports_are_not_token_acl(
    tmp_path: Path,
) -> None:
    fixture_root = create_acl_directory(tmp_path / "rehearsal-fixtures")
    output = create_acl_directory(tmp_path / "rehearsal-output", broad_read=True)
    artifacts = build_rehearsal_artifacts(fixture_root)
    outcome = run_rehearsal(artifacts)
    assert outcome.snapshot is not None

    paths = write_production_write_token_rehearsal_outputs(
        output,
        outcome.snapshot,
        outcome.report,
    )

    assert paths.snapshot is not None
    assert_private_file(paths.snapshot)
    for report in (paths.text_report, paths.json_report):
        assert has_effective_right(
            report,
            windows_files._WIN_BUILTIN_USERS_SID,
            windows_files._FILE_READ_DATA,
        )


def test_generation_state_allows_broad_read_but_rejects_nonadmin_write(
    safe_root: Path,
) -> None:
    state = build_initial_production_write_token_generation_state(
        production_target(),
        issued_at=ISSUED_AT,
    )
    readable = safe_root / "generation-readable.json"
    writable = safe_root / "generation-writable.json"
    write_production_write_token_generation_state(state, readable)
    write_production_write_token_generation_state(state, writable)

    set_private_file_acl(readable, broad_principal="BU", broad_rights="GR")
    assert load_production_write_token_generation_state(readable) == state

    set_private_file_acl(writable, broad_principal="BU", broad_rights="GWSD")
    with pytest.raises(ProductionWriteTokenIOError) as loaded:
        load_production_write_token_generation_state(writable)
    assert loaded.value.code == "unsafe_production_write_token_generation_path"
    with pytest.raises(ProductionWriteTokenIOError) as path_set:
        validate_production_write_token_path_set(
            production_write_token_path=safe_root / "future-write-token.json",
            generation_state_path=writable,
            production_read_token_path=safe_root / "production-read-token.json",
            test_write_token_path=safe_root / "test-write-token.json",
            client_config_path=None,
            write_token_exists=False,
            generation_state_exists=True,
        )
    assert path_set.value.code == "unsafe_production_write_token_path_set"
