"""Synthetic-only private secret read tests; no Google SDK or online calls."""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import traceback
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

import tridentine_calendar_google_sync.google_auth as google_auth
import tridentine_calendar_google_sync.google_test_write_auth as google_test_write_auth
import tridentine_calendar_google_sync.production_write_token_io as token_io
import tridentine_calendar_google_sync.sensitive_paths as sensitive_paths
from tridentine_calendar_google_sync.production_write_token_models import (
    PRODUCTION_WRITE_SCOPES,
    ProductionWriteAuthorizedUserToken,
    ProductionWriteGrantedScopeEvidence,
    ProductionWriteGrantEvidenceOrigin,
)

KINDS = ("client", "read_token", "test_token", "production_token")
LOADERS: dict[str, Callable[[str | Path], object]] = {
    "client": google_auth.load_desktop_client_config,
    "read_token": google_auth.load_authorized_user_token,
    "test_token": google_test_write_auth.load_test_write_authorized_user_token,
    "production_token": token_io.load_production_write_authorized_user_token,
}
ERRORS: dict[str, tuple[type[Exception], str]] = {
    "client": (google_auth.GoogleAuthConfigError, "unsafe_desktop_client_path"),
    "read_token": (google_auth.GoogleAuthConfigError, "unsafe_authorized_user_path"),
    "test_token": (
        google_test_write_auth.TestWriteAuthConfigError,
        "unsafe_test_write_authorized_user_path",
    ),
    "production_token": (
        token_io.ProductionWriteTokenIOError,
        "unsafe_production_write_token_path",
    ),
}


def _text(kind: str) -> str:
    if kind == "client":
        return json.dumps(
            {
                "installed": {
                    "client_id": "unit4-client.example.invalid",
                    "client_secret": "synthetic-private-client-secret",
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": ["http://localhost"],
                }
            }
        )
    if kind == "production_token":
        evidence = ProductionWriteGrantedScopeEvidence(
            origin=ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_AUTHORIZATION_RESPONSE,
            raw_scope_tokens=PRODUCTION_WRITE_SCOPES,
            granted_scopes=PRODUCTION_WRITE_SCOPES,
            observed_at=datetime(2099, 1, 1, tzinfo=UTC),
        )
        token = ProductionWriteAuthorizedUserToken(
            target_safe_ref="T-" + "a" * 12,
            target_config_hash="b" * 64,
            generation=1,
            access_token="synthetic-private-access",
            refresh_token="synthetic-private-refresh",
            client_id="unit4-client.example.invalid",
            client_secret="synthetic-private-client-secret",
            token_uri="https://oauth2.googleapis.com/token",
            scopes=PRODUCTION_WRITE_SCOPES,
            grant_evidence=evidence,
            expiry=datetime(2099, 1, 2, tzinfo=UTC),
        )
        return token_io.render_production_write_authorized_user_token_json(token)
    scopes = (
        google_auth.READ_ONLY_GOOGLE_SCOPES
        if kind == "read_token"
        else google_test_write_auth.TEST_WRITE_GOOGLE_SCOPES
    )
    return json.dumps(
        {
            "type": "authorized_user",
            "token": "synthetic-private-access",
            "refresh_token": "synthetic-private-refresh",
            "client_id": "unit4-client.example.invalid",
            "client_secret": "synthetic-private-client-secret",
            "token_uri": "https://oauth2.googleapis.com/token",
            "scopes": list(scopes),
        }
    )


def _assert_rejected(kind: str, path: Path) -> None:
    error, code = ERRORS[kind]
    with pytest.raises(error) as captured:
        LOADERS[kind](path)
    assert getattr(captured.value, "code", None) == code
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True
    assert str(path) not in "".join(traceback.format_exception(captured.value))


@pytest.mark.parametrize("kind", KINDS)
def test_private_secret_loader_round_trip(tmp_path: Path, kind: str) -> None:
    path = tmp_path / "private-secret.json"
    sensitive_paths.atomic_write_private_text(path, _text(kind))
    before = path.read_bytes()
    assert LOADERS[kind](path) is not None
    assert path.read_bytes() == before


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode checks")
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("mode", (0o640, 0o604, 0o660, 0o606))
def test_secret_group_or_other_permissions_rejected(
    tmp_path: Path,
    kind: str,
    mode: int,
) -> None:
    path = tmp_path / "broad-secret.json"
    path.write_text(_text(kind), encoding="utf-8")
    path.chmod(mode)
    before = path.read_bytes()
    _assert_rejected(kind, path)
    assert path.read_bytes() == before
    assert path.stat().st_mode & 0o777 == mode


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership")
@pytest.mark.parametrize("kind", KINDS)
def test_secret_wrong_effective_owner_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    path = tmp_path / "owner-bound-secret.json"
    sensitive_paths.atomic_write_private_text(path, _text(kind))
    uid = os.geteuid()
    monkeypatch.setattr(sensitive_paths.os, "geteuid", lambda: uid + 1)
    _assert_rejected(kind, path)


@pytest.mark.skipif(os.name != "posix", reason="POSIX hardlink")
@pytest.mark.parametrize("kind", KINDS)
def test_secret_hardlink_rejected(tmp_path: Path, kind: str) -> None:
    path = tmp_path / "original-secret.json"
    alias = tmp_path / "alias-secret.json"
    sensitive_paths.atomic_write_private_text(path, _text(kind))
    os.link(path, alias)
    _assert_rejected(kind, alias)
    assert path.exists() and alias.exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX symlink")
@pytest.mark.parametrize("kind", KINDS)
def test_secret_symlink_rejected(tmp_path: Path, kind: str) -> None:
    path = tmp_path / "original-secret.json"
    alias = tmp_path / "alias-secret.json"
    sensitive_paths.atomic_write_private_text(path, _text(kind))
    alias.symlink_to(path)
    _assert_rejected(kind, alias)


@pytest.mark.skipif(os.name != "posix", reason="POSIX private reader")
@pytest.mark.parametrize("require_protected", (True, False))
def test_windows_option_never_relaxes_posix_mode(
    tmp_path: Path,
    require_protected: bool,
) -> None:
    path = tmp_path / "broad.txt"
    path.write_text("synthetic bytes", encoding="utf-8")
    path.chmod(0o644)
    with pytest.raises(sensitive_paths.SensitivePathError) as captured:
        sensitive_paths.read_private_sensitive_bytes(
            path,
            windows_require_protected_acl=require_protected,
        )
    assert captured.value.code == "sensitive_input_permissions_unsafe"


@pytest.mark.parametrize("require_protected", (True, False))
def test_windows_dispatch_retains_private_acl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    require_protected: bool,
) -> None:
    recorded: dict[str, object] = {}

    def fake_reader(*_args: object, **kwargs: object) -> bytes:
        recorded.update(kwargs)
        return b"synthetic bytes"

    # Substitute only this module's os reference, not process-wide os.name.
    monkeypatch.setattr(sensitive_paths, "os", SimpleNamespace(name="nt", fspath=os.fspath))
    monkeypatch.setattr(sensitive_paths, "read_windows_sensitive_bytes", fake_reader)
    assert (
        sensitive_paths.read_private_sensitive_bytes(
            tmp_path / "dispatch-only.txt",
            windows_require_protected_acl=require_protected,
        )
        == b"synthetic bytes"
    )
    assert recorded["private_acl"] is True
    assert recorded["integrity_acl"] is False
    assert recorded["require_protected_acl"] is require_protected


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO")
def test_private_reader_rejects_fifo_without_waiting(tmp_path: Path) -> None:
    path = tmp_path / "synthetic-fifo"
    os.mkfifo(path, 0o600)
    code = """
import sys
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError, read_private_sensitive_bytes,
)
try:
    read_private_sensitive_bytes(sys.argv[1])
except SensitivePathError as exc:
    sys.exit(0 if exc.code == 'sensitive_input_not_file' else 2)
sys.exit(3)
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(sensitive_paths.__file__).resolve().parents[1])
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-c", code, str(path)],
        env=env,
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0


@pytest.mark.parametrize("kind", KINDS)
def test_secret_loaders_have_no_generic_read_fallback(kind: str) -> None:
    loader = LOADERS[kind]
    module = sys.modules[loader.__module__]
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == loader.__name__
    )
    calls = {
        node.func.id
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "read_private_sensitive_bytes" in calls
    assert "read_sensitive_bytes" not in calls
    if kind == "production_token":
        assert "_require_private_file_mode" not in calls
