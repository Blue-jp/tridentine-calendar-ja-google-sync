from __future__ import annotations

import ast
import os
import sys
import traceback
from pathlib import Path

import pytest
from conftest import REPOSITORY_ROOT
from windows_sensitive_fs_helpers import set_private_file_acl

import tridentine_calendar_google_sync.sensitive_paths as sensitive_paths
from tridentine_calendar_google_sync.google_target import calendar_id_fingerprint
from tridentine_calendar_google_sync.production_write_target import (
    ProductionWriteTargetConfigError,
    load_production_write_target_config,
)
from tridentine_calendar_google_sync.sensitive_paths import (
    atomic_write_private_text,
    read_sensitive_bytes,
)


def _target_text(calendar_id: str = "production-calendar@calendar.example") -> str:
    fingerprint = calendar_id_fingerprint(calendar_id)
    return "\n".join(
        (
            "schema_version = 1",
            'target_environment = "production"',
            'target_label = "production"',
            'target_purpose = "production_calendar_single_update"',
            f'calendar_id = "{calendar_id}"',
            f'expected_target_fingerprint = "{fingerprint}"',
            'expected_summary = "Production Liturgical Calendar"',
            'expected_access_role = "owner"',
            'expected_time_zone = "Asia/Tokyo"',
            "",
        )
    )


def test_production_target_private_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "production-target.toml"
    atomic_write_private_text(path, _target_text())

    config = load_production_write_target_config(path)

    assert config.target_environment == "production"
    assert config.target_purpose == "production_calendar_single_update"
    assert config.expected_access_role == "owner"
    assert config.expected_time_zone == "Asia/Tokyo"


def test_production_target_path_failure_is_private_and_path_free(tmp_path: Path) -> None:
    marker = "PRIVATE_PRODUCTION_TARGET_PATH_MARKER"
    path = tmp_path / marker / "missing.toml"

    with pytest.raises(ProductionWriteTargetConfigError) as captured:
        load_production_write_target_config(path)

    rendered = "".join(traceback.format_exception(captured.value))
    assert captured.value.code == "unsafe_production_write_target_path"
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True
    for value in (str(captured.value), rendered):
        assert marker not in value
        assert str(path) not in value


def test_invalid_production_target_does_not_chain_private_values(tmp_path: Path) -> None:
    marker = "PRIVATE_CALENDAR_ID_MARKER@calendar.example"
    path = tmp_path / "invalid-production-target.toml"
    invalid_text = _target_text(marker).replace(
        'target_label = "production"',
        'target_label = "invalid"',
    )
    atomic_write_private_text(path, invalid_text)

    with pytest.raises(ProductionWriteTargetConfigError) as captured:
        load_production_write_target_config(path)

    rendered = "".join(traceback.format_exception(captured.value))
    assert captured.value.code == "invalid_production_write_target_config"
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True
    assert marker not in str(captured.value)
    assert marker not in rendered


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX ownership and mode bits")
def test_posix_production_target_rejects_group_or_other_permissions(tmp_path: Path) -> None:
    path = tmp_path / "broad-readable-target.toml"
    path.write_text(_target_text(), encoding="utf-8", newline="\n")
    path.chmod(0o644)

    assert read_sensitive_bytes(path) == _target_text().encode("utf-8")
    with pytest.raises(ProductionWriteTargetConfigError) as captured:
        load_production_write_target_config(path)
    assert captured.value.code == "unsafe_production_write_target_path"


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX hard links")
def test_posix_production_target_rejects_hard_links(tmp_path: Path) -> None:
    original = tmp_path / "original-target.toml"
    alias = tmp_path / "alias-target.toml"
    atomic_write_private_text(original, _target_text())
    os.link(original, alias)

    with pytest.raises(ProductionWriteTargetConfigError) as captured:
        load_production_write_target_config(alias)
    assert captured.value.code == "unsafe_production_write_target_path"


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX effective UID")
def test_posix_production_target_requires_current_effective_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "owner-bound-target.toml"
    atomic_write_private_text(path, _target_text())
    actual_uid = os.geteuid()
    monkeypatch.setattr(sensitive_paths.os, "geteuid", lambda: actual_uid + 1)

    with pytest.raises(ProductionWriteTargetConfigError) as captured:
        load_production_write_target_config(path)
    assert captured.value.code == "unsafe_production_write_target_path"


@pytest.mark.skipif(sys.platform != "win32", reason="requires real Win32 ACLs")
def test_windows_production_target_requires_protected_private_acl(tmp_path: Path) -> None:
    path = tmp_path / "windows-private-target.toml"
    atomic_write_private_text(path, _target_text())
    assert load_production_write_target_config(path).target_environment == "production"

    set_private_file_acl(path, broad_principal="BU")
    assert read_sensitive_bytes(path) == _target_text().encode("utf-8")
    with pytest.raises(ProductionWriteTargetConfigError) as captured:
        load_production_write_target_config(path)
    assert captured.value.code == "unsafe_production_write_target_path"


def test_production_target_loader_uses_only_strict_private_reader() -> None:
    path = (
        REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync" / "production_write_target.py"
    )
    tree = ast.parse(path.read_text(encoding="utf-8"))
    function = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "load_production_write_target_config"
    )
    called_names = {
        node.func.id
        for node in ast.walk(function)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert "read_private_sensitive_bytes" in called_names
    assert "read_sensitive_bytes" not in called_names
