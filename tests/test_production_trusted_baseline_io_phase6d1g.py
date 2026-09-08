from __future__ import annotations

import ast
import os
import sys
import traceback
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import REPOSITORY_ROOT, SyntheticBaselineBundle
from windows_sensitive_fs_helpers import set_private_file_acl

import tridentine_calendar_google_sync.sensitive_paths as sensitive_paths
from tridentine_calendar_google_sync.baseline_engine import (
    BaselineInputError,
    BaselineValidationError,
)
from tridentine_calendar_google_sync.baseline_io import (
    load_baseline,
    load_production_trusted_baseline,
    render_baseline_json,
    write_baseline,
)

BundleFactory = Callable[..., SyntheticBaselineBundle]


def _bundle(
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> SyntheticBaselineBundle:
    return synthetic_baseline_bundle_factory(
        valid_source,
        synthetic_profile_factory,
        google_snapshots_dir / "exact_match.json",
    )


def test_production_trusted_baseline_private_round_trip(
    tmp_path: Path,
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    path = tmp_path / "production-trusted-baseline.json"

    write_baseline(bundle.trusted, path)

    assert load_production_trusted_baseline(path) == bundle.trusted


def test_production_loader_rejects_candidate_state_without_affecting_generic_loader(
    tmp_path: Path,
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    path = tmp_path / "candidate-baseline.json"

    write_baseline(bundle.candidate, path)
    assert load_baseline(path) == bundle.candidate

    with pytest.raises(BaselineValidationError) as captured:
        load_production_trusted_baseline(path)
    assert captured.value.code == "production_baseline_not_trusted"


def test_production_loader_failure_is_path_free(tmp_path: Path) -> None:
    marker = "PRIVATE_PRODUCTION_BASELINE_PATH_MARKER"
    path = tmp_path / marker / "missing.json"

    with pytest.raises(BaselineInputError) as captured:
        load_production_trusted_baseline(path)

    rendered = "".join(traceback.format_exception(captured.value))
    assert captured.value.code == "unsafe_production_baseline_path"
    assert captured.value.__cause__ is None
    assert captured.value.__suppress_context__ is True
    for value in (str(captured.value), rendered):
        assert marker not in value
        assert str(path) not in value


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX ownership and mode bits")
def test_posix_production_loader_rejects_group_or_other_permissions_but_generic_loads(
    tmp_path: Path,
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    path = tmp_path / "broad-readable-baseline.json"
    path.write_text(render_baseline_json(bundle.trusted), encoding="utf-8", newline="\n")
    path.chmod(0o644)

    assert load_baseline(path) == bundle.trusted
    with pytest.raises(BaselineInputError) as captured:
        load_production_trusted_baseline(path)
    assert captured.value.code == "unsafe_production_baseline_path"


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX hard links")
def test_posix_production_loader_rejects_hard_linked_baseline(
    tmp_path: Path,
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    original = tmp_path / "original-baseline.json"
    alias = tmp_path / "alias-baseline.json"
    write_baseline(bundle.trusted, original)
    os.link(original, alias)

    with pytest.raises(BaselineInputError) as captured:
        load_production_trusted_baseline(alias)
    assert captured.value.code == "unsafe_production_baseline_path"


@pytest.mark.skipif(os.name != "posix", reason="requires POSIX effective UID")
def test_posix_production_loader_requires_current_effective_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    path = tmp_path / "owner-bound-baseline.json"
    write_baseline(bundle.trusted, path)
    actual_uid = os.geteuid()
    monkeypatch.setattr(sensitive_paths.os, "geteuid", lambda: actual_uid + 1)

    with pytest.raises(BaselineInputError) as captured:
        load_production_trusted_baseline(path)
    assert captured.value.code == "unsafe_production_baseline_path"


@pytest.mark.skipif(sys.platform != "win32", reason="requires real Win32 ACLs")
def test_windows_production_loader_requires_protected_private_acl(
    tmp_path: Path,
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    path = tmp_path / "windows-private-baseline.json"
    write_baseline(bundle.trusted, path)
    assert load_production_trusted_baseline(path) == bundle.trusted

    set_private_file_acl(path, broad_principal="BU")
    assert load_baseline(path) == bundle.trusted
    with pytest.raises(BaselineInputError) as captured:
        load_production_trusted_baseline(path)
    assert captured.value.code == "unsafe_production_baseline_path"


def test_production_cli_builders_use_only_strict_baseline_loader() -> None:
    path = REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync" / "cli.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    functions = {
        node.name: node
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }

    for name in (
        "_build_production_single_update_plan_command",
        "_build_production_single_update_run_spec_command",
    ):
        function = functions[name]
        called_names = {
            node.func.id
            for node in ast.walk(function)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
        assert "load_production_trusted_baseline" in called_names
        assert "load_baseline" not in called_names
