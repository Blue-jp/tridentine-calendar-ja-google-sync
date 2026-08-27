from __future__ import annotations

import argparse
import ast
import tomllib

from conftest import REPOSITORY_ROOT

from tridentine_calendar_google_sync.cli import build_parser

PHASE6B_COMMANDS = {
    "inspect-accepted-production-source-manifest",
    "build-production-single-update-plan",
    "inspect-production-single-update-plan",
    "build-production-single-update-run-spec",
    "inspect-production-single-update-run-spec",
}

PHASE6B_TEST_MODULES = {
    "test_accepted_production_source_manifest_phase6b.py",
    "test_production_single_update_plan_phase6b.py",
    "test_production_single_update_run_spec_phase6b.py",
    "test_phase6b_privacy.py",
    "test_phase6b_ci.py",
    "test_cli_phase6b.py",
}


def _distribution_name(requirement: str) -> str:
    return requirement.split("[", 1)[0].split("<", 1)[0].split(">", 1)[0].split("=", 1)[0]


def test_phase6b_keeps_base_install_free_of_google_network_dependencies() -> None:
    metadata = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    base = {_distribution_name(value) for value in metadata["project"]["dependencies"]}
    forbidden = {
        "google-api-python-client",
        "google-auth",
        "google-auth-httplib2",
        "google-auth-oauthlib",
        "requests",
        "httpx",
        "aiohttp",
    }
    assert base.isdisjoint(forbidden)


def test_phase6b_test_modules_are_offline_base_tests_without_google_marker() -> None:
    tests = REPOSITORY_ROOT / "tests"
    for name in PHASE6B_TEST_MODULES:
        path = tests / name
        assert path.is_file()
        source = path.read_text(encoding="utf-8")
        assert "pytestmark = pytest.mark." + "google_read" not in source
        assert "pytestmark = pytest.mark." + "google_test_write" not in source


def test_phase6b_module_import_graph_has_no_optional_google_distribution() -> None:
    source_root = REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync"
    modules = sorted(source_root.glob("*production*.py"))
    assert modules
    forbidden = {"google", "google_auth_oauthlib", "googleapiclient"}
    for path in modules:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        imported: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        assert imported.isdisjoint(forbidden), path.name


def test_cli_inventory_adds_only_five_explicit_offline_commands() -> None:
    parser = build_parser()
    subparsers = next(
        action for action in parser._actions if isinstance(action, argparse._SubParsersAction)
    )
    assert len(subparsers.choices) == 29
    assert set(subparsers.choices) >= PHASE6B_COMMANDS
    assert not {
        "apply-production",
        "execute-production",
        "run-production-single-update",
        "sync-production",
    } & set(subparsers.choices)


def test_phase6b_schemas_and_documentation_are_packaged_and_linked() -> None:
    metadata = (REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    readme = (REPOSITORY_ROOT / "README.md").read_text(encoding="utf-8")
    document = REPOSITORY_ROOT / "docs" / "production-single-update-planning-foundation.md"
    assert '"schemas" = "tridentine_calendar_google_sync/_schemas"' in metadata
    assert document.is_file()
    assert "docs/production-single-update-planning-foundation.md" in readme
    for name in (
        "accepted-production-source-manifest-v1.schema.json",
        "production-single-update-plan-v1.schema.json",
        "production-single-update-run-spec-v1.schema.json",
    ):
        assert (REPOSITORY_ROOT / "schemas" / name).is_file()
