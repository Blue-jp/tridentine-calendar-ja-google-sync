from __future__ import annotations

import ast
import json
import subprocess
from pathlib import Path

from conftest import REPOSITORY_ROOT

PHASE6B_MODULES = {
    "accepted_production_source_manifest.py",
    "accepted_production_source_manifest_io.py",
    "accepted_production_source_manifest_models.py",
    "accepted_production_source_manifest_report.py",
    "production_approval_material.py",
    "production_single_update_plan.py",
    "production_single_update_plan_io.py",
    "production_single_update_plan_models.py",
    "production_single_update_plan_report.py",
    "production_single_update_run_spec.py",
    "production_single_update_run_spec_io.py",
    "production_single_update_run_spec_models.py",
    "production_single_update_run_spec_report.py",
    "production_write_target.py",
}

PHASE6B_SCHEMAS = {
    "accepted-production-source-manifest-v1.schema.json",
    "production-single-update-plan-v1.schema.json",
    "production-single-update-run-spec-v1.schema.json",
}


def _module_paths() -> list[Path]:
    source = REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync"
    paths = sorted(source / name for name in PHASE6B_MODULES)
    assert all(path.is_file() for path in paths)
    return paths


def _schema_property_names(schema: object) -> set[str]:
    if isinstance(schema, dict):
        names = set(schema.get("properties", {}))
        for value in schema.values():
            names.update(_schema_property_names(value))
        return names
    if isinstance(schema, list):
        names: set[str] = set()
        for value in schema:
            names.update(_schema_property_names(value))
        return names
    return set()


def _all_object_schemas_are_closed(schema: object) -> bool:
    if isinstance(schema, dict):
        if schema.get("type") == "object" and schema.get("additionalProperties") is not False:
            return False
        return all(_all_object_schemas_are_closed(value) for value in schema.values())
    if isinstance(schema, list):
        return all(_all_object_schemas_are_closed(value) for value in schema)
    return True


def test_phase6b_offline_modules_import_no_network_oauth_browser_or_google_package() -> None:
    forbidden = {
        "aiohttp",
        "google",
        "google_auth_oauthlib",
        "googleapiclient",
        "httpx",
        "oauthlib",
        "requests",
        "socket",
        "urllib3",
        "webbrowser",
    }
    for path in _module_paths():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        discovered: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                discovered.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                discovered.add(node.module.split(".", 1)[0])
        assert discovered.isdisjoint(forbidden), path.name


def test_phase6b_planning_modules_expose_no_mutation_or_credential_boundary() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in _module_paths())
    for forbidden in (
        "events.patch",
        "patch_event(",
        "import_event(",
        "delete_event(",
        "load_test_write_credentials",
        "build_test_calendar_write_client",
        "authorization",
        "access_token",
        "refresh_token",
    ):
        assert forbidden not in source


def test_phase6b_schemas_are_recursively_closed_and_transport_identity_free() -> None:
    schemas = REPOSITORY_ROOT / "schemas"
    forbidden_properties = {
        "uid",
        "icaluid",
        "summary",
        "description",
        "current_state",
        "desired_state",
        "calendar_id",
        "google_event_id",
        "event_id",
        "etag",
        "payload",
        "endpoint",
        "http_method",
        "authorization",
        "token",
        "credentials",
    }
    for name in PHASE6B_SCHEMAS:
        schema = json.loads((schemas / name).read_text(encoding="utf-8"))
        assert _all_object_schemas_are_closed(schema), name
        names = {value.casefold() for value in _schema_property_names(schema)}
        assert names.isdisjoint(forbidden_properties), name


def test_phase6b_runtime_artifacts_are_ignored_and_absent_from_git_inventory() -> None:
    ignore = (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8")
    directory_patterns = (
        "accepted-production-source-manifests/",
        "production-single-update-plans/",
        "production-single-update-run-specs/",
    )
    suffix_patterns = (
        ".accepted-production-source-manifest.json",
        ".accepted-production-source-manifest-report.json",
        ".accepted-production-source-manifest-report.txt",
        ".production-single-update-plan.json",
        ".production-single-update-plan-report.json",
        ".production-single-update-plan-report.txt",
        ".production-single-update-run-spec.json",
        ".production-single-update-run-spec-report.json",
        ".production-single-update-run-spec-report.txt",
    )
    for pattern in (*directory_patterns, *(f"*{suffix}" for suffix in suffix_patterns)):
        assert pattern in ignore
    assert "production-write-target*.toml" in ignore

    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    runtime = [
        value
        for value in result.stdout.splitlines()
        if value.startswith(directory_patterns) or value.endswith(suffix_patterns)
    ]
    assert runtime == []


def test_phase6b_sources_tests_schemas_and_doc_contain_no_current_operational_pins() -> None:
    paths = [
        *_module_paths(),
        *(REPOSITORY_ROOT / "tests").glob("*phase6b*.py"),
        *(REPOSITORY_ROOT / "schemas").glob("*production*.json"),
        REPOSITORY_ROOT / "docs" / "production-single-update-planning-foundation.md",
    ]
    current_operational_values = (
        "c0dedd86257df2ff1a950" + "97bcf3824b2b95fce66",
        "1c0ee8a19769f9ff26b1a40d03d0280a" + "fdcbde1d7d50642ad3f2123c117dd552",
        "962725c8029993af7fc02450cb29ab6c" + "18eaa4db0569023f53d114be1247ae62",
        "ja-localization-" + "accepted-20260814",
        "T-e10f" + "0095ab8f",
    )
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for value in current_operational_values:
            assert value not in text, path.name
