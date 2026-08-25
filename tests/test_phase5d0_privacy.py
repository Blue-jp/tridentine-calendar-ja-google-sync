from __future__ import annotations

import ast
import json
import re
import subprocess
import tomllib
from pathlib import Path

from conftest import REPOSITORY_ROOT

SINGLE_UPDATE_BASE_MODULES = {
    "test_single_update_plan.py",
    "test_single_update_plan_io.py",
    "test_single_update_plan_models.py",
    "test_single_update_plan_report.py",
    "test_single_update_run_spec.py",
    "test_single_update_run_spec_io.py",
    "test_single_update_run_spec_models.py",
}


def _sources() -> list[Path]:
    root = REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync"
    paths = sorted(root / name for name in SINGLE_UPDATE_BASE_MODULES)
    assert all(path.is_file() for path in paths)
    return paths


def test_single_update_offline_modules_have_no_network_oauth_or_browser_imports() -> None:
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
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        discovered: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                discovered.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                discovered.add(node.module.split(".", 1)[0])
        assert discovered.isdisjoint(forbidden)


def test_dedicated_plan_does_not_call_or_modify_normal_sync_planner() -> None:
    plan = (
        REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync" / "test_single_update_plan.py"
    ).read_text(encoding="utf-8")
    assert "build_sync_plan" not in plan
    assert "_build_guards" not in plan


def test_single_update_schemas_are_closed_and_plan_is_public_safe() -> None:
    plan_schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "test-single-update-plan-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    run_spec_schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "test-single-update-run-spec-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert plan_schema["additionalProperties"] is False
    assert run_spec_schema["additionalProperties"] is False
    serialized_plan = json.dumps(plan_schema, sort_keys=True).casefold()
    for forbidden in (
        "icaluid",
        "raw_uid",
        "google_event_id",
        '"etag"',
        '"summary"',
        '"description":',
        '"calendar_id"',
        '"payload"',
        '"endpoint"',
        '"http_method"',
    ):
        assert forbidden not in serialized_plan


def test_single_update_runtime_artifacts_are_ignored_and_untracked() -> None:
    ignore = (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8")
    patterns = (
        "test-single-update-plans/",
        "test-single-update-run-specs/",
        "*.test-single-update-plan.json",
        "*.test-single-update-run-spec.json",
        "*.test-single-update-plan-report.json",
        "*.test-single-update-plan-report.txt",
    )
    for pattern in patterns:
        assert pattern in ignore

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
        if value.startswith(("test-single-update-plans/", "test-single-update-run-specs/"))
        or value.endswith(
            (
                ".test-single-update-plan.json",
                ".test-single-update-run-spec.json",
                ".test-single-update-plan-report.json",
                ".test-single-update-plan-report.txt",
            )
        )
    ]
    assert runtime == []


def test_single_update_candidate_files_contain_only_synthetic_identity() -> None:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    paths = [
        REPOSITORY_ROOT / value
        for value in result.stdout.splitlines()
        if "single_update" in value or "phase5d0" in value
    ]
    forbidden = (
        rb"(?i)@group\.calendar\.google\.com",
        rb"(?i)/calendar/ical/[^\s]+/private-[^\s]+/basic\.ics",
        rb"(?i)authorization\s*:\s*bearer\s+",
        rb"(?i)[A-Z]:[\\/]+Users[\\/]+",
        rb"/(?:home|Users)/[^/\s]+/",
        rb"(?i)[A-Z0-9._%+\-]+@gmail\.com",
    )
    for path in paths:
        if path.is_file():
            raw = path.read_bytes()
            assert not any(re.search(pattern, raw) for pattern in forbidden)


def test_single_update_adds_no_dependency_or_test_marker() -> None:
    metadata = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["dependencies"] == [
        "icalendar>=6,<7",
        "pydantic>=2,<3",
    ]
    assert (
        metadata["project"]["optional-dependencies"]["google-test-write"]
        == metadata["project"]["optional-dependencies"]["google-read"]
    )
    markers = metadata["tool"]["pytest"]["ini_options"]["markers"]
    assert not any("single_update" in marker for marker in markers)
