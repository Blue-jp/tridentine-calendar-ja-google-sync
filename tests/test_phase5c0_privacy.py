from __future__ import annotations

import ast
import json
import re
import subprocess
import tomllib
from pathlib import Path

from conftest import REPOSITORY_ROOT
from phase5c0_helpers import BOOTSTRAP_UID, build_bootstrap_bundle

from tridentine_calendar_google_sync.test_bootstrap_plan_io import (
    render_test_bootstrap_add_plan_json,
)
from tridentine_calendar_google_sync.test_bootstrap_plan_report import (
    render_test_bootstrap_add_plan_inspection_json,
    render_test_bootstrap_add_plan_inspection_text,
)

BOOTSTRAP_BASE_MODULES = {
    "test_bootstrap_approval.py",
    "test_bootstrap_plan.py",
    "test_bootstrap_plan_io.py",
    "test_bootstrap_plan_models.py",
    "test_bootstrap_plan_report.py",
    "test_bootstrap_run_spec.py",
    "test_bootstrap_run_spec_io.py",
    "test_bootstrap_run_spec_models.py",
    "test_write_approval_dispatch.py",
    "test_write_spec_dispatch.py",
}


def _sources() -> list[Path]:
    root = REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync"
    paths = sorted(root / name for name in BOOTSTRAP_BASE_MODULES)
    assert all(path.is_file() for path in paths)
    return paths


def test_bootstrap_offline_modules_have_no_google_network_oauth_or_browser_imports() -> None:
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


def test_public_plan_and_inspection_exclude_raw_identity_content_and_request_shape(
    tmp_path: Path,
) -> None:
    bundle = build_bootstrap_bundle(tmp_path)
    outputs = (
        render_test_bootstrap_add_plan_json(bundle.plan),
        render_test_bootstrap_add_plan_inspection_json(bundle.plan),
        render_test_bootstrap_add_plan_inspection_text(bundle.plan),
    )

    for rendered in outputs:
        for forbidden in (
            BOOTSTRAP_UID,
            bundle.source.events[0].summary,
            bundle.source.events[0].description,
            "google_event_id",
            '"etag"',
            '"payload"',
            '"endpoint"',
            '"http_method"',
            '"calendar_id"',
        ):
            assert forbidden not in rendered


def test_bootstrap_schemas_are_closed_and_plan_schema_has_no_raw_uid() -> None:
    plan_schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "test-bootstrap-add-plan-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    run_schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "test-bootstrap-add-run-spec-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert plan_schema["additionalProperties"] is False
    assert run_schema["additionalProperties"] is False
    serialized_plan = json.dumps(plan_schema, sort_keys=True).casefold()
    serialized_run = json.dumps(run_schema, sort_keys=True).casefold()
    for forbidden in ("icaluid", "raw_uid", "google_event_id", '"etag"', "payload", "endpoint"):
        assert forbidden not in serialized_plan
    for forbidden in ("google_event_id", '"etag"', "endpoint", "http_method"):
        assert forbidden not in serialized_run


def test_bootstrap_runtime_artifacts_are_ignored_and_untracked() -> None:
    ignore = (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8")
    patterns = (
        "test-bootstrap-add-plans/",
        "test-bootstrap-add-run-specs/",
        "*.test-bootstrap-add-plan.json",
        "*.test-bootstrap-add-run-spec.json",
        "*.test-bootstrap-add-plan-report.json",
        "*.test-bootstrap-add-plan-report.txt",
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
        if value.startswith(("test-bootstrap-add-plans/", "test-bootstrap-add-run-specs/"))
        or value.endswith(
            (
                ".test-bootstrap-add-plan.json",
                ".test-bootstrap-add-run-spec.json",
                ".test-bootstrap-add-plan-report.json",
                ".test-bootstrap-add-plan-report.txt",
            )
        )
    ]
    assert runtime == []


def test_candidate_files_contain_only_synthetic_invalid_identity_and_no_secret_path() -> None:
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
        if "bootstrap" in value or "phase5c0" in value
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


def test_dependencies_and_lock_groups_remain_unchanged() -> None:
    metadata = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert metadata["project"]["dependencies"] == ["icalendar>=6,<7", "pydantic>=2,<3"]
    assert (
        metadata["project"]["optional-dependencies"]["google-test-write"]
        == metadata["project"]["optional-dependencies"]["google-read"]
    )
