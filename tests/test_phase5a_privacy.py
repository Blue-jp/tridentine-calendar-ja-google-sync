from __future__ import annotations

import ast
import json
import re
import subprocess
from pathlib import Path

import pytest
from conftest import REPOSITORY_ROOT

pytestmark = pytest.mark.google_test_write

PHASE5A_SOURCE_NAMES = {
    "google_test_write_auth.py",
    "google_test_write_client.py",
    "test_write_approval.py",
    "test_write_journal.py",
    "test_write_models.py",
    "test_write_report.py",
    "test_write_run_spec.py",
    "test_write_run_spec_io.py",
    "test_write_target.py",
    "test_write_transport.py",
}


def _phase5a_sources() -> list[Path]:
    root = REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync"
    paths = sorted(root / name for name in PHASE5A_SOURCE_NAMES)
    assert all(path.is_file() for path in paths)
    return paths


def test_phase5a_has_no_eager_google_network_browser_or_oauth_import() -> None:
    forbidden_roots = {
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
    for path in _phase5a_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        roots: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots.add(node.module.split(".", 1)[0])
        assert roots.isdisjoint(forbidden_roots)


def test_google_method_surface_is_static_and_exactly_list_get_import_patch() -> None:
    discovered: set[str] = set()
    for path in _phase5a_sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            receiver = node.func.value
            if (
                isinstance(receiver, ast.Call)
                and isinstance(receiver.func, ast.Attribute)
                and receiver.func.attr == "events"
            ):
                discovered.add(node.func.attr)
    assert discovered == {"list", "get", "import_", "patch"}
    for forbidden in (
        "insert",
        "update",
        "delete",
        "move",
        "watch",
        "clear",
        "batch",
        "calendarList",
        "calendars",
        "acl",
    ):
        assert forbidden not in discovered


def test_no_dynamic_method_escape_hatch_or_if_match_wildcard() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in _phase5a_sources())
    for forbidden in (
        "getattr(service.events()",
        "getattr(self._service",
        '"If-Match": "*"',
        "'If-Match': '*'",
        "events.insert",
        "events.update",
        "events.delete",
        "events.move",
        "calendars.clear",
    ):
        assert forbidden not in source


def test_public_journal_and_report_schemas_exclude_sensitive_fields() -> None:
    for name in ("test-write-journal-v1.schema.json", "test-write-report-v1.schema.json"):
        schema = json.loads((REPOSITORY_ROOT / "schemas" / name).read_text(encoding="utf-8"))
        serialized = json.dumps(schema, sort_keys=True).casefold()
        for forbidden in (
            "calendar_id",
            "google_event_id",
            '"etag"',
            '"summary"',
            '"description"',
            '"payload"',
            '"endpoint"',
            '"authorization"',
            '"access_token"',
            '"refresh_token"',
            '"credentials"',
        ):
            assert forbidden not in serialized


def test_candidate_tracked_phase5a_files_contain_only_synthetic_identity_values() -> None:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    candidate_paths = [
        REPOSITORY_ROOT / value
        for value in result.stdout.splitlines()
        if value.startswith(("tests/", "schemas/", "docs/"))
        or value in {"README.md", ".gitignore", ".github/workflows/test.yml"}
    ]
    forbidden_patterns = (
        rb"(?i)@group\.calendar\.google\.com",
        rb"(?i)/calendar/ical/[^\s]+/private-[^\s]+/basic\.ics",
        rb"(?i)calendar\.google\.com/calendar/[^\s]*[?&]cid=",
        rb"(?i)authorization\s*:\s*bearer\s+",
        rb"(?i)[A-Z]:[\\/]+Users[\\/]+",
        rb"/(?:home|Users)/[^/\s]+/",
        rb"(?i)[A-Z0-9._%+\-]+@gmail\.com",
    )
    for path in candidate_paths:
        if not path.is_file():
            continue
        raw = path.read_bytes()
        assert not any(re.search(pattern, raw) for pattern in forbidden_patterns)


def test_no_runtime_test_or_production_artifact_is_candidate_tracked() -> None:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    tracked = result.stdout.splitlines()
    runtime = [
        path
        for path in tracked
        if path.startswith(
            (
                "snapshots/",
                "state/",
                "baselines/",
                "plans/",
                "test-write-run-specs/",
                "test-write-journals/",
                "test-write-reports/",
                "test-write-receipts/",
            )
        )
        or path.endswith(
            (
                ".baseline.json",
                ".sync-plan.json",
                ".test-write-run-spec.json",
                ".test-write-journal.json",
                ".test-write-report.json",
                ".test-write-receipt.json",
            )
        )
    ]
    assert runtime == []
    assert not any(
        re.search(r"(?i)(?:^|/)(credential|client_secret|token)[^/]*\.json$", path)
        for path in tracked
    )
