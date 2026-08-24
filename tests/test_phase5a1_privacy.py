from __future__ import annotations

import ast
import inspect
import json
import re
import subprocess
import tomllib
from pathlib import Path

import pytest
from conftest import REPOSITORY_ROOT

import tridentine_calendar_google_sync.cli as cli
from tridentine_calendar_google_sync.google_test_prewrite_client import (
    GoogleTestCalendarPrewriteListClient,
)

pytestmark = pytest.mark.google_test_write

PHASE5A1_MODULES = {
    "google_test_prewrite_client.py",
    "test_calendar_prewrite.py",
    "test_calendar_prewrite_io.py",
    "test_calendar_prewrite_models.py",
    "test_calendar_prewrite_report.py",
}


def _sources() -> list[Path]:
    root = REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync"
    paths = sorted(root / name for name in PHASE5A1_MODULES)
    assert all(path.is_file() for path in paths)
    return paths


def test_prewrite_google_call_graph_contains_only_static_events_list() -> None:
    discovered: set[str] = set()
    for path in _sources():
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

    assert discovered == {"list"}
    for forbidden in (
        "get",
        "import_",
        "patch",
        "insert",
        "update",
        "delete",
        "move",
        "watch",
        "clear",
        "batch",
    ):
        assert forbidden not in discovered


def test_prewrite_adapter_has_no_generic_service_or_mutation_escape_hatch() -> None:
    assert {
        name
        for name, value in inspect.getmembers(
            GoogleTestCalendarPrewriteListClient,
            inspect.isfunction,
        )
        if not name.startswith("_")
    } == {"list_events"}
    source = "\n".join(path.read_text(encoding="utf-8") for path in _sources())
    for forbidden in (
        "getattr(service.events()",
        "getattr(self._service",
        "events.insert",
        "events.update",
        "events.delete",
        "events.move",
        "calendars.clear",
        "execute_batch",
    ):
        assert forbidden not in source


def test_cli_prewrite_handler_does_not_reach_write_runner_or_mutation_client() -> None:
    source = inspect.getsource(cli._inspect_test_calendar_prewrite_command)

    assert "build_test_calendar_prewrite_list_client" in source
    assert "inspect_test_calendar_prewrite" in source
    for forbidden in (
        "build_test_calendar_write_client",
        "run_test_calendar_write",
        "approve_test_write_run_spec",
        "import_event",
        "patch_event",
        "get_event",
    ):
        assert forbidden not in source


def test_phase5a1_has_no_eager_google_network_browser_or_oauth_import() -> None:
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
    for path in _sources():
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=path.name)
        top_level: set[str] = set()
        for node in tree.body:
            if isinstance(node, ast.Import):
                top_level.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                top_level.add(node.module.split(".", 1)[0])
        assert top_level.isdisjoint(forbidden_roots)


def test_public_report_schema_excludes_every_sensitive_field() -> None:
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "test-calendar-prewrite-report-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    serialized = json.dumps(schema, sort_keys=True).casefold()
    for forbidden in (
        "calendar_id",
        "target_fingerprint",
        "icaluid",
        "event_id",
        '"etag"',
        '"summary"',
        '"description"',
        "access_token",
        "refresh_token",
        "client_id",
        "client_secret",
        "authorization",
        "request_uri",
        "absolute_path",
        "email",
    ):
        assert forbidden not in serialized


def test_candidate_files_have_no_real_calendar_secret_email_or_local_path() -> None:
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
        if "phase5a1" in value
        or "prewrite" in value
        or value in {"README.md", "docs/test-calendar-write-foundation.md", ".gitignore"}
    ]
    forbidden = (
        rb"(?i)@group\.calendar\.google\.com",
        rb"(?i)/calendar/ical/[^\s]+/private-[^\s]+/basic\.ics",
        rb"(?i)calendar\.google\.com/calendar/[^\s]*[?&]cid=",
        rb"(?i)authorization\s*:\s*bearer\s+",
        rb"(?i)[A-Z]:[\\/]+Users[\\/]+",
        rb"/(?:home|Users)/[^/\s]+/",
        rb"(?i)[A-Z0-9._%+\-]+@gmail\.com",
    )
    for path in paths:
        if path.is_file():
            raw = path.read_bytes()
            assert not any(re.search(pattern, raw) for pattern in forbidden)


def test_prewrite_runtime_artifacts_are_ignored_and_untracked() -> None:
    ignore = (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (
        "test-calendar-prewrite-snapshots/",
        "test-calendar-prewrite-reports/",
        "*.test-calendar-prewrite-snapshot.json",
        "*.test-calendar-prewrite-report.json",
        "*.test-calendar-prewrite-report.txt",
    ):
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
        if value.startswith(
            ("test-calendar-prewrite-snapshots/", "test-calendar-prewrite-reports/")
        )
        or value.endswith(
            (
                ".test-calendar-prewrite-snapshot.json",
                ".test-calendar-prewrite-report.json",
                ".test-calendar-prewrite-report.txt",
            )
        )
    ]
    assert runtime == []


def test_dependencies_and_optional_groups_remain_unchanged() -> None:
    metadata = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert metadata["project"]["dependencies"] == ["icalendar>=6,<7", "pydantic>=2,<3"]
    assert (
        metadata["project"]["optional-dependencies"]["google-test-write"]
        == metadata["project"]["optional-dependencies"]["google-read"]
    )
