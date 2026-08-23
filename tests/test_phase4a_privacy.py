from __future__ import annotations

import ast
import json
import subprocess
from collections.abc import Callable
from pathlib import Path

from conftest import REPOSITORY_ROOT, SyntheticBaselineBundle

from tridentine_calendar_google_sync.baseline_io import render_baseline_json
from tridentine_calendar_google_sync.plan_engine import build_sync_plan
from tridentine_calendar_google_sync.plan_report import render_plan_json_report

BundleFactory = Callable[..., SyntheticBaselineBundle]


def test_baseline_schema_has_no_google_event_id_etag_or_event_content_field() -> None:
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "trusted-baseline-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    property_names = set(schema["properties"])

    for forbidden in (
        '"event_id"',
        '"google_event_id"',
        '"etag"',
        '"summary"',
        '"description"',
        '"location"',
        '"htmlLink"',
        '"calendar_id"',
    ):
        assert forbidden.strip('"') not in property_names


def test_plan_schema_has_no_executable_request_shape() -> None:
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "sync-plan-v1.schema.json").read_text(encoding="utf-8")
    )
    serialized = json.dumps(schema, sort_keys=True)

    assert schema["properties"]["executable"] == {"const": False}
    for forbidden in (
        '"payload"',
        '"method"',
        '"endpoint"',
        '"headers"',
        '"authorization"',
        '"calendar_id"',
        '"event_id"',
        '"etag"',
    ):
        assert forbidden not in serialized


def test_private_baseline_and_public_plan_use_only_required_identity_forms(
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = synthetic_baseline_bundle_factory(
        valid_source,
        synthetic_profile_factory,
        google_snapshots_dir / "exact_match.json",
    )
    private_baseline = render_baseline_json(bundle.trusted)
    plan = build_sync_plan(bundle.profile, bundle.source, bundle.snapshot, bundle.trusted)
    plan_report = render_plan_json_report(plan)

    assert "fixture-valid-001@example.invalid" in private_baseline
    assert "fixture-valid-001@example.invalid" not in plan_report
    for value in (
        bundle.snapshot.events[0].event_id,
        bundle.snapshot.events[0].etag,
        bundle.snapshot.events[0].summary,
        bundle.snapshot.events[0].description,
    ):
        if value:
            assert value not in private_baseline
            assert value not in plan_report


def test_phase4_modules_have_no_google_network_or_optional_dependency_import() -> None:
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
    }
    for name in (
        "baseline_models.py",
        "baseline_engine.py",
        "baseline_io.py",
        "plan_models.py",
        "plan_engine.py",
        "plan_report.py",
    ):
        path = REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync" / name
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=name)
        roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots.add(node.module.split(".", 1)[0])
        assert roots.isdisjoint(forbidden_roots)


def test_baseline_and_plan_runtime_paths_are_ignored_and_untracked() -> None:
    ignore = (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (
        "baselines/",
        "plans/",
        "*.baseline.json",
        "*.sync-plan.json",
    ):
        assert pattern in ignore

    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    tracked_runtime = [
        path
        for path in result.stdout.splitlines()
        if path.startswith(("baselines/", "plans/"))
        or path.endswith((".baseline.json", ".sync-plan.json"))
    ]
    assert tracked_runtime == []
