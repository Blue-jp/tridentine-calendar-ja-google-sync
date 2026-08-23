from __future__ import annotations

import ast
import json
import subprocess

from conftest import REPOSITORY_ROOT

from tridentine_calendar_google_sync.apply_models import ApplyOperationKind
from tridentine_calendar_google_sync.fake_mutation_transport import FakeMutationTransport

PHASE4B_MODULES = (
    "apply_models.py",
    "apply_policy.py",
    "apply_bundle.py",
    "apply_approval.py",
    "apply_bundle_io.py",
    "retry_policy.py",
    "fake_mutation_transport.py",
    "operation_journal.py",
    "plan_io.py",
    "apply_simulation.py",
    "apply_report.py",
)


def test_phase4b_modules_have_no_google_network_http_or_live_transport_imports() -> None:
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
    for name in PHASE4B_MODULES:
        path = REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync" / name
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=name)
        roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots.add(node.module.split(".", 1)[0])
        assert roots.isdisjoint(forbidden_roots)
        assert not any(
            isinstance(node, (ast.ClassDef, ast.FunctionDef))
            and node.name in {"LiveMutationTransport", "GoogleMutationTransport"}
            for node in ast.walk(tree)
        )


def test_operation_vocabulary_and_fake_transport_have_no_delete_capability() -> None:
    assert {kind.value for kind in ApplyOperationKind} == {"add", "update"}
    for name in ("delete", "simulate_delete", "execute_delete"):
        assert not hasattr(FakeMutationTransport, name)


def test_apply_schemas_allow_no_delete_operation_or_executable_true() -> None:
    bundle_schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "apply-bundle-v1.schema.json").read_text(encoding="utf-8")
    )
    report_schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "apply-report-v1.schema.json").read_text(encoding="utf-8")
    )
    serialized_bundle = json.dumps(bundle_schema, sort_keys=True)
    serialized_report = json.dumps(report_schema, sort_keys=True)

    assert '"operation": {"enum": ["add", "update"]}' in serialized_bundle
    assert '"execution_enabled": {"const": false}' in serialized_bundle
    assert '"delete": {"const": 0}' in serialized_report
    assert '"executable": {"const": false}' in serialized_report


def test_base_dependencies_remain_unchanged() -> None:
    import tomllib

    metadata = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    names = {
        requirement.split(">", 1)[0].split("<", 1)[0].split("=", 1)[0]
        for requirement in metadata["project"]["dependencies"]
    }
    assert names == {"icalendar", "pydantic"}


def test_apply_runtime_artifacts_are_ignored_and_not_tracked() -> None:
    ignore = (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8")
    patterns = (
        "apply-bundles/",
        "journals/",
        "simulations/",
        "*.apply-bundle.json",
        "*.operation-journal.json",
        "*.simulation.json",
    )
    for pattern in patterns:
        assert pattern in ignore

    result = subprocess.run(
        ["git", "ls-files"],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    tracked = [
        path
        for path in result.stdout.splitlines()
        if path.startswith(("apply-bundles/", "journals/", "simulations/"))
        or path.endswith((".apply-bundle.json", ".operation-journal.json", ".simulation.json"))
    ]
    assert tracked == []
