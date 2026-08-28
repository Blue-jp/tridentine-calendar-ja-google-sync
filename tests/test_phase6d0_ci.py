from __future__ import annotations

import re
import tomllib

import pytest
from conftest import REPOSITORY_ROOT

pytestmark = pytest.mark.google_production_write

EXPECTED_GOOGLE_DISTRIBUTIONS = {
    "google-api-python-client",
    "google-auth",
    "google-auth-httplib2",
    "google-auth-oauthlib",
}


def _distribution_name(requirement: str) -> str:
    match = re.match(r"[A-Za-z0-9_.-]+", requirement)
    assert match is not None
    return match.group(0).lower().replace("_", "-")


def test_google_production_write_extra_isolated_and_reuses_existing_dependency_set() -> None:
    metadata = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    base = {_distribution_name(value) for value in metadata["project"]["dependencies"]}
    optional = metadata["project"]["optional-dependencies"]
    production_write = {_distribution_name(value) for value in optional["google-production-write"]}
    google_read = {_distribution_name(value) for value in optional["google-read"]}
    test_write = {_distribution_name(value) for value in optional["google-test-write"]}

    assert base == {"icalendar", "pydantic"}
    assert production_write == EXPECTED_GOOGLE_DISTRIBUTIONS
    assert production_write == google_read == test_write


def test_lockfile_records_production_write_extra_without_new_dependency_names() -> None:
    lock = tomllib.loads((REPOSITORY_ROOT / "uv.lock").read_text(encoding="utf-8"))
    project = next(
        package
        for package in lock["package"]
        if package["name"] == "tridentine-calendar-ja-google-sync"
    )
    optional = project["optional-dependencies"]
    production_write = {item["name"] for item in optional["google-production-write"]}
    google_read = {item["name"] for item in optional["google-read"]}
    test_write = {item["name"] for item in optional["google-test-write"]}

    assert {item["name"] for item in project["dependencies"]} == {"icalendar", "pydantic"}
    assert production_write == EXPECTED_GOOGLE_DISTRIBUTIONS
    assert production_write == google_read == test_write


def test_ci_has_eight_linux_windows_layers_and_no_live_inputs() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")

    assert workflow.count("os: ubuntu-latest") == 4
    assert workflow.count("os: windows-latest") == 4
    for layer in ("base", "google-read", "google-test-write", "google-production-write"):
        assert workflow.count(f"layer: {layer}") == 2
    assert workflow.count("--extra dev --extra google-production-write") == 2
    assert workflow.count("pytest_args: -m google_production_write") == 2
    assert "if: matrix.layer != 'base'" in workflow
    assert (
        '-m "not google_read and not google_test_write and not google_production_write"' in workflow
    )
    assert "contents: read" in workflow
    for forbidden in (
        "workflow_dispatch",
        "secrets.",
        "credentials-file",
        "token-file",
        "authorize-production-write-token",
        "rehearse-production-write-token-readonly",
    ):
        assert forbidden not in workflow


def test_phase6d0_tests_are_isolated_in_production_write_layer() -> None:
    tests = sorted((REPOSITORY_ROOT / "tests").glob("test_*phase6d0.py"))

    assert tests
    for path in tests:
        source = path.read_text(encoding="utf-8")
        assert "pytestmark = pytest.mark.google_production_write" in source
