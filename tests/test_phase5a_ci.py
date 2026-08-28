from __future__ import annotations

import re
import tomllib

import pytest
from conftest import REPOSITORY_ROOT

pytestmark = pytest.mark.google_test_write

EXPECTED_GOOGLE_DISTRIBUTIONS = {
    "google-api-python-client",
    "google-auth",
    "google-auth-httplib2",
    "google-auth-oauthlib",
}


def _name(requirement: str) -> str:
    match = re.match(r"[A-Za-z0-9_.-]+", requirement)
    assert match is not None
    return match.group(0).lower().replace("_", "-")


def test_google_test_write_extra_isolated_from_base_and_matches_google_read() -> None:
    metadata = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    base = {_name(value) for value in metadata["project"]["dependencies"]}
    optional = metadata["project"]["optional-dependencies"]
    dev = {_name(value) for value in optional["dev"]}
    google_read = {_name(value) for value in optional["google-read"]}
    google_test_write = {_name(value) for value in optional["google-test-write"]}

    assert base == {"icalendar", "pydantic"}
    assert google_read == EXPECTED_GOOGLE_DISTRIBUTIONS
    assert google_test_write == EXPECTED_GOOGLE_DISTRIBUTIONS
    assert not any(name.startswith("google-") for name in base | dev)


def test_lockfile_records_google_test_write_as_optional_only() -> None:
    lock = tomllib.loads((REPOSITORY_ROOT / "uv.lock").read_text(encoding="utf-8"))
    project = next(
        package
        for package in lock["package"]
        if package["name"] == "tridentine-calendar-ja-google-sync"
    )
    base = {item["name"] for item in project["dependencies"]}
    google_test_write = {
        item["name"] for item in project["optional-dependencies"]["google-test-write"]
    }

    assert base == {"icalendar", "pydantic"}
    assert google_test_write == EXPECTED_GOOGLE_DISTRIBUTIONS


def test_ci_has_exact_linux_windows_base_and_three_google_layers() -> None:
    workflow = (REPOSITORY_ROOT / ".github" / "workflows" / "test.yml").read_text(encoding="utf-8")

    assert workflow.count("layer: base") == 2
    assert workflow.count("layer: google-read") == 2
    assert workflow.count("layer: google-test-write") == 2
    assert workflow.count("layer: google-production-write") == 2
    assert workflow.count("os: ubuntu-latest") == 4
    assert workflow.count("os: windows-latest") == 4
    assert "--extra dev --extra google-test-write" in workflow
    assert "pytest_args: -m google_test_write" in workflow
    assert "pytest_args: -m google_production_write" in workflow
    assert "not google_read and not google_test_write and not google_production_write" in workflow
    assert "contents: read" in workflow
    for forbidden in (
        "workflow_dispatch",
        "TRIDENTINE_ACCEPTED_HTML_ICS_PATH",
        "client_secret",
        "credentials-file",
        "token-file",
        "fetch-google-snapshot",
        "run-test-calendar-write",
    ):
        assert forbidden not in workflow


def test_phase5a_runtime_artifacts_are_gitignored() -> None:
    ignore = (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8")
    for pattern in (
        "test-write-run-specs/",
        "test-write-journals/",
        "test-write-reports/",
        "test-write-receipts/",
        "*.test-write-run-spec.json",
        "*.test-write-journal.json",
        "*.test-write-report.json",
        "*.test-write-receipt.json",
        "test-write-target*.toml",
        "token*.json",
        "credentials*.json",
    ):
        assert pattern in ignore
