from __future__ import annotations

import ast
import re
import socket
import subprocess
import tomllib

import pytest
from conftest import REPOSITORY_ROOT
from pytest_socket import SocketBlockedError

FORBIDDEN_DISTRIBUTIONS = {
    "google-api-python-client",
    "google-auth",
    "google-auth-httplib2",
    "google-auth-oauthlib",
    "oauthlib",
    "requests-oauthlib",
}
FORBIDDEN_IMPORT_ROOTS = {
    "aiohttp",
    "google",
    "httpx",
    "oauthlib",
    "requests",
    "socket",
    "urllib3",
}


def _distribution_name(requirement: str) -> str:
    match = re.match(r"[A-Za-z0-9_.-]+", requirement)
    assert match is not None
    return match.group(0).lower().replace("_", "-")


def test_package_metadata_has_no_google_or_oauth_dependency() -> None:
    metadata = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = metadata["project"]["dependencies"]
    for dependencies in metadata["project"].get("optional-dependencies", {}).values():
        declared.extend(dependencies)

    names = {_distribution_name(requirement) for requirement in declared}
    assert names.isdisjoint(FORBIDDEN_DISTRIBUTIONS)
    assert not any(name.startswith("google-") for name in names)


def test_lockfile_has_no_google_or_oauth_package() -> None:
    locked = tomllib.loads((REPOSITORY_ROOT / "uv.lock").read_text(encoding="utf-8"))
    names = {
        str(package["name"]).lower().replace("_", "-") for package in locked.get("package", [])
    }

    assert names.isdisjoint(FORBIDDEN_DISTRIBUTIONS)
    assert not any(name.startswith("google-") for name in names)


def test_source_package_has_no_network_google_or_oauth_imports() -> None:
    source_root = REPOSITORY_ROOT / "src" / "tridentine_calendar_google_sync"
    discovered: set[str] = set()
    for source_file in source_root.glob("*.py"):
        tree = ast.parse(source_file.read_text(encoding="utf-8"), filename=source_file.name)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                discovered.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                discovered.add(node.module.split(".", maxsplit=1)[0])

    assert discovered.isdisjoint(FORBIDDEN_IMPORT_ROOTS)


def test_only_synthetic_ics_fixtures_are_tracked_by_the_source_tree() -> None:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "*.ics",
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    ics_paths = [REPOSITORY_ROOT / line for line in result.stdout.splitlines() if line]

    assert ics_paths
    assert all(path.parent == REPOSITORY_ROOT / "tests" / "fixtures" for path in ics_paths)
    assert all(path.stat().st_size < 64 * 1024 for path in ics_paths)


def test_synthetic_fixture_inventory_contains_no_url_or_secret_material() -> None:
    fixture_directory = REPOSITORY_ROOT / "tests" / "fixtures"
    expected_names = {
        "duplicate_uid.ics",
        "escaped_newline.ics",
        "explicit_dtend.ics",
        "folded_description.ics",
        "malformed.ics",
        "missing_description.ics",
        "missing_summary.ics",
        "missing_uid.ics",
        "recurring_event.ics",
        "timed_event.ics",
        "unicode_text.ics",
        "valid_minimal.ics",
    }
    fixtures = sorted(fixture_directory.glob("*.ics"))

    assert {path.name for path in fixtures} == expected_names
    forbidden_fragments = (
        "http://",
        "https://",
        "calendar.google.com",
        "authorization:",
        "bearer ",
        "client_secret",
        "access_token",
        "refresh_token",
        "@gmail.com",
    )
    for fixture in fixtures:
        text = fixture.read_text(encoding="utf-8").casefold()
        assert not any(fragment in text for fragment in forbidden_fragments)
        for uid in re.findall(r"(?m)^uid:(.+)$", text):
            assert uid.rstrip("\r").endswith("@example.invalid")


def test_pytest_socket_blocks_network_by_default() -> None:
    with pytest.warns(UserWarning, match=r"socket\.socket"), pytest.raises(SocketBlockedError):
        socket.socket()
