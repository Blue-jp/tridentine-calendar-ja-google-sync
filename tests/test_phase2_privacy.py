from __future__ import annotations

import json
import re
import subprocess
import tomllib
from pathlib import Path

from conftest import REPOSITORY_ROOT
from test_google_snapshot import VALID_SNAPSHOT_NAMES


def test_phase2_adds_no_runtime_dependency() -> None:
    metadata = tomllib.loads((REPOSITORY_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    names = {
        re.match(r"[A-Za-z0-9_.-]+", requirement).group(0).lower()  # type: ignore[union-attr]
        for requirement in metadata["project"]["dependencies"]
    }

    assert names == {"icalendar", "pydantic"}


def test_snapshot_fixture_bytes_have_no_secret_url_calendar_or_local_path(
    google_snapshots_dir: Path,
) -> None:
    forbidden_patterns = (
        rb"(?i)https?://",
        rb"(?i)file://",
        rb"(?i)calendar[_-]?id",
        rb"(?i)private[_-]?ical",
        rb"(?i)authorization\s*:",
        rb"(?i)\bbearer\s+",
        rb"(?i)(?:access|refresh)[_-]?token",
        rb"(?i)client[_-]?secret",
        rb"(?i)cookie\s*:",
        rb"(?i)[A-Z]:[\\/]+Users[\\/]+",
        rb"/(?:home|Users)/[^/\s]+/",
        rb"(?i)@gmail\.com",
        rb"(?i)@group\.calendar\.google\.com",
    )

    for path in google_snapshots_dir.glob("*.json"):
        raw = path.read_bytes()
        assert not any(re.search(pattern, raw) for pattern in forbidden_patterns)
        assert len(raw) < 64 * 1024


def test_valid_snapshot_fixtures_use_only_synthetic_identifiers_and_content(
    google_snapshots_dir: Path,
) -> None:
    for fixture_name in sorted(VALID_SNAPSHOT_NAMES):
        document = json.loads((google_snapshots_dir / fixture_name).read_text(encoding="utf-8"))
        assert document["target_fingerprint"] == "a" * 64
        assert document["event_count"] == len(document["events"])
        for event in document["events"]:
            assert re.fullmatch(r"evtfixture[a-z0-9]+", event["id"])
            if event.get("iCalUID") is not None:
                assert re.fullmatch(r"fixture-[a-z0-9-]+@example\.invalid", event["iCalUID"])
            assert "htmlLink" not in event
            assert not isinstance(event.get("creator"), dict) or "email" not in event["creator"]
            assert not isinstance(event.get("organizer"), dict) or "email" not in event["organizer"]


def test_only_synthetic_snapshot_json_is_present_in_candidate_tracked_files() -> None:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "*.json",
        ],
        cwd=REPOSITORY_ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    snapshot_paths = [
        path
        for path in result.stdout.splitlines()
        if "snapshot" in Path(path).name.casefold()
        or "/google_snapshots/" in f"/{path.replace('\\', '/')}/"
    ]

    assert set(snapshot_paths) == {
        "schemas/google-snapshot-v1.schema.json",
        *{
            f"tests/fixtures/google_snapshots/{name}"
            for name in VALID_SNAPSHOT_NAMES | {"malformed_snapshot.json"}
        },
    }


def test_snapshot_schema_has_no_calendar_or_credential_field() -> None:
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "google-snapshot-v1.schema.json").read_text(encoding="utf-8")
    )
    serialized = json.dumps(schema, sort_keys=True).casefold()

    for forbidden in (
        "calendar_id",
        "calendarid",
        "private_ical",
        "authorization",
        "access_token",
        "refresh_token",
        "client_secret",
        "credentials",
    ):
        assert forbidden not in serialized
