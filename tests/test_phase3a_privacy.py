from __future__ import annotations

import json
import re
from pathlib import Path

from conftest import REPOSITORY_ROOT

from tridentine_calendar_google_sync.google_client import EVENTS_LIST_FIELDS

EXPECTED_PAGE_FIXTURES = {
    "cancelled.json",
    "color_label.json",
    "empty_page_with_token.json",
    "malformed.json",
    "one_page.json",
    "permission_error.json",
    "rate_limit_error.json",
    "special.json",
    "two_pages.json",
    "unknown_extended.json",
}


def test_raw_api_page_fixture_inventory_is_exact_and_synthetic(
    google_api_pages_dir: Path,
) -> None:
    paths = sorted(google_api_pages_dir.glob("*.json"))

    assert {path.name for path in paths} == EXPECTED_PAGE_FIXTURES
    assert all(path.stat().st_size < 64 * 1024 for path in paths)


def test_raw_page_fixtures_have_no_url_email_or_secret_value(
    google_api_pages_dir: Path,
) -> None:
    forbidden = (
        rb"(?i)https?://",
        rb"(?i)file://",
        rb"(?i)authorization\s*:",
        rb"(?i)\bbearer\s+",
        rb"(?i)(?:access|refresh)[_-]?token",
        rb"(?i)client[_-]?secret",
        rb"(?i)cookie\s*:",
        rb"(?i)@[a-z0-9._-]*gmail\.com",
        rb"(?i)@group\.calendar\.google\.com",
        rb"(?i)[A-Z]:[\\/]+Users[\\/]+",
        rb"/(?:home|Users)/[^/\s]+/",
    )

    for path in google_api_pages_dir.glob("*.json"):
        raw = path.read_bytes()
        assert not any(re.search(pattern, raw) for pattern in forbidden)


def test_raw_page_events_use_only_fixture_identity_values(
    google_api_pages_dir: Path,
) -> None:
    event_count = 0
    for path in google_api_pages_dir.glob("*.json"):
        document = json.loads(path.read_text(encoding="utf-8"))
        for response in document.get("responses", []):
            items = response.get("items", [])
            if not isinstance(items, list):
                continue
            for event in items:
                event_count += 1
                assert re.fullmatch(r"evtfixtureapi[0-9]+", event["id"])
                uid = event.get("iCalUID")
                if uid is not None:
                    assert re.fullmatch(r"fixture-api-[0-9]+@example\.invalid", uid)
                assert "htmlLink" not in event
                assert not isinstance(event.get("creator"), dict) or "email" not in event["creator"]
                assert (
                    not isinstance(event.get("organizer"), dict)
                    or "email" not in event["organizer"]
                )
    assert event_count == 8


def test_events_list_field_mask_has_no_attendee_or_write_payload_field() -> None:
    for forbidden in (
        "attendees",
        "attachments",
        "conferenceData",
        "hangoutLink",
        "creator(email)",
        "organizer(email)",
    ):
        assert forbidden not in EVENTS_LIST_FIELDS


def test_secret_and_runtime_artifact_patterns_remain_gitignored() -> None:
    ignore = (REPOSITORY_ROOT / ".gitignore").read_text(encoding="utf-8")

    for pattern in (
        "credentials*.json",
        "client_secret*.json",
        "oauth_client*.json",
        "authorized_user*.json",
        "token*.json",
        "private-config/",
        "google-target*.toml",
        "snapshots/",
        "state/",
    ):
        assert pattern in ignore

    assert "google-snapshot*.json" in ignore
    assert "!schemas/google-snapshot-v1.schema.json" in ignore
