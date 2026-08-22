from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from tridentine_calendar_google_sync.models import AcceptedSourceProfile
from tridentine_calendar_google_sync.profiles import load_profile

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
FIXTURES_DIR = Path(__file__).parent / "fixtures"
PROFILES_DIR = REPOSITORY_ROOT / "profiles"


DEFAULT_SYNTHETIC_EXPECTED: dict[str, Any] = {
    "vcalendar_count": 1,
    "vevent_count": 1,
    "uid_total_count": 1,
    "uid_unique_count": 1,
    "uid_duplicate_count": 0,
    "first_date": date(2026, 1, 15),
    "last_date": date(2026, 1, 15),
    "all_day_count": 1,
    "timed_count": 0,
    "dtstart_date_count": 1,
    "dtend_present_count": 0,
    "summary_present_count": 1,
    "description_present_count": 1,
    "dtstamp_present_count": 1,
    "rrule_count": 0,
    "recurrence_id_count": 0,
    "event_x_property_count": 0,
}


def build_synthetic_profile(
    source_path: Path,
    expected_overrides: Mapping[str, Any] | None = None,
    *,
    sha256_override: str | None = None,
) -> AcceptedSourceProfile:
    """Build a validated, non-production profile for a synthetic fixture."""
    base = load_profile("accepted-20260814", profiles_dir=PROFILES_DIR)
    data = base.model_dump(mode="python")
    data.update(
        {
            "profile_id": "synthetic-test-profile",
            "project_name": "Synthetic offline calendar fixture",
        }
    )
    data["source"].update(
        {
            "accepted_tag": "synthetic-test-tag",
            "accepted_commit": "0" * 40,
            "html_sha256": sha256_override or hashlib.sha256(source_path.read_bytes()).hexdigest(),
            "plain_sha256": "1" * 64,
        }
    )
    expected = dict(DEFAULT_SYNTHETIC_EXPECTED)
    if expected_overrides:
        expected.update(expected_overrides)
    for field_name in ("first_date", "last_date"):
        field_value = expected[field_name]
        if isinstance(field_value, str):
            expected[field_name] = date.fromisoformat(field_value)
    data["expected"] = expected
    return AcceptedSourceProfile.model_validate(data)


def write_profile_directory(profile: AcceptedSourceProfile, directory: Path) -> Path:
    """Write one synthetic profile to a pytest-owned temporary directory."""
    directory.mkdir(parents=True, exist_ok=True)
    expected = profile.expected
    text = f'''schema_version = "{profile.schema_version}"
profile_id = "{profile.profile_id}"
project_name = "Synthetic offline calendar fixture"

[source]
accepted_tag = "{profile.source.accepted_tag}"
accepted_commit = "{profile.source.accepted_commit}"
html_sha256 = "{profile.source.html_sha256}"
plain_sha256 = "{profile.source.plain_sha256}"

[expected]
vcalendar_count = {expected.vcalendar_count}
vevent_count = {expected.vevent_count}
uid_total_count = {expected.uid_total_count}
uid_unique_count = {expected.uid_unique_count}
uid_duplicate_count = {expected.uid_duplicate_count}
first_date = "{expected.first_date.isoformat()}"
last_date = "{expected.last_date.isoformat()}"
all_day_count = {expected.all_day_count}
timed_count = {expected.timed_count}
dtstart_date_count = {expected.dtstart_date_count}
dtend_present_count = {expected.dtend_present_count}
summary_present_count = {expected.summary_present_count}
description_present_count = {expected.description_present_count}
dtstamp_present_count = {expected.dtstamp_present_count}
rrule_count = {expected.rrule_count}
recurrence_id_count = {expected.recurrence_id_count}
event_x_property_count = {expected.event_x_property_count}
'''
    (directory / f"{profile.profile_id}.toml").write_text(text, encoding="utf-8")
    return directory


@pytest.fixture
def fixtures_dir() -> Path:
    return FIXTURES_DIR


@pytest.fixture
def valid_source(fixtures_dir: Path) -> Path:
    return fixtures_dir / "valid_minimal.ics"


@pytest.fixture
def synthetic_profile_factory() -> Callable[..., AcceptedSourceProfile]:
    return build_synthetic_profile
