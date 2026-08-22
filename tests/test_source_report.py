from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from conftest import REPOSITORY_ROOT
from jsonschema import Draft202012Validator, FormatChecker

from tridentine_calendar_google_sync.models import AcceptedSourceProfile
from tridentine_calendar_google_sync.source_ics import inspect_source
from tridentine_calendar_google_sync.source_report import (
    build_json_report,
    render_json_report,
    render_text_report,
)

ProfileFactory = Callable[..., AcceptedSourceProfile]


def test_json_report_is_schema_valid_and_contains_only_aggregate_data(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    profile = synthetic_profile_factory(valid_source)
    inspection = inspect_source(valid_source, profile)

    report = build_json_report(inspection, profile)
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "source-inspection-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )

    Draft202012Validator(schema, format_checker=FormatChecker()).validate(report)
    assert report["schema_version"] == "1.0"
    assert report["mode"] == "offline"
    assert report["profile"]["profile_id"] == "synthetic-test-profile"
    assert report["aggregate"]["vevent_count"] == 1
    assert report["source_valid"] is True
    assert report["content_hash"] == inspection.content_hash
    assert "events" not in report


def test_json_and_content_hash_are_deterministic(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    profile = synthetic_profile_factory(valid_source)

    first_inspection = inspect_source(valid_source, profile)
    second_inspection = inspect_source(valid_source, profile)
    first_json = render_json_report(first_inspection, profile)
    second_json = render_json_report(second_inspection, profile)

    assert first_inspection.content_hash == second_inspection.content_hash
    assert first_json == second_json
    assert json.loads(first_json) == build_json_report(first_inspection, profile)


def test_human_report_contains_required_offline_summary(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    profile = synthetic_profile_factory(valid_source)
    inspection = inspect_source(valid_source, profile)

    report = render_text_report(inspection, profile)

    required_fragments = (
        "offline",
        "synthetic-test-profile",
        "synthetic-test-tag",
        "source SHA match: yes",
        "VEVENT count: 1",
        "UID total: 1",
        "UID unique: 1",
        "duplicate UID count: 0",
        "all-day count: 1",
        "timed count: 0",
        "2026-01-15",
        "DTEND-present count: 0",
        "SUMMARY-present count: 1",
        "DESCRIPTION-present count: 1",
        "RRULE count: 0",
        "fatal count: 0",
        "source valid: yes",
        "report hash:",
    )
    assert all(fragment in report for fragment in required_fragments)


def test_findings_have_deterministic_order_in_json_report(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = fixtures_dir / "duplicate_uid.ics"
    profile = synthetic_profile_factory(
        source,
        {
            "vevent_count": 2,
            "uid_total_count": 2,
            "uid_unique_count": 2,
            "first_date": "2026-06-01",
            "last_date": "2026-06-02",
            "all_day_count": 2,
            "dtstart_date_count": 2,
            "summary_present_count": 2,
            "description_present_count": 2,
            "dtstamp_present_count": 2,
        },
    )
    inspection = inspect_source(source, profile)

    first = build_json_report(inspection, profile)
    second = build_json_report(inspection, profile)

    assert first["findings"] == second["findings"]
    assert first["fatal_errors"] == first["findings"]
