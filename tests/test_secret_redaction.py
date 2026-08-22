from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from tridentine_calendar_google_sync.models import AcceptedSourceProfile
from tridentine_calendar_google_sync.source_ics import inspect_source
from tridentine_calendar_google_sync.source_report import (
    render_json_report,
    render_text_report,
)

ProfileFactory = Callable[..., AcceptedSourceProfile]


def _all_normal_reports(
    source: Path,
    profile: AcceptedSourceProfile,
) -> tuple[str, str]:
    inspection = inspect_source(source, profile)
    return (
        render_text_report(inspection, profile),
        render_json_report(inspection, profile),
    )


def test_reports_exclude_raw_uid_description_and_absolute_source_path(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    raw_uid = "fixture-valid-001@example.invalid"
    raw_description = "Safe fixture description"
    profile = synthetic_profile_factory(valid_source)

    reports = _all_normal_reports(valid_source, profile)

    for report in reports:
        assert raw_uid not in report
        assert raw_description not in report
        assert str(valid_source.resolve()) not in report


def test_duplicate_report_contains_only_safe_uid_reference(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = fixtures_dir / "duplicate_uid.ics"
    raw_uid = "fixture-duplicate-001@example.invalid"
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

    reports = _all_normal_reports(source, profile)

    for report in reports:
        assert raw_uid not in report
        assert "U-" in report


def test_malformed_report_does_not_echo_parser_content(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = fixtures_dir / "malformed.ics"
    raw_description = "This component is intentionally not closed"
    profile = synthetic_profile_factory(source)

    reports = _all_normal_reports(source, profile)

    for report in reports:
        assert raw_description not in report
        assert "fixture-malformed-001@example.invalid" not in report
        assert str(source.resolve()) not in report
