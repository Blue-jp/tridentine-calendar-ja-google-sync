from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from tridentine_calendar_google_sync.models import AcceptedSourceProfile
from tridentine_calendar_google_sync.source_ics import inspect_source

ProfileFactory = Callable[..., AcceptedSourceProfile]


@pytest.mark.parametrize(
    ("fixture_name", "expected_date", "expected_code"),
    [
        ("missing_uid.ics", "2026-07-01", "missing_uid"),
        ("missing_summary.ics", "2026-08-01", "missing_summary"),
        ("missing_description.ics", "2026-09-01", "missing_description"),
    ],
)
def test_required_event_properties_are_fatal(
    fixture_name: str,
    expected_date: str,
    expected_code: str,
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = fixtures_dir / fixture_name
    profile = synthetic_profile_factory(
        source,
        {"first_date": expected_date, "last_date": expected_date},
    )

    inspection = inspect_source(source, profile)

    assert inspection.source_valid is False
    assert inspection.fatal is True
    assert expected_code in {finding.code for finding in inspection.findings}


def test_duplicate_uid_is_fatal_and_only_safe_reference_is_reported(
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

    inspection = inspect_source(source, profile)

    assert inspection.uid_total_count == 2
    assert inspection.uid_unique_count == 1
    assert inspection.uid_duplicate_count == 1
    assert inspection.source_valid is False
    duplicate_findings = [
        finding for finding in inspection.findings if finding.code == "duplicate_uid"
    ]
    assert duplicate_findings
    assert all(finding.event_ref is not None for finding in duplicate_findings)
    assert raw_uid not in repr(inspection)
    assert raw_uid not in repr(inspection.findings)


def test_profile_count_anomaly_is_fatal(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    profile = synthetic_profile_factory(valid_source, {"vevent_count": 4938})

    inspection = inspect_source(valid_source, profile)

    assert inspection.source_valid is False
    assert inspection.fatal is True
    assert "expected_vevent_count_mismatch" in {finding.code for finding in inspection.findings}


def test_profile_date_range_anomaly_is_fatal(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    profile = synthetic_profile_factory(
        valid_source,
        {"first_date": "2024-01-01", "last_date": "2034-12-31"},
    )

    inspection = inspect_source(valid_source, profile)

    assert inspection.source_valid is False
    assert inspection.fatal is True
    codes = {finding.code for finding in inspection.findings}
    assert "expected_first_date_mismatch" in codes
    assert "expected_last_date_mismatch" in codes


def test_missing_dtstart_is_fatal(
    tmp_path: Path,
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    raw = valid_source.read_bytes()
    newline = b"\r\n" if b"\r\n" in raw else b"\n"
    source = tmp_path / "missing-start.ics"
    source.write_bytes(raw.replace(b"DTSTART;VALUE=DATE:20260115" + newline, b""))
    profile = synthetic_profile_factory(source)

    inspection = inspect_source(source, profile)

    assert inspection.source_valid is False
    assert inspection.fatal is True
    assert "missing_dtstart" in {finding.code for finding in inspection.findings}


def test_malformed_ics_returns_redacted_fatal_inspection(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = fixtures_dir / "malformed.ics"
    raw_uid = "fixture-malformed-001@example.invalid"
    raw_description = "This component is intentionally not closed"
    profile = synthetic_profile_factory(source)

    inspection = inspect_source(source, profile)

    assert inspection.source_valid is False
    assert inspection.fatal is True
    assert inspection.malformed_event_count >= 1
    assert "malformed_ics" in {finding.code for finding in inspection.findings}
    assert raw_uid not in repr(inspection)
    assert raw_description not in repr(inspection)
