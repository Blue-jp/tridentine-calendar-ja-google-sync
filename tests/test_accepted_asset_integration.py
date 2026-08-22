from __future__ import annotations

import os
from pathlib import Path

import pytest
from conftest import PROFILES_DIR

from tridentine_calendar_google_sync.profiles import load_profile
from tridentine_calendar_google_sync.source_ics import inspect_source


@pytest.mark.integration
def test_full_accepted_html_asset_when_explicitly_configured() -> None:
    configured_path = os.environ.get("TRIDENTINE_ACCEPTED_HTML_ICS_PATH")
    if not configured_path:
        pytest.skip("Accepted HTML ICS path is not configured")

    profile = load_profile("accepted-20260814", profiles_dir=PROFILES_DIR)
    try:
        inspection = inspect_source(Path(configured_path), profile)
    except Exception as exc:  # Broad catch deliberately redacts unexpected parser failures.
        pytest.fail(f"Accepted asset validation failed safely: {type(exc).__name__}")

    assert inspection.source_sha_matches is True
    assert inspection.vevent_count == 4938
    assert inspection.uid_total_count == 4938
    assert inspection.uid_unique_count == 4938
    assert inspection.uid_duplicate_count == 0
    assert inspection.first_date is not None
    assert inspection.first_date.isoformat() == "2024-01-01"
    assert inspection.last_date is not None
    assert inspection.last_date.isoformat() == "2034-12-31"
    assert inspection.all_day_count == 4938
    assert inspection.timed_count == 0
    assert inspection.dtend_present_count == 0
    assert inspection.summary_present_count == 4938
    assert inspection.description_present_count == 4938
    assert inspection.dtstamp_present_count == 4938
    assert inspection.rrule_count == 0
    assert inspection.recurrence_id_count == 0
    assert inspection.fatal_count == 0
    assert inspection.source_valid is True
