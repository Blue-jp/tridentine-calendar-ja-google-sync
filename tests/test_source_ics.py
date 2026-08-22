from __future__ import annotations

import os
from collections.abc import Callable
from datetime import date, timedelta
from pathlib import Path

import pytest

from tridentine_calendar_google_sync import source_ics
from tridentine_calendar_google_sync.models import AcceptedSourceProfile
from tridentine_calendar_google_sync.normalization import semantic_text_identity
from tridentine_calendar_google_sync.source_ics import SourceInputError, inspect_source

ProfileFactory = Callable[..., AcceptedSourceProfile]


def _profile_for_date(
    factory: ProfileFactory,
    source: Path,
    expected_date: str,
    **overrides: object,
) -> AcceptedSourceProfile:
    expected = {"first_date": expected_date, "last_date": expected_date, **overrides}
    return factory(source, expected)


def test_valid_minimal_all_day_event_and_implicit_end(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    profile = synthetic_profile_factory(valid_source)

    inspection = inspect_source(valid_source, profile)

    assert inspection.source_sha_matches is True
    assert inspection.source_valid is True
    assert inspection.fatal is False
    assert inspection.vcalendar_count == 1
    assert inspection.vevent_count == 1
    assert inspection.all_day_count == 1
    assert inspection.timed_count == 0
    assert inspection.dtend_present_count == 0
    event = inspection.events[0]
    assert event.all_day is True
    assert event.start_date == date(2026, 1, 15)
    assert event.dtend_present is False
    assert event.explicit_end_date is None
    assert event.effective_end_date == date(2026, 1, 16)
    assert event.effective_end_date == event.start_date + timedelta(days=1)


def test_sha_mismatch_stops_before_parse(
    monkeypatch: pytest.MonkeyPatch,
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    parse_was_called = False

    def unexpected_parse(_raw: bytes) -> object:
        nonlocal parse_was_called
        parse_was_called = True
        raise AssertionError("parser must not run after a SHA mismatch")

    monkeypatch.setattr(source_ics, "parse_source_bytes", unexpected_parse)
    profile = synthetic_profile_factory(valid_source, sha256_override="f" * 64)

    inspection = inspect_source(valid_source, profile)

    assert parse_was_called is False
    assert inspection.source_sha_matches is False
    assert inspection.source_valid is False
    assert inspection.fatal is True
    assert {finding.code for finding in inspection.findings} == {"source_sha256_mismatch"}


def test_explicit_dtend_is_preserved_as_exclusive_end(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = fixtures_dir / "explicit_dtend.ics"
    profile = _profile_for_date(
        synthetic_profile_factory,
        source,
        "2026-05-01",
        dtend_present_count=1,
    )

    inspection = inspect_source(source, profile)

    assert inspection.source_valid is True
    event = inspection.events[0]
    assert event.dtend_present is True
    assert event.explicit_end_date == date(2026, 5, 3)
    assert event.effective_end_date == date(2026, 5, 3)


def test_explicit_dtend_not_after_start_is_invalid(
    tmp_path: Path,
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    raw = valid_source.read_bytes()
    newline = b"\r\n" if b"\r\n" in raw else b"\n"
    invalid = raw.replace(
        b"DTSTART;VALUE=DATE:20260115" + newline,
        b"DTSTART;VALUE=DATE:20260115" + newline + b"DTEND;VALUE=DATE:20260115" + newline,
    )
    source = tmp_path / "invalid-end.ics"
    source.write_bytes(invalid)
    profile = synthetic_profile_factory(source, {"dtend_present_count": 1})

    inspection = inspect_source(source, profile)

    assert inspection.source_valid is False
    assert inspection.fatal is True
    assert any("dtend" in finding.code for finding in inspection.findings)


def test_folded_line_is_unfolded_without_semantic_cleanup(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = fixtures_dir / "folded_description.ics"
    profile = _profile_for_date(synthetic_profile_factory, source, "2026-02-01")

    inspection = inspect_source(source, profile)

    assert inspection.source_valid is True
    assert inspection.events[0].description == (
        "This synthetic description is folded across a transportline and must be unfolded exactly."
    )


def test_escaped_newline_and_punctuation_are_decoded_once(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = fixtures_dir / "escaped_newline.ics"
    profile = _profile_for_date(synthetic_profile_factory, source, "2026-03-01")

    inspection = inspect_source(source, profile)

    assert inspection.source_valid is True
    assert inspection.events[0].description == (
        "First synthetic line\nSecond synthetic line, with comma; and semicolon"
    )


def test_unicode_and_whitespace_are_preserved_exactly(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = fixtures_dir / "unicode_text.ics"
    profile = _profile_for_date(synthetic_profile_factory, source, "2026-04-01")

    inspection = inspect_source(source, profile)

    event = inspection.events[0]
    assert event.summary == "  架空の典礼日　\uff21\uff22\uff23"
    assert event.description == "  日本語の説明 é と é を区別する　空白"
    assert semantic_text_identity(event.summary) is event.summary
    assert semantic_text_identity(event.description) is event.description


def test_timed_event_is_recognized_but_rejected_by_all_day_profile(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = fixtures_dir / "timed_event.ics"
    profile = _profile_for_date(synthetic_profile_factory, source, "2026-10-01")

    inspection = inspect_source(source, profile)

    assert inspection.timed_count == 1
    assert inspection.all_day_count == 0
    assert inspection.events[0].start_datetime is not None
    assert inspection.source_valid is False
    assert inspection.fatal is True


def test_rrule_is_counted_and_rejected_by_nonrecurring_profile(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = fixtures_dir / "recurring_event.ics"
    profile = _profile_for_date(synthetic_profile_factory, source, "2026-11-01")

    inspection = inspect_source(source, profile)

    assert inspection.rrule_count == 1
    assert inspection.events[0].rrule_present is True
    assert inspection.source_valid is False
    assert inspection.fatal is True


@pytest.mark.parametrize(
    "source_value", ["https://example.invalid/calendar.ics", "file:///fixture.ics"]
)
def test_nonlocal_source_forms_are_rejected_without_access(
    source_value: str,
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    profile = synthetic_profile_factory(valid_source)

    with pytest.raises(SourceInputError) as caught:
        inspect_source(source_value, profile)

    assert source_value not in str(caught.value)


def test_windows_style_local_path_is_not_misclassified_as_a_url(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    if os.name == "nt":
        source = valid_source
        source_value = str(source)
        assert "\\" in source_value
    else:
        monkeypatch.chdir(tmp_path)
        source = Path(r"C:\synthetic\calendar.ics")
        source.write_bytes(valid_source.read_bytes())
        source_value = str(source)
    profile = synthetic_profile_factory(source)

    inspection = inspect_source(source_value, profile)

    assert inspection.source_valid is True


def test_symbolic_link_source_is_rejected(
    tmp_path: Path,
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    link = tmp_path / "fixture-link.ics"
    try:
        link.symlink_to(valid_source)
    except OSError:
        pytest.skip("symbolic links are unavailable in this test environment")
    profile = synthetic_profile_factory(valid_source)

    with pytest.raises(SourceInputError) as caught:
        inspect_source(link, profile)

    assert str(link) not in str(caught.value)


def test_oversized_source_is_rejected_before_reading(
    tmp_path: Path,
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = tmp_path / "oversized.ics"
    with source.open("wb") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    profile = synthetic_profile_factory(valid_source)

    with pytest.raises(SourceInputError) as caught:
        inspect_source(source, profile)

    assert str(source) not in str(caught.value)
