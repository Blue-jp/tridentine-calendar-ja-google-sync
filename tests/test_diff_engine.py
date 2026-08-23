from __future__ import annotations

import json
import unicodedata
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.diff_models import (
    DiffClassification,
    ManagedScope,
)
from tridentine_calendar_google_sync.google_snapshot import (
    load_google_snapshot,
    parse_google_snapshot_bytes,
)
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.source_ics import inspect_source

ProfileFactory = Callable[..., AcceptedSourceProfile]


def _snapshot_document_for_source(source: SourceCalendarInspection) -> dict[str, Any]:
    event = source.events[0]
    assert event.uid is not None
    assert event.start_date is not None
    assert event.effective_end_date is not None
    return {
        "schema_version": "1.0",
        "snapshot_format": "sanitized-google-calendar-v1",
        "target_fingerprint": "b" * 64,
        "complete": True,
        "event_count": 1,
        "page_count": 1,
        "events": [
            {
                "id": "evtfixturememory001",
                "iCalUID": event.uid,
                "summary": event.summary,
                "description": event.description,
                "start": {"date": event.start_date.isoformat()},
                "end": {"date": event.effective_end_date.isoformat()},
                "allDay": True,
                "status": "confirmed",
                "eventType": "default",
            }
        ],
    }


def _parse_document(document: dict[str, Any]):
    raw = json.dumps(document, ensure_ascii=False).encode("utf-8")
    return parse_google_snapshot_bytes(raw)


def _source(
    valid_source: Path,
    factory: ProfileFactory,
):
    return inspect_source(valid_source, factory(valid_source))


def _diff(
    fixture_name: str,
    *,
    valid_source: Path,
    factory: ProfileFactory,
    snapshots: Path,
    managed_scope: ManagedScope | None = None,
):
    source = _source(valid_source, factory)
    snapshot = load_google_snapshot(snapshots / fixture_name)
    return diff_source_to_snapshot(source, snapshot, managed_scope)


def test_exact_match_is_unchanged(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _diff(
        "exact_match.json",
        valid_source=valid_source,
        factory=synthetic_profile_factory,
        snapshots=google_snapshots_dir,
    )

    assert diff.counts.unchanged == 1
    assert diff.counts.update == 0
    assert diff.counts.add == 0
    assert diff.fatal is False
    assert diff.has_changes is False
    assert diff.events[0].classification is DiffClassification.UNCHANGED


@pytest.mark.parametrize(
    ("fixture_name", "expected_fields"),
    [
        ("summary_changed.json", {"summary"}),
        ("description_changed.json", {"description"}),
        ("date_changed.json", {"start_date", "end_date"}),
    ],
)
def test_exact_managed_field_changes_are_updates_with_content_free_differences(
    fixture_name: str,
    expected_fields: set[str],
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _diff(
        fixture_name,
        valid_source=valid_source,
        factory=synthetic_profile_factory,
        snapshots=google_snapshots_dir,
    )

    assert diff.counts.update == 1
    event = diff.events[0]
    assert event.classification is DiffClassification.UPDATE
    assert {item.field for item in event.differences} == expected_fields
    for difference in event.differences:
        assert len(difference.current_hash) == 64
        assert len(difference.desired_hash) == 64
        assert difference.current_hash != difference.desired_hash


def test_multiple_managed_field_changes_are_one_update_with_all_fields(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = _source(valid_source, synthetic_profile_factory)
    document = _snapshot_document_for_source(source)
    event = document["events"][0]
    event.update(
        {
            "summary": "Changed multiple-field summary",
            "description": "Changed multiple-field description",
            "start": {"date": "2026-01-20"},
            "end": {"date": "2026-01-21"},
        }
    )

    diff = diff_source_to_snapshot(source, _parse_document(document))

    assert diff.counts.update == 1
    assert {item.field for item in diff.events[0].differences} == {
        "summary",
        "description",
        "start_date",
        "end_date",
    }


def test_empty_description_is_present_and_not_equal_to_nonempty_source(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = _source(valid_source, synthetic_profile_factory)
    document = _snapshot_document_for_source(source)
    document["events"][0]["description"] = ""

    diff = diff_source_to_snapshot(source, _parse_document(document))

    description = diff.events[0].differences[0]
    assert description.field == "description"
    assert description.current_present is True
    assert description.current_length == 0
    assert description.desired_present is True


def test_null_and_absent_google_description_have_same_canonical_diff(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source = _source(valid_source, synthetic_profile_factory)
    null_document = _snapshot_document_for_source(source)
    null_document["events"][0]["description"] = None
    absent_document = _snapshot_document_for_source(source)
    absent_document["events"][0].pop("description")

    null_snapshot = _parse_document(null_document)
    absent_snapshot = _parse_document(absent_document)
    null_diff = diff_source_to_snapshot(source, null_snapshot)
    absent_diff = diff_source_to_snapshot(source, absent_snapshot)

    assert null_snapshot.content_hash == absent_snapshot.content_hash
    assert null_diff == absent_diff
    assert null_diff.events[0].differences[0].current_present is False


def test_unicode_is_compared_exactly_without_normalization(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source_path = fixtures_dir / "unicode_text.ics"
    source = inspect_source(
        source_path,
        synthetic_profile_factory(
            source_path,
            {"first_date": "2026-04-01", "last_date": "2026-04-01"},
        ),
    )
    exact_document = _snapshot_document_for_source(source)

    exact = diff_source_to_snapshot(source, _parse_document(exact_document))
    normalized_document = _snapshot_document_for_source(source)
    description = normalized_document["events"][0]["description"]
    assert isinstance(description, str)
    normalized_document["events"][0]["description"] = unicodedata.normalize("NFC", description)
    normalized = diff_source_to_snapshot(source, _parse_document(normalized_document))

    assert exact.counts.unchanged == 1
    assert normalized.counts.update == 1
    assert {item.field for item in normalized.events[0].differences} == {"description"}


def test_newlines_are_compared_exactly(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source_path = fixtures_dir / "escaped_newline.ics"
    source = inspect_source(
        source_path,
        synthetic_profile_factory(
            source_path,
            {"first_date": "2026-03-01", "last_date": "2026-03-01"},
        ),
    )
    exact_document = _snapshot_document_for_source(source)
    changed_document = _snapshot_document_for_source(source)
    description = changed_document["events"][0]["description"]
    assert isinstance(description, str)
    changed_document["events"][0]["description"] = description.replace("\n", " ")

    exact = diff_source_to_snapshot(source, _parse_document(exact_document))
    changed = diff_source_to_snapshot(source, _parse_document(changed_document))

    assert exact.counts.unchanged == 1
    assert changed.counts.update == 1
    assert {item.field for item in changed.events[0].differences} == {"description"}


def test_leading_trailing_and_full_width_whitespace_are_compared_exactly(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
) -> None:
    source_path = fixtures_dir / "unicode_text.ics"
    source = inspect_source(
        source_path,
        synthetic_profile_factory(
            source_path,
            {"first_date": "2026-04-01", "last_date": "2026-04-01"},
        ),
    )
    changed_document = _snapshot_document_for_source(source)
    event = changed_document["events"][0]
    assert isinstance(event["summary"], str)
    assert isinstance(event["description"], str)
    event["summary"] = event["summary"].strip().replace("　", " ")
    event["description"] = event["description"].strip().replace("　", " ")

    diff = diff_source_to_snapshot(source, _parse_document(changed_document))

    assert diff.counts.update == 1
    assert {item.field for item in diff.events[0].differences} == {
        "summary",
        "description",
    }


def test_source_only_event_is_add(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _diff(
        "missing_google_event.json",
        valid_source=valid_source,
        factory=synthetic_profile_factory,
        snapshots=google_snapshots_dir,
    )

    assert diff.counts.add == 1
    assert diff.events[0].reason_codes == ("source_only",)
    assert diff.fatal is False


def test_google_only_event_is_unmanaged_by_default(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _diff(
        "extra_unmanaged_event.json",
        valid_source=valid_source,
        factory=synthetic_profile_factory,
        snapshots=google_snapshots_dir,
    )

    assert diff.counts.unchanged == 1
    assert diff.counts.unmanaged_google_event == 1
    assert diff.counts.delete_candidate == 0
    assert diff.fatal is False


def test_private_marker_can_make_google_only_event_a_delete_candidate(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    scope = ManagedScope(
        private_marker_key="tridentine-calendar-managed",
        private_marker_value="true",
    )
    diff = _diff(
        "managed_delete_candidate.json",
        valid_source=valid_source,
        factory=synthetic_profile_factory,
        snapshots=google_snapshots_dir,
        managed_scope=scope,
    )

    assert diff.counts.unchanged == 1
    assert diff.counts.delete_candidate == 1
    candidate = next(
        event
        for event in diff.events
        if event.classification is DiffClassification.DELETE_CANDIDATE
    )
    assert candidate.ownership_evidence == ("private_extended_property",)
    assert diff.fatal is False


@pytest.mark.parametrize(
    "scope",
    [
        ManagedScope(trusted_source_uids=frozenset({"fixture-unmanaged-001@example.invalid"})),
        ManagedScope(trusted_google_event_ids=frozenset({"evtfixtureunmanaged001"})),
    ],
)
def test_trusted_manifest_evidence_can_make_google_only_event_managed(
    scope: ManagedScope,
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _diff(
        "extra_unmanaged_event.json",
        valid_source=valid_source,
        factory=synthetic_profile_factory,
        snapshots=google_snapshots_dir,
        managed_scope=scope,
    )

    assert diff.counts.delete_candidate == 1
    assert diff.counts.unmanaged_google_event == 0


def test_duplicate_google_icaluid_is_fatal_and_ambiguous(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _diff(
        "duplicate_icaluid.json",
        valid_source=valid_source,
        factory=synthetic_profile_factory,
        snapshots=google_snapshots_dir,
    )

    assert diff.counts.duplicate_google_icaluid == 1
    assert diff.fatal is True
    assert diff.has_ambiguous is True


@pytest.mark.parametrize(
    ("fixture_name", "reason"),
    [
        ("cancelled_event.json", "cancelled_event"),
        ("recurring_event.json", "recurring_master"),
        ("special_event_type.json", "non_default_event_type"),
        ("timed_event.json", "not_all_day"),
    ],
)
def test_unsafe_google_shapes_are_ambiguous(
    fixture_name: str,
    reason: str,
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _diff(
        fixture_name,
        valid_source=valid_source,
        factory=synthetic_profile_factory,
        snapshots=google_snapshots_dir,
    )

    assert diff.counts.ambiguous == 1
    assert diff.fatal is True
    assert reason in diff.events[0].reason_codes


def test_missing_google_icaluid_never_matches_source_identity(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _diff(
        "missing_icaluid.json",
        valid_source=valid_source,
        factory=synthetic_profile_factory,
        snapshots=google_snapshots_dir,
    )

    assert diff.counts.add == 1
    assert diff.counts.unmanaged_google_event == 1
    assert diff.counts.unchanged == 0
    assert diff.fatal is False


def test_event_specific_color_is_warning_not_content_update(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _diff(
        "event_color.json",
        valid_source=valid_source,
        factory=synthetic_profile_factory,
        snapshots=google_snapshots_dir,
    )

    assert diff.counts.unchanged == 1
    assert diff.counts.update == 0
    assert {warning.code for warning in diff.warnings} == {"google_event_color_present"}
    assert diff.fatal is False


def test_duplicate_source_uid_is_fatal_classification(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    source_path = fixtures_dir / "duplicate_uid.ics"
    profile = synthetic_profile_factory(
        source_path,
        {
            "vevent_count": 2,
            "uid_total_count": 2,
            "uid_unique_count": 1,
            "uid_duplicate_count": 1,
            "first_date": "2026-06-01",
            "last_date": "2026-06-02",
            "all_day_count": 2,
            "dtstart_date_count": 2,
            "summary_present_count": 2,
            "description_present_count": 2,
            "dtstamp_present_count": 2,
        },
    )
    source = inspect_source(source_path, profile)
    snapshot = load_google_snapshot(google_snapshots_dir / "missing_google_event.json")

    diff = diff_source_to_snapshot(source, snapshot)

    assert diff.counts.duplicate_source_uid == 1
    assert diff.fatal is True


def test_invalid_source_and_source_guard_are_classified(
    fixtures_dir: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    source_path = fixtures_dir / "missing_uid.ics"
    source = inspect_source(
        source_path,
        synthetic_profile_factory(
            source_path,
            {"first_date": "2026-07-01", "last_date": "2026-07-01"},
        ),
    )
    snapshot = load_google_snapshot(google_snapshots_dir / "missing_google_event.json")

    diff = diff_source_to_snapshot(source, snapshot)

    assert diff.counts.invalid_source == 1
    assert diff.fatal is True


def test_sha_mismatch_is_fatal_guard(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    source = inspect_source(
        valid_source,
        synthetic_profile_factory(valid_source, sha256_override="f" * 64),
    )
    snapshot = load_google_snapshot(google_snapshots_dir / "missing_google_event.json")

    diff = diff_source_to_snapshot(source, snapshot)

    assert diff.counts.fatal_guard == 1
    assert diff.fatal is True


def test_incomplete_snapshot_is_fatal_guard(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    source = _source(valid_source, synthetic_profile_factory)
    snapshot = load_google_snapshot(google_snapshots_dir / "exact_match.json").model_copy(
        update={"complete": False}
    )

    diff = diff_source_to_snapshot(source, snapshot)

    assert diff.counts.fatal_guard == 1
    assert diff.fatal is True


def test_diff_content_hash_and_order_are_deterministic(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    source = _source(valid_source, synthetic_profile_factory)
    snapshot = load_google_snapshot(google_snapshots_dir / "extra_unmanaged_event.json")

    first = diff_source_to_snapshot(source, snapshot)
    second = diff_source_to_snapshot(source, snapshot)

    assert first == second
    assert first.content_hash == second.content_hash
    assert len(first.content_hash) == 64


def test_managed_scope_rejects_partial_or_empty_marker() -> None:
    with pytest.raises(ValidationError):
        ManagedScope(private_marker_key="marker")
    with pytest.raises(ValidationError):
        ManagedScope(private_marker_key="", private_marker_value="true")


def test_managed_scope_hides_raw_ownership_values() -> None:
    raw_uid = "fixture-secret-scope@example.invalid"
    raw_event_id = "evtfixturesecretscope"
    scope = ManagedScope(
        trusted_source_uids=frozenset({raw_uid}),
        trusted_google_event_ids=frozenset({raw_event_id}),
    )

    rendered = repr(scope) + str(scope.model_dump(mode="json"))

    assert raw_uid not in rendered
    assert raw_event_id not in rendered
