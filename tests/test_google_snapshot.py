from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from conftest import REPOSITORY_ROOT
from jsonschema import Draft202012Validator, FormatChecker

from tridentine_calendar_google_sync.google_snapshot import (
    MAX_GOOGLE_SNAPSHOT_BYTES,
    GoogleSnapshotInputError,
    GoogleSnapshotParseError,
    load_google_snapshot,
    parse_google_snapshot_bytes,
)

VALID_SNAPSHOT_NAMES = {
    "cancelled_event.json",
    "date_changed.json",
    "description_changed.json",
    "duplicate_icaluid.json",
    "event_color.json",
    "exact_match.json",
    "extra_unmanaged_event.json",
    "managed_delete_candidate.json",
    "missing_google_event.json",
    "missing_icaluid.json",
    "recurring_event.json",
    "special_event_type.json",
    "summary_changed.json",
    "timed_event.json",
}


def test_snapshot_fixture_inventory_is_complete(google_snapshots_dir: Path) -> None:
    names = {path.name for path in google_snapshots_dir.glob("*.json")}

    assert names == VALID_SNAPSHOT_NAMES | {"malformed_snapshot.json"}


def test_valid_snapshot_fixtures_match_published_json_schema(
    google_snapshots_dir: Path,
) -> None:
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "google-snapshot-v1.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema, format_checker=FormatChecker())

    for fixture_name in sorted(VALID_SNAPSHOT_NAMES):
        document = json.loads((google_snapshots_dir / fixture_name).read_text(encoding="utf-8"))
        validator.validate(document)


@pytest.mark.parametrize("fixture_name", sorted(VALID_SNAPSHOT_NAMES))
def test_all_synthetic_snapshots_except_malformed_are_valid(
    fixture_name: str,
    google_snapshots_dir: Path,
) -> None:
    snapshot = load_google_snapshot(google_snapshots_dir / fixture_name)

    assert snapshot.schema_version == "1.0"
    assert snapshot.snapshot_format == "sanitized-google-calendar-v1"
    assert snapshot.target_fingerprint == "a" * 64
    assert snapshot.complete is True
    assert snapshot.event_count == len(snapshot.events)


def test_exact_snapshot_canonicalizes_all_day_event_and_safe_references(
    google_snapshots_dir: Path,
) -> None:
    snapshot = load_google_snapshot(google_snapshots_dir / "exact_match.json")

    assert snapshot.event_count == 1
    event = snapshot.events[0]
    assert event.event_id == "evtfixture001"
    assert event.ical_uid == "fixture-valid-001@example.invalid"
    assert event.safe_event_reference.startswith("G-")
    assert event.safe_ical_uid_reference is not None
    assert event.safe_ical_uid_reference.startswith("U-")
    assert event.all_day is True
    assert event.start.date is not None
    assert event.start.date.isoformat() == "2026-01-15"
    assert event.end.date is not None
    assert event.end.date.isoformat() == "2026-01-16"
    assert event.start.date_time is None


def test_timed_snapshot_preserves_aware_datetime_shape(google_snapshots_dir: Path) -> None:
    snapshot = load_google_snapshot(google_snapshots_dir / "timed_event.json")
    event = snapshot.events[0]

    assert event.all_day is False
    assert event.start.date is None
    assert event.start.date_time is not None
    assert event.start.date_time.tzinfo is not None
    assert event.end.date_time is not None


def test_missing_icaluid_is_observed_without_inventing_identity(
    google_snapshots_dir: Path,
) -> None:
    snapshot = load_google_snapshot(google_snapshots_dir / "missing_icaluid.json")

    assert snapshot.events[0].ical_uid is None
    assert snapshot.events[0].safe_ical_uid_reference is None


def test_snapshot_content_hash_is_deterministic(google_snapshots_dir: Path) -> None:
    raw = (google_snapshots_dir / "exact_match.json").read_bytes()

    first = parse_google_snapshot_bytes(raw)
    second = parse_google_snapshot_bytes(raw)

    assert first.content_hash == second.content_hash
    assert len(first.content_hash) == 64


def test_captured_at_is_excluded_from_snapshot_content_hash(
    google_snapshots_dir: Path,
) -> None:
    document = json.loads((google_snapshots_dir / "exact_match.json").read_text(encoding="utf-8"))
    document["captured_at"] = "2026-01-01T00:00:00Z"
    first = parse_google_snapshot_bytes(json.dumps(document).encode("utf-8"))
    document["captured_at"] = "2026-02-01T00:00:00Z"
    second = parse_google_snapshot_bytes(json.dumps(document).encode("utf-8"))

    assert first.content_hash == second.content_hash


def test_target_fingerprint_is_required(google_snapshots_dir: Path) -> None:
    document = json.loads((google_snapshots_dir / "exact_match.json").read_text(encoding="utf-8"))
    document.pop("target_fingerprint")

    with pytest.raises(GoogleSnapshotParseError):
        parse_google_snapshot_bytes(json.dumps(document).encode("utf-8"))


def test_raw_google_values_are_excluded_from_repr_and_serialization(
    google_snapshots_dir: Path,
) -> None:
    raw_event_id = "evtfixture001"
    raw_uid = "fixture-valid-001@example.invalid"
    raw_summary = "Synthetic all-day observance"
    raw_description = "Safe fixture description"
    snapshot = load_google_snapshot(google_snapshots_dir / "exact_match.json")
    event = snapshot.events[0]

    rendered = repr(snapshot) + repr(event) + json.dumps(event.model_dump(mode="json"))

    for sensitive_value in (raw_event_id, raw_uid, raw_summary, raw_description):
        assert sensitive_value not in rendered


def test_malformed_json_has_content_free_error(google_snapshots_dir: Path) -> None:
    path = google_snapshots_dir / "malformed_snapshot.json"

    with pytest.raises(GoogleSnapshotParseError) as caught:
        load_google_snapshot(path)

    message = str(caught.value)
    assert caught.value.code == "invalid_google_snapshot"
    assert str(path.resolve()) not in message
    assert "target_fingerprint" not in message


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(event_count=2),
        lambda value: value.update(complete="true"),
        lambda value: value.update(calendar_id="forbidden"),
    ],
)
def test_closed_snapshot_schema_rejects_invalid_documents(
    mutation: object,
    google_snapshots_dir: Path,
) -> None:
    document = json.loads((google_snapshots_dir / "exact_match.json").read_text(encoding="utf-8"))
    mutation(document)  # type: ignore[operator]
    raw = json.dumps(document).encode("utf-8")

    with pytest.raises(GoogleSnapshotParseError):
        parse_google_snapshot_bytes(raw)


def test_duplicate_json_keys_are_rejected() -> None:
    raw = b'{"schema_version":"1.0","schema_version":"1.0"}'

    with pytest.raises(GoogleSnapshotParseError):
        parse_google_snapshot_bytes(raw)


@pytest.mark.parametrize(
    "source_value",
    ["https://example.invalid/snapshot.json", "file:///synthetic/snapshot.json"],
)
def test_nonlocal_snapshot_forms_are_rejected_safely(source_value: str) -> None:
    with pytest.raises(GoogleSnapshotInputError) as caught:
        load_google_snapshot(source_value)

    assert source_value not in str(caught.value)


def test_windows_style_snapshot_path_is_a_local_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    google_snapshots_dir: Path,
) -> None:
    fixture = google_snapshots_dir / "exact_match.json"
    if os.name == "nt":
        source = fixture
        source_value = str(source)
        assert "\\" in source_value
    else:
        monkeypatch.chdir(tmp_path)
        source = Path(r"C:\synthetic\snapshot.json")
        source.write_bytes(fixture.read_bytes())
        source_value = str(source)

    snapshot = load_google_snapshot(source_value)

    assert snapshot.event_count == 1


def test_snapshot_symlink_is_rejected(
    tmp_path: Path,
    google_snapshots_dir: Path,
) -> None:
    fixture = google_snapshots_dir / "exact_match.json"
    link = tmp_path / "snapshot-link.json"
    try:
        link.symlink_to(fixture)
    except OSError:
        pytest.skip("symbolic links are unavailable in this test environment")

    with pytest.raises(GoogleSnapshotInputError) as caught:
        load_google_snapshot(link)

    assert str(link) not in str(caught.value)


def test_oversized_snapshot_is_rejected_before_json_parse(tmp_path: Path) -> None:
    path = tmp_path / "oversized-snapshot.json"
    with path.open("wb") as stream:
        stream.truncate(MAX_GOOGLE_SNAPSHOT_BYTES + 1)

    with pytest.raises(GoogleSnapshotInputError) as caught:
        load_google_snapshot(path)

    assert caught.value.code == "google_snapshot_too_large"
    assert str(path) not in str(caught.value)
