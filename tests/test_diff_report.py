from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

from conftest import REPOSITORY_ROOT
from jsonschema import Draft202012Validator, FormatChecker

from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.diff_report import (
    build_diff_json_report,
    render_diff_json_report,
    render_diff_text_report,
)
from tridentine_calendar_google_sync.google_snapshot import load_google_snapshot
from tridentine_calendar_google_sync.models import AcceptedSourceProfile
from tridentine_calendar_google_sync.source_ics import inspect_source

ProfileFactory = Callable[..., AcceptedSourceProfile]


def _build_diff(
    fixture_name: str,
    valid_source: Path,
    factory: ProfileFactory,
    snapshots: Path,
):
    source = inspect_source(valid_source, factory(valid_source))
    snapshot = load_google_snapshot(snapshots / fixture_name)
    return diff_source_to_snapshot(source, snapshot)


def test_diff_json_report_validates_against_closed_schema(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _build_diff(
        "summary_changed.json",
        valid_source,
        synthetic_profile_factory,
        google_snapshots_dir,
    )
    report = build_diff_json_report(diff)
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "diff-report-v1.schema.json").read_text(encoding="utf-8")
    )

    Draft202012Validator(schema, format_checker=FormatChecker()).validate(report)
    assert report["schema_version"] == "1.0"
    assert report["mode"] == "offline"
    assert report["counts"]["update"] == 1
    assert report["fatal"] is False
    assert report["content_hash"] == diff.content_hash


def test_diff_json_and_content_hash_are_deterministic(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    first = _build_diff(
        "extra_unmanaged_event.json",
        valid_source,
        synthetic_profile_factory,
        google_snapshots_dir,
    )
    second = _build_diff(
        "extra_unmanaged_event.json",
        valid_source,
        synthetic_profile_factory,
        google_snapshots_dir,
    )

    assert first.content_hash == second.content_hash
    assert render_diff_json_report(first) == render_diff_json_report(second)


def test_update_report_contains_hashes_and_lengths_not_event_content(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _build_diff(
        "summary_changed.json",
        valid_source,
        synthetic_profile_factory,
        google_snapshots_dir,
    )

    report = build_diff_json_report(diff)

    assert len(report["differences"]) == 1
    difference = report["differences"][0]["differences"][0]
    assert difference["field"] == "summary"
    assert len(difference["current_hash"]) == 64
    assert len(difference["desired_hash"]) == 64
    assert difference["current_length"] > 0
    assert difference["desired_length"] > 0


def test_normal_changes_are_classifications_only_not_executable_payloads(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _build_diff(
        "summary_changed.json",
        valid_source,
        synthetic_profile_factory,
        google_snapshots_dir,
    )

    report = build_diff_json_report(diff)

    assert report["proposed_operations"] == [
        {
            "classification": "update",
            "source_ref": diff.events[0].source_ref,
            "google_refs": list(diff.events[0].google_refs),
        }
    ]
    rendered = json.dumps(report)
    for forbidden_key in ("payload", "method", "endpoint", "calendar_id"):
        assert forbidden_key not in rendered


def test_fatal_diff_has_no_proposed_operations(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _build_diff(
        "duplicate_icaluid.json",
        valid_source,
        synthetic_profile_factory,
        google_snapshots_dir,
    )

    report = build_diff_json_report(diff)

    assert report["fatal"] is True
    assert report["fatal_errors"]
    assert report["proposed_operations"] == []


def test_human_report_has_required_counts_and_safe_target_reference(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _build_diff(
        "summary_changed.json",
        valid_source,
        synthetic_profile_factory,
        google_snapshots_dir,
    )

    report = render_diff_text_report(diff)

    for fragment in (
        "Offline Google snapshot diff",
        "mode: offline",
        "source profile: synthetic-test-profile",
        "target fingerprint: T-aaaaaaaaaaaa",
        "Google event count: 1",
        "update: 1",
        "unchanged: 0",
        "fatal: no",
        "fields=summary",
        "U-",
        "G-",
    ):
        assert fragment in report


def test_reports_redact_raw_identity_content_and_local_paths(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _build_diff(
        "summary_changed.json",
        valid_source,
        synthetic_profile_factory,
        google_snapshots_dir,
    )
    reports = (render_diff_text_report(diff), render_diff_json_report(diff))
    sensitive_values = (
        "fixture-valid-001@example.invalid",
        "evtfixture001",
        "Synthetic all-day observance",
        "Changed synthetic summary",
        "Safe fixture description",
        str(valid_source.resolve()),
        str((google_snapshots_dir / "summary_changed.json").resolve()),
    )

    for report in reports:
        for sensitive_value in sensitive_values:
            assert sensitive_value not in report


def test_unmanaged_event_is_not_proposed_as_delete(
    valid_source: Path,
    synthetic_profile_factory: ProfileFactory,
    google_snapshots_dir: Path,
) -> None:
    diff = _build_diff(
        "extra_unmanaged_event.json",
        valid_source,
        synthetic_profile_factory,
        google_snapshots_dir,
    )

    report = build_diff_json_report(diff)

    assert report["counts"]["unmanaged_google_event"] == 1
    assert all(
        operation["classification"] != "delete_candidate"
        for operation in report["proposed_operations"]
    )
