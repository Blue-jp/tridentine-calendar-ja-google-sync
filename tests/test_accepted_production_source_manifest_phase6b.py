from __future__ import annotations

import hashlib
import json
import re
from datetime import date
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from tridentine_calendar_google_sync.accepted_production_source_manifest import (
    AcceptedProductionSourceManifestError,
    accepted_production_source_manifest_data,
    build_accepted_production_source_manifest,
    calculate_accepted_production_source_manifest_hash,
    verify_accepted_production_source_manifest,
)
from tridentine_calendar_google_sync.accepted_production_source_manifest_io import (
    AcceptedProductionSourceManifestIOError,
    load_accepted_production_source_manifest,
    parse_accepted_production_source_manifest_bytes,
    render_accepted_production_source_manifest_json,
    write_accepted_production_source_manifest,
)
from tridentine_calendar_google_sync.accepted_production_source_manifest_models import (
    AcceptedProductionSourceManifest,
)
from tridentine_calendar_google_sync.accepted_production_source_manifest_report import (
    build_accepted_production_source_manifest_inspection,
    render_accepted_production_source_manifest_inspection_json,
    render_accepted_production_source_manifest_inspection_text,
)
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.source_ics import inspect_source

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = REPOSITORY_ROOT / "schemas" / "accepted-production-source-manifest-v1.schema.json"
REPOSITORY_IDENTITY = "ExampleOrg/production-calendar"


def _source_text(
    *,
    uid: str = "accepted-observance-001@example.org",
    summary: str = "Production calendar observance",
) -> str:
    return "\r\n".join(
        (
            "BEGIN:VCALENDAR",
            "VERSION:2.0",
            "PRODID:-//Example Organization//Accepted Calendar//EN",
            "BEGIN:VEVENT",
            f"UID:{uid}",
            "DTSTAMP:20260101T000000Z",
            "DTSTART;VALUE=DATE:20260115",
            f"SUMMARY:{summary}",
            "DESCRIPTION:Approved production description",
            "END:VEVENT",
            "END:VCALENDAR",
            "",
        )
    )


def _production_profile(path: Path) -> AcceptedSourceProfile:
    raw_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    return AcceptedSourceProfile.model_validate(
        {
            "schema_version": "1.0",
            "profile_id": "accepted-production-sample",
            "project_name": "Production liturgical calendar",
            "source": {
                "accepted_tag": "calendar-accepted-v1",
                "accepted_commit": "a" * 40,
                "html_sha256": raw_sha256,
                "plain_sha256": "b" * 64,
            },
            "expected": {
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
            },
        }
    )


def _production_inputs(
    tmp_path: Path,
    *,
    uid: str = "accepted-observance-001@example.org",
    summary: str = "Production calendar observance",
) -> tuple[AcceptedSourceProfile, SourceCalendarInspection]:
    source_path = tmp_path / "accepted-production.ics"
    source_path.write_text(_source_text(uid=uid, summary=summary), encoding="utf-8", newline="")
    profile = _production_profile(source_path)
    return profile, inspect_source(source_path, profile)


def _manifest(tmp_path: Path) -> AcceptedProductionSourceManifest:
    profile, source = _production_inputs(tmp_path)
    return build_accepted_production_source_manifest(
        profile,
        source,
        repository_identity=REPOSITORY_IDENTITY,
    )


def test_builds_pin_agnostic_closed_accepted_production_manifest(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)

    verify_accepted_production_source_manifest(manifest)
    assert manifest.manifest_type == "accepted_production_source"
    assert manifest.production is True
    assert manifest.acceptance_state == "accepted"
    assert manifest.synthetic is False
    assert manifest.repository_identity == REPOSITORY_IDENTITY
    assert manifest.repository_tag == "calendar-accepted-v1"
    assert manifest.repository_commit == "a" * 40
    assert manifest.event_count == 1
    assert manifest.all_day_count == 1
    assert manifest.timed_count == 0
    assert manifest.recurring_event_count == 0
    assert manifest.manifest_content_hash == calculate_accepted_production_source_manifest_hash(
        manifest
    )
    assert manifest.accepted_tag == manifest.repository_tag
    assert manifest.accepted_commit == manifest.repository_commit
    assert manifest.source_sha256 == manifest.ics_sha256
    assert manifest.source_profile == manifest.profile_id
    assert manifest.source_event_count == manifest.event_count
    assert manifest.recurring_count == manifest.recurring_event_count

    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(accepted_production_source_manifest_data(manifest))


@pytest.mark.parametrize(
    "repository_identity",
    (
        "ExampleOrg/test-calendar",
        "ExampleOrg/synthetic-calendar",
        "ExampleOrg/calendar.invalid",
    ),
)
def test_rejects_test_synthetic_and_invalid_repository_markers(
    tmp_path: Path,
    repository_identity: str,
) -> None:
    profile, source = _production_inputs(tmp_path)
    with pytest.raises(AcceptedProductionSourceManifestError) as raised:
        build_accepted_production_source_manifest(
            profile,
            source,
            repository_identity=repository_identity,
        )
    assert raised.value.code == "accepted_production_source_marker_forbidden"


@pytest.mark.parametrize(
    ("uid", "summary"),
    (
        ("accepted-observance@example.invalid", "Production observance"),
        ("accepted-observance@example.org", "Test calendar observance"),
        ("synthetic-observance@example.org", "Production observance"),
    ),
)
def test_rejects_invalid_uid_and_event_test_markers(
    tmp_path: Path,
    uid: str,
    summary: str,
) -> None:
    profile, source = _production_inputs(tmp_path, uid=uid, summary=summary)
    with pytest.raises(AcceptedProductionSourceManifestError):
        build_accepted_production_source_manifest(
            profile,
            source,
            repository_identity=REPOSITORY_IDENTITY,
        )


def test_rejects_unaccepted_profile_dirty_source_and_mismatched_pin(tmp_path: Path) -> None:
    profile, source = _production_inputs(tmp_path)

    unaccepted = profile.model_copy(
        update={
            "profile_id": "production-release",
            "source": profile.source.model_copy(update={"accepted_tag": "release-v1"}),
        }
    )
    with pytest.raises(AcceptedProductionSourceManifestError) as unaccepted_error:
        build_accepted_production_source_manifest(
            unaccepted,
            source,
            repository_identity=REPOSITORY_IDENTITY,
        )
    assert unaccepted_error.value.code == "accepted_production_source_not_accepted"

    dirty = source.model_copy(update={"source_valid": False})
    with pytest.raises(AcceptedProductionSourceManifestError) as dirty_error:
        build_accepted_production_source_manifest(
            profile,
            dirty,
            repository_identity=REPOSITORY_IDENTITY,
        )
    assert dirty_error.value.code == "accepted_production_source_not_clean"

    mismatched = source.model_copy(update={"raw_sha256": "f" * 64})
    with pytest.raises(AcceptedProductionSourceManifestError) as mismatch_error:
        build_accepted_production_source_manifest(
            profile,
            mismatched,
            repository_identity=REPOSITORY_IDENTITY,
        )
    assert mismatch_error.value.code == "accepted_production_source_profile_mismatch"


def test_rejects_tampering_and_unknown_or_wrong_fixed_fields(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    tampered = manifest.model_copy(update={"event_count": 2})
    with pytest.raises(AcceptedProductionSourceManifestError):
        verify_accepted_production_source_manifest(tampered)

    data: dict[str, Any] = manifest.model_dump(mode="python")
    data["unexpected"] = True
    with pytest.raises(ValidationError):
        AcceptedProductionSourceManifest.model_validate(data, strict=True)

    data.pop("unexpected")
    data["acceptance_state"] = "candidate"
    with pytest.raises(ValidationError):
        AcceptedProductionSourceManifest.model_validate(data, strict=True)


def test_canonical_repository_external_io_is_atomic_and_no_overwrite(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    rendered = render_accepted_production_source_manifest_json(manifest)
    assert parse_accepted_production_source_manifest_bytes(rendered.encode("utf-8")) == manifest

    output = tmp_path / "accepted-production-source-manifest.json"
    assert write_accepted_production_source_manifest(manifest, output) == output
    assert load_accepted_production_source_manifest(output) == manifest
    with pytest.raises(AcceptedProductionSourceManifestIOError):
        write_accepted_production_source_manifest(manifest, output)

    noncanonical = json.loads(rendered)
    noncanonical["manifest_content_hash"] = "f" * 64
    tampered = (json.dumps(noncanonical, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    with pytest.raises(AcceptedProductionSourceManifestError):
        parse_accepted_production_source_manifest_bytes(tampered)


def test_safe_inspection_uses_prefixed_references_and_redacts_raw_pins(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path)
    report = build_accepted_production_source_manifest_inspection(manifest)
    json_report = render_accepted_production_source_manifest_inspection_json(manifest)
    text_report = render_accepted_production_source_manifest_inspection_text(manifest)
    combined = json_report + text_report

    expected_patterns = {
        "repository_reference": r"^R-[0-9a-f]{12}$",
        "tag_reference": r"^A-[0-9a-f]{12}$",
        "commit_reference": r"^C-[0-9a-f]{12}$",
        "ics_reference": r"^I-[0-9a-f]{12}$",
        "profile_reference": r"^P-[0-9a-f]{12}$",
        "source_content_reference": r"^S-[0-9a-f]{12}$",
        "manifest_reference": r"^M-[0-9a-f]{12}$",
    }
    for key, pattern in expected_patterns.items():
        assert re.fullmatch(pattern, str(report[key])) is not None

    for raw_value in (
        manifest.repository_identity,
        manifest.repository_tag,
        manifest.repository_commit,
        manifest.ics_sha256,
        manifest.profile_id,
        manifest.source_content_hash,
        manifest.manifest_content_hash,
    ):
        assert raw_value not in combined
    assert report["acceptance_state"] == "accepted"
    assert report["integrity"] == "verified"
