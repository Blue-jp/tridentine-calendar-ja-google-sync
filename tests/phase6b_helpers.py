from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from tridentine_calendar_google_sync.accepted_production_source_manifest import (
    build_accepted_production_source_manifest,
)
from tridentine_calendar_google_sync.accepted_production_source_manifest_models import (
    AcceptedProductionSourceManifest,
)
from tridentine_calendar_google_sync.baseline_engine import (
    baseline_confirmation_phrase,
    build_baseline_candidate,
    trust_baseline,
)
from tridentine_calendar_google_sync.baseline_models import TrustedBaseline
from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.google_models import GoogleSnapshot
from tridentine_calendar_google_sync.google_snapshot import parse_google_snapshot_bytes
from tridentine_calendar_google_sync.google_target import calendar_id_fingerprint
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.production_write_target import (
    ProductionWriteTargetConfig,
)
from tridentine_calendar_google_sync.source_ics import inspect_source

PRODUCTION_LIKE_PROFILE_ID = "accepted-20990101"
PRODUCTION_LIKE_REPOSITORY = "calendar-owner/calendar-source"
PRODUCTION_LIKE_CALENDAR_ID = "phase6b-production@calendar.example"
PRODUCTION_LIKE_SUMMARY = "Phase 6B Production Calendar"
PRODUCTION_LIKE_TIME_ZONE = "Asia/Tokyo"
PRODUCTION_LIKE_CURRENT_TAG = "accepted-phase6b-current"
PRODUCTION_LIKE_UPDATED_TAG = "accepted-phase6b-updated"
PRODUCTION_LIKE_CURRENT_COMMIT = "1" * 40
PRODUCTION_LIKE_UPDATED_COMMIT = "2" * 40
PRODUCTION_LIKE_PLAIN_SHA256 = "3" * 64
PRODUCTION_LIKE_START_DATE = date(2099, 1, 1)


@dataclass(frozen=True)
class ProductionSourceFixture:
    path: Path
    profile: AcceptedSourceProfile
    source: SourceCalendarInspection


@dataclass(frozen=True)
class ProductionPlanningInputs:
    current: ProductionSourceFixture
    updated: ProductionSourceFixture
    snapshot: GoogleSnapshot
    baseline: TrustedBaseline
    manifest: AcceptedProductionSourceManifest
    target: ProductionWriteTargetConfig


def production_like_uid(index: int) -> str:
    return f"phase6b-{index:06d}@calendar.example"


def production_like_summary(index: int) -> str:
    return f"Calendar observance {index:06d}"


def production_like_ics_bytes(
    descriptions: Sequence[str],
    *,
    summaries: Sequence[str] | None = None,
    uids: Sequence[str] | None = None,
    first_date: date = PRODUCTION_LIKE_START_DATE,
) -> bytes:
    count = len(descriptions)
    resolved_summaries = tuple(summaries or (production_like_summary(i + 1) for i in range(count)))
    resolved_uids = tuple(uids or (production_like_uid(i + 1) for i in range(count)))
    if len(resolved_summaries) != count or len(resolved_uids) != count:
        raise ValueError("Production-like fixture fields must have equal lengths")

    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Phase 6B Calendar//EN"]
    for offset, (uid, summary, description) in enumerate(
        zip(resolved_uids, resolved_summaries, descriptions, strict=True)
    ):
        start = first_date + timedelta(days=offset)
        lines.extend(
            (
                "BEGIN:VEVENT",
                f"UID:{uid}",
                "DTSTAMP:20980101T000000Z",
                f"DTSTART;VALUE=DATE:{start.strftime('%Y%m%d')}",
                f"SUMMARY:{summary}",
                f"DESCRIPTION:{description}",
                "END:VEVENT",
            )
        )
    lines.append("END:VCALENDAR")
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def production_like_profile(
    raw: bytes,
    *,
    event_count: int,
    accepted_tag: str,
    accepted_commit: str,
    first_date: date = PRODUCTION_LIKE_START_DATE,
    profile_id: str = PRODUCTION_LIKE_PROFILE_ID,
    project_name: str = "Production calendar source acceptance",
) -> AcceptedSourceProfile:
    last_date = first_date + timedelta(days=event_count - 1)
    return AcceptedSourceProfile.model_validate(
        {
            "schema_version": "1.0",
            "profile_id": profile_id,
            "project_name": project_name,
            "source": {
                "accepted_tag": accepted_tag,
                "accepted_commit": accepted_commit,
                "html_sha256": hashlib.sha256(raw).hexdigest(),
                "plain_sha256": PRODUCTION_LIKE_PLAIN_SHA256,
            },
            "expected": {
                "vcalendar_count": 1,
                "vevent_count": event_count,
                "uid_total_count": event_count,
                "uid_unique_count": event_count,
                "uid_duplicate_count": 0,
                "first_date": first_date,
                "last_date": last_date,
                "all_day_count": event_count,
                "timed_count": 0,
                "dtstart_date_count": event_count,
                "dtend_present_count": 0,
                "summary_present_count": event_count,
                "description_present_count": event_count,
                "dtstamp_present_count": event_count,
                "rrule_count": 0,
                "recurrence_id_count": 0,
                "event_x_property_count": 0,
            },
        },
        strict=True,
    )


def write_production_source(
    directory: Path,
    name: str,
    descriptions: Sequence[str],
    *,
    accepted_tag: str,
    accepted_commit: str,
    summaries: Sequence[str] | None = None,
    uids: Sequence[str] | None = None,
    first_date: date = PRODUCTION_LIKE_START_DATE,
    profile_id: str = PRODUCTION_LIKE_PROFILE_ID,
    project_name: str = "Production calendar source acceptance",
) -> ProductionSourceFixture:
    directory.mkdir(parents=True, exist_ok=True)
    raw = production_like_ics_bytes(
        descriptions,
        summaries=summaries,
        uids=uids,
        first_date=first_date,
    )
    path = directory / f"{name}.ics"
    path.write_bytes(raw)
    profile = production_like_profile(
        raw,
        event_count=len(descriptions),
        accepted_tag=accepted_tag,
        accepted_commit=accepted_commit,
        first_date=first_date,
        profile_id=profile_id,
        project_name=project_name,
    )
    return ProductionSourceFixture(path=path, profile=profile, source=inspect_source(path, profile))


def make_production_write_target(
    *,
    calendar_id: str = PRODUCTION_LIKE_CALENDAR_ID,
    expected_summary: str = PRODUCTION_LIKE_SUMMARY,
) -> ProductionWriteTargetConfig:
    return ProductionWriteTargetConfig(
        schema_version=1,
        target_environment="production",
        target_label="production",
        target_purpose="production_calendar_single_update",
        calendar_id=calendar_id,
        expected_target_fingerprint=calendar_id_fingerprint(calendar_id),
        expected_summary=expected_summary,
        expected_access_role="owner",
        expected_time_zone=PRODUCTION_LIKE_TIME_ZONE,
    )


def production_snapshot_document(
    source: SourceCalendarInspection,
    target_fingerprint: str,
    *,
    event_overrides: dict[int, dict[str, Any]] | None = None,
    extra_events: Sequence[dict[str, Any]] = (),
) -> dict[str, object]:
    overrides = event_overrides or {}
    events: list[dict[str, Any]] = []
    for index, event in enumerate(source.events, start=1):
        if (
            event.uid is None
            or event.summary is None
            or event.description is None
            or event.start_date is None
            or event.effective_end_date is None
        ):
            raise ValueError("Production-like source event is incomplete")
        document: dict[str, Any] = {
            "id": f"evtphase6b{index:06d}",
            "iCalUID": event.uid,
            "summary": event.summary,
            "description": event.description,
            "start": {"date": event.start_date.isoformat()},
            "end": {"date": event.effective_end_date.isoformat()},
            "allDay": True,
            "status": "confirmed",
            "eventType": "default",
            "etag": f"phase6b-etag-{index:06d}",
        }
        document.update(overrides.get(index, {}))
        events.append(document)
    events.extend(dict(event) for event in extra_events)
    return {
        "schema_version": "1.0",
        "snapshot_format": "sanitized-google-calendar-v1",
        "target_fingerprint": target_fingerprint,
        "complete": True,
        "event_count": len(events),
        "page_count": 1,
        "collection_metadata_hash": "4" * 64,
        "events": events,
    }


def build_production_snapshot(
    source: SourceCalendarInspection,
    target: ProductionWriteTargetConfig,
    *,
    event_overrides: dict[int, dict[str, Any]] | None = None,
    extra_events: Sequence[dict[str, Any]] = (),
) -> GoogleSnapshot:
    document = production_snapshot_document(
        source,
        target.expected_target_fingerprint,
        event_overrides=event_overrides,
        extra_events=extra_events,
    )
    return parse_google_snapshot_bytes(json.dumps(document, ensure_ascii=False).encode("utf-8"))


def build_production_planning_inputs(
    tmp_path: Path,
    *,
    event_count: int = 2,
    updated_indexes: Sequence[int] = (2,),
) -> ProductionPlanningInputs:
    if event_count < 2:
        raise ValueError("Production planning fixtures require at least two events")
    current_descriptions = tuple(
        f"Current calendar description {index:06d}" for index in range(1, event_count + 1)
    )
    updated = set(updated_indexes)
    updated_descriptions = tuple(
        (f"Updated calendar description {index:06d}" if index in updated else description)
        for index, description in enumerate(current_descriptions, start=1)
    )
    current = write_production_source(
        tmp_path,
        "current",
        current_descriptions,
        accepted_tag=PRODUCTION_LIKE_CURRENT_TAG,
        accepted_commit=PRODUCTION_LIKE_CURRENT_COMMIT,
    )
    desired = write_production_source(
        tmp_path,
        "accepted",
        updated_descriptions,
        accepted_tag=PRODUCTION_LIKE_UPDATED_TAG,
        accepted_commit=PRODUCTION_LIKE_UPDATED_COMMIT,
    )
    target = make_production_write_target()
    snapshot = build_production_snapshot(current.source, target)
    current_diff = diff_source_to_snapshot(current.source, snapshot)
    candidate = build_baseline_candidate(current.profile, current.source, snapshot, current_diff)
    baseline = trust_baseline(candidate, baseline_confirmation_phrase(candidate))
    manifest = build_accepted_production_source_manifest(
        desired.profile,
        desired.source,
        repository_identity=PRODUCTION_LIKE_REPOSITORY,
    )
    return ProductionPlanningInputs(
        current=current,
        updated=desired,
        snapshot=snapshot,
        baseline=baseline,
        manifest=manifest,
        target=target,
    )


def write_profile_directory(profile: AcceptedSourceProfile, directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    expected = profile.expected
    text = f'''schema_version = "{profile.schema_version}"
profile_id = "{profile.profile_id}"
project_name = "{profile.project_name}"

[source]
accepted_tag = "{profile.accepted_tag}"
accepted_commit = "{profile.accepted_commit}"
html_sha256 = "{profile.html_sha256}"
plain_sha256 = "{profile.plain_sha256}"

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
    (directory / f"{profile.profile_id}.toml").write_text(text, encoding="utf-8", newline="\n")
    return directory


def write_production_target_config(target: ProductionWriteTargetConfig, path: Path) -> Path:
    path.write_text(
        "\n".join(
            (
                f"schema_version = {target.schema_version}",
                f'target_environment = "{target.target_environment}"',
                f'target_label = "{target.target_label}"',
                f'target_purpose = "{target.target_purpose}"',
                f'calendar_id = "{target.calendar_id}"',
                f'expected_target_fingerprint = "{target.expected_target_fingerprint}"',
                f'expected_summary = "{target.expected_summary}"',
                f'expected_access_role = "{target.expected_access_role}"',
                f'expected_time_zone = "{target.expected_time_zone}"',
                "",
            )
        ),
        encoding="utf-8",
        newline="\n",
    )
    return path
