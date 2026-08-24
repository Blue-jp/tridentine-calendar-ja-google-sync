from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from conftest import build_synthetic_profile
from phase5a1_helpers import (
    SequencePrewriteClient,
    make_prewrite_target_config,
    prewrite_event,
    prewrite_page,
)

from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.diff_models import CalendarDiff
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.source_ics import inspect_source
from tridentine_calendar_google_sync.test_bootstrap_plan import (
    build_test_bootstrap_add_plan,
)
from tridentine_calendar_google_sync.test_bootstrap_plan_models import (
    TestBootstrapAddPlan,
)
from tridentine_calendar_google_sync.test_calendar_prewrite import (
    inspect_test_calendar_prewrite,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_models import (
    TestCalendarPrewriteSnapshot,
)
from tridentine_calendar_google_sync.test_write_target import TestWriteTargetConfig

BOOTSTRAP_UID = "phase5c-add-acceptance-20260824@tridentine-calendar-google-sync.invalid"
BOOTSTRAP_SUMMARY = "【同期テスト】架空イベント（追加受入）"  # noqa: RUF001
BOOTSTRAP_DESCRIPTION = "Synthetic Test bootstrap add acceptance event."


@dataclass(frozen=True)
class BootstrapBundle:
    source_path: Path
    profile: AcceptedSourceProfile
    source: SourceCalendarInspection
    target: TestWriteTargetConfig
    prewrite_snapshot: TestCalendarPrewriteSnapshot
    diff: CalendarDiff
    plan: TestBootstrapAddPlan


def bootstrap_ics_bytes(
    *,
    uid: str = BOOTSTRAP_UID,
    summary: str = BOOTSTRAP_SUMMARY,
    description: str = BOOTSTRAP_DESCRIPTION,
    dtstart: str = "20260825",
    dtend: str | None = None,
    extra_lines: tuple[str, ...] = (),
) -> bytes:
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//example.invalid//Synthetic Bootstrap Test//EN",
        "BEGIN:VEVENT",
        f"UID:{uid}",
        "DTSTAMP:20260824T000000Z",
        f"DTSTART;VALUE=DATE:{dtstart}",
    ]
    if dtend is not None:
        lines.append(f"DTEND;VALUE=DATE:{dtend}")
    lines.extend((f"SUMMARY:{summary}", f"DESCRIPTION:{description}", *extra_lines))
    lines.extend(("END:VEVENT", "END:VCALENDAR", ""))
    return "\r\n".join(lines).encode("utf-8")


def build_bootstrap_source(
    tmp_path: Path,
    *,
    source_bytes: bytes | None = None,
    profile_overrides: dict[str, Any] | None = None,
) -> tuple[Path, AcceptedSourceProfile, SourceCalendarInspection]:
    source_path = tmp_path / "synthetic-bootstrap-source.ics"
    source_path.write_bytes(source_bytes or bootstrap_ics_bytes())
    profile = build_synthetic_profile(
        source_path,
        {"first_date": "2026-08-25", "last_date": "2026-08-25"},
    )
    if profile_overrides:
        data = profile.model_dump(mode="python")
        for key, value in profile_overrides.items():
            if key.startswith("source."):
                data["source"][key.removeprefix("source.")] = value
            else:
                data[key] = value
        profile = AcceptedSourceProfile.model_validate(data)
    return source_path, profile, inspect_source(source_path, profile)


def build_prewrite_snapshot(
    *,
    nonempty: bool = False,
) -> tuple[TestWriteTargetConfig, TestCalendarPrewriteSnapshot]:
    target = make_prewrite_target_config()
    items = [prewrite_event()] if nonempty else []
    result = inspect_test_calendar_prewrite(
        SequencePrewriteClient([prewrite_page(items)]),
        target,
        sleep=lambda _delay: None,
        jitter=lambda _maximum: 0.0,
    )
    return target, result.snapshot


def build_empty_prewrite_snapshot() -> tuple[TestWriteTargetConfig, TestCalendarPrewriteSnapshot]:
    return build_prewrite_snapshot()


def build_bootstrap_bundle(tmp_path: Path) -> BootstrapBundle:
    source_path, profile, source = build_bootstrap_source(tmp_path)
    target, prewrite_snapshot = build_empty_prewrite_snapshot()
    diff = diff_source_to_snapshot(source, prewrite_snapshot.snapshot)
    plan = build_test_bootstrap_add_plan(
        profile,
        source,
        prewrite_snapshot,
        target,
        diff=diff,
    )
    return BootstrapBundle(
        source_path=source_path,
        profile=profile,
        source=source,
        target=target,
        prewrite_snapshot=prewrite_snapshot,
        diff=diff,
        plan=plan,
    )


def write_test_target_config(target: TestWriteTargetConfig, path: Path) -> Path:
    text = f'''schema_version = 1
target_environment = "test"
target_label = "test"
target_purpose = "test_calendar_write_acceptance"
calendar_id = "{target.calendar_id}"
expected_target_fingerprint = "{target.expected_target_fingerprint}"
expected_summary = "{target.expected_summary}"
expected_access_role = "owner"
expected_time_zone = "Asia/Tokyo"
'''
    path.write_text(text, encoding="utf-8", newline="\n")
    return path
