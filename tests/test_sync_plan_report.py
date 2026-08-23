from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import REPOSITORY_ROOT, SyntheticBaselineBundle
from jsonschema import Draft202012Validator, FormatChecker

from tridentine_calendar_google_sync.google_snapshot import parse_google_snapshot_bytes
from tridentine_calendar_google_sync.plan_engine import (
    PlanInputError,
    build_sync_plan,
    verify_sync_plan_content_hash,
)
from tridentine_calendar_google_sync.plan_report import (
    build_plan_json_report,
    render_plan_json_report,
    render_plan_text_report,
)

BundleFactory = Callable[..., SyntheticBaselineBundle]


def _bundle(
    valid_source: Path,
    profile_factory: Callable[..., object],
    bundle_factory: BundleFactory,
    snapshots: Path,
) -> SyntheticBaselineBundle:
    return bundle_factory(valid_source, profile_factory, snapshots / "exact_match.json")


def test_draft_plan_report_validates_closed_schema_and_exact_root_fields(
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    plan = build_sync_plan(bundle.profile, bundle.source, bundle.snapshot, bundle.trusted)
    report = build_plan_json_report(plan)
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "sync-plan-v1.schema.json").read_text(encoding="utf-8")
    )

    Draft202012Validator(schema, format_checker=FormatChecker()).validate(report)
    assert set(report) == {
        "schema_version",
        "plan_type",
        "tool_version",
        "state",
        "executable",
        "approval_required",
        "baseline",
        "current_source",
        "target_fingerprint",
        "snapshot_content_hash",
        "diff_summary",
        "thresholds",
        "proposed_actions",
        "safety_guards",
        "plan_content_hash",
    }
    assert report["state"] == "draft"
    assert report["executable"] is False
    assert report["approval_required"] is False
    assert report["proposed_actions"] == []
    assert report["safety_guards"] == []


def test_blocked_update_report_has_safe_action_without_request_payload(
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    snapshot = parse_google_snapshot_bytes(
        (google_snapshots_dir / "summary_changed.json").read_bytes()
    )
    plan = build_sync_plan(bundle.profile, bundle.source, snapshot, bundle.trusted)

    report = build_plan_json_report(plan)
    action = report["proposed_actions"][0]

    assert report["state"] == "blocked"
    assert report["approval_required"] is True
    assert action["action"] == "update"
    assert action["changed_fields"] == ["summary"]
    assert action["destructive"] is False
    assert action["separate_approval_required"] is False
    serialized = json.dumps(report, ensure_ascii=False)
    for forbidden in (
        '"payload"',
        '"method"',
        '"endpoint"',
        '"headers"',
        '"if_match"',
        '"calendar_id"',
        '"event_id"',
        '"etag"',
        '"iCalUID"',
    ):
        assert forbidden not in serialized


def test_plan_reports_are_deterministic_and_redact_raw_identity_content_and_paths(
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    snapshot = parse_google_snapshot_bytes(
        (google_snapshots_dir / "summary_changed.json").read_bytes()
    )
    first = build_sync_plan(bundle.profile, bundle.source, snapshot, bundle.trusted)
    second = build_sync_plan(bundle.profile, bundle.source, snapshot, bundle.trusted)
    json_report = render_plan_json_report(first)
    text_report = render_plan_text_report(first)

    assert first.plan_content_hash == second.plan_content_hash
    assert render_plan_json_report(first) == render_plan_json_report(second)
    assert render_plan_text_report(first) == render_plan_text_report(second)
    sensitive_values = [
        bundle.source.events[0].uid,
        bundle.source.events[0].summary,
        bundle.source.events[0].description,
        snapshot.events[0].event_id,
        snapshot.events[0].ical_uid,
        snapshot.events[0].etag,
        snapshot.events[0].summary,
        snapshot.events[0].description,
        str(valid_source.resolve()),
        str((google_snapshots_dir / "summary_changed.json").resolve()),
    ]
    for report in (json_report, text_report):
        for value in sensitive_values:
            if value:
                assert value not in report
    assert first.target_fingerprint not in text_report
    assert json_report.count(first.target_fingerprint) == 1
    assert "target reference: T-" in text_report


def test_plan_content_hash_verifier_rejects_mutation(
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    plan = build_sync_plan(bundle.profile, bundle.source, bundle.snapshot, bundle.trusted)
    tampered = plan.model_copy(update={"snapshot_content_hash": "f" * 64})

    with pytest.raises(PlanInputError) as caught:
        verify_sync_plan_content_hash(tampered)
    assert caught.value.code == "sync_plan_content_hash_mismatch"
