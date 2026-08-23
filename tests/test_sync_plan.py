from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import SyntheticBaselineBundle
from pydantic import ValidationError

from tridentine_calendar_google_sync.baseline_engine import (
    BaselineValidationError,
    baseline_confirmation_phrase,
    build_baseline_candidate,
    trust_baseline,
)
from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.google_snapshot import parse_google_snapshot_bytes
from tridentine_calendar_google_sync.plan_engine import (
    PlanInputError,
    baseline_to_managed_scope,
    build_sync_plan,
    diff_with_trusted_baseline,
    verify_sync_plan_content_hash,
)
from tridentine_calendar_google_sync.plan_models import (
    PlanActionKind,
    PlanState,
    PlanThresholds,
)
from tridentine_calendar_google_sync.source_ics import inspect_source

BundleFactory = Callable[..., SyntheticBaselineBundle]


def _bundle(
    valid_source: Path,
    profile_factory: Callable[..., object],
    bundle_factory: BundleFactory,
    snapshots: Path,
) -> SyntheticBaselineBundle:
    return bundle_factory(valid_source, profile_factory, snapshots / "exact_match.json")


def _calendar_bytes(count: int, *, replace_last_uid: bool = False) -> bytes:
    events: list[str] = []
    for index in range(count):
        uid_index = 9999 if replace_last_uid and index == count - 1 else index
        events.extend(
            (
                "BEGIN:VEVENT",
                f"UID:fixture-plan-{uid_index:04d}@example.invalid",
                "DTSTAMP:20260101T000000Z",
                "DTSTART;VALUE=DATE:20260115",
                f"SUMMARY:Synthetic plan event {uid_index:04d}",
                f"DESCRIPTION:Safe plan description {uid_index:04d}",
                "END:VEVENT",
            )
        )
    lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Synthetic Plan Test//EN"]
    lines.extend(events)
    lines.append("END:VCALENDAR")
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def _profile_overrides(count: int) -> dict[str, object]:
    return {
        "vevent_count": count,
        "uid_total_count": count,
        "uid_unique_count": count,
        "first_date": "2026-01-15",
        "last_date": "2026-01-15",
        "all_day_count": count,
        "dtstart_date_count": count,
        "summary_present_count": count,
        "description_present_count": count,
        "dtstamp_present_count": count,
    }


def _snapshot_document(count: int) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "snapshot_format": "sanitized-google-calendar-v1",
        "target_fingerprint": "b" * 64,
        "complete": True,
        "event_count": count,
        "page_count": 1,
        "events": [
            {
                "id": f"evtfixtureplan{index:04d}",
                "iCalUID": f"fixture-plan-{index:04d}@example.invalid",
                "summary": f"Synthetic plan event {index:04d}",
                "description": f"Safe plan description {index:04d}",
                "start": {"date": "2026-01-15"},
                "end": {"date": "2026-01-16"},
                "allDay": True,
                "status": "confirmed",
                "eventType": "default",
            }
            for index in range(count)
        ],
    }


def _large_bundle(
    tmp_path: Path,
    profile_factory: Callable[..., object],
    *,
    count: int = 101,
) -> tuple[object, object, object, dict[str, object], object]:
    source_path = tmp_path / f"source-{count}.ics"
    source_path.write_bytes(_calendar_bytes(count))
    profile = profile_factory(source_path, _profile_overrides(count))
    source = inspect_source(source_path, profile)
    document = _snapshot_document(count)
    snapshot = parse_google_snapshot_bytes(json.dumps(document, ensure_ascii=False).encode("utf-8"))
    diff = diff_source_to_snapshot(source, snapshot)
    candidate = build_baseline_candidate(profile, source, snapshot, diff)
    trusted = trust_baseline(candidate, baseline_confirmation_phrase(candidate))
    return profile, source, snapshot, document, trusted


def _current_source(
    tmp_path: Path,
    profile_factory: Callable[..., object],
    count: int,
    *,
    replace_last_uid: bool = False,
) -> tuple[object, object]:
    path = tmp_path / f"current-{count}-{replace_last_uid}.ics"
    path.write_bytes(_calendar_bytes(count, replace_last_uid=replace_last_uid))
    profile = profile_factory(path, _profile_overrides(count))
    return profile, inspect_source(path, profile)


def test_candidate_baseline_is_rejected_as_ownership_scope(
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

    with pytest.raises(PlanInputError) as caught:
        baseline_to_managed_scope(bundle.candidate)
    assert caught.value.code == "baseline_not_trusted"


def test_trusted_baseline_isolated_scope_and_exact_draft_plan(
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

    scope = baseline_to_managed_scope(bundle.trusted)
    plan = build_sync_plan(
        bundle.profile,
        bundle.source,
        bundle.snapshot,
        bundle.trusted,
    )

    assert scope.trusted_baseline_uids == frozenset(bundle.trusted.managed_uids)
    assert scope.trusted_source_uids == frozenset()
    assert scope.trusted_google_event_ids == frozenset()
    assert plan.state is PlanState.DRAFT
    assert plan.executable is False
    assert plan.approval_required is False
    assert plan.proposed_actions == ()
    assert plan.safety_guards == ()
    verify_sync_plan_content_hash(plan)


def test_default_thresholds_block_single_update(
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

    assert plan.state is PlanState.BLOCKED
    assert plan.executable is False
    assert plan.approval_required is True
    assert len(plan.proposed_actions) == 1
    assert plan.proposed_actions[0].action is PlanActionKind.UPDATE
    assert {guard.code for guard in plan.safety_guards} >= {
        "update_threshold_exceeded",
        "all_events_update",
        "mass_change_guard",
    }


def test_large_single_update_with_explicit_threshold_requires_review(
    tmp_path: Path,
    synthetic_profile_factory: Callable[..., object],
) -> None:
    profile, source, _snapshot, document, trusted = _large_bundle(
        tmp_path, synthetic_profile_factory
    )
    document["events"][0]["summary"] = "Changed synthetic summary"
    changed_snapshot = parse_google_snapshot_bytes(
        json.dumps(document, ensure_ascii=False).encode("utf-8")
    )

    plan = build_sync_plan(
        profile,
        source,
        changed_snapshot,
        trusted,
        thresholds=PlanThresholds(max_update=1),
    )

    assert plan.state is PlanState.REVIEW_REQUIRED
    assert plan.executable is False
    assert plan.approval_required is True
    assert plan.safety_guards == ()
    action = plan.proposed_actions[0]
    assert action.action is PlanActionKind.UPDATE
    assert action.changed_fields == ("summary",)
    assert action.destructive is False
    assert action.separate_approval_required is False


def test_large_single_add_with_threshold_requires_review(
    tmp_path: Path,
    synthetic_profile_factory: Callable[..., object],
) -> None:
    _old_profile, _old_source, snapshot, _document, trusted = _large_bundle(
        tmp_path, synthetic_profile_factory
    )
    profile, source = _current_source(tmp_path, synthetic_profile_factory, 102)

    plan = build_sync_plan(
        profile,
        source,
        snapshot,
        trusted,
        thresholds=PlanThresholds(max_add=1),
    )

    assert plan.state is PlanState.REVIEW_REQUIRED
    assert len(plan.proposed_actions) == 1
    action = plan.proposed_actions[0]
    assert action.action is PlanActionKind.ADD
    assert action.destructive is False
    assert action.separate_approval_required is False


def test_large_single_delete_requires_separate_approval(
    tmp_path: Path,
    synthetic_profile_factory: Callable[..., object],
) -> None:
    _old_profile, _old_source, snapshot, _document, trusted = _large_bundle(
        tmp_path, synthetic_profile_factory
    )
    profile, source = _current_source(tmp_path, synthetic_profile_factory, 100)

    plan = build_sync_plan(
        profile,
        source,
        snapshot,
        trusted,
        thresholds=PlanThresholds(max_delete=1),
    )

    assert plan.state is PlanState.REVIEW_REQUIRED
    action = plan.proposed_actions[0]
    assert action.action is PlanActionKind.DELETE_CANDIDATE
    assert action.ownership_evidence == ("trusted_baseline",)
    assert action.destructive is True
    assert action.separate_approval_required is True
    assert {guard.code for guard in plan.safety_guards} == {"delete_requires_separate_approval"}


def test_unmanaged_duplicate_and_ambiguous_inputs_are_blocked(
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
    cases = (
        ("extra_unmanaged_event.json", "unmanaged_google_event_present"),
        ("duplicate_icaluid.json", "duplicate_google_icaluid_present"),
        ("cancelled_event.json", "ambiguous_events_present"),
    )

    for snapshot_name, guard_code in cases:
        snapshot = parse_google_snapshot_bytes((google_snapshots_dir / snapshot_name).read_bytes())
        plan = build_sync_plan(bundle.profile, bundle.source, snapshot, bundle.trusted)
        assert plan.state is PlanState.BLOCKED
        assert plan.executable is False
        assert guard_code in {guard.code for guard in plan.safety_guards}


def test_zero_google_all_add_and_zero_source_all_delete_are_blocked(
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
    empty_snapshot = parse_google_snapshot_bytes(
        (google_snapshots_dir / "missing_google_event.json").read_bytes()
    )
    add_plan = build_sync_plan(bundle.profile, bundle.source, empty_snapshot, bundle.trusted)
    zero_source = bundle.source.model_copy(update={"vevent_count": 0, "events": ()})
    delete_plan = build_sync_plan(bundle.profile, zero_source, bundle.snapshot, bundle.trusted)

    assert add_plan.state is PlanState.BLOCKED
    assert {guard.code for guard in add_plan.safety_guards} >= {
        "zero_google_event_count",
        "all_events_add",
    }
    assert delete_plan.state is PlanState.BLOCKED
    assert {guard.code for guard in delete_plan.safety_guards} >= {
        "zero_source_event_count",
        "all_events_delete_candidate",
    }


def test_target_mismatch_and_tampered_baseline_are_rejected(
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
    target_mismatch = bundle.snapshot.model_copy(update={"target_fingerprint": "c" * 64})

    with pytest.raises(PlanInputError) as caught:
        diff_with_trusted_baseline(bundle.source, target_mismatch, bundle.trusted)
    assert caught.value.code == "baseline_target_mismatch"

    tampered = bundle.trusted.model_copy(update={"source_event_count": 2})
    with pytest.raises(BaselineValidationError):
        baseline_to_managed_scope(tampered)


def test_accepted_tag_transition_is_preserved_in_draft_plan(
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
    data = bundle.profile.model_dump(mode="python")
    data["source"] = dict(data["source"])
    data["source"]["accepted_tag"] = "synthetic-next-accepted-tag"
    data["source"]["accepted_commit"] = "2" * 40
    profile = type(bundle.profile).model_validate(data)

    plan = build_sync_plan(profile, bundle.source, bundle.snapshot, bundle.trusted)

    assert plan.state is PlanState.DRAFT
    assert plan.baseline.source.accepted_tag == "synthetic-test-tag"
    assert plan.current_source.accepted_tag == "synthetic-next-accepted-tag"


def test_plan_hash_is_deterministic_and_executable_true_is_rejected(
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

    first = build_sync_plan(bundle.profile, bundle.source, bundle.snapshot, bundle.trusted)
    second = build_sync_plan(bundle.profile, bundle.source, bundle.snapshot, bundle.trusted)

    assert first == second
    assert first.plan_content_hash == second.plan_content_hash
    with pytest.raises(ValidationError):
        first.model_copy(update={"executable": True}, deep=True).__class__.model_validate(
            {**first.model_dump(mode="python"), "executable": True}
        )
