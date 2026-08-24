from __future__ import annotations

from pathlib import Path

import pytest
from conftest import build_synthetic_baseline_bundle, build_synthetic_profile
from phase5c0_helpers import (
    BOOTSTRAP_SUMMARY,
    BOOTSTRAP_UID,
    bootstrap_ics_bytes,
    build_bootstrap_bundle,
    build_bootstrap_source,
    build_prewrite_snapshot,
)

from tridentine_calendar_google_sync.diff_models import DiffClassification
from tridentine_calendar_google_sync.google_snapshot import load_google_snapshot
from tridentine_calendar_google_sync.plan_engine import build_sync_plan
from tridentine_calendar_google_sync.plan_models import PlanState, PlanThresholds
from tridentine_calendar_google_sync.test_bootstrap_plan import (
    TestBootstrapPlanError as BootstrapError,
)
from tridentine_calendar_google_sync.test_bootstrap_plan import (
    build_test_bootstrap_add_plan,
    validate_test_bootstrap_eligibility,
)
from tridentine_calendar_google_sync.test_bootstrap_plan_models import (
    ALLOWED_BOOTSTRAP_ORIGINAL_GUARDS,
    PRODUCTION_ACCEPTED_TAG,
    PRODUCTION_SOURCE_PROFILE_ID,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetPolicyError as TargetPolicyError,
)


def test_valid_empty_test_target_and_one_synthetic_add_are_eligible(tmp_path: Path) -> None:
    bundle = build_bootstrap_bundle(tmp_path)

    eligibility = validate_test_bootstrap_eligibility(
        bundle.profile,
        bundle.source,
        bundle.prewrite_snapshot,
        bundle.target,
        bundle.diff,
    )

    assert eligibility.eligible is True
    assert eligibility.safe_uid_ref == bundle.source.events[0].safe_uid_reference
    assert eligibility.original_guard_codes == ALLOWED_BOOTSTRAP_ORIGINAL_GUARDS
    assert bundle.diff.source_event_count == 1
    assert bundle.diff.google_event_count == 0
    assert bundle.diff.counts.add == 1
    assert bundle.diff.counts.update == 0
    assert bundle.diff.counts.delete_candidate == 0


def test_normal_sync_plan_global_guards_remain_blocked_and_unchanged(
    tmp_path: Path,
) -> None:
    valid_source = Path("tests/fixtures/valid_minimal.ics")
    exact_snapshot = Path("tests/fixtures/google_snapshots/exact_match.json")
    empty_snapshot = load_google_snapshot(
        Path("tests/fixtures/google_snapshots/missing_google_event.json")
    )
    bundle = build_synthetic_baseline_bundle(
        valid_source,
        build_synthetic_profile,
        exact_snapshot,
    )

    plan = build_sync_plan(
        bundle.profile,
        bundle.source,
        empty_snapshot,
        bundle.trusted,
        thresholds=PlanThresholds(max_add=1),
    )

    assert plan.state is PlanState.BLOCKED
    assert len(plan.proposed_actions) == 1
    assert {guard.code for guard in plan.safety_guards} == {
        "zero_google_event_count",
        "all_events_add",
        "mass_change_guard",
    }


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("target_environment", "production"),
        ("target_label", "production"),
        ("target_purpose", "production_calendar_sync"),
        ("calendar_id", "primary"),
        ("expected_summary", "Ordinary Calendar"),
        ("expected_target_fingerprint", "f" * 64),
    ),
)
def test_target_policy_failure_rejects_bootstrap_before_plan(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    bundle = build_bootstrap_bundle(tmp_path)
    target = bundle.target.model_copy(update={field: value})

    with pytest.raises(TargetPolicyError):
        build_test_bootstrap_add_plan(
            bundle.profile,
            bundle.source,
            bundle.prewrite_snapshot,
            target,
            diff=bundle.diff,
        )


def test_nonempty_test_snapshot_is_ineligible_and_bootstrap_is_not_reusable(
    tmp_path: Path,
) -> None:
    bundle = build_bootstrap_bundle(tmp_path)
    target, nonempty = build_prewrite_snapshot(nonempty=True)

    with pytest.raises(BootstrapError) as captured:
        build_test_bootstrap_add_plan(bundle.profile, bundle.source, nonempty, target)
    assert captured.value.code == "bootstrap_snapshot_not_empty_or_safe"


def test_incomplete_or_target_mismatched_snapshot_is_rejected(tmp_path: Path) -> None:
    bundle = build_bootstrap_bundle(tmp_path)
    incomplete_nested = bundle.prewrite_snapshot.snapshot.model_copy(update={"complete": False})
    incomplete = bundle.prewrite_snapshot.model_copy(update={"snapshot": incomplete_nested})
    mismatch = bundle.prewrite_snapshot.model_copy(update={"target_safe_ref": "T-ffffffffffff"})

    for snapshot in (incomplete, mismatch):
        with pytest.raises(BootstrapError):
            build_test_bootstrap_add_plan(
                bundle.profile,
                bundle.source,
                snapshot,
                bundle.target,
            )


@pytest.mark.parametrize(
    "profile_overrides",
    (
        {"profile_id": PRODUCTION_SOURCE_PROFILE_ID},
        {"source.accepted_tag": PRODUCTION_ACCEPTED_TAG},
        {"profile_id": "ordinary-profile"},
        {"source.accepted_tag": "ordinary-tag"},
        {"project_name": "Ordinary calendar"},
    ),
)
def test_production_or_unmarked_profile_is_rejected(
    tmp_path: Path,
    profile_overrides: dict[str, str],
) -> None:
    _path, profile, source = build_bootstrap_source(
        tmp_path,
        profile_overrides=profile_overrides,
    )
    target, snapshot = build_prewrite_snapshot()

    with pytest.raises(BootstrapError):
        build_test_bootstrap_add_plan(profile, source, snapshot, target)


@pytest.mark.parametrize(
    "source_bytes",
    (
        bootstrap_ics_bytes(uid="fixture-bootstrap@example.com"),
        bootstrap_ics_bytes(summary="Ordinary synthetic observance"),
        bootstrap_ics_bytes(description=""),
        bootstrap_ics_bytes(extra_lines=("RRULE:FREQ=DAILY",)),
        bootstrap_ics_bytes(dtend="20260824"),
    ),
)
def test_invalid_uid_marker_text_recurrence_or_span_is_rejected(
    tmp_path: Path,
    source_bytes: bytes,
) -> None:
    _path, profile, source = build_bootstrap_source(tmp_path, source_bytes=source_bytes)
    target, snapshot = build_prewrite_snapshot()

    with pytest.raises(BootstrapError):
        build_test_bootstrap_add_plan(profile, source, snapshot, target)


def test_source_count_zero_or_two_is_rejected(tmp_path: Path) -> None:
    bundle = build_bootstrap_bundle(tmp_path)
    event = bundle.source.events[0]
    zero = bundle.source.model_copy(
        update={
            "vevent_count": 0,
            "events": (),
            "uid_total_count": 0,
            "uid_unique_count": 0,
            "all_day_count": 0,
            "dtstart_date_count": 0,
            "summary_present_count": 0,
            "description_present_count": 0,
        }
    )
    two = bundle.source.model_copy(
        update={
            "vevent_count": 2,
            "events": (event, event.model_copy(update={"source_index": 1})),
            "uid_total_count": 2,
            "all_day_count": 2,
            "dtstart_date_count": 2,
            "summary_present_count": 2,
            "description_present_count": 2,
        }
    )

    for source in (zero, two):
        with pytest.raises(BootstrapError):
            build_test_bootstrap_add_plan(
                bundle.profile,
                source,
                bundle.prewrite_snapshot,
                bundle.target,
            )


@pytest.mark.parametrize(
    "count_updates",
    (
        {"add": 0, "update": 1},
        {"add": 0, "delete_candidate": 1},
        {"add": 0, "unmanaged_google_event": 1},
        {"add": 0, "ambiguous": 1},
        {"add": 0, "duplicate_source_uid": 1},
        {"add": 0, "duplicate_google_icaluid": 1},
        {"add": 0, "invalid_source": 1},
        {"add": 0, "fatal_guard": 1},
    ),
)
def test_every_non_add_diff_classification_is_rejected(
    tmp_path: Path,
    count_updates: dict[str, int],
) -> None:
    bundle = build_bootstrap_bundle(tmp_path)
    counts = bundle.diff.counts.model_copy(update=count_updates)
    diff = bundle.diff.model_copy(update={"counts": counts})

    with pytest.raises(BootstrapError) as captured:
        validate_test_bootstrap_eligibility(
            bundle.profile,
            bundle.source,
            bundle.prewrite_snapshot,
            bundle.target,
            diff,
        )
    assert captured.value.code == "bootstrap_diff_classification_invalid"


def test_diff_event_must_be_exact_source_only_add(tmp_path: Path) -> None:
    bundle = build_bootstrap_bundle(tmp_path)
    event = bundle.diff.events[0].model_copy(update={"classification": DiffClassification.UPDATE})
    diff = bundle.diff.model_copy(update={"events": (event,)})

    with pytest.raises(BootstrapError) as captured:
        validate_test_bootstrap_eligibility(
            bundle.profile,
            bundle.source,
            bundle.prewrite_snapshot,
            bundle.target,
            diff,
        )
    assert captured.value.code == "bootstrap_diff_event_identity_invalid"


@pytest.mark.parametrize(
    "guards",
    (
        (),
        ("zero_google_event_count", "all_events_add"),
        (*ALLOWED_BOOTSTRAP_ORIGINAL_GUARDS, "unknown_guard"),
        tuple(reversed(ALLOWED_BOOTSTRAP_ORIGINAL_GUARDS)),
    ),
)
def test_only_exact_ordered_three_original_guard_codes_are_allowed(
    tmp_path: Path,
    guards: tuple[str, ...],
) -> None:
    bundle = build_bootstrap_bundle(tmp_path)

    with pytest.raises(BootstrapError) as captured:
        validate_test_bootstrap_eligibility(
            bundle.profile,
            bundle.source,
            bundle.prewrite_snapshot,
            bundle.target,
            bundle.diff,
            original_guard_codes=guards,
        )
    assert captured.value.code == "bootstrap_original_guard_codes_forbidden"


def test_planned_synthetic_identity_and_marker_are_exact(tmp_path: Path) -> None:
    bundle = build_bootstrap_bundle(tmp_path)
    event = bundle.source.events[0]

    assert event.uid == BOOTSTRAP_UID
    assert event.summary == BOOTSTRAP_SUMMARY
    assert event.uid.endswith(".invalid")
    assert "同期テスト" in event.summary
