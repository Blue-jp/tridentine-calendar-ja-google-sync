from __future__ import annotations

import json
from pathlib import Path

import jsonschema
import pytest
from conftest import REPOSITORY_ROOT, build_synthetic_profile
from phase5d0_helpers import (
    CURRENT_DESCRIPTION,
    SINGLE_UPDATE_ETAG,
    SINGLE_UPDATE_EVENT_ID,
    SINGLE_UPDATE_UID,
    UPDATED_DESCRIPTION,
    build_single_update_bundle,
    build_single_update_prewrite_snapshot,
    single_update_ics_bytes,
)

from tridentine_calendar_google_sync.baseline_engine import (
    build_baseline_candidate,
    calculate_baseline_content_hash,
)
from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.plan_engine import PlanInputError, build_sync_plan
from tridentine_calendar_google_sync.plan_models import PlanState, PlanThresholds
from tridentine_calendar_google_sync.source_ics import inspect_source
from tridentine_calendar_google_sync.test_calendar_prewrite import (
    TestCalendarPrewriteError as CalendarPrewriteError,
)
from tridentine_calendar_google_sync.test_single_update_plan import (
    TestSingleUpdatePlanError as SingleUpdatePlanError,
)
from tridentine_calendar_google_sync.test_single_update_plan import (
    build_test_single_update_plan,
    calculate_test_single_update_plan_hash,
    validate_test_single_update_eligibility,
    verify_test_single_update_plan,
)
from tridentine_calendar_google_sync.test_single_update_plan_io import (
    TestSingleUpdatePlanIOError as SingleUpdatePlanIOError,
)
from tridentine_calendar_google_sync.test_single_update_plan_io import (
    load_test_single_update_plan,
    parse_test_single_update_plan_bytes,
    render_test_single_update_plan_json,
    write_test_single_update_plan,
)
from tridentine_calendar_google_sync.test_single_update_plan_models import (
    ALLOWED_SINGLE_UPDATE_ORIGINAL_GUARDS,
)
from tridentine_calendar_google_sync.test_single_update_plan_report import (
    build_test_single_update_plan_inspection,
    render_test_single_update_plan_inspection_json,
    render_test_single_update_plan_inspection_text,
)
from tridentine_calendar_google_sync.test_write_run_spec import (
    TestWriteRunSpecError as WriteRunSpecError,
)
from tridentine_calendar_google_sync.test_write_run_spec import (
    build_test_write_run_spec,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetPolicyError as TargetPolicyError,
)


def test_valid_description_only_plan_has_exact_fixed_contract(tmp_path: Path) -> None:
    bundle = build_single_update_bundle(tmp_path)
    plan = bundle.plan

    assert plan.plan_type == "test_single_update"
    assert plan.test_only is True
    assert plan.single_update_only is True
    assert plan.production_locked is True
    assert plan.executable is False
    assert plan.baseline_state == "trusted"
    assert plan.baseline_hash == bundle.baseline.baseline_content_hash
    assert plan.baseline_snapshot_hash == bundle.baseline.snapshot_content_hash
    assert plan.baseline_snapshot_hash == plan.snapshot_hash
    assert plan.managed_uid_count == 1
    assert plan.source_event_count == 1
    assert plan.snapshot_event_count == 1
    assert (plan.operation_count, plan.add_count, plan.update_count, plan.delete_count) == (
        1,
        0,
        1,
        0,
    )
    assert plan.changed_fields == ("description",)
    assert plan.original_guard_codes == ALLOWED_SINGLE_UPDATE_ORIGINAL_GUARDS
    assert plan.eligibility == "eligible"
    assert plan.approval_required is True
    verify_test_single_update_plan(plan)


def test_updated_source_sha_is_distinct_from_baseline_and_bound_to_plan(
    tmp_path: Path,
) -> None:
    bundle = build_single_update_bundle(tmp_path)

    assert bundle.baseline.source_sha256 == bundle.current_source.raw_sha256
    assert bundle.baseline.source_sha256 != bundle.updated_source.raw_sha256
    assert bundle.plan.source_sha256 == bundle.updated_source.raw_sha256
    assert bundle.plan.source_sha256 != bundle.baseline.source_sha256
    verify_test_single_update_plan(bundle.plan)


def test_same_target_uid_but_different_valid_snapshot_is_rejected_with_safe_code(
    tmp_path: Path,
) -> None:
    bundle = build_single_update_bundle(tmp_path)
    alternate = build_single_update_prewrite_snapshot(
        bundle.target,
        etag="fixture-etag-alternate-valid-snapshot",
    )

    assert alternate.target_safe_ref == bundle.prewrite_snapshot.target_safe_ref
    assert alternate.snapshot.events[0].ical_uid == (
        bundle.prewrite_snapshot.snapshot.events[0].ical_uid
    )
    assert alternate.snapshot_content_hash != bundle.prewrite_snapshot.snapshot_content_hash
    with pytest.raises(SingleUpdatePlanError) as captured:
        build_test_single_update_plan(
            bundle.updated_profile,
            bundle.updated_source,
            alternate,
            bundle.baseline,
            bundle.target,
        )
    assert captured.value.code == "trusted_baseline_snapshot_mismatch"


def test_baseline_hash_tamper_is_rejected_safely(tmp_path: Path) -> None:
    bundle = build_single_update_bundle(tmp_path)
    tampered = bundle.baseline.model_copy(update={"baseline_content_hash": "f" * 64})

    with pytest.raises(SingleUpdatePlanError) as captured:
        build_test_single_update_plan(
            bundle.updated_profile,
            bundle.updated_source,
            bundle.prewrite_snapshot,
            tampered,
            bundle.target,
        )
    assert captured.value.code == "single_update_baseline_diff_failed"


def test_normal_planner_remains_blocked_and_normal_run_spec_remains_unavailable(
    tmp_path: Path,
) -> None:
    bundle = build_single_update_bundle(tmp_path)
    normal = build_sync_plan(
        bundle.updated_profile,
        bundle.updated_source,
        bundle.prewrite_snapshot.snapshot,
        bundle.baseline,
        thresholds=PlanThresholds(max_add=0, max_update=1, max_delete=0),
    )

    assert normal.state is PlanState.BLOCKED
    assert normal.executable is False
    assert normal.diff_summary.counts.update == 1
    assert {guard.code for guard in normal.safety_guards} == {
        "all_events_update",
        "mass_change_guard",
    }
    with pytest.raises(WriteRunSpecError) as captured:
        build_test_write_run_spec(
            bundle.updated_profile,
            bundle.updated_source,
            bundle.prewrite_snapshot.snapshot,
            normal,
            bundle.target,
            trusted_baseline=bundle.baseline,
        )
    assert captured.value.code == "unsafe_test_write_plan"


def test_eligibility_recomputes_exact_diff_and_original_guards(tmp_path: Path) -> None:
    bundle = build_single_update_bundle(tmp_path)
    from tridentine_calendar_google_sync.plan_engine import diff_with_trusted_baseline

    diff = diff_with_trusted_baseline(
        bundle.updated_source,
        bundle.prewrite_snapshot.snapshot,
        bundle.baseline,
    )
    eligibility = validate_test_single_update_eligibility(
        bundle.updated_profile,
        bundle.updated_source,
        bundle.prewrite_snapshot,
        bundle.baseline,
        bundle.target,
        diff,
    )

    assert diff.source_event_count == 1
    assert diff.google_event_count == 1
    assert diff.counts.update == 1
    assert diff.counts.add == 0
    assert diff.counts.delete_candidate == 0
    assert eligibility.original_guard_codes == ALLOWED_SINGLE_UPDATE_ORIGINAL_GUARDS


def test_no_change_and_non_description_changes_are_rejected(tmp_path: Path) -> None:
    bundle = build_single_update_bundle(tmp_path)
    with pytest.raises(SingleUpdatePlanError):
        build_test_single_update_plan(
            bundle.current_profile,
            bundle.current_source,
            bundle.prewrite_snapshot,
            bundle.baseline,
            bundle.target,
        )

    summary_path = tmp_path / "summary-change.ics"
    summary_path.write_bytes(
        single_update_ics_bytes(CURRENT_DESCRIPTION, summary="Synthetic Test changed summary")
    )
    summary_profile = build_synthetic_profile(summary_path)
    summary_source = inspect_source(summary_path, summary_profile)
    with pytest.raises(SingleUpdatePlanError):
        build_test_single_update_plan(
            summary_profile,
            summary_source,
            bundle.prewrite_snapshot,
            bundle.baseline,
            bundle.target,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("target_environment", "production"),
        ("target_label", "production"),
        ("target_purpose", "production_calendar_sync"),
        ("calendar_id", "primary"),
    ),
)
def test_non_test_or_primary_target_is_rejected(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    bundle = build_single_update_bundle(tmp_path)
    target = bundle.target.model_copy(update={field: value})
    with pytest.raises(TargetPolicyError):
        build_test_single_update_plan(
            bundle.updated_profile,
            bundle.updated_source,
            bundle.prewrite_snapshot,
            bundle.baseline,
            target,
        )


def test_candidate_baseline_is_rejected(tmp_path: Path) -> None:
    bundle = build_single_update_bundle(tmp_path)
    candidate = build_baseline_candidate(
        bundle.current_profile,
        bundle.current_source,
        bundle.prewrite_snapshot.snapshot,
        diff_source_to_snapshot(
            bundle.current_source,
            bundle.prewrite_snapshot.snapshot,
        ),
    )
    with pytest.raises(SingleUpdatePlanError):
        build_test_single_update_plan(
            bundle.updated_profile,
            bundle.updated_source,
            bundle.prewrite_snapshot,
            candidate,
            bundle.target,
        )


@pytest.mark.parametrize("managed_count", (0, 2))
def test_baseline_managed_uid_count_must_be_exactly_one(
    tmp_path: Path,
    managed_count: int,
) -> None:
    bundle = build_single_update_bundle(tmp_path)
    managed = () if managed_count == 0 else (SINGLE_UPDATE_UID, "second@example.invalid")
    provisional = bundle.baseline.model_copy(
        update={
            "managed_uid_count": managed_count,
            "managed_uids": managed,
            "baseline_content_hash": "0" * 64,
        }
    )
    baseline = provisional.model_copy(
        update={"baseline_content_hash": calculate_baseline_content_hash(provisional)}
    )
    with pytest.raises((SingleUpdatePlanError, PlanInputError)):
        build_test_single_update_plan(
            bundle.updated_profile,
            bundle.updated_source,
            bundle.prewrite_snapshot,
            baseline,
            bundle.target,
        )


@pytest.mark.parametrize(
    "field",
    (
        "complete",
        "snapshot_event_count",
        "event_id",
        "etag",
        "cancelled",
        "recurring",
        "timed",
        "event_type",
        "uid_mismatch",
    ),
)
def test_invalid_current_snapshot_shapes_are_rejected(
    tmp_path: Path,
    field: str,
) -> None:
    bundle = build_single_update_bundle(tmp_path)
    wrapper = bundle.prewrite_snapshot
    nested = wrapper.snapshot
    event = nested.events[0]
    if field == "complete":
        nested = nested.model_copy(update={"complete": False})
    elif field == "snapshot_event_count":
        nested = nested.model_copy(update={"event_count": 2})
    elif field == "event_id":
        nested = nested.model_copy(update={"events": (event.model_copy(update={"event_id": ""}),)})
    elif field == "etag":
        nested = nested.model_copy(update={"events": (event.model_copy(update={"etag": None}),)})
    elif field == "cancelled":
        nested = nested.model_copy(
            update={"events": (event.model_copy(update={"status": "cancelled"}),)}
        )
    elif field == "recurring":
        nested = nested.model_copy(
            update={"events": (event.model_copy(update={"recurrence": ("RRULE:FREQ=DAILY",)}),)}
        )
    elif field == "timed":
        nested = nested.model_copy(
            update={"events": (event.model_copy(update={"all_day": False}),)}
        )
    elif field == "event_type":
        nested = nested.model_copy(
            update={"events": (event.model_copy(update={"event_type": "focusTime"}),)}
        )
    else:
        nested = nested.model_copy(
            update={"events": (event.model_copy(update={"ical_uid": "other@example.invalid"}),)}
        )
    tampered = wrapper.model_copy(update={"snapshot": nested})

    with pytest.raises((SingleUpdatePlanError, CalendarPrewriteError, PlanInputError)):
        build_test_single_update_plan(
            bundle.updated_profile,
            bundle.updated_source,
            tampered,
            bundle.baseline,
            bundle.target,
        )


@pytest.mark.parametrize(
    ("summary", "description"),
    (
        ("Ordinary synthetic event", UPDATED_DESCRIPTION),
        ("Synthetic Test changed summary", UPDATED_DESCRIPTION),
        ("Synthetic Test changed summary", CURRENT_DESCRIPTION),
    ),
)
def test_missing_test_marker_or_non_description_change_is_rejected(
    tmp_path: Path,
    summary: str,
    description: str,
) -> None:
    bundle = build_single_update_bundle(tmp_path)
    path = tmp_path / f"invalid-source-{len(summary)}-{len(description)}.ics"
    path.write_bytes(single_update_ics_bytes(description, summary=summary))
    profile = build_synthetic_profile(path)
    source = inspect_source(path, profile)
    with pytest.raises((SingleUpdatePlanError, PlanInputError)):
        build_test_single_update_plan(
            profile,
            source,
            bundle.prewrite_snapshot,
            bundle.baseline,
            bundle.target,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("plan_type", "normal"),
        ("single_update_only", False),
        ("executable", True),
        ("managed_uid_count", 2),
        ("baseline_snapshot_hash", "f" * 64),
        ("snapshot_hash", "f" * 64),
        ("operation_count", 2),
        ("add_count", 1),
        ("update_count", 0),
        ("delete_count", 1),
        ("changed_fields", ("summary",)),
        ("original_guard_codes", ("unknown_guard",)),
        ("eligibility", "ineligible"),
    ),
)
def test_rehashed_fixed_policy_tampering_is_rejected(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    plan = build_single_update_bundle(tmp_path).plan
    provisional = plan.model_copy(update={field: value, "plan_content_hash": "0" * 64})
    tampered = provisional.model_copy(
        update={"plan_content_hash": calculate_test_single_update_plan_hash(provisional)}
    )
    with pytest.raises(SingleUpdatePlanError):
        verify_test_single_update_plan(tampered)


def test_plan_schema_roundtrip_determinism_and_safe_inspection(tmp_path: Path) -> None:
    bundle = build_single_update_bundle(tmp_path)
    plan = bundle.plan
    rendered = render_test_single_update_plan_json(plan)
    assert parse_test_single_update_plan_bytes(rendered.encode("utf-8")) == plan
    assert render_test_single_update_plan_json(plan) == rendered
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "test-single-update-plan-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.validate(json.loads(rendered), schema)

    reports = (
        json.dumps(build_test_single_update_plan_inspection(plan), ensure_ascii=False),
        render_test_single_update_plan_inspection_json(plan),
        render_test_single_update_plan_inspection_text(plan),
    )
    for report in reports:
        for forbidden in (
            SINGLE_UPDATE_UID,
            UPDATED_DESCRIPTION,
            SINGLE_UPDATE_EVENT_ID,
            SINGLE_UPDATE_ETAG,
            bundle.target.calendar_id,
            bundle.target.expected_target_fingerprint,
            str(tmp_path),
        ):
            assert forbidden not in report


def test_plan_io_is_repository_external_atomic_and_no_overwrite(tmp_path: Path) -> None:
    plan = build_single_update_bundle(tmp_path).plan
    output = tmp_path / "fixture.test-single-update-plan.json"
    write_test_single_update_plan(plan, output)
    assert load_test_single_update_plan(output) == plan
    with pytest.raises(SingleUpdatePlanIOError):
        write_test_single_update_plan(plan, output)
    with pytest.raises(SingleUpdatePlanIOError):
        write_test_single_update_plan(
            plan,
            REPOSITORY_ROOT / "must-not-write.test-single-update-plan.json",
        )


@pytest.mark.parametrize(
    "raw",
    (
        b"not-json",
        b'{"schema_version":"2.0"}',
        b'{"schema_version":"1.0","schema_version":"1.0"}',
    ),
)
def test_plan_parser_rejects_malformed_unknown_or_duplicate_documents(raw: bytes) -> None:
    with pytest.raises(SingleUpdatePlanIOError):
        parse_test_single_update_plan_bytes(raw)


def test_plan_has_no_raw_identity_content_or_concurrency_values(tmp_path: Path) -> None:
    bundle = build_single_update_bundle(tmp_path)
    rendered = render_test_single_update_plan_json(bundle.plan)
    for forbidden in (
        SINGLE_UPDATE_UID,
        bundle.updated_source.events[0].summary,
        bundle.updated_source.events[0].description,
        SINGLE_UPDATE_EVENT_ID,
        SINGLE_UPDATE_ETAG,
        bundle.target.calendar_id,
        '"payload"',
        '"endpoint"',
        '"http_method"',
    ):
        assert forbidden not in rendered
