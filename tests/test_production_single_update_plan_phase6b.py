from __future__ import annotations

import json
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from conftest import REPOSITORY_ROOT
from phase5a_helpers import make_test_target_config
from phase6b_helpers import (
    PRODUCTION_LIKE_REPOSITORY,
    PRODUCTION_LIKE_START_DATE,
    PRODUCTION_LIKE_UPDATED_COMMIT,
    PRODUCTION_LIKE_UPDATED_TAG,
    build_production_planning_inputs,
    build_production_snapshot,
    make_production_write_target,
    production_like_summary,
    production_like_uid,
    production_snapshot_document,
    write_production_source,
)

from tridentine_calendar_google_sync.accepted_production_source_manifest import (
    AcceptedProductionSourceManifestError,
    build_accepted_production_source_manifest,
    calculate_accepted_production_source_manifest_hash,
)
from tridentine_calendar_google_sync.baseline_engine import (
    calculate_baseline_content_hash,
)
from tridentine_calendar_google_sync.baseline_io import render_baseline_json
from tridentine_calendar_google_sync.baseline_models import BaselineState, TrustedBaseline
from tridentine_calendar_google_sync.google_snapshot import parse_google_snapshot_bytes
from tridentine_calendar_google_sync.plan_engine import diff_with_trusted_baseline
from tridentine_calendar_google_sync.production_single_update_plan import (
    ProductionSingleUpdatePlanError,
    build_production_single_update_plan,
    calculate_production_single_update_plan_hash,
    validate_production_single_update_eligibility,
    verify_production_single_update_plan,
)
from tridentine_calendar_google_sync.production_single_update_plan_io import (
    ProductionSingleUpdatePlanIOError,
    load_production_single_update_plan,
    parse_production_single_update_plan_bytes,
    render_production_single_update_plan_json,
    write_production_single_update_plan,
)
from tridentine_calendar_google_sync.production_single_update_plan_report import (
    build_production_single_update_plan_inspection,
    render_production_single_update_plan_inspection_json,
    render_production_single_update_plan_inspection_text,
)


def _build(inputs: Any) -> Any:
    return build_production_single_update_plan(
        inputs.manifest,
        inputs.updated.profile,
        inputs.updated.source,
        inputs.snapshot,
        inputs.baseline,
        inputs.target,
    )


def _rehash_baseline(baseline: TrustedBaseline, **updates: object) -> TrustedBaseline:
    provisional = baseline.model_copy(update={**updates, "baseline_content_hash": "0" * 64})
    return provisional.model_copy(
        update={"baseline_content_hash": calculate_baseline_content_hash(provisional)}
    )


def _snapshot_from_document(document: dict[str, object]) -> Any:
    return parse_google_snapshot_bytes(json.dumps(document, ensure_ascii=False).encode("utf-8"))


def test_valid_plan_is_one_description_update_with_unrelated_unchanged_event(
    tmp_path: Path,
) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    plan = _build(inputs)
    eligibility = validate_production_single_update_eligibility(
        inputs.manifest,
        inputs.updated.profile,
        inputs.updated.source,
        inputs.snapshot,
        inputs.baseline,
        inputs.target,
        diff_with_trusted_baseline(inputs.updated.source, inputs.snapshot, inputs.baseline),
    )

    assert plan.plan_type == "production_single_update"
    assert plan.production is True
    assert plan.synthetic is False
    assert plan.state == "review_required"
    assert plan.executable is False
    assert (plan.operation_count, plan.add_count, plan.update_count, plan.delete_count) == (
        1,
        0,
        1,
        0,
    )
    assert plan.changed_fields == ("description",)
    assert plan.unchanged_count == plan.source_event_count - 1 == 1
    assert plan.managed_uid_count == plan.source_event_count == plan.snapshot_event_count == 2
    assert plan.manifest_hash == inputs.manifest.manifest_content_hash
    assert plan.baseline_hash == inputs.baseline.baseline_content_hash
    assert plan.baseline_snapshot_hash == plan.snapshot_hash == inputs.snapshot.content_hash
    assert plan.safe_uid_ref == eligibility.safe_uid_ref
    assert plan.google_ref == eligibility.google_ref
    assert plan.pre_image_hash == eligibility.pre_image_hash
    assert plan.patch_hash == eligibility.patch_hash
    assert calculate_production_single_update_plan_hash(plan) == plan.plan_content_hash
    verify_production_single_update_plan(plan)


def test_plan_is_deterministic_schema_valid_and_round_trips_canonically(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    first = _build(inputs)
    second = _build(inputs)
    rendered = render_production_single_update_plan_json(first)

    assert first == second
    assert parse_production_single_update_plan_bytes(rendered.encode("utf-8")) == first
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "production-single-update-plan-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.validate(json.loads(rendered), schema)
    assert schema["additionalProperties"] is False


def test_plan_and_inspection_are_raw_content_free(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    plan = _build(inputs)
    private_render = render_production_single_update_plan_json(plan)
    reports = (
        json.dumps(build_production_single_update_plan_inspection(plan), ensure_ascii=False),
        render_production_single_update_plan_inspection_json(plan),
        render_production_single_update_plan_inspection_text(plan),
    )
    event = inputs.updated.source.events[-1]
    google_event = inputs.snapshot.events[-1]

    for forbidden in (
        event.uid,
        event.summary,
        event.description,
        inputs.target.calendar_id,
        google_event.event_id,
        google_event.etag,
    ):
        assert forbidden is not None
        assert forbidden not in private_render
        assert forbidden not in repr(plan)
        assert all(forbidden not in report for report in reports)
    for private_provenance in (
        inputs.target.expected_target_fingerprint,
        inputs.manifest.repository_identity,
        inputs.manifest.repository_tag,
        inputs.manifest.repository_commit,
        inputs.manifest.ics_sha256,
        inputs.manifest.profile_id,
    ):
        assert all(private_provenance not in report for report in reports)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("plan_type", "normal"),
        ("production", False),
        ("synthetic", True),
        ("state", "draft"),
        ("executable", True),
        ("operation_count", 2),
        ("add_count", 1),
        ("update_count", 0),
        ("delete_count", 1),
        ("changed_fields", ("summary",)),
        ("approval_required", False),
    ),
)
def test_rehashed_fixed_policy_tampering_is_rejected(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    plan = _build(build_production_planning_inputs(tmp_path))
    provisional = plan.model_copy(update={field: value, "plan_content_hash": "0" * 64})
    tampered = provisional.model_copy(
        update={"plan_content_hash": calculate_production_single_update_plan_hash(provisional)}
    )

    with pytest.raises(ProductionSingleUpdatePlanError):
        verify_production_single_update_plan(tampered)


def test_manifest_source_and_baseline_mismatches_fail_closed(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path)

    manifest_provisional = inputs.manifest.model_copy(
        update={"repository_commit": "f" * 40, "manifest_content_hash": "0" * 64}
    )
    wrong_manifest = manifest_provisional.model_copy(
        update={
            "manifest_content_hash": calculate_accepted_production_source_manifest_hash(
                manifest_provisional
            )
        }
    )
    with pytest.raises(ProductionSingleUpdatePlanError) as manifest_error:
        build_production_single_update_plan(
            wrong_manifest,
            inputs.updated.profile,
            inputs.updated.source,
            inputs.snapshot,
            inputs.baseline,
            inputs.target,
        )
    assert manifest_error.value.code == "production_single_update_manifest_source_mismatch"

    with pytest.raises(ProductionSingleUpdatePlanError):
        build_production_single_update_plan(
            inputs.manifest,
            inputs.current.profile,
            inputs.current.source,
            inputs.snapshot,
            inputs.baseline,
            inputs.target,
        )

    tampered_baseline = inputs.baseline.model_copy(update={"baseline_content_hash": "f" * 64})
    with pytest.raises(ProductionSingleUpdatePlanError) as baseline_error:
        build_production_single_update_plan(
            inputs.manifest,
            inputs.updated.profile,
            inputs.updated.source,
            inputs.snapshot,
            tampered_baseline,
            inputs.target,
        )
    assert baseline_error.value.code == "production_single_update_baseline_diff_failed"


def test_full_snapshot_drift_in_an_unrelated_event_is_rejected(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    drifted = build_production_snapshot(
        inputs.current.source,
        inputs.target,
        event_overrides={1: {"etag": "phase6b-unrelated-drift"}},
    )
    assert drifted.content_hash != inputs.snapshot.content_hash

    with pytest.raises(ProductionSingleUpdatePlanError) as captured:
        build_production_single_update_plan(
            inputs.manifest,
            inputs.updated.profile,
            inputs.updated.source,
            drifted,
            inputs.baseline,
            inputs.target,
        )
    assert captured.value.code == "production_single_update_baseline_binding_invalid"


def _build_variant_manifest(fixture: Any) -> Any:
    return build_accepted_production_source_manifest(
        fixture.profile,
        fixture.source,
        repository_identity=PRODUCTION_LIKE_REPOSITORY,
    )


def _variant_cases(tmp_path: Path) -> tuple[Callable[[], Any], ...]:
    base = build_production_planning_inputs(tmp_path / "base")

    def zero_update() -> Any:
        return build_production_single_update_plan(
            _build_variant_manifest(base.current),
            base.current.profile,
            base.current.source,
            base.snapshot,
            base.baseline,
            base.target,
        )

    def two_updates() -> Any:
        inputs = build_production_planning_inputs(tmp_path / "two", updated_indexes=(1, 2))
        return _build(inputs)

    def summary_update() -> Any:
        desired = write_production_source(
            tmp_path / "summary",
            "accepted",
            ("Current calendar description 000001", "Current calendar description 000002"),
            summaries=(production_like_summary(1), "Changed calendar observance"),
            accepted_tag=PRODUCTION_LIKE_UPDATED_TAG,
            accepted_commit=PRODUCTION_LIKE_UPDATED_COMMIT,
        )
        return build_production_single_update_plan(
            _build_variant_manifest(desired),
            desired.profile,
            desired.source,
            base.snapshot,
            base.baseline,
            base.target,
        )

    def add() -> Any:
        desired = write_production_source(
            tmp_path / "add",
            "accepted",
            (
                "Current calendar description 000001",
                "Updated calendar description 000002",
                "Added calendar description 000003",
            ),
            accepted_tag=PRODUCTION_LIKE_UPDATED_TAG,
            accepted_commit=PRODUCTION_LIKE_UPDATED_COMMIT,
        )
        return build_production_single_update_plan(
            _build_variant_manifest(desired),
            desired.profile,
            desired.source,
            base.snapshot,
            base.baseline,
            base.target,
        )

    def delete() -> Any:
        desired = write_production_source(
            tmp_path / "delete",
            "accepted",
            ("Updated calendar description 000001",),
            accepted_tag=PRODUCTION_LIKE_UPDATED_TAG,
            accepted_commit=PRODUCTION_LIKE_UPDATED_COMMIT,
        )
        return build_production_single_update_plan(
            _build_variant_manifest(desired),
            desired.profile,
            desired.source,
            base.snapshot,
            base.baseline,
            base.target,
        )

    return zero_update, two_updates, summary_update, add, delete


def test_zero_two_add_delete_and_unsupported_field_matrices_fail_closed(tmp_path: Path) -> None:
    for case in _variant_cases(tmp_path):
        with pytest.raises(ProductionSingleUpdatePlanError):
            case()


@pytest.mark.parametrize(
    ("profile_id", "project_name", "uid"),
    (
        ("synthetic-accepted", "Production calendar acceptance", None),
        ("accepted-20990101", "Synthetic calendar acceptance", None),
        ("accepted-20990101", "Production calendar acceptance", "phase6b@example.invalid"),
    ),
)
def test_synthetic_or_reserved_identity_cannot_enter_manifest_or_plan(
    tmp_path: Path,
    profile_id: str,
    project_name: str,
    uid: str | None,
) -> None:
    fixture = write_production_source(
        tmp_path,
        "rejected",
        ("Current calendar description 000001", "Updated calendar description 000002"),
        uids=(uid, "phase6b-000002@calendar.example") if uid is not None else None,
        accepted_tag=PRODUCTION_LIKE_UPDATED_TAG,
        accepted_commit=PRODUCTION_LIKE_UPDATED_COMMIT,
        profile_id=profile_id,
        project_name=project_name,
    )
    with pytest.raises(AcceptedProductionSourceManifestError):
        _build_variant_manifest(fixture)


def test_plan_io_is_repository_external_atomic_and_no_overwrite(tmp_path: Path) -> None:
    plan = _build(build_production_planning_inputs(tmp_path))
    output = tmp_path / "phase6b.production-single-update-plan.json"

    write_production_single_update_plan(plan, output)
    assert load_production_single_update_plan(output) == plan
    with pytest.raises(ProductionSingleUpdatePlanIOError):
        write_production_single_update_plan(plan, output)
    with pytest.raises(ProductionSingleUpdatePlanIOError):
        write_production_single_update_plan(
            plan,
            REPOSITORY_ROOT / "must-not-write.production-single-update-plan.json",
        )


@pytest.mark.parametrize(
    "mutate",
    (
        lambda raw: raw.replace(b'"operation_count": 1', b'"operation_count": 2', 1),
        lambda raw: raw.replace(
            b'"schema_version": "1.0",',
            b'"schema_version": "1.0",\n  "unexpected": true,',
            1,
        ),
        lambda raw: raw.replace(
            b'"schema_version": "1.0",',
            b'"schema_version": "1.0",\n  "schema_version": "1.0",',
            1,
        ),
        lambda raw: raw.rstrip(b"\n"),
    ),
)
def test_plan_parser_rejects_tampered_unknown_duplicate_or_noncanonical_json(
    tmp_path: Path,
    mutate: Callable[[bytes], bytes],
) -> None:
    rendered = render_production_single_update_plan_json(
        _build(build_production_planning_inputs(tmp_path))
    ).encode("utf-8")
    with pytest.raises(ProductionSingleUpdatePlanIOError):
        parse_production_single_update_plan_bytes(mutate(rendered))


def test_production_like_scale_4938_preserves_exact_single_update_contract(
    tmp_path: Path,
) -> None:
    inputs = build_production_planning_inputs(tmp_path, event_count=4938, updated_indexes=(4938,))
    plan = _build(inputs)

    assert plan.source_event_count == plan.snapshot_event_count == plan.managed_uid_count == 4938
    assert plan.unchanged_count == 4937
    assert (plan.add_count, plan.update_count, plan.delete_count) == (0, 1, 0)


def test_target_policy_matrix_fails_before_plan_creation(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    valid = inputs.target
    cases = (
        (
            "test_target",
            make_test_target_config(),
            "invalid_production_write_target",
        ),
        (
            "primary",
            valid.model_copy(update={"calendar_id": "primary"}),
            "production_write_target_policy_mismatch",
        ),
        (
            "fingerprint",
            valid.model_copy(update={"expected_target_fingerprint": "f" * 64}),
            "production_write_target_fingerprint_mismatch",
        ),
        (
            "environment",
            valid.model_copy(update={"target_environment": "test"}),
            "production_write_target_policy_mismatch",
        ),
        (
            "label",
            valid.model_copy(update={"target_label": "test"}),
            "production_write_target_policy_mismatch",
        ),
        (
            "purpose",
            valid.model_copy(update={"target_purpose": "test_calendar_write_acceptance"}),
            "production_write_target_policy_mismatch",
        ),
    )
    for name, target, code in cases:
        with pytest.raises(ValueError) as captured:
            build_production_single_update_plan(
                inputs.manifest,
                inputs.updated.profile,
                inputs.updated.source,
                inputs.snapshot,
                inputs.baseline,
                target,  # type: ignore[arg-type]
            )
        assert getattr(captured.value, "code", None) == code, name


def test_baseline_state_target_and_ownership_matrix_has_stable_safe_failures(
    tmp_path: Path,
) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    candidate = _rehash_baseline(inputs.baseline, state=BaselineState.CANDIDATE)
    wrong_target = _rehash_baseline(inputs.baseline, target_fingerprint="f" * 64)
    missing_owned_uid = _rehash_baseline(
        inputs.baseline,
        managed_uid_count=1,
        managed_uids=(inputs.baseline.managed_uids[0],),
    )
    cases = (
        ("candidate", candidate, "production_single_update_baseline_diff_failed"),
        (
            "test_baseline",
            _rehash_baseline(
                inputs.baseline,
                source_profile="synthetic-accepted",
                accepted_tag="accepted-test-calendar",
            ),
            "production_single_update_baseline_provenance_invalid",
        ),
        (
            "target_mismatch",
            wrong_target,
            "production_single_update_baseline_diff_failed",
        ),
        (
            "managed_uid_missing",
            missing_owned_uid,
            "production_single_update_baseline_binding_invalid",
        ),
    )
    for name, baseline, code in cases:
        with pytest.raises(ProductionSingleUpdatePlanError) as captured:
            build_production_single_update_plan(
                inputs.manifest,
                inputs.updated.profile,
                inputs.updated.source,
                inputs.snapshot,
                baseline,
                inputs.target,
            )
        assert captured.value.code == code, name


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("source_profile", "accepted-test-calendar"),
        ("source_profile", "accepted-synthetic-calendar"),
        ("source_profile", "accepted-テスト-calendar"),
        ("source_profile", "accepted.invalid"),
        ("accepted_tag", "accepted-test-calendar"),
        ("accepted_tag", "accepted-synthetic-calendar"),
        ("accepted_tag", "accepted-テスト-calendar"),
        ("accepted_tag", "accepted.invalid"),
        ("accepted_commit", "0" * 40),
        ("source_sha256", "0" * 64),
    ),
)
def test_rehashed_nonproduction_baseline_provenance_is_rejected(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    baseline = _rehash_baseline(inputs.baseline, **{field: value})

    with pytest.raises(ProductionSingleUpdatePlanError) as captured:
        build_production_single_update_plan(
            inputs.manifest,
            inputs.updated.profile,
            inputs.updated.source,
            inputs.snapshot,
            baseline,
            inputs.target,
        )
    assert captured.value.code == "production_single_update_baseline_provenance_invalid"


def test_safe_older_baseline_provenance_need_not_equal_current_manifest(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    older = _rehash_baseline(
        inputs.baseline,
        accepted_tag="accepted-older-production-release",
        accepted_commit="a" * 40,
        source_sha256="b" * 64,
    )

    plan = build_production_single_update_plan(
        inputs.manifest,
        inputs.updated.profile,
        inputs.updated.source,
        inputs.snapshot,
        older,
        inputs.target,
    )
    assert plan.baseline_hash == older.baseline_content_hash
    assert plan.accepted_tag == inputs.manifest.accepted_tag


def test_baseline_requires_no_google_event_id_or_etag(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    rendered = render_baseline_json(inputs.baseline).casefold()

    assert '"event_id"' not in rendered
    assert '"google_event_id"' not in rendered
    assert '"etag"' not in rendered
    assert _build(inputs).operation_count == 1


def test_snapshot_fail_closed_matrix_maps_to_stable_preplan_codes(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    base_document = production_snapshot_document(
        inputs.current.source,
        inputs.target.expected_target_fingerprint,
    )

    incomplete_document = dict(base_document)
    incomplete_document["complete"] = False
    incomplete = _snapshot_from_document(incomplete_document)

    duplicate_document = json.loads(json.dumps(base_document))
    duplicate_events = duplicate_document["events"]
    assert isinstance(duplicate_events, list)
    duplicate_events[1]["iCalUID"] = duplicate_events[0]["iCalUID"]
    duplicate = _snapshot_from_document(duplicate_document)

    deleted_document = json.loads(json.dumps(base_document))
    deleted_events = deleted_document["events"]
    assert isinstance(deleted_events, list)
    deleted_events.pop()
    deleted_document["event_count"] = 1
    deleted = _snapshot_from_document(deleted_document)

    template = dict(duplicate_events[0])
    template.update(
        {
            "id": "evtphase6badded000001",
            "iCalUID": "phase6b-added@calendar.example",
            "summary": "Added calendar observance",
            "description": "Added calendar description",
            "etag": "phase6b-added-etag",
        }
    )
    added = build_production_snapshot(
        inputs.current.source,
        inputs.target,
        extra_events=(template,),
    )
    relevant_drift = build_production_snapshot(
        inputs.current.source,
        inputs.target,
        event_overrides={2: {"etag": "phase6b-relevant-drift"}},
    )
    ambiguous = build_production_snapshot(
        inputs.current.source,
        inputs.target,
        event_overrides={2: {"eventType": "focusTime"}},
    )
    alternate_target = make_production_write_target(
        calendar_id="phase6b-alternate-production@calendar.example"
    )
    wrong_target_snapshot = build_production_snapshot(inputs.current.source, alternate_target)

    cases = (
        ("incomplete", incomplete, "production_single_update_baseline_binding_invalid"),
        (
            "target_mismatch",
            wrong_target_snapshot,
            "production_single_update_baseline_diff_failed",
        ),
        (
            "duplicate_icaluid",
            duplicate,
            "production_single_update_baseline_binding_invalid",
        ),
        (
            "relevant_drift",
            relevant_drift,
            "production_single_update_baseline_binding_invalid",
        ),
        ("added_event", added, "production_single_update_baseline_binding_invalid"),
        ("deleted_event", deleted, "production_single_update_baseline_binding_invalid"),
        ("ambiguous", ambiguous, "production_single_update_baseline_binding_invalid"),
    )
    for name, snapshot, code in cases:
        with pytest.raises(ProductionSingleUpdatePlanError) as captured:
            build_production_single_update_plan(
                inputs.manifest,
                inputs.updated.profile,
                inputs.updated.source,
                snapshot,
                inputs.baseline,
                inputs.target,
            )
        assert captured.value.code == code, name


def test_source_provenance_and_invalid_source_matrix_is_rejected(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    source = inputs.updated.source
    cases = (
        ("sha", source.model_copy(update={"raw_sha256": "f" * 64})),
        ("profile", source.model_copy(update={"profile_id": "accepted-other"})),
        ("count", source.model_copy(update={"vevent_count": 3})),
        (
            "date",
            source.model_copy(update={"last_date": source.last_date + timedelta(days=1)}),
        ),
        (
            "invalid",
            source.model_copy(update={"source_valid": False, "fatal": True}),
        ),
    )
    for name, changed_source in cases:
        with pytest.raises(ProductionSingleUpdatePlanError) as captured:
            build_production_single_update_plan(
                inputs.manifest,
                inputs.updated.profile,
                changed_source,
                inputs.snapshot,
                inputs.baseline,
                inputs.target,
            )
        assert captured.value.code == "production_single_update_manifest_invalid", name


def test_date_combined_field_and_unmanaged_uid_changes_fail_closed(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path / "base")

    shifted = write_production_source(
        tmp_path / "date",
        "accepted",
        ("Current calendar description 000001", "Updated calendar description 000002"),
        accepted_tag=PRODUCTION_LIKE_UPDATED_TAG,
        accepted_commit=PRODUCTION_LIKE_UPDATED_COMMIT,
        first_date=PRODUCTION_LIKE_START_DATE + timedelta(days=1),
    )
    combined = write_production_source(
        tmp_path / "combined",
        "accepted",
        ("Current calendar description 000001", "Updated calendar description 000002"),
        summaries=(production_like_summary(1), "Changed calendar observance"),
        accepted_tag=PRODUCTION_LIKE_UPDATED_TAG,
        accepted_commit=PRODUCTION_LIKE_UPDATED_COMMIT,
    )
    changed_uid = write_production_source(
        tmp_path / "uid",
        "accepted",
        ("Current calendar description 000001", "Updated calendar description 000002"),
        uids=(production_like_uid(1), "phase6b-replacement@calendar.example"),
        accepted_tag=PRODUCTION_LIKE_UPDATED_TAG,
        accepted_commit=PRODUCTION_LIKE_UPDATED_COMMIT,
    )
    cases = (
        ("date_change", shifted, "production_single_update_diff_classification_invalid"),
        (
            "description_and_summary",
            combined,
            "production_single_update_diff_fields_invalid",
        ),
        (
            "updated_uid_not_managed",
            changed_uid,
            "production_single_update_baseline_binding_invalid",
        ),
    )
    for name, fixture, code in cases:
        manifest = _build_variant_manifest(fixture)
        with pytest.raises(ProductionSingleUpdatePlanError) as captured:
            build_production_single_update_plan(
                manifest,
                fixture.profile,
                fixture.source,
                inputs.snapshot,
                inputs.baseline,
                inputs.target,
            )
        assert captured.value.code == code, name
