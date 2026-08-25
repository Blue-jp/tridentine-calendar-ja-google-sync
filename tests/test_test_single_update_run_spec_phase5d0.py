from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from conftest import REPOSITORY_ROOT
from phase5d0_helpers import (
    SINGLE_UPDATE_ETAG,
    SINGLE_UPDATE_EVENT_ID,
    SINGLE_UPDATE_UID,
    UPDATED_DESCRIPTION,
    build_single_update_bundle,
    build_single_update_prewrite_snapshot,
)

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.baseline_engine import (
    BaselineValidationError,
)
from tridentine_calendar_google_sync.test_calendar_prewrite import (
    TestCalendarPrewriteError as CalendarPrewriteError,
)
from tridentine_calendar_google_sync.test_single_update_approval import (
    TestSingleUpdateApprovalError as SingleUpdateApprovalError,
)
from tridentine_calendar_google_sync.test_single_update_approval import (
    approve_test_single_update_run_spec,
)
from tridentine_calendar_google_sync.test_single_update_approval import (
    test_single_update_approval_challenge as approval_challenge,
)
from tridentine_calendar_google_sync.test_single_update_plan import (
    TestSingleUpdatePlanError as SingleUpdatePlanError,
)
from tridentine_calendar_google_sync.test_single_update_plan import (
    calculate_test_single_update_plan_hash,
    verify_test_single_update_plan,
)
from tridentine_calendar_google_sync.test_single_update_run_spec import (
    TestSingleUpdateRunSpecError as SingleUpdateRunSpecError,
)
from tridentine_calendar_google_sync.test_single_update_run_spec import (
    build_test_single_update_run_spec,
    calculate_test_single_update_operation_hash,
    calculate_test_single_update_run_spec_hash,
    verify_test_single_update_run_spec,
    verify_test_single_update_run_spec_bindings,
)
from tridentine_calendar_google_sync.test_single_update_run_spec_io import (
    TestSingleUpdateRunSpecIOError as SingleUpdateRunSpecIOError,
)
from tridentine_calendar_google_sync.test_single_update_run_spec_io import (
    load_test_single_update_run_spec,
    parse_test_single_update_run_spec_bytes,
    render_test_single_update_run_spec_json,
    write_test_single_update_run_spec,
)
from tridentine_calendar_google_sync.test_write_approval_dispatch import (
    any_test_write_approval_challenge,
    approve_any_test_write_run_spec,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteOperationKind as OperationKind,
)
from tridentine_calendar_google_sync.test_write_spec_dispatch import (
    TestWriteSpecDispatchError as WriteSpecDispatchError,
)
from tridentine_calendar_google_sync.test_write_spec_dispatch import (
    verify_any_test_write_run_spec,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetPolicyError as TargetPolicyError,
)

pytestmark = pytest.mark.google_test_write


def _spec(bundle: Any) -> Any:
    return build_test_single_update_run_spec(
        bundle.updated_profile,
        bundle.updated_source,
        bundle.prewrite_snapshot,
        bundle.plan,
        bundle.baseline,
        bundle.target,
    )


def _challenge_kwargs(bundle: Any) -> dict[str, Any]:
    return {
        "current_snapshot_hash": bundle.prewrite_snapshot.snapshot_content_hash,
        "current_plan_hash": bundle.plan.plan_content_hash,
        "current_baseline_hash": bundle.baseline.baseline_content_hash,
    }


def test_valid_run_spec_is_exactly_one_description_update(tmp_path: Path) -> None:
    bundle = build_single_update_bundle(tmp_path)
    run_spec = _spec(bundle)

    assert run_spec.run_type == "test-single-update-run-spec-v1"
    assert run_spec.planning_mode == "test_single_update"
    assert run_spec.single_update is True
    assert run_spec.test_only is True
    assert run_spec.production_locked is True
    assert run_spec.baseline_state == "trusted"
    assert run_spec.trusted_baseline_hash == bundle.baseline.baseline_content_hash
    assert run_spec.baseline_snapshot_hash == bundle.baseline.snapshot_content_hash
    assert run_spec.baseline_snapshot_hash == run_spec.current_snapshot_hash
    assert run_spec.single_update_plan_hash == bundle.plan.plan_content_hash
    assert bundle.baseline.source_sha256 != bundle.updated_source.raw_sha256
    assert run_spec.source_sha256 == bundle.updated_source.raw_sha256
    assert (run_spec.operation_count, run_spec.add_count, run_spec.update_count) == (1, 0, 1)
    assert run_spec.delete_count == 0
    assert run_spec.changed_fields == ("description",)
    assert run_spec.operation.operation is OperationKind.UPDATE
    assert run_spec.operation.changed_fields == ("description",)
    assert run_spec.operation.google_event_id == SINGLE_UPDATE_EVENT_ID
    assert run_spec.operation.expected_etag == SINGLE_UPDATE_ETAG
    assert run_spec.operation.current_state.description != UPDATED_DESCRIPTION
    assert run_spec.operation.desired_state.description == UPDATED_DESCRIPTION
    verify_test_single_update_run_spec(run_spec)
    verify_test_single_update_run_spec_bindings(run_spec, bundle.plan, bundle.baseline)


def test_run_spec_is_deterministic_schema_valid_and_private(tmp_path: Path) -> None:
    bundle = build_single_update_bundle(tmp_path)
    first = _spec(bundle)
    second = _spec(bundle)
    rendered = render_test_single_update_run_spec_json(first)

    assert first == second
    assert calculate_test_single_update_run_spec_hash(first) == first.run_spec_content_hash
    assert (
        calculate_test_single_update_operation_hash(first.operation)
        == first.operation.operation_content_hash
    )
    assert parse_test_single_update_run_spec_bytes(rendered.encode("utf-8")) == first
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "test-single-update-run-spec-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    jsonschema.validate(json.loads(rendered), schema)
    for value in (
        SINGLE_UPDATE_UID,
        SINGLE_UPDATE_EVENT_ID,
        SINGLE_UPDATE_ETAG,
        bundle.updated_source.events[0].summary,
        bundle.updated_source.events[0].description,
        bundle.target.calendar_id,
        bundle.target.expected_target_fingerprint,
    ):
        assert value not in repr(first)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("run_type", "test-calendar-write-run-spec-v1"),
        ("planning_mode", "normal"),
        ("single_update", False),
        ("test_only", False),
        ("production_locked", False),
        ("baseline_state", "candidate"),
        ("baseline_snapshot_hash", "f" * 64),
        ("operation_count", 2),
        ("add_count", 1),
        ("update_count", 0),
        ("delete_count", 1),
        ("changed_fields", ("summary",)),
        ("approval_required", False),
    ),
)
def test_rehashed_run_spec_fixed_policy_tampering_is_rejected(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    run_spec = _spec(build_single_update_bundle(tmp_path))
    provisional = run_spec.model_copy(update={field: value, "run_spec_content_hash": "0" * 64})
    tampered = provisional.model_copy(
        update={"run_spec_content_hash": calculate_test_single_update_run_spec_hash(provisional)}
    )
    with pytest.raises(SingleUpdateRunSpecError):
        verify_test_single_update_run_spec(tampered)


@pytest.mark.parametrize("etag", ("", "*", "unsafe\r\nvalue"))
def test_missing_wildcard_or_header_injection_etag_is_rejected(
    tmp_path: Path,
    etag: str,
) -> None:
    run_spec = _spec(build_single_update_bundle(tmp_path))
    operation_provisional = run_spec.operation.model_copy(
        update={"expected_etag": etag, "operation_content_hash": "0" * 64}
    )
    operation = operation_provisional.model_copy(
        update={
            "operation_content_hash": calculate_test_single_update_operation_hash(
                operation_provisional
            )
        }
    )
    provisional = run_spec.model_copy(
        update={"operation": operation, "run_spec_content_hash": "0" * 64}
    )
    tampered = provisional.model_copy(
        update={"run_spec_content_hash": calculate_test_single_update_run_spec_hash(provisional)}
    )
    with pytest.raises(SingleUpdateRunSpecError):
        verify_test_single_update_run_spec(tampered)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("changed_fields", ("summary",)),
        ("google_event_id", ""),
        ("expected_etag", "*"),
    ),
)
def test_rehashed_operation_policy_tampering_is_rejected(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    run_spec = _spec(build_single_update_bundle(tmp_path))
    operation_provisional = run_spec.operation.model_copy(
        update={field: value, "operation_content_hash": "0" * 64}
    )
    operation = operation_provisional.model_copy(
        update={
            "operation_content_hash": calculate_test_single_update_operation_hash(
                operation_provisional
            )
        }
    )
    provisional = run_spec.model_copy(
        update={"operation": operation, "run_spec_content_hash": "0" * 64}
    )
    tampered = provisional.model_copy(
        update={"run_spec_content_hash": calculate_test_single_update_run_spec_hash(provisional)}
    )
    with pytest.raises(SingleUpdateRunSpecError):
        verify_test_single_update_run_spec(tampered)


def test_cross_artifact_mismatch_is_rejected(tmp_path: Path) -> None:
    first = build_single_update_bundle(tmp_path / "first")
    second = build_single_update_bundle(tmp_path / "second")
    run_spec = _spec(first)
    tampered_plan = second.plan.model_copy(update={"plan_content_hash": "f" * 64})

    with pytest.raises(SingleUpdatePlanError):
        verify_test_single_update_run_spec_bindings(
            run_spec,
            tampered_plan,
            first.baseline,
        )
    with pytest.raises(WriteSpecDispatchError):
        verify_any_test_write_run_spec(run_spec)


def test_rehashed_plan_provenance_tampering_fails_cross_binding(tmp_path: Path) -> None:
    bundle = build_single_update_bundle(tmp_path)
    run_spec = _spec(bundle)

    baseline_provisional = bundle.plan.model_copy(
        update={"baseline_hash": "f" * 64, "plan_content_hash": "0" * 64}
    )
    baseline_tampered = baseline_provisional.model_copy(
        update={"plan_content_hash": calculate_test_single_update_plan_hash(baseline_provisional)}
    )
    verify_test_single_update_plan(baseline_tampered)
    with pytest.raises(SingleUpdateRunSpecError) as baseline_error:
        verify_test_single_update_run_spec_bindings(
            run_spec,
            baseline_tampered,
            bundle.baseline,
        )
    assert baseline_error.value.code == "test_single_update_run_spec_binding_mismatch"

    snapshot_provisional = bundle.plan.model_copy(
        update={
            "baseline_snapshot_hash": "f" * 64,
            "snapshot_hash": "f" * 64,
            "plan_content_hash": "0" * 64,
        }
    )
    snapshot_tampered = snapshot_provisional.model_copy(
        update={"plan_content_hash": calculate_test_single_update_plan_hash(snapshot_provisional)}
    )
    verify_test_single_update_plan(snapshot_tampered)
    with pytest.raises(SingleUpdateRunSpecError) as snapshot_error:
        verify_test_single_update_run_spec_bindings(
            run_spec,
            snapshot_tampered,
            bundle.baseline,
        )
    assert snapshot_error.value.code == "trusted_baseline_snapshot_mismatch"


def test_valid_plan_with_alternate_run_spec_snapshot_fails_safe_binding(
    tmp_path: Path,
) -> None:
    bundle = build_single_update_bundle(tmp_path)
    run_spec = _spec(bundle)
    alternate = build_single_update_prewrite_snapshot(
        bundle.target,
        etag="fixture-etag-alternate-run-spec-snapshot",
    )
    assert alternate.snapshot_content_hash != run_spec.current_snapshot_hash
    provisional = run_spec.model_copy(
        update={
            "baseline_snapshot_hash": alternate.snapshot_content_hash,
            "current_snapshot_hash": alternate.snapshot_content_hash,
            "run_spec_content_hash": "0" * 64,
        }
    )
    forged = provisional.model_copy(
        update={"run_spec_content_hash": calculate_test_single_update_run_spec_hash(provisional)}
    )
    verify_test_single_update_run_spec(forged)

    with pytest.raises(SingleUpdateRunSpecError) as captured:
        verify_test_single_update_run_spec_bindings(
            forged,
            bundle.plan,
            bundle.baseline,
        )
    assert captured.value.code == "trusted_baseline_snapshot_mismatch"

    with pytest.raises(SingleUpdateRunSpecError) as approval_error:
        approval_challenge(
            forged,
            bundle.plan,
            bundle.baseline,
            current_snapshot_hash=forged.current_snapshot_hash,
            current_plan_hash=bundle.plan.plan_content_hash,
            current_baseline_hash=bundle.baseline.baseline_content_hash,
        )
    assert approval_error.value.code == "trusted_baseline_snapshot_mismatch"


def test_rehashed_run_spec_target_mismatch_fails_plan_binding(tmp_path: Path) -> None:
    bundle = build_single_update_bundle(tmp_path)
    run_spec = _spec(bundle)
    alternate_fingerprint = "c" * 64
    provisional = run_spec.model_copy(
        update={
            "target_fingerprint": alternate_fingerprint,
            "target_safe_ref": f"T-{alternate_fingerprint[:12]}",
            "run_spec_content_hash": "0" * 64,
        }
    )
    forged = provisional.model_copy(
        update={"run_spec_content_hash": calculate_test_single_update_run_spec_hash(provisional)}
    )
    verify_test_single_update_run_spec(forged)
    with pytest.raises(SingleUpdateRunSpecError) as captured:
        verify_test_single_update_run_spec_bindings(
            forged,
            bundle.plan,
            bundle.baseline,
        )
    assert captured.value.code == "test_single_update_run_spec_binding_mismatch"


def test_builder_rejects_source_snapshot_baseline_or_target_mismatch(tmp_path: Path) -> None:
    bundle = build_single_update_bundle(tmp_path)
    cases = (
        {
            "source": bundle.current_source,
            "snapshot": bundle.prewrite_snapshot,
            "baseline": bundle.baseline,
            "target": bundle.target,
        },
        {
            "source": bundle.updated_source,
            "snapshot": bundle.prewrite_snapshot.model_copy(
                update={"snapshot_content_hash": "f" * 64}
            ),
            "baseline": bundle.baseline,
            "target": bundle.target,
        },
        {
            "source": bundle.updated_source,
            "snapshot": bundle.prewrite_snapshot,
            "baseline": bundle.baseline.model_copy(update={"baseline_content_hash": "f" * 64}),
            "target": bundle.target,
        },
        {
            "source": bundle.updated_source,
            "snapshot": bundle.prewrite_snapshot,
            "baseline": bundle.baseline,
            "target": bundle.target.model_copy(update={"target_label": "production"}),
        },
    )
    for case in cases:
        with pytest.raises(
            (
                SingleUpdateRunSpecError,
                SingleUpdatePlanError,
                CalendarPrewriteError,
                TargetPolicyError,
                BaselineValidationError,
            )
        ):
            build_test_single_update_run_spec(
                bundle.updated_profile,
                case["source"],
                case["snapshot"],
                bundle.plan,
                case["baseline"],
                case["target"],
            )


def test_exact_approval_and_union_dispatch_preserve_existing_phrase(tmp_path: Path) -> None:
    bundle = build_single_update_bundle(tmp_path)
    run_spec = _spec(bundle)
    kwargs = _challenge_kwargs(bundle)
    direct = approval_challenge(
        run_spec,
        bundle.plan,
        bundle.baseline,
        **kwargs,
    )
    dispatched = any_test_write_approval_challenge(
        run_spec,
        single_update_plan=bundle.plan,
        trusted_baseline=bundle.baseline,
        **kwargs,
    )

    assert direct == dispatched
    assert direct == (
        f"AUTHORIZE TEST CALENDAR WRITE {run_spec.target_safe_ref} "
        f"R-{run_spec.run_spec_content_hash[:12]} A-0 U-1"
    )
    assert (
        approve_test_single_update_run_spec(
            run_spec,
            bundle.plan,
            bundle.baseline,
            direct,
            **kwargs,
        )
        is run_spec
    )
    assert (
        approve_any_test_write_run_spec(
            run_spec,
            direct,
            single_update_plan=bundle.plan,
            trusted_baseline=bundle.baseline,
            **kwargs,
        )
        is run_spec
    )


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value + " ",
        lambda value: value.lower(),
        lambda value: value.replace("A-0", "A-1"),
        lambda value: value.replace("U-1", "U-0"),
        lambda value: value.replace("R-", "R-f"),
        lambda value: value.replace("T-", "T-f"),
    ),
)
def test_approval_rejects_every_nonexact_confirmation(
    tmp_path: Path,
    mutation: Callable[[str], str],
) -> None:
    bundle = build_single_update_bundle(tmp_path)
    run_spec = _spec(bundle)
    kwargs = _challenge_kwargs(bundle)
    challenge = approval_challenge(
        run_spec,
        bundle.plan,
        bundle.baseline,
        **kwargs,
    )
    with pytest.raises(SingleUpdateApprovalError):
        approve_test_single_update_run_spec(
            run_spec,
            bundle.plan,
            bundle.baseline,
            mutation(challenge),
            **kwargs,
        )


@pytest.mark.parametrize(
    "field",
    (
        "current_snapshot_hash",
        "current_plan_hash",
        "current_baseline_hash",
    ),
)
def test_approval_rejects_stale_bound_artifact_hash(
    tmp_path: Path,
    field: str,
) -> None:
    bundle = build_single_update_bundle(tmp_path)
    run_spec = _spec(bundle)
    kwargs = _challenge_kwargs(bundle)
    kwargs[field] = "f" * 64
    with pytest.raises(SingleUpdateApprovalError):
        approval_challenge(
            run_spec,
            bundle.plan,
            bundle.baseline,
            **kwargs,
        )


def test_production_reference_cannot_generate_approval(tmp_path: Path) -> None:
    bundle = build_single_update_bundle(tmp_path)
    run_spec = _spec(bundle)
    production = run_spec.model_copy(update={"target_safe_ref": PRODUCTION_TARGET_REFERENCE})
    with pytest.raises(SingleUpdateRunSpecError):
        approval_challenge(
            production,
            bundle.plan,
            bundle.baseline,
            **_challenge_kwargs(bundle),
        )


def test_private_run_spec_io_is_repository_external_and_no_overwrite(
    tmp_path: Path,
) -> None:
    run_spec = _spec(build_single_update_bundle(tmp_path))
    output = tmp_path / "fixture.test-single-update-run-spec.json"
    write_test_single_update_run_spec(run_spec, output)
    assert load_test_single_update_run_spec(output) == run_spec
    with pytest.raises(SingleUpdateRunSpecIOError):
        write_test_single_update_run_spec(run_spec, output)
    with pytest.raises(SingleUpdateRunSpecIOError):
        write_test_single_update_run_spec(
            run_spec,
            REPOSITORY_ROOT / "must-not-write.test-single-update-run-spec.json",
        )
