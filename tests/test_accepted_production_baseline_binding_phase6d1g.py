from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from conftest import clear_phase6d1g_active_accepted_baseline_pin
from phase6b_helpers import build_production_planning_inputs

from tridentine_calendar_google_sync import cli
from tridentine_calendar_google_sync.baseline_engine import calculate_baseline_content_hash
from tridentine_calendar_google_sync.baseline_models import TrustedBaseline
from tridentine_calendar_google_sync.production_approval_material import (
    production_approval_material_data,
)
from tridentine_calendar_google_sync.production_single_update_plan import (
    ProductionSingleUpdatePlanError,
    build_production_single_update_plan,
    calculate_production_single_update_plan_hash,
    verify_production_single_update_plan,
    verify_production_single_update_plan_accepted_baseline,
)
from tridentine_calendar_google_sync.production_single_update_plan_io import (
    ProductionSingleUpdatePlanIOError,
    parse_production_single_update_plan_bytes,
    render_production_single_update_plan_json,
)
from tridentine_calendar_google_sync.production_single_update_run_spec import (
    build_production_single_update_run_spec,
)
from tridentine_calendar_google_sync.production_single_update_run_spec_io import (
    ProductionSingleUpdateRunSpecIOError,
    parse_production_single_update_run_spec_bytes,
    render_production_single_update_run_spec_json,
)
from tridentine_calendar_google_sync.production_write_target import (
    calculate_production_write_target_hash,
)

ISSUED_AT = datetime(2099, 1, 1, 12, 0, tzinfo=UTC)


def _rehash_baseline(baseline: TrustedBaseline, **updates: object) -> TrustedBaseline:
    provisional = baseline.model_copy(update={**updates, "baseline_content_hash": "0" * 64})
    return provisional.model_copy(
        update={"baseline_content_hash": calculate_baseline_content_hash(provisional)}
    )


def _plan(inputs: Any) -> Any:
    return build_production_single_update_plan(
        inputs.manifest,
        inputs.updated.profile,
        inputs.updated.source,
        inputs.snapshot,
        inputs.baseline,
        inputs.target,
    )


def test_plan_run_spec_and_approval_material_bind_exact_active_pin(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    plan = _plan(inputs)
    run_spec = build_production_single_update_run_spec(
        inputs.manifest,
        inputs.updated.profile,
        inputs.updated.source,
        inputs.snapshot,
        plan,
        inputs.baseline,
        inputs.target,
        issued_at=ISSUED_AT,
    )
    pin = inputs.accepted_baseline_pin

    assert plan.schema_version == "2.0"
    assert plan.accepted_baseline_pin_id == pin.pin_id
    assert plan.accepted_baseline_generation == pin.generation
    assert plan.accepted_baseline_pin_hash == pin.pin_content_hash
    assert run_spec.schema_version == "2.0"
    assert run_spec.run_type == "production-single-update-run-spec-v2"
    assert run_spec.accepted_baseline_pin_id == pin.pin_id
    assert run_spec.accepted_baseline_generation == pin.generation
    assert run_spec.accepted_baseline_pin_hash == pin.pin_content_hash
    material = production_approval_material_data(run_spec)
    assert material["accepted_baseline_pin_id"] == pin.pin_id
    assert material["accepted_baseline_generation"] == pin.generation
    assert material["accepted_baseline_pin_hash"] == pin.pin_content_hash


def test_directly_rehashed_trusted_baseline_cannot_build_plan_under_other_active_pin(
    tmp_path: Path,
) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    forged = _rehash_baseline(inputs.baseline, source_sha256="9" * 64)

    with pytest.raises(ProductionSingleUpdatePlanError) as captured:
        build_production_single_update_plan(
            inputs.manifest,
            inputs.updated.profile,
            inputs.updated.source,
            inputs.snapshot,
            forged,
            inputs.target,
        )
    assert captured.value.code == "production_single_update_accepted_baseline_binding_invalid"


def test_rehashed_plan_pin_claim_needs_current_package_authority(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    plan = _plan(inputs)
    provisional = plan.model_copy(
        update={
            "accepted_baseline_pin_hash": "f" * 64,
            "plan_content_hash": "0" * 64,
        }
    )
    forged = provisional.model_copy(
        update={"plan_content_hash": calculate_production_single_update_plan_hash(provisional)}
    )

    verify_production_single_update_plan(forged)
    with pytest.raises(ProductionSingleUpdatePlanError) as captured:
        verify_production_single_update_plan_accepted_baseline(forged)
    assert captured.value.code == "production_single_update_accepted_baseline_binding_invalid"


def test_cli_empty_packaged_registry_stops_before_private_inputs(
    monkeypatch: pytest.MonkeyPatch,
    capsys: Any,
) -> None:
    clear_phase6d1g_active_accepted_baseline_pin()
    touched = 0

    def forbidden(*_args: object, **_kwargs: object) -> Any:
        nonlocal touched
        touched += 1
        raise AssertionError("private Production input was read before active pin")

    monkeypatch.setattr(cli, "load_accepted_production_source_manifest", forbidden)
    monkeypatch.setattr(cli, "load_profile", forbidden)
    monkeypatch.setattr(cli, "inspect_source", forbidden)
    monkeypatch.setattr(cli, "load_google_snapshot", forbidden)
    monkeypatch.setattr(cli, "load_baseline", forbidden)
    monkeypatch.setattr(cli, "load_production_write_target_config", forbidden)

    result = cli.main(
        [
            "build-production-single-update-plan",
            "--manifest",
            "private-manifest.json",
            "--source",
            "private-source.ics",
            "--profile",
            "accepted-20990101",
            "--profiles-dir",
            "private-profiles",
            "--google-snapshot",
            "private-snapshot.json",
            "--trusted-baseline",
            "private-baseline.json",
            "--target-config",
            "private-target.toml",
            "--output",
            "private-plan.json",
        ]
    )

    captured = capsys.readouterr()
    assert result == cli.EXIT_FATAL_GUARD
    assert touched == 0
    assert "No Accepted Production baseline pin is active" in captured.err
    assert "private-" not in captured.err


def test_target_config_hash_remains_plan_local_not_baseline_registry_authority(
    tmp_path: Path,
) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    plan = _plan(inputs)

    assert plan.target_config_hash == calculate_production_write_target_hash(inputs.target)
    assert "target_config_hash" not in type(inputs.accepted_baseline_pin).model_fields


def test_v1_plan_and_run_spec_shapes_are_not_silently_migrated(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    plan = _plan(inputs)
    run_spec = build_production_single_update_run_spec(
        inputs.manifest,
        inputs.updated.profile,
        inputs.updated.source,
        inputs.snapshot,
        plan,
        inputs.baseline,
        inputs.target,
        issued_at=ISSUED_AT,
    )

    plan_document = json.loads(render_production_single_update_plan_json(plan))
    plan_document["schema_version"] = "1.0"
    for field in (
        "accepted_baseline_pin_id",
        "accepted_baseline_generation",
        "accepted_baseline_pin_hash",
    ):
        plan_document.pop(field)
    old_plan = (json.dumps(plan_document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    with pytest.raises(ProductionSingleUpdatePlanIOError):
        parse_production_single_update_plan_bytes(old_plan)

    run_document = json.loads(
        render_production_single_update_run_spec_json(run_spec, now=ISSUED_AT)
    )
    run_document["schema_version"] = "1.0"
    run_document["run_type"] = "production-single-update-run-spec-v1"
    for field in (
        "accepted_baseline_pin_id",
        "accepted_baseline_generation",
        "accepted_baseline_pin_hash",
    ):
        run_document.pop(field)
    old_run = (json.dumps(run_document, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    with pytest.raises(ProductionSingleUpdateRunSpecIOError):
        parse_production_single_update_run_spec_bytes(old_run, now=ISSUED_AT)
