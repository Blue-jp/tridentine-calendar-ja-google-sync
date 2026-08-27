from __future__ import annotations

import json
from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from conftest import REPOSITORY_ROOT
from phase6b_helpers import build_production_planning_inputs

from tridentine_calendar_google_sync.production_approval_material import (
    calculate_production_approval_material_hash,
    production_approval_material_data,
    verify_production_approval_material_hash,
)
from tridentine_calendar_google_sync.production_single_update_plan import (
    build_production_single_update_plan,
)
from tridentine_calendar_google_sync.production_single_update_run_spec import (
    ProductionSingleUpdateRunSpecError,
    build_production_single_update_run_spec,
    calculate_production_single_update_operation_hash,
    calculate_production_single_update_run_spec_hash,
    verify_production_single_update_run_spec,
    verify_production_single_update_run_spec_bindings,
)
from tridentine_calendar_google_sync.production_single_update_run_spec_io import (
    ProductionSingleUpdateRunSpecIOError,
    load_production_single_update_run_spec,
    parse_production_single_update_run_spec_bytes,
    render_production_single_update_run_spec_json,
    write_production_single_update_run_spec,
)
from tridentine_calendar_google_sync.production_single_update_run_spec_models import (
    PRODUCTION_RUN_SPEC_MAX_LIFETIME_SECONDS,
    ProductionSingleUpdateOperation,
    ProductionSingleUpdateRunSpec,
)
from tridentine_calendar_google_sync.production_single_update_run_spec_report import (
    build_production_single_update_run_spec_inspection,
    render_production_single_update_run_spec_inspection_json,
    render_production_single_update_run_spec_inspection_text,
)
from tridentine_calendar_google_sync.test_write_spec_dispatch import (
    TestWriteSpecDispatchError as WriteSpecDispatchError,
)
from tridentine_calendar_google_sync.test_write_spec_dispatch import (
    verify_any_test_write_run_spec,
)
from tridentine_calendar_google_sync.test_write_transport import run_test_calendar_write

ISSUED_AT = datetime(2099, 1, 1, 12, 0, tzinfo=UTC)


def _plan(inputs: Any) -> Any:
    return build_production_single_update_plan(
        inputs.manifest,
        inputs.updated.profile,
        inputs.updated.source,
        inputs.snapshot,
        inputs.baseline,
        inputs.target,
    )


def _run_spec(inputs: Any, *, expires_at: datetime | None = None) -> Any:
    plan = _plan(inputs)
    return build_production_single_update_run_spec(
        inputs.manifest,
        inputs.updated.profile,
        inputs.updated.source,
        inputs.snapshot,
        plan,
        inputs.baseline,
        inputs.target,
        issued_at=ISSUED_AT,
        expires_at=expires_at,
    )


def _rehash_run_spec(
    run_spec: ProductionSingleUpdateRunSpec,
    *,
    updates: Mapping[str, object] | None = None,
    operation: ProductionSingleUpdateOperation | None = None,
) -> ProductionSingleUpdateRunSpec:
    provisional = run_spec.model_copy(
        update={
            **dict(updates or {}),
            **({"operation": operation} if operation is not None else {}),
            "approval_material_hash": "0" * 64,
            "run_spec_content_hash": "0" * 64,
        }
    )
    with_run_hash = provisional.model_copy(
        update={
            "run_spec_content_hash": calculate_production_single_update_run_spec_hash(provisional)
        }
    )
    return with_run_hash.model_copy(
        update={
            "approval_material_hash": calculate_production_approval_material_hash(with_run_hash)
        }
    )


def _different(value: object) -> object:
    if isinstance(value, bool):
        return not value
    if isinstance(value, datetime):
        return value + timedelta(microseconds=1)
    if isinstance(value, int):
        return value + 1
    if isinstance(value, str):
        replacement = "f" if not value.endswith("f") else "e"
        return value[:-1] + replacement if value else replacement
    if isinstance(value, tuple):
        return (*value, "changed")
    raise TypeError(f"No bit-change fixture for {type(value)!r}")


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value) | set().union(*(_all_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value))
    return set()


def test_valid_run_spec_is_short_lived_non_executable_and_exactly_bound(
    tmp_path: Path,
) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    plan = _plan(inputs)
    run_spec = _run_spec(inputs)

    assert run_spec.run_type == "production-single-update-run-spec-v1"
    assert run_spec.production is True
    assert run_spec.production_only is True
    assert run_spec.synthetic is False
    assert run_spec.executable is False
    assert run_spec.issued_at == ISSUED_AT
    assert run_spec.expires_at == ISSUED_AT + timedelta(
        seconds=PRODUCTION_RUN_SPEC_MAX_LIFETIME_SECONDS
    )
    assert run_spec.production_plan_hash == plan.plan_content_hash
    assert run_spec.trusted_baseline_hash == inputs.baseline.baseline_content_hash
    assert run_spec.manifest_hash == inputs.manifest.manifest_content_hash
    assert run_spec.current_snapshot_hash == inputs.snapshot.content_hash
    assert (run_spec.operation_count, run_spec.add_count, run_spec.update_count) == (1, 0, 1)
    assert run_spec.delete_count == 0
    assert run_spec.changed_fields == ("description",)
    assert run_spec.operation.operation == "update"
    assert run_spec.operation.safe_uid_ref == plan.safe_uid_ref
    assert run_spec.operation.google_ref == plan.google_ref
    assert run_spec.operation.pre_image_hash == plan.pre_image_hash
    assert run_spec.operation.patch_hash == plan.patch_hash
    assert (
        calculate_production_single_update_operation_hash(run_spec.operation)
        == run_spec.operation.operation_content_hash
    )
    assert calculate_production_single_update_run_spec_hash(run_spec) == (
        run_spec.run_spec_content_hash
    )
    assert calculate_production_approval_material_hash(run_spec) == (
        run_spec.approval_material_hash
    )
    verify_production_single_update_run_spec(run_spec, now=ISSUED_AT)
    verify_production_single_update_run_spec_bindings(run_spec, plan, now=ISSUED_AT)
    verify_production_approval_material_hash(run_spec)


def test_lifetime_boundaries_are_exact_and_expiry_is_fail_closed(tmp_path: Path) -> None:
    run_spec = _run_spec(build_production_planning_inputs(tmp_path))

    verify_production_single_update_run_spec(run_spec, now=run_spec.issued_at)
    verify_production_single_update_run_spec(
        run_spec,
        now=run_spec.expires_at - timedelta(microseconds=1),
    )
    with pytest.raises(ProductionSingleUpdateRunSpecError) as not_yet:
        verify_production_single_update_run_spec(
            run_spec,
            now=run_spec.issued_at - timedelta(microseconds=1),
        )
    assert not_yet.value.code == "production_single_update_not_yet_valid"
    with pytest.raises(ProductionSingleUpdateRunSpecError) as expired:
        verify_production_single_update_run_spec(run_spec, now=run_spec.expires_at)
    assert expired.value.code == "production_single_update_expired"


def test_explicit_short_lifetime_is_allowed_but_zero_extended_or_non_utc_is_rejected(
    tmp_path: Path,
) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    short = _run_spec(inputs, expires_at=ISSUED_AT + timedelta(minutes=15))
    verify_production_single_update_run_spec(
        short,
        now=short.expires_at - timedelta(microseconds=1),
    )

    for expiry in (
        ISSUED_AT,
        ISSUED_AT + timedelta(seconds=PRODUCTION_RUN_SPEC_MAX_LIFETIME_SECONDS + 1),
    ):
        with pytest.raises(ValueError):
            _run_spec(inputs, expires_at=expiry)

    naive = ISSUED_AT.replace(tzinfo=None)
    non_utc = ISSUED_AT.astimezone(tz=timezone(timedelta(hours=9)))
    for issue_time in (naive, non_utc):
        plan = _plan(inputs)
        with pytest.raises(ProductionSingleUpdateRunSpecError) as captured:
            build_production_single_update_run_spec(
                inputs.manifest,
                inputs.updated.profile,
                inputs.updated.source,
                inputs.snapshot,
                plan,
                inputs.baseline,
                inputs.target,
                issued_at=issue_time,
            )
        assert captured.value.code == "production_single_update_clock_invalid"


def test_run_spec_is_deterministic_schema_valid_and_canonical(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    first = _run_spec(inputs)
    second = _run_spec(inputs)
    rendered = render_production_single_update_run_spec_json(first, now=ISSUED_AT)

    assert first == second
    assert (
        parse_production_single_update_run_spec_bytes(
            rendered.encode("utf-8"),
            now=ISSUED_AT,
        )
        == first
    )
    schema = json.loads(
        (
            REPOSITORY_ROOT / "schemas" / "production-single-update-run-spec-v1.schema.json"
        ).read_text(encoding="utf-8")
    )
    document = json.loads(rendered)
    jsonschema.validate(document, schema)
    assert schema["additionalProperties"] is False
    assert schema["properties"]["operation"]["additionalProperties"] is False


def test_run_spec_and_reports_contain_no_raw_identity_text_or_transport_values(
    tmp_path: Path,
) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    run_spec = _run_spec(inputs)
    rendered = render_production_single_update_run_spec_json(run_spec, now=ISSUED_AT)
    document = json.loads(rendered)
    reports = (
        json.dumps(
            build_production_single_update_run_spec_inspection(run_spec, now=ISSUED_AT),
            ensure_ascii=False,
        ),
        render_production_single_update_run_spec_inspection_json(run_spec, now=ISSUED_AT),
        render_production_single_update_run_spec_inspection_text(run_spec, now=ISSUED_AT),
    )
    source_event = inputs.updated.source.events[-1]
    google_event = inputs.snapshot.events[-1]

    forbidden_keys = {
        "uid",
        "icaluid",
        "summary",
        "description",
        "current_state",
        "desired_state",
        "calendar_id",
        "google_event_id",
        "event_id",
        "etag",
        "payload",
        "endpoint",
        "http_method",
    }
    assert {key.casefold() for key in _all_keys(document)}.isdisjoint(forbidden_keys)
    for forbidden in (
        source_event.uid,
        source_event.summary,
        source_event.description,
        inputs.target.calendar_id,
        google_event.event_id,
        google_event.etag,
    ):
        assert forbidden is not None
        assert forbidden not in rendered
        assert forbidden not in repr(run_spec)
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


def test_approval_material_hash_changes_for_every_approved_run_spec_field(
    tmp_path: Path,
) -> None:
    run_spec = _run_spec(build_production_planning_inputs(tmp_path))
    original_hash = calculate_production_approval_material_hash(run_spec)
    material = production_approval_material_data(run_spec)
    expected_top_level = set(ProductionSingleUpdateRunSpec.model_fields) - {
        "approval_material_hash"
    }
    assert set(material) == expected_top_level

    for field_name in sorted(expected_top_level - {"operation"}):
        changed = run_spec.model_copy(
            update={field_name: _different(getattr(run_spec, field_name))}
        )
        assert calculate_production_approval_material_hash(changed) != original_hash, field_name

    operation_material = material["operation"]
    assert isinstance(operation_material, dict)
    assert set(operation_material) == set(ProductionSingleUpdateOperation.model_fields)
    for field_name in sorted(ProductionSingleUpdateOperation.model_fields):
        changed_operation = run_spec.operation.model_copy(
            update={field_name: _different(getattr(run_spec.operation, field_name))}
        )
        changed = run_spec.model_copy(update={"operation": changed_operation})
        assert calculate_production_approval_material_hash(changed) != original_hash, field_name


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("run_type", "test-calendar-write-run-spec-v1"),
        ("production", False),
        ("production_only", False),
        ("synthetic", True),
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
    run_spec = _run_spec(build_production_planning_inputs(tmp_path))
    tampered = _rehash_run_spec(run_spec, updates={field: value})

    with pytest.raises(ProductionSingleUpdateRunSpecError):
        verify_production_single_update_run_spec(tampered, now=ISSUED_AT)


def test_operation_and_approval_hash_tampering_are_rejected(tmp_path: Path) -> None:
    run_spec = _run_spec(build_production_planning_inputs(tmp_path))
    operation = run_spec.operation.model_copy(update={"operation_content_hash": "f" * 64})
    bad_operation = run_spec.model_copy(update={"operation": operation})
    with pytest.raises(ProductionSingleUpdateRunSpecError) as operation_error:
        verify_production_single_update_run_spec(bad_operation, now=ISSUED_AT)
    assert operation_error.value.code == "production_single_update_operation_hash_mismatch"

    bad_approval = run_spec.model_copy(update={"approval_material_hash": "f" * 64})
    with pytest.raises(ProductionSingleUpdateRunSpecError) as approval_error:
        verify_production_single_update_run_spec(bad_approval, now=ISSUED_AT)
    assert approval_error.value.code == "production_approval_material_hash_mismatch"


def test_rehashed_cross_artifact_mismatch_fails_binding(tmp_path: Path) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    plan = _plan(inputs)
    run_spec = _run_spec(inputs)
    forged = _rehash_run_spec(run_spec, updates={"target_config_hash": "f" * 64})

    verify_production_single_update_run_spec(forged, now=ISSUED_AT)
    with pytest.raises(ProductionSingleUpdateRunSpecError) as captured:
        verify_production_single_update_run_spec_bindings(forged, plan, now=ISSUED_AT)
    assert captured.value.code == "production_single_update_run_spec_binding_mismatch"


def test_run_spec_io_is_repository_external_atomic_expiry_aware_and_no_overwrite(
    tmp_path: Path,
) -> None:
    run_spec = _run_spec(build_production_planning_inputs(tmp_path))
    output = tmp_path / "phase6b.production-single-update-run-spec.json"

    write_production_single_update_run_spec(run_spec, output, now=ISSUED_AT)
    assert load_production_single_update_run_spec(output, now=ISSUED_AT) == run_spec
    with pytest.raises(ProductionSingleUpdateRunSpecIOError):
        write_production_single_update_run_spec(run_spec, output, now=ISSUED_AT)
    with pytest.raises(ProductionSingleUpdateRunSpecIOError):
        write_production_single_update_run_spec(
            run_spec,
            REPOSITORY_ROOT / "must-not-write.production-single-update-run-spec.json",
            now=ISSUED_AT,
        )
    with pytest.raises(ProductionSingleUpdateRunSpecError) as expired:
        load_production_single_update_run_spec(
            output,
            now=run_spec.expires_at,
        )
    assert expired.value.code == "production_single_update_expired"
    historical = load_production_single_update_run_spec(
        output,
        now=run_spec.expires_at,
        require_current=False,
    )
    report = build_production_single_update_run_spec_inspection(
        historical,
        now=run_spec.expires_at,
    )
    assert report["temporal_state"] == "expired"
    assert report["expired"] is True


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
def test_run_spec_parser_rejects_tampered_unknown_duplicate_or_noncanonical_json(
    tmp_path: Path,
    mutate: Callable[[bytes], bytes],
) -> None:
    rendered = render_production_single_update_run_spec_json(
        _run_spec(build_production_planning_inputs(tmp_path)),
        now=ISSUED_AT,
    ).encode("utf-8")
    with pytest.raises(ProductionSingleUpdateRunSpecIOError):
        parse_production_single_update_run_spec_bytes(mutate(rendered), now=ISSUED_AT)


class _ClientMustRemainUntouched:
    def __init__(self) -> None:
        self.calls = 0

    def __getattribute__(self, name: str) -> Any:
        if name not in {"calls", "__dict__", "__class__"}:
            object.__setattr__(self, "calls", object.__getattribute__(self, "calls") + 1)
            raise AssertionError("Production Run Spec touched the Test Google client")
        return object.__getattribute__(self, name)


def test_existing_test_write_dispatch_keeps_production_hard_locked_with_client_zero(
    tmp_path: Path,
) -> None:
    inputs = build_production_planning_inputs(tmp_path)
    run_spec = _run_spec(inputs)
    client = _ClientMustRemainUntouched()

    with pytest.raises(WriteSpecDispatchError) as direct:
        verify_any_test_write_run_spec(run_spec)  # type: ignore[arg-type]
    assert direct.value.code == "unknown_test_write_run_spec_type"
    with pytest.raises(WriteSpecDispatchError):
        run_test_calendar_write(  # type: ignore[arg-type]
            run_spec,
            inputs.target,
            client,
            "not-authority",
            current_snapshot_hash=run_spec.current_snapshot_hash,
            current_plan_hash=run_spec.production_plan_hash,
            current_baseline_hash=run_spec.trusted_baseline_hash,
        )
    assert client.calls == 0
