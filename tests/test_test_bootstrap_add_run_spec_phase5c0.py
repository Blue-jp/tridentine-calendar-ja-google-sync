from __future__ import annotations

import json
import os
from pathlib import Path

import jsonschema
import pytest
from conftest import REPOSITORY_ROOT
from phase5c0_helpers import BOOTSTRAP_SUMMARY, BOOTSTRAP_UID, build_bootstrap_bundle

from tridentine_calendar_google_sync.test_bootstrap_plan import (
    TestBootstrapPlanError as BootstrapError,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec import (
    TestBootstrapRunSpecError as RunSpecError,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec import (
    build_test_bootstrap_add_run_spec,
    calculate_test_bootstrap_add_operation_hash,
    calculate_test_bootstrap_add_run_spec_hash,
    private_test_bootstrap_add_run_spec_data,
    verify_test_bootstrap_add_run_spec,
    verify_test_bootstrap_add_run_spec_plan,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec_io import (
    TestBootstrapRunSpecIOError as RunSpecIOError,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec_io import (
    load_test_bootstrap_add_run_spec,
    parse_test_bootstrap_add_run_spec_bytes,
    render_test_bootstrap_add_run_spec_json,
    write_test_bootstrap_add_run_spec,
)
from tridentine_calendar_google_sync.test_calendar_prewrite import (
    TestCalendarPrewriteError as PrewriteError,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteOperationKind as OperationKind,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetPolicyError as TargetPolicyError,
)


def _run_spec(tmp_path: Path):
    bundle = build_bootstrap_bundle(tmp_path)
    run_spec = build_test_bootstrap_add_run_spec(
        bundle.profile,
        bundle.source,
        bundle.prewrite_snapshot,
        bundle.plan,
        bundle.target,
    )
    return bundle, run_spec


def test_valid_bootstrap_run_spec_has_exact_discriminator_and_add_only_shape(
    tmp_path: Path,
) -> None:
    bundle, run_spec = _run_spec(tmp_path)

    assert run_spec.run_type == "test-bootstrap-add-run-spec-v1"
    assert run_spec.planning_mode == "test_bootstrap_add"
    assert run_spec.bootstrap_add is True
    assert run_spec.test_only is True
    assert run_spec.production_locked is True
    assert run_spec.target_environment == "test"
    assert run_spec.source_event_count == 1
    assert run_spec.snapshot_event_count == 0
    assert run_spec.trusted_baseline_hash is None
    assert run_spec.bootstrap_plan_hash == bundle.plan.plan_content_hash
    assert run_spec.current_snapshot_hash == bundle.plan.snapshot_hash
    assert (
        run_spec.operation_count,
        run_spec.add_count,
        run_spec.update_count,
        run_spec.delete_count,
    ) == (
        1,
        1,
        0,
        0,
    )
    assert run_spec.operation.operation is OperationKind.ADD
    assert run_spec.operation.google_ref is None
    assert run_spec.operation.current_state is None
    assert run_spec.operation.google_event_id is None
    assert run_spec.operation.expected_etag is None
    verify_test_bootstrap_add_run_spec(run_spec)
    verify_test_bootstrap_add_run_spec_plan(run_spec, bundle.plan)


def test_run_spec_is_deterministic_hash_bound_and_schema_valid(tmp_path: Path) -> None:
    _first_bundle, first = _run_spec(tmp_path)
    _second_bundle, second = _run_spec(tmp_path)
    document = private_test_bootstrap_add_run_spec_data(first)
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "test-bootstrap-add-run-spec-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )

    assert first == second
    assert calculate_test_bootstrap_add_operation_hash(first.operation) == (
        first.operation.operation_content_hash
    )
    assert calculate_test_bootstrap_add_run_spec_hash(first) == first.run_spec_content_hash
    jsonschema.validate(document, schema)


@pytest.mark.parametrize(
    "updates",
    (
        {"planning_mode": "normal_sync_plan"},
        {"bootstrap_add": False},
        {"test_only": False},
        {"production_locked": False},
        {"target_environment": "production"},
        {"snapshot_event_count": 1},
        {"trusted_baseline_hash": "f" * 64},
        {"operation_count": 0},
        {"operation_count": 2},
        {"add_count": 0},
        {"update_count": 1},
        {"delete_count": 1},
    ),
)
def test_rehashed_run_spec_fixed_policy_tampering_is_rejected(
    tmp_path: Path,
    updates: dict[str, object],
) -> None:
    _bundle, run_spec = _run_spec(tmp_path)
    provisional = run_spec.model_copy(update={**updates, "run_spec_content_hash": "0" * 64})
    forged = provisional.model_copy(
        update={"run_spec_content_hash": calculate_test_bootstrap_add_run_spec_hash(provisional)}
    )

    with pytest.raises(RunSpecError):
        verify_test_bootstrap_add_run_spec(forged)


@pytest.mark.parametrize(
    "operation_updates",
    (
        {"operation": OperationKind.UPDATE},
        {"changed_fields": ("summary",)},
    ),
)
def test_rehashed_operation_update_or_partial_fields_cannot_be_injected(
    tmp_path: Path,
    operation_updates: dict[str, object],
) -> None:
    _bundle, run_spec = _run_spec(tmp_path)
    operation_provisional = run_spec.operation.model_copy(
        update={**operation_updates, "operation_content_hash": "0" * 64}
    )
    operation = operation_provisional.model_copy(
        update={
            "operation_content_hash": calculate_test_bootstrap_add_operation_hash(
                operation_provisional
            )
        }
    )
    provisional = run_spec.model_copy(
        update={"operation": operation, "run_spec_content_hash": "0" * 64}
    )
    forged = provisional.model_copy(
        update={"run_spec_content_hash": calculate_test_bootstrap_add_run_spec_hash(provisional)}
    )

    with pytest.raises(RunSpecError):
        verify_test_bootstrap_add_run_spec(forged)


def test_plan_tamper_and_cross_artifact_mismatch_are_rejected(tmp_path: Path) -> None:
    bundle, run_spec = _run_spec(tmp_path)
    tampered_plan = bundle.plan.model_copy(update={"plan_content_hash": "f" * 64})
    mismatched = run_spec.model_copy(update={"bootstrap_plan_hash": "e" * 64})

    with pytest.raises(BootstrapError):
        verify_test_bootstrap_add_run_spec_plan(run_spec, tampered_plan)
    with pytest.raises(RunSpecError):
        verify_test_bootstrap_add_run_spec_plan(mismatched, bundle.plan)


@pytest.mark.parametrize(
    "mismatch",
    ("source", "snapshot", "target"),
)
def test_builder_recomputes_and_rejects_source_snapshot_or_target_mismatch(
    tmp_path: Path,
    mismatch: str,
) -> None:
    bundle = build_bootstrap_bundle(tmp_path)
    source = bundle.source
    snapshot = bundle.prewrite_snapshot
    target = bundle.target
    if mismatch == "source":
        source = source.model_copy(update={"raw_sha256": "f" * 64})
    elif mismatch == "snapshot":
        snapshot = snapshot.model_copy(update={"snapshot_content_hash": "f" * 64})
    else:
        target = target.model_copy(update={"expected_target_fingerprint": "f" * 64})

    with pytest.raises((RunSpecError, BootstrapError, PrewriteError, TargetPolicyError)):
        build_test_bootstrap_add_run_spec(
            bundle.profile,
            source,
            snapshot,
            bundle.plan,
            target,
        )


def test_run_spec_private_json_roundtrip_no_overwrite_and_repository_guard(
    tmp_path: Path,
) -> None:
    _bundle, run_spec = _run_spec(tmp_path)
    rendered = render_test_bootstrap_add_run_spec_json(run_spec)
    output = tmp_path / "fixture.test-bootstrap-add-run-spec.json"

    assert parse_test_bootstrap_add_run_spec_bytes(rendered.encode("utf-8")) == run_spec
    write_test_bootstrap_add_run_spec(run_spec, output)
    assert load_test_bootstrap_add_run_spec(output) == run_spec
    with pytest.raises(RunSpecIOError):
        write_test_bootstrap_add_run_spec(run_spec, output)
    with pytest.raises(RunSpecIOError):
        write_test_bootstrap_add_run_spec(
            run_spec,
            REPOSITORY_ROOT / "forbidden.test-bootstrap-add-run-spec.json",
        )


def test_run_spec_parser_rejects_unknown_duplicate_and_tamper(tmp_path: Path) -> None:
    _bundle, run_spec = _run_spec(tmp_path)
    document = private_test_bootstrap_add_run_spec_data(run_spec)
    unknown = {**document, "expected_etag": "fixture-forbidden"}
    with pytest.raises(RunSpecIOError):
        parse_test_bootstrap_add_run_spec_bytes(json.dumps(unknown).encode("utf-8"))

    duplicate = render_test_bootstrap_add_run_spec_json(run_spec).replace(
        '"schema_version": "1.0",',
        '"schema_version": "1.0",\n  "schema_version": "1.0",',
        1,
    )
    with pytest.raises(RunSpecIOError):
        parse_test_bootstrap_add_run_spec_bytes(duplicate.encode("utf-8"))

    tampered = dict(document)
    tampered["source_sha256"] = "f" * 64
    with pytest.raises(RunSpecError):
        parse_test_bootstrap_add_run_spec_bytes(json.dumps(tampered).encode("utf-8"))


def test_symlink_run_spec_output_is_rejected(tmp_path: Path) -> None:
    _bundle, run_spec = _run_spec(tmp_path)
    real = tmp_path / "real-run-spec.json"
    link = tmp_path / "linked-run-spec.json"
    real.write_text("existing", encoding="utf-8")
    try:
        os.symlink(real, link)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(RunSpecIOError):
        write_test_bootstrap_add_run_spec(run_spec, link)


def test_private_run_spec_hides_raw_identity_and_content_from_repr(tmp_path: Path) -> None:
    _bundle, run_spec = _run_spec(tmp_path)
    rendered = repr(run_spec)

    assert BOOTSTRAP_UID not in rendered
    assert BOOTSTRAP_SUMMARY not in rendered
    assert run_spec.target_fingerprint not in rendered
