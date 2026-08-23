from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import REPOSITORY_ROOT
from jsonschema import Draft202012Validator
from phase4b_helpers import (
    approved_bundle,
    build_add_apply_bundle,
    build_multi_apply_bundle,
    build_update_apply_bundle,
)
from pydantic import ValidationError
from test_sync_plan import _current_source, _large_bundle

from tridentine_calendar_google_sync.apply_approval import (
    apply_approval_challenge,
    approve_apply_bundle,
)
from tridentine_calendar_google_sync.apply_bundle import (
    build_apply_bundle,
    calculate_apply_bundle_integrity,
    calculate_apply_operation_integrity,
    private_bundle_data,
    verify_apply_bundle_integrity,
)
from tridentine_calendar_google_sync.apply_bundle_io import (
    load_apply_bundle,
    parse_apply_bundle_bytes,
    render_apply_bundle_json,
    write_apply_bundle,
)
from tridentine_calendar_google_sync.apply_models import (
    ApplyAddPayload,
    ApplyBundle,
    ApplyBundleState,
    ApplyEnvironment,
    ApplyOperationKind,
    ApplyUpdatePayload,
)
from tridentine_calendar_google_sync.apply_policy import (
    ApplyConfirmationError,
    ApplyGuardError,
    ApplyInputError,
    ApplyIOError,
    ApplyValidationError,
)
from tridentine_calendar_google_sync.fake_mutation_transport import FakeMutationTransport
from tridentine_calendar_google_sync.operation_journal import initialize_operation_journal
from tridentine_calendar_google_sync.plan_engine import build_sync_plan
from tridentine_calendar_google_sync.plan_models import PlanThresholds


def test_update_bundle_is_private_integrity_pinned_and_non_executable(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    value = build_update_apply_bundle(tmp_path, synthetic_profile_factory)
    bundle = value.bundle

    assert bundle.state is ApplyBundleState.APPROVAL_REQUIRED
    assert bundle.environment is ApplyEnvironment.TEST
    assert bundle.generated_operation_count == 1
    assert bundle.add_count == 0
    assert bundle.update_count == 1
    assert bundle.delete_count == 0
    assert bundle.production_locked is True
    assert bundle.execution_enabled is False
    operation = bundle.operations[0]
    assert operation.operation is ApplyOperationKind.UPDATE
    assert isinstance(operation.payload, ApplyUpdatePayload)
    assert operation.destructive is False
    assert operation.approval_required is True
    verify_apply_bundle_integrity(bundle)


def test_add_bundle_contains_only_add_payload_and_no_delete_model(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    value = build_add_apply_bundle(tmp_path, synthetic_profile_factory)
    operation = value.bundle.operations[0]

    assert value.bundle.add_count == 1
    assert value.bundle.update_count == 0
    assert operation.operation is ApplyOperationKind.ADD
    assert isinstance(operation.payload, ApplyAddPayload)
    assert not hasattr(value.bundle, "delete_operations")
    assert {kind.value for kind in ApplyOperationKind} == {"add", "update"}


def test_approval_requires_exact_test_only_challenge_and_current_plan_hash(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    value = build_update_apply_bundle(tmp_path, synthetic_profile_factory)
    challenge = apply_approval_challenge(value.bundle, value.plan.plan_content_hash)

    with pytest.raises(ApplyConfirmationError):
        approve_apply_bundle(
            value.bundle,
            "AUTHORIZE TEST APPLY T-000000000000 P-000000000000 A-0 U-0",
            value.plan.plan_content_hash,
        )
    with pytest.raises(ApplyGuardError) as caught:
        apply_approval_challenge(value.bundle, "f" * 64)
    assert caught.value.code == "apply_plan_stale_or_mismatched"

    approved = approved_bundle(value)
    assert approved.state is ApplyBundleState.APPROVED_FOR_SIMULATION
    assert approved.execution_enabled is False
    assert challenge.startswith("AUTHORIZE TEST APPLY T-")


def test_tampered_payload_operation_and_bundle_hashes_are_rejected(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    value = build_update_apply_bundle(tmp_path, synthetic_profile_factory)
    operation = value.bundle.operations[0]

    tampered_payload = operation.payload.model_copy(update={"summary": "Tampered synthetic"})
    tampered_operation = operation.model_copy(update={"payload": tampered_payload})
    tampered_bundle = value.bundle.model_copy(update={"operations": (tampered_operation,)})
    with pytest.raises(ApplyValidationError):
        verify_apply_bundle_integrity(tampered_bundle)

    stale_bundle = value.bundle.model_copy(update={"source_event_count": 999})
    with pytest.raises(ApplyValidationError):
        verify_apply_bundle_integrity(stale_bundle)


def test_bundle_model_rejects_noncanonical_operation_order_after_rehash(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    value = build_multi_apply_bundle(tmp_path, synthetic_profile_factory)
    original = value.bundle.operations
    assert [operation.operation.value for operation in original] == [
        "add",
        "add",
        "update",
    ]
    reordered = []
    for sequence, operation in enumerate((original[-1], *original[:-1]), start=1):
        provisional = operation.model_copy(
            update={
                "operation_sequence": sequence,
                "operation_integrity_hash": "0" * 64,
            }
        )
        reordered.append(
            provisional.model_copy(
                update={
                    "operation_integrity_hash": calculate_apply_operation_integrity(provisional)
                }
            )
        )
    provisional_bundle = value.bundle.model_copy(
        update={
            "operations": tuple(reordered),
            "bundle_integrity_hash": "0" * 64,
        }
    )
    recalculated_hash = calculate_apply_bundle_integrity(provisional_bundle)
    data = private_bundle_data(provisional_bundle)
    data.update(
        {
            "state": value.bundle.state,
            "environment": value.bundle.environment,
            "plan_state": value.bundle.plan_state,
            "operations": tuple(reordered),
            "bundle_integrity_hash": recalculated_hash,
        }
    )

    with pytest.raises(ValidationError):
        ApplyBundle.model_validate(data, strict=True)


def test_private_bundle_json_schema_roundtrip_and_public_model_redaction(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    value = build_update_apply_bundle(tmp_path, synthetic_profile_factory)
    rendered = render_apply_bundle_json(value.bundle)
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "apply-bundle-v1.schema.json").read_text(encoding="utf-8")
    )

    Draft202012Validator(schema).validate(json.loads(rendered))
    assert parse_apply_bundle_bytes(rendered.encode("utf-8")) == value.bundle
    internal = repr(value.bundle) + json.dumps(value.bundle.model_dump(mode="json"))
    operation = value.bundle.operations[0]
    assert operation.source_uid not in internal
    assert operation.payload.event_id not in internal  # type: ignore[union-attr]
    assert operation.payload.etag not in internal  # type: ignore[union-attr]


def test_apply_bundle_atomic_write_load_no_overwrite_and_repo_rejection(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    value = build_update_apply_bundle(tmp_path, synthetic_profile_factory)
    path = tmp_path / "synthetic.apply-bundle.json"

    assert write_apply_bundle(value.bundle, path) == path
    assert load_apply_bundle(path) == value.bundle
    with pytest.raises(ApplyIOError):
        write_apply_bundle(value.bundle, path)

    repo_path = REPOSITORY_ROOT / "must-not-create.apply-bundle.json"
    with pytest.raises(ApplyIOError):
        write_apply_bundle(value.bundle, repo_path)
    assert not repo_path.exists()


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json",
        b'{"schema_version":"2.0"}',
        b'{"schema_version":"1.0","schema_version":"1.0"}',
    ],
)
def test_malformed_duplicate_or_unsupported_bundle_is_rejected(raw: bytes) -> None:
    with pytest.raises(ApplyValidationError):
        parse_apply_bundle_bytes(raw)


def test_delete_plan_and_blocked_plan_cannot_build_bundle(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    _old_profile, _old_source, snapshot, _document, baseline = _large_bundle(
        tmp_path,
        synthetic_profile_factory,
        count=101,
    )
    profile, source = _current_source(tmp_path, synthetic_profile_factory, 100)
    delete_plan = build_sync_plan(
        profile,
        source,
        snapshot,
        baseline,
        thresholds=PlanThresholds(max_delete=1),
    )

    with pytest.raises(ApplyGuardError) as caught:
        build_apply_bundle(
            profile,
            source,
            snapshot,
            baseline,
            delete_plan,
            ApplyEnvironment.TEST,
        )
    assert caught.value.code == "unsafe_sync_plan_counts"


def test_explicit_environment_is_required_and_production_nonzero_is_forbidden(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    value = build_update_apply_bundle(tmp_path, synthetic_profile_factory)

    with pytest.raises(ApplyInputError):
        build_apply_bundle(
            value.profile,
            value.source,
            value.snapshot,
            value.baseline,
            value.plan,
            "test",  # type: ignore[arg-type]
        )
    with pytest.raises(ApplyGuardError):
        build_apply_bundle(
            value.profile,
            value.source,
            value.snapshot,
            value.baseline,
            value.plan,
            ApplyEnvironment.PRODUCTION,
        )


def test_production_bundle_persistence_is_always_forbidden(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    value = build_update_apply_bundle(tmp_path, synthetic_profile_factory)
    production_like = value.bundle.model_copy(
        update={
            "environment": ApplyEnvironment.PRODUCTION,
            "target_reference": "T-e10f0095ab8f",
            "target_fingerprint": "e10f0095ab8f" + "0" * 52,
        }
    )

    with pytest.raises(ApplyGuardError) as caught:
        write_apply_bundle(production_like, tmp_path / "must-not-write.json")
    assert caught.value.code == "production_apply_bundle_write_forbidden"


def test_valid_production_zero_bundle_cannot_be_written_approved_or_journaled(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    profile, source, snapshot, _document, baseline = _large_bundle(
        tmp_path,
        synthetic_profile_factory,
        count=101,
    )
    plan = build_sync_plan(profile, source, snapshot, baseline)
    test_zero = build_apply_bundle(
        profile,
        source,
        snapshot,
        baseline,
        plan,
        ApplyEnvironment.TEST,
    )
    provisional = test_zero.model_copy(
        update={
            "environment": ApplyEnvironment.PRODUCTION,
            "target_reference": "T-e10f0095ab8f",
            "target_fingerprint": "e10f0095ab8f" + "0" * 52,
            "bundle_integrity_hash": "0" * 64,
        }
    )
    production = provisional.model_copy(
        update={"bundle_integrity_hash": calculate_apply_bundle_integrity(provisional)}
    )

    verify_apply_bundle_integrity(production)
    assert production.generated_operation_count == 0
    with pytest.raises(ApplyGuardError):
        write_apply_bundle(production, tmp_path / "must-not-write-production.json")
    with pytest.raises(ApplyGuardError):
        apply_approval_challenge(production, production.plan_content_hash)
    with pytest.raises(ApplyGuardError):
        FakeMutationTransport.from_bundle(production)
    with pytest.raises(ApplyGuardError):
        initialize_operation_journal(production)
