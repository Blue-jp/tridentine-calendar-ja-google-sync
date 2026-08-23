from __future__ import annotations

from typing import Any

import pytest
from phase4b_helpers import build_add_apply_bundle, build_update_apply_bundle
from phase5a_helpers import make_test_target_config, managed_state
from pydantic import ValidationError

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteOperation as WriteOperation,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteOperationKind as OperationKind,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteRunSpec as WriteRunSpec,
)
from tridentine_calendar_google_sync.test_write_run_spec import (
    TestWriteRunSpecError as RunSpecError,
)
from tridentine_calendar_google_sync.test_write_run_spec import (
    build_test_write_run_spec,
    calculate_test_write_operation_hash,
    calculate_test_write_run_spec_hash,
    private_test_write_run_spec_data,
    verify_test_write_run_spec,
)

pytestmark = pytest.mark.google_test_write


def _bind_target_to_snapshot(monkeypatch: pytest.MonkeyPatch, fingerprint: str) -> None:
    import tridentine_calendar_google_sync.test_write_run_spec as run_spec_module

    monkeypatch.setattr(
        run_spec_module,
        "validate_test_write_target_config",
        lambda _target: fingerprint,
    )
    monkeypatch.setattr(
        run_spec_module,
        "test_write_target_reference",
        lambda _target: f"T-{fingerprint[:12]}",
    )


def _add_run_spec(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> WriteRunSpec:
    bundle = build_add_apply_bundle(tmp_path, synthetic_profile_factory)
    _bind_target_to_snapshot(monkeypatch, bundle.snapshot.target_fingerprint)
    return build_test_write_run_spec(
        bundle.profile,
        bundle.source,
        bundle.snapshot,
        bundle.plan,
        make_test_target_config(),
    )


def _update_run_spec(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[WriteRunSpec, Any]:
    bundle = build_update_apply_bundle(tmp_path, synthetic_profile_factory)
    _bind_target_to_snapshot(monkeypatch, bundle.snapshot.target_fingerprint)
    return (
        build_test_write_run_spec(
            bundle.profile,
            bundle.source,
            bundle.snapshot,
            bundle.plan,
            make_test_target_config(),
            trusted_baseline=bundle.baseline,
        ),
        bundle,
    )


def test_add_run_spec_is_test_only_one_operation_without_baseline(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_spec = _add_run_spec(tmp_path, synthetic_profile_factory, monkeypatch)

    assert run_spec.test_only is True
    assert run_spec.production_locked is True
    assert run_spec.operation_count == 1
    assert (run_spec.add_count, run_spec.update_count) == (1, 0)
    assert run_spec.operation.operation is OperationKind.ADD
    assert run_spec.trusted_baseline_hash is None
    assert run_spec.operation.google_event_id is None
    assert run_spec.operation.expected_etag is None
    verify_test_write_run_spec(run_spec)


def test_update_run_spec_requires_trusted_baseline_and_fresh_identity(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_spec, _bundle = _update_run_spec(tmp_path, synthetic_profile_factory, monkeypatch)

    assert (run_spec.add_count, run_spec.update_count) == (0, 1)
    assert run_spec.operation.operation is OperationKind.UPDATE
    assert run_spec.trusted_baseline_hash is not None
    assert run_spec.operation.google_event_id
    assert run_spec.operation.expected_etag
    assert run_spec.operation.changed_fields == ("summary",)
    verify_test_write_run_spec(run_spec)


def test_update_without_trusted_baseline_is_rejected(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = build_update_apply_bundle(tmp_path, synthetic_profile_factory)
    _bind_target_to_snapshot(monkeypatch, bundle.snapshot.target_fingerprint)

    with pytest.raises(RunSpecError) as captured:
        build_test_write_run_spec(
            bundle.profile,
            bundle.source,
            bundle.snapshot,
            bundle.plan,
            make_test_target_config(),
        )
    assert captured.value.code == "trusted_test_baseline_required"


def test_add_and_update_run_specs_are_deterministic(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first = _add_run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    second = _add_run_spec(tmp_path, synthetic_profile_factory, monkeypatch)

    assert private_test_write_run_spec_data(first) == private_test_write_run_spec_data(second)
    assert calculate_test_write_run_spec_hash(first) == first.run_spec_content_hash
    assert calculate_test_write_operation_hash(first.operation) == (
        first.operation.operation_content_hash
    )


def test_run_spec_and_operation_tampering_are_detected(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = _add_run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    tampered_spec = original.model_copy(update={"run_spec_content_hash": "f" * 64})
    with pytest.raises(RunSpecError) as spec_error:
        verify_test_write_run_spec(tampered_spec)
    assert spec_error.value.code == "test_write_run_spec_hash_mismatch"

    tampered_operation = original.operation.model_copy(update={"operation_content_hash": "f" * 64})
    provisional = original.model_copy(
        update={"operation": tampered_operation, "run_spec_content_hash": "0" * 64}
    )
    tampered = provisional.model_copy(
        update={"run_spec_content_hash": calculate_test_write_run_spec_hash(provisional)}
    )
    with pytest.raises(RunSpecError) as operation_error:
        verify_test_write_run_spec(tampered)
    assert operation_error.value.code == "test_write_operation_hash_mismatch"


@pytest.mark.parametrize(
    ("add_count", "update_count"),
    ((0, 0), (1, 1), (2, 0), (0, 2)),
)
def test_model_rejects_zero_mixed_or_multiple_operations(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    add_count: int,
    update_count: int,
) -> None:
    original = _add_run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    values = private_test_write_run_spec_data(original)
    values["add_count"] = add_count
    values["update_count"] = update_count
    with pytest.raises(ValidationError):
        WriteRunSpec.model_validate(values, strict=True)


def test_operation_model_rejects_update_without_event_id_or_etag() -> None:
    state = managed_state()
    base = {
        "operation": "update",
        "source_ref": "U-111111111111",
        "google_ref": "G-222222222222",
        "changed_fields": ("summary",),
        "current_state": state,
        "desired_state": state.model_copy(update={"summary": "Changed"}),
        "google_event_id": None,
        "expected_etag": None,
        "operation_content_hash": "0" * 64,
    }
    with pytest.raises(ValidationError):
        WriteOperation.model_validate(base, strict=True)


def test_operation_model_rejects_wildcard_etag() -> None:
    state = managed_state()
    with pytest.raises(ValidationError):
        WriteOperation(
            operation=OperationKind.UPDATE,
            source_ref="U-111111111111",
            google_ref="G-222222222222",
            changed_fields=("summary",),
            current_state=state,
            desired_state=state.model_copy(update={"summary": "Changed"}),
            google_event_id="evtfixturesynthetic",
            expected_etag="*",
            operation_content_hash="0" * 64,
        )


def test_private_run_spec_values_are_excluded_from_repr(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_spec, _bundle = _update_run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    rendered = repr(run_spec)

    assert run_spec.operation.desired_state.ical_uid not in rendered
    assert run_spec.operation.google_event_id not in rendered
    assert run_spec.operation.expected_etag not in rendered
    assert run_spec.operation.desired_state.summary not in rendered
    assert run_spec.operation.desired_state.description not in rendered
    assert run_spec.target_fingerprint not in rendered


def test_production_safe_reference_is_blocked_before_run_spec_generation(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tridentine_calendar_google_sync.test_write_run_spec as run_spec_module

    bundle = build_add_apply_bundle(tmp_path, synthetic_profile_factory)
    monkeypatch.setattr(
        run_spec_module,
        "validate_test_write_target_config",
        lambda _target: bundle.snapshot.target_fingerprint,
    )
    monkeypatch.setattr(
        run_spec_module,
        "test_write_target_reference",
        lambda _target: PRODUCTION_TARGET_REFERENCE,
    )

    with pytest.raises(RunSpecError) as captured:
        build_test_write_run_spec(
            bundle.profile,
            bundle.source,
            bundle.snapshot,
            bundle.plan,
            make_test_target_config(),
        )
    assert captured.value.code == "production_test_write_run_spec_forbidden"
