from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import jsonschema  # type: ignore[import-untyped]
import pytest
from conftest import REPOSITORY_ROOT
from phase6b_helpers import build_production_planning_inputs

from tridentine_calendar_google_sync.production_approval_state import (
    ProductionApprovalStateError,
    build_production_arm_receipt,
    build_production_execute_permit,
    build_production_kill_switch,
    calculate_production_arm_receipt_hash,
    calculate_production_execute_permit_hash,
    calculate_production_kill_switch_hash,
    derive_production_execute_nonce,
    private_phase6c_mock_approval_store_data,
    production_arm_challenge,
    production_execute_challenge,
    transition_production_kill_switch,
    verify_phase6c_mock_approval_store,
    verify_production_arm_confirmation,
    verify_production_arm_receipt,
    verify_production_arm_receipt_integrity,
    verify_production_execute_confirmation,
    verify_production_execute_permit,
    verify_production_execute_permit_integrity,
    verify_production_kill_switch,
    verify_production_kill_switch_transition,
)
from tridentine_calendar_google_sync.production_approval_state_io import (
    build_phase6c_mock_approval_store,
    parse_production_arm_receipt_bytes,
    parse_production_execute_permit_bytes,
    parse_production_kill_switch_bytes,
    render_production_arm_receipt_json,
    render_production_execute_permit_json,
    render_production_kill_switch_json,
)
from tridentine_calendar_google_sync.production_approval_state_models import (
    PRODUCTION_ARM_MAX_LIFETIME_SECONDS,
    ProductionArmReceipt,
    ProductionExecutePermit,
    ProductionKillSwitch,
    ProductionMockApprovalStore,
)
from tridentine_calendar_google_sync.production_single_update_plan import (
    build_production_single_update_plan,
)
from tridentine_calendar_google_sync.production_single_update_plan_models import (
    ProductionSingleUpdatePlan,
)
from tridentine_calendar_google_sync.production_single_update_run_spec import (
    build_production_single_update_run_spec,
)
from tridentine_calendar_google_sync.production_single_update_run_spec_models import (
    ProductionSingleUpdateRunSpec,
)
from tridentine_calendar_google_sync.production_transport_models import (
    ProductionTokenSeparationPolicy,
)

ISSUED_AT = datetime(2099, 1, 1, 12, 0, tzinfo=UTC)
ARM_NONCE = "a" * 32
SWITCH_GENERATION = 1
TOKEN_GENERATION = 11


@dataclass(frozen=True)
class ApprovalArtifacts:
    plan: ProductionSingleUpdatePlan
    run_spec: ProductionSingleUpdateRunSpec
    initial_kill_switch: ProductionKillSwitch
    kill_switch: ProductionKillSwitch
    approval_store: ProductionMockApprovalStore
    approval_store_directory: Path
    receipt: ProductionArmReceipt
    permit: ProductionExecutePermit


def _artifacts(tmp_path: Path) -> ApprovalArtifacts:
    inputs = build_production_planning_inputs(tmp_path)
    plan = build_production_single_update_plan(
        inputs.manifest,
        inputs.updated.profile,
        inputs.updated.source,
        inputs.snapshot,
        inputs.baseline,
        inputs.target,
    )
    run_spec = build_production_single_update_run_spec(
        inputs.manifest,
        inputs.updated.profile,
        inputs.updated.source,
        inputs.snapshot,
        plan,
        inputs.baseline,
        inputs.target,
        issued_at=ISSUED_AT,
        expires_at=ISSUED_AT + timedelta(hours=1),
    )
    initial_kill_switch = build_production_kill_switch(
        run_spec.target_safe_ref,
        issued_at=ISSUED_AT,
    )
    kill_switch = transition_production_kill_switch(
        initial_kill_switch,
        state="on",
        issued_at=ISSUED_AT + timedelta(microseconds=1),
    )
    approval_store_directory = tmp_path / "approval-store"
    approval_store_directory.mkdir()
    approval_store = build_phase6c_mock_approval_store(approval_store_directory)
    receipt = build_production_arm_receipt(
        run_spec,
        plan,
        kill_switch,
        approval_store,
        write_token_generation=TOKEN_GENERATION,
        arm_nonce=ARM_NONCE,
        issued_at=ISSUED_AT + timedelta(seconds=1),
    )
    permit = build_production_execute_permit(
        receipt,
        run_spec,
        plan,
        kill_switch,
        approval_store,
        arm_confirmation=production_arm_challenge(receipt),
        write_token_generation=TOKEN_GENERATION,
    )
    return ApprovalArtifacts(
        plan,
        run_spec,
        initial_kill_switch,
        kill_switch,
        approval_store,
        approval_store_directory,
        receipt,
        permit,
    )


def _rehash_arm(receipt: ProductionArmReceipt, field: str, value: object) -> ProductionArmReceipt:
    provisional = receipt.model_copy(update={field: value, "content_hash": "0" * 64})
    return provisional.model_copy(
        update={"content_hash": calculate_production_arm_receipt_hash(provisional)}
    )


def _rehash_permit(
    permit: ProductionExecutePermit,
    field: str,
    value: object,
) -> ProductionExecutePermit:
    provisional = permit.model_copy(update={field: value, "content_hash": "0" * 64})
    return provisional.model_copy(
        update={"content_hash": calculate_production_execute_permit_hash(provisional)}
    )


def _different_hex(value: str) -> str:
    return value[:-1] + ("e" if value.endswith("f") else "f")


def test_kill_switch_initial_state_and_monotonic_transition_chain_are_exact() -> None:
    target_ref = "T-0123456789ab"
    default = build_production_kill_switch(target_ref, issued_at=ISSUED_AT)
    enabled = transition_production_kill_switch(
        default,
        state="on",
        issued_at=ISSUED_AT + timedelta(seconds=1),
    )
    disabled = transition_production_kill_switch(
        enabled,
        state="off",
        issued_at=ISSUED_AT + timedelta(seconds=2),
    )
    reenabled = transition_production_kill_switch(
        disabled,
        state="on",
        issued_at=ISSUED_AT + timedelta(seconds=3),
    )

    assert default.state == "off"
    assert default.generation == 0
    assert default.transition_kind == "initial"
    assert default.previous_switch_hash is None
    assert (enabled.generation, disabled.generation, reenabled.generation) == (1, 2, 3)
    assert enabled.previous_switch_hash == default.content_hash
    assert disabled.previous_switch_hash == enabled.content_hash
    assert reenabled.previous_switch_hash == disabled.content_hash
    verify_production_kill_switch_transition(default, enabled)
    verify_production_kill_switch_transition(enabled, disabled)
    verify_production_kill_switch_transition(disabled, reenabled)

    forged_on = default.model_copy(update={"state": "on", "content_hash": "0" * 64})
    forged_on = forged_on.model_copy(
        update={"content_hash": calculate_production_kill_switch_hash(forged_on)}
    )
    with pytest.raises(ProductionApprovalStateError) as forged:
        verify_production_kill_switch(forged_on)
    assert forged.value.code == "production_kill_switch_invalid"

    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "production-kill-switch-v1.schema.json").read_text("utf-8")
    )
    off_document = json.loads(render_production_kill_switch_json(default))
    jsonschema.validate(off_document, schema)
    on_zero_document = {**off_document, "state": "on"}
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(on_zero_document, schema)

    with pytest.raises(ProductionApprovalStateError) as off:
        verify_production_kill_switch(default, require_on=True)
    assert off.value.code == "production_kill_switch_off"
    verify_production_kill_switch(
        enabled,
        target_safe_ref=target_ref,
        required_generation=1,
        require_on=True,
    )
    for expected_target, generation, code in (
        ("T-fedcba987654", 1, "production_kill_switch_target_mismatch"),
        (target_ref, 2, "production_kill_switch_generation_mismatch"),
    ):
        with pytest.raises(ProductionApprovalStateError) as captured:
            verify_production_kill_switch(
                enabled,
                target_safe_ref=expected_target,
                required_generation=generation,
                require_on=True,
            )
        assert captured.value.code == code

    reused_generation = reenabled.model_copy(
        update={
            "generation": enabled.generation,
            "content_hash": "0" * 64,
        }
    )
    reused_generation = reused_generation.model_copy(
        update={"content_hash": calculate_production_kill_switch_hash(reused_generation)}
    )
    with pytest.raises(ProductionApprovalStateError) as reused:
        verify_production_kill_switch_transition(disabled, reused_generation)
    assert reused.value.code == "production_kill_switch_transition_mismatch"

    with pytest.raises(ProductionApprovalStateError) as clock:
        transition_production_kill_switch(
            enabled,
            state="off",
            issued_at=enabled.issued_at,
        )
    assert clock.value.code == "production_kill_switch_transition_clock_invalid"


def test_valid_arm_execute_chain_is_exact_short_lived_and_raw_free(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)
    receipt = artifacts.receipt
    permit = artifacts.permit

    verify_production_arm_receipt(
        receipt,
        artifacts.run_spec,
        artifacts.plan,
        artifacts.kill_switch,
        artifacts.approval_store,
        write_token_generation=TOKEN_GENERATION,
        now=receipt.issued_at,
    )
    verify_production_execute_permit(
        permit,
        receipt,
        artifacts.run_spec,
        artifacts.plan,
        artifacts.kill_switch,
        artifacts.approval_store,
        write_token_generation=TOKEN_GENERATION,
        now=permit.issued_at,
    )
    assert (receipt.expires_at - receipt.issued_at).total_seconds() == 600
    assert receipt.expires_at <= artifacts.run_spec.expires_at
    assert permit.expires_at == min(receipt.expires_at, artifacts.run_spec.expires_at)
    assert permit.one_time is True
    assert permit.consumed is False
    assert (permit.operation_count, permit.add_count, permit.update_count, permit.delete_count) == (
        1,
        0,
        1,
        0,
    )
    assert permit.changed_fields == ("description",)
    assert receipt.approval_store_hash == artifacts.approval_store.content_hash
    assert permit.approval_store_hash == artifacts.approval_store.content_hash
    assert permit.execute_nonce == derive_production_execute_nonce(
        receipt.content_hash,
        receipt.arm_nonce,
    )
    assert artifacts.approval_store.mock_only is True
    assert artifacts.approval_store.live_capable is False
    assert artifacts.approval_store.private_dacl_assured is False
    assert artifacts.approval_store.phase6d_private_dacl_review_required is True
    verify_phase6c_mock_approval_store(artifacts.approval_store)
    assert production_arm_challenge(receipt) == (
        f"ARM PRODUCTION CALENDAR WRITE {receipt.target_safe_ref} "
        f"R-{receipt.run_spec_hash[:12]} P-{receipt.plan_hash[:12]} "
        f"X-{receipt.content_hash[:12]} U-1"
    )
    assert production_execute_challenge(permit) == (
        f"EXECUTE PRODUCTION CALENDAR WRITE {permit.target_safe_ref} "
        f"R-{permit.run_spec_hash[:12]} X-{permit.content_hash[:12]} U-1"
    )
    arm_json = render_production_arm_receipt_json(receipt)
    permit_json = render_production_execute_permit_json(permit)
    forbidden = (
        "calendar_id",
        "iCalUID",
        "event_id",
        "etag",
        "summary",
        "token_path",
        "credentials",
    )
    assert all(item not in arm_json + permit_json for item in forbidden)

    second = build_production_execute_permit(
        receipt,
        artifacts.run_spec,
        artifacts.plan,
        artifacts.kill_switch,
        artifacts.approval_store,
        arm_confirmation=production_arm_challenge(receipt),
        write_token_generation=TOKEN_GENERATION,
    )
    assert second == permit
    assert second.content_hash == permit.content_hash


def test_confirmation_is_case_and_whitespace_sensitive(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)
    arm = production_arm_challenge(artifacts.receipt)
    execute = production_execute_challenge(artifacts.permit)
    verify_production_arm_confirmation(artifacts.receipt, arm)
    verify_production_execute_confirmation(artifacts.permit, execute)

    for confirmation, verifier, artifact in (
        (arm.lower(), verify_production_arm_confirmation, artifacts.receipt),
        (arm + " ", verify_production_arm_confirmation, artifacts.receipt),
        (execute.lower(), verify_production_execute_confirmation, artifacts.permit),
        (execute.replace(" ", "  ", 1), verify_production_execute_confirmation, artifacts.permit),
    ):
        with pytest.raises(ProductionApprovalStateError):
            verifier(artifact, confirmation)  # type: ignore[arg-type]

    with pytest.raises(ProductionApprovalStateError) as captured:
        build_production_execute_permit(
            artifacts.receipt,
            artifacts.run_spec,
            artifacts.plan,
            artifacts.kill_switch,
            artifacts.approval_store,
            arm_confirmation=arm + " ",
            write_token_generation=TOKEN_GENERATION,
        )
    assert captured.value.code == "production_arm_confirmation_mismatch"


def test_arm_lifetime_run_spec_cap_expiry_and_clock_anomaly_are_fail_closed(
    tmp_path: Path,
) -> None:
    artifacts = _artifacts(tmp_path)
    receipt = artifacts.receipt
    assert PRODUCTION_ARM_MAX_LIFETIME_SECONDS == 600
    verify_production_arm_receipt_integrity(receipt, now=receipt.issued_at)
    verify_production_arm_receipt_integrity(
        receipt,
        now=receipt.expires_at - timedelta(microseconds=1),
    )
    for now, expected in (
        (receipt.issued_at - timedelta(microseconds=1), "production_arm_not_yet_valid"),
        (receipt.expires_at, "production_arm_expired"),
    ):
        with pytest.raises(ProductionApprovalStateError) as captured:
            verify_production_arm_receipt_integrity(receipt, now=now)
        assert captured.value.code == expected

    for invalid_expiry in (
        receipt.issued_at,
        receipt.issued_at + timedelta(seconds=601),
        artifacts.run_spec.expires_at + timedelta(seconds=1),
    ):
        with pytest.raises((ProductionApprovalStateError, ValueError)):
            build_production_arm_receipt(
                artifacts.run_spec,
                artifacts.plan,
                artifacts.kill_switch,
                artifacts.approval_store,
                write_token_generation=TOKEN_GENERATION,
                arm_nonce=ARM_NONCE,
                issued_at=receipt.issued_at,
                expires_at=invalid_expiry,
            )

    non_utc = ISSUED_AT.astimezone(timezone(timedelta(hours=9)))
    with pytest.raises(ProductionApprovalStateError) as clock:
        build_production_arm_receipt(
            artifacts.run_spec,
            artifacts.plan,
            artifacts.kill_switch,
            artifacts.approval_store,
            write_token_generation=TOKEN_GENERATION,
            arm_nonce=ARM_NONCE,
            issued_at=non_utc,
        )
    assert clock.value.code == "production_arm_clock_invalid"


def test_switch_and_token_generation_changes_invalidate_both_stages(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)
    changed_switch = transition_production_kill_switch(
        artifacts.kill_switch,
        state="on",
        issued_at=ISSUED_AT + timedelta(seconds=3),
    )
    for verify in ("arm", "execute"):
        with pytest.raises(ProductionApprovalStateError) as captured:
            if verify == "arm":
                verify_production_arm_receipt(
                    artifacts.receipt,
                    artifacts.run_spec,
                    artifacts.plan,
                    changed_switch,
                    artifacts.approval_store,
                    write_token_generation=TOKEN_GENERATION,
                    now=artifacts.permit.issued_at,
                )
            else:
                verify_production_execute_permit(
                    artifacts.permit,
                    artifacts.receipt,
                    artifacts.run_spec,
                    artifacts.plan,
                    changed_switch,
                    artifacts.approval_store,
                    write_token_generation=TOKEN_GENERATION,
                    now=artifacts.permit.issued_at,
                )
        assert captured.value.code == "production_kill_switch_generation_mismatch"

    for generation in (False, 0, TOKEN_GENERATION + 1):
        with pytest.raises((ProductionApprovalStateError, ValueError)):
            verify_production_execute_permit(
                artifacts.permit,
                artifacts.receipt,
                artifacts.run_spec,
                artifacts.plan,
                artifacts.kill_switch,
                artifacts.approval_store,
                write_token_generation=generation,
                now=artifacts.permit.issued_at,
            )


def test_three_future_token_roles_are_distinct_secret_free_and_write_generation_bound(
    tmp_path: Path,
) -> None:
    artifacts = _artifacts(tmp_path)
    policy = ProductionTokenSeparationPolicy(write_token_generation=TOKEN_GENERATION)
    roles = (
        policy.production_read_role,
        policy.test_write_role,
        policy.production_write_role,
    )
    assert roles == ("production_read_only", "test_write", "production_write")
    assert len(set(roles)) == 3
    assert policy.token_paths_present is False
    assert policy.token_values_present is False
    assert policy.write_token_generation == artifacts.receipt.write_token_generation
    assert policy.write_token_generation == artifacts.permit.write_token_generation
    verify_production_execute_permit(
        artifacts.permit,
        artifacts.receipt,
        artifacts.run_spec,
        artifacts.plan,
        artifacts.kill_switch,
        artifacts.approval_store,
        write_token_generation=policy.write_token_generation,
        now=artifacts.permit.issued_at,
    )
    exposed = set(ProductionTokenSeparationPolicy.model_fields)
    assert exposed.isdisjoint(
        {"token", "token_path", "token_value", "credentials", "client", "calendar_id"}
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("target_safe_ref", "T-fedcba987654"),
        ("run_spec_hash", "f" * 64),
        ("plan_hash", "e" * 64),
        ("manifest_hash", "d" * 64),
        ("source_sha256", "c" * 64),
        ("trusted_baseline_hash", "b" * 64),
        ("snapshot_hash", "a" * 64),
        ("operation_count", 2),
        ("add_count", 1),
        ("update_count", 0),
        ("delete_count", 1),
        ("changed_fields", ("summary",)),
        ("patch_hash", "9" * 64),
        ("approval_material_hash", "8" * 64),
        ("approval_store_hash", "6" * 64),
        ("arm_nonce", "7" * 32),
        ("kill_switch_generation", SWITCH_GENERATION + 1),
        ("write_token_generation", TOKEN_GENERATION + 1),
    ),
)
def test_every_arm_binding_mutation_invalidates_existing_execute_permit(
    tmp_path: Path,
    field: str,
    replacement: object,
) -> None:
    artifacts = _artifacts(tmp_path)
    mutated = _rehash_arm(artifacts.receipt, field, replacement)
    with pytest.raises(ProductionApprovalStateError):
        verify_production_execute_permit(
            artifacts.permit,
            mutated,
            artifacts.run_spec,
            artifacts.plan,
            artifacts.kill_switch,
            artifacts.approval_store,
            write_token_generation=TOKEN_GENERATION,
            now=artifacts.permit.issued_at,
        )


def test_every_execute_bit_change_invalidates_prior_human_confirmation(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)
    original_confirmation = production_execute_challenge(artifacts.permit)
    replacements: dict[str, object] = {
        "arm_receipt_hash": _different_hex(artifacts.permit.arm_receipt_hash),
        "run_spec_hash": _different_hex(artifacts.permit.run_spec_hash),
        "target_safe_ref": "T-fedcba987654",
        "operation_count": 2,
        "add_count": 1,
        "update_count": 0,
        "delete_count": 1,
        "changed_fields": ("summary",),
        "patch_hash": _different_hex(artifacts.permit.patch_hash),
        "approval_store_hash": _different_hex(artifacts.permit.approval_store_hash),
        "arm_nonce": "c" * 32,
        "execute_nonce": "d" * 32,
        "kill_switch_generation": SWITCH_GENERATION + 1,
        "write_token_generation": TOKEN_GENERATION + 1,
        "issued_at": artifacts.permit.issued_at + timedelta(microseconds=1),
        "expires_at": artifacts.permit.expires_at - timedelta(microseconds=1),
    }
    for field, replacement in replacements.items():
        mutated = _rehash_permit(artifacts.permit, field, replacement)
        with pytest.raises(ProductionApprovalStateError):
            verify_production_execute_confirmation(mutated, original_confirmation)


def test_hash_tamper_and_closed_schema_are_rejected(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)
    for artifact, verifier in (
        (
            artifacts.kill_switch.model_copy(update={"content_hash": "f" * 64}),
            verify_production_kill_switch,
        ),
        (
            artifacts.receipt.model_copy(update={"content_hash": "f" * 64}),
            verify_production_arm_receipt_integrity,
        ),
        (
            artifacts.permit.model_copy(update={"content_hash": "f" * 64}),
            verify_production_execute_permit_integrity,
        ),
    ):
        with pytest.raises(ProductionApprovalStateError):
            verifier(artifact)  # type: ignore[arg-type]

    rendered_and_schemas = (
        (
            json.dumps(
                private_phase6c_mock_approval_store_data(artifacts.approval_store),
                indent=2,
            )
            + "\n",
            "production-mock-approval-store-v1.schema.json",
        ),
        (
            render_production_kill_switch_json(artifacts.kill_switch),
            "production-kill-switch-v1.schema.json",
        ),
        (
            render_production_arm_receipt_json(artifacts.receipt),
            "production-arm-receipt-v1.schema.json",
        ),
        (
            render_production_execute_permit_json(artifacts.permit),
            "production-execute-permit-v1.schema.json",
        ),
    )
    for rendered, schema_name in rendered_and_schemas:
        schema = json.loads((REPOSITORY_ROOT / "schemas" / schema_name).read_text("utf-8"))
        jsonschema.validate(json.loads(rendered), schema)
        assert schema["additionalProperties"] is False
        document = json.loads(rendered)
        document["unexpected"] = True
        with pytest.raises(jsonschema.ValidationError):
            jsonschema.validate(document, schema)


def test_canonical_round_trip_and_noncanonical_input_rejection(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path)
    kill_raw = render_production_kill_switch_json(artifacts.kill_switch).encode()
    arm_raw = render_production_arm_receipt_json(artifacts.receipt).encode()
    permit_raw = render_production_execute_permit_json(artifacts.permit).encode()
    assert parse_production_kill_switch_bytes(kill_raw) == artifacts.kill_switch
    assert (
        parse_production_arm_receipt_bytes(arm_raw, now=artifacts.receipt.issued_at)
        == artifacts.receipt
    )
    assert (
        parse_production_execute_permit_bytes(permit_raw, now=artifacts.permit.issued_at)
        == artifacts.permit
    )
    kill_noncanonical = json.dumps(json.loads(kill_raw), sort_keys=True).encode()
    arm_noncanonical = json.dumps(json.loads(arm_raw), sort_keys=True).encode()
    permit_noncanonical = json.dumps(json.loads(permit_raw), sort_keys=True).encode()
    with pytest.raises(ProductionApprovalStateError):
        parse_production_kill_switch_bytes(kill_noncanonical)
    with pytest.raises(ProductionApprovalStateError):
        parse_production_arm_receipt_bytes(
            arm_noncanonical,
            now=artifacts.receipt.issued_at,
        )
    with pytest.raises(ProductionApprovalStateError):
        parse_production_execute_permit_bytes(
            permit_noncanonical,
            now=artifacts.permit.issued_at,
        )


def test_no_secret_or_transport_identity_fields_exist() -> None:
    field_names = (
        set(ProductionKillSwitch.model_fields)
        | set(ProductionMockApprovalStore.model_fields)
        | set(ProductionArmReceipt.model_fields)
        | set(ProductionExecutePermit.model_fields)
    )
    forbidden = {
        "calendar_id",
        "uid",
        "ical_uid",
        "event_id",
        "etag",
        "summary",
        "description",
        "token",
        "token_path",
        "credentials",
        "authorization",
        "url",
        "payload",
    }
    assert field_names.isdisjoint(forbidden)
