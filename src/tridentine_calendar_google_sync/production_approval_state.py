"""Build and verify mock-only two-stage Production approval state.

The models in this module grant no live capability.  They contain only safe
references, hashes, counters, generations, nonces, and UTC timestamps.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Literal

from tridentine_calendar_google_sync.production_approval_material import (
    verify_production_approval_material_hash,
)
from tridentine_calendar_google_sync.production_approval_state_models import (
    PRODUCTION_ARM_MAX_LIFETIME_SECONDS,
    ProductionArmReceipt,
    ProductionExecutePermit,
    ProductionExecutePermitConsumption,
    ProductionKillSwitch,
    ProductionMockApprovalStore,
    derive_production_execute_nonce,
)
from tridentine_calendar_google_sync.production_single_update_plan_models import (
    PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS,
    ProductionSingleUpdatePlan,
)
from tridentine_calendar_google_sync.production_single_update_run_spec import (
    verify_production_single_update_run_spec_bindings,
)
from tridentine_calendar_google_sync.production_single_update_run_spec_models import (
    ProductionSingleUpdateRunSpec,
)

_KILL_SWITCH_HASH_DOMAIN = b"tridentine-calendar-google-sync:production-kill-switch:v1\x00"
_ARM_RECEIPT_HASH_DOMAIN = b"tridentine-calendar-google-sync:production-arm-receipt:v1\x00"
_EXECUTE_PERMIT_HASH_DOMAIN = b"tridentine-calendar-google-sync:production-execute-permit:v1\x00"
_PERMIT_CONSUMPTION_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:production-permit-consumption:v1\x00"
)
_MOCK_APPROVAL_STORE_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:phase6c-mock-approval-store:v1\x00"
)


class ProductionApprovalStateError(ValueError):
    """A content-free approval, generation, lifetime, or integrity failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _hash_mapping(domain: bytes, value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def _utc_clock(value: datetime, *, code: str) -> None:
    offset = value.utcoffset() if isinstance(value, datetime) else None
    if offset is None or offset.total_seconds() != 0:
        raise ProductionApprovalStateError(
            code,
            "Production approval verification clock must be UTC",
        )


def _same(*pairs: tuple[str, str]) -> bool:
    return all(hmac.compare_digest(left, right) for left, right in pairs)


def _valid_generation(value: object, *, allow_zero: bool) -> bool:
    return type(value) is int and value >= (0 if allow_zero else 1)


def private_production_kill_switch_data(
    kill_switch: ProductionKillSwitch,
) -> dict[str, object]:
    """Return canonical raw-free kill-switch data."""

    return {
        "schema_version": kill_switch.schema_version,
        "switch_type": kill_switch.switch_type,
        "state": kill_switch.state,
        "generation": kill_switch.generation,
        "transition_kind": kill_switch.transition_kind,
        "previous_switch_hash": kill_switch.previous_switch_hash,
        "target_safe_ref": kill_switch.target_safe_ref,
        "issued_at": kill_switch.issued_at.isoformat(),
        "content_hash": kill_switch.content_hash,
    }


def calculate_production_kill_switch_hash(kill_switch: ProductionKillSwitch) -> str:
    data = private_production_kill_switch_data(kill_switch)
    del data["content_hash"]
    return _hash_mapping(_KILL_SWITCH_HASH_DOMAIN, data)


def build_production_kill_switch(
    target_safe_ref: str,
    *,
    issued_at: datetime,
) -> ProductionKillSwitch:
    """Build the sole valid initial state: OFF at generation zero."""

    try:
        provisional = ProductionKillSwitch(
            generation=0,
            target_safe_ref=target_safe_ref,
            issued_at=issued_at,
            content_hash="0" * 64,
        )
    except ValueError as exc:
        raise ProductionApprovalStateError(
            "production_kill_switch_invalid",
            "Production kill-switch state is invalid",
        ) from exc
    result = provisional.model_copy(
        update={"content_hash": calculate_production_kill_switch_hash(provisional)}
    )
    verify_production_kill_switch(result)
    return result


def transition_production_kill_switch(
    previous: ProductionKillSwitch,
    *,
    state: Literal["off", "on"],
    issued_at: datetime,
) -> ProductionKillSwitch:
    """Create exactly the next generation, linked to the prior switch hash."""

    verify_production_kill_switch(previous)
    if state not in ("off", "on"):
        raise ProductionApprovalStateError(
            "production_kill_switch_transition_invalid",
            "Production kill-switch transition is invalid",
        )
    if issued_at <= previous.issued_at:
        raise ProductionApprovalStateError(
            "production_kill_switch_transition_clock_invalid",
            "Production kill-switch transition time must advance",
        )
    try:
        provisional = ProductionKillSwitch(
            state=state,
            generation=previous.generation + 1,
            transition_kind="transition",
            previous_switch_hash=previous.content_hash,
            target_safe_ref=previous.target_safe_ref,
            issued_at=issued_at,
            content_hash="0" * 64,
        )
    except ValueError as exc:
        raise ProductionApprovalStateError(
            "production_kill_switch_transition_invalid",
            "Production kill-switch transition is invalid",
        ) from exc
    result = provisional.model_copy(
        update={"content_hash": calculate_production_kill_switch_hash(provisional)}
    )
    verify_production_kill_switch_transition(previous, result)
    return result


def verify_production_kill_switch_transition(
    previous: ProductionKillSwitch,
    current: ProductionKillSwitch,
) -> None:
    """Verify a linked monotonic generation transition without reuse or skipping."""

    verify_production_kill_switch(previous)
    verify_production_kill_switch(current)
    valid = (
        current.transition_kind == "transition"
        and current.generation == previous.generation + 1
        and current.issued_at > previous.issued_at
        and _same(
            (current.previous_switch_hash or "", previous.content_hash),
            (current.target_safe_ref, previous.target_safe_ref),
        )
    )
    if not valid:
        raise ProductionApprovalStateError(
            "production_kill_switch_transition_mismatch",
            "Production kill-switch transition does not match its predecessor",
        )


def verify_production_kill_switch(
    kill_switch: ProductionKillSwitch,
    *,
    target_safe_ref: str | None = None,
    required_generation: int | None = None,
    require_on: bool = False,
) -> None:
    """Verify integrity and optional target/state/generation preconditions."""

    if not isinstance(kill_switch, ProductionKillSwitch):
        raise ProductionApprovalStateError(
            "production_kill_switch_invalid",
            "Production kill-switch state is invalid",
        )
    try:
        ProductionKillSwitch.model_validate(kill_switch.model_dump(), strict=True)
    except (TypeError, ValueError) as exc:
        raise ProductionApprovalStateError(
            "production_kill_switch_invalid",
            "Production kill-switch state is invalid",
        ) from exc
    if not hmac.compare_digest(
        calculate_production_kill_switch_hash(kill_switch),
        kill_switch.content_hash,
    ):
        raise ProductionApprovalStateError(
            "production_kill_switch_hash_mismatch",
            "Production kill-switch integrity verification failed",
        )
    if target_safe_ref is not None and not hmac.compare_digest(
        kill_switch.target_safe_ref,
        target_safe_ref,
    ):
        raise ProductionApprovalStateError(
            "production_kill_switch_target_mismatch",
            "Production kill-switch target does not match",
        )
    if required_generation is not None and (
        not _valid_generation(required_generation, allow_zero=True)
        or kill_switch.generation != required_generation
    ):
        raise ProductionApprovalStateError(
            "production_kill_switch_generation_mismatch",
            "Production kill-switch generation does not match",
        )
    if require_on and kill_switch.state != "on":
        raise ProductionApprovalStateError(
            "production_kill_switch_off",
            "Production kill switch is off",
        )


def private_phase6c_mock_approval_store_data(
    store: ProductionMockApprovalStore,
) -> dict[str, object]:
    """Return the exact secret-free mock-store attestation data."""

    return {
        "schema_version": store.schema_version,
        "store_type": store.store_type,
        "mock_only": store.mock_only,
        "live_capable": store.live_capable,
        "private_dacl_assured": store.private_dacl_assured,
        "phase6d_private_dacl_review_required": store.phase6d_private_dacl_review_required,
        "directory_identity_hash": store.directory_identity_hash,
        "store_safe_ref": store.store_safe_ref,
        "content_hash": store.content_hash,
    }


def calculate_phase6c_mock_approval_store_hash(
    store: ProductionMockApprovalStore,
) -> str:
    data = private_phase6c_mock_approval_store_data(store)
    del data["content_hash"]
    return _hash_mapping(_MOCK_APPROVAL_STORE_HASH_DOMAIN, data)


def verify_phase6c_mock_approval_store(store: ProductionMockApprovalStore) -> None:
    """Verify an exact Phase 6C mock-only attestation; it grants no live capability."""

    if not isinstance(store, ProductionMockApprovalStore):
        raise ProductionApprovalStateError(
            "phase6c_mock_approval_store_invalid",
            "Phase 6C mock approval store attestation is invalid",
        )
    try:
        ProductionMockApprovalStore.model_validate(store.model_dump(), strict=True)
    except (TypeError, ValueError) as exc:
        raise ProductionApprovalStateError(
            "phase6c_mock_approval_store_invalid",
            "Phase 6C mock approval store attestation is invalid",
        ) from exc
    if not hmac.compare_digest(
        calculate_phase6c_mock_approval_store_hash(store),
        store.content_hash,
    ):
        raise ProductionApprovalStateError(
            "phase6c_mock_approval_store_hash_mismatch",
            "Phase 6C mock approval store integrity verification failed",
        )


def private_production_arm_receipt_data(
    receipt: ProductionArmReceipt,
) -> dict[str, object]:
    """Return canonical raw-free ARM receipt data."""

    return {
        "schema_version": receipt.schema_version,
        "receipt_type": receipt.receipt_type,
        "production": receipt.production,
        "target_safe_ref": receipt.target_safe_ref,
        "run_spec_hash": receipt.run_spec_hash,
        "plan_hash": receipt.plan_hash,
        "manifest_hash": receipt.manifest_hash,
        "source_sha256": receipt.source_sha256,
        "trusted_baseline_hash": receipt.trusted_baseline_hash,
        "snapshot_hash": receipt.snapshot_hash,
        "operation_count": receipt.operation_count,
        "add_count": receipt.add_count,
        "update_count": receipt.update_count,
        "delete_count": receipt.delete_count,
        "changed_fields": list(receipt.changed_fields),
        "patch_hash": receipt.patch_hash,
        "approval_material_hash": receipt.approval_material_hash,
        "approval_store_hash": receipt.approval_store_hash,
        "arm_nonce": receipt.arm_nonce,
        "kill_switch_generation": receipt.kill_switch_generation,
        "write_token_generation": receipt.write_token_generation,
        "issued_at": receipt.issued_at.isoformat(),
        "expires_at": receipt.expires_at.isoformat(),
        "content_hash": receipt.content_hash,
    }


def calculate_production_arm_receipt_hash(receipt: ProductionArmReceipt) -> str:
    data = private_production_arm_receipt_data(receipt)
    del data["content_hash"]
    return _hash_mapping(_ARM_RECEIPT_HASH_DOMAIN, data)


def build_production_arm_receipt(
    run_spec: ProductionSingleUpdateRunSpec,
    plan: ProductionSingleUpdatePlan,
    kill_switch: ProductionKillSwitch,
    approval_store: ProductionMockApprovalStore,
    *,
    write_token_generation: int,
    arm_nonce: str,
    issued_at: datetime,
    expires_at: datetime | None = None,
) -> ProductionArmReceipt:
    """Build a maximum-ten-minute ARM receipt from intact Phase 6B artifacts."""

    _utc_clock(issued_at, code="production_arm_clock_invalid")
    verify_production_single_update_run_spec_bindings(run_spec, plan, now=issued_at)
    verify_production_approval_material_hash(run_spec, now=issued_at, require_current=True)
    verify_production_kill_switch(
        kill_switch,
        target_safe_ref=run_spec.target_safe_ref,
        require_on=True,
    )
    verify_phase6c_mock_approval_store(approval_store)
    maximum_expiry = min(
        issued_at + timedelta(seconds=PRODUCTION_ARM_MAX_LIFETIME_SECONDS),
        run_spec.expires_at,
    )
    resolved_expiry = maximum_expiry if expires_at is None else expires_at
    if resolved_expiry > maximum_expiry:
        raise ProductionApprovalStateError(
            "production_arm_lifetime_invalid",
            "Production ARM receipt lifetime exceeds its bound",
        )
    try:
        provisional = ProductionArmReceipt(
            target_safe_ref=run_spec.target_safe_ref,
            run_spec_hash=run_spec.run_spec_content_hash,
            plan_hash=plan.plan_content_hash,
            manifest_hash=run_spec.manifest_hash,
            source_sha256=run_spec.source_sha256,
            trusted_baseline_hash=run_spec.trusted_baseline_hash,
            snapshot_hash=run_spec.current_snapshot_hash,
            operation_count=run_spec.operation_count,
            add_count=run_spec.add_count,
            update_count=run_spec.update_count,
            delete_count=run_spec.delete_count,
            changed_fields=run_spec.changed_fields,
            patch_hash=run_spec.operation.patch_hash,
            approval_material_hash=run_spec.approval_material_hash,
            approval_store_hash=approval_store.content_hash,
            arm_nonce=arm_nonce,
            kill_switch_generation=kill_switch.generation,
            write_token_generation=write_token_generation,
            issued_at=issued_at,
            expires_at=resolved_expiry,
            content_hash="0" * 64,
        )
    except ValueError as exc:
        raise ProductionApprovalStateError(
            "production_arm_invalid",
            "Production ARM receipt is invalid",
        ) from exc
    receipt = provisional.model_copy(
        update={"content_hash": calculate_production_arm_receipt_hash(provisional)}
    )
    verify_production_arm_receipt(
        receipt,
        run_spec,
        plan,
        kill_switch,
        approval_store,
        write_token_generation=write_token_generation,
        now=issued_at,
    )
    return receipt


def verify_production_arm_receipt_integrity(
    receipt: ProductionArmReceipt,
    *,
    now: datetime | None = None,
    require_current: bool = True,
) -> None:
    """Verify the closed ARM policy, integrity hash, and optional freshness."""

    if not isinstance(receipt, ProductionArmReceipt):
        raise ProductionApprovalStateError(
            "production_arm_invalid",
            "Production ARM receipt is invalid",
        )
    try:
        ProductionArmReceipt.model_validate(receipt.model_dump(), strict=True)
    except (TypeError, ValueError) as exc:
        raise ProductionApprovalStateError(
            "production_arm_invalid",
            "Production ARM receipt is invalid",
        ) from exc
    if not hmac.compare_digest(
        calculate_production_arm_receipt_hash(receipt),
        receipt.content_hash,
    ):
        raise ProductionApprovalStateError(
            "production_arm_hash_mismatch",
            "Production ARM receipt integrity verification failed",
        )
    if require_current:
        current_time = datetime.now(UTC) if now is None else now
        _utc_clock(current_time, code="production_arm_clock_invalid")
        if current_time < receipt.issued_at:
            raise ProductionApprovalStateError(
                "production_arm_not_yet_valid",
                "Production ARM receipt is not yet valid",
            )
        if current_time >= receipt.expires_at:
            raise ProductionApprovalStateError(
                "production_arm_expired",
                "Production ARM receipt has expired",
            )


def verify_production_arm_receipt(
    receipt: ProductionArmReceipt,
    run_spec: ProductionSingleUpdateRunSpec,
    plan: ProductionSingleUpdatePlan,
    kill_switch: ProductionKillSwitch,
    approval_store: ProductionMockApprovalStore,
    *,
    write_token_generation: int,
    now: datetime,
) -> None:
    """Verify every ARM binding against current immutable inputs and generations."""

    verify_production_arm_receipt_integrity(receipt, now=now)
    verify_production_single_update_run_spec_bindings(run_spec, plan, now=now)
    verify_production_approval_material_hash(run_spec, now=now, require_current=True)
    verify_production_kill_switch(
        kill_switch,
        target_safe_ref=run_spec.target_safe_ref,
        required_generation=receipt.kill_switch_generation,
        require_on=True,
    )
    verify_phase6c_mock_approval_store(approval_store)
    valid = (
        receipt.expires_at <= run_spec.expires_at
        and receipt.operation_count == run_spec.operation_count == 1
        and receipt.add_count == run_spec.add_count == 0
        and receipt.update_count == run_spec.update_count == 1
        and receipt.delete_count == run_spec.delete_count == 0
        and receipt.changed_fields
        == run_spec.changed_fields
        == PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
        and _valid_generation(write_token_generation, allow_zero=False)
        and receipt.write_token_generation == write_token_generation
        and _same(
            (receipt.target_safe_ref, run_spec.target_safe_ref),
            (receipt.run_spec_hash, run_spec.run_spec_content_hash),
            (receipt.plan_hash, plan.plan_content_hash),
            (receipt.manifest_hash, run_spec.manifest_hash),
            (receipt.source_sha256, run_spec.source_sha256),
            (receipt.trusted_baseline_hash, run_spec.trusted_baseline_hash),
            (receipt.snapshot_hash, run_spec.current_snapshot_hash),
            (receipt.patch_hash, run_spec.operation.patch_hash),
            (receipt.approval_material_hash, run_spec.approval_material_hash),
            (receipt.approval_store_hash, approval_store.content_hash),
        )
    )
    if not valid:
        raise ProductionApprovalStateError(
            "production_arm_binding_mismatch",
            "Production ARM receipt binding does not match",
        )


def production_arm_challenge(receipt: ProductionArmReceipt) -> str:
    """Return the exact, case-sensitive, whitespace-sensitive ARM phrase."""

    verify_production_arm_receipt_integrity(receipt, require_current=False)
    return (
        f"ARM PRODUCTION CALENDAR WRITE {receipt.target_safe_ref} "
        f"R-{receipt.run_spec_hash[:12]} P-{receipt.plan_hash[:12]} "
        f"X-{receipt.content_hash[:12]} U-1"
    )


def verify_production_arm_confirmation(
    receipt: ProductionArmReceipt,
    confirmation: str,
) -> None:
    expected = production_arm_challenge(receipt)
    try:
        valid = hmac.compare_digest(
            confirmation.encode("utf-8", errors="strict"),
            expected.encode("utf-8", errors="strict"),
        )
    except (AttributeError, UnicodeError):
        valid = False
    if not valid:
        raise ProductionApprovalStateError(
            "production_arm_confirmation_mismatch",
            "Production ARM confirmation did not exactly match",
        )


def private_production_execute_permit_data(
    permit: ProductionExecutePermit,
) -> dict[str, object]:
    """Return canonical raw-free EXECUTE permit data."""

    return {
        "schema_version": permit.schema_version,
        "permit_type": permit.permit_type,
        "production": permit.production,
        "arm_receipt_hash": permit.arm_receipt_hash,
        "run_spec_hash": permit.run_spec_hash,
        "target_safe_ref": permit.target_safe_ref,
        "operation_count": permit.operation_count,
        "add_count": permit.add_count,
        "update_count": permit.update_count,
        "delete_count": permit.delete_count,
        "changed_fields": list(permit.changed_fields),
        "patch_hash": permit.patch_hash,
        "approval_store_hash": permit.approval_store_hash,
        "arm_nonce": permit.arm_nonce,
        "execute_nonce": permit.execute_nonce,
        "kill_switch_generation": permit.kill_switch_generation,
        "write_token_generation": permit.write_token_generation,
        "issued_at": permit.issued_at.isoformat(),
        "expires_at": permit.expires_at.isoformat(),
        "one_time": permit.one_time,
        "consumed": permit.consumed,
        "content_hash": permit.content_hash,
    }


def calculate_production_execute_permit_hash(permit: ProductionExecutePermit) -> str:
    data = private_production_execute_permit_data(permit)
    del data["content_hash"]
    return _hash_mapping(_EXECUTE_PERMIT_HASH_DOMAIN, data)


def build_production_execute_permit(
    receipt: ProductionArmReceipt,
    run_spec: ProductionSingleUpdateRunSpec,
    plan: ProductionSingleUpdatePlan,
    kill_switch: ProductionKillSwitch,
    approval_store: ProductionMockApprovalStore,
    *,
    arm_confirmation: str,
    write_token_generation: int,
) -> ProductionExecutePermit:
    """Build the sole deterministic permit for one intact ARM receipt."""

    issued_at = receipt.issued_at
    _utc_clock(issued_at, code="production_execute_clock_invalid")
    verify_production_arm_receipt(
        receipt,
        run_spec,
        plan,
        kill_switch,
        approval_store,
        write_token_generation=write_token_generation,
        now=issued_at,
    )
    verify_production_arm_confirmation(receipt, arm_confirmation)
    resolved_expiry = min(receipt.expires_at, run_spec.expires_at)
    try:
        provisional = ProductionExecutePermit(
            arm_receipt_hash=receipt.content_hash,
            run_spec_hash=run_spec.run_spec_content_hash,
            target_safe_ref=receipt.target_safe_ref,
            operation_count=receipt.operation_count,
            add_count=receipt.add_count,
            update_count=receipt.update_count,
            delete_count=receipt.delete_count,
            changed_fields=receipt.changed_fields,
            patch_hash=receipt.patch_hash,
            approval_store_hash=receipt.approval_store_hash,
            arm_nonce=receipt.arm_nonce,
            execute_nonce=derive_production_execute_nonce(
                receipt.content_hash,
                receipt.arm_nonce,
            ),
            kill_switch_generation=receipt.kill_switch_generation,
            write_token_generation=receipt.write_token_generation,
            issued_at=issued_at,
            expires_at=resolved_expiry,
            content_hash="0" * 64,
        )
    except ValueError as exc:
        raise ProductionApprovalStateError(
            "production_execute_permit_invalid",
            "Production EXECUTE permit is invalid",
        ) from exc
    permit = provisional.model_copy(
        update={"content_hash": calculate_production_execute_permit_hash(provisional)}
    )
    verify_production_execute_permit(
        permit,
        receipt,
        run_spec,
        plan,
        kill_switch,
        approval_store,
        write_token_generation=write_token_generation,
        now=issued_at,
    )
    return permit


def verify_production_execute_permit_integrity(
    permit: ProductionExecutePermit,
    *,
    now: datetime | None = None,
    require_current: bool = True,
) -> None:
    """Verify closed EXECUTE policy, hash, and optional freshness."""

    if not isinstance(permit, ProductionExecutePermit):
        raise ProductionApprovalStateError(
            "production_execute_permit_invalid",
            "Production EXECUTE permit is invalid",
        )
    try:
        ProductionExecutePermit.model_validate(permit.model_dump(), strict=True)
    except (TypeError, ValueError) as exc:
        raise ProductionApprovalStateError(
            "production_execute_permit_invalid",
            "Production EXECUTE permit is invalid",
        ) from exc
    if not hmac.compare_digest(
        calculate_production_execute_permit_hash(permit),
        permit.content_hash,
    ):
        raise ProductionApprovalStateError(
            "production_execute_permit_hash_mismatch",
            "Production EXECUTE permit integrity verification failed",
        )
    if require_current:
        current_time = datetime.now(UTC) if now is None else now
        _utc_clock(current_time, code="production_execute_clock_invalid")
        if current_time < permit.issued_at:
            raise ProductionApprovalStateError(
                "production_execute_permit_not_yet_valid",
                "Production EXECUTE permit is not yet valid",
            )
        if current_time >= permit.expires_at:
            raise ProductionApprovalStateError(
                "production_execute_permit_expired",
                "Production EXECUTE permit has expired",
            )


def verify_production_execute_permit(
    permit: ProductionExecutePermit,
    receipt: ProductionArmReceipt,
    run_spec: ProductionSingleUpdateRunSpec,
    plan: ProductionSingleUpdatePlan,
    kill_switch: ProductionKillSwitch,
    approval_store: ProductionMockApprovalStore,
    *,
    write_token_generation: int,
    now: datetime,
) -> None:
    """Verify the complete ARM-to-EXECUTE chain and current generations."""

    verify_production_execute_permit_integrity(permit, now=now)
    verify_production_arm_receipt(
        receipt,
        run_spec,
        plan,
        kill_switch,
        approval_store,
        write_token_generation=write_token_generation,
        now=now,
    )
    verify_production_kill_switch(
        kill_switch,
        target_safe_ref=permit.target_safe_ref,
        required_generation=permit.kill_switch_generation,
        require_on=True,
    )
    valid = (
        permit.issued_at == receipt.issued_at
        and permit.expires_at <= receipt.expires_at
        and permit.expires_at <= run_spec.expires_at
        and permit.operation_count == receipt.operation_count == run_spec.operation_count == 1
        and permit.add_count == receipt.add_count == run_spec.add_count == 0
        and permit.update_count == receipt.update_count == run_spec.update_count == 1
        and permit.delete_count == receipt.delete_count == run_spec.delete_count == 0
        and permit.changed_fields
        == receipt.changed_fields
        == run_spec.changed_fields
        == PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
        and _valid_generation(write_token_generation, allow_zero=False)
        and permit.write_token_generation
        == receipt.write_token_generation
        == write_token_generation
        and permit.kill_switch_generation == receipt.kill_switch_generation
        and _same(
            (permit.arm_receipt_hash, receipt.content_hash),
            (permit.run_spec_hash, run_spec.run_spec_content_hash),
            (permit.target_safe_ref, receipt.target_safe_ref),
            (permit.target_safe_ref, run_spec.target_safe_ref),
            (permit.patch_hash, receipt.patch_hash),
            (permit.patch_hash, run_spec.operation.patch_hash),
            (permit.arm_nonce, receipt.arm_nonce),
            (permit.approval_store_hash, receipt.approval_store_hash),
            (permit.approval_store_hash, approval_store.content_hash),
        )
    )
    if not valid:
        raise ProductionApprovalStateError(
            "production_execute_permit_binding_mismatch",
            "Production EXECUTE permit binding does not match",
        )


def production_execute_challenge(permit: ProductionExecutePermit) -> str:
    """Return the exact, case-sensitive, whitespace-sensitive EXECUTE phrase."""

    verify_production_execute_permit_integrity(permit, require_current=False)
    return (
        f"EXECUTE PRODUCTION CALENDAR WRITE {permit.target_safe_ref} "
        f"R-{permit.run_spec_hash[:12]} X-{permit.content_hash[:12]} U-1"
    )


def verify_production_execute_confirmation(
    permit: ProductionExecutePermit,
    confirmation: str,
) -> None:
    expected = production_execute_challenge(permit)
    try:
        valid = hmac.compare_digest(
            confirmation.encode("utf-8", errors="strict"),
            expected.encode("utf-8", errors="strict"),
        )
    except (AttributeError, UnicodeError):
        valid = False
    if not valid:
        raise ProductionApprovalStateError(
            "production_execute_confirmation_mismatch",
            "Production EXECUTE confirmation did not exactly match",
        )


def private_production_permit_consumption_data(
    consumption: ProductionExecutePermitConsumption,
) -> dict[str, object]:
    """Return canonical durable consumption data."""

    return {
        "schema_version": consumption.schema_version,
        "state_type": consumption.state_type,
        "state": consumption.state,
        "permit_hash": consumption.permit_hash,
        "approval_store_hash": consumption.approval_store_hash,
        "target_safe_ref": consumption.target_safe_ref,
        "consumed_at": consumption.consumed_at.isoformat(),
        "content_hash": consumption.content_hash,
    }


def calculate_production_permit_consumption_hash(
    consumption: ProductionExecutePermitConsumption,
) -> str:
    data = private_production_permit_consumption_data(consumption)
    del data["content_hash"]
    return _hash_mapping(_PERMIT_CONSUMPTION_HASH_DOMAIN, data)


def build_production_permit_consumption(
    permit: ProductionExecutePermit,
    *,
    consumed_at: datetime,
) -> ProductionExecutePermitConsumption:
    """Build the durable state published atomically before any API call."""

    verify_production_execute_permit_integrity(permit, now=consumed_at)
    provisional = ProductionExecutePermitConsumption(
        permit_hash=permit.content_hash,
        approval_store_hash=permit.approval_store_hash,
        target_safe_ref=permit.target_safe_ref,
        consumed_at=consumed_at,
        content_hash="0" * 64,
    )
    result = provisional.model_copy(
        update={"content_hash": calculate_production_permit_consumption_hash(provisional)}
    )
    verify_production_permit_consumption(result, permit=permit)
    return result


def verify_production_permit_consumption(
    consumption: ProductionExecutePermitConsumption,
    *,
    permit: ProductionExecutePermit | None = None,
) -> None:
    """Verify a durable consumed state and its optional permit binding."""

    try:
        valid_type = isinstance(consumption, ProductionExecutePermitConsumption)
        if valid_type:
            ProductionExecutePermitConsumption.model_validate(
                consumption.model_dump(),
                strict=True,
            )
        valid = valid_type and hmac.compare_digest(
            calculate_production_permit_consumption_hash(consumption),
            consumption.content_hash,
        )
    except (TypeError, ValueError):
        valid = False
    if not valid:
        raise ProductionApprovalStateError(
            "production_execute_consumption_invalid",
            "Production EXECUTE permit consumption state is invalid",
        )
    if permit is not None and not _same(
        (consumption.permit_hash, permit.content_hash),
        (consumption.approval_store_hash, permit.approval_store_hash),
        (consumption.target_safe_ref, permit.target_safe_ref),
    ):
        raise ProductionApprovalStateError(
            "production_execute_consumption_binding_mismatch",
            "Production EXECUTE permit consumption binding does not match",
        )


__all__ = [
    "ProductionApprovalStateError",
    "build_production_arm_receipt",
    "build_production_execute_permit",
    "build_production_kill_switch",
    "build_production_permit_consumption",
    "calculate_phase6c_mock_approval_store_hash",
    "calculate_production_arm_receipt_hash",
    "calculate_production_execute_permit_hash",
    "calculate_production_kill_switch_hash",
    "calculate_production_permit_consumption_hash",
    "derive_production_execute_nonce",
    "private_phase6c_mock_approval_store_data",
    "private_production_arm_receipt_data",
    "private_production_execute_permit_data",
    "private_production_kill_switch_data",
    "private_production_permit_consumption_data",
    "production_arm_challenge",
    "production_execute_challenge",
    "transition_production_kill_switch",
    "verify_phase6c_mock_approval_store",
    "verify_production_arm_confirmation",
    "verify_production_arm_receipt",
    "verify_production_arm_receipt_integrity",
    "verify_production_execute_confirmation",
    "verify_production_execute_permit",
    "verify_production_execute_permit_integrity",
    "verify_production_kill_switch",
    "verify_production_kill_switch_transition",
    "verify_production_permit_consumption",
]
