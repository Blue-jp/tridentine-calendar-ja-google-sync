"""Closed, raw-free approval-state models for mock Production execution."""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.production_single_update_plan_models import (
    PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS,
)

PRODUCTION_ARM_MAX_LIFETIME_SECONDS = 10 * 60
_EXECUTE_NONCE_DOMAIN = b"tridentine-calendar-google-sync:execute-nonce:v1\x00"


def _is_utc(value: datetime) -> bool:
    offset = value.utcoffset()
    return offset is not None and offset.total_seconds() == 0


def derive_production_execute_nonce(arm_receipt_hash: str, arm_nonce: str) -> str:
    """Derive the sole permitted EXECUTE nonce for one ARM receipt."""

    if (
        len(arm_receipt_hash) != 64
        or any(character not in "0123456789abcdef" for character in arm_receipt_hash)
        or len(arm_nonce) != 32
        or any(character not in "0123456789abcdef" for character in arm_nonce)
    ):
        raise ValueError("Production EXECUTE nonce inputs are invalid")
    material = f"{arm_receipt_hash}:{arm_nonce}".encode("ascii")
    return hashlib.sha256(_EXECUTE_NONCE_DOMAIN + material).hexdigest()[:32]


class ProductionKillSwitch(StrictFrozenModel):
    """Content-addressed, default-off Production kill-switch state."""

    schema_version: Literal["1.0"] = "1.0"
    switch_type: Literal["production-single-update-kill-switch-v1"] = (
        "production-single-update-kill-switch-v1"
    )
    state: Literal["off", "on"] = "off"
    generation: int = Field(ge=0)
    transition_kind: Literal["initial", "transition"] = "initial"
    previous_switch_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    issued_at: datetime
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def fixed_contract(self) -> Self:
        initial = (
            self.transition_kind == "initial"
            and self.state == "off"
            and self.generation == 0
            and self.previous_switch_hash is None
        )
        transition = (
            self.transition_kind == "transition"
            and self.generation >= 1
            and self.previous_switch_hash is not None
        )
        if not _is_utc(self.issued_at) or not (initial or transition):
            raise ValueError("Production kill-switch issue time must be UTC")
        return self


class ProductionMockApprovalStore(StrictFrozenModel):
    """Exact Phase 6C mock store attestation with no private-DACL claim."""

    schema_version: Literal["1.0"] = "1.0"
    store_type: Literal["phase6c-mock-approval-store-v1"] = "phase6c-mock-approval-store-v1"
    mock_only: Literal[True] = True
    live_capable: Literal[False] = False
    private_dacl_assured: Literal[False] = False
    phase6d_private_dacl_review_required: Literal[True] = True
    directory_identity_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    store_safe_ref: str = Field(pattern=r"^S-[0-9a-f]{12}$")
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def fixed_contract(self) -> Self:
        if self.store_safe_ref != f"S-{self.directory_identity_hash[:12]}":
            raise ValueError("Phase 6C mock approval store identity is invalid")
        return self


class ProductionArmReceipt(StrictFrozenModel):
    """Short-lived first-stage approval bound to every static write input."""

    schema_version: Literal["1.0"] = "1.0"
    receipt_type: Literal["production-single-update-arm-receipt-v1"] = (
        "production-single-update-arm-receipt-v1"
    )
    production: Literal[True] = True
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    run_spec_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_baseline_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_count: Literal[1] = 1
    add_count: Literal[0] = 0
    update_count: Literal[1] = 1
    delete_count: Literal[0] = 0
    changed_fields: tuple[Literal["description"], ...] = PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
    patch_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    approval_material_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    approval_store_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    arm_nonce: str = Field(pattern=r"^[0-9a-f]{32}$", repr=False)
    kill_switch_generation: int = Field(ge=0)
    write_token_generation: int = Field(ge=1)
    issued_at: datetime
    expires_at: datetime
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def fixed_contract_and_lifetime(self) -> Self:
        lifetime = (self.expires_at - self.issued_at).total_seconds()
        if (
            not _is_utc(self.issued_at)
            or not _is_utc(self.expires_at)
            or not 0 < lifetime <= PRODUCTION_ARM_MAX_LIFETIME_SECONDS
            or self.changed_fields != PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
        ):
            raise ValueError("Production ARM receipt policy is invalid")
        return self


class ProductionExecutePermit(StrictFrozenModel):
    """Second-stage one-time permit; durable consumption is stored separately."""

    schema_version: Literal["1.0"] = "1.0"
    permit_type: Literal["production-single-update-execute-permit-v1"] = (
        "production-single-update-execute-permit-v1"
    )
    production: Literal[True] = True
    arm_receipt_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_spec_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    operation_count: Literal[1] = 1
    add_count: Literal[0] = 0
    update_count: Literal[1] = 1
    delete_count: Literal[0] = 0
    changed_fields: tuple[Literal["description"], ...] = PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
    patch_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    approval_store_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    arm_nonce: str = Field(pattern=r"^[0-9a-f]{32}$", repr=False)
    execute_nonce: str = Field(pattern=r"^[0-9a-f]{32}$", repr=False)
    kill_switch_generation: int = Field(ge=0)
    write_token_generation: int = Field(ge=1)
    issued_at: datetime
    expires_at: datetime
    one_time: Literal[True] = True
    consumed: Literal[False] = False
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def fixed_contract_and_lifetime(self) -> Self:
        if (
            not _is_utc(self.issued_at)
            or not _is_utc(self.expires_at)
            or self.expires_at <= self.issued_at
            or self.changed_fields != PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
            or self.execute_nonce
            != derive_production_execute_nonce(self.arm_receipt_hash, self.arm_nonce)
        ):
            raise ValueError("Production EXECUTE permit policy is invalid")
        return self


class ProductionExecutePermitConsumption(StrictFrozenModel):
    """Durable one-winner record written before the first mock API call."""

    schema_version: Literal["1.0"] = "1.0"
    state_type: Literal["production-execute-permit-consumption-v1"] = (
        "production-execute-permit-consumption-v1"
    )
    state: Literal["consumed"] = "consumed"
    permit_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    approval_store_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    consumed_at: datetime
    content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def fixed_contract(self) -> Self:
        if not _is_utc(self.consumed_at):
            raise ValueError("Production permit consumption time must be UTC")
        return self


__all__ = [
    "PRODUCTION_ARM_MAX_LIFETIME_SECONDS",
    "ProductionArmReceipt",
    "ProductionExecutePermit",
    "ProductionExecutePermitConsumption",
    "ProductionKillSwitch",
    "ProductionMockApprovalStore",
    "derive_production_execute_nonce",
]
