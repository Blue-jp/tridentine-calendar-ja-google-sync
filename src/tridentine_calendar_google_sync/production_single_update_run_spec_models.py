"""Closed raw-content-free Run Spec models for one Production update."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.production_single_update_plan_models import (
    PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS,
)

PRODUCTION_RUN_SPEC_MAX_LIFETIME_SECONDS = 24 * 60 * 60


class ProductionSingleUpdateOperation(StrictFrozenModel):
    """One content-addressed update with no raw values or transport identity."""

    operation: Literal["update"] = "update"
    safe_uid_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    google_ref: str = Field(pattern=r"^G-[0-9a-f]{12}$")
    changed_fields: tuple[Literal["description"], ...] = PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
    pre_image_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    patch_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def description_update_only(self) -> Self:
        if self.changed_fields != PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS:
            raise ValueError("Production operation must change Description only")
        return self


class ProductionSingleUpdateRunSpec(StrictFrozenModel):
    """Integrity-pinned offline contract without execution authority."""

    schema_version: Literal["1.0"] = "1.0"
    run_type: Literal["production-single-update-run-spec-v1"] = (
        "production-single-update-run-spec-v1"
    )
    planning_mode: Literal["production_single_update"] = "production_single_update"
    production: Literal[True] = True
    production_only: Literal[True] = True
    synthetic: Literal[False] = False
    single_update: Literal[True] = True
    update_only: Literal[True] = True
    executable: Literal[False] = False
    tool_version: str = Field(min_length=1)
    issued_at: datetime
    expires_at: datetime
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False, exclude=True)
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    target_config_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_environment: Literal["production"] = "production"
    baseline_state: Literal["trusted"] = "trusted"
    trusted_baseline_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_profile: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    accepted_tag: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
    accepted_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_event_count: int = Field(ge=2)
    current_snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_event_count: int = Field(ge=2)
    diff_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    production_plan_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    unchanged_count: int = Field(ge=1)
    operation_count: Literal[1] = 1
    add_count: Literal[0] = 0
    update_count: Literal[1] = 1
    delete_count: Literal[0] = 0
    changed_fields: tuple[Literal["description"], ...] = PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
    operation: ProductionSingleUpdateOperation
    approval_required: Literal[True] = True
    approval_material_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    run_spec_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def fixed_contract_and_lifetime(self) -> Self:
        issued_offset = self.issued_at.utcoffset()
        expires_offset = self.expires_at.utcoffset()
        lifetime = (self.expires_at - self.issued_at).total_seconds()
        if (
            issued_offset is None
            or expires_offset is None
            or issued_offset.total_seconds() != 0
            or expires_offset.total_seconds() != 0
            or not 0 < lifetime <= PRODUCTION_RUN_SPEC_MAX_LIFETIME_SECONDS
            or self.target_safe_ref != f"T-{self.target_fingerprint[:12]}"
            or self.baseline_snapshot_hash != self.current_snapshot_hash
            or self.source_event_count != self.snapshot_event_count
            or self.unchanged_count != self.source_event_count - 1
            or self.changed_fields != PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
            or self.operation.changed_fields != PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
        ):
            raise ValueError("Production Single Update Run Spec policy is invalid")
        return self

    @property
    def plan_hash(self) -> str:
        """Expose the dedicated Plan binding through a stable compatibility name."""

        return self.production_plan_hash


__all__ = [
    "PRODUCTION_RUN_SPEC_MAX_LIFETIME_SECONDS",
    "ProductionSingleUpdateOperation",
    "ProductionSingleUpdateRunSpec",
]
