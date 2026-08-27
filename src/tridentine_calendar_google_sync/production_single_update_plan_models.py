"""Closed public-safe models for one offline Production Description update plan."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.models import StrictFrozenModel

PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS: tuple[Literal["description"], ...] = ("description",)


class ProductionSingleUpdateEligibility(StrictFrozenModel):
    """Content-free evidence emitted only after every Production guard passes."""

    eligible: Literal[True] = True
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False, exclude=True)
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    target_config_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    safe_uid_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    google_ref: str = Field(pattern=r"^G-[0-9a-f]{12}$")
    baseline_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    diff_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    pre_image_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    patch_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def target_reference_is_coherent(self) -> Self:
        if self.target_safe_ref != f"T-{self.target_fingerprint[:12]}":
            raise ValueError("Production eligibility target reference is invalid")
        return self


class ProductionSingleUpdatePlan(StrictFrozenModel):
    """Non-executable, raw-content-free plan for one Production update."""

    schema_version: Literal["1.0"] = "1.0"
    plan_type: Literal["production_single_update"] = "production_single_update"
    planning_mode: Literal["production_single_update"] = "production_single_update"
    production: Literal[True] = True
    production_only: Literal[True] = True
    synthetic: Literal[False] = False
    single_update_only: Literal[True] = True
    update_only: Literal[True] = True
    state: Literal["review_required"] = "review_required"
    executable: Literal[False] = False
    tool_version: str = Field(min_length=1)
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$", repr=False, exclude=True)
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    target_config_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_environment: Literal["production"] = "production"
    target_label: Literal["production"] = "production"
    target_purpose: Literal["production_calendar_single_update"] = (
        "production_calendar_single_update"
    )
    baseline_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_state: Literal["trusted"] = "trusted"
    managed_uid_count: int = Field(ge=2)
    manifest_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_profile: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    accepted_tag: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
    accepted_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_event_count: int = Field(ge=2)
    snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_event_count: int = Field(ge=2)
    diff_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    unchanged_count: int = Field(ge=1)
    operation_count: Literal[1] = 1
    add_count: Literal[0] = 0
    update_count: Literal[1] = 1
    delete_count: Literal[0] = 0
    changed_fields: tuple[Literal["description"], ...] = PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
    safe_uid_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    google_ref: str = Field(pattern=r"^G-[0-9a-f]{12}$")
    pre_image_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    patch_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    eligibility: Literal["eligible"] = "eligible"
    approval_required: Literal[True] = True
    plan_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def fixed_contract_is_coherent(self) -> Self:
        if (
            self.target_safe_ref != f"T-{self.target_fingerprint[:12]}"
            or self.baseline_snapshot_hash != self.snapshot_hash
            or self.managed_uid_count != self.source_event_count
            or self.source_event_count != self.snapshot_event_count
            or self.unchanged_count + self.update_count != self.source_event_count
            or self.changed_fields != PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
        ):
            raise ValueError("Production Single Update Plan policy is invalid")
        return self


__all__ = [
    "PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS",
    "ProductionSingleUpdateEligibility",
    "ProductionSingleUpdatePlan",
]
