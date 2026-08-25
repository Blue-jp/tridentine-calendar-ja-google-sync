"""Strict public-safe models for one Test-only Description update plan."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.models import StrictFrozenModel

ALLOWED_SINGLE_UPDATE_ORIGINAL_GUARDS = (
    "all_events_update",
    "mass_change_guard",
)
PRODUCTION_SOURCE_PROFILE_ID = "accepted-20260814"
PRODUCTION_ACCEPTED_TAG = "ja-localization-accepted-20260814"
SINGLE_UPDATE_CHANGED_FIELDS: tuple[Literal["description"], ...] = ("description",)


class TestSingleUpdateEligibility(StrictFrozenModel):
    """Content-free evidence returned only after every update guard passes."""

    eligible: Literal[True] = True
    target_fingerprint: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        repr=False,
        exclude=True,
    )
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    safe_uid_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    baseline_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    diff_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    original_guard_codes: tuple[str, ...]

    @model_validator(mode="after")
    def eligibility_evidence_is_coherent(self) -> Self:
        if self.target_safe_ref != f"T-{self.target_fingerprint[:12]}":
            raise ValueError("Single Update eligibility target reference is invalid")
        if self.target_safe_ref == PRODUCTION_TARGET_REFERENCE:
            raise ValueError("Production target is forbidden")
        if self.original_guard_codes != ALLOWED_SINGLE_UPDATE_ORIGINAL_GUARDS:
            raise ValueError("Single Update original guards are not exactly allowlisted")
        return self


class TestSingleUpdatePlan(StrictFrozenModel):
    """Non-executable Test-only plan for one managed Description update."""

    schema_version: Literal["1.0"] = "1.0"
    plan_type: Literal["test_single_update"] = "test_single_update"
    test_only: Literal[True] = True
    single_update_only: Literal[True] = True
    production_locked: Literal[True] = True
    executable: Literal[False] = False
    tool_version: str = Field(min_length=1)
    target_fingerprint: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        repr=False,
        exclude=True,
    )
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    target_environment: Literal["test"] = "test"
    target_label: Literal["test"] = "test"
    target_purpose: Literal["test_calendar_write_acceptance"] = "test_calendar_write_acceptance"
    baseline_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_state: Literal["trusted"] = "trusted"
    managed_uid_count: Literal[1] = 1
    source_profile: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_event_count: Literal[1] = 1
    snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_event_count: Literal[1] = 1
    diff_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_count: Literal[1] = 1
    add_count: Literal[0] = 0
    update_count: Literal[1] = 1
    delete_count: Literal[0] = 0
    changed_fields: tuple[str, ...] = SINGLE_UPDATE_CHANGED_FIELDS
    safe_uid_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    original_guard_codes: tuple[str, ...]
    eligibility: Literal["eligible"] = "eligible"
    approval_required: Literal[True] = True
    plan_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def fixed_single_update_contract_is_coherent(self) -> Self:
        if self.target_safe_ref != f"T-{self.target_fingerprint[:12]}":
            raise ValueError("Single Update target reference does not match fingerprint")
        if self.target_safe_ref == PRODUCTION_TARGET_REFERENCE:
            raise ValueError("Production target is forbidden")
        if self.source_profile == PRODUCTION_SOURCE_PROFILE_ID:
            raise ValueError("Production source profile is forbidden")
        if self.baseline_snapshot_hash != self.snapshot_hash:
            raise ValueError("Trusted baseline snapshot does not match current snapshot")
        if self.changed_fields != SINGLE_UPDATE_CHANGED_FIELDS:
            raise ValueError("Single Update changed fields must be Description only")
        if self.original_guard_codes != ALLOWED_SINGLE_UPDATE_ORIGINAL_GUARDS:
            raise ValueError("Single Update original guards are not exactly allowlisted")
        return self


__all__ = [
    "ALLOWED_SINGLE_UPDATE_ORIGINAL_GUARDS",
    "PRODUCTION_ACCEPTED_TAG",
    "PRODUCTION_SOURCE_PROFILE_ID",
    "SINGLE_UPDATE_CHANGED_FIELDS",
    "TestSingleUpdateEligibility",
    "TestSingleUpdatePlan",
]
