"""Strict public-safe model for one Test-only bootstrap add plan."""

from __future__ import annotations

from typing import Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.models import StrictFrozenModel

ALLOWED_BOOTSTRAP_ORIGINAL_GUARDS = (
    "zero_google_event_count",
    "all_events_add",
    "mass_change_guard",
)
PRODUCTION_SOURCE_PROFILE_ID = "accepted-20260814"
PRODUCTION_ACCEPTED_TAG = "ja-localization-accepted-20260814"


class TestBootstrapEligibility(StrictFrozenModel):
    """Content-free evidence returned only after every bootstrap guard passes."""

    eligible: Literal[True] = True
    target_fingerprint: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        repr=False,
        exclude=True,
    )
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    safe_uid_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    diff_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    original_guard_codes: tuple[str, ...]

    @model_validator(mode="after")
    def eligibility_evidence_is_allowlisted(self) -> Self:
        if self.target_safe_ref != f"T-{self.target_fingerprint[:12]}":
            raise ValueError("Bootstrap eligibility target reference is invalid")
        if self.target_safe_ref == PRODUCTION_TARGET_REFERENCE:
            raise ValueError("Production target is forbidden")
        if self.original_guard_codes != ALLOWED_BOOTSTRAP_ORIGINAL_GUARDS:
            raise ValueError("Bootstrap eligibility guard codes are not exactly allowlisted")
        return self


class TestBootstrapAddPlan(StrictFrozenModel):
    """Non-executable Test-only plan for one synthetic add into an empty calendar."""

    schema_version: Literal["1.0"] = "1.0"
    plan_type: Literal["test_bootstrap_add"] = "test_bootstrap_add"
    test_only: Literal[True] = True
    bootstrap_only: Literal[True] = True
    executable: Literal[False] = False
    production_locked: Literal[True] = True
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
    source_profile: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_event_count: Literal[1] = 1
    snapshot_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_event_count: Literal[0] = 0
    diff_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_count: Literal[1] = 1
    add_count: Literal[1] = 1
    update_count: Literal[0] = 0
    delete_count: Literal[0] = 0
    safe_uid_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    original_guard_codes: tuple[str, ...]
    bootstrap_eligibility: Literal["eligible"] = "eligible"
    approval_required: Literal[True] = True
    plan_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def fixed_bootstrap_contract_is_coherent(self) -> Self:
        if self.target_safe_ref != f"T-{self.target_fingerprint[:12]}":
            raise ValueError("Bootstrap target reference does not match fingerprint")
        if self.target_safe_ref == PRODUCTION_TARGET_REFERENCE:
            raise ValueError("Production target is forbidden")
        if self.source_profile == PRODUCTION_SOURCE_PROFILE_ID:
            raise ValueError("Production source profile is forbidden")
        if self.original_guard_codes != ALLOWED_BOOTSTRAP_ORIGINAL_GUARDS:
            raise ValueError("Bootstrap original guard codes are not exactly allowlisted")
        return self


__all__ = [
    "ALLOWED_BOOTSTRAP_ORIGINAL_GUARDS",
    "PRODUCTION_ACCEPTED_TAG",
    "PRODUCTION_SOURCE_PROFILE_ID",
    "TestBootstrapAddPlan",
    "TestBootstrapEligibility",
]
