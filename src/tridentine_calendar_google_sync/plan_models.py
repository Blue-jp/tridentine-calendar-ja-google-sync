"""Strict content-free models for non-executable synchronization plans."""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.diff_models import DiffCounts
from tridentine_calendar_google_sync.models import StrictFrozenModel

SafeSourceReference = Annotated[str, Field(pattern=r"^U-[0-9a-f]{12}$")]
SafeGoogleReference = Annotated[str, Field(pattern=r"^G-[0-9a-f]{12}$")]
ChangedFieldName = Literal["summary", "description", "start_date", "end_date"]
OwnershipEvidence = Literal[
    "trusted_baseline",
    "trusted_source_uid",
    "trusted_google_event_id",
    "private_extended_property",
]
FindingCode = Annotated[str, Field(pattern=r"^[a-z][a-z0-9_]*$")]


class PlanState(StrEnum):
    """Human review state; no state is executable in Phase 4A."""

    DRAFT = "draft"
    REVIEW_REQUIRED = "review_required"
    BLOCKED = "blocked"


class PlanActionKind(StrEnum):
    """Content-free action vocabulary derived from safe diff classifications."""

    ADD = "add"
    UPDATE = "update"
    DELETE_CANDIDATE = "delete_candidate"


class ChangedFieldCounts(StrictFrozenModel):
    """Aggregate changed-field counts in fixed report order."""

    summary: int = Field(ge=0)
    description: int = Field(ge=0)
    start_date: int = Field(ge=0)
    end_date: int = Field(ge=0)


class DiffSummary(StrictFrozenModel):
    """Redacted aggregate of a CalendarDiff without its event array."""

    counts: DiffCounts
    changed_fields: ChangedFieldCounts
    source_event_count: int = Field(ge=0)
    google_event_count: int = Field(ge=0)
    warning_count: int = Field(ge=0)
    fatal_event_count: int = Field(ge=0)
    proposed_action_count: int = Field(ge=0)
    fatal: bool
    has_changes: bool
    has_ambiguous: bool
    diff_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class PlanSourceProvenance(StrictFrozenModel):
    """Public Accepted-source provenance captured for baseline and current inputs."""

    profile_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    accepted_tag: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
    accepted_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_content_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    event_count: int = Field(ge=0)
    first_date: date | None = None
    last_date: date | None = None


class BaselinePlanProvenance(StrictFrozenModel):
    """Trusted baseline facts required by a plan without exposing managed UIDs."""

    schema_version: str = Field(pattern=r"^1\.0$")
    baseline_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    managed_uid_count: int = Field(ge=0)
    source: PlanSourceProvenance


class PlanThresholds(StrictFrozenModel):
    """Explicit review thresholds; zero is the safe default for every action."""

    max_add: int = Field(default=0, ge=0)
    max_update: int = Field(default=0, ge=0)
    max_delete: int = Field(default=0, ge=0)


class PlanGuard(StrictFrozenModel):
    """One redacted guard observation used to block or flag a plan."""

    severity: Literal["warning", "fatal"]
    code: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    message: str = Field(min_length=1)
    observed_count: int | None = Field(default=None, ge=0)
    limit: int | None = Field(default=None, ge=0)


class PlanAction(StrictFrozenModel):
    """Non-executable content-free action carrying only safe references."""

    action: PlanActionKind
    source_ref: SafeSourceReference | None = None
    google_refs: tuple[SafeGoogleReference, ...] = ()
    source_date: date | None = None
    google_date: date | None = None
    changed_fields: tuple[ChangedFieldName, ...] = ()
    ownership_evidence: tuple[OwnershipEvidence, ...] = ()
    finding_codes: tuple[FindingCode, ...] = ()
    destructive: bool
    separate_approval_required: bool

    @model_validator(mode="after")
    def action_shape_is_safe(self) -> Self:
        """Enforce safe reference and approval shapes for every action kind."""

        if self.action is PlanActionKind.ADD:
            if self.source_ref is None or self.google_refs or self.changed_fields:
                raise ValueError("add action shape is invalid")
            if self.destructive or self.separate_approval_required:
                raise ValueError("add action cannot be destructive")
        elif self.action is PlanActionKind.UPDATE:
            if self.source_ref is None or len(self.google_refs) != 1 or not self.changed_fields:
                raise ValueError("update action shape is invalid")
            if self.destructive or self.separate_approval_required:
                raise ValueError("update action cannot be destructive")
        else:
            if self.source_ref is None or len(self.google_refs) != 1 or self.changed_fields:
                raise ValueError("delete candidate shape is invalid")
            if not self.destructive or not self.separate_approval_required:
                raise ValueError("delete candidate requires separate approval")
        return self


class SyncPlan(StrictFrozenModel):
    """Deterministic review artifact that can never authorize execution."""

    schema_version: Literal["1.0"] = "1.0"
    plan_type: Literal["non-executable-sync-plan-v1"] = "non-executable-sync-plan-v1"
    tool_version: str = Field(min_length=1)
    state: PlanState
    executable: Literal[False] = False
    approval_required: bool
    baseline: BaselinePlanProvenance
    current_source: PlanSourceProvenance
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    diff_summary: DiffSummary
    thresholds: PlanThresholds
    proposed_actions: tuple[PlanAction, ...]
    safety_guards: tuple[PlanGuard, ...]
    plan_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def review_state_matches_guards_and_actions(self) -> Self:
        """Keep blocked/review/draft semantics internally consistent."""

        has_fatal_guard = any(guard.severity == "fatal" for guard in self.safety_guards)
        if self.state is PlanState.BLOCKED and not has_fatal_guard:
            raise ValueError("blocked plan requires a fatal guard")
        if self.state is PlanState.REVIEW_REQUIRED and (
            has_fatal_guard or not self.proposed_actions
        ):
            raise ValueError("review-required plan shape is invalid")
        if self.state is PlanState.DRAFT and (has_fatal_guard or self.proposed_actions):
            raise ValueError("draft plan must be an unblocked zero-action plan")
        if self.state is PlanState.DRAFT and (
            self.diff_summary.has_changes
            or self.diff_summary.fatal
            or self.diff_summary.proposed_action_count != 0
        ):
            raise ValueError("draft plan requires a zero-difference summary")
        if self.approval_required is (self.state is PlanState.DRAFT):
            raise ValueError("approval-required flag does not match plan state")
        return self


__all__ = [
    "BaselinePlanProvenance",
    "ChangedFieldCounts",
    "ChangedFieldName",
    "DiffSummary",
    "FindingCode",
    "OwnershipEvidence",
    "PlanAction",
    "PlanActionKind",
    "PlanGuard",
    "PlanSourceProvenance",
    "PlanState",
    "PlanThresholds",
    "SafeGoogleReference",
    "SafeSourceReference",
    "SyncPlan",
]
