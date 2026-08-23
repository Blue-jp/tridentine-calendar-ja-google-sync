"""Strict immutable models for candidate and explicitly trusted UID baselines."""

from __future__ import annotations

from enum import StrEnum
from typing import Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.models import StrictFrozenModel


class BaselineState(StrEnum):
    """The only lifecycle states accepted by the baseline contract."""

    CANDIDATE = "candidate"
    TRUSTED = "trusted"


class TrustedBaseline(StrictFrozenModel):
    """Pinned source/snapshot/diff provenance plus an internal UID inventory.

    Raw managed UIDs are deliberately excluded from repr and normal Pydantic
    serialization.  Only the private baseline renderer may serialize them.
    """

    schema_version: str = Field(pattern=r"^1\.0$")
    state: BaselineState
    tool_version: str = Field(min_length=1)
    target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_profile: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    accepted_tag: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
    accepted_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_event_count: int = Field(ge=0)
    snapshot_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_event_count: int = Field(ge=0)
    diff_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    managed_uid_count: int = Field(ge=0)
    managed_uids: tuple[str, ...] = Field(repr=False, exclude=True)
    baseline_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def uid_inventory_is_sorted_unique_and_counted(self) -> Self:
        """Reject duplicate, empty, unsorted, or miscounted UID inventories."""

        if any(uid == "" for uid in self.managed_uids):
            raise ValueError("managed UID values must not be empty")
        if self.managed_uids != tuple(sorted(set(self.managed_uids))):
            raise ValueError("managed UID inventory must be sorted and unique")
        if self.managed_uid_count != len(self.managed_uids):
            raise ValueError("managed UID count does not match the inventory")
        return self


BaselineCandidate = TrustedBaseline


__all__ = ["BaselineCandidate", "BaselineState", "TrustedBaseline"]
