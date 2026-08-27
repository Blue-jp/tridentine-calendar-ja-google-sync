"""Strict immutable model for one Accepted Production source manifest."""

from __future__ import annotations

from datetime import date
from typing import Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.models import StrictFrozenModel

_FORBIDDEN_MARKERS = ("test", "synthetic", "テスト")


def _contains_forbidden_marker(value: str) -> bool:
    folded = value.casefold()
    return ".invalid" in folded or any(marker.casefold() in folded for marker in _FORBIDDEN_MARKERS)


class AcceptedProductionSourceManifest(StrictFrozenModel):
    """Content-addressed provenance for one clean Accepted Production ICS."""

    schema_version: Literal["1.0"] = "1.0"
    manifest_type: Literal["accepted_production_source"] = "accepted_production_source"
    production: Literal[True] = True
    acceptance_state: Literal["accepted"] = "accepted"
    synthetic: Literal[False] = False
    repository_identity: str = Field(
        pattern=r"^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$",
        min_length=3,
        max_length=201,
    )
    repository_tag: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
    repository_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    ics_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    profile_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    event_count: int = Field(gt=0)
    first_date: date
    last_date: date
    all_day_count: int = Field(ge=0)
    timed_count: int = Field(ge=0)
    recurring_event_count: int = Field(ge=0)
    source_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    manifest_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def accepted_production_contract_is_coherent(self) -> Self:
        """Reject self-contradictory, synthetic, or unaccepted manifests."""

        repository_parts = self.repository_identity.split("/", 1)
        if any(
            part in {".", ".."} or part.casefold().endswith(".git") for part in repository_parts
        ):
            raise ValueError("repository identity is invalid")
        marker_values = (
            self.repository_identity,
            self.repository_tag,
            self.profile_id,
        )
        if any(_contains_forbidden_marker(value) for value in marker_values):
            raise ValueError("Accepted Production source markers are invalid")
        if "accepted" not in self.repository_tag.casefold() or "accepted" not in (
            self.profile_id.casefold()
        ):
            raise ValueError("Accepted Production source lacks accepted provenance")
        if (
            self.repository_commit == "0" * 40
            or self.ics_sha256 == "0" * 64
            or self.source_content_hash == "0" * 64
        ):
            raise ValueError("Accepted Production source provenance is invalid")
        if self.first_date > self.last_date:
            raise ValueError("Accepted Production source date range is invalid")
        if self.all_day_count + self.timed_count != self.event_count:
            raise ValueError("Accepted Production source event counts are inconsistent")
        if self.recurring_event_count > self.event_count:
            raise ValueError("Accepted Production recurring count is inconsistent")
        return self

    @property
    def accepted_tag(self) -> str:
        """Compatibility name for downstream provenance binding."""

        return self.repository_tag

    @property
    def accepted_commit(self) -> str:
        """Compatibility name for downstream provenance binding."""

        return self.repository_commit

    @property
    def source_sha256(self) -> str:
        """Compatibility name for downstream provenance binding."""

        return self.ics_sha256

    @property
    def source_profile(self) -> str:
        """Compatibility name for downstream provenance binding."""

        return self.profile_id

    @property
    def source_event_count(self) -> int:
        """Compatibility name for downstream provenance binding."""

        return self.event_count

    @property
    def recurring_count(self) -> int:
        """Compatibility name for downstream provenance binding."""

        return self.recurring_event_count


__all__ = ["AcceptedProductionSourceManifest"]
