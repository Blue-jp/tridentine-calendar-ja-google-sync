"""Closed public-safe models for accepted Production baseline pins."""

from __future__ import annotations

from typing import Final, Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.models import StrictFrozenModel

ACCEPTED_PRODUCTION_BASELINE_SOURCE_REPOSITORY: Final = "Blue-jp/tridentine_calendar"
ACCEPTED_PRODUCTION_BASELINE_SYNC_REPOSITORY: Final = "Blue-jp/tridentine-calendar-ja-google-sync"

_NONPRODUCTION_MARKERS = ("test", "synthetic", "テスト", "架空", ".invalid")


def _contains_nonproduction_marker(value: str) -> bool:
    folded = value.casefold()
    return any(marker.casefold() in folded for marker in _NONPRODUCTION_MARKERS)


class AcceptedProductionBaselinePin(StrictFrozenModel):
    """One reviewable full-hash pin for a private Trusted Baseline."""

    pin_id: str = Field(pattern=r"^production-baseline-g[0-9]{4,}$")
    generation: int = Field(ge=1)
    previous_pin_content_hash: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    baseline_schema_version: Literal["1.0"] = "1.0"
    tool_version: str = Field(min_length=1, max_length=128)
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    source_profile: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    accepted_tag: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
    accepted_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_event_count: int = Field(ge=2)
    snapshot_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    snapshot_event_count: int = Field(ge=2)
    diff_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    managed_uid_count: int = Field(ge=2)
    candidate_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    trusted_baseline_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    pin_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def fixed_contract_is_coherent(self) -> Self:
        expected_pin_id = f"production-baseline-g{self.generation:04d}"
        first_generation = self.generation == 1 and self.previous_pin_content_hash is None
        later_generation = self.generation > 1 and self.previous_pin_content_hash is not None
        if (
            self.pin_id != expected_pin_id
            or not (first_generation or later_generation)
            or self.source_event_count != self.snapshot_event_count
            or self.source_event_count != self.managed_uid_count
            or self.candidate_content_hash == self.trusted_baseline_content_hash
            or "accepted" not in self.source_profile.casefold()
            or "accepted" not in self.accepted_tag.casefold()
            or _contains_nonproduction_marker(self.source_profile)
            or _contains_nonproduction_marker(self.accepted_tag)
        ):
            raise ValueError("Accepted Production baseline pin policy is invalid")
        return self


class AcceptedProductionBaselineRegistry(StrictFrozenModel):
    """Packaged append-only registry whose final pin is the sole active pin."""

    schema_version: Literal["1.0"] = "1.0"
    registry_type: Literal["accepted_production_baseline_registry"] = (
        "accepted_production_baseline_registry"
    )
    production: Literal[True] = True
    synthetic: Literal[False] = False
    source_repository: Literal["Blue-jp/tridentine_calendar"] = (
        ACCEPTED_PRODUCTION_BASELINE_SOURCE_REPOSITORY
    )
    sync_repository: Literal["Blue-jp/tridentine-calendar-ja-google-sync"] = (
        ACCEPTED_PRODUCTION_BASELINE_SYNC_REPOSITORY
    )
    active_pin_id: str | None = Field(
        default=None,
        pattern=r"^production-baseline-g[0-9]{4,}$",
    )
    pins: tuple[AcceptedProductionBaselinePin, ...] = ()
    registry_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def generation_chain_is_coherent(self) -> Self:
        if not self.pins and self.active_pin_id is not None:
            raise ValueError("Empty baseline registry cannot have an active pin")
        if not self.pins:
            return self

        if self.active_pin_id != self.pins[-1].pin_id:
            raise ValueError("Active baseline pin must be the newest generation")
        if len({pin.pin_id for pin in self.pins}) != len(self.pins):
            raise ValueError("Accepted Production baseline pin IDs must be unique")
        if len({pin.generation for pin in self.pins}) != len(self.pins):
            raise ValueError("Accepted Production baseline generations must be unique")

        for index, pin in enumerate(self.pins, start=1):
            if pin.generation != index:
                raise ValueError("Accepted Production baseline generations must be contiguous")
            expected_previous = None if index == 1 else self.pins[index - 2].pin_content_hash
            if pin.previous_pin_content_hash != expected_previous:
                raise ValueError("Accepted Production baseline pin chain is invalid")
        return self


__all__ = [
    "ACCEPTED_PRODUCTION_BASELINE_SOURCE_REPOSITORY",
    "ACCEPTED_PRODUCTION_BASELINE_SYNC_REPOSITORY",
    "AcceptedProductionBaselinePin",
    "AcceptedProductionBaselineRegistry",
]
