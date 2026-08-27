"""Closed offline configuration for the one approved Production Calendar target."""

from __future__ import annotations

import hashlib
import hmac
import json
import tomllib
from collections.abc import Mapping
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, ValidationError, model_validator

from tridentine_calendar_google_sync.google_target import (
    calendar_id_fingerprint,
    short_target_reference,
)
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    read_sensitive_bytes,
)

PRODUCTION_WRITE_TARGET_PURPOSE = "production_calendar_single_update"
PRODUCTION_WRITE_TIME_ZONE = "Asia/Tokyo"
_TARGET_HASH_DOMAIN = b"tridentine-calendar-google-sync:production-write-target:v1\x00"
_NONPRODUCTION_MARKERS = ("test", "synthetic", "テスト", "架空")


class ProductionWriteTargetError(ValueError):
    """A content-free Production target configuration failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class ProductionWriteTargetConfigError(ProductionWriteTargetError):
    """The private Production target document is malformed or unsafe."""


class ProductionWriteTargetPolicyError(ProductionWriteTargetError):
    """The configured target is not an exact Production write target."""


class ProductionWriteTargetConfig(StrictFrozenModel):
    """Repository-external exact identity for Production offline planning."""

    schema_version: Literal[1]
    target_environment: Literal["production"]
    target_label: Literal["production"]
    target_purpose: Literal["production_calendar_single_update"]
    calendar_id: str = Field(min_length=1, max_length=1024, repr=False, exclude=True)
    expected_target_fingerprint: str = Field(
        pattern=r"^[0-9a-f]{64}$",
        repr=False,
        exclude=True,
    )
    expected_summary: str = Field(min_length=1, max_length=1024, repr=False, exclude=True)
    expected_access_role: Literal["owner"]
    expected_time_zone: Literal["Asia/Tokyo"]

    @model_validator(mode="after")
    def exact_non_test_production_target(self) -> Self:
        if self.calendar_id.casefold() == "primary":
            raise ValueError("the primary calendar alias is forbidden")
        actual = calendar_id_fingerprint(self.calendar_id)
        if not hmac.compare_digest(actual, self.expected_target_fingerprint):
            raise ValueError("the target fingerprint does not match the Calendar ID")
        folded_summary = self.expected_summary.casefold()
        if any(marker.casefold() in folded_summary for marker in _NONPRODUCTION_MARKERS):
            raise ValueError("the Production Calendar summary contains a non-Production marker")
        return self


def private_production_write_target_data(
    config: ProductionWriteTargetConfig,
) -> dict[str, object]:
    """Return the exact private target material used only for local hashing."""

    return {
        "schema_version": config.schema_version,
        "target_environment": config.target_environment,
        "target_label": config.target_label,
        "target_purpose": config.target_purpose,
        "calendar_id": config.calendar_id,
        "expected_target_fingerprint": config.expected_target_fingerprint,
        "expected_summary": config.expected_summary,
        "expected_access_role": config.expected_access_role,
        "expected_time_zone": config.expected_time_zone,
    }


def calculate_production_write_target_hash(config: ProductionWriteTargetConfig) -> str:
    """Bind every static target field without exposing it in reports."""

    encoded = json.dumps(
        private_production_write_target_data(config),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_TARGET_HASH_DOMAIN + encoded).hexdigest()


def validate_production_write_target_config(config: ProductionWriteTargetConfig) -> str:
    """Recheck the closed Production identity and return its full fingerprint."""

    if not isinstance(config, ProductionWriteTargetConfig):
        raise ProductionWriteTargetPolicyError(
            "invalid_production_write_target",
            "Production write target configuration is invalid",
        )
    if (
        config.schema_version != 1
        or config.target_environment != "production"
        or config.target_label != "production"
        or config.target_purpose != PRODUCTION_WRITE_TARGET_PURPOSE
        or config.expected_access_role != "owner"
        or config.expected_time_zone != PRODUCTION_WRITE_TIME_ZONE
        or config.calendar_id.casefold() == "primary"
    ):
        raise ProductionWriteTargetPolicyError(
            "production_write_target_policy_mismatch",
            "Production write target policy verification failed",
        )
    actual = calendar_id_fingerprint(config.calendar_id)
    if not hmac.compare_digest(actual, config.expected_target_fingerprint):
        raise ProductionWriteTargetPolicyError(
            "production_write_target_fingerprint_mismatch",
            "Production write target identity did not match",
        )
    folded_summary = config.expected_summary.casefold()
    if any(marker.casefold() in folded_summary for marker in _NONPRODUCTION_MARKERS):
        raise ProductionWriteTargetPolicyError(
            "production_write_target_marker_forbidden",
            "Production write target contains a non-Production marker",
        )
    return actual


def production_write_target_reference(config: ProductionWriteTargetConfig) -> str:
    """Return the redacted target reference after complete validation."""

    return short_target_reference(validate_production_write_target_config(config))


def load_production_write_target_config(path: str | Path) -> ProductionWriteTargetConfig:
    """Load one strict repository-external Production target TOML document."""

    try:
        raw = read_sensitive_bytes(path)
        value: Mapping[str, object] = tomllib.loads(raw.decode("utf-8", errors="strict"))
        config = ProductionWriteTargetConfig.model_validate(value, strict=True)
        validate_production_write_target_config(config)
        return config
    except ProductionWriteTargetError:
        raise
    except SensitivePathError as exc:
        raise ProductionWriteTargetConfigError(
            "unsafe_production_write_target_path",
            "Production write target path is unsafe or unavailable",
        ) from exc
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValidationError) as exc:
        raise ProductionWriteTargetConfigError(
            "invalid_production_write_target_config",
            "Production write target configuration is invalid",
        ) from exc


__all__ = [
    "PRODUCTION_WRITE_TARGET_PURPOSE",
    "PRODUCTION_WRITE_TIME_ZONE",
    "ProductionWriteTargetConfig",
    "ProductionWriteTargetConfigError",
    "ProductionWriteTargetError",
    "ProductionWriteTargetPolicyError",
    "calculate_production_write_target_hash",
    "load_production_write_target_config",
    "private_production_write_target_data",
    "production_write_target_reference",
    "validate_production_write_target_config",
]
