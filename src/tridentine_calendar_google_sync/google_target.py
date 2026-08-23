"""Strict private target configuration and pre-API calendar identity guards."""

from __future__ import annotations

import hashlib
import hmac
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import Field, ValidationError

from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    read_sensitive_bytes,
)

_TARGET_FINGERPRINT_DOMAIN = b"tridentine-calendar-google-sync:calendar-target:v1\x00"
CalendarAccessRole = Literal["owner"]


class GoogleTargetError(ValueError):
    """A target configuration or identity error with redacted public text."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class TargetConfigError(GoogleTargetError):
    """Invalid or unsafe target configuration."""


class TargetIdentityError(GoogleTargetError):
    """Configured target identity or metadata did not match expectations."""


class TargetConfig(StrictFrozenModel):
    """One local-only calendar target contract.

    ``calendar_id`` remains available internally to the read-only fetcher but
    is omitted from repr and normal Pydantic serialization.
    """

    schema_version: Literal[1]
    target_label: str = Field(pattern=r"^[a-z0-9][a-z0-9._-]{0,63}$")
    calendar_id: str = Field(min_length=1, max_length=1024, repr=False, exclude=True)
    expected_target_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_summary: str = Field(min_length=1)
    expected_access_role: Literal["owner"]
    expected_time_zone: str | None = Field(default=None, min_length=1, max_length=255)

    @property
    def label(self) -> str:
        """Return the safe target label used by command output."""

        return self.target_label

    @property
    def expected_fingerprint(self) -> str:
        """Return the configured full target fingerprint."""

        return self.expected_target_fingerprint

    @property
    def expected_timezone(self) -> str | None:
        """Return the optional expected Google Calendar timezone."""

        return self.expected_time_zone


class TargetMetadataObservation(StrictFrozenModel):
    """Privacy-safe fields returned by a calendar metadata read."""

    summary: str = Field(min_length=1, repr=False, exclude=True)
    access_role: CalendarAccessRole
    timezone: str = Field(min_length=1, max_length=255)


def calendar_id_fingerprint(calendar_id: str) -> str:
    """Return the full domain-separated lowercase SHA-256 target fingerprint."""

    return hashlib.sha256(
        _TARGET_FINGERPRINT_DOMAIN + calendar_id.encode("utf-8", errors="strict")
    ).hexdigest()


def short_target_reference(fingerprint: str) -> str:
    """Return the only target identifier suitable for human-readable output."""

    if len(fingerprint) != 64 or any(
        character not in "0123456789abcdef" for character in fingerprint
    ):
        raise TargetConfigError(
            "invalid_target_fingerprint",
            "target fingerprint is invalid",
        )
    return f"T-{fingerprint[:12]}"


def verify_target_fingerprint(config: TargetConfig) -> str:
    """Verify the private Calendar ID locally before any API client is constructed."""

    actual = calendar_id_fingerprint(config.calendar_id)
    if not hmac.compare_digest(actual, config.expected_fingerprint):
        raise TargetIdentityError(
            "target_fingerprint_mismatch",
            "configured calendar identity does not match the expected fingerprint",
        )
    return actual


def verify_target_metadata(
    config: TargetConfig,
    observation: TargetMetadataObservation,
) -> None:
    """Reject a readable calendar whose public metadata differs from the target contract."""

    if observation.summary != config.expected_summary:
        raise TargetIdentityError(
            "target_summary_mismatch",
            "calendar summary does not match the configured target",
        )
    if observation.access_role != config.expected_access_role:
        raise TargetIdentityError(
            "target_access_role_mismatch",
            "calendar access role does not match the configured target",
        )
    if config.expected_time_zone is not None and observation.timezone != config.expected_time_zone:
        raise TargetIdentityError(
            "target_timezone_mismatch",
            "calendar timezone does not match the configured target",
        )


def load_target_config(path: str | Path) -> TargetConfig:
    """Load one explicit private TOML path without searching the environment."""

    try:
        raw_bytes = read_sensitive_bytes(path)
        decoded = raw_bytes.decode("utf-8", errors="strict")
        value = tomllib.loads(decoded)
        return TargetConfig.model_validate(value, strict=True)
    except GoogleTargetError:
        raise
    except SensitivePathError as exc:
        raise TargetConfigError(
            "unsafe_target_config_path",
            "target configuration path is unsafe or unavailable",
        ) from exc
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValidationError) as exc:
        raise TargetConfigError(
            "invalid_target_config",
            "target configuration is invalid",
        ) from exc


__all__ = [
    "CalendarAccessRole",
    "GoogleTargetError",
    "TargetConfig",
    "TargetConfigError",
    "TargetIdentityError",
    "TargetMetadataObservation",
    "calendar_id_fingerprint",
    "load_target_config",
    "short_target_reference",
    "verify_target_fingerprint",
    "verify_target_metadata",
]
