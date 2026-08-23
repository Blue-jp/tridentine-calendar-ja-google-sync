"""Strict Test Calendar target policy for the isolated write layer."""

from __future__ import annotations

import hmac
import tomllib
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, ValidationError, model_validator

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.google_target import (
    calendar_id_fingerprint,
    short_target_reference,
)
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    read_sensitive_bytes,
)

TEST_WRITE_TARGET_PURPOSE = "test_calendar_write_acceptance"
TEST_WRITE_TIME_ZONE = "Asia/Tokyo"


class TestWriteTargetError(ValueError):
    """A redacted Test Calendar target configuration or identity failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class TestWriteTargetConfigError(TestWriteTargetError):
    """The private Test Calendar target configuration is unsafe or invalid."""


class TestWriteTargetPolicyError(TestWriteTargetError):
    """The configured or observed target is not an approved Test Calendar."""


class TestWriteTargetConfig(StrictFrozenModel):
    """Repository-external Test Calendar contract with hidden sensitive values."""

    schema_version: Literal[1]
    target_environment: Literal["test"]
    target_label: Literal["test"]
    target_purpose: Literal["test_calendar_write_acceptance"]
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
    def clearly_identifies_a_nonproduction_test_target(self) -> Self:
        if self.calendar_id.casefold() == "primary":
            raise ValueError("the primary calendar is forbidden")
        summary = self.expected_summary.casefold()
        if "test" not in summary and "テスト" not in self.expected_summary:
            raise ValueError("the Test Calendar summary must include an explicit test marker")
        actual_fingerprint = calendar_id_fingerprint(self.calendar_id)
        if not hmac.compare_digest(actual_fingerprint, self.expected_target_fingerprint):
            raise ValueError("the target fingerprint does not match the Calendar ID")
        if short_target_reference(actual_fingerprint) == PRODUCTION_TARGET_REFERENCE:
            raise ValueError("the Production target is forbidden")
        return self


class TestWriteTargetObservation(StrictFrozenModel):
    """The minimal remote metadata used to revalidate a Test Calendar."""

    summary: str = Field(min_length=1, max_length=1024, repr=False, exclude=True)
    access_role: str = Field(min_length=1, max_length=64)
    time_zone: str = Field(min_length=1, max_length=255)


def validate_test_write_target_config(config: TestWriteTargetConfig) -> str:
    """Recheck every local Test-only and Production-lock invariant."""

    if not isinstance(config, TestWriteTargetConfig):
        raise TestWriteTargetConfigError(
            "invalid_test_write_target",
            "Test write target configuration is invalid",
        )
    if (
        config.target_environment != "test"
        or config.target_label != "test"
        or config.target_purpose != TEST_WRITE_TARGET_PURPOSE
        or config.expected_access_role != "owner"
        or config.expected_time_zone != TEST_WRITE_TIME_ZONE
        or config.calendar_id.casefold() == "primary"
    ):
        raise TestWriteTargetPolicyError(
            "test_write_target_policy_mismatch",
            "Test write target policy was not satisfied",
        )
    actual_fingerprint = calendar_id_fingerprint(config.calendar_id)
    if not hmac.compare_digest(actual_fingerprint, config.expected_target_fingerprint):
        raise TestWriteTargetPolicyError(
            "test_write_target_fingerprint_mismatch",
            "Test write target identity did not match",
        )
    reference = short_target_reference(actual_fingerprint)
    if reference == PRODUCTION_TARGET_REFERENCE:
        raise TestWriteTargetPolicyError(
            "production_test_write_target_forbidden",
            "Production Calendar write access is forbidden",
        )
    summary = config.expected_summary.casefold()
    if "test" not in summary and "テスト" not in config.expected_summary:
        raise TestWriteTargetPolicyError(
            "test_write_summary_marker_missing",
            "Test write target summary lacks an explicit test marker",
        )
    return actual_fingerprint


def test_write_target_reference(config: TestWriteTargetConfig) -> str:
    """Return the only Test target identity allowed in public output."""

    return short_target_reference(validate_test_write_target_config(config))


def verify_test_write_target_metadata(
    config: TestWriteTargetConfig,
    observation: TestWriteTargetObservation,
) -> None:
    """Require exact summary, owner access, and Asia/Tokyo before a write preflight."""

    validate_test_write_target_config(config)
    if not isinstance(observation, TestWriteTargetObservation):
        raise TestWriteTargetPolicyError(
            "invalid_test_write_target_observation",
            "Test write target metadata is invalid",
        )
    if not hmac.compare_digest(
        observation.summary.encode("utf-8", errors="strict"),
        config.expected_summary.encode("utf-8", errors="strict"),
    ):
        raise TestWriteTargetPolicyError(
            "test_write_target_summary_mismatch",
            "Test write target summary did not match",
        )
    if observation.access_role != "owner":
        raise TestWriteTargetPolicyError(
            "test_write_target_not_owned",
            "Test write target must have owner access",
        )
    if observation.time_zone != TEST_WRITE_TIME_ZONE:
        raise TestWriteTargetPolicyError(
            "test_write_target_timezone_mismatch",
            "Test write target timezone did not match",
        )


def load_test_write_target_config(path: str | Path) -> TestWriteTargetConfig:
    """Load and verify one explicit repository-external Test target TOML file."""

    try:
        raw = read_sensitive_bytes(path)
        value = tomllib.loads(raw.decode("utf-8", errors="strict"))
        config = TestWriteTargetConfig.model_validate(value, strict=True)
        validate_test_write_target_config(config)
        return config
    except TestWriteTargetError:
        raise
    except SensitivePathError as exc:
        raise TestWriteTargetConfigError(
            "unsafe_test_write_target_path",
            "Test write target configuration path is unsafe or unavailable",
        ) from exc
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValidationError) as exc:
        raise TestWriteTargetConfigError(
            "invalid_test_write_target_config",
            "Test write target configuration is invalid",
        ) from exc


__all__ = [
    "TEST_WRITE_TARGET_PURPOSE",
    "TEST_WRITE_TIME_ZONE",
    "TestWriteTargetConfig",
    "TestWriteTargetConfigError",
    "TestWriteTargetError",
    "TestWriteTargetObservation",
    "TestWriteTargetPolicyError",
    "load_test_write_target_config",
    "test_write_target_reference",
    "validate_test_write_target_config",
    "verify_test_write_target_metadata",
]
