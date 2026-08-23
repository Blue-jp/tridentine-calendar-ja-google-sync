"""Fail-closed environment and operation policy for offline apply bundles."""

from __future__ import annotations

import re

from tridentine_calendar_google_sync.apply_models import (
    ApplyBundle,
    ApplyEnvironment,
)

PRODUCTION_TARGET_REFERENCE = "T-e10f0095ab8f"


class ApplyError(ValueError):
    """Base apply-bundle failure with identifier- and content-free public text."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class ApplyInputError(ApplyError):
    """Input objects cannot safely produce or load an apply bundle."""


class ApplyGuardError(ApplyError):
    """A fatal environment, state, count, or provenance guard fired."""


class ApplyValidationError(ApplyError):
    """Private bundle content failed structural or integrity validation."""


class ApplyConfirmationError(ApplyError):
    """The exact test-only approval phrase was not supplied."""


class ApplyIOError(ApplyError):
    """A private bundle path could not be read or written safely."""


def target_reference(target_fingerprint: str) -> str:
    """Return a safe short target reference after strict fingerprint validation."""

    if len(target_fingerprint) != 64 or any(
        character not in "0123456789abcdef" for character in target_fingerprint
    ):
        raise ApplyInputError(
            "invalid_apply_target_fingerprint",
            "apply target fingerprint is invalid",
        )
    return f"T-{target_fingerprint[:12]}"


def validate_environment_target(
    environment: ApplyEnvironment,
    target_fingerprint: str,
    target_label: str,
) -> str:
    """Reject every Production or disguised-Production bundle at entry."""

    if (
        not isinstance(target_label, str)
        or re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}",
            target_label,
        )
        is None
    ):
        raise ApplyInputError("invalid_apply_target_label", "apply target label is invalid")
    if environment is ApplyEnvironment.PRODUCTION:
        raise ApplyGuardError(
            "production_bundle_generation_forbidden",
            "Production apply bundle generation is forbidden",
        )
    if target_label.casefold() == "production":
        raise ApplyGuardError(
            "production_label_forbidden",
            "Production-labelled apply bundle generation is forbidden",
        )
    reference = target_reference(target_fingerprint)
    if reference == PRODUCTION_TARGET_REFERENCE:
        raise ApplyGuardError(
            "production_target_bundle_generation_forbidden",
            "Production target apply bundle generation is forbidden",
        )
    return reference


def validate_bundle_environment_policy(bundle: ApplyBundle) -> None:
    """Enforce immutable Production lock and test-only lifecycle states."""

    reference = validate_environment_target(
        bundle.environment,
        bundle.target_fingerprint,
        bundle.target_label,
    )
    if reference != bundle.target_reference:
        raise ApplyGuardError(
            "apply_target_reference_mismatch",
            "apply target reference is inconsistent",
        )
    if bundle.delete_count != 0:
        raise ApplyGuardError(
            "delete_operation_forbidden",
            "delete operations are not supported",
        )


def require_test_bundle(bundle: ApplyBundle) -> None:
    """Reject every approval or simulation transition outside test."""

    validate_bundle_environment_policy(bundle)
    if bundle.environment is not ApplyEnvironment.TEST:
        raise ApplyGuardError(
            "test_apply_bundle_required",
            "approval and simulation require a test apply bundle",
        )


__all__ = [
    "PRODUCTION_TARGET_REFERENCE",
    "ApplyConfirmationError",
    "ApplyError",
    "ApplyGuardError",
    "ApplyIOError",
    "ApplyInputError",
    "ApplyValidationError",
    "require_test_bundle",
    "target_reference",
    "validate_bundle_environment_policy",
    "validate_environment_target",
]
