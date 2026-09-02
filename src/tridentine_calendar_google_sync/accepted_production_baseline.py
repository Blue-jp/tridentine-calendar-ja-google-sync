"""Build and verify accepted Production baseline pins without live authority."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping

from pydantic import ValidationError

from tridentine_calendar_google_sync.accepted_production_baseline_models import (
    AcceptedProductionBaselinePin,
)
from tridentine_calendar_google_sync.baseline_engine import (
    baseline_confirmation_phrase,
    calculate_baseline_content_hash,
    trust_baseline,
    verify_baseline_content_hash,
)
from tridentine_calendar_google_sync.baseline_models import BaselineState, TrustedBaseline
from tridentine_calendar_google_sync.production_write_target import (
    ProductionWriteTargetConfig,
    calculate_production_write_target_hash,
    production_write_target_reference,
    validate_production_write_target_config,
)

_PIN_HASH_DOMAIN = b"tridentine-calendar-google-sync:accepted-production-baseline-pin:v1\x00"
_NONPRODUCTION_MARKERS = ("test", "synthetic", "テスト", "架空", ".invalid")
_ZERO_SHA256 = "0" * 64
_ZERO_SHA1 = "0" * 40


class AcceptedProductionBaselineError(ValueError):
    """A content-, identity-, and path-free baseline acceptance failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class AcceptedProductionBaselineInputError(AcceptedProductionBaselineError):
    """Candidate, Trusted Baseline, target, or predecessor is not acceptable."""


class AcceptedProductionBaselineValidationError(AcceptedProductionBaselineError):
    """An accepted baseline pin failed fixed-policy or integrity verification."""


def _hash_mapping(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_PIN_HASH_DOMAIN + encoded).hexdigest()


def _contains_nonproduction_marker(value: str) -> bool:
    folded = value.casefold()
    return any(marker.casefold() in folded for marker in _NONPRODUCTION_MARKERS)


def accepted_production_baseline_pin_data(
    pin: AcceptedProductionBaselinePin,
) -> dict[str, object]:
    """Return the complete public-safe canonical pin document."""

    return {
        "pin_id": pin.pin_id,
        "generation": pin.generation,
        "previous_pin_content_hash": pin.previous_pin_content_hash,
        "baseline_schema_version": pin.baseline_schema_version,
        "tool_version": pin.tool_version,
        "target_safe_ref": pin.target_safe_ref,
        "target_config_hash": pin.target_config_hash,
        "source_profile": pin.source_profile,
        "accepted_tag": pin.accepted_tag,
        "accepted_commit": pin.accepted_commit,
        "source_sha256": pin.source_sha256,
        "source_event_count": pin.source_event_count,
        "snapshot_content_hash": pin.snapshot_content_hash,
        "snapshot_event_count": pin.snapshot_event_count,
        "diff_content_hash": pin.diff_content_hash,
        "managed_uid_count": pin.managed_uid_count,
        "candidate_content_hash": pin.candidate_content_hash,
        "trusted_baseline_content_hash": pin.trusted_baseline_content_hash,
        "pin_content_hash": pin.pin_content_hash,
    }


def calculate_accepted_production_baseline_pin_hash(
    pin: AcceptedProductionBaselinePin,
) -> str:
    """Calculate the domain-separated full pin hash."""

    data = accepted_production_baseline_pin_data(pin)
    del data["pin_content_hash"]
    return _hash_mapping(data)


def verify_accepted_production_baseline_pin(
    pin: AcceptedProductionBaselinePin,
) -> None:
    """Revalidate the closed pin contract and its complete content hash."""

    if not isinstance(pin, AcceptedProductionBaselinePin):
        raise AcceptedProductionBaselineValidationError(
            "invalid_accepted_production_baseline_pin",
            "Accepted Production baseline pin is invalid",
        )
    try:
        AcceptedProductionBaselinePin.model_validate(
            pin.model_dump(mode="python"),
            strict=True,
        )
    except ValidationError as exc:
        raise AcceptedProductionBaselineValidationError(
            "accepted_production_baseline_pin_policy_mismatch",
            "Accepted Production baseline pin policy verification failed",
        ) from exc
    required_nonzero = (
        pin.target_config_hash,
        pin.source_sha256,
        pin.snapshot_content_hash,
        pin.diff_content_hash,
        pin.candidate_content_hash,
        pin.trusted_baseline_content_hash,
    )
    if pin.accepted_commit == _ZERO_SHA1 or any(
        value == _ZERO_SHA256 for value in required_nonzero
    ):
        raise AcceptedProductionBaselineValidationError(
            "accepted_production_baseline_pin_provenance_invalid",
            "Accepted Production baseline pin provenance is invalid",
        )
    if not hmac.compare_digest(
        calculate_accepted_production_baseline_pin_hash(pin),
        pin.pin_content_hash,
    ):
        raise AcceptedProductionBaselineValidationError(
            "accepted_production_baseline_pin_hash_mismatch",
            "Accepted Production baseline pin integrity verification failed",
        )


def candidate_content_hash_from_trusted_baseline(baseline: TrustedBaseline) -> str:
    """Derive the exact candidate-state hash committed by a Trusted Baseline."""

    try:
        verify_baseline_content_hash(baseline)
    except Exception as exc:
        raise AcceptedProductionBaselineValidationError(
            "accepted_production_baseline_integrity_failed",
            "Trusted Production baseline integrity verification failed",
        ) from exc
    if baseline.state is not BaselineState.TRUSTED:
        raise AcceptedProductionBaselineValidationError(
            "accepted_production_baseline_not_trusted",
            "Accepted Production baseline must be in trusted state",
        )
    candidate_view = baseline.model_copy(
        update={
            "state": BaselineState.CANDIDATE,
            "baseline_content_hash": _ZERO_SHA256,
        }
    )
    return calculate_baseline_content_hash(candidate_view)


def _verify_production_baseline_values(baseline: TrustedBaseline) -> None:
    marker_values = (baseline.source_profile, baseline.accepted_tag, *baseline.managed_uids)
    if (
        baseline.schema_version != "1.0"
        or baseline.source_event_count < 2
        or baseline.source_event_count != baseline.snapshot_event_count
        or baseline.source_event_count != baseline.managed_uid_count
        or baseline.accepted_commit == _ZERO_SHA1
        or baseline.source_sha256 == _ZERO_SHA256
        or baseline.snapshot_content_hash == _ZERO_SHA256
        or baseline.diff_content_hash == _ZERO_SHA256
        or "accepted" not in baseline.source_profile.casefold()
        or "accepted" not in baseline.accepted_tag.casefold()
        or any(_contains_nonproduction_marker(value) for value in marker_values)
    ):
        raise AcceptedProductionBaselineInputError(
            "accepted_production_baseline_policy_mismatch",
            "Production baseline values are not eligible for acceptance",
        )


def build_accepted_production_baseline_pin(
    candidate: TrustedBaseline,
    trusted_baseline: TrustedBaseline,
    target: ProductionWriteTargetConfig,
    *,
    generation: int,
    previous_pin: AcceptedProductionBaselinePin | None = None,
) -> AcceptedProductionBaselinePin:
    """Build a public-safe proposal pin from one exact local trust transition."""

    try:
        verify_baseline_content_hash(candidate)
        verify_baseline_content_hash(trusted_baseline)
    except Exception as exc:
        raise AcceptedProductionBaselineInputError(
            "accepted_production_baseline_integrity_failed",
            "Production baseline integrity verification failed",
        ) from exc
    if candidate.state is not BaselineState.CANDIDATE:
        raise AcceptedProductionBaselineInputError(
            "accepted_production_baseline_candidate_required",
            "A candidate baseline is required for Production baseline acceptance",
        )
    if trusted_baseline.state is not BaselineState.TRUSTED:
        raise AcceptedProductionBaselineInputError(
            "accepted_production_baseline_trusted_required",
            "A Trusted Baseline is required for Production baseline acceptance",
        )
    _verify_production_baseline_values(candidate)
    _verify_production_baseline_values(trusted_baseline)

    expected_trusted = trust_baseline(candidate, baseline_confirmation_phrase(candidate))
    if expected_trusted != trusted_baseline:
        raise AcceptedProductionBaselineInputError(
            "accepted_production_baseline_transition_mismatch",
            "Candidate and Trusted Baseline do not form one exact transition",
        )

    target_fingerprint = validate_production_write_target_config(target)
    if (
        candidate.target_fingerprint != target_fingerprint
        or trusted_baseline.target_fingerprint != target_fingerprint
    ):
        raise AcceptedProductionBaselineInputError(
            "accepted_production_baseline_target_mismatch",
            "Production baseline target does not match the accepted target",
        )

    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 1:
        raise AcceptedProductionBaselineInputError(
            "accepted_production_baseline_generation_invalid",
            "Accepted Production baseline generation is invalid",
        )
    if generation == 1:
        if previous_pin is not None:
            raise AcceptedProductionBaselineInputError(
                "accepted_production_baseline_predecessor_invalid",
                "First Production baseline generation cannot have a predecessor",
            )
        previous_hash = None
    else:
        if previous_pin is None:
            raise AcceptedProductionBaselineInputError(
                "accepted_production_baseline_predecessor_required",
                "Later Production baseline generation requires its predecessor",
            )
        verify_accepted_production_baseline_pin(previous_pin)
        if previous_pin.generation != generation - 1:
            raise AcceptedProductionBaselineInputError(
                "accepted_production_baseline_predecessor_invalid",
                "Production baseline predecessor generation is invalid",
            )
        previous_hash = previous_pin.pin_content_hash

    try:
        provisional = AcceptedProductionBaselinePin(
            pin_id=f"production-baseline-g{generation:04d}",
            generation=generation,
            previous_pin_content_hash=previous_hash,
            baseline_schema_version="1.0",
            tool_version=trusted_baseline.tool_version,
            target_safe_ref=production_write_target_reference(target),
            target_config_hash=calculate_production_write_target_hash(target),
            source_profile=trusted_baseline.source_profile,
            accepted_tag=trusted_baseline.accepted_tag,
            accepted_commit=trusted_baseline.accepted_commit,
            source_sha256=trusted_baseline.source_sha256,
            source_event_count=trusted_baseline.source_event_count,
            snapshot_content_hash=trusted_baseline.snapshot_content_hash,
            snapshot_event_count=trusted_baseline.snapshot_event_count,
            diff_content_hash=trusted_baseline.diff_content_hash,
            managed_uid_count=trusted_baseline.managed_uid_count,
            candidate_content_hash=candidate.baseline_content_hash,
            trusted_baseline_content_hash=trusted_baseline.baseline_content_hash,
            pin_content_hash=_ZERO_SHA256,
        )
    except ValidationError as exc:
        raise AcceptedProductionBaselineInputError(
            "accepted_production_baseline_pin_invalid",
            "Production baseline cannot produce a valid acceptance pin",
        ) from exc
    pin = provisional.model_copy(
        update={"pin_content_hash": calculate_accepted_production_baseline_pin_hash(provisional)}
    )
    verify_accepted_production_baseline_pin(pin)
    return pin


def verify_trusted_baseline_against_accepted_pin(
    baseline: TrustedBaseline,
    target: ProductionWriteTargetConfig,
    pin: AcceptedProductionBaselinePin,
) -> None:
    """Require one private Trusted Baseline to match every active full-hash pin."""

    verify_accepted_production_baseline_pin(pin)
    try:
        verify_baseline_content_hash(baseline)
    except Exception as exc:
        raise AcceptedProductionBaselineValidationError(
            "accepted_production_baseline_integrity_failed",
            "Trusted Production baseline integrity verification failed",
        ) from exc
    if baseline.state is not BaselineState.TRUSTED:
        raise AcceptedProductionBaselineValidationError(
            "accepted_production_baseline_not_trusted",
            "Accepted Production baseline must be in trusted state",
        )
    try:
        _verify_production_baseline_values(baseline)
    except AcceptedProductionBaselineInputError as exc:
        raise AcceptedProductionBaselineValidationError(
            exc.code,
            exc.public_message,
        ) from exc

    target_fingerprint = validate_production_write_target_config(target)
    candidate_hash = candidate_content_hash_from_trusted_baseline(baseline)
    matches = (
        baseline.target_fingerprint == target_fingerprint
        and pin.baseline_schema_version == baseline.schema_version
        and pin.tool_version == baseline.tool_version
        and pin.target_safe_ref == production_write_target_reference(target)
        and hmac.compare_digest(
            pin.target_config_hash,
            calculate_production_write_target_hash(target),
        )
        and pin.source_profile == baseline.source_profile
        and pin.accepted_tag == baseline.accepted_tag
        and pin.accepted_commit == baseline.accepted_commit
        and hmac.compare_digest(pin.source_sha256, baseline.source_sha256)
        and pin.source_event_count == baseline.source_event_count
        and hmac.compare_digest(
            pin.snapshot_content_hash,
            baseline.snapshot_content_hash,
        )
        and pin.snapshot_event_count == baseline.snapshot_event_count
        and hmac.compare_digest(pin.diff_content_hash, baseline.diff_content_hash)
        and pin.managed_uid_count == baseline.managed_uid_count
        and hmac.compare_digest(pin.candidate_content_hash, candidate_hash)
        and hmac.compare_digest(
            pin.trusted_baseline_content_hash,
            baseline.baseline_content_hash,
        )
    )
    if not matches:
        raise AcceptedProductionBaselineValidationError(
            "accepted_production_baseline_binding_mismatch",
            "Trusted Production baseline does not match the accepted active pin",
        )


__all__ = [
    "AcceptedProductionBaselineError",
    "AcceptedProductionBaselineInputError",
    "AcceptedProductionBaselineValidationError",
    "accepted_production_baseline_pin_data",
    "build_accepted_production_baseline_pin",
    "calculate_accepted_production_baseline_pin_hash",
    "candidate_content_hash_from_trusted_baseline",
    "verify_accepted_production_baseline_pin",
    "verify_trusted_baseline_against_accepted_pin",
]
