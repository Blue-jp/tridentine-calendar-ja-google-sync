"""Deterministic abstract retry policy for offline fake mutation simulation."""

from __future__ import annotations

import hashlib
import math
from collections.abc import Callable
from enum import StrEnum

from pydantic import Field

from tridentine_calendar_google_sync.models import StrictFrozenModel

_JITTER_DOMAIN = b"tridentine-calendar-google-sync:fake-retry-jitter:v1\x00"


class SimulationOutcomeKind(StrEnum):
    """Complete injected fake-transport outcome vocabulary."""

    SUCCESS = "success"
    RATE_LIMIT = "rate_limit"
    SERVER_500 = "server_500"
    SERVER_502 = "server_502"
    SERVER_503 = "server_503"
    VALIDATION_FAILURE = "validation_failure"
    PERMISSION_DENIED = "permission_denied"
    TARGET_MISSING = "target_missing"
    ETAG_CONFLICT = "etag_conflict"
    AMBIGUOUS_IDENTITY = "ambiguous_identity"
    UNCERTAIN_OUTCOME = "uncertain_outcome"
    DUPLICATE_IDENTITY = "duplicate_identity"
    PERMANENT_FAILURE = "permanent_failure"


class RetryDecision(StrEnum):
    """Policy decision after one fake attempt."""

    SUCCEEDED = "succeeded"
    RETRY = "retry"
    STOP_FAILURE = "stop_failure"
    STOP_UNCERTAIN = "stop_uncertain"
    STOP_CONFLICT = "stop_conflict"


class ApplyRetryPolicy(StrictFrozenModel):
    """Bounded abstract retry units; this model never sleeps."""

    max_attempts: int = Field(default=5, ge=1, le=10)
    base_delay_units: int = Field(default=1, ge=1, le=1024)
    maximum_delay_units: int = Field(default=16, ge=1, le=65536)
    maximum_jitter_units: int = Field(default=1, ge=0, le=1024)


class RetryEvaluation(StrictFrozenModel):
    """One deterministic retry decision for journaling and tests."""

    outcome: SimulationOutcomeKind
    attempt: int = Field(ge=1)
    decision: RetryDecision
    delay_units: int = Field(ge=0)


JitterFunction = Callable[[str, int, int], int]
RETRYABLE_SIMULATION_OUTCOMES = frozenset(
    {
        SimulationOutcomeKind.RATE_LIMIT,
        SimulationOutcomeKind.SERVER_500,
        SimulationOutcomeKind.SERVER_502,
        SimulationOutcomeKind.SERVER_503,
    }
)


def deterministic_jitter_units(
    operation_key: str,
    attempt: int,
    maximum_jitter_units: int,
) -> int:
    """Return stable domain-separated jitter without random or time dependencies."""

    if len(operation_key) != 64 or any(
        character not in "0123456789abcdef" for character in operation_key
    ):
        raise ValueError("operation key is invalid")
    if attempt < 1 or maximum_jitter_units < 0:
        raise ValueError("jitter input is invalid")
    if maximum_jitter_units == 0:
        return 0
    digest = hashlib.sha256(
        _JITTER_DOMAIN + operation_key.encode("ascii") + b"\x00" + str(attempt).encode("ascii")
    ).digest()
    return int.from_bytes(digest[:8], "big") % (maximum_jitter_units + 1)


def retry_delay_units(
    policy: ApplyRetryPolicy,
    *,
    operation_key: str,
    attempt: int,
    jitter: JitterFunction = deterministic_jitter_units,
) -> int:
    """Calculate a bounded exponential delay unit count without waiting."""

    if attempt < 1 or attempt >= policy.max_attempts:
        raise ValueError("retry delay attempt is out of range")
    exponent = min(attempt - 1, 30)
    backoff = min(
        policy.base_delay_units * (2**exponent),
        policy.maximum_delay_units,
    )
    jitter_value = jitter(operation_key, attempt, policy.maximum_jitter_units)
    if isinstance(jitter_value, bool) or not isinstance(jitter_value, int):
        raise ValueError("jitter result must be an integer")
    if not 0 <= jitter_value <= policy.maximum_jitter_units:
        raise ValueError("jitter result is out of range")
    delay = min(backoff + jitter_value, policy.maximum_delay_units)
    if not math.isfinite(float(delay)):
        raise ValueError("retry delay is invalid")
    return int(delay)


def evaluate_retry(
    policy: ApplyRetryPolicy,
    *,
    operation_key: str,
    outcome: SimulationOutcomeKind,
    attempt: int,
    jitter: JitterFunction = deterministic_jitter_units,
) -> RetryEvaluation:
    """Return the fail-closed decision for one injected fake outcome."""

    if not 1 <= attempt <= policy.max_attempts:
        raise ValueError("attempt is out of range")
    if outcome is SimulationOutcomeKind.SUCCESS:
        decision = RetryDecision.SUCCEEDED
        delay = 0
    elif outcome in RETRYABLE_SIMULATION_OUTCOMES:
        if attempt < policy.max_attempts:
            decision = RetryDecision.RETRY
            delay = retry_delay_units(
                policy,
                operation_key=operation_key,
                attempt=attempt,
                jitter=jitter,
            )
        else:
            decision = RetryDecision.STOP_FAILURE
            delay = 0
    elif outcome is SimulationOutcomeKind.ETAG_CONFLICT:
        decision = RetryDecision.STOP_CONFLICT
        delay = 0
    elif outcome is SimulationOutcomeKind.UNCERTAIN_OUTCOME:
        decision = RetryDecision.STOP_UNCERTAIN
        delay = 0
    else:
        decision = RetryDecision.STOP_FAILURE
        delay = 0
    return RetryEvaluation(
        outcome=outcome,
        attempt=attempt,
        decision=decision,
        delay_units=delay,
    )


__all__ = [
    "RETRYABLE_SIMULATION_OUTCOMES",
    "ApplyRetryPolicy",
    "JitterFunction",
    "RetryDecision",
    "RetryEvaluation",
    "SimulationOutcomeKind",
    "deterministic_jitter_units",
    "evaluate_retry",
    "retry_delay_units",
]
