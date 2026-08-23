"""Deterministic in-memory add/update transport for offline simulation only."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping, Sequence

from pydantic import Field

from tridentine_calendar_google_sync.apply_bundle import verify_apply_bundle_integrity
from tridentine_calendar_google_sync.apply_models import (
    ApplyAddPayload,
    ApplyBundle,
    ApplyOperation,
    ApplyOperationKind,
    ApplyUpdatePayload,
)
from tridentine_calendar_google_sync.apply_policy import require_test_bundle
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.retry_policy import SimulationOutcomeKind

_ETAG_HASH_DOMAIN = b"tridentine-calendar-google-sync:fake-etag:v1\x00"
_EVENT_ID_DOMAIN = b"tridentine-calendar-google-sync:fake-event-id:v1\x00"
_STATE_HASH_DOMAIN = b"tridentine-calendar-google-sync:fake-transport-state:v1\x00"


class FakeMutationError(ValueError):
    """A content- and identifier-free fake transport failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class FakeMutationResult(StrictFrozenModel):
    """One safe injected or successful fake mutation observation."""

    operation_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation: ApplyOperationKind
    source_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    google_ref: str | None = Field(default=None, pattern=r"^G-[0-9a-f]{12}$")
    attempt: int = Field(ge=1)
    outcome: SimulationOutcomeKind
    outcome_code: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    payload_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_etag_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    result_state_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    transport_state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class _FakeEvent:
    __slots__ = ("etag", "event_id", "source_uid", "state_hash")

    def __init__(self, *, event_id: str, source_uid: str, etag: str, state_hash: str) -> None:
        self.event_id = event_id
        self.source_uid = source_uid
        self.etag = etag
        self.state_hash = state_hash


def _sha256(domain: bytes, value: bytes) -> str:
    return hashlib.sha256(domain + value).hexdigest()


def hash_fake_etag(etag: str) -> str:
    """Return a safe hash for journal/report use without exposing raw ETags."""

    return _sha256(_ETAG_HASH_DOMAIN, etag.encode("utf-8"))


class FakeMutationTransport:
    """Fake-only state machine exposing add/update and intentionally no delete method."""

    __slots__ = ("_applied", "_events", "_injected")

    def __init__(
        self,
        *,
        events: Mapping[str, tuple[str, str, str]],
        injected_outcomes: Mapping[str, Sequence[SimulationOutcomeKind]] | None = None,
    ) -> None:
        self._events = {
            event_id: _FakeEvent(
                event_id=event_id,
                source_uid=source_uid,
                etag=etag,
                state_hash=state_hash,
            )
            for event_id, (source_uid, etag, state_hash) in events.items()
        }
        self._injected = {
            key: tuple(outcomes) for key, outcomes in (injected_outcomes or {}).items()
        }
        self._applied: dict[str, FakeMutationResult] = {}

    def __repr__(self) -> str:
        return (
            "FakeMutationTransport("
            f"event_count={len(self._events)}, injected_operation_count={len(self._injected)})"
        )

    @classmethod
    def from_bundle(
        cls,
        bundle: ApplyBundle,
        *,
        injected_outcomes: Mapping[str, Sequence[SimulationOutcomeKind]] | None = None,
    ) -> FakeMutationTransport:
        """Seed update concurrency state from one verified test-only bundle."""

        verify_apply_bundle_integrity(bundle)
        require_test_bundle(bundle)
        events: dict[str, tuple[str, str, str]] = {}
        for operation in bundle.operations:
            if operation.operation is ApplyOperationKind.UPDATE:
                payload = operation.payload
                if not isinstance(payload, ApplyUpdatePayload):
                    raise FakeMutationError(
                        "fake_update_payload_invalid",
                        "fake update payload is invalid",
                    )
                existing = events.get(payload.event_id)
                state = (operation.source_uid, payload.etag, operation.before_hash)
                if existing is not None and existing != state:
                    raise FakeMutationError(
                        "fake_event_seed_conflict",
                        "fake event seed contains a conflict",
                    )
                events[payload.event_id] = state
        return cls(events=events, injected_outcomes=injected_outcomes)

    def _injected_outcome(
        self,
        operation: ApplyOperation,
        attempt: int,
    ) -> SimulationOutcomeKind:
        outcomes = self._injected.get(operation.operation_integrity_hash, ())
        if attempt <= len(outcomes):
            return outcomes[attempt - 1]
        return SimulationOutcomeKind.SUCCESS

    def _result(
        self,
        operation: ApplyOperation,
        *,
        attempt: int,
        outcome: SimulationOutcomeKind,
        outcome_code: str,
        expected_etag_hash: str | None,
        result_state_hash: str | None,
    ) -> FakeMutationResult:
        return FakeMutationResult(
            operation_key=operation.operation_integrity_hash,
            operation=operation.operation,
            source_ref=operation.source_ref,
            google_ref=operation.google_ref,
            attempt=attempt,
            outcome=outcome,
            outcome_code=outcome_code,
            payload_hash=operation.payload_hash,
            expected_etag_hash=expected_etag_hash,
            result_state_hash=result_state_hash,
            transport_state_hash=self.state_hash(),
        )

    def _injected_result(
        self,
        operation: ApplyOperation,
        *,
        attempt: int,
        expected_etag_hash: str | None,
    ) -> FakeMutationResult | None:
        outcome = self._injected_outcome(operation, attempt)
        if outcome is SimulationOutcomeKind.SUCCESS:
            return None
        code = {
            SimulationOutcomeKind.RATE_LIMIT: "rate_limit",
            SimulationOutcomeKind.SERVER_500: "server_500",
            SimulationOutcomeKind.SERVER_502: "server_502",
            SimulationOutcomeKind.SERVER_503: "server_503",
            SimulationOutcomeKind.VALIDATION_FAILURE: "validation_failure",
            SimulationOutcomeKind.PERMISSION_DENIED: "permission_denied",
            SimulationOutcomeKind.TARGET_MISSING: "target_missing",
            SimulationOutcomeKind.ETAG_CONFLICT: "etag_conflict",
            SimulationOutcomeKind.AMBIGUOUS_IDENTITY: "ambiguous_identity",
            SimulationOutcomeKind.UNCERTAIN_OUTCOME: "uncertain_outcome",
            SimulationOutcomeKind.DUPLICATE_IDENTITY: "duplicate_identity",
            SimulationOutcomeKind.PERMANENT_FAILURE: "permanent_failure",
        }[outcome]
        return self._result(
            operation,
            attempt=attempt,
            outcome=outcome,
            outcome_code=code,
            expected_etag_hash=expected_etag_hash,
            result_state_hash=None,
        )

    def simulate_add(
        self,
        operation: ApplyOperation,
        *,
        attempt: int,
    ) -> FakeMutationResult:
        """Simulate one add without network, Google imports, or external mutation."""

        if operation.operation is not ApplyOperationKind.ADD or not isinstance(
            operation.payload,
            ApplyAddPayload,
        ):
            raise FakeMutationError("fake_add_operation_invalid", "fake add operation is invalid")
        if attempt < 1:
            raise FakeMutationError("fake_attempt_invalid", "fake attempt is invalid")
        applied = self._applied.get(operation.operation_integrity_hash)
        if applied is not None:
            return applied
        injected = self._injected_result(
            operation,
            attempt=attempt,
            expected_etag_hash=None,
        )
        if injected is not None:
            return injected
        if any(event.source_uid == operation.source_uid for event in self._events.values()):
            return self._result(
                operation,
                attempt=attempt,
                outcome=SimulationOutcomeKind.DUPLICATE_IDENTITY,
                outcome_code="duplicate_identity",
                expected_etag_hash=None,
                result_state_hash=None,
            )
        event_id = (
            "fake-"
            + _sha256(
                _EVENT_ID_DOMAIN,
                operation.source_uid.encode("utf-8"),
            )[:24]
        )
        etag = (
            "fake-etag-"
            + _sha256(
                _ETAG_HASH_DOMAIN,
                operation.operation_integrity_hash.encode("ascii"),
            )[:24]
        )
        self._events[event_id] = _FakeEvent(
            event_id=event_id,
            source_uid=operation.source_uid,
            etag=etag,
            state_hash=operation.after_hash,
        )
        result = self._result(
            operation,
            attempt=attempt,
            outcome=SimulationOutcomeKind.SUCCESS,
            outcome_code="success",
            expected_etag_hash=None,
            result_state_hash=operation.after_hash,
        )
        self._applied[operation.operation_integrity_hash] = result
        return result

    def simulate_update(
        self,
        operation: ApplyOperation,
        *,
        attempt: int,
    ) -> FakeMutationResult:
        """Simulate one ETag-conditional update entirely in memory."""

        if operation.operation is not ApplyOperationKind.UPDATE or not isinstance(
            operation.payload,
            ApplyUpdatePayload,
        ):
            raise FakeMutationError(
                "fake_update_operation_invalid",
                "fake update operation is invalid",
            )
        if attempt < 1:
            raise FakeMutationError("fake_attempt_invalid", "fake attempt is invalid")
        applied = self._applied.get(operation.operation_integrity_hash)
        if applied is not None:
            return applied
        expected_hash = hash_fake_etag(operation.payload.etag)
        injected = self._injected_result(
            operation,
            attempt=attempt,
            expected_etag_hash=expected_hash,
        )
        if injected is not None:
            return injected
        event = self._events.get(operation.payload.event_id)
        if event is None:
            return self._result(
                operation,
                attempt=attempt,
                outcome=SimulationOutcomeKind.TARGET_MISSING,
                outcome_code="target_missing",
                expected_etag_hash=expected_hash,
                result_state_hash=None,
            )
        if not hmac.compare_digest(event.etag, operation.payload.etag):
            return self._result(
                operation,
                attempt=attempt,
                outcome=SimulationOutcomeKind.ETAG_CONFLICT,
                outcome_code="etag_conflict",
                expected_etag_hash=expected_hash,
                result_state_hash=None,
            )
        event.etag = (
            "fake-etag-"
            + _sha256(
                _ETAG_HASH_DOMAIN,
                (event.etag + "\x00" + operation.operation_integrity_hash).encode("utf-8"),
            )[:24]
        )
        event.state_hash = operation.after_hash
        result = self._result(
            operation,
            attempt=attempt,
            outcome=SimulationOutcomeKind.SUCCESS,
            outcome_code="success",
            expected_etag_hash=expected_hash,
            result_state_hash=operation.after_hash,
        )
        self._applied[operation.operation_integrity_hash] = result
        return result

    def state_hash(self) -> str:
        """Return a deterministic safe hash of the complete fake transport state."""

        data = [
            {
                "event_id_hash": _sha256(_EVENT_ID_DOMAIN, event.event_id.encode("utf-8")),
                "uid_hash": _sha256(_EVENT_ID_DOMAIN, event.source_uid.encode("utf-8")),
                "etag_hash": hash_fake_etag(event.etag),
                "state_hash": event.state_hash,
            }
            for event in sorted(self._events.values(), key=lambda item: item.event_id)
        ]
        encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return _sha256(_STATE_HASH_DOMAIN, encoded)


__all__ = [
    "FakeMutationError",
    "FakeMutationResult",
    "FakeMutationTransport",
    "hash_fake_etag",
]
