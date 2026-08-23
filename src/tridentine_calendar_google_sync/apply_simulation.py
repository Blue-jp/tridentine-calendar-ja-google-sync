"""Sequential deterministic runner for approved fake-only apply bundles."""

from __future__ import annotations

import hashlib
import hmac
import json
from enum import StrEnum
from typing import Literal

from pydantic import Field

from tridentine_calendar_google_sync.apply_approval import (
    mark_apply_simulation_complete,
    mark_apply_simulation_failed,
)
from tridentine_calendar_google_sync.apply_bundle import verify_apply_bundle_integrity
from tridentine_calendar_google_sync.apply_models import (
    ApplyBundle,
    ApplyBundleState,
    ApplyEnvironment,
    ApplyOperation,
    ApplyOperationKind,
    ApplyUpdatePayload,
)
from tridentine_calendar_google_sync.apply_policy import ApplyGuardError, require_test_bundle
from tridentine_calendar_google_sync.fake_mutation_transport import (
    FakeMutationResult,
    FakeMutationTransport,
    hash_fake_etag,
)
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.operation_journal import (
    JournalEntryStatus,
    JournalState,
    OperationJournal,
    append_operation_journal_entry,
    initialize_operation_journal,
    transition_operation_journal,
    verify_operation_journal,
)
from tridentine_calendar_google_sync.retry_policy import (
    RETRYABLE_SIMULATION_OUTCOMES,
    ApplyRetryPolicy,
    JitterFunction,
    RetryDecision,
    deterministic_jitter_units,
    evaluate_retry,
)

_RESULT_HASH_DOMAIN = b"tridentine-calendar-google-sync:fake-apply-result:v1\x00"


class ApplySimulationState(StrEnum):
    """Terminal fake simulation outcome."""

    COMPLETED = "completed"
    PARTIAL_FAILURE = "partial_failure"
    UNCERTAIN = "uncertain"
    ETAG_CONFLICT = "etag_conflict"
    BLOCKED = "blocked"


class SimulatedOperationResult(StrictFrozenModel):
    """One terminal safe operation result; attempt details remain in the journal."""

    operation_index: int = Field(ge=1)
    operation_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation: ApplyOperationKind
    source_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    google_ref: str | None = Field(default=None, pattern=r"^G-[0-9a-f]{12}$")
    status: JournalEntryStatus
    attempts: int = Field(ge=0)
    retry_count: int = Field(ge=0)
    outcome_code: str = Field(pattern=r"^[a-z][a-z0-9_]*$")
    payload_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_state_hash: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class ApplySimulationResult(StrictFrozenModel):
    """Complete deterministic fake result with no rollback or execution authority."""

    schema_version: Literal["1.0"] = "1.0"
    result_type: Literal["fake-apply-simulation-result-v1"] = "fake-apply-simulation-result-v1"
    state: ApplySimulationState
    mutation_mode: Literal["fake"] = "fake"
    executable: Literal[False] = False
    rollback_available: Literal[False] = False
    environment: ApplyEnvironment
    approval_state: Literal["approved_for_simulation"] = "approved_for_simulation"
    source_profile: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    bundle_integrity_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    final_bundle_integrity_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    final_bundle_state: ApplyBundleState
    plan_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    baseline_integrity_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_reference: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    total_operation_count: int = Field(ge=0)
    add_count: int = Field(ge=0)
    update_count: int = Field(ge=0)
    delete_count: Literal[0] = 0
    attempted_operation_count: int = Field(ge=0)
    succeeded_count: int = Field(ge=0)
    failed_count: int = Field(ge=0)
    uncertain_count: int = Field(ge=0)
    etag_conflict_count: int = Field(ge=0)
    skipped_count: int = Field(ge=0)
    retry_count: int = Field(ge=0)
    partial_results: bool
    operation_results: tuple[SimulatedOperationResult, ...]
    journal: OperationJournal
    final_transport_state_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    result_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")


class ApplySimulationError(ValueError):
    """Content-free fake simulation failure before a result can be produced."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _expected_etag_hash(operation: ApplyOperation) -> str | None:
    payload = operation.payload
    if isinstance(payload, ApplyUpdatePayload):
        return hash_fake_etag(payload.etag)
    return None


def _simulate_attempt(
    transport: FakeMutationTransport,
    operation: ApplyOperation,
    attempt: int,
) -> FakeMutationResult:
    if operation.operation is ApplyOperationKind.ADD:
        return transport.simulate_add(operation, attempt=attempt)
    if operation.operation is ApplyOperationKind.UPDATE:
        return transport.simulate_update(operation, attempt=attempt)
    raise ApplySimulationError(
        "unsupported_simulation_operation",
        "fake simulation operation is unsupported",
    )


def _recheck_simulation_policy(bundle: ApplyBundle) -> None:
    """Re-run every immutable policy guard before initial use and each operation."""

    verify_apply_bundle_integrity(bundle)
    require_test_bundle(bundle)
    if bundle.state is not ApplyBundleState.APPROVED_FOR_SIMULATION:
        raise ApplyGuardError(
            "apply_bundle_not_approved_for_simulation",
            "apply bundle is not approved for simulation",
        )
    if bundle.delete_count != 0:
        raise ApplyGuardError(
            "delete_operation_forbidden",
            "delete operations are not supported",
        )


def _journal_status(decision: RetryDecision) -> JournalEntryStatus:
    return {
        RetryDecision.SUCCEEDED: JournalEntryStatus.SUCCEEDED,
        RetryDecision.RETRY: JournalEntryStatus.RETRYING,
        RetryDecision.STOP_FAILURE: JournalEntryStatus.FAILED,
        RetryDecision.STOP_UNCERTAIN: JournalEntryStatus.UNCERTAIN,
        RetryDecision.STOP_CONFLICT: JournalEntryStatus.ETAG_CONFLICT,
    }[decision]


def _result_hash_data(result: ApplySimulationResult) -> dict[str, object]:
    return {
        "schema_version": result.schema_version,
        "result_type": result.result_type,
        "state": result.state.value,
        "mutation_mode": result.mutation_mode,
        "executable": result.executable,
        "rollback_available": result.rollback_available,
        "environment": result.environment.value,
        "approval_state": result.approval_state,
        "source_profile": result.source_profile,
        "bundle_integrity_hash": result.bundle_integrity_hash,
        "final_bundle_integrity_hash": result.final_bundle_integrity_hash,
        "final_bundle_state": result.final_bundle_state.value,
        "plan_content_hash": result.plan_content_hash,
        "baseline_integrity_hash": result.baseline_integrity_hash,
        "target_reference": result.target_reference,
        "total_operation_count": result.total_operation_count,
        "add_count": result.add_count,
        "update_count": result.update_count,
        "delete_count": result.delete_count,
        "attempted_operation_count": result.attempted_operation_count,
        "succeeded_count": result.succeeded_count,
        "failed_count": result.failed_count,
        "uncertain_count": result.uncertain_count,
        "etag_conflict_count": result.etag_conflict_count,
        "skipped_count": result.skipped_count,
        "retry_count": result.retry_count,
        "partial_results": result.partial_results,
        "operation_results": [item.model_dump(mode="json") for item in result.operation_results],
        "journal_content_hash": result.journal.journal_content_hash,
        "final_transport_state_hash": result.final_transport_state_hash,
    }


def calculate_apply_simulation_result_hash(result: ApplySimulationResult) -> str:
    """Recalculate the deterministic fake result hash."""

    encoded = json.dumps(
        _result_hash_data(result),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_RESULT_HASH_DOMAIN + encoded).hexdigest()


def verify_apply_simulation_result(result: ApplySimulationResult) -> None:
    """Verify result counts, journal chain, and aggregate hash."""

    verify_operation_journal(result.journal)
    if (
        result.environment is not ApplyEnvironment.TEST
        or result.approval_state != "approved_for_simulation"
        or result.delete_count != 0
        or result.total_operation_count == 0
        or result.total_operation_count != result.add_count + result.update_count
        or result.total_operation_count != len(result.operation_results)
        or result.add_count
        != sum(item.operation is ApplyOperationKind.ADD for item in result.operation_results)
        or result.update_count
        != sum(item.operation is ApplyOperationKind.UPDATE for item in result.operation_results)
    ):
        raise ApplySimulationError(
            "simulation_result_count_mismatch",
            "fake simulation result count verification failed",
        )
    if tuple(item.operation_index for item in result.operation_results) != tuple(
        range(1, result.total_operation_count + 1)
    ) or len({item.operation_key for item in result.operation_results}) != len(
        result.operation_results
    ):
        raise ApplySimulationError(
            "simulation_result_order_mismatch",
            "fake simulation result order verification failed",
        )
    status_counts = {
        status: sum(item.status is status for item in result.operation_results)
        for status in JournalEntryStatus
    }
    expected_failed = status_counts[JournalEntryStatus.FAILED]
    if (
        result.succeeded_count != status_counts[JournalEntryStatus.SUCCEEDED]
        or result.failed_count != expected_failed
        or result.uncertain_count != status_counts[JournalEntryStatus.UNCERTAIN]
        or result.etag_conflict_count != status_counts[JournalEntryStatus.ETAG_CONFLICT]
        or result.skipped_count != status_counts[JournalEntryStatus.SKIPPED]
        or result.attempted_operation_count != result.total_operation_count - result.skipped_count
        or result.retry_count != sum(item.retry_count for item in result.operation_results)
        or status_counts[JournalEntryStatus.RETRYING] != 0
    ):
        raise ApplySimulationError(
            "simulation_result_aggregate_mismatch",
            "fake simulation result aggregate verification failed",
        )
    expected_partial = (
        result.succeeded_count > 0 and result.state is not ApplySimulationState.COMPLETED
    )
    if result.partial_results != expected_partial:
        raise ApplySimulationError(
            "simulation_partial_state_mismatch",
            "fake simulation partial-result verification failed",
        )
    state_contract = {
        ApplySimulationState.COMPLETED: (
            JournalState.COMPLETED,
            ApplyBundleState.SIMULATION_COMPLETE,
            JournalEntryStatus.SUCCEEDED,
        ),
        ApplySimulationState.PARTIAL_FAILURE: (
            JournalState.PARTIAL_FAILURE,
            ApplyBundleState.SIMULATION_FAILED,
            JournalEntryStatus.FAILED,
        ),
        ApplySimulationState.UNCERTAIN: (
            JournalState.UNCERTAIN,
            ApplyBundleState.SIMULATION_FAILED,
            JournalEntryStatus.UNCERTAIN,
        ),
        ApplySimulationState.ETAG_CONFLICT: (
            JournalState.ETAG_CONFLICT,
            ApplyBundleState.SIMULATION_FAILED,
            JournalEntryStatus.ETAG_CONFLICT,
        ),
        ApplySimulationState.BLOCKED: (
            JournalState.BLOCKED,
            ApplyBundleState.SIMULATION_FAILED,
            JournalEntryStatus.FAILED,
        ),
    }
    journal_state, final_bundle_state, terminal_status = state_contract[result.state]
    if (
        result.journal.state is not journal_state
        or result.final_bundle_state is not final_bundle_state
    ):
        raise ApplySimulationError(
            "simulation_state_mismatch",
            "fake simulation state verification failed",
        )
    terminal_count = status_counts[terminal_status]
    if result.state is ApplySimulationState.COMPLETED:
        valid_terminal_shape = terminal_count == result.total_operation_count
    else:
        valid_terminal_shape = terminal_count == 1
    if not valid_terminal_shape:
        raise ApplySimulationError(
            "simulation_terminal_result_mismatch",
            "fake simulation terminal result verification failed",
        )
    terminal_seen = False
    journal_cursor = 0
    for operation_result in result.operation_results:
        if operation_result.status is JournalEntryStatus.SKIPPED and not terminal_seen:
            raise ApplySimulationError(
                "simulation_skip_order_mismatch",
                "fake simulation skip order verification failed",
            )
        if terminal_seen and operation_result.status is not JournalEntryStatus.SKIPPED:
            raise ApplySimulationError(
                "simulation_stop_order_mismatch",
                "fake simulation stop order verification failed",
            )
        if operation_result.status not in {
            JournalEntryStatus.SUCCEEDED,
            JournalEntryStatus.FAILED,
            JournalEntryStatus.UNCERTAIN,
            JournalEntryStatus.ETAG_CONFLICT,
            JournalEntryStatus.SKIPPED,
        }:
            raise ApplySimulationError(
                "simulation_terminal_status_invalid",
                "fake simulation terminal status verification failed",
            )
        if operation_result.status is JournalEntryStatus.SKIPPED:
            expected_entry_count = 1
            if operation_result.attempts != 0 or operation_result.retry_count != 0:
                raise ApplySimulationError(
                    "simulation_skipped_result_invalid",
                    "fake simulation skipped result verification failed",
                )
        else:
            expected_entry_count = operation_result.attempts
            if (
                operation_result.attempts < 1
                or operation_result.retry_count != operation_result.attempts - 1
            ):
                raise ApplySimulationError(
                    "simulation_attempt_count_mismatch",
                    "fake simulation attempt verification failed",
                )
        entries = result.journal.entries[journal_cursor : journal_cursor + expected_entry_count]
        if len(entries) != expected_entry_count:
            raise ApplySimulationError(
                "simulation_journal_result_mismatch",
                "fake simulation journal/result verification failed",
            )
        journal_cursor += expected_entry_count
        for attempt_index, entry in enumerate(entries, start=1):
            expected_attempt = (
                0 if operation_result.status is JournalEntryStatus.SKIPPED else attempt_index
            )
            if (
                entry.operation_index != operation_result.operation_index
                or entry.operation_key != operation_result.operation_key
                or entry.operation is not operation_result.operation
                or entry.source_ref != operation_result.source_ref
                or entry.google_ref != operation_result.google_ref
                or entry.payload_hash != operation_result.payload_hash
                or entry.attempt != expected_attempt
            ):
                raise ApplySimulationError(
                    "simulation_journal_identity_mismatch",
                    "fake simulation journal identity verification failed",
                )
            is_terminal_entry = attempt_index == len(entries)
            if not is_terminal_entry and entry.status is not JournalEntryStatus.RETRYING:
                raise ApplySimulationError(
                    "simulation_retry_journal_mismatch",
                    "fake simulation retry journal verification failed",
                )
            if not is_terminal_entry and entry.delay_units < 1:
                raise ApplySimulationError(
                    "simulation_retry_delay_invalid",
                    "fake simulation retry delay verification failed",
                )
            if is_terminal_entry and (
                entry.status is not operation_result.status
                or entry.outcome_code != operation_result.outcome_code
                or entry.result_state_hash != operation_result.result_state_hash
            ):
                raise ApplySimulationError(
                    "simulation_terminal_journal_mismatch",
                    "fake simulation terminal journal verification failed",
                )
        if operation_result.status not in {
            JournalEntryStatus.SUCCEEDED,
            JournalEntryStatus.SKIPPED,
        }:
            terminal_seen = True
    if journal_cursor != result.journal.entry_count:
        raise ApplySimulationError(
            "simulation_journal_count_mismatch",
            "fake simulation journal count verification failed",
        )
    if (
        result.journal.bundle_integrity_hash != result.bundle_integrity_hash
        or result.journal.plan_content_hash != result.plan_content_hash
        or result.journal.baseline_integrity_hash != result.baseline_integrity_hash
        or result.journal.target_reference != result.target_reference
        or result.journal.operation_count != result.total_operation_count
    ):
        raise ApplySimulationError(
            "simulation_journal_binding_mismatch",
            "fake simulation journal binding verification failed",
        )
    if not hmac.compare_digest(
        calculate_apply_simulation_result_hash(result),
        result.result_content_hash,
    ):
        raise ApplySimulationError(
            "simulation_result_hash_mismatch",
            "fake simulation result hash verification failed",
        )


def run_apply_simulation(
    bundle: ApplyBundle,
    transport: FakeMutationTransport,
    *,
    retry_policy: ApplyRetryPolicy | None = None,
    jitter: JitterFunction = deterministic_jitter_units,
) -> ApplySimulationResult:
    """Run approved test-only operations sequentially against one fake transport."""

    if not isinstance(transport, FakeMutationTransport):
        raise ApplySimulationError(
            "fake_transport_required",
            "fake mutation transport is required",
        )
    _recheck_simulation_policy(bundle)
    policy = retry_policy or ApplyRetryPolicy()
    journal = initialize_operation_journal(bundle)
    operation_results: list[SimulatedOperationResult] = []
    terminal_state: ApplySimulationState | None = None
    terminal_index: int | None = None

    for index, operation in enumerate(bundle.operations):
        _recheck_simulation_policy(bundle)
        for attempt in range(1, policy.max_attempts + 1):
            transport_result = _simulate_attempt(transport, operation, attempt)
            evaluation = evaluate_retry(
                policy,
                operation_key=operation.operation_integrity_hash,
                outcome=transport_result.outcome,
                attempt=attempt,
                jitter=jitter,
            )
            status = _journal_status(evaluation.decision)
            outcome_code = (
                "retry_exhausted"
                if transport_result.outcome in RETRYABLE_SIMULATION_OUTCOMES
                and evaluation.decision is RetryDecision.STOP_FAILURE
                else transport_result.outcome_code
            )
            journal = append_operation_journal_entry(
                journal,
                operation_index=operation.operation_sequence,
                operation_key=operation.operation_integrity_hash,
                operation=operation.operation,
                source_ref=operation.source_ref,
                google_ref=operation.google_ref,
                attempt=attempt,
                status=status,
                outcome_code=outcome_code,
                delay_units=evaluation.delay_units,
                payload_hash=operation.payload_hash,
                response_hash=transport_result.transport_state_hash,
                expected_etag_hash=transport_result.expected_etag_hash,
                result_state_hash=transport_result.result_state_hash,
            )
            if evaluation.decision is RetryDecision.RETRY:
                continue
            operation_results.append(
                SimulatedOperationResult(
                    operation_index=operation.operation_sequence,
                    operation_key=operation.operation_integrity_hash,
                    operation=operation.operation,
                    source_ref=operation.source_ref,
                    google_ref=operation.google_ref,
                    status=status,
                    attempts=attempt,
                    retry_count=attempt - 1,
                    outcome_code=outcome_code,
                    payload_hash=operation.payload_hash,
                    result_state_hash=transport_result.result_state_hash,
                )
            )
            if evaluation.decision is RetryDecision.STOP_UNCERTAIN:
                terminal_state = ApplySimulationState.UNCERTAIN
            elif evaluation.decision is RetryDecision.STOP_CONFLICT:
                terminal_state = ApplySimulationState.ETAG_CONFLICT
            elif evaluation.decision is RetryDecision.STOP_FAILURE:
                terminal_state = ApplySimulationState.PARTIAL_FAILURE
            if terminal_state is not None:
                terminal_index = index
            break
        if terminal_state is not None:
            break

    if terminal_state is not None and terminal_index is not None:
        for operation in bundle.operations[terminal_index + 1 :]:
            journal = append_operation_journal_entry(
                journal,
                operation_index=operation.operation_sequence,
                operation_key=operation.operation_integrity_hash,
                operation=operation.operation,
                source_ref=operation.source_ref,
                google_ref=operation.google_ref,
                attempt=0,
                status=JournalEntryStatus.SKIPPED,
                outcome_code="skipped_after_stop",
                payload_hash=operation.payload_hash,
                response_hash=transport.state_hash(),
                expected_etag_hash=_expected_etag_hash(operation),
            )
            operation_results.append(
                SimulatedOperationResult(
                    operation_index=operation.operation_sequence,
                    operation_key=operation.operation_integrity_hash,
                    operation=operation.operation,
                    source_ref=operation.source_ref,
                    google_ref=operation.google_ref,
                    status=JournalEntryStatus.SKIPPED,
                    attempts=0,
                    retry_count=0,
                    outcome_code="skipped_after_stop",
                    payload_hash=operation.payload_hash,
                    result_state_hash=None,
                )
            )
    if terminal_state is None:
        terminal_state = ApplySimulationState.COMPLETED
        journal_state = JournalState.COMPLETED
        final_bundle = mark_apply_simulation_complete(bundle)
    else:
        journal_state = {
            ApplySimulationState.PARTIAL_FAILURE: JournalState.PARTIAL_FAILURE,
            ApplySimulationState.UNCERTAIN: JournalState.UNCERTAIN,
            ApplySimulationState.ETAG_CONFLICT: JournalState.ETAG_CONFLICT,
        }[terminal_state]
        final_bundle = mark_apply_simulation_failed(bundle)
    journal = transition_operation_journal(journal, journal_state)
    succeeded_count = sum(item.status is JournalEntryStatus.SUCCEEDED for item in operation_results)
    skipped_count = sum(item.status is JournalEntryStatus.SKIPPED for item in operation_results)
    failed_count = sum(item.status is JournalEntryStatus.FAILED for item in operation_results)
    uncertain_count = sum(item.status is JournalEntryStatus.UNCERTAIN for item in operation_results)
    etag_conflict_count = sum(
        item.status is JournalEntryStatus.ETAG_CONFLICT for item in operation_results
    )
    provisional = ApplySimulationResult(
        state=terminal_state,
        environment=bundle.environment,
        approval_state="approved_for_simulation",
        source_profile=bundle.source_profile,
        bundle_integrity_hash=bundle.bundle_integrity_hash,
        final_bundle_integrity_hash=final_bundle.bundle_integrity_hash,
        final_bundle_state=final_bundle.state,
        plan_content_hash=bundle.plan_content_hash,
        baseline_integrity_hash=bundle.baseline_integrity_hash,
        target_reference=bundle.target_reference,
        total_operation_count=len(bundle.operations),
        add_count=bundle.add_count,
        update_count=bundle.update_count,
        delete_count=0,
        attempted_operation_count=len(bundle.operations) - skipped_count,
        succeeded_count=succeeded_count,
        failed_count=failed_count,
        uncertain_count=uncertain_count,
        etag_conflict_count=etag_conflict_count,
        skipped_count=skipped_count,
        retry_count=sum(item.retry_count for item in operation_results),
        partial_results=succeeded_count > 0
        and terminal_state is not ApplySimulationState.COMPLETED,
        operation_results=tuple(operation_results),
        journal=journal,
        final_transport_state_hash=transport.state_hash(),
        result_content_hash="0" * 64,
    )
    result = provisional.model_copy(
        update={"result_content_hash": calculate_apply_simulation_result_hash(provisional)}
    )
    verify_apply_simulation_result(result)
    return result


__all__ = [
    "ApplySimulationError",
    "ApplySimulationResult",
    "ApplySimulationState",
    "SimulatedOperationResult",
    "calculate_apply_simulation_result_hash",
    "run_apply_simulation",
    "verify_apply_simulation_result",
]
