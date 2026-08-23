from __future__ import annotations

import pytest
from phase4b_helpers import (
    approved_bundle,
    build_add_apply_bundle,
    build_multi_apply_bundle,
    build_two_update_apply_bundle,
    build_update_apply_bundle,
)

import tridentine_calendar_google_sync.apply_simulation as simulation_module
from tridentine_calendar_google_sync.apply_models import ApplyBundleState
from tridentine_calendar_google_sync.apply_policy import ApplyGuardError
from tridentine_calendar_google_sync.apply_report import build_apply_json_report
from tridentine_calendar_google_sync.apply_simulation import (
    ApplySimulationError,
    ApplySimulationState,
    run_apply_simulation,
    verify_apply_simulation_result,
)
from tridentine_calendar_google_sync.fake_mutation_transport import FakeMutationTransport
from tridentine_calendar_google_sync.operation_journal import (
    JournalEntryStatus,
    JournalState,
    verify_operation_journal,
)
from tridentine_calendar_google_sync.retry_policy import (
    ApplyRetryPolicy,
    SimulationOutcomeKind,
)


@pytest.mark.parametrize("builder", [build_update_apply_bundle, build_add_apply_bundle])
def test_approved_add_or_update_simulation_completes_without_execution_authority(
    builder: object,
    tmp_path: object,
    synthetic_profile_factory: object,
) -> None:
    value = builder(tmp_path, synthetic_profile_factory)  # type: ignore[operator]
    approved = approved_bundle(value)
    transport = FakeMutationTransport.from_bundle(approved)
    before_bundle_hash = approved.bundle_integrity_hash

    result = run_apply_simulation(approved, transport)

    assert result.state is ApplySimulationState.COMPLETED
    assert result.executable is False
    assert result.rollback_available is False
    assert result.succeeded_count == 1
    assert result.failed_count == result.skipped_count == 0
    assert result.final_bundle_state is ApplyBundleState.SIMULATION_COMPLETE
    assert approved.bundle_integrity_hash == before_bundle_hash
    assert result.journal.state is JournalState.COMPLETED
    assert result.journal.start_marker == "simulation_start"
    assert result.journal.completion_marker == "simulation_complete"
    verify_operation_journal(result.journal)
    verify_apply_simulation_result(result)


@pytest.mark.parametrize(
    "outcome",
    (
        SimulationOutcomeKind.RATE_LIMIT,
        SimulationOutcomeKind.SERVER_500,
        SimulationOutcomeKind.SERVER_502,
        SimulationOutcomeKind.SERVER_503,
    ),
)
def test_retryable_outcomes_retry_once_with_abstract_delay_only(
    outcome: SimulationOutcomeKind,
    tmp_path: object,
    synthetic_profile_factory: object,
) -> None:
    value = build_update_apply_bundle(tmp_path, synthetic_profile_factory)  # type: ignore[arg-type]
    approved = approved_bundle(value)
    operation = approved.operations[0]
    transport = FakeMutationTransport.from_bundle(
        approved,
        injected_outcomes={operation.operation_integrity_hash: (outcome,)},
    )

    result = run_apply_simulation(
        approved,
        transport,
        jitter=lambda _key, _attempt, _maximum: 0,
    )

    assert result.state is ApplySimulationState.COMPLETED
    assert result.retry_count == 1
    assert result.operation_results[0].attempts == 2
    assert [entry.status for entry in result.journal.entries] == [
        JournalEntryStatus.RETRYING,
        JournalEntryStatus.SUCCEEDED,
    ]
    assert result.journal.entries[0].delay_units == 1


@pytest.mark.parametrize(
    ("outcome", "state", "status"),
    (
        (
            SimulationOutcomeKind.VALIDATION_FAILURE,
            ApplySimulationState.PARTIAL_FAILURE,
            JournalEntryStatus.FAILED,
        ),
        (
            SimulationOutcomeKind.PERMISSION_DENIED,
            ApplySimulationState.PARTIAL_FAILURE,
            JournalEntryStatus.FAILED,
        ),
        (
            SimulationOutcomeKind.TARGET_MISSING,
            ApplySimulationState.PARTIAL_FAILURE,
            JournalEntryStatus.FAILED,
        ),
        (
            SimulationOutcomeKind.AMBIGUOUS_IDENTITY,
            ApplySimulationState.PARTIAL_FAILURE,
            JournalEntryStatus.FAILED,
        ),
        (
            SimulationOutcomeKind.DUPLICATE_IDENTITY,
            ApplySimulationState.PARTIAL_FAILURE,
            JournalEntryStatus.FAILED,
        ),
        (
            SimulationOutcomeKind.PERMANENT_FAILURE,
            ApplySimulationState.PARTIAL_FAILURE,
            JournalEntryStatus.FAILED,
        ),
        (
            SimulationOutcomeKind.UNCERTAIN_OUTCOME,
            ApplySimulationState.UNCERTAIN,
            JournalEntryStatus.UNCERTAIN,
        ),
        (
            SimulationOutcomeKind.ETAG_CONFLICT,
            ApplySimulationState.ETAG_CONFLICT,
            JournalEntryStatus.FAILED,
        ),
    ),
)
def test_nonretryable_outcomes_stop_after_one_attempt(
    outcome: SimulationOutcomeKind,
    state: ApplySimulationState,
    status: JournalEntryStatus,
    tmp_path: object,
    synthetic_profile_factory: object,
) -> None:
    value = build_update_apply_bundle(tmp_path, synthetic_profile_factory)  # type: ignore[arg-type]
    approved = approved_bundle(value)
    operation = approved.operations[0]
    transport = FakeMutationTransport.from_bundle(
        approved,
        injected_outcomes={operation.operation_integrity_hash: (outcome,)},
    )

    result = run_apply_simulation(approved, transport)

    assert result.state is state
    assert result.operation_results[0].status is status
    assert result.operation_results[0].attempts == 1
    assert result.retry_count == 0
    assert result.final_bundle_state is ApplyBundleState.SIMULATION_FAILED
    assert result.journal.completion_marker == "simulation_failed"


def test_default_retry_policy_allows_four_retries_then_fifth_attempt_success(
    tmp_path: object,
    synthetic_profile_factory: object,
) -> None:
    value = build_update_apply_bundle(tmp_path, synthetic_profile_factory)  # type: ignore[arg-type]
    approved = approved_bundle(value)
    operation = approved.operations[0]
    retryable_outcomes = (
        SimulationOutcomeKind.RATE_LIMIT,
        SimulationOutcomeKind.SERVER_500,
        SimulationOutcomeKind.SERVER_502,
        SimulationOutcomeKind.SERVER_503,
    )
    transport = FakeMutationTransport.from_bundle(
        approved,
        injected_outcomes={operation.operation_integrity_hash: retryable_outcomes},
    )
    jitter_calls: list[int] = []

    def zero_jitter(_key: str, attempt: int, _maximum: int) -> int:
        jitter_calls.append(attempt)
        return 0

    result = run_apply_simulation(
        approved,
        transport,
        jitter=zero_jitter,
    )

    assert ApplyRetryPolicy().max_attempts == 5
    assert result.state is ApplySimulationState.COMPLETED
    assert result.retry_count == 4
    assert result.operation_results[0].attempts == 5
    assert result.operation_results[0].outcome_code == "success"
    assert jitter_calls == [1, 2, 3, 4]
    assert [entry.status for entry in result.journal.entries] == [
        JournalEntryStatus.RETRYING,
        JournalEntryStatus.RETRYING,
        JournalEntryStatus.RETRYING,
        JournalEntryStatus.RETRYING,
        JournalEntryStatus.SUCCEEDED,
    ]


def test_default_retry_exhaustion_stops_after_fifth_attempt_without_sixth_call(
    tmp_path: object,
    synthetic_profile_factory: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = build_update_apply_bundle(tmp_path, synthetic_profile_factory)  # type: ignore[arg-type]
    approved = approved_bundle(value)
    operation = approved.operations[0]
    transport = FakeMutationTransport.from_bundle(
        approved,
        injected_outcomes={
            operation.operation_integrity_hash: (
                SimulationOutcomeKind.RATE_LIMIT,
                SimulationOutcomeKind.RATE_LIMIT,
                SimulationOutcomeKind.RATE_LIMIT,
                SimulationOutcomeKind.RATE_LIMIT,
                SimulationOutcomeKind.RATE_LIMIT,
                SimulationOutcomeKind.SUCCESS,
            )
        },
    )
    attempts: list[int] = []
    jitter_calls: list[int] = []
    original_simulate_update = FakeMutationTransport.simulate_update

    def count_simulate_update(
        self: FakeMutationTransport,
        current_operation: object,
        *,
        attempt: int,
    ) -> object:
        attempts.append(attempt)
        return original_simulate_update(
            self,
            current_operation,  # type: ignore[arg-type]
            attempt=attempt,
        )

    def zero_jitter(_key: str, attempt: int, _maximum: int) -> int:
        jitter_calls.append(attempt)
        return 0

    monkeypatch.setattr(FakeMutationTransport, "simulate_update", count_simulate_update)
    result = run_apply_simulation(approved, transport, jitter=zero_jitter)

    assert result.state is ApplySimulationState.PARTIAL_FAILURE
    assert result.retry_count == 4
    assert result.operation_results[0].attempts == 5
    assert result.operation_results[0].outcome_code == "retry_exhausted"
    assert attempts == [1, 2, 3, 4, 5]
    assert jitter_calls == [1, 2, 3, 4]
    assert [entry.status for entry in result.journal.entries] == [
        JournalEntryStatus.RETRYING,
        JournalEntryStatus.RETRYING,
        JournalEntryStatus.RETRYING,
        JournalEntryStatus.RETRYING,
        JournalEntryStatus.FAILED,
    ]


def test_retry_exhaustion_is_bounded_and_fails_closed(
    tmp_path: object,
    synthetic_profile_factory: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Retain the earlier bounded-retry regression at the new five-attempt limit."""

    test_default_retry_exhaustion_stops_after_fifth_attempt_without_sixth_call(
        tmp_path,
        synthetic_profile_factory,
        monkeypatch,
    )


def test_etag_conflict_fails_once_without_retry_or_mutation_and_skips_tail(
    tmp_path: object,
    synthetic_profile_factory: object,
) -> None:
    value = build_two_update_apply_bundle(tmp_path, synthetic_profile_factory)  # type: ignore[arg-type]
    approved = approved_bundle(value)
    first_operation = approved.operations[0]
    transport = FakeMutationTransport.from_bundle(
        approved,
        injected_outcomes={
            first_operation.operation_integrity_hash: (SimulationOutcomeKind.ETAG_CONFLICT,)
        },
    )
    initial_transport_state = transport.state_hash()

    result = run_apply_simulation(approved, transport)
    report = build_apply_json_report(result)

    assert result.state is ApplySimulationState.ETAG_CONFLICT
    assert result.attempted_operation_count == 1
    assert result.failed_count == 1
    assert result.etag_conflict_count == 1
    assert result.retry_count == 0
    assert result.succeeded_count == 0
    assert result.skipped_count == 1
    assert result.partial_results is False
    assert transport.state_hash() == initial_transport_state
    assert result.final_transport_state_hash == initial_transport_state
    assert [item.status for item in result.operation_results] == [
        JournalEntryStatus.FAILED,
        JournalEntryStatus.SKIPPED,
    ]
    assert result.operation_results[0].outcome_code == "etag_conflict"
    assert result.operation_results[1].attempts == 0
    assert report["stopped_early"] is True
    assert result.journal.state is JournalState.ETAG_CONFLICT
    assert result.journal.completion_marker == "simulation_failed"
    assert [entry.status for entry in result.journal.entries] == [
        JournalEntryStatus.FAILED,
        JournalEntryStatus.SKIPPED,
    ]
    assert result.journal.entries[0].outcome_code == "etag_conflict"
    verify_operation_journal(result.journal)
    verify_apply_simulation_result(result)


def test_partial_failure_preserves_prior_success_and_skips_later_operation(
    tmp_path: object,
    synthetic_profile_factory: object,
) -> None:
    value = build_multi_apply_bundle(tmp_path, synthetic_profile_factory)  # type: ignore[arg-type]
    approved = approved_bundle(value)
    assert len(approved.operations) == 3
    failed_operation = approved.operations[1]
    transport = FakeMutationTransport.from_bundle(
        approved,
        injected_outcomes={
            failed_operation.operation_integrity_hash: (SimulationOutcomeKind.PERMANENT_FAILURE,)
        },
    )

    result = run_apply_simulation(approved, transport)

    assert result.state is ApplySimulationState.PARTIAL_FAILURE
    assert result.partial_results is True
    assert result.succeeded_count == 1
    assert result.failed_count == 1
    assert result.skipped_count == 1
    assert [item.status for item in result.operation_results] == [
        JournalEntryStatus.SUCCEEDED,
        JournalEntryStatus.FAILED,
        JournalEntryStatus.SKIPPED,
    ]
    assert result.rollback_available is False
    assert result.journal.state is JournalState.PARTIAL_FAILURE


def test_fake_transport_is_idempotent_and_has_no_delete_method(
    tmp_path: object,
    synthetic_profile_factory: object,
) -> None:
    value = build_add_apply_bundle(tmp_path, synthetic_profile_factory)  # type: ignore[arg-type]
    approved = approved_bundle(value)
    transport = FakeMutationTransport.from_bundle(approved)
    operation = approved.operations[0]

    first = transport.simulate_add(operation, attempt=1)
    state_after_first = transport.state_hash()
    second = transport.simulate_add(operation, attempt=2)

    assert first == second
    assert transport.state_hash() == state_after_first
    assert not hasattr(transport, "delete")
    assert not hasattr(transport, "simulate_delete")


def test_unapproved_bundle_and_nonfake_transport_are_rejected(
    tmp_path: object,
    synthetic_profile_factory: object,
) -> None:
    value = build_update_apply_bundle(tmp_path, synthetic_profile_factory)  # type: ignore[arg-type]
    transport = FakeMutationTransport.from_bundle(approved_bundle(value))

    with pytest.raises(ApplyGuardError):
        run_apply_simulation(value.bundle, transport)
    with pytest.raises(ApplySimulationError):
        run_apply_simulation(approved_bundle(value), object())  # type: ignore[arg-type]


def test_simulation_policy_is_rechecked_initially_and_before_every_operation(
    tmp_path: object,
    synthetic_profile_factory: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    value = build_multi_apply_bundle(tmp_path, synthetic_profile_factory)  # type: ignore[arg-type]
    approved = approved_bundle(value)
    transport = FakeMutationTransport.from_bundle(approved)
    verify_calls = 0
    policy_calls = 0
    original_verify = simulation_module.verify_apply_bundle_integrity
    original_policy = simulation_module.require_test_bundle

    def verify(bundle: object) -> None:
        nonlocal verify_calls
        verify_calls += 1
        original_verify(bundle)  # type: ignore[arg-type]

    def policy(bundle: object) -> None:
        nonlocal policy_calls
        policy_calls += 1
        original_policy(bundle)  # type: ignore[arg-type]

    monkeypatch.setattr(simulation_module, "verify_apply_bundle_integrity", verify)
    monkeypatch.setattr(simulation_module, "require_test_bundle", policy)

    result = run_apply_simulation(approved, transport)

    assert result.state is ApplySimulationState.COMPLETED
    assert verify_calls == 1 + len(approved.operations)
    assert policy_calls == 1 + len(approved.operations)
