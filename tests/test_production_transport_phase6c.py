from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from phase6b_helpers import build_production_snapshot
from phase6c_transport_helpers import (
    PHASE6C_NOW,
    PHASE6C_TOKEN_GENERATION,
    ProductionTransportArtifacts,
    build_production_transport_artifacts,
    make_state_provider,
    make_transport_bundle,
)

from tridentine_calendar_google_sync.production_approval_state import (
    build_production_execute_permit,
    production_arm_challenge,
    transition_production_kill_switch,
)
from tridentine_calendar_google_sync.production_approval_state_models import (
    derive_production_execute_nonce,
)
from tridentine_calendar_google_sync.production_execution_journal import (
    ProductionExecutionJournalPhase,
    load_production_execution_journal_file,
)
from tridentine_calendar_google_sync.production_fake_transport import (
    FakeProductionTransportBundle,
    ProductionTransportFailure,
    paginate_production_snapshot,
    production_live_execution_not_available,
)
from tridentine_calendar_google_sync.production_single_update_run_spec import (
    calculate_production_single_update_run_spec_hash,
)
from tridentine_calendar_google_sync.production_transport import (
    ProductionMockExecutionError,
    phase6c_production_live_execution_hard_off,
    run_production_single_update_mock,
)
from tridentine_calendar_google_sync.production_transport_models import (
    ProductionExecutionResultState,
    ProductionExecutionStateProvider,
    ProductionMockExecutionResult,
)


def _run(
    artifacts: ProductionTransportArtifacts,
    tmp_path: Path,
    transport: FakeProductionTransportBundle,
    *,
    state_provider: ProductionExecutionStateProvider | None = None,
    execute_confirmation: str | None = None,
    suffix: str = "one",
) -> ProductionMockExecutionResult:
    return run_production_single_update_mock(
        run_spec=artifacts.run_spec,
        plan=artifacts.plan,
        manifest=artifacts.inputs.manifest,
        trusted_baseline=artifacts.inputs.baseline,
        bound_snapshot=artifacts.inputs.snapshot,
        desired_source=artifacts.inputs.updated.source,
        arm_receipt=artifacts.arm_receipt,
        execute_permit=artifacts.execute_permit,
        execute_confirmation=(
            artifacts.execute_confirmation if execute_confirmation is None else execute_confirmation
        ),
        approval_kill_switch=artifacts.kill_switch,
        approval_store=artifacts.approval_store,
        write_token_generation=PHASE6C_TOKEN_GENERATION,
        permit_consumption_directory=artifacts.approval_store_directory,
        journal_path=tmp_path / f"journal-{suffix}.ndjson",
        full_snapshot_reader=transport.full_snapshot_reader,
        fresh_event_reader=transport.fresh_event_reader,
        single_update_mutator=transport.single_update_mutator,
        state_provider=(
            make_state_provider(artifacts) if state_provider is None else state_provider
        ),
        now=PHASE6C_NOW + timedelta(seconds=1),
    )


@pytest.mark.parametrize(
    ("page_sizes", "expected_calls"),
    [
        ((4,), 5),
        ((2, 2), 7),
        ((1, 1, 2), 9),
    ],
)
def test_nominal_call_counts_and_durable_journal(
    tmp_path: Path,
    page_sizes: tuple[int, ...],
    expected_calls: int,
) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    transport = make_transport_bundle(artifacts, page_sizes=page_sizes)

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.SUCCEEDED
    assert result.api_call_count == expected_calls
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0
    assert result.baseline_renewal_required is True
    assert result.recovered_uncertain_outcome is False
    assert transport.raw_call_counts == (expected_calls - 3, 2, 1)
    assert transport.call_log.count("events.patch") == 1
    assert transport.patch_observations[0].body_fields == ("description",)
    assert transport.patch_observations[0].if_match_wildcard is False
    assert transport.patch_observations[0].send_updates == "none"
    assert transport.patch_observations[0].token_role == "production_write"
    assert transport.patch_observations[0].write_token_generation_present is True
    assert all(
        observation.token_role == "production_read_only"
        for observation in transport.get_observations
    )
    assert len(transport.list_observations) == expected_calls - 3
    assert all(
        observation.token_role == "production_read_only"
        and observation.single_events is False
        and observation.show_deleted is True
        and observation.max_results == 2500
        and observation.time_min_present is False
        and observation.time_max_present is False
        and observation.sync_token_present is False
        and observation.query_present is False
        for observation in transport.list_observations
    )
    journal = load_production_execution_journal_file(tmp_path / "journal-one.ndjson")
    assert journal.journal_content_hash == result.journal.journal_content_hash
    assert tuple(entry.phase for entry in journal.entries) == tuple(ProductionExecutionJournalPhase)


def test_exact_execute_confirmation_and_replay_stop_before_api(tmp_path: Path) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    rejected_transport = make_transport_bundle(artifacts, page_sizes=(4,))
    rejected = _run(
        artifacts,
        tmp_path,
        rejected_transport,
        execute_confirmation="EXECUTE production calendar write",
        suffix="bad-confirmation",
    )
    assert rejected.result_state is ProductionExecutionResultState.FAILED_APPROVAL
    assert rejected.permit_consumed is False
    assert rejected_transport.call_log == ()

    first_transport = make_transport_bundle(artifacts, page_sizes=(4,))
    first = _run(artifacts, tmp_path, first_transport, suffix="first")
    assert first.result_state is ProductionExecutionResultState.SUCCEEDED
    replay_transport = make_transport_bundle(artifacts, page_sizes=(4,))
    replay = _run(artifacts, tmp_path, replay_transport, suffix="replay")
    assert replay.result_state is ProductionExecutionResultState.FAILED_APPROVAL
    assert replay_transport.call_log == ()


def test_execute_nonce_and_permit_key_are_deterministic_per_arm(tmp_path: Path) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    rebuilt = build_production_execute_permit(
        artifacts.arm_receipt,
        artifacts.run_spec,
        artifacts.plan,
        artifacts.kill_switch,
        artifacts.approval_store,
        arm_confirmation=production_arm_challenge(artifacts.arm_receipt),
        write_token_generation=PHASE6C_TOKEN_GENERATION,
    )
    assert rebuilt.execute_nonce == derive_production_execute_nonce(
        artifacts.arm_receipt.content_hash,
        artifacts.arm_receipt.arm_nonce,
    )
    assert rebuilt.content_hash == artifacts.execute_permit.content_hash


def test_switch_generation_is_rechecked_before_patch(tmp_path: Path) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    changed = transition_production_kill_switch(
        artifacts.kill_switch,
        issued_at=PHASE6C_NOW,
        state="on",
    )
    transport = make_transport_bundle(artifacts, page_sizes=(4,))
    provider = make_state_provider(
        artifacts,
        kill_switches=(artifacts.kill_switch, changed),
    )

    result = _run(artifacts, tmp_path, transport, state_provider=provider)

    assert result.result_state is ProductionExecutionResultState.FAILED_KILL_SWITCH
    assert transport.call_log == ("events.list", "events.get")
    assert transport.raw_call_counts == (1, 1, 0)


def test_pre_snapshot_drift_consumes_permit_but_never_patches(tmp_path: Path) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    drifted = build_production_snapshot(
        artifacts.inputs.current.source,
        artifacts.inputs.target,
        event_overrides={1: {"description": "Unrelated external drift"}},
    )
    transport = FakeProductionTransportBundle(
        collections=(paginate_production_snapshot(drifted, (4,)),),
        get_events=(),
    )

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.FAILED_DRIFT
    assert result.permit_consumed is True
    assert transport.raw_call_counts == (1, 0, 0)


def test_fresh_preimage_mismatch_stops_before_patch(tmp_path: Path) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    pre = artifacts.inputs.snapshot
    target = next(
        event
        for event in pre.events
        if event.safe_ical_uid_reference == artifacts.run_spec.operation.safe_uid_ref
    )
    mismatched = target.model_copy(update={"summary": "Changed outside planning"})
    transport = FakeProductionTransportBundle(
        collections=(paginate_production_snapshot(pre, (4,)),),
        get_events=(mismatched,),
        expected_if_match=target.etag,
    )

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.FAILED_PREIMAGE
    assert transport.raw_call_counts == (1, 1, 0)


def test_etag_conflict_is_one_attempt_and_no_second_patch(tmp_path: Path) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    transport = make_transport_bundle(
        artifacts,
        page_sizes=(4,),
        patch_failure=ProductionTransportFailure(
            "etag_conflict",
            etag_conflict=True,
        ),
    )

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.ETAG_CONFLICT
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0
    assert transport.raw_call_counts == (1, 1, 1)


@pytest.mark.parametrize("desired_found", [True, False])
def test_uncertain_patch_outcome_uses_one_get_and_never_second_patch(
    tmp_path: Path,
    desired_found: bool,
) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    pre_snapshot = artifacts.inputs.snapshot
    post_snapshot = build_production_snapshot(
        artifacts.inputs.updated.source,
        artifacts.inputs.target,
    )
    pre_event = next(
        event
        for event in pre_snapshot.events
        if event.safe_ical_uid_reference == artifacts.run_spec.operation.safe_uid_ref
    )
    post_event = next(
        event
        for event in post_snapshot.events
        if event.safe_ical_uid_reference == artifacts.run_spec.operation.safe_uid_ref
    )
    recovery = post_event if desired_found else pre_event
    transport = FakeProductionTransportBundle(
        collections=(
            paginate_production_snapshot(pre_snapshot, (4,)),
            paginate_production_snapshot(post_snapshot, (4,)),
        ),
        get_events=(pre_event, recovery),
        expected_if_match=pre_event.etag,
        patch_failure=ProductionTransportFailure(
            "response_lost",
            uncertain_patch_outcome=True,
        ),
    )

    result = _run(artifacts, tmp_path, transport)

    expected = (
        ProductionExecutionResultState.SUCCEEDED
        if desired_found
        else ProductionExecutionResultState.WRITE_OUTCOME_UNCERTAIN
    )
    assert result.result_state is expected
    assert result.recovered_uncertain_outcome is desired_found
    assert transport.raw_call_counts[2] == 1
    assert transport.call_log.count("events.patch") == 1


def test_three_pages_plus_one_read_retry_is_exactly_ten_calls(tmp_path: Path) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    transport = make_transport_bundle(
        artifacts,
        page_sizes=(1, 1, 2),
        list_failures={1: ProductionTransportFailure("rate_limit", retryable_read=True)},
    )

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.SUCCEEDED
    assert result.api_call_count == 10
    assert result.read_retry_count == 1


def test_predicted_eleventh_call_is_not_issued(tmp_path: Path) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    transport = make_transport_bundle(artifacts, page_sizes=(1, 1, 1, 1))

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.API_CALL_LIMIT_EXCEEDED
    assert result.api_call_count == 10
    assert len(transport.call_log) == 10
    assert transport.call_log.count("events.patch") == 1


def test_capability_facades_and_live_hard_off() -> None:
    assert not hasattr(production_live_execution_not_available, "list_events")
    with pytest.raises(ProductionTransportFailure) as fake_exc:
        production_live_execution_not_available()
    assert fake_exc.value.code == ("production_live_execution_not_available_in_phase_6c")
    with pytest.raises(ProductionMockExecutionError) as orchestrator_exc:
        phase6c_production_live_execution_hard_off()
    assert orchestrator_exc.value.code == ("production_live_execution_not_available_in_phase_6c")


def test_run_spec_tamper_fails_before_consumption_and_api(tmp_path: Path) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    tampered = artifacts.run_spec.model_copy(update={"diff_hash": "e" * 64})
    tampered = tampered.model_copy(
        update={"run_spec_content_hash": calculate_production_single_update_run_spec_hash(tampered)}
    )
    artifacts = ProductionTransportArtifacts(
        inputs=artifacts.inputs,
        plan=artifacts.plan,
        run_spec=tampered,
        kill_switch=artifacts.kill_switch,
        initial_kill_switch=artifacts.initial_kill_switch,
        approval_store=artifacts.approval_store,
        approval_store_directory=artifacts.approval_store_directory,
        arm_receipt=artifacts.arm_receipt,
        execute_permit=artifacts.execute_permit,
        execute_confirmation=artifacts.execute_confirmation,
    )
    transport = make_transport_bundle(artifacts, page_sizes=(4,))

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.FAILED_APPROVAL
    assert result.permit_consumed is False
    assert transport.call_log == ()
