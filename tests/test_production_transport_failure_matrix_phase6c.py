from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import pytest
from phase6b_helpers import build_production_snapshot
from phase6c_transport_helpers import (
    PHASE6C_NOW,
    PHASE6C_TOKEN_GENERATION,
    ProductionTransportArtifacts,
    build_production_transport_artifacts,
    make_state_provider,
)

import tridentine_calendar_google_sync.production_transport as production_transport_module
from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.diff_models import ManagedScope
from tridentine_calendar_google_sync.google_models import GoogleEventTime, GoogleSnapshot
from tridentine_calendar_google_sync.production_approval_state import (
    build_production_kill_switch,
    transition_production_kill_switch,
)
from tridentine_calendar_google_sync.production_approval_state_io import (
    load_production_execute_permit_consumption,
    production_execute_permit_consumption_filename,
)
from tridentine_calendar_google_sync.production_execution_journal import (
    ProductionExecutionJournalError,
    ProductionExecutionJournalPhase,
    load_production_execution_journal_file,
)
from tridentine_calendar_google_sync.production_fake_transport import (
    FakeProductionTransportBundle,
    ProductionTransportFailure,
    paginate_production_snapshot,
)
from tridentine_calendar_google_sync.production_transport import (
    ProductionMockExecutionError,
    run_production_single_update_mock,
    verify_production_post_write_zero_diff,
)
from tridentine_calendar_google_sync.production_transport_models import (
    ProductionExecutionResultState,
    ProductionExecutionStateProvider,
    ProductionMockExecutionResult,
    ProductionTokenSeparationPolicy,
)


def _target_events(
    artifacts: ProductionTransportArtifacts,
    post_snapshot: GoogleSnapshot,
) -> tuple[Any, Any]:
    pre_event = next(
        event
        for event in artifacts.inputs.snapshot.events
        if event.safe_ical_uid_reference == artifacts.run_spec.operation.safe_uid_ref
    )
    post_event = next(
        event
        for event in post_snapshot.events
        if event.safe_ical_uid_reference == artifacts.run_spec.operation.safe_uid_ref
    )
    return pre_event, post_event


def _bundle(
    artifacts: ProductionTransportArtifacts,
    *,
    pre_snapshot: GoogleSnapshot | None = None,
    post_snapshot: GoogleSnapshot | None = None,
    fresh_event: Any | None = None,
    read_back_event: Any | None = None,
    page_sizes: tuple[int, ...] | None = None,
    patch_failure: ProductionTransportFailure | None = None,
) -> FakeProductionTransportBundle:
    resolved_pre = artifacts.inputs.snapshot if pre_snapshot is None else pre_snapshot
    clean_post = build_production_snapshot(
        artifacts.inputs.updated.source,
        artifacts.inputs.target,
    )
    resolved_post = clean_post if post_snapshot is None else post_snapshot
    default_fresh, default_read_back = _target_events(artifacts, clean_post)
    sizes = (resolved_pre.event_count,) if page_sizes is None else page_sizes
    post_sizes = sizes
    if sum(post_sizes) != resolved_post.event_count:
        post_sizes = (resolved_post.event_count,)
    return FakeProductionTransportBundle(
        collections=(
            paginate_production_snapshot(resolved_pre, sizes),
            paginate_production_snapshot(resolved_post, post_sizes),
        ),
        get_events=(
            default_fresh if fresh_event is None else fresh_event,
            default_read_back if read_back_event is None else read_back_event,
        ),
        patch_failure=patch_failure,
        expected_if_match=(default_fresh if fresh_event is None else fresh_event).etag,
    )


def _run(
    artifacts: ProductionTransportArtifacts,
    tmp_path: Path,
    transport: FakeProductionTransportBundle,
    *,
    provider: ProductionExecutionStateProvider | None = None,
    permit_consumption_directory: Path | None = None,
    suffix: str = "matrix",
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
        execute_confirmation=artifacts.execute_confirmation,
        approval_kill_switch=artifacts.kill_switch,
        approval_store=artifacts.approval_store,
        write_token_generation=PHASE6C_TOKEN_GENERATION,
        permit_consumption_directory=(
            artifacts.approval_store_directory
            if permit_consumption_directory is None
            else permit_consumption_directory
        ),
        journal_path=tmp_path / f"journal-{suffix}.ndjson",
        full_snapshot_reader=transport.full_snapshot_reader,
        fresh_event_reader=transport.fresh_event_reader,
        single_update_mutator=transport.single_update_mutator,
        state_provider=make_state_provider(artifacts) if provider is None else provider,
        now=PHASE6C_NOW + timedelta(seconds=1),
    )


@pytest.mark.parametrize(
    "event_updates",
    [
        {"summary": "External summary"},
        {"description": "External description"},
        {"start": GoogleEventTime(date=date(2099, 2, 1))},
        {"status": "cancelled"},
        {"recurrence": ("RRULE:FREQ=YEARLY",)},
        {"event_type": "birthday"},
        {"ical_uid": "other@calendar.example"},
        {"event_id": "other-event-id"},
        {"etag": None},
        {"etag": "*"},
        {"etag": "stale-etag"},
    ],
)
def test_every_preimage_mismatch_stops_before_patch(
    tmp_path: Path,
    event_updates: dict[str, object],
) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    post = build_production_snapshot(artifacts.inputs.updated.source, artifacts.inputs.target)
    fresh, _ = _target_events(artifacts, post)
    transport = _bundle(artifacts, fresh_event=fresh.model_copy(update=event_updates))

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.FAILED_PREIMAGE
    assert transport.raw_call_counts[2] == 0


@pytest.mark.parametrize(
    "variant",
    [
        "unrelated_description",
        "unrelated_summary",
        "unrelated_date",
        "target_description",
        "added",
        "removed",
        "duplicate",
        "incomplete",
        "wrong_target",
    ],
)
def test_pre_full_snapshot_fail_closed_matrix(tmp_path: Path, variant: str) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    kwargs: dict[str, object] = {}
    if variant == "unrelated_description":
        kwargs["event_overrides"] = {1: {"description": "Unrelated drift"}}
    elif variant == "unrelated_summary":
        kwargs["event_overrides"] = {1: {"summary": "Unrelated drift"}}
    elif variant == "unrelated_date":
        kwargs["event_overrides"] = {1: {"start": {"date": "2099-03-01"}}}
    elif variant == "target_description":
        kwargs["event_overrides"] = {2: {"description": "Target external drift"}}
    elif variant == "duplicate":
        first_uid = artifacts.inputs.current.source.events[0].uid
        kwargs["event_overrides"] = {2: {"iCalUID": first_uid}}
    elif variant == "added":
        kwargs["extra_events"] = (
            {
                "id": "extra-pre-event",
                "iCalUID": "extra-pre@calendar.example",
                "summary": "Extra",
                "description": "Extra",
                "start": {"date": "2099-12-01"},
                "end": {"date": "2099-12-02"},
                "allDay": True,
                "status": "confirmed",
                "eventType": "default",
                "etag": "extra-pre-etag",
            },
        )
    pre = build_production_snapshot(
        artifacts.inputs.current.source,
        artifacts.inputs.target,
        **kwargs,
    )
    if variant == "removed":
        pre = pre.model_copy(update={"event_count": pre.event_count - 1, "events": pre.events[:-1]})
    elif variant == "incomplete":
        pre = pre.model_copy(update={"complete": False})
    elif variant == "wrong_target":
        pre = pre.model_copy(update={"target_fingerprint": "f" * 64})
    transport = _bundle(artifacts, pre_snapshot=pre)

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.FAILED_DRIFT
    assert transport.raw_call_counts[2] == 0


@pytest.mark.parametrize(
    "event_updates",
    [
        {"description": "Old Description"},
        {"summary": "Unexpected summary"},
        {"start": GoogleEventTime(date=date(2099, 2, 1))},
        {"end": GoogleEventTime(date=date(2099, 2, 2))},
        {"status": "cancelled"},
        {"recurrence": ("RRULE:FREQ=YEARLY",)},
        {"event_type": "birthday"},
        {"color_id": "1"},
        {"event_label_id": "2"},
    ],
)
def test_every_readback_mismatch_fails_without_rollback_or_second_patch(
    tmp_path: Path,
    event_updates: dict[str, object],
) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    post = build_production_snapshot(artifacts.inputs.updated.source, artifacts.inputs.target)
    _, read_back = _target_events(artifacts, post)
    transport = _bundle(
        artifacts,
        read_back_event=read_back.model_copy(update=event_updates),
    )

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.FAILED_READBACK
    assert transport.call_log.count("events.patch") == 1
    assert result.mutation_retry_count == 0


@pytest.mark.parametrize(
    "variant",
    [
        "unrelated_description",
        "unrelated_summary",
        "unrelated_date",
        "added",
        "removed",
        "duplicate",
        "incomplete",
        "wrong_target",
        "summary_metadata",
    ],
)
def test_post_full_snapshot_fail_closed_matrix(tmp_path: Path, variant: str) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    kwargs: dict[str, object] = {}
    if variant == "unrelated_description":
        kwargs["event_overrides"] = {1: {"description": "Unrelated drift"}}
    elif variant == "unrelated_summary":
        kwargs["event_overrides"] = {1: {"summary": "Unrelated drift"}}
    elif variant == "unrelated_date":
        kwargs["event_overrides"] = {1: {"start": {"date": "2099-03-01"}}}
    elif variant == "duplicate":
        first_uid = artifacts.inputs.updated.source.events[0].uid
        kwargs["event_overrides"] = {2: {"iCalUID": first_uid}}
    elif variant == "added":
        kwargs["extra_events"] = (
            {
                "id": "extra-production-like-event",
                "iCalUID": "extra@calendar.example",
                "summary": "Extra",
                "description": "Extra",
                "start": {"date": "2099-12-01"},
                "end": {"date": "2099-12-02"},
                "allDay": True,
                "status": "confirmed",
                "eventType": "default",
                "etag": "extra-etag",
            },
        )
    post = build_production_snapshot(
        artifacts.inputs.updated.source,
        artifacts.inputs.target,
        **kwargs,
    )
    if variant == "removed":
        post = post.model_copy(
            update={
                "event_count": post.event_count - 1,
                "events": post.events[:-1],
            }
        )
    elif variant == "incomplete":
        post = post.model_copy(update={"complete": False})
    elif variant == "wrong_target":
        post = post.model_copy(update={"target_fingerprint": "f" * 64})
    elif variant == "summary_metadata":
        post = post.model_copy(update={"collection_metadata_hash": "5" * 64})
    transport = _bundle(artifacts, post_snapshot=post)

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.FAILED_POST_SNAPSHOT
    assert transport.call_log.count("events.patch") == 1
    assert result.mutation_retry_count == 0


@pytest.mark.parametrize(
    ("switch_stage", "token_stage"),
    [
        ("off_before_list", "exact"),
        ("off_before_patch", "exact"),
        ("changed_before_list", "exact"),
        ("changed_before_patch", "exact"),
        ("exact", "missing_before_list"),
        ("exact", "changed_before_list"),
        ("exact", "changed_before_patch"),
    ],
)
def test_switch_and_token_generation_matrix(
    tmp_path: Path,
    switch_stage: str,
    token_stage: str,
) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    off = transition_production_kill_switch(
        artifacts.kill_switch,
        issued_at=PHASE6C_NOW,
        state="off",
    )
    changed = transition_production_kill_switch(
        artifacts.kill_switch,
        issued_at=PHASE6C_NOW,
        state="on",
    )
    switches = {
        "off_before_list": (off,),
        "off_before_patch": (artifacts.kill_switch, off),
        "changed_before_list": (changed,),
        "changed_before_patch": (artifacts.kill_switch, changed),
        "exact": (artifacts.kill_switch,),
    }[switch_stage]
    generations = {
        "exact": (PHASE6C_TOKEN_GENERATION,),
        "missing_before_list": (None,),
        "changed_before_list": (PHASE6C_TOKEN_GENERATION + 1,),
        "changed_before_patch": (PHASE6C_TOKEN_GENERATION, PHASE6C_TOKEN_GENERATION + 1),
    }[token_stage]
    provider = make_state_provider(
        artifacts,
        kill_switches=switches,
        token_generations=generations,
    )
    transport = _bundle(artifacts)

    result = _run(artifacts, tmp_path, transport, provider=provider)

    assert result.result_state is ProductionExecutionResultState.FAILED_KILL_SWITCH
    expected_reads = 2 if switch_stage.endswith("patch") or token_stage.endswith("patch") else 0
    assert len(transport.call_log) == expected_reads
    assert transport.raw_call_counts[2] == 0


@pytest.mark.parametrize(
    "failure",
    [
        ProductionTransportFailure("permission_denied"),
        ProductionTransportFailure("bad_request"),
        ProductionTransportFailure("not_found"),
        ProductionTransportFailure("gone"),
    ],
)
def test_nonretryable_read_failure_never_retries(
    tmp_path: Path,
    failure: ProductionTransportFailure,
) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    pre = artifacts.inputs.snapshot
    transport = FakeProductionTransportBundle(
        collections=(paginate_production_snapshot(pre, (pre.event_count,)),),
        get_events=(),
        list_failures={1: failure},
    )

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.FAILED_DRIFT
    assert result.api_call_count == 1
    assert result.read_retry_count == 0
    assert transport.raw_call_counts == (1, 0, 0)


def test_mutation_retry_classification_is_rejected_and_patch_never_retries(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="classification"):
        ProductionTransportFailure("permission_denied", retryable_read=True)
    artifacts = build_production_transport_artifacts(tmp_path)
    transport = _bundle(
        artifacts,
        patch_failure=ProductionTransportFailure("server_503", retryable_read=True),
    )

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.FAILED_TRANSPORT
    assert transport.call_log.count("events.patch") == 1
    assert result.mutation_retry_count == 0


@pytest.mark.parametrize(
    "code",
    ["rate_limit", "rate_limit_403", "server_500", "server_502", "server_503"],
)
def test_only_closed_retryable_read_codes_get_one_bounded_retry(
    tmp_path: Path,
    code: str,
) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    pre = artifacts.inputs.snapshot
    post = build_production_snapshot(artifacts.inputs.updated.source, artifacts.inputs.target)
    fresh, read_back = _target_events(artifacts, post)
    transport = FakeProductionTransportBundle(
        collections=(
            paginate_production_snapshot(pre, (pre.event_count,)),
            paginate_production_snapshot(post, (post.event_count,)),
        ),
        get_events=(fresh, read_back),
        list_failures={1: ProductionTransportFailure(code, retryable_read=True)},
        expected_if_match=fresh.etag,
    )

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.SUCCEEDED
    assert result.api_call_count == 6
    assert result.read_retry_count == 1


def test_switch_target_mismatch_blocks_before_first_api(tmp_path: Path) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    wrong_target_initial = build_production_kill_switch(
        "T-ffffffffffff",
        issued_at=PHASE6C_NOW - timedelta(seconds=2),
    )
    wrong_target_switch = transition_production_kill_switch(
        wrong_target_initial,
        state="on",
        issued_at=PHASE6C_NOW - timedelta(seconds=1),
    )
    provider = make_state_provider(
        artifacts,
        kill_switches=(wrong_target_switch,),
    )
    transport = _bundle(artifacts)

    result = _run(artifacts, tmp_path, transport, provider=provider)

    assert result.result_state is ProductionExecutionResultState.FAILED_KILL_SWITCH
    assert transport.call_log == ()


@pytest.mark.parametrize(
    "scenario",
    ["drift", "preimage", "etag", "patch", "uncertain", "readback"],
)
def test_every_terminal_failure_consumes_permit_and_replay_has_zero_api_calls(
    tmp_path: Path,
    scenario: str,
) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    post = build_production_snapshot(artifacts.inputs.updated.source, artifacts.inputs.target)
    fresh, read_back = _target_events(artifacts, post)
    if scenario == "drift":
        drifted = build_production_snapshot(
            artifacts.inputs.current.source,
            artifacts.inputs.target,
            event_overrides={1: {"description": "drift"}},
        )
        first_transport = _bundle(artifacts, pre_snapshot=drifted)
    elif scenario == "preimage":
        first_transport = _bundle(
            artifacts,
            fresh_event=fresh.model_copy(update={"summary": "drift"}),
        )
    elif scenario == "etag":
        first_transport = _bundle(
            artifacts,
            patch_failure=ProductionTransportFailure("etag_conflict", etag_conflict=True),
        )
    elif scenario == "patch":
        first_transport = _bundle(
            artifacts,
            patch_failure=ProductionTransportFailure("server_503", retryable_read=True),
        )
    elif scenario == "uncertain":
        first_transport = _bundle(
            artifacts,
            read_back_event=fresh,
            patch_failure=ProductionTransportFailure(
                "response_lost",
                uncertain_patch_outcome=True,
            ),
        )
    else:
        first_transport = _bundle(
            artifacts,
            read_back_event=read_back.model_copy(update={"summary": "drift"}),
        )
    first = _run(artifacts, tmp_path, first_transport, suffix=f"first-{scenario}")
    assert first.permit_consumed is True
    clean = _bundle(artifacts)

    replay = _run(artifacts, tmp_path, clean, suffix=f"replay-{scenario}")

    assert replay.result_state is ProductionExecutionResultState.FAILED_APPROVAL
    assert clean.call_log == ()


def test_alternate_approval_store_directory_cannot_replay_permit(tmp_path: Path) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    first_transport = _bundle(artifacts)
    first = _run(artifacts, tmp_path, first_transport, suffix="bound-store-first")
    assert first.result_state is ProductionExecutionResultState.SUCCEEDED
    alternate_store_directory = tmp_path / "alternate-approval-store"
    alternate_store_directory.mkdir()
    replay_transport = _bundle(artifacts)

    replay = _run(
        artifacts,
        tmp_path,
        replay_transport,
        permit_consumption_directory=alternate_store_directory,
        suffix="alternate-store-replay",
    )

    assert replay.result_state is ProductionExecutionResultState.FAILED_APPROVAL
    assert replay.permit_consumed is False
    assert replay_transport.call_log == ()
    assert replay_transport.raw_call_counts == (0, 0, 0)


@pytest.mark.parametrize("variant", ["incompatible", "get_failure"])
def test_uncertain_outcome_incompatible_or_get_failure_never_second_patches(
    tmp_path: Path,
    variant: str,
) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    post = build_production_snapshot(artifacts.inputs.updated.source, artifacts.inputs.target)
    fresh, read_back = _target_events(artifacts, post)
    recovery: Any = (
        read_back.model_copy(update={"summary": "incompatible"})
        if variant == "incompatible"
        else ProductionTransportFailure("permission_denied")
    )
    pre_pages = paginate_production_snapshot(
        artifacts.inputs.snapshot,
        (artifacts.inputs.snapshot.event_count,),
    )
    transport = FakeProductionTransportBundle(
        collections=(pre_pages,),
        get_events=(fresh, recovery),
        patch_failure=ProductionTransportFailure(
            "response_lost",
            uncertain_patch_outcome=True,
        ),
        expected_if_match=fresh.etag,
    )

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.WRITE_OUTCOME_UNCERTAIN
    assert transport.call_log.count("events.patch") == 1


def test_concurrent_orchestrators_have_one_consumption_winner_and_one_api_start(
    tmp_path: Path,
) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    transports = (_bundle(artifacts), _bundle(artifacts))

    def invoke(index: int) -> ProductionMockExecutionResult:
        return _run(
            artifacts,
            tmp_path,
            transports[index],
            suffix=f"concurrent-{index}",
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(invoke, (0, 1)))

    assert sorted(result.result_state.value for result in results) == [
        "failed_approval",
        "succeeded",
    ]
    assert sum(bool(transport.call_log) for transport in transports) == 1
    assert sum(len(transport.call_log) for transport in transports) == 5


@pytest.mark.parametrize(
    "variant",
    ["update", "add", "delete_candidate", "unmanaged", "ambiguous", "duplicate", "invalid"],
)
def test_standalone_post_write_zero_diff_matrix(tmp_path: Path, variant: str) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    source = artifacts.inputs.updated.source
    scope = ManagedScope(
        trusted_source_uids=frozenset(
            event.uid for event in source.events if event.uid is not None
        ),
        trusted_baseline_uids=frozenset(artifacts.inputs.baseline.managed_uids),
    )
    if variant == "update":
        snapshot = artifacts.inputs.snapshot
        expected_count = "update"
    elif variant == "add":
        snapshot = build_production_snapshot(source, artifacts.inputs.target).model_copy(
            update={
                "event_count": source.vevent_count - 1,
                "events": build_production_snapshot(source, artifacts.inputs.target).events[:-1],
            }
        )
        expected_count = "add"
    elif variant in {"delete_candidate", "unmanaged"}:
        if variant == "delete_candidate":
            source = source.model_copy(
                update={
                    "vevent_count": source.vevent_count - 1,
                    "uid_total_count": source.uid_total_count - 1,
                    "uid_unique_count": source.uid_unique_count - 1,
                    "last_date": source.events[-2].start_date,
                    "all_day_count": source.all_day_count - 1,
                    "dtstart_date_count": source.dtstart_date_count - 1,
                    "summary_present_count": source.summary_present_count - 1,
                    "description_present_count": source.description_present_count - 1,
                    "dtstamp_present_count": source.dtstamp_present_count - 1,
                    "events": source.events[:-1],
                }
            )
            snapshot = build_production_snapshot(
                artifacts.inputs.updated.source,
                artifacts.inputs.target,
            )
            expected_count = "delete_candidate"
        else:
            expected_count = "unmanaged_google_event"
            snapshot = build_production_snapshot(
                source,
                artifacts.inputs.target,
                extra_events=(
                    {
                        "id": "extra-zero-diff-event",
                        "iCalUID": "extra-zero@calendar.example",
                        "summary": "Extra",
                        "description": "Extra",
                        "start": {"date": "2099-12-01"},
                        "end": {"date": "2099-12-02"},
                        "allDay": True,
                        "status": "confirmed",
                        "eventType": "default",
                        "etag": "extra-zero-etag",
                    },
                ),
            )
    elif variant == "ambiguous":
        snapshot = build_production_snapshot(
            source,
            artifacts.inputs.target,
            event_overrides={2: {"recurrence": ["RRULE:FREQ=YEARLY"]}},
        )
        expected_count = "ambiguous"
    elif variant == "duplicate":
        first_uid = source.events[0].uid
        snapshot = build_production_snapshot(
            source,
            artifacts.inputs.target,
            event_overrides={2: {"iCalUID": first_uid}},
        )
        expected_count = "duplicate_google_icaluid"
    else:
        snapshot = build_production_snapshot(source, artifacts.inputs.target)
        source = source.model_copy(update={"fatal": True, "source_valid": False})
        expected_count = None

    diff = diff_source_to_snapshot(source, snapshot, scope)
    if expected_count is not None:
        assert getattr(diff.counts, expected_count) >= 1
    else:
        assert source.source_valid is False and source.fatal is True

    with pytest.raises(ProductionMockExecutionError) as exc_info:
        verify_production_post_write_zero_diff(source, snapshot, scope)
    assert exc_info.value.code == "production_post_write_zero_diff_failed"


def test_current_scale_4938_events_two_pages_and_seven_calls(tmp_path: Path) -> None:
    artifacts = build_production_transport_artifacts(tmp_path, event_count=4_938)
    transport = _bundle(artifacts, page_sizes=(2_469, 2_469))

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.SUCCEEDED
    assert result.api_call_count == 7
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0
    assert result.zero_diff_verified is True


def test_secret_free_three_token_role_policy_is_closed() -> None:
    policy = ProductionTokenSeparationPolicy(write_token_generation=7)
    assert {
        policy.production_read_role,
        policy.test_write_role,
        policy.production_write_role,
    } == {"production_read_only", "test_write", "production_write"}
    assert policy.roles_distinct is True
    assert policy.token_paths_present is False
    assert policy.token_values_present is False


def test_mixed_or_duck_typed_transport_capabilities_are_rejected_before_api(
    tmp_path: Path,
) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    transport = _bundle(artifacts)
    other = _bundle(artifacts)
    transport.fresh_event_reader = other.fresh_event_reader

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.FAILED_APPROVAL
    assert result.permit_consumed is False
    assert result.safe_findings == ("production_mock_transport_required",)
    assert transport.call_log == ()
    assert other.call_log == ()


@pytest.mark.parametrize(
    ("facade_attribute", "method_name"),
    [
        ("full_snapshot_reader", "list_events"),
        ("fresh_event_reader", "get_event"),
        ("single_update_mutator", "patch_description"),
    ],
)
def test_subclassed_or_overridden_facades_are_rejected_before_consumption(
    tmp_path: Path,
    facade_attribute: str,
    method_name: str,
) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    transport = _bundle(artifacts)
    original_facade = getattr(transport, facade_attribute)

    def forbidden_override(_self: Any, **_kwargs: Any) -> Any:
        raise AssertionError("overridden facade must never be called")

    subclass = type(
        f"Overridden{type(original_facade).__name__}",
        (type(original_facade),),
        {method_name: forbidden_override},
    )
    overridden = subclass(transport._script)
    setattr(transport, facade_attribute, overridden)

    result = _run(artifacts, tmp_path, transport)

    assert result.result_state is ProductionExecutionResultState.FAILED_APPROVAL
    assert result.safe_findings == ("production_mock_transport_required",)
    assert result.permit_consumed is False
    assert transport.call_log == ()


def test_arbitrary_exception_codes_cannot_enter_public_artifacts() -> None:
    with pytest.raises(ValueError, match="failure code"):
        ProductionTransportFailure("private_description_value")


def test_journal_fsync_failure_at_mutation_intent_stops_before_patch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    transport = _bundle(artifacts)
    original = production_transport_module.append_production_execution_journal_file

    def fail_before_patch(path: Any, previous: Any, updated: Any) -> Any:
        if updated.entries[-1].phase is ProductionExecutionJournalPhase.MUTATION_INTENT:
            raise ProductionExecutionJournalError(
                "production_journal_append_failed",
                "Production execution journal could not be appended safely",
            )
        return original(path, previous, updated)

    monkeypatch.setattr(
        production_transport_module,
        "append_production_execution_journal_file",
        fail_before_patch,
    )

    with pytest.raises(ProductionExecutionJournalError) as exc_info:
        _run(artifacts, tmp_path, transport)
    assert exc_info.value.code == "production_journal_append_failed"
    assert transport.call_log == ("events.list", "events.get")
    assert transport.raw_call_counts == (1, 1, 0)
    consumption_path = (
        artifacts.approval_store_directory
        / production_execute_permit_consumption_filename(artifacts.execute_permit)
    )
    consumption = load_production_execute_permit_consumption(
        consumption_path,
        approval_store=artifacts.approval_store,
        permit=artifacts.execute_permit,
    )
    assert consumption.state == "consumed"
    journal_path = tmp_path / "journal-matrix.ndjson"
    nonterminal = load_production_execution_journal_file(
        journal_path,
        require_terminal=False,
    )
    assert nonterminal.entries[-1].phase is ProductionExecutionJournalPhase.PRE_IMAGE_VERIFIED
    with pytest.raises(ProductionExecutionJournalError):
        load_production_execution_journal_file(journal_path)


def test_least_capability_facades_expose_no_generic_google_methods(tmp_path: Path) -> None:
    artifacts = build_production_transport_artifacts(tmp_path)
    transport = _bundle(artifacts)
    public_by_facade = (
        {name for name in dir(transport.full_snapshot_reader) if not name.startswith("_")},
        {name for name in dir(transport.fresh_event_reader) if not name.startswith("_")},
        {name for name in dir(transport.single_update_mutator) if not name.startswith("_")},
    )
    assert public_by_facade == (
        {"list_events"},
        {"get_event"},
        {"patch_description"},
    )
    forbidden = {
        "import_event",
        "insert_event",
        "update_event",
        "delete_event",
        "move_event",
        "watch_events",
        "clear_calendar",
        "batch",
    }
    assert all(not methods & forbidden for methods in public_by_facade)
