from __future__ import annotations

import json
from pathlib import Path

import pytest
from phase6b_helpers import build_production_snapshot
from phase6d0_rehearsal_helpers import (
    RehearsalArtifacts,
    build_rehearsal_artifacts,
    run_rehearsal,
)

from tridentine_calendar_google_sync.production_write_token import (
    ProductionWriteTokenRefreshError,
)
from tridentine_calendar_google_sync.production_write_token_models import (
    ProductionTokenRole,
    ProductionWriteAuthorizedUserToken,
    ProductionWriteCredentialSession,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal import (
    ProductionWriteTokenRehearsalError,
    ProductionWriteTokenRehearsalOutcome,
    production_write_token_rehearsal_challenge,
    run_production_write_token_readonly_rehearsal_mock,
    verify_production_write_token_rehearsal_confirmation,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_io import (
    ProductionWriteTokenRehearsalIOError,
    write_production_write_token_rehearsal_outputs,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_models import (
    ProductionWriteTokenReadOnlyTransport,
    ProductionWriteTokenRehearsalResultState,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_report import (
    render_production_write_token_rehearsal_report_json,
    render_production_write_token_rehearsal_report_text,
    render_production_write_token_rehearsal_snapshot_json,
    verify_production_write_token_rehearsal_report,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_transport import (
    FakeProductionWriteCredentialSessionProvider,
    FakeProductionWriteTokenReadOnlyTransport,
    FakeProductionWriteTokenReadOnlyTransportProvider,
    ProductionWriteTokenRehearsalTransportError,
    paginate_production_write_token_rehearsal_snapshot,
    phase6d0_live_rehearsal_transport_hard_off,
)

pytestmark = pytest.mark.google_production_write


def _run_with_transport(
    artifacts: RehearsalArtifacts,
    transport: ProductionWriteTokenReadOnlyTransport,
    *,
    confirmation: str | None = None,
) -> ProductionWriteTokenRehearsalOutcome:
    inputs = artifacts.inputs
    return run_production_write_token_readonly_rehearsal_mock(
        credential_session_provider=artifacts.credential_provider,
        transport_provider=FakeProductionWriteTokenReadOnlyTransportProvider(transport),
        target=inputs.target,
        manifest=inputs.manifest,
        accepted_profile=inputs.updated.profile,
        accepted_source=inputs.updated.source,
        trusted_baseline=inputs.baseline,
        confirmation=confirmation or artifacts.confirmation,
    )


@pytest.mark.parametrize(
    ("page_sizes", "expected_calls"),
    [((4,), 2), ((2, 2), 3), ((1, 1, 2), 4)],
)
def test_exact_rehearsal_succeeds_with_complete_pagination(
    tmp_path: Path,
    page_sizes: tuple[int, ...],
    expected_calls: int,
) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path, page_sizes=page_sizes)
    outcome = run_rehearsal(artifacts)
    assert outcome.report.result_state is ProductionWriteTokenRehearsalResultState.READY
    assert outcome.report.calendar_api_call_count == expected_calls
    assert outcome.report.list_call_count == len(page_sizes)
    assert outcome.report.get_call_count == 1
    assert outcome.report.mutation_call_count == 0
    assert artifacts.transport.call_log == ("events.list",) * len(page_sizes) + ("events.get",)
    assert outcome.snapshot is not None
    assert len(outcome.snapshot.events) == outcome.snapshot.event_count
    assert all(event.safe_event_ref.startswith("G-") for event in outcome.snapshot.events)
    assert all(event.safe_uid_ref.startswith("U-") for event in outcome.snapshot.events)
    verify_production_write_token_rehearsal_report(outcome.report, outcome.snapshot)
    assert all(request.time_min is None for request in artifacts.transport.list_requests)
    assert all(request.time_max is None for request in artifacts.transport.list_requests)
    assert all(request.sync_token is None for request in artifacts.transport.list_requests)
    assert all(request.query is None for request in artifacts.transport.list_requests)


def test_exact_read_challenge_is_case_and_whitespace_sensitive(tmp_path: Path) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    target = artifacts.inputs.target
    expected = production_write_token_rehearsal_challenge(target)
    assert expected.startswith("READ PRODUCTION CALENDAR USING DEDICATED WRITE TOKEN T-")
    verify_production_write_token_rehearsal_confirmation(target, expected)
    for value in (expected.lower(), f"{expected} ", expected.replace(" ", "  ", 1)):
        with pytest.raises(ProductionWriteTokenRehearsalError):
            verify_production_write_token_rehearsal_confirmation(target, value)


def test_challenge_mismatch_stops_before_any_api_call(tmp_path: Path) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    outcome = _run_with_transport(artifacts, artifacts.transport, confirmation="wrong")
    assert outcome.report.result_state is ProductionWriteTokenRehearsalResultState.TARGET_MISMATCH
    assert outcome.report.calendar_api_call_count == 0
    assert artifacts.transport.call_log == ()
    assert artifacts.credential_provider.load_count == 0
    assert artifacts.transport_provider.build_count == 0


def test_refresh_failure_returns_safe_stop_without_client_or_api(tmp_path: Path) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path / "fixtures")
    failure = ProductionWriteTokenRefreshError(
        "production_write_token_refresh_failed",
        "Production write-token refresh failed without browser fallback",
    )
    provider = FakeProductionWriteCredentialSessionProvider(
        failure,
        refresh_attempt_count=1,
    )
    outcome = run_production_write_token_readonly_rehearsal_mock(
        credential_session_provider=provider,
        transport_provider=artifacts.transport_provider,
        target=artifacts.inputs.target,
        manifest=artifacts.inputs.manifest,
        accepted_profile=artifacts.inputs.updated.profile,
        accepted_source=artifacts.inputs.updated.source,
        trusted_baseline=artifacts.inputs.baseline,
        confirmation=artifacts.confirmation,
    )
    assert (
        outcome.report.result_state is ProductionWriteTokenRehearsalResultState.TOKEN_REFRESH_FAILED
    )
    assert outcome.snapshot is None
    assert outcome.report.token_refresh_count == 1
    assert outcome.report.browser_launch_count == 0
    assert outcome.report.rehearsal_client_construction_count == 0
    assert outcome.report.calendar_api_call_count == 0
    assert provider.load_count == 1
    assert artifacts.transport_provider.build_count == 0
    assert artifacts.transport.call_log == ()

    output = tmp_path / "failure-output"
    output.mkdir()
    paths = write_production_write_token_rehearsal_outputs(
        output,
        None,
        outcome.report,
    )
    assert paths.snapshot is None
    assert not (output / "production-write-token-readonly-rehearsal-snapshot.json").exists()
    assert paths.text_report.is_file()
    assert paths.json_report.is_file()


def test_token_role_confusion_stops_before_api(tmp_path: Path) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    token = artifacts.session.token.model_copy(update={"role": ProductionTokenRole.TEST_WRITE})
    session = ProductionWriteCredentialSession.model_construct(
        token=token,
        generation_state=artifacts.session.generation_state,
        refresh_count=0,
        browser_fallback_count=0,
        calendar_api_call_count=0,
    )
    outcome = run_production_write_token_readonly_rehearsal_mock(
        credential_session_provider=FakeProductionWriteCredentialSessionProvider(session),
        transport_provider=artifacts.transport_provider,
        target=artifacts.inputs.target,
        manifest=artifacts.inputs.manifest,
        accepted_profile=artifacts.inputs.updated.profile,
        accepted_source=artifacts.inputs.updated.source,
        trusted_baseline=artifacts.inputs.baseline,
        confirmation=artifacts.confirmation,
    )
    assert (
        outcome.report.result_state is ProductionWriteTokenRehearsalResultState.TOKEN_ROLE_MISMATCH
    )
    assert outcome.report.calendar_api_call_count == 0


def test_scope_confusion_stops_before_api(tmp_path: Path) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    token = ProductionWriteAuthorizedUserToken.model_construct(
        **{
            **artifacts.session.token.__dict__,
            "scopes": ("https://www.googleapis.com/auth/calendar",),
            "granted_scopes": ("https://www.googleapis.com/auth/calendar",),
        }
    )
    session = ProductionWriteCredentialSession.model_construct(
        token=token,
        generation_state=artifacts.session.generation_state,
        refresh_count=0,
        browser_fallback_count=0,
        calendar_api_call_count=0,
    )
    outcome = run_production_write_token_readonly_rehearsal_mock(
        credential_session_provider=FakeProductionWriteCredentialSessionProvider(session),
        transport_provider=artifacts.transport_provider,
        target=artifacts.inputs.target,
        manifest=artifacts.inputs.manifest,
        accepted_profile=artifacts.inputs.updated.profile,
        accepted_source=artifacts.inputs.updated.source,
        trusted_baseline=artifacts.inputs.baseline,
        confirmation=artifacts.confirmation,
    )
    assert outcome.report.result_state is ProductionWriteTokenRehearsalResultState.SCOPE_MISMATCH
    assert outcome.report.calendar_api_call_count == 0


def test_source_change_stops_before_get(tmp_path: Path) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path, updated_indexes=(2,))
    outcome = run_rehearsal(artifacts)
    assert outcome.report.result_state is not ProductionWriteTokenRehearsalResultState.READY
    assert outcome.report.calendar_api_call_count == 0
    assert outcome.report.get_call_count == 0
    assert artifacts.transport.mutation_raw_calls == 0


@pytest.mark.parametrize(
    "event_overrides",
    [
        {1: {"description": "one-bit unrelated drift"}},
        {2: {"summary": "one-bit relevant drift"}},
        {3: {"start": {"date": "2099-12-30"}, "end": {"date": "2099-12-31"}}},
    ],
)
def test_any_full_snapshot_drift_stops_before_get(
    tmp_path: Path,
    event_overrides: dict[int, dict[str, object]],
) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    drifted = build_production_snapshot(
        artifacts.inputs.current.source,
        artifacts.inputs.target,
        event_overrides=event_overrides,
    )
    pages = paginate_production_write_token_rehearsal_snapshot(
        drifted,
        (drifted.event_count,),
        target_summary=artifacts.inputs.target.expected_summary,
    )
    transport = FakeProductionWriteTokenReadOnlyTransport(
        collections=(pages,),
        get_events=(),
    )
    outcome = _run_with_transport(artifacts, transport)
    assert outcome.report.get_call_count == 0
    assert transport.mutation_raw_calls == 0
    assert outcome.report.result_state in {
        ProductionWriteTokenRehearsalResultState.PRODUCTION_FULL_SNAPSHOT_DRIFT,
        ProductionWriteTokenRehearsalResultState.DUPLICATE_IDENTITY,
    }


def test_added_and_removed_event_stop_before_get(tmp_path: Path) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    for events in (
        artifacts.inputs.snapshot.events[:-1],
        (*artifacts.inputs.snapshot.events, artifacts.inputs.snapshot.events[0]),
    ):
        page = paginate_production_write_token_rehearsal_snapshot(
            artifacts.inputs.snapshot,
            (artifacts.inputs.snapshot.event_count,),
            target_summary=artifacts.inputs.target.expected_summary,
        )[0].model_copy(update={"events": events})
        transport = FakeProductionWriteTokenReadOnlyTransport(
            collections=((page,),),
            get_events=(),
        )
        outcome = _run_with_transport(artifacts, transport)
        assert outcome.report.get_call_count == 0
        assert outcome.report.result_state is not ProductionWriteTokenRehearsalResultState.READY


def test_wrong_target_and_incomplete_collection_stop(tmp_path: Path) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    page = paginate_production_write_token_rehearsal_snapshot(
        artifacts.inputs.snapshot,
        (4,),
        target_summary=artifacts.inputs.target.expected_summary,
    )[0]
    wrong = page.model_copy(update={"target_fingerprint": "f" * 64})
    wrong_transport = FakeProductionWriteTokenReadOnlyTransport(
        collections=((wrong,),),
        get_events=(),
    )
    wrong_result = _run_with_transport(artifacts, wrong_transport)
    assert (
        wrong_result.report.result_state is ProductionWriteTokenRehearsalResultState.TARGET_MISMATCH
    )
    assert wrong_result.report.get_call_count == 0

    incomplete = page.model_copy(
        update={"collection_complete": False, "next_page_token": "phase6d0-page-2"}
    )
    incomplete_transport = FakeProductionWriteTokenReadOnlyTransport(
        collections=((incomplete,),),
        get_events=(),
    )
    incomplete_result = _run_with_transport(artifacts, incomplete_transport)
    assert (
        incomplete_result.report.result_state is not ProductionWriteTokenRehearsalResultState.READY
    )
    assert incomplete_result.report.get_call_count == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("etag", None),
        ("summary", "changed summary"),
        ("description", "changed description"),
        ("status", "cancelled"),
        ("event_type", "focusTime"),
        ("recurrence", ("RRULE:FREQ=DAILY",)),
        ("ical_uid", "different@calendar.example"),
    ],
)
def test_fresh_get_mismatch_fails_without_mutation(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    expected = min(
        artifacts.inputs.snapshot.events,
        key=lambda event: (event.safe_ical_uid_reference or "", event.safe_event_reference),
    )
    changed = expected.model_copy(update={field: value})
    pages = paginate_production_write_token_rehearsal_snapshot(
        artifacts.inputs.snapshot,
        (4,),
        target_summary=artifacts.inputs.target.expected_summary,
    )
    transport = FakeProductionWriteTokenReadOnlyTransport(
        collections=(pages,),
        get_events=(changed,),
    )
    outcome = _run_with_transport(artifacts, transport)
    assert (
        outcome.report.result_state
        is ProductionWriteTokenRehearsalResultState.GET_VERIFICATION_FAILED
    )
    assert outcome.report.get_call_count == 1
    assert outcome.report.rehearsal_client_construction_count == 1
    assert transport.mutation_raw_calls == 0


def test_read_retry_is_bounded_and_api_budget_blocks_sixth_call(tmp_path: Path) -> None:
    retryable = ProductionWriteTokenRehearsalTransportError("server_503", retryable=True)
    artifacts = build_rehearsal_artifacts(tmp_path)
    pages = paginate_production_write_token_rehearsal_snapshot(
        artifacts.inputs.snapshot,
        (1, 1, 2),
        target_summary=artifacts.inputs.target.expected_summary,
    )
    expected = min(
        artifacts.inputs.snapshot.events,
        key=lambda event: (event.safe_ical_uid_reference or "", event.safe_event_reference),
    )
    transport = FakeProductionWriteTokenReadOnlyTransport(
        collections=(pages,),
        get_events=(expected,),
        list_failures={1: retryable},
    )
    outcome = _run_with_transport(artifacts, transport)
    assert outcome.report.result_state is ProductionWriteTokenRehearsalResultState.READY
    assert outcome.report.calendar_api_call_count == 5
    assert outcome.report.read_retry_count == 1

    pages4 = paginate_production_write_token_rehearsal_snapshot(
        artifacts.inputs.snapshot,
        (1, 1, 1, 1),
        target_summary=artifacts.inputs.target.expected_summary,
    )
    blocked = FakeProductionWriteTokenReadOnlyTransport(
        collections=(pages4,),
        get_events=(expected,),
        list_failures={1: retryable},
    )
    blocked_outcome = _run_with_transport(artifacts, blocked)
    assert (
        blocked_outcome.report.result_state
        is ProductionWriteTokenRehearsalResultState.API_CALL_LIMIT_EXCEEDED
    )
    assert blocked_outcome.report.calendar_api_call_count == 5
    assert blocked.get_raw_calls == 0


def test_4938_event_two_page_rehearsal_uses_three_calls(tmp_path: Path) -> None:
    artifacts = build_rehearsal_artifacts(
        tmp_path,
        event_count=4938,
        page_sizes=(2500, 2438),
    )
    outcome = run_rehearsal(artifacts)
    assert outcome.report.result_state is ProductionWriteTokenRehearsalResultState.READY
    assert outcome.report.event_count == 4938
    assert outcome.snapshot is not None and len(outcome.snapshot.events) == 4938
    assert outcome.report.source_unchanged_count == 4938
    assert outcome.report.calendar_api_call_count == 3
    assert outcome.report.list_call_count == 2
    assert outcome.report.get_call_count == 1
    assert artifacts.transport.mutation_raw_calls == 0


def test_rehearsal_capabilities_are_list_get_only_and_live_is_hard_off(
    tmp_path: Path,
) -> None:
    transport = build_rehearsal_artifacts(tmp_path).transport
    public_callables = {
        name
        for name in dir(transport)
        if not name.startswith("_") and callable(getattr(transport, name))
    }
    assert public_callables == {"list_events", "get_event"}
    for name in (
        "patch",
        "patch_description",
        "import_event",
        "insert",
        "update",
        "delete",
        "move",
        "batch",
        "service",
    ):
        assert not hasattr(transport, name)
    with pytest.raises(ProductionWriteTokenRehearsalTransportError):
        phase6d0_live_rehearsal_transport_hard_off()


def test_report_snapshot_and_output_are_redacted_atomic_and_no_overwrite(
    tmp_path: Path,
) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path / "fixtures")
    outcome = run_rehearsal(artifacts)
    assert outcome.snapshot is not None
    texts = (
        render_production_write_token_rehearsal_snapshot_json(outcome.snapshot),
        render_production_write_token_rehearsal_report_json(outcome.report, outcome.snapshot),
        render_production_write_token_rehearsal_report_text(outcome.report, outcome.snapshot),
    )
    selected = min(
        artifacts.inputs.snapshot.events,
        key=lambda event: (event.safe_ical_uid_reference or "", event.safe_event_reference),
    )
    forbidden = (
        artifacts.inputs.target.calendar_id,
        artifacts.inputs.target.expected_target_fingerprint,
        selected.event_id,
        selected.etag or "",
        selected.ical_uid or "",
        selected.summary or "",
        selected.description or "",
        str(tmp_path),
    )
    for text in texts:
        assert all(value not in text for value in forbidden if value)
        json_text = text if text.lstrip().startswith("{") else None
        if json_text is not None:
            json.loads(json_text)
    output = tmp_path / "external-output"
    output.mkdir()
    paths = write_production_write_token_rehearsal_outputs(
        output,
        outcome.snapshot,
        outcome.report,
    )
    assert paths.snapshot is not None and paths.snapshot.is_file()
    assert paths.text_report.is_file()
    assert paths.json_report.is_file()
    with pytest.raises(ProductionWriteTokenRehearsalIOError):
        write_production_write_token_rehearsal_outputs(
            output,
            outcome.snapshot,
            outcome.report,
        )
