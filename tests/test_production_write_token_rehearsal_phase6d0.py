from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import threading
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import test_token_start_linked_session_phase6d1h as linked_tests
from phase6b_helpers import build_production_snapshot
from phase6d0_auth_helpers import ISSUED_AT, production_token
from phase6d0_rehearsal_helpers import (
    RehearsalArtifacts,
    build_rehearsal_artifacts,
    run_rehearsal,
)

from tridentine_calendar_google_sync import (
    google_auth,
    google_client,
)
from tridentine_calendar_google_sync import (
    production_write_token as tokens,
)
from tridentine_calendar_google_sync import (
    production_write_token_io as token_io,
)
from tridentine_calendar_google_sync import (
    production_write_token_operation_record as records,
)
from tridentine_calendar_google_sync import (
    production_write_token_rehearsal as rehearsal,
)
from tridentine_calendar_google_sync import (
    production_write_token_rehearsal_transport as rehearsal_transport,
)
from tridentine_calendar_google_sync.production_write_target import (
    ProductionWriteTargetPolicyError,
    calculate_production_write_target_hash,
    production_write_target_reference,
    validate_production_write_target_config,
)
from tridentine_calendar_google_sync.production_write_token import (
    ProductionWriteTokenRefreshError,
)
from tridentine_calendar_google_sync.production_write_token_models import (
    ProductionTokenRole,
    ProductionWriteAuthorizedUserToken,
    ProductionWriteCredentialSession,
    ProductionWriteGrantEvidenceOrigin,
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
    require_phase6d0_rehearsal_providers,
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
    output.mkdir(mode=0o700)
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
    output.mkdir(mode=0o700)
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


_BOUND_TARGET_MISMATCH = "production_rehearsal_bound_target_mismatch"
_BOUND_USE_INVALID = "production_rehearsal_bound_provider_use_invalid"
_SESSION_FAILED = "production_rehearsal_token_session_failed"
_NOW = linked_tests.NOW

_BOUND_DENIED = (
    *linked_tests._DENIED,
    (tokens, "_load_production_write_credential_session"),
    (FakeProductionWriteCredentialSessionProvider, "load_session"),
    (google_auth, "authorize_google_readonly"),
    (google_auth, "load_readonly_credentials"),
    (google_client, "build_read_only_calendar_client"),
    (google_client.GoogleEventsListClient, "list_events"),
)
_SETUP_DENIED = (
    (tokens, "_prepare_start_linked_session_mock"),
    (tokens, "_start_linked_session_context"),
    (records, "_shared_start_session_scope"),
    (records.private_lock, "acquire_posix_private_directory_lock"),
    (records.private_create, "create_posix_private_bytes"),
    (records, "read_private_sensitive_bytes"),
    (token_io, "validate_production_write_token_path_set"),
    (token_io, "load_production_write_token_generation_state"),
    (token_io, "load_production_write_authorized_user_token"),
    (token_io, "persist_refreshed_production_write_token"),
    (Path, "resolve"),
    (Path, "exists"),
    (Path, "lstat"),
)


@contextmanager
def _bound_denials(
    patch: pytest.MonkeyPatch, targets: tuple = _BOUND_DENIED
) -> Iterator[Counter[str]]:
    effects = linked_tests._Effects()
    originals = [(owner, name, getattr(owner, name)) for owner, name in targets]
    try:
        with patch.context() as local:
            for owner, name, _ in originals:
                local.setattr(owner, name, effects.forbid(f"{owner.__name__}.{name}"))
            yield effects.calls
    finally:
        for owner, name, original in originals:
            assert getattr(owner, name) is original


def test_bound_effect_monitor_calibrates_without_delegation_and_restores(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    targets = (*_BOUND_DENIED, *_SETUP_DENIED)
    delegated = []

    def tripwire(*_args: object, **_kwargs: object) -> None:
        delegated.append("delegated")

    originals = [(owner, name, getattr(owner, name)) for owner, name in targets]
    with monkeypatch.context() as local:
        for owner, name in targets:
            local.setattr(owner, name, tripwire)
        with _bound_denials(local, targets) as calls:
            for owner, name in targets:
                with pytest.raises(linked_tests._Denied):
                    getattr(owner, name)()
        assert all(getattr(owner, name) is tripwire for owner, name in targets)
    assert all(getattr(owner, name) is original for owner, name, original in originals)
    assert not delegated
    assert calls == Counter({f"{owner.__name__}.{name}": 1 for owner, name in targets})


class _BoundTrial:
    """Own the synthetic preparation state separately from the rehearsal data."""

    def __init__(
        self,
        scratch: Path,
        *,
        expired: bool = False,
        directory: Path | None = None,
    ) -> None:
        self.artifacts = build_rehearsal_artifacts(scratch / "rehearsal")
        self.storage = linked_tests._Trial(expired=expired, directory=directory)
        self.storage.target = self.artifacts.inputs.target
        self.storage.confirmation = self.artifacts.confirmation
        self.storage.state = tokens.build_initial_production_write_token_generation_state(
            self.storage.target, issued_at=ISSUED_AT
        )
        expiry = _NOW - timedelta(seconds=1) if expired else _NOW + timedelta(hours=1)
        self.storage.old_token = production_token(self.storage.state, expiry=expiry)
        self.storage.token = self.storage.old_token
        self.calls: Counter[str] = Counter()
        self.fakes: list[linked_tests._Refresher] = []
        self.lower_errors: list[BaseException] = []
        self.linked_inputs: list[tuple[tuple, dict]] = []
        self.delivered: list[ProductionWriteCredentialSession] = []
        self.clock_error: BaseException | None = None
        self.factory_error: BaseException | None = None
        self.time = _NOW
        self.refresher_factory: Callable[[], linked_tests._Refresher] = lambda: (
            linked_tests._Refresher(self.storage)
        )

    def clock(self) -> datetime:
        self.calls["clock"] += 1
        if self.clock_error is not None:
            raise self.clock_error
        return self.time

    def make_refresher(self) -> linked_tests._Refresher:
        self.calls["factory"] += 1
        if self.factory_error is not None:
            raise self.factory_error
        fake = self.refresher_factory()
        self.fakes.append(fake)
        return fake

    def bind(self, **overrides):
        values = {
            "binding": self.storage.binding,
            "operation": self.storage.operation,
            "production_write_token_path": self.storage.paths["write"],
            "generation_state_path": self.storage.paths["generation"],
            "production_read_token_path": self.storage.paths["read"],
            "test_write_token_path": self.storage.paths["test"],
            "target": self.storage.target,
            "confirmation": self.storage.confirmation,
            "now_utc": self.clock,
            "make_refresher": self.make_refresher,
        }
        values.update(overrides)
        return tokens._bind_mock_rehearsal_session_provider(**values)

    def run(self, provider, **overrides) -> ProductionWriteTokenRehearsalOutcome:
        inputs = self.artifacts.inputs
        values = {
            "credential_session_provider": provider,
            "transport_provider": self.artifacts.transport_provider,
            "target": inputs.target,
            "manifest": inputs.manifest,
            "accepted_profile": inputs.updated.profile,
            "accepted_source": inputs.updated.source,
            "trusted_baseline": inputs.baseline,
            "confirmation": self.artifacts.confirmation,
        }
        values.update(overrides)
        return run_production_write_token_readonly_rehearsal_mock(**values)

    def observe(
        self, patch: pytest.MonkeyPatch, *, before_build: Callable[[], None] | None = None
    ) -> None:
        linked = tokens._prepare_start_linked_session_mock
        build = FakeProductionWriteTokenReadOnlyTransportProvider.build_transport
        list_events = FakeProductionWriteTokenReadOnlyTransport.list_events
        get_event = FakeProductionWriteTokenReadOnlyTransport.get_event

        def observe_linked(*args, **kwargs):
            self.calls["linked"] += 1
            self.linked_inputs.append((args, kwargs))
            try:
                session = linked(*args, **kwargs)
            except BaseException as error:
                self.lower_errors.append(error)
                raise
            self.storage.event("linked_return")
            self.delivered.append(session)
            return session

        def observe_build(provider, *, session, target):
            assert session is self.delivered[-1]
            assert target == self.artifacts.inputs.target
            if before_build is not None:
                before_build()
            self.storage.event("build")
            return build(provider, session=session, target=target)

        def observe_list(transport, *args, **kwargs):
            self.storage.event("list")
            return list_events(transport, *args, **kwargs)

        def observe_get(transport, *args, **kwargs):
            self.storage.event("get")
            return get_event(transport, *args, **kwargs)

        patch.setattr(tokens, "_prepare_start_linked_session_mock", observe_linked)
        patch.setattr(
            FakeProductionWriteTokenReadOnlyTransportProvider, "build_transport", observe_build
        )
        patch.setattr(FakeProductionWriteTokenReadOnlyTransport, "list_events", observe_list)
        patch.setattr(FakeProductionWriteTokenReadOnlyTransport, "get_event", observe_get)

    def assert_no_reads(self, outcome: ProductionWriteTokenRehearsalOutcome, *, earlier_reads=0):
        report = outcome.report
        assert outcome.snapshot is None
        assert report.rehearsal_client_construction_count == report.calendar_api_call_count == 0
        assert report.list_call_count == report.get_call_count == report.mutation_call_count == 0
        assert self.artifacts.transport_provider.build_count == earlier_reads
        assert self.artifacts.transport.call_log == ("events.list", "events.get") * earlier_reads


def _assert_bound_refusal(error, code: str) -> None:
    assert type(error) is tokens.ProductionWriteTokenConfigError
    assert error.code == code


def _assert_bound_scope_result(trial: _BoundTrial, outcome, state, *, earlier_reads=0) -> None:
    assert type(trial.lower_errors[-1]) is records._ScopeFailure
    assert trial.lower_errors[-1].result.state is state
    assert (
        outcome.report.result_state
        is ProductionWriteTokenRehearsalResultState.INPUT_BINDING_MISMATCH
    )
    assert outcome.report.safe_code == _SESSION_FAILED
    trial.assert_no_reads(outcome, earlier_reads=earlier_reads)


def test_bound_setup_detaches_values_without_storage_or_adapter_calls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trial = _BoundTrial(tmp_path)
    storage = trial.storage
    binding = replace(storage.binding)
    operation = replace(storage.operation)
    target = storage.target.model_copy()
    submitted = {"binding": binding, "operation": operation, "target": target}
    with _bound_denials(monkeypatch, (*_BOUND_DENIED, *_SETUP_DENIED)) as denied:
        provider = trial.bind(**submitted)
        with pytest.raises(tokens.ProductionWriteTokenConfigError) as reinitialized:
            provider.__init__(**submitted)
        _assert_bound_refusal(reinitialized.value, _BOUND_USE_INVALID)
        with pytest.raises(tokens.ProductionWriteTokenConfigError) as rebound:
            provider._snapshot = object()
        _assert_bound_refusal(rebound.value, _BOUND_USE_INVALID)
        assert not trial.calls and not storage.calls
    assert not denied
    object.__setattr__(binding, "pair_ref", "changed-pair")
    object.__setattr__(binding, "storage_ref", "changed-storage")
    object.__setattr__(binding, "directory", storage.directory / "different")
    object.__setattr__(operation, "operation_id", "changed-operation")
    object.__setattr__(operation, "predecessor_id", "changed-predecessor")
    object.__setattr__(target, "expected_summary", "Changed fixture summary")
    submitted["target"] = target.model_copy()
    submitted["binding"] = replace(binding)
    submitted["operation"] = replace(operation)

    with storage.installed(monkeypatch) as local, _bound_denials(local) as denied:
        trial.observe(local)
        outcome = trial.run(provider)
    assert not denied
    assert outcome.report.result_state is ProductionWriteTokenRehearsalResultState.READY
    args, kwargs = trial.linked_inputs[0]
    assert args[4] == storage.target and args[4] is not target
    assert args[4].calendar_id == storage.target.calendar_id
    assert args[4].expected_target_fingerprint == storage.target.expected_target_fingerprint
    assert args[4].expected_summary == storage.target.expected_summary
    assert args[5] == storage.confirmation
    assert kwargs["binding"] == storage.binding and kwargs["binding"] is not binding
    assert kwargs["operation"] == storage.operation and kwargs["operation"] is not operation


@pytest.mark.parametrize(
    "case",
    (
        "swapped",
        "other_pair",
        "same_read",
        "start_leaf",
        "same_exclusions",
        "same_ids",
        "no_predecessor",
        "new_pair",
    ),
)
def test_bound_setup_invalid_layout_and_operations_are_pure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    trial = _BoundTrial(tmp_path)
    paths = trial.storage.paths
    operation = trial.storage.operation
    choices = {
        "swapped": {
            "production_write_token_path": paths["generation"],
            "generation_state_path": paths["write"],
        },
        "other_pair": {
            "production_write_token_path": paths["write"].parent / "other" / paths["write"].name
        },
        "same_read": {"production_read_token_path": paths["write"]},
        "start_leaf": {"test_write_token_path": trial.storage.directory / records.RECORD_LEAF},
        "same_exclusions": {"test_write_token_path": paths["read"]},
        "same_ids": {"operation": replace(operation, predecessor_id=operation.operation_id)},
        "no_predecessor": {"operation": replace(operation, predecessor_id=None)},
        "new_pair": {
            "operation": replace(
                operation, kind=records.OperationKind.NEW_PAIR, predecessor_id=None
            )
        },
    }
    with (
        _bound_denials(monkeypatch, (*_BOUND_DENIED, *_SETUP_DENIED)) as denied,
        pytest.raises(tokens.ProductionWriteTokenConfigError) as refused,
    ):
        trial.bind(**choices[case])
    _assert_bound_refusal(refused.value, _BOUND_USE_INVALID)
    assert not denied and not trial.calls and not trial.storage.calls


def test_bound_request_full_target_and_closed_signature_before_effects(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trial = _BoundTrial(tmp_path)
    provider = trial.bind()
    target = trial.storage.target
    same_reference = target.model_copy(update={"expected_summary": "Another fixture summary"})
    other = linked_tests.production_target()
    assert production_write_target_reference(same_reference) == production_write_target_reference(
        target
    )
    assert calculate_production_write_target_hash(
        same_reference
    ) != calculate_production_write_target_hash(target)
    assert validate_production_write_target_config(other)
    assert calculate_production_write_target_hash(other) != calculate_production_write_target_hash(
        target
    )
    overrides = {
        "binding": trial.storage.binding,
        "production_write_token_path": trial.storage.paths["write"],
        "operation": trial.storage.operation,
        "now": _NOW,
        "refresher": trial.storage.refresher,
    }
    inherited_target = type("InheritedRehearsalTarget", (type(target),), {})
    subtype = inherited_target.model_validate(
        {name: getattr(target, name) for name in type(target).model_fields}
    )
    with _bound_denials(monkeypatch, (*_BOUND_DENIED, *_SETUP_DENIED)) as denied:
        with pytest.raises(tokens.ProductionWriteTokenConfigError) as setup:
            trial.bind(target=subtype)
        _assert_bound_refusal(setup.value, _BOUND_USE_INVALID)
        with pytest.raises(tokens.ProductionWriteTokenConfigError) as request:
            provider.load_session(target=subtype)
        _assert_bound_refusal(request.value, _BOUND_USE_INVALID)
        for mismatch in (other, same_reference):
            with pytest.raises(tokens.ProductionWriteTokenConfigError) as refused:
                provider.load_session(target=mismatch)
            _assert_bound_refusal(refused.value, _BOUND_TARGET_MISMATCH)
        for key, value in overrides.items():
            with pytest.raises(TypeError):
                provider.load_session(target=target, **{key: value})
    assert not denied and not trial.calls and not trial.storage.calls


def test_bound_wrapper_preserves_target_and_confirmation_precedence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trial = _BoundTrial(tmp_path)
    provider = trial.bind()
    target = trial.storage.target.model_copy(update={"expected_target_fingerprint": "0" * 64})
    with _bound_denials(monkeypatch, (*_BOUND_DENIED, *_SETUP_DENIED)) as denied:
        with pytest.raises(ProductionWriteTargetPolicyError) as refused:
            trial.run(provider, target=target, confirmation="wrong")
        assert refused.value.code == "production_write_target_fingerprint_mismatch"
        outcome = trial.run(provider, confirmation="wrong")
    assert outcome.report.result_state is ProductionWriteTokenRehearsalResultState.TARGET_MISMATCH
    assert outcome.report.safe_code == "production_rehearsal_confirmation_mismatch"
    trial.assert_no_reads(outcome)
    assert not denied and not trial.calls and not trial.storage.calls


@pytest.mark.parametrize("bad_part", ("manifest", "source", "baseline"))
def test_bound_manifest_source_baseline_refuse_before_provider_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, bad_part: str
) -> None:
    trial = _BoundTrial(tmp_path)
    provider = trial.bind()
    other = build_rehearsal_artifacts(tmp_path / "drift", updated_indexes=(1,)).inputs
    values = {
        "manifest": {"manifest": other.manifest},
        "source": {"accepted_source": other.updated.source},
        "baseline": {"trusted_baseline": other.baseline},
    }
    targets = (*_BOUND_DENIED, *_SETUP_DENIED, (type(provider), "load_session"))
    with _bound_denials(monkeypatch, targets) as denied:
        outcome = trial.run(provider, **values[bad_part])
    assert outcome.report.safe_code is not None
    assert ("baseline" if bad_part == "baseline" else "manifest_source") in outcome.report.safe_code
    trial.assert_no_reads(outcome)
    assert not denied and not trial.calls and not trial.storage.calls


def test_bound_gate_requires_exact_initialized_types_without_load_or_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trial = _BoundTrial(tmp_path)
    provider = trial.bind()
    transport = trial.artifacts.transport_provider
    inherited_provider = type("InheritedBoundProvider", (type(provider),), {})
    inherited_transport = type("InheritedFakeTransportProvider", (type(transport),), {})
    spoof = type(
        "FlagSpoof", (), {"mock_only": True, "live_capable": False, "browser_launch_count": 0}
    )()
    refusals = (
        (object(), transport),
        (spoof, transport),
        (object.__new__(inherited_provider), transport),
        (object.__new__(type(provider)), transport),
        (provider, FakeProductionWriteTokenReadOnlyTransportProvider(object())),
        (provider, inherited_transport(trial.artifacts.transport)),
    )
    targets = (
        *_BOUND_DENIED,
        *_SETUP_DENIED,
        (type(provider), "load_session"),
        (type(transport), "build_transport"),
    )
    with _bound_denials(monkeypatch, targets) as denied:
        require_phase6d0_rehearsal_providers(provider, transport)
        for bad_provider, bad_transport in refusals:
            with pytest.raises(
                (
                    ProductionWriteTokenRehearsalTransportError,
                    tokens.ProductionWriteTokenConfigError,
                )
            ):
                require_phase6d0_rehearsal_providers(bad_provider, bad_transport)
    assert not denied and not trial.calls and not trial.storage.calls


@pytest.mark.parametrize("expired", (False, True), ids=("unexpired", "expired"))
def test_bound_wrapper_real_memory_connection_and_retained_start_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, expired: bool
) -> None:
    trial = _BoundTrial(tmp_path, expired=expired)
    storage = trial.storage
    provider = trial.bind()

    def check_finalization() -> None:
        assert not storage.active
        assert storage.snapshot().delivery == "return_path_selected"
        assert storage.snapshot().diagnostic_status == "complete"

    with storage.installed(monkeypatch) as local, _bound_denials(local) as denied:
        trial.observe(local, before_build=check_finalization)
        outcome = trial.run(provider)
        first_start = storage.raw
        first_calls = storage.calls.copy()
        assert first_start is not None
        assert records._matches_start_record(first_start, storage.binding, storage.operation)
        assert provider.refresh_attempt_count == int(expired)
        assert not provider._active
        assert outcome.report.result_state is ProductionWriteTokenRehearsalResultState.READY
        assert outcome.report.token_refresh_count == int(expired)
        assert outcome.report.rehearsal_client_construction_count == 1
        assert outcome.report.calendar_api_call_count == 2
        assert outcome.report.list_call_count == outcome.report.get_call_count == 1
        assert outcome.report.mutation_call_count == outcome.report.read_retry_count == 0
        assert outcome.snapshot is not None and outcome.snapshot.event_count == 4
        assert trial.artifacts.transport_provider.build_count == 1
        assert trial.artifacts.transport.call_log == ("events.list", "events.get")
        verify_production_write_token_rehearsal_report(outcome.report, outcome.snapshot)
        assert first_calls["acquire"] == first_calls["entry"] == first_calls["exit"] == 1
        assert first_calls["publish"] == first_calls["read_record"] == 1
        assert first_calls["read_state"] == first_calls["read_token"] == 1 + int(expired)
        assert first_calls["refresh"] == first_calls["writer"] == storage.published == int(expired)
        assert first_calls["checkpoint"] == (9 if expired else 6)
        assert storage.events.index("publish") < storage.events.index("read_record")
        assert storage.events.index("read_record") < storage.events.index("read_state")
        assert storage.events[-5:] == ["exit", "linked_return", "build", "list", "get"]
        assert trial.delivered[0].refresh_count == int(expired)
        assert trial.calls == Counter(clock=1, factory=1, linked=1)
        fake = trial.fakes[0]
        assert fake.calls == fake.refresh_attempt_count == int(expired)
        assert fake.browser_fallback_count == fake.calendar_api_call_count == 0
        if expired:
            token = trial.delivered[0].token
            assert token.expiry > _NOW
            assert (
                token.grant_evidence.origin
                is ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE
            )
            assert token.client_id == storage.old_token.client_id
            assert token.client_secret == storage.old_token.client_secret
            assert token.token_uri == storage.old_token.token_uri

        second = trial.run(provider)
        _assert_bound_scope_result(
            trial, second, records.RecordState.SLOT_OCCUPIED, earlier_reads=1
        )
        assert provider.refresh_attempt_count == 0 and not provider._active
        assert trial.calls == Counter(clock=2, factory=2, linked=2)

        replacement = trial.bind(
            operation=replace(storage.operation, operation_id="different-explicit-operation")
        )
        third = trial.run(replacement)
        _assert_bound_scope_result(trial, third, records.RecordState.SLOT_OCCUPIED, earlier_reads=1)
        assert replacement.refresh_attempt_count == 0 and not replacement._active
        assert trial.calls == Counter(clock=3, factory=3, linked=3)
        assert len(trial.delivered) == 1
        assert len({id(fake) for fake in trial.fakes}) == 3
        assert not any(fake.calls for fake in trial.fakes[1:])
        assert storage.calls["acquire"] == storage.calls["entry"] == storage.calls["exit"] == 3
        assert storage.raw == first_start
        for key in ("publish", "read_record", "read_state", "read_token", "refresh", "writer"):
            assert storage.calls[key] == first_calls[key]
    assert not denied


@pytest.mark.parametrize("offset", (None, timezone(timedelta(hours=1))), ids=("naive", "non-utc"))
def test_bound_clock_value_reaches_real_supported_platform_utc_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, offset: timezone | None
) -> None:
    trial = _BoundTrial(tmp_path)
    trial.time = _NOW.replace(tzinfo=offset)
    provider = trial.bind()
    with trial.storage.installed(monkeypatch) as local, _bound_denials(local) as denied:
        trial.observe(local)
        outcome = trial.run(provider)
    assert outcome.report.safe_code == "production_write_token_clock_invalid"
    assert type(trial.lower_errors[0]) is tokens.ProductionWriteTokenConfigError
    assert trial.lower_errors[0].code == outcome.report.safe_code
    trial.assert_no_reads(outcome)
    assert trial.calls == Counter(clock=1, factory=1, linked=1)
    assert not trial.storage.calls and not denied
    assert not provider._active and provider.refresh_attempt_count == 0


class _CounterTripwireRefresher(linked_tests._Refresher):
    def __init__(self, storage: linked_tests._Trial) -> None:
        self.counter_failure = linked_tests._Cancel("Synthetic late counter failure")
        self.reject_late_reads = False
        self.rejected_counter_reads = 0
        super().__init__(storage)

    def __getattribute__(self, name: str):
        if name == "refresh_attempt_count" and self.reject_late_reads:
            self.rejected_counter_reads += 1
            raise self.counter_failure
        return super().__getattribute__(name)

    def calibrate(self) -> None:
        assert self.reject_late_reads and self.rejected_counter_reads == 0
        with pytest.raises(linked_tests._Cancel) as sentinel:
            _ = self.refresh_attempt_count
        assert sentinel.value is self.counter_failure and self.rejected_counter_reads == 1


@pytest.mark.parametrize(
    "publication", (False, True, None), ids=("not-published", "possible", "unknown")
)
def test_bound_writer_w_and_held_p_keep_publication_and_safe_attempt_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, publication: bool | None
) -> None:
    trial = _BoundTrial(tmp_path, expired=True)
    storage = trial.storage
    fake = _CounterTripwireRefresher(storage)
    trial.refresher_factory = lambda: fake
    provider = trial.bind()
    writer_error = token_io.ProductionWriteTokenIOError(
        "synthetic_bound_writer", "Synthetic bound writer failed", publication_possible=publication
    )
    storage.faults["writer"] = writer_error
    seen_writer_errors = []
    seen_held_errors = []
    persist = tokens._persist_linked
    held_body = tokens._load_production_write_credential_session_held

    def writer(*args, **kwargs):
        fake.reject_late_reads = True
        return storage._save(*args, **kwargs)

    def watch_persist(*args, **kwargs):
        try:
            return persist(*args, **kwargs)
        except BaseException as error:
            seen_writer_errors.append(error)
            raise

    def watch_held(*args, **kwargs):
        try:
            return held_body(*args, **kwargs)
        except BaseException as error:
            seen_held_errors.append(error)
            raise

    with storage.installed(monkeypatch) as local, _bound_denials(local) as denied:
        trial.observe(local)
        local.setattr(token_io, "persist_refreshed_production_write_token", writer)
        local.setattr(tokens, "_persist_linked", watch_persist)
        local.setattr(tokens, "_load_production_write_credential_session_held", watch_held)
        outcome = trial.run(provider)
    assert not denied
    assert seen_writer_errors == [writer_error]
    assert len(seen_held_errors) == len(trial.lower_errors) == 1
    persistence_error = trial.lower_errors[0]
    assert persistence_error is seen_held_errors[0]
    assert type(persistence_error) is tokens.ProductionWriteTokenRefreshPersistenceError
    assert persistence_error.publication_possible is publication
    assert outcome.report.safe_code == persistence_error.code
    assert (
        outcome.report.result_state is ProductionWriteTokenRehearsalResultState.TOKEN_REFRESH_FAILED
    )
    assert outcome.report.token_refresh_count == provider.refresh_attempt_count == 1
    assert outcome.report.browser_launch_count == provider.browser_launch_count == 0
    assert not provider._active
    assert storage.snapshot().credential_publication is publication
    assert storage.snapshot().record_publication is True
    assert storage.calls["writer"] == storage.calls["refresh"] == 1
    assert storage.calls["acquire"] == storage.calls["exit"] == 1
    assert storage.exit_triples[0][1] is persistence_error
    assert storage.raw is not None and not trial.delivered
    assert trial.calls == Counter(clock=1, factory=1, linked=1)
    trial.assert_no_reads(outcome)
    fake.calibrate()


def test_bound_pre_save_cancel_keeps_first_identity_even_if_exit_also_cancels(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trial = _BoundTrial(tmp_path, expired=True)
    storage = trial.storage
    fake = _CounterTripwireRefresher(storage)
    trial.refresher_factory = lambda: fake
    provider = trial.bind()
    cancelled = linked_tests._Cancel("Synthetic pre-save cancellation")
    storage.faults["reread_token"] = cancelled
    storage.faults["exit"] = linked_tests._Cancel("Synthetic later exit cancellation")

    def read_token(path):
        if storage.calls["read_token"] == 1:
            fake.reject_late_reads = True
        return storage._read_token(path)

    with storage.installed(monkeypatch) as local, _bound_denials(local) as denied:
        trial.observe(local)
        local.setattr(token_io, "load_production_write_authorized_user_token", read_token)
        with pytest.raises(linked_tests._Cancel) as refused:
            trial.run(provider)
    assert not denied and refused.value is cancelled and trial.lower_errors == [cancelled]
    assert storage.exit_triples[0][1] is cancelled
    assert not provider._active and provider.refresh_attempt_count == 1
    assert storage.calls["refresh"] == storage.calls["exit"] == 1
    assert storage.calls["writer"] == 0 and storage.raw is not None
    assert storage.snapshot().record_publication is True
    assert not trial.delivered and not trial.artifacts.transport.call_log
    assert trial.artifacts.transport_provider.build_count == 0
    assert trial.calls == Counter(clock=1, factory=1, linked=1)
    fake.calibrate()


@pytest.mark.parametrize("stage", ("clock", "factory"))
@pytest.mark.parametrize("cancel", (False, True), ids=("ordinary", "cancel"))
def test_bound_adapter_failure_and_cancel_release_active_without_lower_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str, cancel: bool
) -> None:
    trial = _BoundTrial(tmp_path)
    provider = trial.bind()
    fault = (
        linked_tests._Cancel("Synthetic adapter cancellation")
        if cancel
        else ValueError("Synthetic adapter failure")
    )
    setattr(trial, f"{stage}_error", fault)
    with trial.storage.installed(monkeypatch) as local, _bound_denials(local) as denied:
        trial.observe(local)
        if cancel:
            with pytest.raises(linked_tests._Cancel) as refused:
                trial.run(provider)
            assert refused.value is fault
        else:
            outcome = trial.run(provider)
            assert outcome.report.safe_code == _SESSION_FAILED
            trial.assert_no_reads(outcome)
        assert not provider._active and provider.refresh_attempt_count == 0
        assert trial.calls == Counter(clock=1, factory=int(stage == "factory"))
        assert not trial.storage.calls and not trial.lower_errors and not trial.delivered
        assert not trial.artifacts.transport.call_log
        setattr(trial, f"{stage}_error", None)
        recovered = trial.run(provider)
        assert recovered.report.result_state is ProductionWriteTokenRehearsalResultState.READY
        assert trial.calls == Counter(clock=2, factory=1 + int(stage == "factory"), linked=1)
        assert trial.storage.calls["publish"] == trial.storage.calls["exit"] == 1
    assert not denied and not provider._active


@pytest.mark.parametrize(
    "field", ("refresh_attempt_count", "calendar_api_call_count", "browser_fallback_count")
)
def test_bound_factory_checks_zero_initial_counters_before_lower_entry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    trial = _BoundTrial(tmp_path)
    fake = linked_tests._Refresher(trial.storage)
    setattr(fake, field, 1)
    trial.refresher_factory = lambda: fake
    provider = trial.bind()
    with _bound_denials(monkeypatch, (*_BOUND_DENIED, *_SETUP_DENIED)) as denied:
        outcome = trial.run(provider)
    assert outcome.report.safe_code == _BOUND_USE_INVALID
    trial.assert_no_reads(outcome)
    assert trial.calls == Counter(clock=1, factory=1)
    assert not denied and not provider._active and provider.refresh_attempt_count == 0


def test_bound_observed_refresh_counter_does_not_replace_held_fake_accounting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trial = _BoundTrial(tmp_path, expired=True)

    class MiscountingFake(linked_tests._Refresher):
        def refresh(self, token, scopes):
            result = super().refresh(token, scopes)
            self.refresh_attempt_count = 2
            return result

    trial.refresher_factory = lambda: MiscountingFake(trial.storage)
    provider = trial.bind()
    with trial.storage.installed(monkeypatch) as local, _bound_denials(local) as denied:
        trial.observe(local)
        outcome = trial.run(provider)
    assert outcome.report.safe_code == "production_write_token_refresh_accounting_invalid"
    assert (
        outcome.report.result_state is ProductionWriteTokenRehearsalResultState.TOKEN_REFRESH_FAILED
    )
    assert outcome.report.token_refresh_count == provider.refresh_attempt_count == 1
    assert trial.fakes[0].refresh_attempt_count == 2
    assert trial.storage.calls["refresh"] == trial.storage.calls["exit"] == 1
    assert trial.storage.calls["writer"] == 0 and not trial.delivered
    assert not denied and not provider._active
    trial.assert_no_reads(outcome)


@pytest.mark.parametrize("attempt", ("reentry", "other_thread", "wrong_pid"))
def test_bound_unauthorized_actor_does_not_reset_an_active_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attempt: str
) -> None:
    trial = _BoundTrial(tmp_path, expired=True)
    provider = trial.bind()
    failures = []

    def try_load() -> None:
        try:
            provider.load_session(target=trial.storage.target)
        except BaseException as error:
            failures.append(error)

    class CallbackFake(linked_tests._Refresher):
        def refresh(self, token, scopes):
            result = super().refresh(token, scopes)
            before = trial.calls.copy()
            assert provider._active and provider.refresh_attempt_count == 1
            if attempt == "other_thread":
                thread = threading.Thread(target=try_load)
                thread.start()
                thread.join(timeout=5)
                assert not thread.is_alive()
            elif attempt == "wrong_pid":
                with monkeypatch.context() as actor:
                    other_pid = tokens.getpid() + 1
                    actor.setattr(tokens, "getpid", lambda: other_pid)
                    try_load()
            else:
                try_load()
            assert provider._active and provider.refresh_attempt_count == 1
            assert trial.calls == before
            return result

    trial.refresher_factory = lambda: CallbackFake(trial.storage)
    with trial.storage.installed(monkeypatch) as local, _bound_denials(local) as denied:
        trial.observe(local)
        outcome = trial.run(provider)
    assert outcome.report.result_state is ProductionWriteTokenRehearsalResultState.READY
    assert len(failures) == 1
    _assert_bound_refusal(failures[0], _BOUND_USE_INVALID)
    assert not denied and not provider._active
    assert trial.calls == Counter(clock=1, factory=1, linked=1)
    assert trial.storage.calls["refresh"] == trial.storage.calls["writer"] == 1


@pytest.mark.skipif(sys.platform != "win32", reason="actual Windows START-linked platform refusal")
def test_bound_actual_windows_refusal_precedes_paths_start_and_fake_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    trial = _BoundTrial(tmp_path)
    provider = trial.bind()
    # Both linked entry and its context preflight must reach the real platform gate.
    targets = (*_BOUND_DENIED, *_SETUP_DENIED[2:])
    with monkeypatch.context() as local, _bound_denials(local, targets) as denied:
        trial.observe(local)
        outcome = trial.run(provider)
    _assert_bound_scope_result(trial, outcome, records.RecordState.UNSUPPORTED_PLATFORM)
    assert trial.calls == Counter(clock=1, factory=1, linked=1)
    assert not denied and not trial.storage.calls and not trial.delivered
    assert not trial.fakes[0].calls and not provider._active


_BOUND_LOCK_CHILD = """
import sys
from pathlib import Path

from tridentine_calendar_google_sync.production_write_token_operation_record import private_lock

try:
    with private_lock.acquire_posix_private_directory_lock(Path(sys.argv[1])):
        result = "acquired"
except private_lock.PosixPrivateLockError as error:
    result = "busy" if error.code == "posix_directory_lock_busy" else "other"
except BaseException:
    result = "other"
raise SystemExit(0 if result == sys.argv[2] else 1)
"""

_BOUND_REQUEST_CHILD = """
import sys
from pathlib import Path

try:
    sys.path.insert(0, sys.argv[1])
    from test_production_write_token_rehearsal_phase6d0 import _check_fresh_bound_request

    _check_fresh_bound_request(Path(sys.argv[2]), Path(sys.argv[3]))
except BaseException:
    raise SystemExit(1) from None
"""


def _run_bound_child(script: str, *arguments: Path | str) -> None:
    # Only ordinary interpreter/locale settings, never inherited credential variables.
    allowed = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "LD_LIBRARY_PATH")
    environment = {name: os.environ[name] for name in allowed if name in os.environ}
    try:
        result = subprocess.run(
            [sys.executable, "-B", "-c", script, *(str(argument) for argument in arguments)],
            env=environment,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        pytest.fail("Synthetic bound rehearsal child could not complete", pytrace=False)
    if result.returncode or result.stdout or result.stderr:
        pytest.fail("Synthetic bound rehearsal child reported an unexpected result", pytrace=False)


def _check_fresh_bound_request(scratch: Path, pair: Path) -> None:
    """Build independent test expectations and request the existing pair in a child."""
    trial = _BoundTrial(scratch, expired=True, directory=pair)
    provider = trial.bind()
    targets = (
        *_BOUND_DENIED,
        (records.private_create, "create_posix_private_bytes"),
        (records, "read_private_sensitive_bytes"),
        (token_io, "load_production_write_token_generation_state"),
        (token_io, "load_production_write_authorized_user_token"),
        (token_io, "persist_refreshed_production_write_token"),
    )
    with pytest.MonkeyPatch.context() as patch, _bound_denials(patch, targets) as denied:
        trial.observe(patch)
        outcome = trial.run(provider)
    _assert_bound_scope_result(trial, outcome, records.RecordState.SLOT_OCCUPIED)
    assert trial.calls == Counter(clock=1, factory=1, linked=1)
    assert not trial.fakes[0].calls and not trial.delivered
    assert not provider._active and provider.refresh_attempt_count == 0
    assert not denied and not trial.storage.calls


@pytest.mark.skipif(sys.platform != "linux", reason="real POSIX bound rehearsal and child probes")
@pytest.mark.parametrize("end", ("success", "writer_fault", "cancel"))
def test_bound_linux_real_preparation_lock_and_independent_occupied_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, end: str
) -> None:
    pair = tmp_path / "private-bound-pair"
    pair.mkdir(mode=0o700)
    trial = _BoundTrial(tmp_path, expired=True, directory=pair)
    storage = trial.storage
    token_io.write_production_write_token_bundle(
        storage.old_token, storage.paths["write"], storage.state, storage.paths["generation"]
    )
    provider = trial.bind()
    acquire = records.private_lock.acquire_posix_private_directory_lock
    publish = records.private_create.create_posix_private_bytes
    read_record = records.read_private_sensitive_bytes
    load_state = token_io.load_production_write_token_generation_state
    load_token = token_io.load_production_write_authorized_user_token
    persist = token_io.persist_refreshed_production_write_token
    cancelled = linked_tests._Cancel("Synthetic native pre-save cancellation")
    writer_error = token_io.ProductionWriteTokenIOError(
        "synthetic_native_bound_writer",
        "Synthetic native writer failed",
        publication_possible=False,
    )
    start_readbacks = []

    @contextmanager
    def counted_acquire(path):
        assert path == pair
        entered = False
        storage.event("acquire")
        try:
            with acquire(path) as backend:
                storage.active = entered = True
                storage.event("entry")
                yield backend
        finally:
            if entered:
                storage.active = False
                storage.event("backend_exit")

    def check_competitor():
        with pytest.raises(records.private_lock.PosixPrivateLockError) as refused:
            acquire(pair)
        assert refused.value.code == "posix_directory_lock_busy"
        storage.effect("same_process_busy")

    def publish_start(path, data):
        assert path == pair / records.RECORD_LEAF
        storage.effect("native_publish")
        return publish(path, data)

    def read_start(path, *, max_size):
        assert path == pair / records.RECORD_LEAF
        storage.effect("native_readback")
        result = read_record(path, max_size=max_size)
        start_readbacks.append(result)
        return result

    def read_state(path):
        storage.effect("native_state")
        if storage.calls["native_state"] == 1:
            assert len(start_readbacks) == 1
            assert records._matches_start_record(
                start_readbacks[0], storage.binding, storage.operation
            )
            check_competitor()
            _run_bound_child(_BOUND_LOCK_CHILD, pair, "busy")
            storage.effect("independent_busy")
        return load_state(path)

    def read_token(path):
        storage.effect("native_token")
        if end == "cancel" and storage.calls["native_token"] == 2:
            raise cancelled
        return load_token(path)

    def write_token(token, path, *, expected_token):
        storage.effect("native_writer")
        check_competitor()
        if end == "writer_fault":
            raise writer_error
        return persist(token, path, expected_token=expected_token)

    def verify_released_before_build():
        assert not storage.active and storage.calls["backend_exit"] == 1
        _run_bound_child(_BOUND_LOCK_CHILD, pair, "acquired")
        storage.event("independent_available_before_build")

    with monkeypatch.context() as local, _bound_denials(local) as denied:
        trial.observe(local, before_build=verify_released_before_build)
        local.setattr(records.private_lock, "acquire_posix_private_directory_lock", counted_acquire)
        local.setattr(records.private_create, "create_posix_private_bytes", publish_start)
        local.setattr(records, "read_private_sensitive_bytes", read_start)
        local.setattr(token_io, "load_production_write_token_generation_state", read_state)
        local.setattr(token_io, "load_production_write_authorized_user_token", read_token)
        local.setattr(token_io, "persist_refreshed_production_write_token", write_token)
        if end == "cancel":
            with pytest.raises(linked_tests._Cancel) as caught:
                trial.run(provider)
            assert caught.value is cancelled and trial.lower_errors == [cancelled]
        else:
            outcome = trial.run(provider)
            if end == "success":
                assert outcome.report.result_state is ProductionWriteTokenRehearsalResultState.READY
                assert outcome.report.token_refresh_count == 1
                assert storage.events[-6:] == [
                    "backend_exit",
                    "linked_return",
                    "independent_available_before_build",
                    "build",
                    "list",
                    "get",
                ]
                assert trial.artifacts.transport.call_log == ("events.list", "events.get")
                assert trial.artifacts.transport_provider.build_count == 1
            else:
                assert (
                    outcome.report.result_state
                    is ProductionWriteTokenRehearsalResultState.TOKEN_REFRESH_FAILED
                )
                assert outcome.report.token_refresh_count == 1
                assert (
                    type(trial.lower_errors[0])
                    is tokens.ProductionWriteTokenRefreshPersistenceError
                )
                assert trial.lower_errors[0].publication_possible is False
                trial.assert_no_reads(outcome)
    assert not denied
    assert storage.calls["acquire"] == storage.calls["entry"] == storage.calls["backend_exit"] == 1
    assert storage.calls["native_publish"] == storage.calls["native_readback"] == 1
    assert storage.calls["native_state"] == storage.calls["native_token"] == 2
    assert storage.calls["independent_busy"] == 1
    assert storage.calls["same_process_busy"] == (1 if end == "cancel" else 2)
    assert trial.fakes[0].calls == provider.refresh_attempt_count == 1
    assert storage.calls["native_writer"] == int(end != "cancel")
    assert not storage.active and not provider._active
    if end != "success":
        assert not trial.delivered and not trial.artifacts.transport.call_log
        assert trial.artifacts.transport_provider.build_count == 0
        _run_bound_child(_BOUND_LOCK_CHILD, pair, "acquired")
    with acquire(pair) as backend:
        backend.revalidate()
    assert (load_token(storage.paths["write"]) != storage.old_token) is (end == "success")
    assert load_state(storage.paths["generation"]) == storage.state
    retained_start = read_record(pair / records.RECORD_LEAF, max_size=records.MAX_RECORD_BYTES)
    assert retained_start == start_readbacks[0]
    _run_bound_child(_BOUND_REQUEST_CHILD, Path(__file__).parent, tmp_path / "fresh-request", pair)
    assert (
        read_record(pair / records.RECORD_LEAF, max_size=records.MAX_RECORD_BYTES) == retained_start
    )


def _definition(parent: ast.Module | ast.ClassDef, name: str) -> ast.FunctionDef:
    nodes = [
        node for node in parent.body if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    assert len(nodes) == 1
    return nodes[0]


def _bridge_calls(node: ast.AST, name: str | None = None) -> list[ast.Call]:
    def function_name(call: ast.Call) -> str:
        if isinstance(call.func, ast.Name):
            return call.func.id
        if isinstance(call.func, ast.Attribute):
            return call.func.attr
        return ""

    return sorted(
        (
            call
            for call in ast.walk(node)
            if isinstance(call, ast.Call) and (name is None or function_name(call) == name)
        ),
        key=lambda call: (call.lineno, call.col_offset),
    )


def test_bound_bridge_has_one_linked_call_and_keeps_exact_gates_and_order() -> None:
    token_tree = ast.parse(Path(tokens.__file__).read_text(encoding="utf-8"))
    transport_tree = ast.parse(Path(rehearsal_transport.__file__).read_text(encoding="utf-8"))
    rehearsal_tree = ast.parse(Path(rehearsal.__file__).read_text(encoding="utf-8"))
    classes = [
        node
        for node in token_tree.body
        if isinstance(node, ast.ClassDef) and node.name == "_BoundMockRehearsalSessionProvider"
    ]
    assert len(classes) == 1
    provider_class = classes[0]
    bind = _definition(token_tree, "_bind_mock_rehearsal_session_provider")
    bound_load = _definition(provider_class, "load_session")
    bridge_calls = _bridge_calls(bound_load, "_prepare_start_linked_session_mock")
    assert len(bridge_calls) == 1
    assert _bridge_calls(token_tree, "_prepare_start_linked_session_mock") == bridge_calls

    gate = _definition(transport_tree, "require_phase6d0_rehearsal_providers")
    wrapper = _definition(rehearsal_tree, "run_production_write_token_readonly_rehearsal_mock")
    inner = _definition(
        rehearsal_tree, "_run_production_write_token_readonly_rehearsal_with_session_mock"
    )
    for bridge in (bind, provider_class, gate, wrapper):
        for forbidden in (
            "_load_production_write_credential_session",
            "prepare_production_write_rehearsal_credential_session",
            "prepare_production_write_rehearsal_credential_session_mock",
            "create_start_record",
            "read_start_record",
            "_create_linked_start",
            "acquire_posix_private_directory_lock",
            "create_posix_private_bytes",
            "replace_posix_private_bytes",
            "persist_refreshed_production_write_token",
            "write_production_write_token_bundle",
            "read_private_sensitive_bytes",
        ):
            assert not _bridge_calls(bridge, forbidden)

    loads = _bridge_calls(wrapper, "load_session")
    assert len(loads) == 1
    assert ast.unparse(loads[0]) == "credential_session_provider.load_session(target=target)"
    gate_branches = [
        node
        for node in gate.body
        if isinstance(node, ast.If)
        and ast.unparse(node.test)
        == "type(credential_provider) is _BoundMockRehearsalSessionProvider"
    ]
    assert len(gate_branches) == 1
    bound_gate = gate_branches[0]
    assert any(
        isinstance(node, ast.Compare)
        and ast.unparse(node)
        == "type(transport_provider) is not FakeProductionWriteTokenReadOnlyTransportProvider"
        for node in ast.walk(bound_gate)
    )
    assert len(_bridge_calls(bound_gate, "_require_initialized")) == 1
    assert len(_bridge_calls(bound_gate, "require_phase6d0_rehearsal_transport")) == 1
    for effect in ("load_session", "build_transport"):
        assert not _bridge_calls(gate, effect)

    wrapper_branches = [
        node
        for node in ast.walk(wrapper)
        if isinstance(node, ast.If)
        and ast.unparse(node.test)
        == "type(credential_session_provider) is _BoundMockRehearsalSessionProvider"
    ]
    assert len(wrapper_branches) == 1
    early = wrapper_branches[0]
    for validator in ("_verify_manifest_source", "_verify_baseline_provenance"):
        calls = _bridge_calls(wrapper, validator)
        assert len(calls) == 1 and calls == _bridge_calls(early, validator)
        assert calls[0].lineno < loads[0].lineno
        assert len(_bridge_calls(inner, validator)) == 1
    assert _bridge_calls(wrapper, "require_phase6d0_rehearsal_providers")[0].lineno < early.lineno
    assert loads[0].lineno < _bridge_calls(wrapper, "_mock_session_context")[0].lineno
    assert (
        _bridge_calls(wrapper, "_mock_session_context")[0].lineno
        < _bridge_calls(wrapper, "build_transport")[0].lineno
    )

    public = _definition(token_tree, "prepare_production_write_rehearsal_credential_session")
    assert not _bridge_calls(public, "_load_production_write_credential_session")
    assert any(
        isinstance(node, ast.Constant)
        and node.value == "production_write_token_provider_session_enforcement_unavailable"
        for node in ast.walk(public)
    )
