from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

import pytest
from phase4b_helpers import build_add_apply_bundle, build_update_apply_bundle
from phase5a_helpers import SYNTHETIC_ETAG, SYNTHETIC_EVENT_ID, make_test_target_config

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.google_errors import SafeGoogleError
from tridentine_calendar_google_sync.google_test_write_client import (
    TestWriteClientError as ClientError,
)
from tridentine_calendar_google_sync.test_write_approval import (
    test_write_approval_challenge as approval_challenge,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteManagedState as ManagedState,
)
from tridentine_calendar_google_sync.test_write_run_spec import (
    build_test_write_run_spec,
    calculate_test_write_operation_hash,
    calculate_test_write_run_spec_hash,
)
from tridentine_calendar_google_sync.test_write_transport import (
    TestWriteExecutionState as ExecutionState,
)
from tridentine_calendar_google_sync.test_write_transport import (
    TestWriteTransportError as TransportError,
)
from tridentine_calendar_google_sync.test_write_transport import (
    run_test_calendar_write,
    verify_test_write_execution_result,
)

pytestmark = pytest.mark.google_test_write


def _raw_event(
    state: ManagedState,
    *,
    event_id: str = SYNTHETIC_EVENT_ID,
    etag: str = SYNTHETIC_ETAG,
    **overrides: object,
) -> dict[str, object]:
    event: dict[str, object] = {
        "id": event_id,
        "iCalUID": state.ical_uid,
        "summary": state.summary,
        "description": state.description,
        "start": {"date": state.start_date.isoformat()},
        "end": {"date": state.end_date.isoformat()},
        "status": "confirmed",
        "eventType": "default",
        "etag": etag,
    }
    event.update(overrides)
    return event


def _page(items: list[Mapping[str, object]]) -> dict[str, object]:
    return {
        "summary": "Synthetic Test Calendar",
        "timeZone": "Asia/Tokyo",
        "accessRole": "owner",
        "items": items,
    }


@dataclass
class _Client:
    list_queue: list[object] = field(default_factory=list)
    get_queue: list[object] = field(default_factory=list)
    import_queue: list[object] = field(default_factory=list)
    patch_queue: list[object] = field(default_factory=list)
    calls: list[tuple[str, dict[str, object]]] = field(default_factory=list)
    bound_calendar_id: str | None = None

    def verify_bound_target(self, target_config: object) -> None:
        calendar_id = getattr(target_config, "calendar_id", None)
        if self.bound_calendar_id is None:
            self.bound_calendar_id = calendar_id
            return
        if self.bound_calendar_id != calendar_id:
            raise ClientError(
                "test_write_target_binding_mismatch",
                "Test write client target binding did not match",
            )

    def _take(
        self,
        name: str,
        queue: list[object],
        kwargs: dict[str, object],
    ) -> Mapping[str, object]:
        self.calls.append((name, kwargs))
        if not queue:
            raise AssertionError(f"unexpected {name} call")
        value = queue.pop(0)
        if isinstance(value, BaseException):
            raise value
        assert isinstance(value, Mapping)
        return value

    def list_events(
        self,
        *,
        page_token: str | None,
        ical_uid: str | None = None,
    ) -> Mapping[str, object]:
        return self._take(
            "list",
            self.list_queue,
            {"page_token": page_token, "ical_uid": ical_uid},
        )

    def get_event(self, *, event_id: str) -> Mapping[str, object]:
        return self._take("get", self.get_queue, {"event_id": event_id})

    def import_event(
        self,
        *,
        body: Mapping[str, object],
    ) -> Mapping[str, object]:
        return self._take("import", self.import_queue, {"body": dict(body)})

    def patch_event(
        self,
        *,
        event_id: str,
        body: Mapping[str, object],
        etag: str,
    ) -> Mapping[str, object]:
        return self._take(
            "patch",
            self.patch_queue,
            {
                "event_id": event_id,
                "body": dict(body),
                "etag": etag,
            },
        )


def _retryable(operation: str) -> SafeGoogleError:
    return SafeGoogleError(
        status=503,
        reason="service_unavailable",
        retryable=True,
        attempt=1,
        operation=operation,
    )


def _etag_conflict() -> SafeGoogleError:
    return SafeGoogleError(
        status=412,
        reason="etag_conflict",
        retryable=False,
        attempt=1,
        operation="events.patch",
    )


def _prepare(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    *,
    update: bool,
) -> tuple[Any, Any, Any, str]:
    import tridentine_calendar_google_sync.test_write_run_spec as run_spec_module
    import tridentine_calendar_google_sync.test_write_transport as transport_module

    bundle = (
        build_update_apply_bundle(tmp_path, synthetic_profile_factory)
        if update
        else build_add_apply_bundle(tmp_path, synthetic_profile_factory)
    )
    fingerprint = bundle.snapshot.target_fingerprint
    reference = f"T-{fingerprint[:12]}"
    monkeypatch.setattr(
        run_spec_module, "validate_test_write_target_config", lambda _target: fingerprint
    )
    monkeypatch.setattr(run_spec_module, "test_write_target_reference", lambda _target: reference)
    target = make_test_target_config().model_copy(
        update={"expected_target_fingerprint": fingerprint}
    )
    spec = build_test_write_run_spec(
        bundle.profile,
        bundle.source,
        bundle.snapshot,
        bundle.plan,
        target,
        trusted_baseline=bundle.baseline if update else None,
    )
    monkeypatch.setattr(
        transport_module, "validate_test_write_target_config", lambda _target: fingerprint
    )
    monkeypatch.setattr(transport_module, "test_write_target_reference", lambda _target: reference)
    monkeypatch.setattr(
        transport_module,
        "verify_test_write_target_metadata",
        lambda _target, _observation: None,
    )

    def fresh_snapshot(_client: object, _target: object, counters: Any, **_kwargs: object) -> Any:
        counters.consume_api_call()
        return bundle.snapshot

    monkeypatch.setattr(transport_module, "_fresh_snapshot", fresh_snapshot)
    challenge = approval_challenge(
        spec,
        current_snapshot_hash=spec.current_snapshot_hash,
        current_plan_hash=spec.plan_hash,
        current_baseline_hash=spec.trusted_baseline_hash,
    )
    return spec, bundle, target, challenge


def _run(spec: Any, target: Any, client: _Client, challenge: str) -> Any:
    if client.bound_calendar_id is None:
        client.bound_calendar_id = target.calendar_id
    return run_test_calendar_write(
        spec,
        target,
        client,
        challenge,
        current_snapshot_hash=spec.current_snapshot_hash,
        current_plan_hash=spec.plan_hash,
        current_baseline_hash=spec.trusted_baseline_hash,
        sleep=lambda _delay: None,
        jitter=lambda _maximum: 0.0,
    )


def test_exact_add_imports_once_and_requires_exact_read_back(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=False
    )
    desired = spec.operation.desired_state
    imported = _raw_event(desired)
    client = _Client(import_queue=[imported], get_queue=[imported])

    result = _run(spec, target, client, challenge)

    assert result.state is ExecutionState.SUCCEEDED
    assert result.success is True
    assert result.read_back_verified is True
    assert result.recovered_after_uncertain is False
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls] == ["import", "get"]
    import_body = client.calls[0][1]["body"]
    assert isinstance(import_body, dict)
    assert import_body["iCalUID"] == desired.ical_uid
    assert set(import_body) == {
        "iCalUID",
        "summary",
        "description",
        "start",
        "end",
        "eventType",
    }
    verify_test_write_execution_result(result)


@pytest.mark.parametrize(
    "changed",
    (
        {"iCalUID": "wrong-fixture@example.invalid"},
        {"summary": "Wrong"},
        {"description": "Wrong"},
        {"start": {"date": "2026-06-20"}},
        {"end": {"date": "2026-06-20"}},
        {"start": {"dateTime": "2026-06-01T00:00:00Z"}},
        {"eventType": "focusTime"},
        {"status": "cancelled"},
        {"recurrence": ["RRULE:FREQ=DAILY"]},
        {"colorId": "1"},
        {"eventLabelId": "fixture-label"},
    ),
)
def test_add_read_back_mismatch_stops_without_second_import_or_rollback(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    changed: dict[str, object],
) -> None:
    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=False
    )
    desired = spec.operation.desired_state
    imported = _raw_event(desired)
    mismatched = _raw_event(desired, **changed)
    client = _Client(import_queue=[imported], get_queue=[mismatched])

    result = _run(spec, target, client, challenge)

    assert result.success is False
    assert result.stopped is True
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls].count("import") == 1
    assert all(name != "delete" for name, _values in client.calls)
    assert result.journal.rollback_available is False


def test_import_response_loss_recovers_only_by_exact_uid_lookup(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=False
    )
    desired = spec.operation.desired_state
    client = _Client(
        import_queue=[_retryable("events.import")],
        list_queue=[_page([_raw_event(desired)])],
    )
    result = _run(spec, target, client, challenge)

    assert result.success is True
    assert result.recovered_after_uncertain is True
    assert result.read_back_verified is True
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls] == ["import", "list"]


@pytest.mark.parametrize("mode", ("missing", "duplicate", "mismatch"))
def test_import_uncertain_nonexact_lookup_stops_without_second_import(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=False
    )
    desired = spec.operation.desired_state
    if mode == "missing":
        events: list[Mapping[str, object]] = []
    elif mode == "duplicate":
        events = [
            _raw_event(desired, event_id="evtfixtureuncertain1"),
            _raw_event(desired, event_id="evtfixtureuncertain2"),
        ]
    else:
        events = [_raw_event(desired, summary="Mismatch")]
    client = _Client(import_queue=[_retryable("events.import")], list_queue=[_page(events)])

    result = _run(spec, target, client, challenge)

    expected_state = ExecutionState.FAILED if mode == "duplicate" else ExecutionState.UNCERTAIN
    assert result.state is expected_state
    assert result.success is False
    assert result.stopped is True
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls].count("import") == 1


def test_exact_update_gets_fresh_etag_patches_changed_fields_once_and_reads_back(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=True
    )
    current = _raw_event(
        spec.operation.current_state,
        event_id=spec.operation.google_event_id,
        etag=spec.operation.expected_etag,
    )
    desired = _raw_event(
        spec.operation.desired_state,
        event_id=spec.operation.google_event_id,
        etag="fixture-etag-after-patch",
    )
    client = _Client(get_queue=[current, desired], patch_queue=[desired])

    result = _run(spec, target, client, challenge)

    assert result.success is True
    assert [name for name, _values in client.calls] == ["get", "patch", "get"]
    patch = client.calls[1][1]
    assert patch["event_id"] == spec.operation.google_event_id
    assert patch["etag"] == spec.operation.expected_etag
    assert patch["etag"] != "*"
    assert patch["body"] == {"summary": spec.operation.desired_state.summary}
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0


def test_update_read_back_mismatch_stops_without_second_patch(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=True
    )
    current = _raw_event(
        spec.operation.current_state,
        event_id=spec.operation.google_event_id,
        etag=spec.operation.expected_etag,
    )
    desired = _raw_event(
        spec.operation.desired_state,
        event_id=spec.operation.google_event_id,
        etag="fixture-etag-after-patch",
    )
    mismatched = _raw_event(
        spec.operation.desired_state,
        event_id=spec.operation.google_event_id,
        etag="fixture-etag-after-patch",
        description="Mismatch",
    )
    client = _Client(get_queue=[current, mismatched], patch_queue=[desired])

    result = _run(spec, target, client, challenge)

    assert result.state is ExecutionState.FAILED
    assert result.read_back_verified is False
    assert result.stopped is True
    assert [name for name, _values in client.calls].count("patch") == 1
    assert result.mutation_retry_count == 0


def test_date_update_patch_contains_atomic_valid_start_end_pair(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, _bundle, target, _challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=True
    )
    desired_state = spec.operation.desired_state.model_copy(
        update={
            "start_date": spec.operation.desired_state.start_date.replace(day=2),
            "end_date": spec.operation.desired_state.end_date.replace(day=3),
        }
    )
    provisional_operation = spec.operation.model_copy(
        update={
            "changed_fields": ("start_date", "end_date"),
            "desired_state": desired_state,
            "operation_content_hash": "0" * 64,
        }
    )
    operation = provisional_operation.model_copy(
        update={
            "operation_content_hash": calculate_test_write_operation_hash(provisional_operation)
        }
    )
    provisional_spec = spec.model_copy(
        update={"operation": operation, "run_spec_content_hash": "0" * 64}
    )
    spec = provisional_spec.model_copy(
        update={"run_spec_content_hash": calculate_test_write_run_spec_hash(provisional_spec)}
    )
    challenge = approval_challenge(
        spec,
        current_snapshot_hash=spec.current_snapshot_hash,
        current_plan_hash=spec.plan_hash,
        current_baseline_hash=spec.trusted_baseline_hash,
    )
    current = _raw_event(
        spec.operation.current_state,
        event_id=spec.operation.google_event_id,
        etag=spec.operation.expected_etag,
    )
    desired = _raw_event(
        desired_state,
        event_id=spec.operation.google_event_id,
        etag="fixture-etag-after-date-patch",
    )
    client = _Client(get_queue=[current, desired], patch_queue=[desired])

    result = _run(spec, target, client, challenge)

    assert result.success is True
    patch_body = client.calls[1][1]["body"]
    assert patch_body == {
        "start": {"date": desired_state.start_date.isoformat()},
        "end": {"date": desired_state.end_date.isoformat()},
    }


def test_fresh_etag_mismatch_stops_before_patch(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=True
    )
    changed_etag = _raw_event(
        spec.operation.current_state,
        event_id=spec.operation.google_event_id,
        etag="fixture-etag-concurrent-change",
    )
    client = _Client(get_queue=[changed_etag])

    result = _run(spec, target, client, challenge)

    assert result.state is ExecutionState.ETAG_CONFLICT
    assert result.success is False
    assert result.mutation_attempt_count == 0
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls] == ["get"]


def test_http_412_stops_with_no_patch_retry_or_success(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=True
    )
    current = _raw_event(
        spec.operation.current_state,
        event_id=spec.operation.google_event_id,
        etag=spec.operation.expected_etag,
    )
    client = _Client(get_queue=[current], patch_queue=[_etag_conflict()])

    result = _run(spec, target, client, challenge)

    assert result.state is ExecutionState.ETAG_CONFLICT
    assert result.success is False
    assert result.stopped is True
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls].count("patch") == 1


def test_patch_response_loss_recovers_by_read_without_second_patch(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=True
    )
    current = _raw_event(
        spec.operation.current_state,
        event_id=spec.operation.google_event_id,
        etag=spec.operation.expected_etag,
    )
    desired = _raw_event(
        spec.operation.desired_state,
        event_id=spec.operation.google_event_id,
        etag="fixture-etag-recovered",
    )
    client = _Client(get_queue=[current, desired], patch_queue=[_retryable("events.patch")])

    result = _run(spec, target, client, challenge)

    assert result.success is True
    assert result.recovered_after_uncertain is True
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls].count("patch") == 1


def test_patch_response_loss_mismatch_stops_without_second_patch_or_rollback(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=True
    )
    current = _raw_event(
        spec.operation.current_state,
        event_id=spec.operation.google_event_id,
        etag=spec.operation.expected_etag,
    )
    client = _Client(get_queue=[current, current], patch_queue=[_retryable("events.patch")])

    result = _run(spec, target, client, challenge)

    assert result.state is ExecutionState.UNCERTAIN
    assert result.stopped is True
    assert [name for name, _values in client.calls].count("patch") == 1
    assert result.mutation_retry_count == 0
    assert result.journal.rollback_available is False


def test_fresh_read_retries_are_bounded_and_never_repeat_mutation(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=True
    )
    current = _raw_event(
        spec.operation.current_state,
        event_id=spec.operation.google_event_id,
        etag=spec.operation.expected_etag,
    )
    desired = _raw_event(
        spec.operation.desired_state,
        event_id=spec.operation.google_event_id,
        etag="fixture-etag-after-read-retry",
    )
    client = _Client(
        get_queue=[_retryable("events.get"), current, desired],
        patch_queue=[desired],
    )

    result = _run(spec, target, client, challenge)

    assert result.success is True
    assert result.read_retry_count == 1
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls].count("patch") == 1


def test_production_or_mismatched_target_is_rejected_before_client_touch(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import tridentine_calendar_google_sync.test_write_transport as transport_module

    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=False
    )
    monkeypatch.setattr(
        transport_module,
        "test_write_target_reference",
        lambda _target: PRODUCTION_TARGET_REFERENCE,
    )
    client = _Client()

    with pytest.raises(TransportError) as captured:
        _run(spec, target, client, challenge)
    assert captured.value.code == "production_or_mismatched_test_write_target"
    assert client.calls == []


def test_client_target_binding_mismatch_is_rejected_before_first_api(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=False
    )
    client = _Client(bound_calendar_id="other-owned-target@example.invalid")

    with pytest.raises(ClientError) as captured:
        _run(spec, target, client, challenge)

    assert captured.value.code == "test_write_target_binding_mismatch"
    assert client.calls == []


def test_result_public_form_redacts_raw_uid_event_id_etag_and_content(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=True
    )
    current = _raw_event(
        spec.operation.current_state,
        event_id=spec.operation.google_event_id,
        etag=spec.operation.expected_etag,
    )
    desired = _raw_event(
        spec.operation.desired_state,
        event_id=spec.operation.google_event_id,
        etag="fixture-etag-redaction-new",
    )
    result = _run(
        spec,
        target,
        _Client(get_queue=[current, desired], patch_queue=[desired]),
        challenge,
    )
    rendered = result.model_dump_json()

    for value in (
        spec.operation.desired_state.ical_uid,
        spec.operation.google_event_id,
        spec.operation.expected_etag,
        spec.operation.desired_state.summary,
        spec.operation.desired_state.description,
        spec.target_fingerprint,
    ):
        assert value not in rendered
