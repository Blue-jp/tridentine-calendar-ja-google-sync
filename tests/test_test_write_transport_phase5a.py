from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
from conftest import REPOSITORY_ROOT
from jsonschema import Draft202012Validator
from phase4b_helpers import build_add_apply_bundle, build_update_apply_bundle
from phase5a1_helpers import prewrite_page
from phase5a_helpers import SYNTHETIC_ETAG, SYNTHETIC_EVENT_ID, make_test_target_config
from phase5c0_helpers import build_bootstrap_bundle
from phase5d0_helpers import build_single_update_bundle
from test_google_test_write_client_phase5a import _Service

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.google_errors import SafeGoogleError
from tridentine_calendar_google_sync.google_test_write_client import (
    GoogleTestCalendarWriteClient,
)
from tridentine_calendar_google_sync.google_test_write_client import (
    TestWriteClientError as ClientError,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec import (
    build_test_bootstrap_add_run_spec,
)
from tridentine_calendar_google_sync.test_single_update_run_spec import (
    build_test_single_update_run_spec,
)
from tridentine_calendar_google_sync.test_write_approval import (
    test_write_approval_challenge as approval_challenge,
)
from tridentine_calendar_google_sync.test_write_approval_dispatch import (
    any_test_write_approval_challenge,
)
from tridentine_calendar_google_sync.test_write_journal import (
    parse_test_write_journal_bytes,
    render_test_write_journal_json,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteManagedState as ManagedState,
)
from tridentine_calendar_google_sync.test_write_report import build_test_write_json_report
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


def _budget_inputs(tmp_path: Path, *, update: bool):
    if update:
        bundle = build_single_update_bundle(tmp_path)
        spec = build_test_single_update_run_spec(
            bundle.updated_profile,
            bundle.updated_source,
            bundle.prewrite_snapshot,
            bundle.plan,
            bundle.baseline,
            bundle.target,
        )
        bindings = {
            "single_update_plan": bundle.plan,
            "trusted_baseline": bundle.baseline,
            "current_baseline_hash": spec.trusted_baseline_hash,
        }
        current = _raw_event(
            spec.operation.current_state,
            event_id=spec.operation.google_event_id,
            etag=spec.operation.expected_etag,
        )
        snapshot_items = [current]
        desired = _raw_event(spec.operation.desired_state, event_id=spec.operation.google_event_id)
    else:
        bundle = build_bootstrap_bundle(tmp_path)
        spec = build_test_bootstrap_add_run_spec(
            bundle.profile,
            bundle.source,
            bundle.prewrite_snapshot,
            bundle.plan,
            bundle.target,
        )
        bindings = {"bootstrap_plan": bundle.plan}
        snapshot_items = []
        desired = _raw_event(spec.operation.desired_state)
    bindings.update(
        current_snapshot_hash=spec.current_snapshot_hash,
        current_plan_hash=bundle.plan.plan_content_hash,
    )
    challenge = any_test_write_approval_challenge(spec, **bindings)
    return spec, bundle.target, bindings, challenge, snapshot_items, desired


def _write_schema(kind: str, version: int) -> Draft202012Validator:
    path = REPOSITORY_ROOT / "schemas" / f"test-write-{kind}-v{version}.schema.json"
    return Draft202012Validator(json.loads(path.read_text(encoding="utf-8")))


@pytest.mark.parametrize(
    ("mutation", "failure_operation"),
    [("patch", "events.patch"), ("patch", "events.get"), ("import", "events.get")],
    ids=["patch-412", "get-412-after-patch", "get-412-after-import"],
)
def test_http_412_is_reported_at_the_phase_that_received_it(
    tmp_path: Path, mutation: str, failure_operation: str
) -> None:
    update = mutation == "patch"
    spec, target, bindings, challenge, items, desired = _budget_inputs(tmp_path, update=update)
    readback_failed = failure_operation == "events.get"
    failure = SafeGoogleError(
        status=412, reason="etag_conflict", retryable=False, attempt=1, operation=failure_operation
    )
    client = _Client(
        list_queue=[prewrite_page(items, summary=target.expected_summary)],
        get_queue=[*items, *([failure] if readback_failed else [])],
        patch_queue=[desired if readback_failed else failure] if update else [],
        import_queue=[] if update else [desired],
    )
    result = run_test_calendar_write(spec, target, client, challenge, **bindings)
    report = build_test_write_json_report(result)
    journal = result.journal
    assert result.schema_version == journal.schema_version == report["schema_version"] == "1.0"
    calls = ["list", *(["get"] if update else []), mutation, *(["get"] if readback_failed else [])]
    assert [name for name, _ in client.calls] == calls
    assert result.api_call_count == journal.api_call_count == report["api_call_count"] == len(calls)
    assert (
        result.mutation_attempt_count
        == journal.mutation_attempt_count
        == report["mutation_attempt_count"]
        == 1
    )
    assert (
        result.mutation_retry_count
        == journal.mutation_retry_count
        == report["mutation_retry_count"]
        == 0
    )
    assert result.read_retry_count == journal.read_retry_count == report["read_retry_count"] == 0
    assert result.success is report["success"] is False
    assert result.stopped is report["stopped"] is True
    assert result.read_back_verified is report["read_back_verified"] is False

    expected_entries = [("preflight", "succeeded", None)]
    if readback_failed:
        expected_entries += [
            ("mutation", "succeeded", None),
            ("read_back", "failed", "test_write_guard_failed"),
        ]
    else:
        expected_entries.append(("mutation", "failed", "etag_conflict"))
    assert [
        (e.phase.value, e.status.value, e.safe_error_code) for e in journal.entries
    ] == expected_entries
    assert (
        journal.state.value
        == result.state.value
        == report["state"]
        == ("failed" if readback_failed else "etag_conflict")
    )
    assert (
        list(result.safe_findings)
        == report["safe_findings"]
        == [journal.entries[-1].safe_error_code]
    )


@pytest.mark.parametrize("update", [False, True], ids=["add", "update"])
@pytest.mark.parametrize(
    ("remaining", "readback_fails"),
    [(0, False), (1, False), (2, False), (2, True)],
    ids=["no-slot", "one-slot", "two-slots", "last-read-fails"],
)
def test_budget_at_mutation_dispatch(
    tmp_path: Path, update: bool, remaining: int, readback_fails: bool
) -> None:
    spec, target, bindings, challenge, snapshot_items, desired = _budget_inputs(
        tmp_path, update=update
    )

    # Preflight consumes one list retry and, only for UPDATE, one fresh ETag GET.
    list_count = 10 - remaining - int(update)
    pages = [
        prewrite_page(next_page_token=f"page-{i}", summary=target.expected_summary)
        for i in range(list_count - 2)
    ]
    client = _Client(
        list_queue=[
            _retryable("events.list"),
            *pages,
            prewrite_page(snapshot_items, summary=target.expected_summary),
        ],
        get_queue=[*snapshot_items, _retryable("events.get") if readback_fails else desired],
        import_queue=[desired],
        patch_queue=[desired],
    )
    result = run_test_calendar_write(
        spec,
        target,
        client,
        challenge,
        **bindings,
        sleep=lambda _delay: None,
        jitter=lambda _maximum: 0.0,
    )
    journal = parse_test_write_journal_bytes(
        render_test_write_journal_json(result.journal).encode()
    )
    report = build_test_write_json_report(result)
    expected_calls = ["list"] * list_count + (["get"] if update else [])
    assert result.schema_version == journal.schema_version == report["schema_version"] == "1.0"
    sent = remaining == 2
    verified = sent and not readback_fails
    if sent:
        expected_calls.extend(["patch" if update else "import", "get"])
    assert [name for name, _ in client.calls] == expected_calls
    assert (
        result.api_call_count
        == journal.api_call_count
        == report["api_call_count"]
        == len(expected_calls)
    )
    assert result.read_retry_count == journal.read_retry_count == report["read_retry_count"] == 1
    assert (
        result.mutation_attempt_count
        == journal.mutation_attempt_count
        == report["mutation_attempt_count"]
        == int(sent)
    )
    assert result.mutation_retry_count == report["mutation_retry_count"] == 0
    assert result.read_back_verified is report["read_back_verified"] is verified
    assert result.state is (ExecutionState.SUCCEEDED if verified else ExecutionState.FAILED)
    assert report["state"] == result.state.value
    entries = [(e.phase.value, e.status.value, e.api_call_count) for e in journal.entries]
    if sent:
        assert entries == [
            ("preflight", "succeeded", 8),
            ("mutation", "succeeded", 9),
            ("read_back", "succeeded" if verified else "failed", 10),
        ]
    else:
        assert entries == [("preflight", "failed", 10 - remaining)]
    if not verified:
        assert journal.entries[-1].safe_error_code == "test_write_api_call_budget_exceeded"
        assert report["safe_findings"] == ["test_write_api_call_budget_exceeded"]


@pytest.mark.parametrize(
    ("response", "pages", "retry"),
    [({}, 1, False), ({"id": ""}, 2, True), ({"id": 7}, 7, True)],
    ids=["missing", "empty-after-pagination-and-retry", "nonstring-at-budget-boundary"],
)
def test_acknowledged_import_without_id_returns_v2_stop(
    tmp_path: Path, response: dict[str, object], pages: int, retry: bool
) -> None:
    spec, target, bindings, challenge, _, _ = _budget_inputs(tmp_path, update=False)
    client = _Client(
        list_queue=[
            *([_retryable("events.list")] if retry else []),
            *[prewrite_page(next_page_token=f"page-{i}") for i in range(pages - 1)],
            prewrite_page(),
        ],
        import_queue=[response],
    )
    result = run_test_calendar_write(
        spec, target, client, challenge, **bindings, sleep=lambda _: None, jitter=lambda _: 0.0
    )
    report = build_test_write_json_report(result)
    journal = result.journal
    reads = pages + int(retry)
    code = "test_write_read_back_identity_missing"
    assert [name for name, _ in client.calls] == ["list"] * reads + ["import"]
    assert all(args["ical_uid"] is None for name, args in client.calls if name == "list")
    assert [
        (
            e.phase.value,
            e.status.value,
            e.safe_error_code,
            e.api_call_count,
            e.mutation_attempt_count,
        )
        for e in journal.entries
    ] == [
        ("preflight", "succeeded", None, reads, 0),
        ("mutation", "succeeded", None, reads + 1, 1),
        ("read_back", "failed", code, reads + 1, 1),
    ]
    assert all(e.read_retry_count == int(retry) for e in journal.entries)
    assert journal.schema_version == result.schema_version == report["schema_version"] == "2.0"
    assert journal.journal_type == "test-write-operation-journal-v2"
    assert result.result_type == "test-calendar-write-result-v2"
    assert report["report_type"] == "test-calendar-write-report-v2"
    assert journal.state.value == result.state.value == report["state"] == "failed"
    assert result.success is report["success"] is False
    assert result.stopped is report["stopped"] is True
    assert result.read_back_verified is report["read_back_verified"] is False
    assert result.recovered_after_uncertain is report["recovered_after_uncertain"] is False
    assert list(result.safe_findings) == report["safe_findings"] == [code]
    assert (
        journal.api_call_count
        == result.api_call_count
        == report["api_call_count"]
        == len(client.calls)
    )
    assert (
        journal.read_retry_count
        == result.read_retry_count
        == report["read_retry_count"]
        == int(retry)
    )
    assert (
        journal.mutation_attempt_count
        == result.mutation_attempt_count
        == report["mutation_attempt_count"]
        == 1
    )
    assert (
        journal.mutation_retry_count
        == result.mutation_retry_count
        == report["mutation_retry_count"]
        == 0
    )
    assert report["journal_hash"] == journal.journal_content_hash
    assert report["result_hash"] == result.result_content_hash

    journal_doc = json.loads(render_test_write_journal_json(journal))
    for kind, document in (("journal", journal_doc), ("report", report)):
        v2 = _write_schema(kind, 2)
        v2.validate(document)
        assert not _write_schema(kind, 1).is_valid(document)
        assert not v2.is_valid({**document, "schema_version": "1.0"})
        assert not v2.is_valid({**document, f"{kind}_type": "unexpected"})
        assert not v2.is_valid({**document, "operation": "update"})
    wrong_terminal = {**journal_doc["entries"][-1], "safe_error_code": "test_write_guard_failed"}
    assert not _write_schema("journal", 2).is_valid(
        {**journal_doc, "entries": [*journal_doc["entries"][:-1], wrong_terminal]}
    )
    assert not _write_schema("report", 2).is_valid({**report, "read_back_verified": True})


def test_patch_header_refusal_records_only_completed_preflight_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spec, target, bindings, challenge, snapshot_items, _ = _budget_inputs(tmp_path, update=True)
    service = _Service()
    events = service.events()
    events.responses["list"] = prewrite_page(snapshot_items, summary=target.expected_summary)
    events.responses["get"] = snapshot_items[0]
    build_patch = events.patch

    def without_headers(**parameters: object):
        request = build_patch(**parameters)
        del request.headers
        return request

    monkeypatch.setattr(events, "patch", without_headers)
    result = run_test_calendar_write(
        spec,
        target,
        GoogleTestCalendarWriteClient(service, target_config=target),
        challenge,
        **bindings,
    )

    assert [name for name, _ in events.calls] == ["list", "get", "patch"]
    assert events.requests["list"].execute_calls == events.requests["get"].execute_calls == [0]
    assert events.requests["patch"].execute_calls == []
    journal = parse_test_write_journal_bytes(
        render_test_write_journal_json(result.journal).encode()
    )
    report = build_test_write_json_report(result)
    assert result.state is ExecutionState.FAILED
    assert result.api_call_count == journal.api_call_count == report["api_call_count"] == 2
    assert (
        result.mutation_attempt_count
        == journal.mutation_attempt_count
        == report["mutation_attempt_count"]
        == 0
    )
    assert result.read_retry_count == result.mutation_retry_count == 0
    assert result.read_back_verified is report["read_back_verified"] is False
    assert [(e.phase.value, e.status.value) for e in journal.entries] == [("preflight", "failed")]
    assert journal.entries[-1].safe_error_code == "test_write_guard_failed"
    assert report["safe_findings"] == ["test_write_guard_failed"]


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
