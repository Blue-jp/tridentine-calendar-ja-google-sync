from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest
from phase5a1_helpers import prewrite_page
from phase5c0_helpers import build_bootstrap_bundle
from test_test_write_transport_phase5a import _Client, _raw_event, _retryable

from tridentine_calendar_google_sync.test_bootstrap_approval import (
    test_bootstrap_add_approval_challenge as approval_challenge,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec import (
    build_test_bootstrap_add_run_spec,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetPolicyError as TargetPolicyError,
)
from tridentine_calendar_google_sync.test_write_transport import (
    TestWriteExecutionState as ExecutionState,
)
from tridentine_calendar_google_sync.test_write_transport import (
    run_test_calendar_write,
    verify_test_write_execution_result,
)

pytestmark = pytest.mark.google_test_write


def _inputs(tmp_path: Path):
    bundle = build_bootstrap_bundle(tmp_path)
    run_spec = build_test_bootstrap_add_run_spec(
        bundle.profile,
        bundle.source,
        bundle.prewrite_snapshot,
        bundle.plan,
        bundle.target,
    )
    challenge = approval_challenge(
        run_spec,
        bundle.plan,
        current_snapshot_hash=run_spec.current_snapshot_hash,
        current_plan_hash=bundle.plan.plan_content_hash,
        current_baseline_hash=None,
    )
    return bundle, run_spec, challenge


def _run(bundle: object, run_spec: object, client: _Client, challenge: str):
    return run_test_calendar_write(
        run_spec,  # type: ignore[arg-type]
        bundle.target,  # type: ignore[attr-defined]
        client,
        challenge,
        current_snapshot_hash=run_spec.current_snapshot_hash,  # type: ignore[attr-defined]
        current_plan_hash=bundle.plan.plan_content_hash,  # type: ignore[attr-defined]
        current_baseline_hash=None,
        bootstrap_plan=bundle.plan,  # type: ignore[attr-defined]
        sleep=lambda _delay: None,
        jitter=lambda _maximum: 0.0,
    )


def _desired_raw(run_spec: object, *, etag: str = "fixture-bootstrap-etag-created"):
    return _raw_event(
        run_spec.operation.desired_state,  # type: ignore[attr-defined]
        event_id="evtfixturebootstrapcreated001",
        etag=etag,
    )


def test_bootstrap_add_uses_list_import_get_once_and_never_patch(tmp_path: Path) -> None:
    bundle, run_spec, challenge = _inputs(tmp_path)
    desired = _desired_raw(run_spec)
    client = _Client(
        list_queue=[prewrite_page()],
        import_queue=[desired],
        get_queue=[desired],
    )

    result = _run(bundle, run_spec, client, challenge)

    assert result.state is ExecutionState.SUCCEEDED
    assert result.success is True
    assert result.read_back_verified is True
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls] == ["list", "import", "get"]
    assert [name for name, _values in client.calls].count("patch") == 0
    assert client.calls[1][1]["body"]["iCalUID"] == run_spec.operation.desired_state.ical_uid
    verify_test_write_execution_result(result)


def test_nonempty_fresh_snapshot_stops_before_import_or_patch(tmp_path: Path) -> None:
    bundle, run_spec, challenge = _inputs(tmp_path)
    existing = _desired_raw(run_spec, etag="fixture-existing-etag")
    client = _Client(list_queue=[prewrite_page([existing])])

    result = _run(bundle, run_spec, client, challenge)

    assert result.success is False
    assert result.stopped is True
    assert result.mutation_attempt_count == 0
    assert [name for name, _values in client.calls] == ["list"]


def test_production_target_stops_before_list_import_get_or_patch(tmp_path: Path) -> None:
    bundle, run_spec, challenge = _inputs(tmp_path)
    production_target = bundle.target.model_copy(update={"target_environment": "production"})
    client = _Client()

    with pytest.raises(TargetPolicyError):
        run_test_calendar_write(
            run_spec,
            production_target,
            client,
            challenge,
            current_snapshot_hash=run_spec.current_snapshot_hash,
            current_plan_hash=bundle.plan.plan_content_hash,
            current_baseline_hash=None,
            bootstrap_plan=bundle.plan,
        )
    assert client.calls == []


def test_uncertain_import_recovers_by_uid_lookup_without_second_mutation(
    tmp_path: Path,
) -> None:
    bundle, run_spec, challenge = _inputs(tmp_path)
    desired = _desired_raw(run_spec)
    client = _Client(
        list_queue=[prewrite_page(), prewrite_page([desired])],
        import_queue=[_retryable("events.import")],
    )

    result = _run(bundle, run_spec, client, challenge)

    assert result.success is True
    assert result.recovered_after_uncertain is True
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls] == ["list", "import", "list"]


@pytest.mark.parametrize(
    "matches",
    ([], ["mismatch"], ["duplicate", "duplicate"]),
)
def test_uncertain_import_nonexact_lookup_stops_without_second_import(
    tmp_path: Path,
    matches: list[str],
) -> None:
    bundle, run_spec, challenge = _inputs(tmp_path)
    desired_state = run_spec.operation.desired_state
    events: list[Mapping[str, object]] = []
    for index, value in enumerate(matches):
        event = _raw_event(
            desired_state,
            event_id=f"evtfixturebootstrapuncertain{index}",
            etag=f"fixture-bootstrap-etag-{index}",
        )
        if value == "mismatch":
            event["summary"] = "Mismatch"
        events.append(event)
    client = _Client(
        list_queue=[prewrite_page(), prewrite_page(events)],
        import_queue=[_retryable("events.import")],
    )

    result = _run(bundle, run_spec, client, challenge)

    assert result.success is False
    assert result.stopped is True
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls].count("import") == 1
    assert [name for name, _values in client.calls].count("patch") == 0
