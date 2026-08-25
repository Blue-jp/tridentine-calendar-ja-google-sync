from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from phase5d0_helpers import (
    build_single_update_bundle,
    build_single_update_prewrite_snapshot,
)
from test_test_write_transport_phase5a import _Client, _page, _raw_event, _retryable

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.test_single_update_run_spec import (
    TestSingleUpdateRunSpecError as SingleUpdateRunSpecError,
)
from tridentine_calendar_google_sync.test_single_update_run_spec import (
    build_test_single_update_run_spec,
    calculate_test_single_update_run_spec_hash,
)
from tridentine_calendar_google_sync.test_write_approval_dispatch import (
    any_test_write_approval_challenge,
)
from tridentine_calendar_google_sync.test_write_spec_dispatch import (
    TestWriteSpecDispatchError as WriteSpecDispatchError,
)
from tridentine_calendar_google_sync.test_write_transport import (
    TestWriteExecutionState as ExecutionState,
)
from tridentine_calendar_google_sync.test_write_transport import (
    run_test_calendar_write,
    verify_test_write_execution_result,
)

pytestmark = pytest.mark.google_test_write


def _prepared(tmp_path: Path) -> tuple[Any, Any, str]:
    bundle = build_single_update_bundle(tmp_path)
    run_spec = build_test_single_update_run_spec(
        bundle.updated_profile,
        bundle.updated_source,
        bundle.prewrite_snapshot,
        bundle.plan,
        bundle.baseline,
        bundle.target,
    )
    challenge = any_test_write_approval_challenge(
        run_spec,
        current_snapshot_hash=run_spec.current_snapshot_hash,
        current_plan_hash=run_spec.single_update_plan_hash,
        current_baseline_hash=run_spec.trusted_baseline_hash,
        single_update_plan=bundle.plan,
        trusted_baseline=bundle.baseline,
    )
    return bundle, run_spec, challenge


def _run(bundle: Any, run_spec: Any, client: _Client, challenge: str) -> Any:
    return run_test_calendar_write(
        run_spec,
        bundle.target,
        client,
        challenge,
        current_snapshot_hash=run_spec.current_snapshot_hash,
        current_plan_hash=run_spec.single_update_plan_hash,
        current_baseline_hash=run_spec.trusted_baseline_hash,
        single_update_plan=bundle.plan,
        trusted_baseline=bundle.baseline,
        sleep=lambda _delay: None,
        jitter=lambda _maximum: 0.0,
    )


def test_description_update_uses_list_get_patch_get_once(tmp_path: Path) -> None:
    bundle, run_spec, challenge = _prepared(tmp_path)
    current = _raw_event(
        run_spec.operation.current_state,
        event_id=run_spec.operation.google_event_id,
        etag=run_spec.operation.expected_etag,
    )
    desired = _raw_event(
        run_spec.operation.desired_state,
        event_id=run_spec.operation.google_event_id,
        etag="fixture-etag-after-single-update",
    )
    client = _Client(
        list_queue=[_page([current])],
        get_queue=[current, desired],
        patch_queue=[desired],
    )

    result = _run(bundle, run_spec, client, challenge)

    assert result.state is ExecutionState.SUCCEEDED
    assert result.success is True
    assert result.read_back_verified is True
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls] == ["list", "get", "patch", "get"]
    patch = client.calls[2][1]
    assert patch["event_id"] == run_spec.operation.google_event_id
    assert patch["etag"] == run_spec.operation.expected_etag
    assert patch["etag"] != "*"
    assert patch["body"] == {"description": run_spec.operation.desired_state.description}
    assert all(name != "import" for name, _values in client.calls)
    verify_test_write_execution_result(result)


def test_missing_dedicated_plan_or_baseline_stops_before_client_touch(
    tmp_path: Path,
) -> None:
    bundle, run_spec, challenge = _prepared(tmp_path)
    for kwargs in (
        {"single_update_plan": None, "trusted_baseline": bundle.baseline},
        {"single_update_plan": bundle.plan, "trusted_baseline": None},
    ):
        client = _Client()
        with pytest.raises(WriteSpecDispatchError):
            run_test_calendar_write(
                run_spec,
                bundle.target,
                client,
                challenge,
                current_snapshot_hash=run_spec.current_snapshot_hash,
                current_plan_hash=run_spec.single_update_plan_hash,
                current_baseline_hash=run_spec.trusted_baseline_hash,
                sleep=lambda _delay: None,
                jitter=lambda _maximum: 0.0,
                **kwargs,
            )
        assert client.calls == []


def test_alternate_valid_snapshot_binding_stops_before_approval_or_client(
    tmp_path: Path,
) -> None:
    bundle, run_spec, challenge = _prepared(tmp_path)
    alternate = build_single_update_prewrite_snapshot(
        bundle.target,
        etag="fixture-etag-client-zero-alternate",
    )
    provisional = run_spec.model_copy(
        update={
            "baseline_snapshot_hash": alternate.snapshot_content_hash,
            "current_snapshot_hash": alternate.snapshot_content_hash,
            "run_spec_content_hash": "0" * 64,
        }
    )
    forged = provisional.model_copy(
        update={"run_spec_content_hash": calculate_test_single_update_run_spec_hash(provisional)}
    )
    client = _Client()

    with pytest.raises(SingleUpdateRunSpecError) as captured:
        _run(bundle, forged, client, challenge)
    assert captured.value.code == "trusted_baseline_snapshot_mismatch"
    assert client.calls == []


def test_production_reference_stops_before_client_touch(tmp_path: Path) -> None:
    bundle, run_spec, challenge = _prepared(tmp_path)
    production = run_spec.model_copy(update={"target_safe_ref": PRODUCTION_TARGET_REFERENCE})
    client = _Client()

    with pytest.raises(SingleUpdateRunSpecError):
        _run(bundle, production, client, challenge)
    assert client.calls == []


def test_fresh_etag_mismatch_stops_before_patch(tmp_path: Path) -> None:
    bundle, run_spec, challenge = _prepared(tmp_path)
    current = _raw_event(
        run_spec.operation.current_state,
        event_id=run_spec.operation.google_event_id,
        etag=run_spec.operation.expected_etag,
    )
    changed = _raw_event(
        run_spec.operation.current_state,
        event_id=run_spec.operation.google_event_id,
        etag="fixture-etag-concurrent-change",
    )
    client = _Client(list_queue=[_page([current])], get_queue=[changed])

    result = _run(bundle, run_spec, client, challenge)

    assert result.state is ExecutionState.ETAG_CONFLICT
    assert result.mutation_attempt_count == 0
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls] == ["list", "get"]


def test_uncertain_patch_recovers_by_read_without_second_patch(tmp_path: Path) -> None:
    bundle, run_spec, challenge = _prepared(tmp_path)
    current = _raw_event(
        run_spec.operation.current_state,
        event_id=run_spec.operation.google_event_id,
        etag=run_spec.operation.expected_etag,
    )
    desired = _raw_event(
        run_spec.operation.desired_state,
        event_id=run_spec.operation.google_event_id,
        etag="fixture-etag-recovered",
    )
    client = _Client(
        list_queue=[_page([current])],
        get_queue=[current, desired],
        patch_queue=[_retryable("events.patch")],
    )

    result = _run(bundle, run_spec, client, challenge)

    assert result.success is True
    assert result.recovered_after_uncertain is True
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls].count("patch") == 1


def test_uncertain_mismatch_stops_without_second_patch(tmp_path: Path) -> None:
    bundle, run_spec, challenge = _prepared(tmp_path)
    current = _raw_event(
        run_spec.operation.current_state,
        event_id=run_spec.operation.google_event_id,
        etag=run_spec.operation.expected_etag,
    )
    client = _Client(
        list_queue=[_page([current])],
        get_queue=[current, current],
        patch_queue=[_retryable("events.patch")],
    )

    result = _run(bundle, run_spec, client, challenge)

    assert result.state is ExecutionState.UNCERTAIN
    assert result.success is False
    assert result.mutation_attempt_count == 1
    assert result.mutation_retry_count == 0
    assert [name for name, _values in client.calls].count("patch") == 1
