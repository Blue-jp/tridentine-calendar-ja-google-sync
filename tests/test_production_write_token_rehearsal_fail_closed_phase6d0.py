from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from phase6b_helpers import (
    PRODUCTION_LIKE_CURRENT_COMMIT,
    PRODUCTION_LIKE_CURRENT_TAG,
    PRODUCTION_LIKE_REPOSITORY,
    write_production_source,
)
from phase6d0_rehearsal_helpers import build_rehearsal_artifacts, run_rehearsal

from tridentine_calendar_google_sync.accepted_production_source_manifest import (
    build_accepted_production_source_manifest,
)
from tridentine_calendar_google_sync.baseline_engine import calculate_baseline_content_hash
from tridentine_calendar_google_sync.baseline_models import BaselineState
from tridentine_calendar_google_sync.production_write_token_rehearsal import (
    run_production_write_token_readonly_rehearsal_mock,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_models import (
    ProductionWriteTokenRehearsalResultState,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_report import (
    ProductionWriteTokenRehearsalReportError,
    verify_production_write_token_rehearsal_report,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_transport import (
    FakeProductionWriteTokenReadOnlyTransport,
    FakeProductionWriteTokenReadOnlyTransportProvider,
    ProductionWriteTokenRehearsalTransportError,
    paginate_production_write_token_rehearsal_snapshot,
)

pytestmark = pytest.mark.google_production_write


def _run_with_inputs(artifacts, **changes):
    inputs = artifacts.inputs
    values = {
        "credential_session_provider": artifacts.credential_provider,
        "transport_provider": artifacts.transport_provider,
        "target": inputs.target,
        "manifest": inputs.manifest,
        "accepted_profile": inputs.updated.profile,
        "accepted_source": inputs.updated.source,
        "trusted_baseline": inputs.baseline,
        "confirmation": artifacts.confirmation,
    }
    transport = changes.pop("transport", None)
    if transport is not None:
        values["transport_provider"] = FakeProductionWriteTokenReadOnlyTransportProvider(transport)
    values.update(changes)
    return run_production_write_token_readonly_rehearsal_mock(**values)


def _rehash_baseline(baseline, **changes):
    provisional = baseline.model_copy(update={**changes, "baseline_content_hash": "0" * 64})
    return provisional.model_copy(
        update={"baseline_content_hash": calculate_baseline_content_hash(provisional)}
    )


@pytest.mark.parametrize(
    "baseline_change",
    [
        {"state": BaselineState.CANDIDATE},
        {"target_fingerprint": "f" * 64},
        {"accepted_tag": "test-baseline"},
    ],
)
def test_nontrusted_or_nonproduction_baseline_stops_before_list(
    tmp_path: Path,
    baseline_change: dict[str, object],
) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    baseline = _rehash_baseline(artifacts.inputs.baseline, **baseline_change)
    outcome = _run_with_inputs(artifacts, trusted_baseline=baseline)
    assert outcome.report.calendar_api_call_count == 0
    assert outcome.report.result_state is not ProductionWriteTokenRehearsalResultState.READY


def test_manifest_tamper_and_test_source_stop_before_list(tmp_path: Path) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    tampered = artifacts.inputs.manifest.model_copy(update={"event_count": 999})
    tampered_result = _run_with_inputs(artifacts, manifest=tampered)
    assert tampered_result.report.calendar_api_call_count == 0

    unsafe_profile = artifacts.inputs.updated.profile.model_copy(
        update={"project_name": "Synthetic Test Production source"}
    )
    unsafe_result = _run_with_inputs(artifacts, accepted_profile=unsafe_profile)
    assert unsafe_result.report.calendar_api_call_count == 0


@pytest.mark.parametrize(
    "baseline_change",
    [
        {"source_profile": "accepted-other-profile"},
        {"accepted_tag": "accepted-other-tag"},
        {"accepted_commit": "9" * 40},
        {"source_sha256": "8" * 64},
        {"source_event_count": 5},
    ],
)
def test_rehashed_production_like_baseline_provenance_mismatch_stops_before_list(
    tmp_path: Path,
    baseline_change: dict[str, object],
) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    baseline = _rehash_baseline(artifacts.inputs.baseline, **baseline_change)
    outcome = _run_with_inputs(artifacts, trusted_baseline=baseline)
    assert outcome.report.calendar_api_call_count == 0
    assert outcome.report.result_state is not ProductionWriteTokenRehearsalResultState.READY


def test_rehashed_baseline_diff_binding_mismatch_stops_before_get(tmp_path: Path) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    baseline = _rehash_baseline(
        artifacts.inputs.baseline,
        diff_content_hash="7" * 64,
    )
    outcome = _run_with_inputs(artifacts, trusted_baseline=baseline)
    assert outcome.report.list_call_count == 1
    assert outcome.report.get_call_count == 0
    assert outcome.report.result_state is not ProductionWriteTokenRehearsalResultState.READY


@pytest.mark.parametrize(
    "source_count",
    [5, 3],
)
def test_source_add_or_delete_provenance_mismatch_stops_before_list(
    tmp_path: Path, source_count: int
) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path / "base")
    source_fixture = write_production_source(
        tmp_path / "changed",
        "accepted",
        tuple(f"Current calendar description {index:06d}" for index in range(1, source_count + 1)),
        accepted_tag=PRODUCTION_LIKE_CURRENT_TAG,
        accepted_commit=PRODUCTION_LIKE_CURRENT_COMMIT,
    )
    manifest = build_accepted_production_source_manifest(
        source_fixture.profile,
        source_fixture.source,
        repository_identity=PRODUCTION_LIKE_REPOSITORY,
    )
    outcome = _run_with_inputs(
        artifacts,
        manifest=manifest,
        accepted_profile=source_fixture.profile,
        accepted_source=source_fixture.source,
    )
    assert outcome.report.result_state is not ProductionWriteTokenRehearsalResultState.READY
    assert outcome.report.calendar_api_call_count == 0
    assert outcome.report.get_call_count == 0


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("event_id", "different-memory-only-id"),
        ("all_day", False),
        ("start", {"date": date(2099, 12, 30), "date_time": None}),
        ("end", {"date": date(2099, 12, 31), "date_time": None}),
        ("color_id", "1"),
        ("event_label_id", "2"),
    ],
)
def test_additional_fresh_get_mismatches_fail_closed(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    selected = min(
        artifacts.inputs.snapshot.events,
        key=lambda event: (event.safe_ical_uid_reference or "", event.safe_event_reference),
    )
    changed = selected.model_copy(update={field: value})
    pages = paginate_production_write_token_rehearsal_snapshot(
        artifacts.inputs.snapshot,
        (4,),
        target_summary=artifacts.inputs.target.expected_summary,
    )
    transport = FakeProductionWriteTokenReadOnlyTransport(
        collections=(pages,),
        get_events=(changed,),
    )
    outcome = _run_with_inputs(artifacts, transport=transport)
    assert (
        outcome.report.result_state
        is ProductionWriteTokenRehearsalResultState.GET_VERIFICATION_FAILED
    )
    assert transport.mutation_raw_calls == 0


@pytest.mark.parametrize("code", ["permission_denied", "bad_request", "not_found", "gone"])
def test_nonretryable_read_failure_is_never_retried(tmp_path: Path, code: str) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    pages = paginate_production_write_token_rehearsal_snapshot(
        artifacts.inputs.snapshot,
        (4,),
        target_summary=artifacts.inputs.target.expected_summary,
    )
    failure = ProductionWriteTokenRehearsalTransportError(code)
    transport = FakeProductionWriteTokenReadOnlyTransport(
        collections=(pages,),
        get_events=(),
        list_failures={1: failure},
    )
    outcome = _run_with_inputs(artifacts, transport=transport)
    assert outcome.report.calendar_api_call_count == 1
    assert outcome.report.read_retry_count == 0
    assert transport.get_raw_calls == 0


def test_deterministic_selection_and_report_tamper_detection(tmp_path: Path) -> None:
    artifacts = build_rehearsal_artifacts(tmp_path)
    outcome = run_rehearsal(artifacts)
    expected = min(
        artifacts.inputs.snapshot.events,
        key=lambda event: (event.safe_ical_uid_reference or "", event.safe_event_reference),
    )
    assert outcome.report.selected_safe_uid_ref == expected.safe_ical_uid_reference
    assert outcome.snapshot is not None
    tampered = outcome.report.model_copy(update={"event_count": outcome.report.event_count + 1})
    with pytest.raises(ProductionWriteTokenRehearsalReportError):
        verify_production_write_token_rehearsal_report(tampered, outcome.snapshot)
