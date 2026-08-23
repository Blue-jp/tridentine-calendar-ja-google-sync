from __future__ import annotations

import json
from pathlib import Path

from conftest import REPOSITORY_ROOT
from jsonschema import Draft202012Validator
from phase4b_helpers import approved_bundle, build_multi_apply_bundle, build_update_apply_bundle

from tridentine_calendar_google_sync.apply_report import (
    build_apply_bundle_json_report,
    build_apply_json_report,
    build_operation_journal_json_report,
    render_apply_bundle_json_report,
    render_apply_bundle_text_report,
    render_apply_json_report,
    render_apply_text_report,
    render_operation_journal_json_report,
    render_operation_journal_text_report,
)
from tridentine_calendar_google_sync.apply_simulation import run_apply_simulation
from tridentine_calendar_google_sync.fake_mutation_transport import FakeMutationTransport
from tridentine_calendar_google_sync.retry_policy import SimulationOutcomeKind


def _schema() -> dict[str, object]:
    return json.loads(
        (REPOSITORY_ROOT / "schemas" / "apply-report-v1.schema.json").read_text(encoding="utf-8")
    )


def test_bundle_simulation_and_journal_public_reports_validate_closed_schema(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    value = build_update_apply_bundle(tmp_path, synthetic_profile_factory)
    approved = approved_bundle(value)
    result = run_apply_simulation(approved, FakeMutationTransport.from_bundle(approved))
    reports = (
        build_apply_bundle_json_report(approved),
        build_apply_json_report(result),
        build_operation_journal_json_report(result.journal),
    )
    validator = Draft202012Validator(_schema())

    for report in reports:
        validator.validate(report)


def test_public_reports_are_deterministic_and_contain_only_safe_references(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    value = build_update_apply_bundle(tmp_path, synthetic_profile_factory)
    approved = approved_bundle(value)
    result = run_apply_simulation(approved, FakeMutationTransport.from_bundle(approved))
    reports = (
        render_apply_bundle_json_report(approved),
        render_apply_bundle_text_report(approved),
        render_apply_json_report(result),
        render_apply_text_report(result),
        render_operation_journal_json_report(result.journal),
        render_operation_journal_text_report(result.journal),
    )
    operation = approved.operations[0]
    raw_values = (
        operation.source_uid,
        operation.payload.event_id,  # type: ignore[union-attr]
        operation.payload.etag,  # type: ignore[union-attr]
        value.source.events[0].summary,
        value.source.events[0].description,
    )

    assert render_apply_json_report(result) == render_apply_json_report(result)
    for report in reports:
        for value_text in raw_values:
            if value_text:
                assert value_text not in report
        for forbidden in (
            '"payload"',
            '"event_id"',
            '"etag"',
            '"calendar_id"',
            '"method"',
            '"endpoint"',
            '"authorization"',
            '"if_match"',
        ):
            assert forbidden not in report
    assert "P-" in reports[0]
    assert "B-" in reports[0]
    assert "T-" in reports[0]


def test_partial_failure_report_exposes_counts_stop_and_no_rollback_only(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    value = build_multi_apply_bundle(tmp_path, synthetic_profile_factory)
    approved = approved_bundle(value)
    failed = approved.operations[1]
    transport = FakeMutationTransport.from_bundle(
        approved,
        injected_outcomes={
            failed.operation_integrity_hash: (SimulationOutcomeKind.PERMISSION_DENIED,)
        },
    )

    result = run_apply_simulation(approved, transport)
    report = build_apply_json_report(result)

    assert report["simulation_state"] == "partial_failure"
    assert report["executable"] is False
    assert report["rollback_available"] is False
    assert report["partial_results"] is True
    assert report["stopped_early"] is True
    assert report["fatal_guard"] is True
    assert report["result_counts"] == {
        "attempted": 2,
        "succeeded": 1,
        "failed": 1,
        "uncertain": 0,
        "etag_conflict": 0,
        "skipped": 1,
        "retries": 0,
    }
    assert report["journal_integrity"] == "verified"
