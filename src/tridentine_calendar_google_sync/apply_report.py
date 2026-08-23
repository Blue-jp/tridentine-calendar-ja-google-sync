"""Deterministic public reports for bundle inspection and fake simulation."""

from __future__ import annotations

import hashlib
import json

from tridentine_calendar_google_sync.apply_bundle import verify_apply_bundle_integrity
from tridentine_calendar_google_sync.apply_models import (
    ApplyBundle,
    ApplyBundleState,
)
from tridentine_calendar_google_sync.apply_simulation import (
    ApplySimulationResult,
    ApplySimulationState,
    SimulatedOperationResult,
    verify_apply_simulation_result,
)
from tridentine_calendar_google_sync.operation_journal import (
    JournalEntryStatus,
    OperationJournal,
    verify_operation_journal,
)

_SIMULATION_REPORT_HASH_DOMAIN = b"tridentine-calendar-google-sync:fake-apply-report:v1\x00"
_BUNDLE_REPORT_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:apply-bundle-inspection-report:v1\x00"
)
_JOURNAL_REPORT_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:operation-journal-inspection-report:v1\x00"
)


def _safe_hash_reference(prefix: str, value: str) -> str:
    return f"{prefix}-{value[:12]}"


def _report_hash(domain: bytes, data: dict[str, object]) -> str:
    encoded = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def _operation_result_data(result: SimulatedOperationResult) -> dict[str, object]:
    return {
        "operation_index": result.operation_index,
        "operation": result.operation.value,
        "source_ref": result.source_ref,
        "google_ref": result.google_ref,
        "status": result.status.value,
        "attempts": result.attempts,
        "retry_count": result.retry_count,
        "outcome_code": result.outcome_code,
    }


def build_apply_json_report(result: ApplySimulationResult) -> dict[str, object]:
    """Build a public simulation report with no raw or full internal hash values."""

    verify_apply_simulation_result(result)
    data: dict[str, object] = {
        "schema_version": result.schema_version,
        "report_type": "offline-apply-simulation-report-v1",
        "mode": "offline simulation",
        "environment": result.environment.value,
        "source_profile": result.source_profile,
        "target_reference": result.target_reference,
        "plan_reference": _safe_hash_reference("P", result.plan_content_hash),
        "bundle_reference": _safe_hash_reference("B", result.bundle_integrity_hash),
        "approval_state": result.approval_state,
        "simulation_state": result.state.value,
        "executable": False,
        "rollback_available": False,
        "operation_counts": {
            "total": result.total_operation_count,
            "add": result.add_count,
            "update": result.update_count,
            "delete": result.delete_count,
        },
        "result_counts": {
            "attempted": result.attempted_operation_count,
            "succeeded": result.succeeded_count,
            "failed": result.failed_count,
            "uncertain": result.uncertain_count,
            "etag_conflict": result.etag_conflict_count,
            "skipped": result.skipped_count,
            "retries": result.retry_count,
        },
        "partial_results": result.partial_results,
        "stopped_early": result.state is not ApplySimulationState.COMPLETED,
        "journal_integrity": "verified",
        "fatal_guard": result.state is not ApplySimulationState.COMPLETED,
        "operation_results": [
            _operation_result_data(operation_result)
            for operation_result in result.operation_results
        ],
    }
    return {**data, "report_hash": _report_hash(_SIMULATION_REPORT_HASH_DOMAIN, data)}


def render_apply_json_report(result: ApplySimulationResult) -> str:
    """Render deterministic public simulation JSON with a final newline."""

    return (
        json.dumps(
            build_apply_json_report(result),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def render_apply_text_report(result: ApplySimulationResult) -> str:
    """Render a compact public simulation report using safe references only."""

    report = build_apply_json_report(result)
    operation_counts = report["operation_counts"]
    result_counts = report["result_counts"]
    assert isinstance(operation_counts, dict)
    assert isinstance(result_counts, dict)
    lines = [
        "Offline fake apply simulation report",
        "mode: offline simulation",
        f"environment: {report['environment']}",
        f"source profile: {report['source_profile']}",
        f"target reference: {report['target_reference']}",
        f"plan reference: {report['plan_reference']}",
        f"bundle reference: {report['bundle_reference']}",
        f"approval state: {report['approval_state']}",
        f"simulation state: {report['simulation_state']}",
        "executable: no",
        "rollback available: no",
        f"total operations: {operation_counts['total']}",
        f"add operations: {operation_counts['add']}",
        f"update operations: {operation_counts['update']}",
        f"delete operations: {operation_counts['delete']}",
        f"attempted operations: {result_counts['attempted']}",
        f"succeeded: {result_counts['succeeded']}",
        f"failed: {result_counts['failed']}",
        f"uncertain: {result_counts['uncertain']}",
        f"ETag conflicts: {result_counts['etag_conflict']}",
        f"skipped: {result_counts['skipped']}",
        f"retries: {result_counts['retries']}",
        f"partial results: {'yes' if report['partial_results'] else 'no'}",
        f"stopped early: {'yes' if report['stopped_early'] else 'no'}",
        f"journal integrity: {report['journal_integrity']}",
        f"fatal guard: {'yes' if report['fatal_guard'] else 'no'}",
    ]
    if result.operation_results:
        lines.append("operation results:")
        for operation_result in result.operation_results:
            references = ",".join(
                value
                for value in (operation_result.source_ref, operation_result.google_ref)
                if value is not None
            )
            lines.append(
                f"- {operation_result.operation_index} {operation_result.operation.value} "
                f"refs={references}; status={operation_result.status.value}; "
                f"attempts={operation_result.attempts}; "
                f"retries={operation_result.retry_count}; "
                f"outcome={operation_result.outcome_code}"
            )
    lines.append(f"report hash: {report['report_hash']}")
    return "\n".join(lines) + "\n"


def build_apply_bundle_json_report(bundle: ApplyBundle) -> dict[str, object]:
    """Build a public integrity-checked bundle inspection document."""

    verify_apply_bundle_integrity(bundle)
    data: dict[str, object] = {
        "schema_version": bundle.schema_version,
        "report_type": "apply-bundle-inspection-report-v1",
        "mode": "bundle inspection",
        "environment": bundle.environment.value,
        "source_profile": bundle.source_profile,
        "state": bundle.state.value,
        "target_reference": bundle.target_reference,
        "plan_reference": _safe_hash_reference("P", bundle.plan_content_hash),
        "bundle_reference": _safe_hash_reference("B", bundle.bundle_integrity_hash),
        "operation_counts": {
            "total": bundle.generated_operation_count,
            "add": bundle.add_count,
            "update": bundle.update_count,
            "delete": bundle.delete_count,
        },
        "approval_required": bundle.state is ApplyBundleState.APPROVAL_REQUIRED,
        "approved_for_simulation": (bundle.state is ApplyBundleState.APPROVED_FOR_SIMULATION),
        "execution_enabled": bundle.execution_enabled,
        "production_locked": bundle.production_locked,
        "integrity": "verified",
    }
    return {**data, "report_hash": _report_hash(_BUNDLE_REPORT_HASH_DOMAIN, data)}


def render_apply_bundle_json_report(bundle: ApplyBundle) -> str:
    """Render deterministic public bundle inspection JSON."""

    return (
        json.dumps(
            build_apply_bundle_json_report(bundle),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def render_apply_bundle_text_report(bundle: ApplyBundle) -> str:
    """Render a compact public bundle inspection report."""

    report = build_apply_bundle_json_report(bundle)
    counts = report["operation_counts"]
    assert isinstance(counts, dict)
    return "\n".join(
        (
            "Apply bundle inspection report",
            "mode: bundle inspection",
            f"environment: {report['environment']}",
            f"source profile: {report['source_profile']}",
            f"state: {report['state']}",
            f"target reference: {report['target_reference']}",
            f"plan reference: {report['plan_reference']}",
            f"bundle reference: {report['bundle_reference']}",
            f"total operations: {counts['total']}",
            f"add operations: {counts['add']}",
            f"update operations: {counts['update']}",
            f"delete operations: {counts['delete']}",
            f"approval required: {'yes' if report['approval_required'] else 'no'}",
            f"approved for simulation: {'yes' if report['approved_for_simulation'] else 'no'}",
            f"execution enabled: {'yes' if report['execution_enabled'] else 'no'}",
            f"Production locked: {'yes' if report['production_locked'] else 'no'}",
            f"integrity: {report['integrity']}",
            f"report hash: {report['report_hash']}",
            "",
        )
    )


def build_operation_journal_json_report(journal: OperationJournal) -> dict[str, object]:
    """Build a public integrity-checked journal inspection document."""

    verify_operation_journal(journal)
    data: dict[str, object] = {
        "schema_version": journal.schema_version,
        "report_type": "operation-journal-inspection-report-v1",
        "mode": "journal inspection",
        "state": journal.state.value,
        "start_marker": journal.start_marker,
        "completion_marker": journal.completion_marker,
        "target_reference": journal.target_reference,
        "plan_reference": _safe_hash_reference("P", journal.plan_content_hash),
        "bundle_reference": _safe_hash_reference("B", journal.bundle_integrity_hash),
        "entry_count": journal.entry_count,
        "operation_count": journal.operation_count,
        "status_counts": {
            status.value: sum(entry.status is status for entry in journal.entries)
            for status in JournalEntryStatus
        },
        "mutation_mode": journal.mutation_mode,
        "rollback_available": journal.rollback_available,
        "journal_integrity": "verified",
    }
    return {**data, "report_hash": _report_hash(_JOURNAL_REPORT_HASH_DOMAIN, data)}


def render_operation_journal_json_report(journal: OperationJournal) -> str:
    """Render deterministic public journal inspection JSON."""

    return (
        json.dumps(
            build_operation_journal_json_report(journal),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def render_operation_journal_text_report(journal: OperationJournal) -> str:
    """Render a compact public journal inspection report."""

    report = build_operation_journal_json_report(journal)
    status_counts = report["status_counts"]
    assert isinstance(status_counts, dict)
    lines = [
        "Operation journal inspection report",
        "mode: journal inspection",
        f"state: {report['state']}",
        f"start marker: {report['start_marker']}",
        f"completion marker: {report['completion_marker'] or 'none'}",
        f"target reference: {report['target_reference']}",
        f"plan reference: {report['plan_reference']}",
        f"bundle reference: {report['bundle_reference']}",
        f"entry count: {report['entry_count']}",
        f"operation count: {report['operation_count']}",
    ]
    lines.extend(f"{status}: {count}" for status, count in status_counts.items())
    lines.extend(
        (
            f"mutation mode: {report['mutation_mode']}",
            "rollback available: no",
            f"journal integrity: {report['journal_integrity']}",
            f"report hash: {report['report_hash']}",
        )
    )
    return "\n".join(lines) + "\n"


__all__ = [
    "build_apply_bundle_json_report",
    "build_apply_json_report",
    "build_operation_journal_json_report",
    "render_apply_bundle_json_report",
    "render_apply_bundle_text_report",
    "render_apply_json_report",
    "render_apply_text_report",
    "render_operation_journal_json_report",
    "render_operation_journal_text_report",
]
