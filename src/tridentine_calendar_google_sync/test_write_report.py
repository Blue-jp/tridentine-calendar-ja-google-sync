"""Deterministic public-safe report for one Test Calendar write run."""

from __future__ import annotations

import hashlib
import json

from tridentine_calendar_google_sync.test_write_transport import (
    TestWriteExecutionResult,
    verify_test_write_execution_result,
)

_REPORT_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-write-report:v1\x00"


def _report_hash(data: dict[str, object]) -> str:
    encoded = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_REPORT_HASH_DOMAIN + encoded).hexdigest()


def build_test_write_json_report(result: TestWriteExecutionResult) -> dict[str, object]:
    """Build a report containing safe references, counters, and hashes only."""

    verify_test_write_execution_result(result)
    data: dict[str, object] = {
        "schema_version": "1.0",
        "report_type": "test-calendar-write-report-v1",
        "live_test_write": True,
        "test_only": True,
        "production_locked": True,
        "target_safe_ref": result.target_safe_ref,
        "run_spec_ref": result.run_spec_ref,
        "source_ref": result.source_ref,
        "operation": result.operation.value,
        "state": result.state.value,
        "success": result.success,
        "read_back_verified": result.read_back_verified,
        "recovered_after_uncertain": result.recovered_after_uncertain,
        "api_call_count": result.api_call_count,
        "read_retry_count": result.read_retry_count,
        "mutation_attempt_count": result.mutation_attempt_count,
        "mutation_retry_count": result.mutation_retry_count,
        "stopped": result.stopped,
        "safe_findings": list(result.safe_findings),
        "journal_hash": result.journal.journal_content_hash,
        "result_hash": result.result_content_hash,
    }
    return {**data, "report_content_hash": _report_hash(data)}


def render_test_write_json_report(result: TestWriteExecutionResult) -> str:
    """Render deterministic UTF-8 JSON with a final newline."""

    return (
        json.dumps(
            build_test_write_json_report(result),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def render_test_write_text_report(result: TestWriteExecutionResult) -> str:
    """Render safe human-readable status without event content or opaque IDs."""

    report = build_test_write_json_report(result)
    findings = report["safe_findings"]
    assert isinstance(findings, list)
    lines = [
        "Test Calendar write report",
        "mode: live Test Calendar write",
        "Test Calendar only: yes",
        "Production locked: yes",
        f"target reference: {report['target_safe_ref']}",
        f"Run Spec reference: {report['run_spec_ref']}",
        f"source reference: {report['source_ref']}",
        f"operation: {report['operation']}",
        f"state: {report['state']}",
        f"success: {'yes' if report['success'] else 'no'}",
        f"read-back verified: {'yes' if report['read_back_verified'] else 'no'}",
        (
            "recovered after uncertain outcome: "
            f"{'yes' if report['recovered_after_uncertain'] else 'no'}"
        ),
        f"API calls: {report['api_call_count']}",
        f"read retries: {report['read_retry_count']}",
        f"mutation attempts: {report['mutation_attempt_count']}",
        f"mutation retries: {report['mutation_retry_count']}",
        f"stopped: {'yes' if report['stopped'] else 'no'}",
        f"safe findings: {','.join(findings) if findings else 'none'}",
        f"journal hash: {report['journal_hash']}",
        f"result hash: {report['result_hash']}",
        f"report hash: {report['report_content_hash']}",
    ]
    return "\n".join(lines) + "\n"


__all__ = [
    "build_test_write_json_report",
    "render_test_write_json_report",
    "render_test_write_text_report",
]
