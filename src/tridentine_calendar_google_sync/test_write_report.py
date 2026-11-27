"""Deterministic public-safe report for one Test Calendar write run."""

from __future__ import annotations

import hashlib
import hmac
import json

from tridentine_calendar_google_sync.test_write_journal import (
    TestWriteJournal,
    verify_test_write_journal,
)
from tridentine_calendar_google_sync.test_write_transport import (
    TestWriteExecutionResult,
    TestWriteTransportError,
    verify_test_write_execution_result,
)


def _report_hash(data: dict[str, object]) -> str:
    tags = (data.get("schema_version"), data.get("report_type"))
    if tags == ("1.0", "test-calendar-write-report-v1"):
        domain = b"tridentine-calendar-google-sync:test-write-report:v1\x00"
    elif tags == ("2.0", "test-calendar-write-report-v2"):
        domain = b"tridentine-calendar-google-sync:test-write-report:v2\x00"
    else:
        raise TestWriteTransportError("test_write_report_invalid", "Unsupported Test write report")
    encoded = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def build_test_write_json_report(result: TestWriteExecutionResult) -> dict[str, object]:
    """Build a report containing safe references, counters, and hashes only."""

    verify_test_write_execution_result(result)
    data: dict[str, object] = {
        "schema_version": result.schema_version,
        "report_type": (
            "test-calendar-write-report-v2"
            if result.schema_version == "2.0"
            else "test-calendar-write-report-v1"
        ),
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


def verify_test_write_json_report(document: dict[str, object], journal: TestWriteJournal) -> None:
    """Verify a decoded report with its independently loaded journal, including all three hashes."""

    verify_test_write_journal(journal)
    fields = dict(document)
    try:
        recorded = fields.pop("report_content_hash")
        actual = _report_hash(fields)
        if (
            not isinstance(recorded, str)
            or not hmac.compare_digest(actual, recorded)
            or fields["schema_version"] != journal.schema_version
            or fields.pop("journal_hash") != journal.journal_content_hash
        ):
            raise ValueError
        # Invert the report projection and validate the result whose digest it cites.
        fields.pop("report_type")
        fields["result_type"] = (
            "test-calendar-write-result-v2"
            if journal.schema_version == "2.0"
            else "test-calendar-write-result-v1"
        )
        fields["result_content_hash"] = fields.pop("result_hash")
        fields["journal"] = journal.model_dump(mode="json")
        result = TestWriteExecutionResult.model_validate_json(json.dumps(fields, allow_nan=False))
        expected = build_test_write_json_report(result)
        if expected["report_content_hash"] != actual:
            raise ValueError
    except (KeyError, TypeError, ValueError):
        raise TestWriteTransportError(
            "test_write_report_invalid", "Test write report integrity or journal binding is invalid"
        ) from None


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
        "Test Calendar write report (v2)"
        if result.schema_version == "2.0"
        else "Test Calendar write report",
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
    "verify_test_write_json_report",
]
