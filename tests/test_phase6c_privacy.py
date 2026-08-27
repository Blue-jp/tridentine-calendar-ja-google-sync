from __future__ import annotations

import ast
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from tridentine_calendar_google_sync.production_execution_journal import (
    ProductionExecutionJournal,
    append_production_execution_journal_entry,
    initialize_production_execution_journal,
    render_production_execution_journal_json,
)
from tridentine_calendar_google_sync.production_execution_journal import (
    ProductionExecutionJournalEntryStatus as EntryStatus,
)
from tridentine_calendar_google_sync.production_execution_journal import (
    ProductionExecutionJournalPhase as Phase,
)
from tridentine_calendar_google_sync.production_execution_journal import (
    ProductionExecutionJournalState as JournalState,
)
from tridentine_calendar_google_sync.production_execution_report import (
    ProductionExecutionReport,
    build_production_execution_report_from_journal,
    render_production_execution_report_json,
    render_production_execution_report_text,
)

START = datetime(2026, 8, 27, tzinfo=UTC)


def _failed_journal() -> ProductionExecutionJournal:
    journal = initialize_production_execution_journal(
        target_safe_ref="T-123456789abc",
        run_spec_ref="R-23456789abcd",
        plan_ref="P-3456789abcde",
        approval_material_hash="a" * 64,
        execute_permit_hash="b" * 64,
        patch_hash="c" * 64,
        started_at=START,
    )
    steps = (
        (Phase.RUN_START, EntryStatus.STARTED, False),
        (Phase.APPROVAL_VALIDATED, EntryStatus.VALIDATED, False),
        (Phase.EXECUTE_PERMIT_CONSUMED, EntryStatus.CONSUMED, True),
        (Phase.KILL_SWITCH_VERIFIED, EntryStatus.VERIFIED, True),
    )
    for second, (phase, status, consumed) in enumerate(steps, start=1):
        journal = append_production_execution_journal_entry(
            journal,
            timestamp=START + timedelta(seconds=second),
            phase=phase,
            status=status,
            api_call_count=0,
            read_retry_count=0,
            mutation_attempt_count=0,
            approval_consumed=consumed,
            kill_switch_generation=1,
            write_token_generation=1,
        )
    return append_production_execution_journal_entry(
        journal,
        timestamp=START + timedelta(seconds=5),
        phase=Phase.TERMINAL_RESULT,
        status=EntryStatus.FAILED,
        safe_code="production_kill_switch_off",
        api_call_count=0,
        read_retry_count=0,
        mutation_attempt_count=0,
        approval_consumed=True,
        kill_switch_generation=1,
        write_token_generation=1,
        terminal_state=JournalState.FAILED_KILL_SWITCH,
    )


def test_journal_and_report_expose_only_safe_refs_hashes_counts_and_codes() -> None:
    journal = _failed_journal()
    report = build_production_execution_report_from_journal(
        journal,
        safe_findings=("production_kill_switch_off",),
    )
    rendered = "\n".join(
        (
            render_production_execution_journal_json(journal),
            render_production_execution_report_json(report, journal),
            render_production_execution_report_text(report, journal),
            repr(journal),
            repr(report),
        )
    )
    lowered = rendered.casefold()
    forbidden_field_names = (
        "calendar_id",
        "raw_uid",
        "event_id",
        "etag",
        "summary",
        "description_value",
        "token_path",
        "token_value",
        "credentials",
        "authorization",
        "request_url",
        "request_body",
        "payload",
        "absolute_path",
    )
    assert all(field not in lowered for field in forbidden_field_names)

    forbidden_values = (
        "private-calendar-id@example.com",
        "raw-uid@private.example",
        "google-event-private-id",
        '"private-etag"',
        "private summary",
        "private description",
        "secret-token-value",
        "c:" + "\\users\\private\\artifact.json",
        "https://www.googleapis.com/calendar/v3/private",
    )
    assert all(value.casefold() not in lowered for value in forbidden_values)


@pytest.mark.parametrize(
    "forbidden_field",
    (
        "calendar_id",
        "uid",
        "event_id",
        "etag",
        "summary",
        "description",
        "token",
        "credentials",
        "path",
        "url",
    ),
)
def test_closed_report_model_rejects_private_extra_fields(forbidden_field: str) -> None:
    journal = _failed_journal()
    report = build_production_execution_report_from_journal(journal)
    data = report.model_dump(mode="python")
    data[forbidden_field] = "private"
    with pytest.raises(ValidationError):
        ProductionExecutionReport.model_validate(data, strict=True)


def test_lower_snake_private_finding_injection_is_rejected_without_echo() -> None:
    journal = _failed_journal()
    report = build_production_execution_report_from_journal(journal)
    document = report.model_dump(mode="python")
    private_value = "private_personal_value"
    document["safe_findings"] = (private_value,)
    with pytest.raises(ValidationError) as captured:
        ProductionExecutionReport.model_validate(document, strict=True)
    assert private_value not in str(captured.value)


def test_new_journal_and_report_modules_have_no_google_sdk_or_network_imports() -> None:
    root = Path(__file__).parents[1] / "src" / "tridentine_calendar_google_sync"
    for filename in (
        "production_approval_state.py",
        "production_approval_state_io.py",
        "production_approval_state_models.py",
        "production_execution_journal.py",
        "production_execution_report.py",
        "production_fake_transport.py",
        "production_transport.py",
        "production_transport_models.py",
    ):
        tree = ast.parse((root / filename).read_text(encoding="utf-8"))
        imports = {
            alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.Import)
            for alias in node.names
        } | {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        assert not any(
            name.startswith(
                (
                    "google",
                    "googleapiclient",
                    "requests",
                    "httpx",
                    "urllib",
                    "socket",
                )
            )
            for name in imports
        )


def test_phase6c_artifact_schemas_have_no_raw_identity_content_or_secret_fields() -> None:
    schema_root = Path(__file__).parents[1] / "schemas"
    names = (
        "production-arm-receipt-v1.schema.json",
        "production-execute-permit-consumption-v1.schema.json",
        "production-execute-permit-v1.schema.json",
        "production-kill-switch-v1.schema.json",
        "production-single-update-execution-journal-v1.schema.json",
        "production-single-update-execution-report-v1.schema.json",
    )
    forbidden_keys = {
        "calendar_id",
        "raw_uid",
        "uid",
        "event_id",
        "etag",
        "summary",
        "description",
        "token",
        "token_path",
        "token_value",
        "credentials",
        "authorization",
        "request_url",
        "request_body",
        "payload",
        "absolute_path",
    }

    def keys(value: object) -> set[str]:
        if isinstance(value, dict):
            return set(value) | set().union(*(keys(item) for item in value.values()))
        if isinstance(value, list):
            return set().union(*(keys(item) for item in value))
        return set()

    for name in names:
        document = json.loads((schema_root / name).read_text(encoding="utf-8"))
        assert forbidden_keys.isdisjoint(keys(document))


def test_phase6c_document_locks_static_dynamic_and_fail_closed_traceability() -> None:
    document = (
        Path(__file__).parents[1] / "docs" / "production-single-update-transport-foundation.md"
    ).read_text(encoding="utf-8")
    static_invariants = (
        "PATCH only",
        "Add / Delete unavailable",
        "One mutation",
        "Mutation retry 0",
        "Exact `If-Match`",
        "Fresh get",
        "Pre-write full snapshot",
        "Post-write full snapshot",
        "Approval consumption",
        "Kill-switch generation",
        "Token generation",
        "API hard cap",
        "Journal integrity",
        "Live hard-off",
    )
    fail_closed_conditions = (
        "Approval mismatch",
        "Approval replay",
        "Expired approval",
        "Switch off",
        "Switch generation mismatch",
        "Token generation mismatch",
        "Pre-snapshot drift",
        "Incomplete snapshot",
        "Target mismatch",
        "Pre-image mismatch",
        "ETag missing/mismatch",
        "HTTP 412",
        "Patch failure",
        "Uncertain outcome",
        "Read-back mismatch",
        "Post-snapshot drift",
        "Zero-diff failure",
        "API budget exceeded",
        "Journal tamper or append failure",
    )
    assert len(static_invariants) == 14
    assert all(f"| {name} |" in document for name in static_invariants)
    assert all(f"| {index}. " in document for index in range(1, 16))
    assert len(fail_closed_conditions) == 19
    assert all(f"| {name} |" in document for name in fail_closed_conditions)
    assert "The following remain dynamic Phase 6D/6E gates:" in document
    assert "append or fsync failure is itself fail closed" in document
    assert "append-failure tests" in document
