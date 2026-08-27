from __future__ import annotations

import json
import multiprocessing
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from jsonschema import (  # type: ignore[import-untyped]
    Draft202012Validator,
)
from jsonschema import (
    ValidationError as JsonSchemaValidationError,
)

from tridentine_calendar_google_sync.production_execution_journal import (
    PRODUCTION_EXECUTION_PHASE_ORDER,
    PRODUCTION_EXECUTION_SAFE_CODES,
    ProductionExecutionJournal,
    append_production_execution_journal_entry,
    append_production_execution_journal_file,
    calculate_production_execution_journal_hash,
    create_production_execution_journal_file,
    initialize_production_execution_journal,
    load_production_execution_journal_file,
    render_production_execution_journal_json,
    verify_production_execution_journal,
)
from tridentine_calendar_google_sync.production_execution_journal import (
    ProductionExecutionJournalEntryStatus as EntryStatus,
)
from tridentine_calendar_google_sync.production_execution_journal import (
    ProductionExecutionJournalError as JournalError,
)
from tridentine_calendar_google_sync.production_execution_journal import (
    ProductionExecutionJournalPhase as Phase,
)
from tridentine_calendar_google_sync.production_execution_journal import (
    ProductionExecutionJournalState as JournalState,
)
from tridentine_calendar_google_sync.production_execution_report import (
    ProductionExecutionReportError,
    build_production_execution_report,
    build_production_execution_report_from_journal,
    calculate_production_execution_report_hash,
    render_production_execution_report_json,
    render_production_execution_report_text,
    verify_production_execution_report,
)
from tridentine_calendar_google_sync.production_transport_models import (
    ProductionExecutionResultState,
    ProductionMockExecutionResult,
)

START = datetime(2026, 8, 27, 1, 2, 3, tzinfo=UTC)
HASH_A = "a" * 64
HASH_B = "b" * 64
HASH_C = "c" * 64


def _concurrent_append_worker(
    path: str,
    previous: ProductionExecutionJournal,
    updated: ProductionExecutionJournal,
    start_event: Any,
    result_queue: Any,
) -> None:
    if not start_event.wait(timeout=10):
        result_queue.put(("start_timeout", False))
        return
    try:
        append_production_execution_journal_file(path, previous, updated)
    except JournalError as exc:
        result_queue.put((exc.code, False))
    else:
        result_queue.put(("success", True))


def _crash_with_journal_lock(path: str) -> None:
    import tridentine_calendar_google_sync.production_execution_journal as module

    module._open_locked_journal(Path(path), exclusive=True)
    os._exit(0)


def _initial() -> ProductionExecutionJournal:
    return initialize_production_execution_journal(
        target_safe_ref="T-123456789abc",
        run_spec_ref="R-23456789abcd",
        plan_ref="P-3456789abcde",
        approval_material_hash=HASH_A,
        execute_permit_hash=HASH_B,
        patch_hash=HASH_C,
        started_at=START,
    )


def _success_steps() -> tuple[
    tuple[
        Phase,
        EntryStatus,
        int,
        int,
        int,
        bool,
        JournalState | None,
    ],
    ...,
]:
    return (
        (Phase.RUN_START, EntryStatus.STARTED, 0, 0, 0, False, None),
        (Phase.APPROVAL_VALIDATED, EntryStatus.VALIDATED, 0, 0, 0, False, None),
        (Phase.EXECUTE_PERMIT_CONSUMED, EntryStatus.CONSUMED, 0, 0, 0, True, None),
        (Phase.KILL_SWITCH_VERIFIED, EntryStatus.VERIFIED, 0, 0, 0, True, None),
        (Phase.PRE_SNAPSHOT_INTENT, EntryStatus.INTENT, 0, 0, 0, True, None),
        (Phase.PRE_SNAPSHOT_VERIFIED, EntryStatus.VERIFIED, 2, 0, 0, True, None),
        (Phase.FRESH_GET_INTENT, EntryStatus.INTENT, 2, 0, 0, True, None),
        (Phase.PRE_IMAGE_VERIFIED, EntryStatus.VERIFIED, 3, 0, 0, True, None),
        (Phase.MUTATION_INTENT, EntryStatus.INTENT, 3, 0, 1, True, None),
        (Phase.MUTATION_RESULT, EntryStatus.SUCCEEDED, 4, 0, 1, True, None),
        (Phase.READBACK_INTENT, EntryStatus.INTENT, 4, 0, 1, True, None),
        (Phase.READBACK_VERIFIED, EntryStatus.VERIFIED, 5, 0, 1, True, None),
        (Phase.POST_SNAPSHOT_INTENT, EntryStatus.INTENT, 5, 0, 1, True, None),
        (Phase.POST_SNAPSHOT_VERIFIED, EntryStatus.VERIFIED, 7, 0, 1, True, None),
        (Phase.ZERO_DIFF_VERIFIED, EntryStatus.VERIFIED, 7, 0, 1, True, None),
        (
            Phase.TERMINAL_RESULT,
            EntryStatus.SUCCEEDED,
            7,
            0,
            1,
            True,
            JournalState.SUCCEEDED,
        ),
    )


def _append_step(
    journal: ProductionExecutionJournal,
    step: tuple[Phase, EntryStatus, int, int, int, bool, JournalState | None],
    *,
    second: int,
) -> ProductionExecutionJournal:
    phase, status, calls, reads, mutations, consumed, terminal_state = step
    return append_production_execution_journal_entry(
        journal,
        timestamp=START + timedelta(seconds=second),
        phase=phase,
        status=status,
        api_call_count=calls,
        read_retry_count=reads,
        mutation_attempt_count=mutations,
        approval_consumed=consumed,
        kill_switch_generation=7,
        write_token_generation=9,
        terminal_state=terminal_state,
    )


def _success() -> ProductionExecutionJournal:
    journal = _initial()
    for second, step in enumerate(_success_steps(), start=1):
        journal = _append_step(journal, step, second=second)
    return journal


def _failure(
    *,
    state: JournalState = JournalState.FAILED_DRIFT,
    code: str = "production_full_snapshot_drift",
) -> ProductionExecutionJournal:
    journal = _initial()
    for second, step in enumerate(_success_steps()[:5], start=1):
        journal = _append_step(journal, step, second=second)
    return append_production_execution_journal_entry(
        journal,
        timestamp=START + timedelta(seconds=6),
        phase=Phase.TERMINAL_RESULT,
        status=EntryStatus.FAILED,
        safe_code=code,
        api_call_count=2,
        read_retry_count=0,
        mutation_attempt_count=0,
        approval_consumed=True,
        kill_switch_generation=7,
        write_token_generation=9,
        terminal_state=state,
    )


def test_success_journal_has_exact_write_ahead_lifecycle_and_hash_chain() -> None:
    journal = _success()
    verify_production_execution_journal(journal)

    assert tuple(entry.phase for entry in journal.entries) == PRODUCTION_EXECUTION_PHASE_ORDER
    assert journal.state is JournalState.SUCCEEDED
    assert journal.api_call_count == 7
    assert journal.mutation_attempt_count == 1
    assert journal.mutation_retry_count == 0
    assert journal.rollback_available is False
    assert journal.approval_consumed is True
    assert calculate_production_execution_journal_hash(journal) == journal.journal_content_hash
    assert all(entry.fsync_required for entry in journal.entries)
    assert next(
        entry.sequence for entry in journal.entries if entry.phase is Phase.MUTATION_INTENT
    ) < next(entry.sequence for entry in journal.entries if entry.phase is Phase.MUTATION_RESULT)
    assert next(
        entry.sequence for entry in journal.entries if entry.phase is Phase.EXECUTE_PERMIT_CONSUMED
    ) < next(
        entry.sequence for entry in journal.entries if entry.phase is Phase.PRE_SNAPSHOT_INTENT
    )


def test_journal_aggregate_json_matches_closed_schema() -> None:
    root = Path(__file__).parents[1]
    schema = json.loads(
        (root / "schemas" / "production-single-update-execution-journal-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    document = json.loads(render_production_execution_journal_json(_success()))
    Draft202012Validator(schema, format_checker=None).validate(document)

    report_schema = json.loads(
        (root / "schemas" / "production-single-update-execution-report-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    assert set(schema["$defs"]["safeCode"]["enum"]) == PRODUCTION_EXECUTION_SAFE_CODES
    assert set(report_schema["$defs"]["safeCode"]["enum"]) == (PRODUCTION_EXECUTION_SAFE_CODES)


def test_append_only_file_is_exclusive_durable_and_round_trips(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "production-execution-journal.ndjson"
    current = _initial()
    fsync_calls = 0
    real_fsync = os.fsync

    def spy_fsync(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        real_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", spy_fsync)
    create_production_execution_journal_file(path, current)
    with pytest.raises(JournalError) as duplicate:
        create_production_execution_journal_file(path, current)
    assert duplicate.value.code == "production_journal_create_failed"

    for second, step in enumerate(_success_steps(), start=1):
        updated = _append_step(current, step, second=second)
        append_production_execution_journal_file(path, current, updated)
        current = updated

    loaded = load_production_execution_journal_file(path)
    assert loaded == current
    assert fsync_calls >= len(_success_steps())
    assert path.read_bytes().count(b"\n") == len(_success_steps()) + 1


def test_append_rejects_stale_prefix_and_repository_path(tmp_path: Path) -> None:
    path = tmp_path / "journal.ndjson"
    initial = _initial()
    create_production_execution_journal_file(path, initial)
    first = _append_step(initial, _success_steps()[0], second=1)
    append_production_execution_journal_file(path, initial, first)
    with pytest.raises(JournalError) as stale:
        append_production_execution_journal_file(path, initial, first)
    assert stale.value.code == "production_journal_stale_append"

    repository_path = Path(__file__).parents[1] / ".unsafe-production-journal"
    with pytest.raises(JournalError) as unsafe:
        create_production_execution_journal_file(repository_path, initial)
    assert unsafe.value.code == "production_journal_create_failed"


def test_cross_process_mutation_intent_has_one_patch_winner_and_one_stale_loser(
    tmp_path: Path,
) -> None:
    path = tmp_path / "journal.ndjson"
    current = _initial()
    create_production_execution_journal_file(path, current)
    for second, step in enumerate(_success_steps()[:8], start=1):
        updated = _append_step(current, step, second=second)
        append_production_execution_journal_file(path, current, updated)
        current = updated
    previous = current
    updated = _append_step(previous, _success_steps()[8], second=9)
    assert updated.entries[-1].phase is Phase.MUTATION_INTENT
    context = multiprocessing.get_context("spawn")
    start_event = context.Event()
    result_queue = context.Queue()
    processes = tuple(
        context.Process(
            target=_concurrent_append_worker,
            args=(str(path), previous, updated, start_event, result_queue),
        )
        for _ in range(2)
    )
    for process in processes:
        process.start()
    start_event.set()
    for process in processes:
        process.join(timeout=20)
        assert process.exitcode == 0
    results = tuple(result_queue.get(timeout=5) for _ in processes)

    assert sorted(code for code, _proceed in results) == [
        "production_journal_stale_append",
        "success",
    ]
    assert sum(proceed for _code, proceed in results) == 1
    assert load_production_execution_journal_file(path, require_terminal=False) == updated


def test_crashed_process_lock_leaves_no_stale_lock_or_append_bypass(tmp_path: Path) -> None:
    path = tmp_path / "journal.ndjson"
    previous = _initial()
    updated = _append_step(previous, _success_steps()[0], second=1)
    create_production_execution_journal_file(path, previous)
    context = multiprocessing.get_context("spawn")
    process = context.Process(target=_crash_with_journal_lock, args=(str(path),))
    process.start()
    process.join(timeout=20)
    assert process.exitcode == 0

    append_production_execution_journal_file(path, previous, updated)
    assert load_production_execution_journal_file(path, require_terminal=False) == updated
    assert tuple(item.name for item in tmp_path.iterdir()) == ("journal.ndjson",)


def test_append_failure_after_durable_mutation_intent_never_forges_terminal_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "journal.ndjson"
    current = _initial()
    create_production_execution_journal_file(path, current)
    for second, step in enumerate(_success_steps()[:9], start=1):
        updated = _append_step(current, step, second=second)
        append_production_execution_journal_file(path, current, updated)
        current = updated
    assert current.entries[-1].phase is Phase.MUTATION_INTENT

    mutation_result = _append_step(current, _success_steps()[9], second=10)

    def fail_write(_descriptor: int, _content: bytes) -> int:
        raise OSError("synthetic durable append failure")

    monkeypatch.setattr(os, "write", fail_write)
    with pytest.raises(JournalError) as captured:
        append_production_execution_journal_file(path, current, mutation_result)
    assert captured.value.code == "production_journal_append_failed"
    assert str(path) not in str(captured.value)

    interrupted = load_production_execution_journal_file(path, require_terminal=False)
    assert interrupted == current
    assert interrupted.terminal is False
    with pytest.raises(JournalError) as terminal_missing:
        load_production_execution_journal_file(path)
    assert terminal_missing.value.code == "production_journal_terminal_missing"


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="symlinks unavailable")
def test_append_rejects_symlink_path(tmp_path: Path) -> None:
    real_path = tmp_path / "real.ndjson"
    link_path = tmp_path / "link.ndjson"
    initial = _initial()
    create_production_execution_journal_file(real_path, initial)
    try:
        link_path.symlink_to(real_path)
    except OSError:
        pytest.skip("symlink creation unavailable")
    first = _append_step(initial, _success_steps()[0], second=1)
    with pytest.raises(JournalError) as unsafe:
        append_production_execution_journal_file(link_path, initial, first)
    assert unsafe.value.code == "production_journal_append_path_unsafe"


@pytest.mark.parametrize("mode", ("tamper", "remove", "reorder", "truncate"))
def test_file_tamper_removed_middle_reorder_and_truncation_are_detected(
    tmp_path: Path,
    mode: str,
) -> None:
    path = tmp_path / "journal.ndjson"
    current = _initial()
    create_production_execution_journal_file(path, current)
    for second, step in enumerate(_success_steps(), start=1):
        updated = _append_step(current, step, second=second)
        append_production_execution_journal_file(path, current, updated)
        current = updated
    lines = path.read_bytes().splitlines(keepends=True)
    if mode == "tamper":
        lines[5] = lines[5].replace(b'"api_call_count":0', b'"api_call_count":1')
    elif mode == "remove":
        del lines[7]
    elif mode == "reorder":
        lines[8], lines[9] = lines[9], lines[8]
    else:
        lines[-1] = lines[-1][:-1]
    damaged = b"".join(lines)

    with pytest.raises(JournalError):
        load_production_execution_journal_file_bytes_for_test(damaged)


def test_header_is_hash_bound_to_first_entry_and_aggregate() -> None:
    journal = _success()
    tampered = journal.model_copy(
        update={
            "target_safe_ref": "T-ffffffffffff",
            "journal_content_hash": "0" * 64,
        }
    )
    tampered = tampered.model_copy(
        update={"journal_content_hash": calculate_production_execution_journal_hash(tampered)}
    )
    with pytest.raises(JournalError) as captured:
        verify_production_execution_journal(tampered)
    assert captured.value.code == "production_journal_header_hash_mismatch"


def test_append_only_file_rejects_validly_shaped_header_field_tamper(tmp_path: Path) -> None:
    path = tmp_path / "journal.ndjson"
    current = _initial()
    create_production_execution_journal_file(path, current)
    first = _append_step(current, _success_steps()[0], second=1)
    append_production_execution_journal_file(path, current, first)
    lines = path.read_bytes().splitlines(keepends=True)
    header = json.loads(lines[0])
    header["target_safe_ref"] = "T-ffffffffffff"
    lines[0] = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"

    with pytest.raises(JournalError):
        load_production_execution_journal_file_bytes_for_test(b"".join(lines))


def load_production_execution_journal_file_bytes_for_test(raw: bytes) -> Any:
    from tridentine_calendar_google_sync.production_execution_journal import (
        parse_production_execution_journal_file_bytes,
    )

    return parse_production_execution_journal_file_bytes(raw)


def test_rehashed_forged_success_without_required_phases_is_rejected() -> None:
    failed = _failure()
    forged = failed.model_copy(
        update={
            "state": JournalState.SUCCEEDED,
            "terminal": True,
            "journal_content_hash": "0" * 64,
        }
    )
    forged = forged.model_copy(
        update={"journal_content_hash": calculate_production_execution_journal_hash(forged)}
    )
    with pytest.raises(JournalError) as captured:
        verify_production_execution_journal(forged)
    assert captured.value.code in {
        "production_journal_terminal_state_mismatch",
        "production_journal_success_lifecycle_incomplete",
    }


def test_nonterminal_and_terminal_failure_are_distinguished() -> None:
    initial = _initial()
    verify_production_execution_journal(initial, require_terminal=False)
    with pytest.raises(JournalError) as missing:
        verify_production_execution_journal(initial)
    assert missing.value.code == "production_journal_terminal_missing"

    failed = _failure()
    verify_production_execution_journal(failed)
    assert failed.state is JournalState.FAILED_DRIFT
    assert failed.mutation_attempt_count == 0


def test_failed_approval_may_stop_before_permit_consumption_and_api() -> None:
    journal = _append_step(_initial(), _success_steps()[0], second=1)
    journal = append_production_execution_journal_entry(
        journal,
        timestamp=START + timedelta(seconds=2),
        phase=Phase.TERMINAL_RESULT,
        status=EntryStatus.FAILED,
        safe_code="production_approval_validation_failed",
        api_call_count=0,
        read_retry_count=0,
        mutation_attempt_count=0,
        approval_consumed=False,
        kill_switch_generation=7,
        write_token_generation=9,
        terminal_state=JournalState.FAILED_APPROVAL,
    )
    verify_production_execution_journal(journal)
    assert journal.approval_consumed is False
    assert journal.api_call_count == 0


def test_permit_consume_failure_may_stop_after_approval_and_before_api() -> None:
    journal = _initial()
    for second, step in enumerate(_success_steps()[:2], start=1):
        journal = _append_step(journal, step, second=second)
    journal = append_production_execution_journal_entry(
        journal,
        timestamp=START + timedelta(seconds=3),
        phase=Phase.TERMINAL_RESULT,
        status=EntryStatus.FAILED,
        safe_code="production_execute_permit_consume_failed",
        api_call_count=0,
        read_retry_count=0,
        mutation_attempt_count=0,
        approval_consumed=False,
        kill_switch_generation=7,
        write_token_generation=9,
        terminal_state=JournalState.FAILED_APPROVAL,
    )
    verify_production_execution_journal(journal)
    assert journal.approval_consumed is False
    assert journal.api_call_count == 0


def test_report_is_integrity_checked_and_bound_to_exact_journal() -> None:
    journal = _success()
    report = build_production_execution_report_from_journal(journal)
    verify_production_execution_report(report, journal)

    assert report.success is True
    assert report.approval_state == "validated"
    assert report.operation_count == 1
    assert report.add_count == report.delete_count == 0
    assert report.update_count == 1
    assert report.changed_fields == ("description",)
    assert report.api_call_count == 7
    assert report.mutation_attempt_count == 1
    assert report.mutation_retry_count == 0
    assert report.pre_snapshot_verified is True
    assert report.pre_image_verified is True
    assert report.read_back_verified is True
    assert report.post_snapshot_verified is True
    assert report.zero_diff_verified is True
    assert report.baseline_renewal_required is True
    assert report.automatic_rollback_count == 0
    assert calculate_production_execution_report_hash(report) == report.report_content_hash

    tampered = report.model_copy(update={"journal_hash": HASH_A})
    with pytest.raises(ProductionExecutionReportError) as captured:
        verify_production_execution_report(tampered, journal)
    assert captured.value.code == "production_execution_report_hash_mismatch"

    other = _failure()
    with pytest.raises(ProductionExecutionReportError) as mismatched:
        verify_production_execution_report(report, other)
    assert mismatched.value.code == "production_execution_report_binding_mismatch"


def test_report_json_matches_schema_and_text_is_safe() -> None:
    journal = _success()
    report = build_production_execution_report_from_journal(journal)
    json_text = render_production_execution_report_json(report, journal)
    text = render_production_execution_report_text(report, journal)
    root = Path(__file__).parents[1]
    schema = json.loads(
        (root / "schemas" / "production-single-update-execution-report-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    Draft202012Validator(schema, format_checker=None).validate(json.loads(json_text))

    unsafe_document = json.loads(json_text)
    unsafe_document["safe_findings"] = ["private_secret_value"]
    with pytest.raises(JsonSchemaValidationError):
        Draft202012Validator(schema, format_checker=None).validate(unsafe_document)

    assert "mock only: yes" in text
    assert "live execution: no" in text
    assert "baseline renewal required: yes" in text
    assert "automatic rollback: 0" in text


def test_report_safe_findings_are_closed_content_free_codes() -> None:
    failed = _failure()
    report = build_production_execution_report_from_journal(
        failed,
        safe_findings=("production_full_snapshot_drift",),
    )
    verify_production_execution_report(report, failed)
    assert report.success is False
    assert report.pre_snapshot_verified is False
    assert report.baseline_renewal_required is False

    with pytest.raises(ValueError):
        build_production_execution_report_from_journal(failed, safe_findings=("raw value leaked!",))


def test_lower_snake_private_value_is_not_an_accepted_safe_code() -> None:
    journal = _append_step(_initial(), _success_steps()[0], second=1)
    private_value = "private_secret_value"
    with pytest.raises(ValueError) as captured:
        append_production_execution_journal_entry(
            journal,
            timestamp=START + timedelta(seconds=2),
            phase=Phase.TERMINAL_RESULT,
            status=EntryStatus.FAILED,
            safe_code=private_value,
            api_call_count=0,
            read_retry_count=0,
            mutation_attempt_count=0,
            approval_consumed=False,
            kill_switch_generation=7,
            write_token_generation=9,
            terminal_state=JournalState.FAILED_PREFLIGHT,
        )
    assert private_value not in str(captured.value)


def test_report_builder_consumes_and_cross_checks_mock_execution_result() -> None:
    journal = _success()
    result = ProductionMockExecutionResult(
        result_state=ProductionExecutionResultState.SUCCEEDED,
        target_safe_ref=journal.target_safe_ref,
        run_spec_ref=journal.run_spec_ref,
        plan_ref=journal.plan_ref,
        approval_state="validated",
        permit_consumed=True,
        patch_hash=journal.patch_hash,
        api_call_count=journal.api_call_count,
        read_retry_count=journal.read_retry_count,
        mutation_attempt_count=journal.mutation_attempt_count,
        pre_snapshot_verified=True,
        pre_image_verified=True,
        read_back_verified=True,
        post_snapshot_verified=True,
        zero_diff_verified=True,
        baseline_renewal_required=True,
        journal=journal,
    )
    report = build_production_execution_report(result)
    verify_production_execution_report(report, journal)
    assert report.result_state is JournalState.SUCCEEDED

    mismatched = result.model_copy(update={"api_call_count": 6})
    with pytest.raises(ProductionExecutionReportError) as captured:
        build_production_execution_report(mismatched)
    assert captured.value.code == "production_execution_result_journal_mismatch"
