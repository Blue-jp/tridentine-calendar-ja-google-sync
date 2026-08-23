from __future__ import annotations

import json
from pathlib import Path

import pytest
from conftest import REPOSITORY_ROOT
from jsonschema import Draft202012Validator
from phase4b_helpers import approved_bundle, build_multi_apply_bundle, build_update_apply_bundle

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.apply_simulation import run_apply_simulation
from tridentine_calendar_google_sync.fake_mutation_transport import FakeMutationTransport
from tridentine_calendar_google_sync.operation_journal import (
    JournalEntryStatus,
    JournalState,
    OperationJournalError,
    append_operation_journal_entry,
    calculate_operation_journal_hash,
    load_operation_journal,
    parse_operation_journal_bytes,
    render_operation_journal_json,
    verify_operation_journal,
    write_operation_journal,
)
from tridentine_calendar_google_sync.retry_policy import SimulationOutcomeKind


def _successful_journal(tmp_path: Path, profile_factory: object):
    value = build_update_apply_bundle(tmp_path, profile_factory)
    approved = approved_bundle(value)
    result = run_apply_simulation(
        approved,
        FakeMutationTransport.from_bundle(approved),
    )
    return value, approved, result.journal


def test_completed_journal_hash_chain_schema_and_round_trip(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    _value, _approved, journal = _successful_journal(tmp_path, synthetic_profile_factory)
    rendered = render_operation_journal_json(journal)
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "operation-journal-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )

    verify_operation_journal(journal)
    Draft202012Validator(schema).validate(json.loads(rendered))
    assert parse_operation_journal_bytes(rendered.encode("utf-8")) == journal
    assert journal.state is JournalState.COMPLETED
    assert journal.start_marker == "simulation_start"
    assert journal.completion_marker == "simulation_complete"
    assert journal.rollback_available is False
    assert journal.entry_count == 1
    assert journal.entries[0].previous_entry_hash == "0" * 64
    assert journal.last_entry_hash == journal.entries[0].entry_hash


def test_journal_json_contains_no_raw_identity_etag_or_payload(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    value, approved, journal = _successful_journal(tmp_path, synthetic_profile_factory)
    rendered = render_operation_journal_json(journal)
    operation = approved.operations[0]

    assert operation.source_uid not in rendered
    assert operation.payload.event_id not in rendered  # type: ignore[union-attr]
    assert operation.payload.etag not in rendered  # type: ignore[union-attr]
    assert value.source.events[0].summary not in rendered
    assert value.source.events[0].description not in rendered
    for forbidden_key in (
        '"payload"',
        '"event_id"',
        '"etag"',
        '"calendar_id"',
        '"method"',
        '"endpoint"',
    ):
        assert forbidden_key not in rendered


@pytest.mark.parametrize(
    "mutation",
    (
        lambda journal: journal.model_copy(
            update={"entries": (journal.entries[0].model_copy(update={"entry_hash": "f" * 64}),)}
        ),
        lambda journal: journal.model_copy(
            update={
                "entries": (
                    journal.entries[0].model_copy(update={"previous_entry_hash": "f" * 64}),
                )
            }
        ),
        lambda journal: journal.model_copy(update={"journal_content_hash": "f" * 64}),
    ),
)
def test_journal_entry_chain_and_aggregate_tamper_are_detected(
    mutation: object,
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    _value, _approved, journal = _successful_journal(tmp_path, synthetic_profile_factory)
    tampered = mutation(journal)  # type: ignore[operator]

    with pytest.raises(OperationJournalError):
        verify_operation_journal(tampered)


def test_partial_failure_journal_has_fatal_marker_and_skipped_tail(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    value = build_multi_apply_bundle(tmp_path, synthetic_profile_factory)
    approved = approved_bundle(value)
    failed = approved.operations[1]
    transport = FakeMutationTransport.from_bundle(
        approved,
        injected_outcomes={
            failed.operation_integrity_hash: (SimulationOutcomeKind.PERMANENT_FAILURE,)
        },
    )

    result = run_apply_simulation(approved, transport)
    journal = result.journal

    assert journal.state is JournalState.PARTIAL_FAILURE
    assert journal.completion_marker == "simulation_failed"
    assert [entry.status for entry in journal.entries] == [
        JournalEntryStatus.SUCCEEDED,
        JournalEntryStatus.FAILED,
        JournalEntryStatus.SKIPPED,
    ]
    verify_operation_journal(journal)


def test_finalized_journal_cannot_be_appended(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    _value, approved, journal = _successful_journal(tmp_path, synthetic_profile_factory)
    operation = approved.operations[0]

    with pytest.raises(OperationJournalError):
        append_operation_journal_entry(
            journal,
            operation_index=1,
            operation_key=operation.operation_integrity_hash,
            operation=operation.operation,
            source_ref=operation.source_ref,
            google_ref=operation.google_ref,
            attempt=2,
            status=JournalEntryStatus.SUCCEEDED,
            outcome_code="success",
            payload_hash=operation.payload_hash,
            result_state_hash=operation.after_hash,
        )


def test_journal_atomic_write_load_and_no_overwrite(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    _value, _approved, journal = _successful_journal(tmp_path, synthetic_profile_factory)
    path = tmp_path / "synthetic.operation-journal.json"

    assert write_operation_journal(journal, path) == path
    assert load_operation_journal(path) == journal
    with pytest.raises(OperationJournalError):
        write_operation_journal(journal, path)

    repo_path = REPOSITORY_ROOT / "must-not-create.operation-journal.json"
    with pytest.raises(OperationJournalError):
        write_operation_journal(journal, repo_path)
    assert not repo_path.exists()


def test_valid_production_reference_journal_cannot_be_written(
    tmp_path: Path,
    synthetic_profile_factory: object,
) -> None:
    _value, _approved, journal = _successful_journal(tmp_path, synthetic_profile_factory)
    provisional = journal.model_copy(
        update={
            "target_reference": PRODUCTION_TARGET_REFERENCE,
            "journal_content_hash": "0" * 64,
        }
    )
    production_journal = provisional.model_copy(
        update={"journal_content_hash": calculate_operation_journal_hash(provisional)}
    )
    verify_operation_journal(production_journal)
    output = tmp_path / "must-not-write-production.operation-journal.json"

    with pytest.raises(OperationJournalError) as caught:
        write_operation_journal(production_journal, output)

    assert caught.value.code == "production_operation_journal_write_forbidden"
    assert not output.exists()
