from __future__ import annotations

from typing import Any

import pytest
from phase4b_helpers import build_add_apply_bundle
from phase5a_helpers import make_test_target_config

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.test_write_journal import (
    TestWriteJournalEntryStatus as EntryStatus,
)
from tridentine_calendar_google_sync.test_write_journal import (
    TestWriteJournalError as JournalError,
)
from tridentine_calendar_google_sync.test_write_journal import (
    TestWriteJournalPhase as JournalPhase,
)
from tridentine_calendar_google_sync.test_write_journal import (
    TestWriteJournalState as JournalState,
)
from tridentine_calendar_google_sync.test_write_journal import (
    append_test_write_journal_entry,
    calculate_test_write_journal_hash,
    initialize_test_write_journal,
    verify_test_write_journal,
)
from tridentine_calendar_google_sync.test_write_run_spec import build_test_write_run_spec

pytestmark = pytest.mark.google_test_write


def _run_spec(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> Any:
    import tridentine_calendar_google_sync.test_write_run_spec as run_spec_module

    bundle = build_add_apply_bundle(tmp_path, synthetic_profile_factory)
    fingerprint = bundle.snapshot.target_fingerprint
    monkeypatch.setattr(
        run_spec_module,
        "validate_test_write_target_config",
        lambda _target: fingerprint,
    )
    monkeypatch.setattr(
        run_spec_module,
        "test_write_target_reference",
        lambda _target: f"T-{fingerprint[:12]}",
    )
    return build_test_write_run_spec(
        bundle.profile,
        bundle.source,
        bundle.snapshot,
        bundle.plan,
        make_test_target_config(),
    )


def test_journal_hash_chain_and_terminal_success_are_valid(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    journal = initialize_test_write_journal(spec)
    journal = append_test_write_journal_entry(
        journal,
        phase=JournalPhase.PREFLIGHT,
        status=EntryStatus.SUCCEEDED,
        api_call_count=1,
        read_retry_count=0,
        mutation_attempt_count=0,
    )
    journal = append_test_write_journal_entry(
        journal,
        phase=JournalPhase.MUTATION,
        status=EntryStatus.SUCCEEDED,
        api_call_count=2,
        read_retry_count=0,
        mutation_attempt_count=1,
    )
    journal = append_test_write_journal_entry(
        journal,
        phase=JournalPhase.READ_BACK,
        status=EntryStatus.SUCCEEDED,
        api_call_count=3,
        read_retry_count=0,
        mutation_attempt_count=1,
    )
    journal = append_test_write_journal_entry(
        journal,
        phase=JournalPhase.COMPLETE,
        status=EntryStatus.SUCCEEDED,
        api_call_count=3,
        read_retry_count=0,
        mutation_attempt_count=1,
        terminal_state=JournalState.COMPLETED,
    )

    verify_test_write_journal(journal)
    assert journal.state is JournalState.COMPLETED
    assert journal.entry_count == 4
    assert journal.mutation_attempt_count == 1
    assert journal.mutation_retry_count == 0
    assert journal.rollback_available is False
    assert calculate_test_write_journal_hash(journal) == journal.journal_content_hash


def test_recovered_uncertain_entry_records_safe_flag_and_zero_mutation_retry(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = initialize_test_write_journal(
        _run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    )
    journal = append_test_write_journal_entry(
        journal,
        phase=JournalPhase.UNCERTAIN_CHECK,
        status=EntryStatus.RECOVERED,
        api_call_count=3,
        read_retry_count=1,
        mutation_attempt_count=1,
        recovered_after_uncertain=True,
        terminal_state=JournalState.COMPLETED,
    )

    verify_test_write_journal(journal)
    assert journal.recovered_after_uncertain is True
    assert journal.mutation_retry_count == 0


def test_journal_entry_or_aggregate_tampering_is_detected(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = initialize_test_write_journal(
        _run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    )
    journal = append_test_write_journal_entry(
        journal,
        phase=JournalPhase.PREFLIGHT,
        status=EntryStatus.SUCCEEDED,
        api_call_count=1,
        read_retry_count=0,
        mutation_attempt_count=0,
    )
    bad_entry = journal.entries[0].model_copy(update={"entry_hash": "f" * 64})
    tampered_entry = journal.model_copy(
        update={"entries": (bad_entry,), "last_entry_hash": bad_entry.entry_hash}
    )
    with pytest.raises(JournalError) as entry_error:
        verify_test_write_journal(tampered_entry)
    assert entry_error.value.code == "test_write_journal_entry_hash_mismatch"

    tampered_aggregate = journal.model_copy(update={"journal_content_hash": "f" * 64})
    with pytest.raises(JournalError) as aggregate_error:
        verify_test_write_journal(tampered_aggregate)
    assert aggregate_error.value.code == "test_write_journal_content_hash_mismatch"


def test_journal_rejects_count_regression_and_api_or_mutation_budget_excess(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = initialize_test_write_journal(
        _run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    )
    journal = append_test_write_journal_entry(
        journal,
        phase=JournalPhase.MUTATION,
        status=EntryStatus.SUCCEEDED,
        api_call_count=2,
        read_retry_count=1,
        mutation_attempt_count=1,
    )
    with pytest.raises(JournalError) as regressed:
        append_test_write_journal_entry(
            journal,
            phase=JournalPhase.READ_BACK,
            status=EntryStatus.SUCCEEDED,
            api_call_count=1,
            read_retry_count=1,
            mutation_attempt_count=1,
        )
    assert regressed.value.code == "test_write_journal_counts_regressed"

    initial = initialize_test_write_journal(
        _run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    )
    for calls, attempts in ((11, 0), (1, 2)):
        with pytest.raises(JournalError) as exceeded:
            append_test_write_journal_entry(
                initial,
                phase=JournalPhase.PREFLIGHT,
                status=EntryStatus.SUCCEEDED,
                api_call_count=calls,
                read_retry_count=0,
                mutation_attempt_count=attempts,
            )
        assert exceeded.value.code == "test_write_journal_budget_exceeded"


def test_public_journal_contains_no_private_run_values(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    journal = initialize_test_write_journal(spec)
    rendered = journal.model_dump_json()

    private_values = (
        spec.target_fingerprint,
        spec.operation.desired_state.ical_uid,
        spec.operation.desired_state.summary,
        spec.operation.desired_state.description,
    )
    for value in private_values:
        assert value not in rendered
    assert "calendar_id" not in rendered.casefold()
    assert "etag" not in rendered.casefold()
    assert "payload" not in rendered.casefold()


def test_production_reference_cannot_be_verified_or_appended(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = initialize_test_write_journal(
        _run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    )
    production = journal.model_copy(update={"target_safe_ref": PRODUCTION_TARGET_REFERENCE})
    with pytest.raises(JournalError) as captured:
        verify_test_write_journal(production)
    assert captured.value.code == "production_test_write_forbidden"
