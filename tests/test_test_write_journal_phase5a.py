from __future__ import annotations

import hashlib
import json
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
    finalize_test_write_missing_identity_journal,
    initialize_test_write_journal,
    parse_test_write_journal_bytes,
    render_test_write_journal_json,
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
        terminal_state=JournalState.COMPLETED,
    )
    verify_test_write_journal(journal)
    assert journal.state is JournalState.COMPLETED
    assert journal.entry_count == 3
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
        phase=JournalPhase.PREFLIGHT,
        status=EntryStatus.SUCCEEDED,
        api_call_count=1,
        read_retry_count=0,
        mutation_attempt_count=0,
    )
    journal = append_test_write_journal_entry(
        journal,
        phase=JournalPhase.MUTATION,
        status=EntryStatus.UNCERTAIN,
        api_call_count=2,
        read_retry_count=0,
        mutation_attempt_count=1,
        safe_error_code="write_outcome_uncertain",
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


def _rehash_journal(journal: Any) -> Any:
    value = journal.model_copy(update={"journal_content_hash": "0" * 64})
    return value.model_copy(
        update={"journal_content_hash": calculate_test_write_journal_hash(value)}
    )


def test_rehashed_empty_completed_journal_is_rejected_by_model_verifier(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    initial = initialize_test_write_journal(
        _run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    )
    forged = _rehash_journal(initial.model_copy(update={"state": JournalState.COMPLETED}))

    with pytest.raises(JournalError) as captured:
        verify_test_write_journal(forged)
    assert captured.value.code == "test_write_journal_lifecycle_mismatch"


@pytest.mark.parametrize("include_mutation", (False, True))
def test_rehashed_completed_prefix_missing_mutation_or_readback_is_rejected(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    include_mutation: bool,
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
    if include_mutation:
        journal = append_test_write_journal_entry(
            journal,
            phase=JournalPhase.MUTATION,
            status=EntryStatus.SUCCEEDED,
            api_call_count=2,
            read_retry_count=0,
            mutation_attempt_count=1,
        )
    forged = _rehash_journal(journal.model_copy(update={"state": JournalState.COMPLETED}))

    with pytest.raises(JournalError) as captured:
        verify_test_write_journal(forged)
    assert captured.value.code == "test_write_journal_lifecycle_mismatch"


def test_legitimate_preflight_failure_and_etag_conflict_journals_remain_valid(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    failed = append_test_write_journal_entry(
        initialize_test_write_journal(spec),
        phase=JournalPhase.PREFLIGHT,
        status=EntryStatus.FAILED,
        api_call_count=1,
        read_retry_count=0,
        mutation_attempt_count=0,
        safe_error_code="test_write_snapshot_hash_mismatch",
        terminal_state=JournalState.FAILED,
    )
    conflict = append_test_write_journal_entry(
        initialize_test_write_journal(spec),
        phase=JournalPhase.PREFLIGHT,
        status=EntryStatus.FAILED,
        api_call_count=1,
        read_retry_count=0,
        mutation_attempt_count=0,
        safe_error_code="etag_conflict",
        terminal_state=JournalState.ETAG_CONFLICT,
    )

    verify_test_write_journal(failed)
    verify_test_write_journal(conflict)
    assert failed.state is JournalState.FAILED
    assert conflict.state is JournalState.ETAG_CONFLICT


@pytest.fixture
def missing_id_journal(tmp_path, synthetic_profile_factory, monkeypatch):
    prefix = initialize_test_write_journal(
        _run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    )
    for phase, api, mutations in (
        (JournalPhase.PREFLIGHT, 4, 0),
        (JournalPhase.MUTATION, 5, 1),
    ):
        prefix = append_test_write_journal_entry(
            prefix,
            phase=phase,
            status=EntryStatus.SUCCEEDED,
            api_call_count=api,
            read_retry_count=2,
            mutation_attempt_count=mutations,
        )
    result = finalize_test_write_missing_identity_journal(prefix)
    assert prefix.schema_version == "1.0" and prefix.state is JournalState.RUNNING
    assert result.entries[0].entry_hash != prefix.entries[0].entry_hash
    return result


def _rehash_wire_journal(data, *, v1_entry=None, aggregate_version="v2"):
    """Model a self-consistent wire document independently of the reader."""

    def digest(domain, payload):
        raw = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
        return hashlib.sha256(
            f"tridentine-calendar-google-sync:{domain}\x00".encode() + raw
        ).hexdigest()

    previous = "0" * 64
    for i, entry in enumerate(data["entries"]):
        entry["previous_entry_hash"] = previous
        payload = {k: v for k, v in entry.items() if k != "entry_hash"}
        previous = digest(f"test-write-journal-entry:{'v1' if i == v1_entry else 'v2'}", payload)
        entry["entry_hash"] = previous
    data["last_entry_hash"] = previous
    payload = {k: v for k, v in data.items() if k != "journal_content_hash"}
    data["journal_content_hash"] = digest(f"test-write-journal:{aggregate_version}", payload)
    return json.dumps(data).encode()


def test_v2_stop_reuses_actual_counts_and_authenticates_all_entries(missing_id_journal):
    raw = render_test_write_journal_json(missing_id_journal)
    data = json.loads(raw)
    assert (
        data["schema_version"] == "2.0"
        and data["journal_type"] == "test-write-operation-journal-v2"
    )
    assert [
        (e["api_call_count"], e["read_retry_count"], e["mutation_attempt_count"])
        for e in data["entries"]
    ] == [(4, 2, 0), (5, 2, 1), (5, 2, 1)]
    assert json.loads(_rehash_wire_journal(data)) == json.loads(raw)
    assert parse_test_write_journal_bytes(raw.encode()) == missing_id_journal


@pytest.mark.parametrize(
    "case",
    (
        "update",
        "get_performed",
        "success",
        "different_reason",
        "decreasing_api",
        "changed_retries",
        "changed_mutations",
        "aggregate_only",
        "mutation_retry",
        "recovered",
        "no_verification_capacity",
        "extra_mutation_phase_api",
        "unknown_version",
        "v1_type",
        "v1_entry",
        "v1_aggregate",
    ),
)
def test_rehashed_invalid_v2_documents_are_refused(missing_id_journal, case):
    data = json.loads(render_test_write_journal_json(missing_id_journal))
    before, mutation, stop = data["entries"]
    if case == "update":
        for record in (data, before, mutation, stop):
            record["operation"] = "update"
    elif case == "get_performed":
        stop["api_call_count"] += 1
    elif case == "success":
        data["state"] = "completed"
        stop.update(status="succeeded", safe_error_code=None)
    elif case == "different_reason":
        stop["safe_error_code"] = "test_write_guard_failed"
    elif case == "decreasing_api":
        stop["api_call_count"] -= 1
    elif case == "changed_retries":
        stop["read_retry_count"] += 1
    elif case == "changed_mutations":
        stop["mutation_attempt_count"] = 0
    elif case == "mutation_retry":
        stop["mutation_retry_count"] = 1
    elif case == "recovered":
        stop["recovered_after_uncertain"] = True
    elif case == "no_verification_capacity":
        before["api_call_count"] = 9
        mutation["api_call_count"] = stop["api_call_count"] = 10
    elif case == "extra_mutation_phase_api":
        mutation["api_call_count"] = stop["api_call_count"] = before["api_call_count"] + 2
    elif case == "unknown_version":
        data["schema_version"] = "3.0"
    elif case == "v1_type":
        data["journal_type"] = "test-write-operation-journal-v1"

    for key in (
        "api_call_count",
        "read_retry_count",
        "mutation_attempt_count",
        "mutation_retry_count",
        "recovered_after_uncertain",
    ):
        data[key] = stop[key]
    if case == "aggregate_only":
        data["api_call_count"] += 1
    raw = _rehash_wire_journal(
        data,
        v1_entry=1 if case == "v1_entry" else None,
        aggregate_version="v1" if case == "v1_aggregate" else "v2",
    )
    with pytest.raises(JournalError):
        parse_test_write_journal_bytes(raw)


def test_verifier_rechecks_v2_semantics_on_model_copies(missing_id_journal):
    forged = _rehash_journal(missing_id_journal.model_copy(update={"api_call_count": 4}))
    with pytest.raises(JournalError):
        verify_test_write_journal(forged)
    with pytest.raises(JournalError):
        verify_test_write_journal(
            missing_id_journal.model_copy(
                update={"journal_type": "test-write-operation-journal-v1"}
            )
        )


@pytest.mark.parametrize(
    ("where", "field", "value"),
    (
        ("journal", "api_call_count", 5.0),
        ("journal", "test_only", 1),
        ("journal", "mutation_retry_count", False),
        ("entry", "api_call_count", 4.0),
        ("entry", "mutation_retry_count", False),
        ("entry", "source_ref", "invalid-reference"),
    ),
)
def test_public_verifier_rejects_unvalidated_v2_fields(missing_id_journal, where, field, value):
    if where == "entry":
        first, *rest = missing_id_journal.entries
        forged = missing_id_journal.model_copy(
            update={"entries": (first.model_copy(update={field: value}), *rest)}
        )
    else:
        forged = missing_id_journal.model_copy(update={field: value})
    with pytest.raises(JournalError):
        verify_test_write_journal(forged)


@pytest.mark.parametrize(
    ("where", "field", "change"),
    (
        ("journal", "schema_version", "omit"),
        ("journal", "journal_type", "omit"),
        ("journal", "recovered_after_uncertain", "omit"),
        ("entry", "mutation_retry_count", "omit"),
        ("entry", "safe_error_code", "omit"),
        ("entry", "mutation_retry_count", False),
        ("journal", "production_locked", 1),
    ),
)
def test_v2_wire_requires_explicit_typed_fields(missing_id_journal, where, field, change):
    # Keep the hash of the original canonical values. A reader silently
    # defaulting or coercing one field would otherwise verify this document.
    data = json.loads(render_test_write_journal_json(missing_id_journal))
    record = data if where == "journal" else data["entries"][0]
    if change == "omit":
        del record[field]
    else:
        record[field] = change
    with pytest.raises(JournalError):
        parse_test_write_journal_bytes(json.dumps(data).encode())
