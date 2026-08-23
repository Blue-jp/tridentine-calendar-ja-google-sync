from __future__ import annotations

import json
from typing import Any

import jsonschema
import pytest
from conftest import REPOSITORY_ROOT
from test_test_write_journal_phase5a import _run_spec as journal_run_spec
from test_test_write_run_spec_phase5a import _add_run_spec
from test_test_write_transport_phase5a import _Client, _prepare, _raw_event, _run

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
    append_test_write_journal_entry,
    initialize_test_write_journal,
    parse_test_write_journal_bytes,
    render_test_write_journal_json,
    verify_test_write_journal,
    write_test_write_journal,
)
from tridentine_calendar_google_sync.test_write_journal import (
    test_write_journal_data as journal_data,
)
from tridentine_calendar_google_sync.test_write_report import (
    build_test_write_json_report,
    render_test_write_json_report,
    render_test_write_text_report,
)
from tridentine_calendar_google_sync.test_write_run_spec import (
    TestWriteRunSpecError as RunSpecError,
)
from tridentine_calendar_google_sync.test_write_run_spec_io import (
    TestWriteRunSpecIOError as RunSpecIOError,
)
from tridentine_calendar_google_sync.test_write_run_spec_io import (
    load_test_write_run_spec,
    parse_test_write_run_spec_bytes,
    render_test_write_run_spec_json,
    write_test_write_run_spec,
)

pytestmark = pytest.mark.google_test_write


def _schema(name: str) -> dict[str, object]:
    return json.loads((REPOSITORY_ROOT / "schemas" / name).read_text(encoding="utf-8"))


def test_run_spec_json_is_deterministic_strict_and_schema_valid(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _add_run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    rendered = render_test_write_run_spec_json(spec)

    assert render_test_write_run_spec_json(spec) == rendered
    parsed = parse_test_write_run_spec_bytes(rendered.encode("utf-8"))
    assert parsed == spec
    jsonschema.validate(json.loads(rendered), _schema("test-write-run-spec-v1.schema.json"))


def test_run_spec_parser_rejects_unknown_duplicate_and_tampered_content(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _add_run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    document = json.loads(render_test_write_run_spec_json(spec))

    unknown = dict(document)
    unknown["calendar_id"] = "fixture-forbidden"
    with pytest.raises(RunSpecIOError):
        parse_test_write_run_spec_bytes(json.dumps(unknown).encode("utf-8"))

    tampered = dict(document)
    tampered["plan_hash"] = "f" * 64
    with pytest.raises(RunSpecError):
        parse_test_write_run_spec_bytes(
            (json.dumps(tampered, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        )

    duplicate = render_test_write_run_spec_json(spec).replace(
        '"schema_version": "1.0",',
        '"schema_version": "1.0",\n  "schema_version": "1.0",',
        1,
    )
    with pytest.raises(RunSpecIOError):
        parse_test_write_run_spec_bytes(duplicate.encode("utf-8"))


def test_run_spec_write_is_repository_external_atomic_and_no_overwrite(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _add_run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    output = tmp_path / "fixture.test-write-run-spec.json"

    write_test_write_run_spec(spec, output)
    assert load_test_write_run_spec(output) == spec
    with pytest.raises(RunSpecIOError):
        write_test_write_run_spec(spec, output)
    with pytest.raises(RunSpecIOError):
        write_test_write_run_spec(spec, REPOSITORY_ROOT / "forbidden.test-write-run-spec.json")


def test_journal_json_round_trip_hash_chain_and_schema(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = journal_run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    journal = initialize_test_write_journal(spec)
    journal = append_test_write_journal_entry(
        journal,
        phase=JournalPhase.PREFLIGHT,
        status=EntryStatus.SUCCEEDED,
        api_call_count=1,
        read_retry_count=0,
        mutation_attempt_count=0,
    )
    rendered = render_test_write_journal_json(journal)

    assert render_test_write_journal_json(journal) == rendered
    parsed = parse_test_write_journal_bytes(rendered.encode("utf-8"))
    assert parsed == journal
    verify_test_write_journal(parsed)
    jsonschema.validate(journal_data(journal), _schema("test-write-journal-v1.schema.json"))


def test_journal_parser_and_writer_reject_tamper_unknown_and_overwrite(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    journal = initialize_test_write_journal(
        journal_run_spec(tmp_path, synthetic_profile_factory, monkeypatch)
    )
    document = journal_data(journal)
    document["calendar_id"] = "fixture-forbidden"
    with pytest.raises(JournalError):
        parse_test_write_journal_bytes(json.dumps(document).encode("utf-8"))

    output = tmp_path / "fixture.test-write-journal.json"
    write_test_write_journal(journal, output)
    with pytest.raises(JournalError):
        write_test_write_journal(journal, output)


def test_public_text_and_json_reports_are_deterministic_schema_valid_and_redacted(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec, _bundle, target, challenge = _prepare(
        tmp_path, synthetic_profile_factory, monkeypatch, update=True
    )
    current = _raw_event(
        spec.operation.current_state,
        event_id=spec.operation.google_event_id,
        etag=spec.operation.expected_etag,
    )
    desired = _raw_event(
        spec.operation.desired_state,
        event_id=spec.operation.google_event_id,
        etag="fixture-etag-report-new",
    )
    result = _run(
        spec,
        target,
        _Client(get_queue=[current, desired], patch_queue=[desired]),
        challenge,
    )

    text_report = render_test_write_text_report(result)
    json_report = render_test_write_json_report(result)
    report = build_test_write_json_report(result)
    assert render_test_write_text_report(result) == text_report
    assert render_test_write_json_report(result) == json_report
    jsonschema.validate(report, _schema("test-write-report-v1.schema.json"))
    for rendered in (text_report, json_report):
        for value in (
            spec.operation.desired_state.ical_uid,
            spec.operation.google_event_id,
            spec.operation.expected_etag,
            spec.operation.desired_state.summary,
            spec.operation.desired_state.description,
            spec.target_fingerprint,
        ):
            assert value not in rendered
        for forbidden in ("calendar_id", "authorization", "access_token", "refresh_token"):
            assert forbidden not in rendered.casefold()


def test_target_schema_is_closed_and_accepts_only_synthetic_private_document() -> None:
    from phase5a_helpers import make_test_target_config

    config = make_test_target_config()
    document = {
        **config.model_dump(mode="json"),
        "calendar_id": config.calendar_id,
        "expected_target_fingerprint": config.expected_target_fingerprint,
        "expected_summary": config.expected_summary,
    }
    schema = _schema("test-write-target-v1.schema.json")
    jsonschema.validate(document, schema)
    document["unexpected"] = "rejected"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(document, schema)
