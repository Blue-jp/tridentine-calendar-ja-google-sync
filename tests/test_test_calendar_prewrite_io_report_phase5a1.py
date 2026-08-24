from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import jsonschema
import pytest
from conftest import REPOSITORY_ROOT
from phase5a1_helpers import (
    SequencePrewriteClient,
    make_prewrite_target_config,
    prewrite_event,
    prewrite_page,
)
from referencing import Registry, Resource

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.sensitive_paths import SensitivePathError
from tridentine_calendar_google_sync.test_calendar_prewrite import (
    TestCalendarPrewriteError as PrewriteError,
)
from tridentine_calendar_google_sync.test_calendar_prewrite import (
    calculate_test_calendar_prewrite_report_hash,
    calculate_test_calendar_prewrite_snapshot_hash,
    inspect_test_calendar_prewrite,
    verify_test_calendar_prewrite_report,
    verify_test_calendar_prewrite_result,
    verify_test_calendar_prewrite_snapshot,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_io import (
    TestCalendarPrewriteIOError as PrewriteIOError,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_io import (
    load_test_calendar_prewrite_snapshot,
    parse_test_calendar_prewrite_snapshot_bytes,
    render_test_calendar_prewrite_snapshot,
    validate_test_calendar_prewrite_output_paths,
    write_test_calendar_prewrite_outputs,
    write_test_calendar_prewrite_snapshot,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_io import (
    test_calendar_prewrite_snapshot_data as snapshot_data,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_report import (
    build_test_calendar_prewrite_json_report,
    render_test_calendar_prewrite_json_report,
    render_test_calendar_prewrite_text_report,
)

pytestmark = pytest.mark.google_test_write


def _result(*, nonempty: bool = False) -> Any:
    items = [prewrite_event()] if nonempty else []
    return inspect_test_calendar_prewrite(
        SequencePrewriteClient([prewrite_page(items)]),
        make_prewrite_target_config(),
        sleep=lambda _delay: None,
        jitter=lambda _maximum: 0.0,
    )


def _schema(name: str) -> dict[str, object]:
    return json.loads((REPOSITORY_ROOT / "schemas" / name).read_text(encoding="utf-8"))


def _validate_snapshot_schema(document: dict[str, object]) -> None:
    nested_schema = _schema("google-snapshot-v1.schema.json")
    nested_id = nested_schema["$id"]
    assert isinstance(nested_id, str)
    registry = Registry().with_resource(nested_id, Resource.from_contents(nested_schema))
    jsonschema.Draft202012Validator(
        _schema("test-calendar-prewrite-snapshot-v1.schema.json"),
        registry=registry,
    ).validate(document)


@pytest.mark.parametrize("nonempty", (False, True))
def test_snapshot_and_reports_are_deterministic_and_schema_valid(nonempty: bool) -> None:
    result = _result(nonempty=nonempty)
    snapshot_text = render_test_calendar_prewrite_snapshot(result.snapshot)
    json_report = render_test_calendar_prewrite_json_report(result)
    text_report = render_test_calendar_prewrite_text_report(result)

    assert render_test_calendar_prewrite_snapshot(result.snapshot) == snapshot_text
    assert render_test_calendar_prewrite_json_report(result) == json_report
    assert render_test_calendar_prewrite_text_report(result) == text_report
    _validate_snapshot_schema(json.loads(snapshot_text))
    jsonschema.validate(
        json.loads(json_report),
        _schema("test-calendar-prewrite-report-v1.schema.json"),
    )
    verify_test_calendar_prewrite_result(result)


def test_empty_and_nonempty_reports_expose_only_safe_aggregate_state() -> None:
    empty = _result()
    nonempty = _result(nonempty=True)

    assert empty.report.prewrite_ready is True
    assert nonempty.report.prewrite_ready is False
    assert empty.report.event_count == 0
    assert nonempty.report.event_count == 1
    for result in (empty, nonempty):
        rendered = render_test_calendar_prewrite_text_report(
            result
        ) + render_test_calendar_prewrite_json_report(result)
        for forbidden in (
            make_prewrite_target_config().calendar_id,
            make_prewrite_target_config().expected_target_fingerprint,
            "fixture-prewrite-001@example.invalid",
            "evtfixtureprewrite001",
            "fixture-etag-prewrite-001",
            "Synthetic prewrite event",
            "Synthetic prewrite description",
        ):
            assert forbidden not in rendered
        assert "Google Calendar writes: 0" in rendered
        assert "Google Calendar event changes: 0" in rendered


def test_snapshot_contains_no_calendar_id_token_credentials_or_request_uri() -> None:
    rendered = render_test_calendar_prewrite_snapshot(_result(nonempty=True).snapshot).casefold()

    assert make_prewrite_target_config().calendar_id.casefold() not in rendered
    for forbidden in (
        "calendar_id",
        "access_token",
        "refresh_token",
        "client_secret",
        "authorization",
        "request_uri",
        "https://calendar.googleapis.com",
    ):
        assert forbidden not in rendered


def test_snapshot_round_trip_and_no_overwrite_write(tmp_path: Path) -> None:
    snapshot = _result(nonempty=True).snapshot
    rendered = render_test_calendar_prewrite_snapshot(snapshot)
    parsed = parse_test_calendar_prewrite_snapshot_bytes(rendered.encode("utf-8"))
    output = tmp_path / "fixture.test-calendar-prewrite-snapshot.json"

    assert parsed == snapshot
    write_test_calendar_prewrite_snapshot(snapshot, output)
    assert load_test_calendar_prewrite_snapshot(output) == snapshot
    with pytest.raises(PrewriteIOError):
        write_test_calendar_prewrite_snapshot(snapshot, output)


def test_snapshot_parser_rejects_unknown_duplicate_and_tampered_content() -> None:
    snapshot = _result().snapshot
    document = snapshot_data(snapshot)
    unknown = {**document, "calendar_id": "fixture-forbidden"}
    with pytest.raises(PrewriteIOError):
        parse_test_calendar_prewrite_snapshot_bytes(json.dumps(unknown).encode("utf-8"))

    duplicate = render_test_calendar_prewrite_snapshot(snapshot).replace(
        '"schema_version": "1.0",',
        '"schema_version": "1.0",\n  "schema_version": "1.0",',
        1,
    )
    with pytest.raises(PrewriteIOError):
        parse_test_calendar_prewrite_snapshot_bytes(duplicate.encode("utf-8"))

    tampered = dict(document)
    tampered["api_call_count"] = 2
    with pytest.raises(PrewriteIOError):
        parse_test_calendar_prewrite_snapshot_bytes(json.dumps(tampered).encode("utf-8"))


def test_three_outputs_are_distinct_atomic_repository_external_and_redacted(
    tmp_path: Path,
) -> None:
    result = _result(nonempty=True)
    snapshot_path = tmp_path / "fixture.test-calendar-prewrite-snapshot.json"
    human_path = tmp_path / "fixture.test-calendar-prewrite-report.txt"
    json_path = tmp_path / "fixture.test-calendar-prewrite-report.json"

    paths = write_test_calendar_prewrite_outputs(
        result,
        snapshot_output=snapshot_path,
        human_report_output=human_path,
        json_report_output=json_path,
    )

    assert paths.snapshot == snapshot_path.resolve()
    assert paths.human_report == human_path.resolve()
    assert paths.json_report == json_path.resolve()
    assert all(path.is_file() for path in (snapshot_path, human_path, json_path))
    assert "configured=True" in repr(paths)
    for path in (human_path, json_path):
        rendered = path.read_text(encoding="utf-8")
        assert "fixture-prewrite-001@example.invalid" not in rendered
        assert "Synthetic prewrite description" not in rendered


@pytest.mark.parametrize("existing_index", (0, 1, 2))
def test_existing_output_rejects_all_outputs_before_any_creation(
    tmp_path: Path,
    existing_index: int,
) -> None:
    paths = [tmp_path / f"fixture-output-{index}.json" for index in range(3)]
    paths[existing_index].write_text("existing", encoding="utf-8")

    with pytest.raises(PrewriteIOError):
        write_test_calendar_prewrite_outputs(
            _result(),
            snapshot_output=paths[0],
            human_report_output=paths[1],
            json_report_output=paths[2],
        )
    assert [path.exists() for path in paths].count(True) == 1


@pytest.mark.parametrize(
    "unsafe",
    (
        "https://example.invalid/output.json",
        "file:///fixture/output.json",
        "//fixture.invalid/share/output.json",
    ),
)
def test_url_or_network_output_is_rejected(unsafe: str, tmp_path: Path) -> None:
    with pytest.raises(PrewriteIOError):
        validate_test_calendar_prewrite_output_paths(
            unsafe,
            tmp_path / "human.txt",
            tmp_path / "report.json",
        )


def test_repository_output_and_colliding_paths_are_rejected(tmp_path: Path) -> None:
    with pytest.raises(PrewriteIOError):
        validate_test_calendar_prewrite_output_paths(
            REPOSITORY_ROOT / "forbidden-prewrite.json",
            tmp_path / "human.txt",
            tmp_path / "report.json",
        )
    same = tmp_path / "same-output.json"
    with pytest.raises(PrewriteIOError):
        validate_test_calendar_prewrite_output_paths(same, same, tmp_path / "other.json")


def test_symlink_output_is_rejected(tmp_path: Path) -> None:
    real = tmp_path / "real-output.json"
    link = tmp_path / "linked-output.json"
    real.write_text("existing", encoding="utf-8")
    try:
        os.symlink(real, link)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(PrewriteIOError):
        validate_test_calendar_prewrite_output_paths(
            link,
            tmp_path / "human.txt",
            tmp_path / "report.json",
        )


@pytest.mark.parametrize("fail_on_call", (1, 2, 3))
def test_injected_output_failure_leaves_no_partial_final_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fail_on_call: int,
) -> None:
    import tridentine_calendar_google_sync.test_calendar_prewrite_io as io_module

    original = io_module.atomic_write_private_text
    call_count = 0

    def injected(*args: object, **kwargs: object) -> None:
        nonlocal call_count
        call_count += 1
        if call_count == fail_on_call:
            raise SensitivePathError("fixture_failure", "synthetic output failure")
        original(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(io_module, "atomic_write_private_text", injected)
    paths = [tmp_path / f"fixture-final-{index}.json" for index in range(3)]

    with pytest.raises(PrewriteIOError):
        write_test_calendar_prewrite_outputs(
            _result(),
            snapshot_output=paths[0],
            human_report_output=paths[1],
            json_report_output=paths[2],
        )
    assert not any(path.exists() for path in paths)


def test_report_builder_contains_fixed_zero_mutation_counters() -> None:
    report = build_test_calendar_prewrite_json_report(_result())

    assert report["read_only"] is True
    assert report["google_write_method_count"] == 0
    assert report["google_write_operation_count"] == 0
    assert report["event_changes"] == 0


def test_rehashed_snapshot_production_reference_is_rejected() -> None:
    snapshot = _result().snapshot
    provisional = snapshot.model_copy(
        update={
            "target_safe_ref": PRODUCTION_TARGET_REFERENCE,
            "wrapper_content_hash": "0" * 64,
        }
    )
    forged = provisional.model_copy(
        update={"wrapper_content_hash": calculate_test_calendar_prewrite_snapshot_hash(provisional)}
    )

    with pytest.raises(PrewriteError):
        verify_test_calendar_prewrite_snapshot(forged)


@pytest.mark.parametrize(
    "updates",
    (
        {"prewrite_ready": True},
        {"google_write_method_count": 1},
        {"google_write_operation_count": 1},
        {"event_changes": 1},
    ),
)
def test_rehashed_nonempty_report_readiness_or_write_counter_forgery_is_rejected(
    updates: dict[str, object],
) -> None:
    report = _result(nonempty=True).report
    provisional = report.model_copy(update={**updates, "report_content_hash": "0" * 64})
    forged = provisional.model_copy(
        update={"report_content_hash": calculate_test_calendar_prewrite_report_hash(provisional)}
    )

    with pytest.raises(PrewriteError):
        verify_test_calendar_prewrite_report(forged)


def test_rehashed_cross_artifact_snapshot_binding_forgery_is_rejected() -> None:
    result = _result()
    report_provisional = result.report.model_copy(
        update={"snapshot_hash": "f" * 64, "report_content_hash": "0" * 64}
    )
    report = report_provisional.model_copy(
        update={
            "report_content_hash": calculate_test_calendar_prewrite_report_hash(report_provisional)
        }
    )
    forged = result.model_copy(update={"report": report})

    with pytest.raises(PrewriteError) as captured:
        verify_test_calendar_prewrite_result(forged)
    assert captured.value.code == "test_prewrite_result_binding_mismatch"
