from __future__ import annotations

import json
import os
from pathlib import Path

import jsonschema
import pytest
from conftest import REPOSITORY_ROOT
from phase5c0_helpers import (
    BOOTSTRAP_DESCRIPTION,
    BOOTSTRAP_SUMMARY,
    BOOTSTRAP_UID,
    build_bootstrap_bundle,
)

from tridentine_calendar_google_sync.test_bootstrap_plan import (
    TestBootstrapPlanError as BootstrapError,
)
from tridentine_calendar_google_sync.test_bootstrap_plan import (
    calculate_test_bootstrap_add_plan_hash,
    private_test_bootstrap_add_plan_data,
    verify_test_bootstrap_add_plan,
)
from tridentine_calendar_google_sync.test_bootstrap_plan_io import (
    TestBootstrapPlanIOError as PlanIOError,
)
from tridentine_calendar_google_sync.test_bootstrap_plan_io import (
    load_test_bootstrap_add_plan,
    parse_test_bootstrap_add_plan_bytes,
    render_test_bootstrap_add_plan_json,
    write_test_bootstrap_add_plan,
)
from tridentine_calendar_google_sync.test_bootstrap_plan_report import (
    build_test_bootstrap_add_plan_inspection,
    render_test_bootstrap_add_plan_inspection_json,
    render_test_bootstrap_add_plan_inspection_text,
)


def _schema() -> dict[str, object]:
    return json.loads(
        (REPOSITORY_ROOT / "schemas" / "test-bootstrap-add-plan-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )


def test_plan_fixed_values_integrity_and_schema_are_exact(tmp_path: Path) -> None:
    plan = build_bootstrap_bundle(tmp_path).plan
    document = private_test_bootstrap_add_plan_data(plan)

    assert plan.plan_type == "test_bootstrap_add"
    assert plan.test_only is True
    assert plan.bootstrap_only is True
    assert plan.executable is False
    assert plan.production_locked is True
    assert (plan.operation_count, plan.add_count, plan.update_count, plan.delete_count) == (
        1,
        1,
        0,
        0,
    )
    assert plan.snapshot_event_count == 0
    assert plan.approval_required is True
    assert calculate_test_bootstrap_add_plan_hash(plan) == plan.plan_content_hash
    verify_test_bootstrap_add_plan(plan)
    jsonschema.validate(document, _schema())


def test_plan_is_deterministic_and_guard_order_is_fixed(tmp_path: Path) -> None:
    first = build_bootstrap_bundle(tmp_path).plan
    second = build_bootstrap_bundle(tmp_path).plan

    assert first == second
    assert render_test_bootstrap_add_plan_json(first) == render_test_bootstrap_add_plan_json(second)
    assert first.original_guard_codes == (
        "zero_google_event_count",
        "all_events_add",
        "mass_change_guard",
    )


def test_plan_contains_no_raw_identity_content_or_executable_request_shape(tmp_path: Path) -> None:
    plan = build_bootstrap_bundle(tmp_path).plan
    rendered = render_test_bootstrap_add_plan_json(plan)

    for forbidden in (
        BOOTSTRAP_UID,
        BOOTSTRAP_SUMMARY,
        BOOTSTRAP_DESCRIPTION,
        "google_event_id",
        '"etag"',
        '"payload"',
        '"endpoint"',
        '"http_method"',
        '"calendar_id"',
    ):
        assert forbidden not in rendered
    assert plan.safe_uid_ref in rendered


@pytest.mark.parametrize(
    "updates",
    (
        {"test_only": False},
        {"bootstrap_only": False},
        {"executable": True},
        {"production_locked": False},
        {"operation_count": 2},
        {"add_count": 0},
        {"update_count": 1},
        {"delete_count": 1},
        {"original_guard_codes": ("unknown_guard",)},
    ),
)
def test_rehashed_fixed_policy_tampering_is_rejected(
    tmp_path: Path,
    updates: dict[str, object],
) -> None:
    plan = build_bootstrap_bundle(tmp_path).plan
    provisional = plan.model_copy(update={**updates, "plan_content_hash": "0" * 64})
    forged = provisional.model_copy(
        update={"plan_content_hash": calculate_test_bootstrap_add_plan_hash(provisional)}
    )

    with pytest.raises(BootstrapError):
        verify_test_bootstrap_add_plan(forged)


def test_plan_render_parse_and_repository_external_no_overwrite_io(tmp_path: Path) -> None:
    plan = build_bootstrap_bundle(tmp_path).plan
    rendered = render_test_bootstrap_add_plan_json(plan)
    parsed = parse_test_bootstrap_add_plan_bytes(rendered.encode("utf-8"))
    output = tmp_path / "fixture.test-bootstrap-add-plan.json"

    assert parsed == plan
    write_test_bootstrap_add_plan(plan, output)
    assert load_test_bootstrap_add_plan(output) == plan
    with pytest.raises(PlanIOError):
        write_test_bootstrap_add_plan(plan, output)
    with pytest.raises(PlanIOError):
        write_test_bootstrap_add_plan(
            plan,
            REPOSITORY_ROOT / "forbidden.test-bootstrap-add-plan.json",
        )


def test_plan_parser_rejects_unknown_duplicate_and_hash_tamper(tmp_path: Path) -> None:
    plan = build_bootstrap_bundle(tmp_path).plan
    document = private_test_bootstrap_add_plan_data(plan)
    unknown = {**document, "raw_uid": BOOTSTRAP_UID}
    with pytest.raises(PlanIOError):
        parse_test_bootstrap_add_plan_bytes(json.dumps(unknown).encode("utf-8"))

    duplicate = render_test_bootstrap_add_plan_json(plan).replace(
        '"schema_version": "1.0",',
        '"schema_version": "1.0",\n  "schema_version": "1.0",',
        1,
    )
    with pytest.raises(PlanIOError):
        parse_test_bootstrap_add_plan_bytes(duplicate.encode("utf-8"))

    tampered = dict(document)
    tampered["diff_hash"] = "f" * 64
    with pytest.raises(BootstrapError):
        parse_test_bootstrap_add_plan_bytes(json.dumps(tampered).encode("utf-8"))


@pytest.mark.parametrize(
    "unsafe",
    (
        "https://example.invalid/plan.json",
        "file:///fixture/plan.json",
        "//fixture.invalid/share/plan.json",
    ),
)
def test_nonlocal_plan_output_is_rejected(tmp_path: Path, unsafe: str) -> None:
    with pytest.raises(PlanIOError):
        write_test_bootstrap_add_plan(build_bootstrap_bundle(tmp_path).plan, unsafe)


def test_symlink_plan_output_is_rejected(tmp_path: Path) -> None:
    plan = build_bootstrap_bundle(tmp_path).plan
    real = tmp_path / "real-plan.json"
    link = tmp_path / "linked-plan.json"
    real.write_text("existing", encoding="utf-8")
    try:
        os.symlink(real, link)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(PlanIOError):
        write_test_bootstrap_add_plan(plan, link)


def test_plan_inspection_is_deterministic_and_content_redacted(tmp_path: Path) -> None:
    plan = build_bootstrap_bundle(tmp_path).plan
    text = render_test_bootstrap_add_plan_inspection_text(plan)
    json_report = render_test_bootstrap_add_plan_inspection_json(plan)
    inspection = build_test_bootstrap_add_plan_inspection(plan)

    assert render_test_bootstrap_add_plan_inspection_text(plan) == text
    assert render_test_bootstrap_add_plan_inspection_json(plan) == json_report
    assert inspection["executable"] is False
    assert inspection["bootstrap_eligibility"] == "eligible"
    for rendered in (text, json_report):
        for forbidden in (
            BOOTSTRAP_UID,
            BOOTSTRAP_SUMMARY,
            BOOTSTRAP_DESCRIPTION,
            plan.target_fingerprint,
            str(tmp_path),
        ):
            assert forbidden not in rendered
