"""Public-safe inspection reports for Test Single Update Plans."""

from __future__ import annotations

import hashlib
import json

from tridentine_calendar_google_sync.test_single_update_plan import (
    verify_test_single_update_plan,
)
from tridentine_calendar_google_sync.test_single_update_plan_models import (
    TestSingleUpdatePlan,
)

_REPORT_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-single-update-plan-report:v1\x00"


def build_test_single_update_plan_inspection(plan: TestSingleUpdatePlan) -> dict[str, object]:
    """Return safe aggregate metadata after complete integrity verification."""

    verify_test_single_update_plan(plan)
    data: dict[str, object] = {
        "schema_version": "1.0",
        "report_type": "test-single-update-plan-inspection-v1",
        "plan_type": plan.plan_type,
        "test_only": plan.test_only,
        "single_update_only": plan.single_update_only,
        "production_locked": plan.production_locked,
        "executable": plan.executable,
        "target_safe_ref": plan.target_safe_ref,
        "baseline_reference": f"B-{plan.baseline_hash[:12]}",
        "baseline_state": plan.baseline_state,
        "managed_uid_count": plan.managed_uid_count,
        "source_profile": plan.source_profile,
        "source_event_count": plan.source_event_count,
        "snapshot_event_count": plan.snapshot_event_count,
        "operation_count": plan.operation_count,
        "add_count": plan.add_count,
        "update_count": plan.update_count,
        "delete_count": plan.delete_count,
        "changed_fields": list(plan.changed_fields),
        "safe_uid_ref": plan.safe_uid_ref,
        "original_guard_codes": list(plan.original_guard_codes),
        "eligibility": plan.eligibility,
        "approval_required": plan.approval_required,
        "integrity": "verified",
        "plan_content_hash": plan.plan_content_hash,
    }
    encoded = json.dumps(
        data,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        **data,
        "report_content_hash": hashlib.sha256(_REPORT_HASH_DOMAIN + encoded).hexdigest(),
    }


def render_test_single_update_plan_inspection_json(plan: TestSingleUpdatePlan) -> str:
    """Render deterministic public-safe inspection JSON."""

    return (
        json.dumps(
            build_test_single_update_plan_inspection(plan),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )


def render_test_single_update_plan_inspection_text(plan: TestSingleUpdatePlan) -> str:
    """Render deterministic public-safe text without content or local paths."""

    report = build_test_single_update_plan_inspection(plan)
    fields = report["changed_fields"]
    guards = report["original_guard_codes"]
    assert isinstance(fields, list) and isinstance(guards, list)
    return "\n".join(
        (
            "Test Calendar Single Update Plan inspection",
            f"schema version: {report['schema_version']}",
            f"plan type: {report['plan_type']}",
            "Test only: yes",
            "single Update only: yes",
            "Production locked: yes",
            "executable: no",
            f"target reference: {report['target_safe_ref']}",
            f"baseline state: {report['baseline_state']}",
            f"baseline reference: {report['baseline_reference']}",
            f"managed UIDs: {report['managed_uid_count']}",
            f"source events: {report['source_event_count']}",
            f"snapshot events: {report['snapshot_event_count']}",
            f"operations: {report['operation_count']}",
            f"add: {report['add_count']}",
            f"update: {report['update_count']}",
            f"delete: {report['delete_count']}",
            f"changed fields: {', '.join(str(field) for field in fields)}",
            f"source reference: {report['safe_uid_ref']}",
            f"original guards: {', '.join(str(code) for code in guards)}",
            f"eligibility: {report['eligibility']}",
            "approval required: yes",
            "integrity: verified",
            f"plan hash: {report['plan_content_hash']}",
            f"report hash: {report['report_content_hash']}",
            "",
        )
    )


__all__ = [
    "build_test_single_update_plan_inspection",
    "render_test_single_update_plan_inspection_json",
    "render_test_single_update_plan_inspection_text",
]
