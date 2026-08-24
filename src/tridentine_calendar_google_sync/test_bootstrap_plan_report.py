"""Public-safe inspection reports for Test bootstrap add plans."""

from __future__ import annotations

import hashlib
import json

from tridentine_calendar_google_sync.test_bootstrap_plan import (
    verify_test_bootstrap_add_plan,
)
from tridentine_calendar_google_sync.test_bootstrap_plan_models import TestBootstrapAddPlan

_REPORT_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-bootstrap-plan-report:v1\x00"


def build_test_bootstrap_add_plan_inspection(
    plan: TestBootstrapAddPlan,
) -> dict[str, object]:
    """Return safe metadata only after complete plan integrity verification."""

    verify_test_bootstrap_add_plan(plan)
    data: dict[str, object] = {
        "schema_version": "1.0",
        "report_type": "test-bootstrap-add-plan-inspection-v1",
        "plan_type": plan.plan_type,
        "test_only": plan.test_only,
        "bootstrap_only": plan.bootstrap_only,
        "executable": plan.executable,
        "production_locked": plan.production_locked,
        "target_safe_ref": plan.target_safe_ref,
        "source_profile": plan.source_profile,
        "source_event_count": plan.source_event_count,
        "snapshot_event_count": plan.snapshot_event_count,
        "operation_count": plan.operation_count,
        "add_count": plan.add_count,
        "update_count": plan.update_count,
        "delete_count": plan.delete_count,
        "safe_uid_ref": plan.safe_uid_ref,
        "original_guard_codes": list(plan.original_guard_codes),
        "bootstrap_eligibility": plan.bootstrap_eligibility,
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


def render_test_bootstrap_add_plan_inspection_json(plan: TestBootstrapAddPlan) -> str:
    """Render deterministic safe inspection JSON."""

    return (
        json.dumps(
            build_test_bootstrap_add_plan_inspection(plan),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )


def render_test_bootstrap_add_plan_inspection_text(plan: TestBootstrapAddPlan) -> str:
    """Render deterministic safe inspection text without paths or event content."""

    report = build_test_bootstrap_add_plan_inspection(plan)
    guards = report["original_guard_codes"]
    assert isinstance(guards, list)
    lines = [
        "Test Calendar bootstrap add plan inspection",
        f"schema version: {report['schema_version']}",
        f"plan type: {report['plan_type']}",
        "Test only: yes",
        "bootstrap only: yes",
        "executable: no",
        "Production locked: yes",
        f"target reference: {report['target_safe_ref']}",
        f"source profile: {report['source_profile']}",
        f"source events: {report['source_event_count']}",
        f"snapshot events: {report['snapshot_event_count']}",
        f"operations: {report['operation_count']}",
        f"add: {report['add_count']}",
        f"update: {report['update_count']}",
        f"delete: {report['delete_count']}",
        f"source reference: {report['safe_uid_ref']}",
        f"original guards: {', '.join(str(code) for code in guards)}",
        f"bootstrap eligibility: {report['bootstrap_eligibility']}",
        "approval required: yes",
        "integrity: verified",
        f"plan hash: {report['plan_content_hash']}",
        f"report hash: {report['report_content_hash']}",
        "",
    ]
    return "\n".join(lines)


__all__ = [
    "build_test_bootstrap_add_plan_inspection",
    "render_test_bootstrap_add_plan_inspection_json",
    "render_test_bootstrap_add_plan_inspection_text",
]
