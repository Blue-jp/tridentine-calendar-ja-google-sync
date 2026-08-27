"""Public-safe inspection reports for Production Single Update Plans."""

from __future__ import annotations

import hashlib
import json

from tridentine_calendar_google_sync.production_single_update_plan import (
    verify_production_single_update_plan,
)
from tridentine_calendar_google_sync.production_single_update_plan_models import (
    ProductionSingleUpdatePlan,
)

_REPORT_HASH_DOMAIN = b"tridentine-calendar-google-sync:production-single-update-plan-report:v1\x00"


def build_production_single_update_plan_inspection(
    plan: ProductionSingleUpdatePlan,
) -> dict[str, object]:
    """Return verified aggregate metadata with no raw source or event content."""

    verify_production_single_update_plan(plan)
    data: dict[str, object] = {
        "schema_version": "1.0",
        "report_type": "production-single-update-plan-inspection-v1",
        "planning_mode": plan.planning_mode,
        "production": True,
        "production_only": True,
        "synthetic": False,
        "state": plan.state,
        "executable": plan.executable,
        "target_safe_ref": plan.target_safe_ref,
        "target_config_reference": f"C-{plan.target_config_hash[:12]}",
        "baseline_reference": f"B-{plan.baseline_hash[:12]}",
        "manifest_reference": f"M-{plan.manifest_hash[:12]}",
        "source_reference": f"S-{plan.source_content_hash[:12]}",
        "snapshot_reference": f"N-{plan.snapshot_hash[:12]}",
        "diff_reference": f"D-{plan.diff_hash[:12]}",
        "managed_uid_count": plan.managed_uid_count,
        "source_event_count": plan.source_event_count,
        "snapshot_event_count": plan.snapshot_event_count,
        "unchanged_count": plan.unchanged_count,
        "operation_count": plan.operation_count,
        "add_count": plan.add_count,
        "update_count": plan.update_count,
        "delete_count": plan.delete_count,
        "changed_fields": list(plan.changed_fields),
        "safe_uid_ref": plan.safe_uid_ref,
        "google_ref": plan.google_ref,
        "pre_image_hash": plan.pre_image_hash,
        "patch_hash": plan.patch_hash,
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


def render_production_single_update_plan_inspection_json(
    plan: ProductionSingleUpdatePlan,
) -> str:
    """Render deterministic public-safe JSON."""

    return (
        json.dumps(
            build_production_single_update_plan_inspection(plan),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )


def render_production_single_update_plan_inspection_text(
    plan: ProductionSingleUpdatePlan,
) -> str:
    """Render deterministic content-free text."""

    report = build_production_single_update_plan_inspection(plan)
    fields = report["changed_fields"]
    assert isinstance(fields, list)
    return "\n".join(
        (
            "Production Calendar Single Update Plan inspection",
            f"planning mode: {report['planning_mode']}",
            f"state: {report['state']}",
            "executable: no",
            f"target reference: {report['target_safe_ref']}",
            f"baseline reference: {report['baseline_reference']}",
            f"manifest reference: {report['manifest_reference']}",
            f"source events: {report['source_event_count']}",
            f"snapshot events: {report['snapshot_event_count']}",
            f"unchanged: {report['unchanged_count']}",
            f"operations: {report['operation_count']}",
            f"add: {report['add_count']}",
            f"update: {report['update_count']}",
            f"delete: {report['delete_count']}",
            f"changed fields: {', '.join(str(field) for field in fields)}",
            f"source reference: {report['safe_uid_ref']}",
            f"Google reference: {report['google_ref']}",
            "approval required: yes",
            "integrity: verified",
            f"plan hash: {report['plan_content_hash']}",
            f"report hash: {report['report_content_hash']}",
            "",
        )
    )


__all__ = [
    "build_production_single_update_plan_inspection",
    "render_production_single_update_plan_inspection_json",
    "render_production_single_update_plan_inspection_text",
]
