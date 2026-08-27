"""Public-safe inspection reports for Production Single Update Run Specs."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from tridentine_calendar_google_sync.production_single_update_run_spec import (
    verify_production_single_update_run_spec,
)
from tridentine_calendar_google_sync.production_single_update_run_spec_models import (
    ProductionSingleUpdateRunSpec,
)

_REPORT_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:production-single-update-run-spec-report:v1\x00"
)


def build_production_single_update_run_spec_inspection(
    run_spec: ProductionSingleUpdateRunSpec,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    """Return verified safe references, counts, hashes, and lifetime only."""

    verify_production_single_update_run_spec(
        run_spec,
        require_current=False,
    )
    current_time = datetime.now(UTC) if now is None else now
    offset = current_time.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError("Production Run Spec inspection clock must be UTC")
    if current_time < run_spec.issued_at:
        temporal_state = "not_yet_valid"
    elif current_time >= run_spec.expires_at:
        temporal_state = "expired"
    else:
        temporal_state = "current"
    operation = run_spec.operation
    data: dict[str, object] = {
        "schema_version": "1.0",
        "report_type": "production-single-update-run-spec-inspection-v1",
        "planning_mode": run_spec.planning_mode,
        "production_only": run_spec.production_only,
        "synthetic": run_spec.synthetic,
        "single_update": run_spec.single_update,
        "update_only": run_spec.update_only,
        "executable": run_spec.executable,
        "issued_at": run_spec.issued_at.isoformat(),
        "expires_at": run_spec.expires_at.isoformat(),
        "temporal_state": temporal_state,
        "expired": temporal_state == "expired",
        "target_safe_ref": run_spec.target_safe_ref,
        "baseline_reference": f"B-{run_spec.trusted_baseline_hash[:12]}",
        "manifest_reference": f"M-{run_spec.manifest_hash[:12]}",
        "snapshot_reference": f"N-{run_spec.current_snapshot_hash[:12]}",
        "plan_reference": f"P-{run_spec.production_plan_hash[:12]}",
        "source_event_count": run_spec.source_event_count,
        "snapshot_event_count": run_spec.snapshot_event_count,
        "unchanged_count": run_spec.unchanged_count,
        "operation_count": run_spec.operation_count,
        "add_count": run_spec.add_count,
        "update_count": run_spec.update_count,
        "delete_count": run_spec.delete_count,
        "changed_fields": list(run_spec.changed_fields),
        "safe_uid_ref": operation.safe_uid_ref,
        "google_ref": operation.google_ref,
        "pre_image_hash": operation.pre_image_hash,
        "patch_hash": operation.patch_hash,
        "approval_required": run_spec.approval_required,
        "approval_material_hash": run_spec.approval_material_hash,
        "integrity": "verified",
        "run_spec_content_hash": run_spec.run_spec_content_hash,
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


def render_production_single_update_run_spec_inspection_json(
    run_spec: ProductionSingleUpdateRunSpec,
    *,
    now: datetime | None = None,
) -> str:
    """Render deterministic public-safe JSON."""

    return (
        json.dumps(
            build_production_single_update_run_spec_inspection(run_spec, now=now),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )


def render_production_single_update_run_spec_inspection_text(
    run_spec: ProductionSingleUpdateRunSpec,
    *,
    now: datetime | None = None,
) -> str:
    """Render deterministic content-free text."""

    report = build_production_single_update_run_spec_inspection(run_spec, now=now)
    fields = report["changed_fields"]
    assert isinstance(fields, list)
    return "\n".join(
        (
            "Production Calendar Single Update Run Spec inspection",
            f"planning mode: {report['planning_mode']}",
            "Production only: yes",
            "executable: no",
            f"issued at: {report['issued_at']}",
            f"expires at: {report['expires_at']}",
            f"temporal state: {report['temporal_state']}",
            f"target reference: {report['target_safe_ref']}",
            f"baseline reference: {report['baseline_reference']}",
            f"manifest reference: {report['manifest_reference']}",
            f"source events: {report['source_event_count']}",
            f"snapshot events: {report['snapshot_event_count']}",
            f"operations: {report['operation_count']}",
            f"add: {report['add_count']}",
            f"update: {report['update_count']}",
            f"delete: {report['delete_count']}",
            f"changed fields: {', '.join(str(field) for field in fields)}",
            f"source reference: {report['safe_uid_ref']}",
            f"Google reference: {report['google_ref']}",
            "approval required: yes",
            "integrity: verified",
            f"Run Spec hash: {report['run_spec_content_hash']}",
            f"report hash: {report['report_content_hash']}",
            "",
        )
    )


__all__ = [
    "build_production_single_update_run_spec_inspection",
    "render_production_single_update_run_spec_inspection_json",
    "render_production_single_update_run_spec_inspection_text",
]
