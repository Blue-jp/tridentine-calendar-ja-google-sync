"""Content-addressed static approval material for a Production Run Spec.

This module creates no challenge, approval, receipt, or execution authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping
from datetime import UTC, datetime

from tridentine_calendar_google_sync.production_single_update_run_spec_models import (
    ProductionSingleUpdateRunSpec,
)

_APPROVAL_MATERIAL_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:production-approval-material:v1\x00"
)


class ProductionApprovalMaterialError(ValueError):
    """A content-free static approval-material integrity failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def production_approval_material_data(
    run_spec: ProductionSingleUpdateRunSpec,
) -> dict[str, object]:
    """Return every static approved field, excluding only derived envelope hashes."""

    operation = run_spec.operation
    return {
        "schema_version": run_spec.schema_version,
        "run_type": run_spec.run_type,
        "planning_mode": run_spec.planning_mode,
        "production": run_spec.production,
        "production_only": run_spec.production_only,
        "synthetic": run_spec.synthetic,
        "single_update": run_spec.single_update,
        "update_only": run_spec.update_only,
        "executable": run_spec.executable,
        "tool_version": run_spec.tool_version,
        "issued_at": run_spec.issued_at.isoformat(),
        "expires_at": run_spec.expires_at.isoformat(),
        "target_fingerprint": run_spec.target_fingerprint,
        "target_safe_ref": run_spec.target_safe_ref,
        "target_config_hash": run_spec.target_config_hash,
        "target_environment": run_spec.target_environment,
        "baseline_state": run_spec.baseline_state,
        "trusted_baseline_hash": run_spec.trusted_baseline_hash,
        "baseline_snapshot_hash": run_spec.baseline_snapshot_hash,
        "manifest_hash": run_spec.manifest_hash,
        "source_profile": run_spec.source_profile,
        "accepted_tag": run_spec.accepted_tag,
        "accepted_commit": run_spec.accepted_commit,
        "source_sha256": run_spec.source_sha256,
        "source_content_hash": run_spec.source_content_hash,
        "source_event_count": run_spec.source_event_count,
        "current_snapshot_hash": run_spec.current_snapshot_hash,
        "snapshot_event_count": run_spec.snapshot_event_count,
        "diff_hash": run_spec.diff_hash,
        "production_plan_hash": run_spec.production_plan_hash,
        "unchanged_count": run_spec.unchanged_count,
        "operation_count": run_spec.operation_count,
        "add_count": run_spec.add_count,
        "update_count": run_spec.update_count,
        "delete_count": run_spec.delete_count,
        "changed_fields": list(run_spec.changed_fields),
        "operation": {
            "operation": operation.operation,
            "safe_uid_ref": operation.safe_uid_ref,
            "google_ref": operation.google_ref,
            "changed_fields": list(operation.changed_fields),
            "pre_image_hash": operation.pre_image_hash,
            "patch_hash": operation.patch_hash,
            "operation_content_hash": operation.operation_content_hash,
        },
        "approval_required": run_spec.approval_required,
        "run_spec_content_hash": run_spec.run_spec_content_hash,
    }


def _hash_mapping(value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_APPROVAL_MATERIAL_HASH_DOMAIN + encoded).hexdigest()


def calculate_production_approval_material_hash(
    run_spec: ProductionSingleUpdateRunSpec,
) -> str:
    """Calculate the domain-separated hash of all static approved fields."""

    if not isinstance(run_spec, ProductionSingleUpdateRunSpec):
        raise ProductionApprovalMaterialError(
            "invalid_production_approval_material",
            "Production approval material is invalid",
        )
    return _hash_mapping(production_approval_material_data(run_spec))


def verify_production_approval_material_hash(
    run_spec: ProductionSingleUpdateRunSpec,
    *,
    now: datetime | None = None,
    require_current: bool = False,
) -> None:
    """Verify the static hash; approval consumers may also require freshness."""

    if require_current:
        current_time = datetime.now(UTC) if now is None else now
        offset = current_time.utcoffset()
        if offset is None or offset.total_seconds() != 0:
            raise ProductionApprovalMaterialError(
                "production_approval_material_clock_invalid",
                "Production approval material verification clock must be UTC",
            )
        if current_time < run_spec.issued_at:
            raise ProductionApprovalMaterialError(
                "production_single_update_not_yet_valid",
                "Production approval material is not yet valid",
            )
        if current_time >= run_spec.expires_at:
            raise ProductionApprovalMaterialError(
                "production_single_update_expired",
                "Production approval material has expired",
            )

    if not hmac.compare_digest(
        calculate_production_approval_material_hash(run_spec),
        run_spec.approval_material_hash,
    ):
        raise ProductionApprovalMaterialError(
            "production_approval_material_hash_mismatch",
            "Production approval material integrity verification failed",
        )


__all__ = [
    "ProductionApprovalMaterialError",
    "calculate_production_approval_material_hash",
    "production_approval_material_data",
    "verify_production_approval_material_hash",
]
