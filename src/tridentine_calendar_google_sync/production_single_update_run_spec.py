"""Build and verify one offline Production Single Update Run Spec."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

from tridentine_calendar_google_sync.accepted_production_source_manifest_models import (
    AcceptedProductionSourceManifest,
)
from tridentine_calendar_google_sync.baseline_models import TrustedBaseline
from tridentine_calendar_google_sync.google_models import GoogleSnapshot
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.production_approval_material import (
    ProductionApprovalMaterialError,
    calculate_production_approval_material_hash,
    verify_production_approval_material_hash,
)
from tridentine_calendar_google_sync.production_single_update_plan import (
    build_production_single_update_plan,
    verify_production_single_update_plan,
)
from tridentine_calendar_google_sync.production_single_update_plan_models import (
    PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS,
    ProductionSingleUpdatePlan,
)
from tridentine_calendar_google_sync.production_single_update_run_spec_models import (
    PRODUCTION_RUN_SPEC_MAX_LIFETIME_SECONDS,
    ProductionSingleUpdateOperation,
    ProductionSingleUpdateRunSpec,
)
from tridentine_calendar_google_sync.production_write_target import (
    ProductionWriteTargetConfig,
)
from tridentine_calendar_google_sync.provenance import tool_version

_OPERATION_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:production-single-update-operation:v1\x00"
)
_RUN_SPEC_HASH_DOMAIN = b"tridentine-calendar-google-sync:production-single-update-run-spec:v1\x00"


class ProductionSingleUpdateRunSpecError(ValueError):
    """A content-free Run Spec policy, binding, lifetime, or integrity failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _hash_mapping(domain: bytes, value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def private_production_single_update_operation_data(
    operation: ProductionSingleUpdateOperation,
) -> dict[str, object]:
    """Return canonical raw-content-free operation data."""

    return {
        "operation": operation.operation,
        "safe_uid_ref": operation.safe_uid_ref,
        "google_ref": operation.google_ref,
        "changed_fields": list(operation.changed_fields),
        "pre_image_hash": operation.pre_image_hash,
        "patch_hash": operation.patch_hash,
        "operation_content_hash": operation.operation_content_hash,
    }


def private_production_single_update_run_spec_data(
    run_spec: ProductionSingleUpdateRunSpec,
) -> dict[str, object]:
    """Return complete canonical Run Spec data with no raw event content."""

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
        "operation": private_production_single_update_operation_data(run_spec.operation),
        "approval_required": run_spec.approval_required,
        "approval_material_hash": run_spec.approval_material_hash,
        "run_spec_content_hash": run_spec.run_spec_content_hash,
    }


def calculate_production_single_update_operation_hash(
    operation: ProductionSingleUpdateOperation,
) -> str:
    """Calculate the exact operation hash."""

    data = private_production_single_update_operation_data(operation)
    del data["operation_content_hash"]
    return _hash_mapping(_OPERATION_HASH_DOMAIN, data)


def calculate_production_single_update_run_spec_hash(
    run_spec: ProductionSingleUpdateRunSpec,
) -> str:
    """Calculate the complete Run Spec hash."""

    data = private_production_single_update_run_spec_data(run_spec)
    del data["run_spec_content_hash"]
    del data["approval_material_hash"]
    return _hash_mapping(_RUN_SPEC_HASH_DOMAIN, data)


def _clock_is_valid(value: datetime) -> bool:
    offset = value.utcoffset()
    return offset is not None and offset.total_seconds() == 0


def verify_production_single_update_run_spec(
    run_spec: ProductionSingleUpdateRunSpec,
    *,
    now: datetime | None = None,
    require_current: bool = True,
) -> None:
    """Verify fixed policy, hashes, and ``issued_at <= now < expires_at``."""

    if not isinstance(run_spec, ProductionSingleUpdateRunSpec):
        raise ProductionSingleUpdateRunSpecError(
            "invalid_production_single_update_run_spec",
            "Production Single Update Run Spec is invalid",
        )
    if require_current:
        current_time = datetime.now(UTC) if now is None else now
        if not _clock_is_valid(current_time):
            raise ProductionSingleUpdateRunSpecError(
                "production_single_update_clock_invalid",
                "Production Run Spec verification clock must be UTC",
            )
        if current_time < run_spec.issued_at:
            raise ProductionSingleUpdateRunSpecError(
                "production_single_update_not_yet_valid",
                "Production Run Spec is not yet valid",
            )
        if current_time >= run_spec.expires_at:
            raise ProductionSingleUpdateRunSpecError(
                "production_single_update_expired",
                "Production Run Spec has expired",
            )
    operation = run_spec.operation
    hash_values = (
        run_spec.target_fingerprint,
        run_spec.target_config_hash,
        run_spec.trusted_baseline_hash,
        run_spec.baseline_snapshot_hash,
        run_spec.manifest_hash,
        run_spec.source_sha256,
        run_spec.source_content_hash,
        run_spec.current_snapshot_hash,
        run_spec.diff_hash,
        run_spec.production_plan_hash,
        operation.pre_image_hash,
        operation.patch_hash,
        operation.operation_content_hash,
        run_spec.approval_material_hash,
        run_spec.run_spec_content_hash,
    )
    lifetime = (run_spec.expires_at - run_spec.issued_at).total_seconds()
    valid = (
        run_spec.schema_version == "1.0"
        and run_spec.run_type == "production-single-update-run-spec-v1"
        and run_spec.planning_mode == "production_single_update"
        and run_spec.production is True
        and run_spec.production_only is True
        and run_spec.synthetic is False
        and run_spec.single_update is True
        and run_spec.update_only is True
        and run_spec.executable is False
        and bool(run_spec.tool_version)
        and _clock_is_valid(run_spec.issued_at)
        and _clock_is_valid(run_spec.expires_at)
        and 0 < lifetime <= PRODUCTION_RUN_SPEC_MAX_LIFETIME_SECONDS
        and all(re.fullmatch(r"[0-9a-f]{64}", value) is not None for value in hash_values)
        and run_spec.target_safe_ref == f"T-{run_spec.target_fingerprint[:12]}"
        and run_spec.target_environment == "production"
        and run_spec.baseline_state == "trusted"
        and run_spec.baseline_snapshot_hash == run_spec.current_snapshot_hash
        and run_spec.source_event_count == run_spec.snapshot_event_count
        and run_spec.source_event_count >= 2
        and run_spec.unchanged_count == run_spec.source_event_count - 1
        and run_spec.operation_count == 1
        and run_spec.add_count == 0
        and run_spec.update_count == 1
        and run_spec.delete_count == 0
        and run_spec.changed_fields == PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
        and operation.operation == "update"
        and operation.changed_fields == PRODUCTION_SINGLE_UPDATE_CHANGED_FIELDS
        and run_spec.approval_required is True
    )
    if not valid:
        raise ProductionSingleUpdateRunSpecError(
            "production_single_update_run_spec_policy_mismatch",
            "Production Single Update Run Spec policy verification failed",
        )
    if not hmac.compare_digest(
        calculate_production_single_update_operation_hash(operation),
        operation.operation_content_hash,
    ):
        raise ProductionSingleUpdateRunSpecError(
            "production_single_update_operation_hash_mismatch",
            "Production operation integrity verification failed",
        )
    try:
        verify_production_approval_material_hash(
            run_spec,
            now=now,
            require_current=require_current,
        )
    except ProductionApprovalMaterialError as exc:
        raise ProductionSingleUpdateRunSpecError(exc.code, exc.public_message) from exc
    if not hmac.compare_digest(
        calculate_production_single_update_run_spec_hash(run_spec),
        run_spec.run_spec_content_hash,
    ):
        raise ProductionSingleUpdateRunSpecError(
            "production_single_update_run_spec_hash_mismatch",
            "Production Run Spec integrity verification failed",
        )


def verify_production_single_update_run_spec_bindings(
    run_spec: ProductionSingleUpdateRunSpec,
    plan: ProductionSingleUpdatePlan,
    *,
    now: datetime | None = None,
) -> None:
    """Verify every duplicated Plan/Run Spec field and both integrity envelopes."""

    verify_production_single_update_plan(plan)
    verify_production_single_update_run_spec(run_spec, now=now)
    operation = run_spec.operation
    if (
        run_spec.target_fingerprint != plan.target_fingerprint
        or run_spec.target_safe_ref != plan.target_safe_ref
        or run_spec.target_config_hash != plan.target_config_hash
        or run_spec.trusted_baseline_hash != plan.baseline_hash
        or run_spec.baseline_snapshot_hash != plan.baseline_snapshot_hash
        or run_spec.manifest_hash != plan.manifest_hash
        or run_spec.source_profile != plan.source_profile
        or run_spec.accepted_tag != plan.accepted_tag
        or run_spec.accepted_commit != plan.accepted_commit
        or run_spec.source_sha256 != plan.source_sha256
        or run_spec.source_content_hash != plan.source_content_hash
        or run_spec.source_event_count != plan.source_event_count
        or run_spec.current_snapshot_hash != plan.snapshot_hash
        or run_spec.snapshot_event_count != plan.snapshot_event_count
        or run_spec.diff_hash != plan.diff_hash
        or run_spec.production_plan_hash != plan.plan_content_hash
        or run_spec.unchanged_count != plan.unchanged_count
        or operation.safe_uid_ref != plan.safe_uid_ref
        or operation.google_ref != plan.google_ref
        or operation.pre_image_hash != plan.pre_image_hash
        or operation.patch_hash != plan.patch_hash
    ):
        raise ProductionSingleUpdateRunSpecError(
            "production_single_update_run_spec_binding_mismatch",
            "Production Plan and Run Spec do not match",
        )


def build_production_single_update_run_spec(
    manifest: AcceptedProductionSourceManifest,
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    current_snapshot: GoogleSnapshot,
    production_plan: ProductionSingleUpdatePlan,
    trusted_baseline: TrustedBaseline,
    target: ProductionWriteTargetConfig,
    *,
    issued_at: datetime,
    expires_at: datetime | None = None,
) -> ProductionSingleUpdateRunSpec:
    """Rebuild all inputs and produce one raw-free, non-executable Run Spec."""

    if not _clock_is_valid(issued_at):
        raise ProductionSingleUpdateRunSpecError(
            "production_single_update_clock_invalid",
            "Production Run Spec issue time must be UTC",
        )
    resolved_expiry = (
        issued_at + timedelta(seconds=PRODUCTION_RUN_SPEC_MAX_LIFETIME_SECONDS)
        if expires_at is None
        else expires_at
    )
    if not _clock_is_valid(resolved_expiry):
        raise ProductionSingleUpdateRunSpecError(
            "production_single_update_clock_invalid",
            "Production Run Spec expiry time must be UTC",
        )
    expected_plan = build_production_single_update_plan(
        manifest,
        profile,
        source,
        current_snapshot,
        trusted_baseline,
        target,
    )
    verify_production_single_update_plan(production_plan)
    if not hmac.compare_digest(
        expected_plan.plan_content_hash,
        production_plan.plan_content_hash,
    ):
        raise ProductionSingleUpdateRunSpecError(
            "production_single_update_plan_recomputation_mismatch",
            "Production Plan does not match canonical inputs",
        )
    operation_provisional = ProductionSingleUpdateOperation(
        safe_uid_ref=production_plan.safe_uid_ref,
        google_ref=production_plan.google_ref,
        pre_image_hash=production_plan.pre_image_hash,
        patch_hash=production_plan.patch_hash,
        operation_content_hash="0" * 64,
    )
    operation = operation_provisional.model_copy(
        update={
            "operation_content_hash": calculate_production_single_update_operation_hash(
                operation_provisional
            )
        }
    )
    provisional = ProductionSingleUpdateRunSpec(
        tool_version=tool_version(),
        issued_at=issued_at,
        expires_at=resolved_expiry,
        target_fingerprint=production_plan.target_fingerprint,
        target_safe_ref=production_plan.target_safe_ref,
        target_config_hash=production_plan.target_config_hash,
        trusted_baseline_hash=production_plan.baseline_hash,
        baseline_snapshot_hash=production_plan.baseline_snapshot_hash,
        manifest_hash=production_plan.manifest_hash,
        source_profile=production_plan.source_profile,
        accepted_tag=production_plan.accepted_tag,
        accepted_commit=production_plan.accepted_commit,
        source_sha256=production_plan.source_sha256,
        source_content_hash=production_plan.source_content_hash,
        source_event_count=production_plan.source_event_count,
        current_snapshot_hash=production_plan.snapshot_hash,
        snapshot_event_count=production_plan.snapshot_event_count,
        diff_hash=production_plan.diff_hash,
        production_plan_hash=production_plan.plan_content_hash,
        unchanged_count=production_plan.unchanged_count,
        operation=operation,
        approval_material_hash="0" * 64,
        run_spec_content_hash="0" * 64,
    )
    with_run_hash = provisional.model_copy(
        update={
            "run_spec_content_hash": calculate_production_single_update_run_spec_hash(provisional)
        }
    )
    run_spec = with_run_hash.model_copy(
        update={
            "approval_material_hash": calculate_production_approval_material_hash(with_run_hash)
        }
    )
    verify_production_single_update_run_spec_bindings(
        run_spec,
        production_plan,
        now=issued_at,
    )
    return run_spec


__all__ = [
    "ProductionSingleUpdateRunSpecError",
    "build_production_single_update_run_spec",
    "calculate_production_single_update_operation_hash",
    "calculate_production_single_update_run_spec_hash",
    "private_production_single_update_operation_data",
    "private_production_single_update_run_spec_data",
    "verify_production_single_update_run_spec",
    "verify_production_single_update_run_spec_bindings",
]
