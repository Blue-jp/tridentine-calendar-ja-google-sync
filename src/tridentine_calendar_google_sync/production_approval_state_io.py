"""Strict repository-external I/O and atomic one-time permit consumption."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from tridentine_calendar_google_sync.production_approval_state import (
    ProductionApprovalStateError,
    build_production_permit_consumption,
    calculate_phase6c_mock_approval_store_hash,
    private_production_arm_receipt_data,
    private_production_execute_permit_data,
    private_production_kill_switch_data,
    private_production_permit_consumption_data,
    verify_phase6c_mock_approval_store,
    verify_production_arm_receipt_integrity,
    verify_production_execute_permit_integrity,
    verify_production_kill_switch,
    verify_production_permit_consumption,
)
from tridentine_calendar_google_sync.production_approval_state_models import (
    ProductionArmReceipt,
    ProductionExecutePermit,
    ProductionExecutePermitConsumption,
    ProductionKillSwitch,
    ProductionMockApprovalStore,
)
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    read_sensitive_bytes,
    validate_sensitive_output_path,
)

MAX_PRODUCTION_APPROVAL_STATE_BYTES = 64 * 1024


class ProductionApprovalStateIOError(ProductionApprovalStateError):
    """A content- and path-free parsing, storage, or consumption failure."""


class _DuplicateJsonKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _closed(value: object, expected: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise TypeError
    return cast(dict[str, Any], value)


def _decode(raw_bytes: bytes, expected: set[str]) -> dict[str, Any]:
    if len(raw_bytes) > MAX_PRODUCTION_APPROVAL_STATE_BYTES:
        raise ProductionApprovalStateIOError(
            "production_approval_state_too_large",
            "Production approval state is too large",
        )
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        return _closed(value, expected)
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        TypeError,
        ValueError,
    ) as exc:
        raise ProductionApprovalStateIOError(
            "invalid_production_approval_state",
            "Production approval state is invalid or noncanonical",
        ) from exc


def _render(data: dict[str, object]) -> str:
    return json.dumps(data, ensure_ascii=False, indent=2, sort_keys=False) + "\n"


def _require_canonical(raw_bytes: bytes, rendered: str) -> None:
    if not hmac.compare_digest(raw_bytes, rendered.encode("utf-8")):
        raise ProductionApprovalStateIOError(
            "noncanonical_production_approval_state",
            "Production approval state is invalid or noncanonical",
        )


_MOCK_STORE_DIRECTORY_DOMAIN = (
    b"tridentine-calendar-google-sync:phase6c-mock-store-directory:v1\x00"
)


def _directory_identity_hash(directory: str | Path) -> str:
    path = Path(directory)
    try:
        validate_sensitive_output_path(
            path / ".phase6c-mock-store-attestation",
            overwrite=True,
        )
        resolved = path.resolve(strict=True)
        stat_result = resolved.stat()
        canonical = os.path.normcase(os.fspath(resolved))
        payload = json.dumps(
            {
                "canonical_directory": canonical,
                "device": stat_result.st_dev,
                "inode": stat_result.st_ino,
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (OSError, SensitivePathError, TypeError, ValueError) as exc:
        raise ProductionApprovalStateIOError(
            "phase6c_mock_approval_store_directory_invalid",
            "Phase 6C mock approval store directory is invalid",
        ) from exc
    return hashlib.sha256(_MOCK_STORE_DIRECTORY_DOMAIN + payload).hexdigest()


def build_phase6c_mock_approval_store(
    directory: str | Path,
) -> ProductionMockApprovalStore:
    """Attest one existing external directory as mock-only, without a DACL claim."""

    identity_hash = _directory_identity_hash(directory)
    provisional = ProductionMockApprovalStore(
        directory_identity_hash=identity_hash,
        store_safe_ref=f"S-{identity_hash[:12]}",
        content_hash="0" * 64,
    )
    store = provisional.model_copy(
        update={"content_hash": calculate_phase6c_mock_approval_store_hash(provisional)}
    )
    verify_phase6c_mock_approval_store_directory(store, directory)
    return store


def verify_phase6c_mock_approval_store_directory(
    store: ProductionMockApprovalStore,
    directory: str | Path,
) -> None:
    """Re-attest the exact directory; Phase 6D must provide a separate DACL store."""

    verify_phase6c_mock_approval_store(store)
    if not hmac.compare_digest(store.directory_identity_hash, _directory_identity_hash(directory)):
        raise ProductionApprovalStateIOError(
            "phase6c_mock_approval_store_directory_mismatch",
            "Phase 6C mock approval store directory does not match",
        )


def _verify_store_path(
    store: ProductionMockApprovalStore,
    path: str | Path,
) -> None:
    verify_phase6c_mock_approval_store_directory(store, Path(path).parent)


def _read(
    path: str | Path,
    *,
    approval_store: ProductionMockApprovalStore,
) -> bytes:
    _verify_store_path(approval_store, path)
    try:
        return read_sensitive_bytes(path, max_size=MAX_PRODUCTION_APPROVAL_STATE_BYTES)
    except SensitivePathError as exc:
        raise ProductionApprovalStateIOError(
            "unsafe_production_approval_state_path",
            "Production approval state path is unsafe or unavailable",
        ) from exc


def _write(
    path: str | Path,
    text: str,
    *,
    approval_store: ProductionMockApprovalStore,
) -> Path:
    _verify_store_path(approval_store, path)
    try:
        atomic_write_private_text(
            path,
            text,
            overwrite=False,
            max_size=MAX_PRODUCTION_APPROVAL_STATE_BYTES,
        )
        return Path(path)
    except SensitivePathError as exc:
        raise ProductionApprovalStateIOError(
            "production_approval_state_write_failed",
            "Production approval state could not be written safely",
        ) from exc


def render_production_kill_switch_json(kill_switch: ProductionKillSwitch) -> str:
    verify_production_kill_switch(kill_switch)
    return _render(private_production_kill_switch_data(kill_switch))


def parse_production_kill_switch_bytes(raw_bytes: bytes) -> ProductionKillSwitch:
    data = _decode(
        raw_bytes,
        {
            "schema_version",
            "switch_type",
            "state",
            "generation",
            "transition_kind",
            "previous_switch_hash",
            "target_safe_ref",
            "issued_at",
            "content_hash",
        },
    )
    try:
        result = ProductionKillSwitch(
            schema_version=data["schema_version"],
            switch_type=data["switch_type"],
            state=data["state"],
            generation=data["generation"],
            transition_kind=data["transition_kind"],
            previous_switch_hash=data["previous_switch_hash"],
            target_safe_ref=data["target_safe_ref"],
            issued_at=datetime.fromisoformat(data["issued_at"]),
            content_hash=data["content_hash"],
        )
        verify_production_kill_switch(result)
        rendered = render_production_kill_switch_json(result)
        _require_canonical(raw_bytes, rendered)
        return result
    except ProductionApprovalStateError:
        raise
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise ProductionApprovalStateIOError(
            "invalid_production_kill_switch",
            "Production kill-switch state is invalid or noncanonical",
        ) from exc


def load_production_kill_switch(
    path: str | Path,
    *,
    approval_store: ProductionMockApprovalStore,
) -> ProductionKillSwitch:
    return parse_production_kill_switch_bytes(_read(path, approval_store=approval_store))


def write_production_kill_switch(
    kill_switch: ProductionKillSwitch,
    path: str | Path,
    *,
    approval_store: ProductionMockApprovalStore,
) -> Path:
    return _write(
        path,
        render_production_kill_switch_json(kill_switch),
        approval_store=approval_store,
    )


_ARM_FIELDS = {
    "schema_version",
    "receipt_type",
    "production",
    "target_safe_ref",
    "run_spec_hash",
    "plan_hash",
    "manifest_hash",
    "source_sha256",
    "trusted_baseline_hash",
    "snapshot_hash",
    "operation_count",
    "add_count",
    "update_count",
    "delete_count",
    "changed_fields",
    "patch_hash",
    "approval_material_hash",
    "approval_store_hash",
    "arm_nonce",
    "kill_switch_generation",
    "write_token_generation",
    "issued_at",
    "expires_at",
    "content_hash",
}


def render_production_arm_receipt_json(receipt: ProductionArmReceipt) -> str:
    verify_production_arm_receipt_integrity(receipt, require_current=False)
    return _render(private_production_arm_receipt_data(receipt))


def parse_production_arm_receipt_bytes(
    raw_bytes: bytes,
    *,
    now: datetime | None = None,
    require_current: bool = True,
) -> ProductionArmReceipt:
    data = _decode(raw_bytes, _ARM_FIELDS)
    try:
        raw_changed_fields = data["changed_fields"]
        if not isinstance(raw_changed_fields, list):
            raise TypeError
        result = ProductionArmReceipt(
            schema_version=data["schema_version"],
            receipt_type=data["receipt_type"],
            production=data["production"],
            target_safe_ref=data["target_safe_ref"],
            run_spec_hash=data["run_spec_hash"],
            plan_hash=data["plan_hash"],
            manifest_hash=data["manifest_hash"],
            source_sha256=data["source_sha256"],
            trusted_baseline_hash=data["trusted_baseline_hash"],
            snapshot_hash=data["snapshot_hash"],
            operation_count=data["operation_count"],
            add_count=data["add_count"],
            update_count=data["update_count"],
            delete_count=data["delete_count"],
            changed_fields=tuple(raw_changed_fields),
            patch_hash=data["patch_hash"],
            approval_material_hash=data["approval_material_hash"],
            approval_store_hash=data["approval_store_hash"],
            arm_nonce=data["arm_nonce"],
            kill_switch_generation=data["kill_switch_generation"],
            write_token_generation=data["write_token_generation"],
            issued_at=datetime.fromisoformat(data["issued_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            content_hash=data["content_hash"],
        )
        verify_production_arm_receipt_integrity(
            result,
            now=now,
            require_current=require_current,
        )
        rendered = render_production_arm_receipt_json(result)
        _require_canonical(raw_bytes, rendered)
        return result
    except ProductionApprovalStateError:
        raise
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise ProductionApprovalStateIOError(
            "invalid_production_arm_receipt",
            "Production ARM receipt is invalid or noncanonical",
        ) from exc


def load_production_arm_receipt(
    path: str | Path,
    *,
    approval_store: ProductionMockApprovalStore,
    now: datetime | None = None,
    require_current: bool = True,
) -> ProductionArmReceipt:
    result = parse_production_arm_receipt_bytes(
        _read(path, approval_store=approval_store),
        now=now,
        require_current=require_current,
    )
    if not hmac.compare_digest(result.approval_store_hash, approval_store.content_hash):
        raise ProductionApprovalStateIOError(
            "phase6c_mock_approval_store_binding_mismatch",
            "Production ARM receipt store binding does not match",
        )
    return result


def write_production_arm_receipt(
    receipt: ProductionArmReceipt,
    path: str | Path,
    *,
    approval_store: ProductionMockApprovalStore,
) -> Path:
    if not hmac.compare_digest(receipt.approval_store_hash, approval_store.content_hash):
        raise ProductionApprovalStateIOError(
            "phase6c_mock_approval_store_binding_mismatch",
            "Production ARM receipt store binding does not match",
        )
    return _write(
        path,
        render_production_arm_receipt_json(receipt),
        approval_store=approval_store,
    )


_PERMIT_FIELDS = {
    "schema_version",
    "permit_type",
    "production",
    "arm_receipt_hash",
    "run_spec_hash",
    "target_safe_ref",
    "operation_count",
    "add_count",
    "update_count",
    "delete_count",
    "changed_fields",
    "patch_hash",
    "approval_store_hash",
    "arm_nonce",
    "execute_nonce",
    "kill_switch_generation",
    "write_token_generation",
    "issued_at",
    "expires_at",
    "one_time",
    "consumed",
    "content_hash",
}


def render_production_execute_permit_json(permit: ProductionExecutePermit) -> str:
    verify_production_execute_permit_integrity(permit, require_current=False)
    return _render(private_production_execute_permit_data(permit))


def parse_production_execute_permit_bytes(
    raw_bytes: bytes,
    *,
    now: datetime | None = None,
    require_current: bool = True,
) -> ProductionExecutePermit:
    data = _decode(raw_bytes, _PERMIT_FIELDS)
    try:
        raw_changed_fields = data["changed_fields"]
        if not isinstance(raw_changed_fields, list):
            raise TypeError
        result = ProductionExecutePermit(
            schema_version=data["schema_version"],
            permit_type=data["permit_type"],
            production=data["production"],
            arm_receipt_hash=data["arm_receipt_hash"],
            run_spec_hash=data["run_spec_hash"],
            target_safe_ref=data["target_safe_ref"],
            operation_count=data["operation_count"],
            add_count=data["add_count"],
            update_count=data["update_count"],
            delete_count=data["delete_count"],
            changed_fields=tuple(raw_changed_fields),
            patch_hash=data["patch_hash"],
            approval_store_hash=data["approval_store_hash"],
            arm_nonce=data["arm_nonce"],
            execute_nonce=data["execute_nonce"],
            kill_switch_generation=data["kill_switch_generation"],
            write_token_generation=data["write_token_generation"],
            issued_at=datetime.fromisoformat(data["issued_at"]),
            expires_at=datetime.fromisoformat(data["expires_at"]),
            one_time=data["one_time"],
            consumed=data["consumed"],
            content_hash=data["content_hash"],
        )
        verify_production_execute_permit_integrity(
            result,
            now=now,
            require_current=require_current,
        )
        rendered = render_production_execute_permit_json(result)
        _require_canonical(raw_bytes, rendered)
        return result
    except ProductionApprovalStateError:
        raise
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise ProductionApprovalStateIOError(
            "invalid_production_execute_permit",
            "Production EXECUTE permit is invalid or noncanonical",
        ) from exc


def load_production_execute_permit(
    path: str | Path,
    *,
    approval_store: ProductionMockApprovalStore,
    now: datetime | None = None,
    require_current: bool = True,
) -> ProductionExecutePermit:
    result = parse_production_execute_permit_bytes(
        _read(path, approval_store=approval_store),
        now=now,
        require_current=require_current,
    )
    if not hmac.compare_digest(result.approval_store_hash, approval_store.content_hash):
        raise ProductionApprovalStateIOError(
            "phase6c_mock_approval_store_binding_mismatch",
            "Production EXECUTE permit store binding does not match",
        )
    return result


def write_production_execute_permit(
    permit: ProductionExecutePermit,
    path: str | Path,
    *,
    approval_store: ProductionMockApprovalStore,
) -> Path:
    if not hmac.compare_digest(permit.approval_store_hash, approval_store.content_hash):
        raise ProductionApprovalStateIOError(
            "phase6c_mock_approval_store_binding_mismatch",
            "Production EXECUTE permit store binding does not match",
        )
    return _write(
        path,
        render_production_execute_permit_json(permit),
        approval_store=approval_store,
    )


_CONSUMPTION_FIELDS = {
    "schema_version",
    "state_type",
    "state",
    "permit_hash",
    "approval_store_hash",
    "target_safe_ref",
    "consumed_at",
    "content_hash",
}


def render_production_permit_consumption_json(
    consumption: ProductionExecutePermitConsumption,
) -> str:
    verify_production_permit_consumption(consumption)
    return _render(private_production_permit_consumption_data(consumption))


def parse_production_permit_consumption_bytes(
    raw_bytes: bytes,
    *,
    permit: ProductionExecutePermit | None = None,
) -> ProductionExecutePermitConsumption:
    data = _decode(raw_bytes, _CONSUMPTION_FIELDS)
    try:
        result = ProductionExecutePermitConsumption(
            schema_version=data["schema_version"],
            state_type=data["state_type"],
            state=data["state"],
            permit_hash=data["permit_hash"],
            approval_store_hash=data["approval_store_hash"],
            target_safe_ref=data["target_safe_ref"],
            consumed_at=datetime.fromisoformat(data["consumed_at"]),
            content_hash=data["content_hash"],
        )
        verify_production_permit_consumption(result, permit=permit)
        rendered = render_production_permit_consumption_json(result)
        _require_canonical(raw_bytes, rendered)
        return result
    except ProductionApprovalStateError:
        raise
    except (KeyError, TypeError, ValueError, ValidationError) as exc:
        raise ProductionApprovalStateIOError(
            "invalid_production_execute_consumption",
            "Production EXECUTE permit consumption is invalid or noncanonical",
        ) from exc


def load_production_execute_permit_consumption(
    path: str | Path,
    *,
    approval_store: ProductionMockApprovalStore,
    permit: ProductionExecutePermit | None = None,
) -> ProductionExecutePermitConsumption:
    result = parse_production_permit_consumption_bytes(
        _read(path, approval_store=approval_store),
        permit=permit,
    )
    if not hmac.compare_digest(result.approval_store_hash, approval_store.content_hash):
        raise ProductionApprovalStateIOError(
            "phase6c_mock_approval_store_binding_mismatch",
            "Production consumption store binding does not match",
        )
    return result


def production_execute_permit_consumption_filename(
    permit: ProductionExecutePermit,
) -> str:
    """Return the canonical ledger key so one permit cannot select a new filename."""

    verify_production_execute_permit_integrity(permit, require_current=False)
    return f"production-execute-permit-{permit.content_hash}.consumed.json"


def consume_production_execute_permit(
    permit: ProductionExecutePermit,
    path: str | Path,
    *,
    approval_store: ProductionMockApprovalStore,
    consumed_at: datetime,
) -> ProductionExecutePermitConsumption:
    """Atomically publish durable consumed state; no overwrite permits one winner."""

    resolved_path = Path(path)
    _verify_store_path(approval_store, resolved_path)
    if not hmac.compare_digest(permit.approval_store_hash, approval_store.content_hash):
        raise ProductionApprovalStateIOError(
            "phase6c_mock_approval_store_binding_mismatch",
            "Production EXECUTE permit store binding does not match",
        )
    if resolved_path.name != production_execute_permit_consumption_filename(permit):
        raise ProductionApprovalStateIOError(
            "production_execute_consumption_path_mismatch",
            "Production EXECUTE consumption path does not match the permit",
        )
    consumption = build_production_permit_consumption(permit, consumed_at=consumed_at)
    try:
        atomic_write_private_text(
            path,
            render_production_permit_consumption_json(consumption),
            overwrite=False,
            max_size=MAX_PRODUCTION_APPROVAL_STATE_BYTES,
        )
    except SensitivePathError as exc:
        code = (
            "production_execute_permit_already_consumed"
            if exc.code == "sensitive_output_exists"
            else "production_execute_consumption_failed"
        )
        message = (
            "Production EXECUTE permit has already been consumed"
            if code == "production_execute_permit_already_consumed"
            else "Production EXECUTE permit could not be consumed safely"
        )
        raise ProductionApprovalStateIOError(code, message) from exc
    return consumption


__all__ = [
    "MAX_PRODUCTION_APPROVAL_STATE_BYTES",
    "ProductionApprovalStateIOError",
    "build_phase6c_mock_approval_store",
    "consume_production_execute_permit",
    "load_production_arm_receipt",
    "load_production_execute_permit",
    "load_production_execute_permit_consumption",
    "load_production_kill_switch",
    "parse_production_arm_receipt_bytes",
    "parse_production_execute_permit_bytes",
    "parse_production_kill_switch_bytes",
    "parse_production_permit_consumption_bytes",
    "production_execute_permit_consumption_filename",
    "render_production_arm_receipt_json",
    "render_production_execute_permit_json",
    "render_production_kill_switch_json",
    "render_production_permit_consumption_json",
    "verify_phase6c_mock_approval_store_directory",
    "write_production_arm_receipt",
    "write_production_execute_permit",
    "write_production_kill_switch",
]
