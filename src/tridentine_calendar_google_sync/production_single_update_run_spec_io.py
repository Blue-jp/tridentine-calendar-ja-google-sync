"""Strict repository-external I/O for Production Single Update Run Specs."""

from __future__ import annotations

import hmac
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from tridentine_calendar_google_sync.production_single_update_run_spec import (
    ProductionSingleUpdateRunSpecError,
    private_production_single_update_run_spec_data,
    verify_production_single_update_run_spec,
)
from tridentine_calendar_google_sync.production_single_update_run_spec_models import (
    ProductionSingleUpdateOperation,
    ProductionSingleUpdateRunSpec,
)
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    read_sensitive_bytes,
)

MAX_PRODUCTION_SINGLE_UPDATE_RUN_SPEC_BYTES = 4 * 1024 * 1024


class ProductionSingleUpdateRunSpecIOError(ProductionSingleUpdateRunSpecError):
    """A content-free Production Run Spec parse or path failure."""


class _DuplicateJsonKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def _parse_datetime(value: object) -> datetime:
    if not isinstance(value, str):
        raise TypeError
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(normalized)


def render_production_single_update_run_spec_json(
    run_spec: ProductionSingleUpdateRunSpec,
    *,
    now: datetime | None = None,
    require_current: bool = True,
) -> str:
    """Render deterministic raw-content-free Run Spec JSON."""

    verify_production_single_update_run_spec(
        run_spec,
        now=now,
        require_current=require_current,
    )
    return (
        json.dumps(
            private_production_single_update_run_spec_data(run_spec),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def parse_production_single_update_run_spec_bytes(
    raw_bytes: bytes,
    *,
    now: datetime | None = None,
    require_current: bool = True,
) -> ProductionSingleUpdateRunSpec:
    """Parse one exact canonical unexpired Production Run Spec."""

    if len(raw_bytes) > MAX_PRODUCTION_SINGLE_UPDATE_RUN_SPEC_BYTES:
        raise ProductionSingleUpdateRunSpecIOError(
            "production_single_update_run_spec_too_large",
            "Production Single Update Run Spec exceeds the size limit",
        )
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict) or set(value) != set(
            ProductionSingleUpdateRunSpec.model_fields
        ):
            raise TypeError
        normalized = dict(value)
        normalized["issued_at"] = _parse_datetime(normalized.get("issued_at"))
        normalized["expires_at"] = _parse_datetime(normalized.get("expires_at"))
        raw_fields = normalized.get("changed_fields")
        if not isinstance(raw_fields, list):
            raise TypeError
        normalized["changed_fields"] = tuple(raw_fields)
        raw_operation = normalized.get("operation")
        if not isinstance(raw_operation, dict) or set(raw_operation) != set(
            ProductionSingleUpdateOperation.model_fields
        ):
            raise TypeError
        operation_data = dict(raw_operation)
        operation_fields = operation_data.get("changed_fields")
        if not isinstance(operation_fields, list):
            raise TypeError
        operation_data["changed_fields"] = tuple(operation_fields)
        normalized["operation"] = ProductionSingleUpdateOperation.model_validate(
            operation_data,
            strict=True,
        )
        run_spec = ProductionSingleUpdateRunSpec.model_validate(normalized, strict=True)
        verify_production_single_update_run_spec(
            run_spec,
            now=now,
            require_current=require_current,
        )
        canonical = render_production_single_update_run_spec_json(
            run_spec,
            now=now,
            require_current=require_current,
        ).encode("utf-8")
        if not hmac.compare_digest(raw_bytes, canonical):
            raise ValueError
        return run_spec
    except (ProductionSingleUpdateRunSpecError, ProductionSingleUpdateRunSpecIOError):
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise ProductionSingleUpdateRunSpecIOError(
            "invalid_production_single_update_run_spec",
            "Production Single Update Run Spec is invalid or noncanonical",
        ) from exc


def load_production_single_update_run_spec(
    path: str | Path,
    *,
    now: datetime | None = None,
    require_current: bool = True,
) -> ProductionSingleUpdateRunSpec:
    """Load one bounded repository-external unexpired Run Spec."""

    try:
        return parse_production_single_update_run_spec_bytes(
            read_sensitive_bytes(path, max_size=MAX_PRODUCTION_SINGLE_UPDATE_RUN_SPEC_BYTES),
            now=now,
            require_current=require_current,
        )
    except ProductionSingleUpdateRunSpecError:
        raise
    except SensitivePathError as exc:
        raise ProductionSingleUpdateRunSpecIOError(
            "unsafe_production_single_update_run_spec_path",
            "Production Single Update Run Spec path is unsafe or unavailable",
        ) from exc


def write_production_single_update_run_spec(
    run_spec: ProductionSingleUpdateRunSpec,
    path: str | Path,
    *,
    now: datetime | None = None,
) -> Path:
    """Atomically create one private Run Spec without overwrite."""

    rendered = render_production_single_update_run_spec_json(
        run_spec,
        now=now,
        require_current=True,
    )
    try:
        atomic_write_private_text(
            path,
            rendered,
            overwrite=False,
            max_size=MAX_PRODUCTION_SINGLE_UPDATE_RUN_SPEC_BYTES,
        )
        return Path(path)
    except SensitivePathError as exc:
        raise ProductionSingleUpdateRunSpecIOError(
            "production_single_update_run_spec_write_failed",
            "Production Single Update Run Spec could not be written safely",
        ) from exc


__all__ = [
    "MAX_PRODUCTION_SINGLE_UPDATE_RUN_SPEC_BYTES",
    "ProductionSingleUpdateRunSpecIOError",
    "load_production_single_update_run_spec",
    "parse_production_single_update_run_spec_bytes",
    "render_production_single_update_run_spec_json",
    "write_production_single_update_run_spec",
]
