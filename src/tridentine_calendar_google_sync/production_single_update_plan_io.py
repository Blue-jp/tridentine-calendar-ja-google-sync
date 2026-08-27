"""Strict repository-external I/O for Production Single Update Plans."""

from __future__ import annotations

import hmac
import json
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from tridentine_calendar_google_sync.production_single_update_plan import (
    ProductionSingleUpdatePlanError,
    private_production_single_update_plan_data,
    verify_production_single_update_plan,
)
from tridentine_calendar_google_sync.production_single_update_plan_models import (
    ProductionSingleUpdatePlan,
)
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    read_sensitive_bytes,
)

MAX_PRODUCTION_SINGLE_UPDATE_PLAN_BYTES = 4 * 1024 * 1024


class ProductionSingleUpdatePlanIOError(ProductionSingleUpdatePlanError):
    """A content-free Production Plan parse or path failure."""


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


def render_production_single_update_plan_json(plan: ProductionSingleUpdatePlan) -> str:
    """Render deterministic raw-content-free Plan JSON."""

    verify_production_single_update_plan(plan)
    return (
        json.dumps(
            private_production_single_update_plan_data(plan),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def parse_production_single_update_plan_bytes(raw_bytes: bytes) -> ProductionSingleUpdatePlan:
    """Parse one exact canonical Production Plan document."""

    if len(raw_bytes) > MAX_PRODUCTION_SINGLE_UPDATE_PLAN_BYTES:
        raise ProductionSingleUpdatePlanIOError(
            "production_single_update_plan_too_large",
            "Production Single Update Plan exceeds the size limit",
        )
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict) or set(value) != set(
            ProductionSingleUpdatePlan.model_fields
        ):
            raise TypeError
        normalized = dict(value)
        raw_fields = normalized.get("changed_fields")
        if not isinstance(raw_fields, list):
            raise TypeError
        normalized["changed_fields"] = tuple(raw_fields)
        plan = ProductionSingleUpdatePlan.model_validate(normalized, strict=True)
        verify_production_single_update_plan(plan)
        if not hmac.compare_digest(
            raw_bytes,
            render_production_single_update_plan_json(plan).encode("utf-8"),
        ):
            raise ValueError
        return plan
    except (ProductionSingleUpdatePlanError, ProductionSingleUpdatePlanIOError):
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise ProductionSingleUpdatePlanIOError(
            "invalid_production_single_update_plan",
            "Production Single Update Plan is invalid or noncanonical",
        ) from exc


def load_production_single_update_plan(path: str | Path) -> ProductionSingleUpdatePlan:
    """Load one bounded repository-external Production Plan."""

    try:
        return parse_production_single_update_plan_bytes(
            read_sensitive_bytes(path, max_size=MAX_PRODUCTION_SINGLE_UPDATE_PLAN_BYTES)
        )
    except ProductionSingleUpdatePlanError:
        raise
    except SensitivePathError as exc:
        raise ProductionSingleUpdatePlanIOError(
            "unsafe_production_single_update_plan_path",
            "Production Single Update Plan path is unsafe or unavailable",
        ) from exc


def write_production_single_update_plan(
    plan: ProductionSingleUpdatePlan,
    path: str | Path,
) -> Path:
    """Atomically create one private Plan without overwrite."""

    rendered = render_production_single_update_plan_json(plan)
    try:
        atomic_write_private_text(
            path,
            rendered,
            overwrite=False,
            max_size=MAX_PRODUCTION_SINGLE_UPDATE_PLAN_BYTES,
        )
        return Path(path)
    except SensitivePathError as exc:
        raise ProductionSingleUpdatePlanIOError(
            "production_single_update_plan_write_failed",
            "Production Single Update Plan could not be written safely",
        ) from exc


__all__ = [
    "MAX_PRODUCTION_SINGLE_UPDATE_PLAN_BYTES",
    "ProductionSingleUpdatePlanIOError",
    "load_production_single_update_plan",
    "parse_production_single_update_plan_bytes",
    "render_production_single_update_plan_json",
    "write_production_single_update_plan",
]
