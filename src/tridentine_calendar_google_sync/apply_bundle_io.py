"""Strict private JSON parsing and atomic test-only apply bundle storage."""

from __future__ import annotations

import json
from datetime import date, datetime
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from tridentine_calendar_google_sync.apply_bundle import (
    private_bundle_data,
    verify_apply_bundle_integrity,
)
from tridentine_calendar_google_sync.apply_models import (
    ApplyAddPayload,
    ApplyBundle,
    ApplyBundleState,
    ApplyEnvironment,
    ApplyOperation,
    ApplyOperationKind,
    ApplyTimeBoundary,
    ApplyUpdatePayload,
)
from tridentine_calendar_google_sync.apply_policy import (
    ApplyError,
    ApplyGuardError,
    ApplyIOError,
    ApplyValidationError,
)
from tridentine_calendar_google_sync.plan_models import ChangedFieldName, PlanState
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    read_sensitive_bytes,
)

MAX_APPLY_BUNDLE_BYTES = 64 * 1024 * 1024


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


def _parse_time(value: object) -> ApplyTimeBoundary:
    if not isinstance(value, dict) or set(value) != {"date", "dateTime"}:
        raise TypeError
    raw_date = value["date"]
    raw_datetime = value["dateTime"]
    parsed_date = date.fromisoformat(raw_date) if isinstance(raw_date, str) else None
    parsed_datetime = None
    if isinstance(raw_datetime, str):
        normalized = raw_datetime[:-1] + "+00:00" if raw_datetime.endswith("Z") else raw_datetime
        parsed_datetime = datetime.fromisoformat(normalized)
    if raw_date is not None and not isinstance(raw_date, str):
        raise TypeError
    if raw_datetime is not None and not isinstance(raw_datetime, str):
        raise TypeError
    return ApplyTimeBoundary(date=parsed_date, date_time=parsed_datetime)


def _parse_payload(value: object) -> ApplyAddPayload | ApplyUpdatePayload:
    if not isinstance(value, dict):
        raise TypeError
    payload_type = value.get("payload_type")
    if payload_type == "add":
        if set(value) != {
            "payload_type",
            "uid",
            "summary",
            "description",
            "start",
            "effective_end",
            "all_day",
            "event_type",
        }:
            raise TypeError
        return ApplyAddPayload(
            uid=value["uid"],
            summary=value["summary"],
            description=value["description"],
            start=_parse_time(value["start"]),
            effective_end=_parse_time(value["effective_end"]),
            all_day=value["all_day"],
            event_type=value["event_type"],
        )
    if payload_type != "update":
        raise TypeError
    allowed = {
        "payload_type",
        "event_id",
        "etag",
        "changed_fields",
        "summary",
        "description",
        "start",
        "effective_end",
    }
    if not set(value).issubset(allowed):
        raise TypeError
    changed = value.get("changed_fields")
    if not isinstance(changed, list):
        raise TypeError
    event_id = value.get("event_id")
    etag = value.get("etag")
    if not isinstance(event_id, str) or not isinstance(etag, str):
        raise TypeError
    fields = cast(tuple[ChangedFieldName, ...], tuple(changed))
    return ApplyUpdatePayload(
        event_id=event_id,
        etag=etag,
        changed_fields=fields,
        summary=value.get("summary"),
        description=value.get("description"),
        start=_parse_time(value["start"]) if "start" in value else None,
        effective_end=(_parse_time(value["effective_end"]) if "effective_end" in value else None),
    )


def _parse_operation(value: object) -> ApplyOperation:
    if not isinstance(value, dict):
        raise TypeError
    expected = {
        "operation",
        "operation_sequence",
        "source_ref",
        "google_ref",
        "start_date",
        "changed_fields",
        "source_event_hash",
        "before_hash",
        "after_hash",
        "payload_hash",
        "source_uid",
        "payload",
        "destructive",
        "approval_required",
        "operation_integrity_hash",
    }
    if set(value) != expected:
        raise TypeError
    changed = value["changed_fields"]
    if not isinstance(changed, list):
        raise TypeError
    return ApplyOperation(
        operation=ApplyOperationKind(value["operation"]),
        operation_sequence=value["operation_sequence"],
        source_ref=value["source_ref"],
        google_ref=value["google_ref"],
        start_date=date.fromisoformat(value["start_date"]),
        changed_fields=cast(tuple[ChangedFieldName, ...], tuple(changed)),
        source_event_hash=value["source_event_hash"],
        before_hash=value["before_hash"],
        after_hash=value["after_hash"],
        payload_hash=value["payload_hash"],
        source_uid=value["source_uid"],
        payload=_parse_payload(value["payload"]),
        destructive=value["destructive"],
        approval_required=value["approval_required"],
        operation_integrity_hash=value["operation_integrity_hash"],
    )


def render_apply_bundle_json(bundle: ApplyBundle) -> str:
    """Render exact private JSON; this includes raw identifiers and payload data."""

    verify_apply_bundle_integrity(bundle)
    return (
        json.dumps(
            private_bundle_data(bundle),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def parse_apply_bundle_bytes(raw_bytes: bytes) -> ApplyBundle:
    """Parse and integrity-check one closed-schema private apply bundle."""

    if len(raw_bytes) > MAX_APPLY_BUNDLE_BYTES:
        raise ApplyIOError("apply_bundle_too_large", "apply bundle exceeds the size limit")
    try:
        decoded = raw_bytes.decode("utf-8", errors="strict")
        value = json.loads(
            decoded,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict):
            raise TypeError
        if value.get("schema_version") != "1.0":
            raise ApplyValidationError(
                "unsupported_apply_bundle_schema",
                "apply bundle schema version is unsupported",
            )
        normalized = dict(value)
        raw_operations = normalized.get("operations")
        if not isinstance(raw_operations, list):
            raise TypeError
        raw_state = normalized.get("state")
        raw_environment = normalized.get("environment")
        raw_plan_state = normalized.get("plan_state")
        if not all(isinstance(item, str) for item in (raw_state, raw_environment, raw_plan_state)):
            raise TypeError
        assert isinstance(raw_state, str)
        assert isinstance(raw_environment, str)
        assert isinstance(raw_plan_state, str)
        normalized.update(
            {
                "state": ApplyBundleState(raw_state),
                "environment": ApplyEnvironment(raw_environment),
                "plan_state": PlanState(raw_plan_state),
                "operations": tuple(_parse_operation(item) for item in raw_operations),
            }
        )
        bundle = ApplyBundle.model_validate(normalized, strict=True)
        verify_apply_bundle_integrity(bundle)
        return bundle
    except ApplyError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        KeyError,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise ApplyValidationError(
            "invalid_apply_bundle",
            "apply bundle is invalid",
        ) from exc


def load_apply_bundle(path: str | Path) -> ApplyBundle:
    """Load one explicit private repository-external bundle path."""

    try:
        return parse_apply_bundle_bytes(read_sensitive_bytes(path, max_size=MAX_APPLY_BUNDLE_BYTES))
    except ApplyError:
        raise
    except SensitivePathError as exc:
        raise ApplyIOError(
            "unsafe_apply_bundle_path",
            "apply bundle path is unsafe or unavailable",
        ) from exc


def write_apply_bundle(bundle: ApplyBundle, path: str | Path) -> Path:
    """Atomically create a test-only private bundle without overwrite."""

    if bundle.environment is ApplyEnvironment.PRODUCTION:
        raise ApplyGuardError(
            "production_apply_bundle_write_forbidden",
            "Production apply bundles cannot be written",
        )
    try:
        atomic_write_private_text(
            path,
            render_apply_bundle_json(bundle),
            overwrite=False,
            max_size=MAX_APPLY_BUNDLE_BYTES,
        )
        return Path(path)
    except ApplyError:
        raise
    except SensitivePathError as exc:
        raise ApplyIOError(
            "apply_bundle_write_failed",
            "apply bundle could not be written safely",
        ) from exc


__all__ = [
    "MAX_APPLY_BUNDLE_BYTES",
    "load_apply_bundle",
    "parse_apply_bundle_bytes",
    "render_apply_bundle_json",
    "write_apply_bundle",
]
