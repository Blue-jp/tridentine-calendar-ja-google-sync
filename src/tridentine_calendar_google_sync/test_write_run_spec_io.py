"""Strict private JSON I/O for one-operation Test write Run Specs."""

from __future__ import annotations

import hmac
import json
from datetime import date
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from tridentine_calendar_google_sync.plan_models import ChangedFieldName
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    read_sensitive_bytes,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteManagedState,
    TestWriteOperation,
    TestWriteOperationKind,
    TestWriteRunSpec,
)
from tridentine_calendar_google_sync.test_write_run_spec import (
    TestWriteRunSpecError,
    private_test_write_run_spec_data,
    verify_test_write_run_spec,
)

MAX_TEST_WRITE_RUN_SPEC_BYTES = 64 * 1024 * 1024


class TestWriteRunSpecIOError(TestWriteRunSpecError):
    """A safe private Run Spec parsing, canonicalization, or path failure."""


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


def _managed_state(value: object) -> TestWriteManagedState:
    data = _closed(
        value,
        {
            "iCalUID",
            "summary",
            "description",
            "start_date",
            "end_date",
            "all_day",
            "event_type",
        },
    )
    if not isinstance(data["start_date"], str) or not isinstance(data["end_date"], str):
        raise TypeError
    return TestWriteManagedState(
        ical_uid=data["iCalUID"],
        summary=data["summary"],
        description=data["description"],
        start_date=date.fromisoformat(data["start_date"]),
        end_date=date.fromisoformat(data["end_date"]),
        all_day=data["all_day"],
        event_type=data["event_type"],
    )


def _operation(value: object) -> TestWriteOperation:
    data = _closed(
        value,
        {
            "operation",
            "source_ref",
            "google_ref",
            "changed_fields",
            "current_state",
            "desired_state",
            "google_event_id",
            "expected_etag",
            "operation_content_hash",
        },
    )
    raw_changed_fields = data["changed_fields"]
    if not isinstance(raw_changed_fields, list):
        raise TypeError
    return TestWriteOperation(
        operation=TestWriteOperationKind(data["operation"]),
        source_ref=data["source_ref"],
        google_ref=data["google_ref"],
        changed_fields=cast(tuple[ChangedFieldName, ...], tuple(raw_changed_fields)),
        current_state=(
            _managed_state(data["current_state"]) if data["current_state"] is not None else None
        ),
        desired_state=_managed_state(data["desired_state"]),
        google_event_id=data["google_event_id"],
        expected_etag=data["expected_etag"],
        operation_content_hash=data["operation_content_hash"],
    )


def render_test_write_run_spec_json(run_spec: TestWriteRunSpec) -> str:
    """Render deterministic local-private JSON after full integrity verification."""

    verify_test_write_run_spec(run_spec)
    return (
        json.dumps(
            private_test_write_run_spec_data(run_spec),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )


def parse_test_write_run_spec_bytes(raw_bytes: bytes) -> TestWriteRunSpec:
    """Parse strict canonical JSON without exposing any private values."""

    if len(raw_bytes) > MAX_TEST_WRITE_RUN_SPEC_BYTES:
        raise TestWriteRunSpecIOError(
            "test_write_run_spec_too_large",
            "Test write Run Spec is too large",
        )
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        data = _closed(
            value,
            {
                "schema_version",
                "run_type",
                "test_only",
                "production_locked",
                "tool_version",
                "target_fingerprint",
                "target_safe_ref",
                "target_environment",
                "source_profile",
                "source_sha256",
                "source_event_count",
                "current_snapshot_hash",
                "plan_hash",
                "trusted_baseline_hash",
                "operation_count",
                "add_count",
                "update_count",
                "operation",
                "approval_required",
                "run_spec_content_hash",
            },
        )
        run_spec = TestWriteRunSpec(
            schema_version=data["schema_version"],
            run_type=data["run_type"],
            test_only=data["test_only"],
            production_locked=data["production_locked"],
            tool_version=data["tool_version"],
            target_fingerprint=data["target_fingerprint"],
            target_safe_ref=data["target_safe_ref"],
            target_environment=data["target_environment"],
            source_profile=data["source_profile"],
            source_sha256=data["source_sha256"],
            source_event_count=data["source_event_count"],
            current_snapshot_hash=data["current_snapshot_hash"],
            plan_hash=data["plan_hash"],
            trusted_baseline_hash=data["trusted_baseline_hash"],
            operation_count=data["operation_count"],
            add_count=data["add_count"],
            update_count=data["update_count"],
            operation=_operation(data["operation"]),
            approval_required=data["approval_required"],
            run_spec_content_hash=data["run_spec_content_hash"],
        )
        verify_test_write_run_spec(run_spec)
        canonical = render_test_write_run_spec_json(run_spec).encode("utf-8")
        if not hmac.compare_digest(raw_bytes, canonical):
            raise ValueError
        return run_spec
    except TestWriteRunSpecError:
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
        raise TestWriteRunSpecIOError(
            "invalid_test_write_run_spec",
            "Test write Run Spec is invalid or noncanonical",
        ) from exc


def load_test_write_run_spec(path: str | Path) -> TestWriteRunSpec:
    """Load one explicit repository-external private Run Spec."""

    try:
        return parse_test_write_run_spec_bytes(
            read_sensitive_bytes(path, max_size=MAX_TEST_WRITE_RUN_SPEC_BYTES)
        )
    except TestWriteRunSpecError:
        raise
    except SensitivePathError as exc:
        raise TestWriteRunSpecIOError(
            "unsafe_test_write_run_spec_path",
            "Test write Run Spec path is unsafe or unavailable",
        ) from exc


def write_test_write_run_spec(run_spec: TestWriteRunSpec, path: str | Path) -> Path:
    """Atomically create one private Run Spec outside every Git worktree."""

    verify_test_write_run_spec(run_spec)
    try:
        atomic_write_private_text(
            path,
            render_test_write_run_spec_json(run_spec),
            overwrite=False,
            max_size=MAX_TEST_WRITE_RUN_SPEC_BYTES,
        )
        return Path(path)
    except SensitivePathError as exc:
        raise TestWriteRunSpecIOError(
            "test_write_run_spec_write_failed",
            "Test write Run Spec could not be written safely",
        ) from exc


__all__ = [
    "MAX_TEST_WRITE_RUN_SPEC_BYTES",
    "TestWriteRunSpecIOError",
    "load_test_write_run_spec",
    "parse_test_write_run_spec_bytes",
    "render_test_write_run_spec_json",
    "write_test_write_run_spec",
]
