"""Strict repository-external I/O for private Single Update Run Specs."""

from __future__ import annotations

import hmac
import json
from datetime import date
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    read_sensitive_bytes,
)
from tridentine_calendar_google_sync.test_single_update_run_spec import (
    TestSingleUpdateRunSpecError,
    private_test_single_update_run_spec_data,
    verify_test_single_update_run_spec,
)
from tridentine_calendar_google_sync.test_single_update_run_spec_models import (
    TestSingleUpdateOperation,
    TestSingleUpdateRunSpec,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteManagedState,
    TestWriteOperationKind,
)

MAX_TEST_SINGLE_UPDATE_RUN_SPEC_BYTES = 64 * 1024 * 1024


class TestSingleUpdateRunSpecIOError(ValueError):
    """A content-free Single Update Run Spec parse or path failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


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


def _parse_state(value: object) -> TestWriteManagedState:
    if not isinstance(value, dict):
        raise TypeError
    normalized = dict(value)
    normalized["ical_uid"] = normalized.pop("iCalUID")
    normalized["start_date"] = date.fromisoformat(normalized["start_date"])
    normalized["end_date"] = date.fromisoformat(normalized["end_date"])
    return TestWriteManagedState.model_validate(normalized, strict=True)


def render_test_single_update_run_spec_json(run_spec: TestSingleUpdateRunSpec) -> str:
    """Render deterministic private JSON after intrinsic verification."""

    verify_test_single_update_run_spec(run_spec)
    return (
        json.dumps(
            private_test_single_update_run_spec_data(run_spec),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def parse_test_single_update_run_spec_bytes(raw_bytes: bytes) -> TestSingleUpdateRunSpec:
    """Parse one exact canonical Single Update Run Spec."""

    if len(raw_bytes) > MAX_TEST_SINGLE_UPDATE_RUN_SPEC_BYTES:
        raise TestSingleUpdateRunSpecIOError(
            "test_single_update_run_spec_too_large",
            "Test Single Update Run Spec exceeds the size limit",
        )
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict) or value.get("run_type") != (
            "test-single-update-run-spec-v1"
        ):
            raise TypeError
        normalized = dict(value)
        raw_fields = normalized.get("changed_fields")
        if not isinstance(raw_fields, list):
            raise TypeError
        normalized["changed_fields"] = tuple(raw_fields)
        raw_operation = normalized.get("operation")
        if not isinstance(raw_operation, dict):
            raise TypeError
        operation_data = dict(raw_operation)
        operation_data["operation"] = TestWriteOperationKind(operation_data["operation"])
        raw_operation_fields = operation_data.get("changed_fields")
        if not isinstance(raw_operation_fields, list):
            raise TypeError
        operation_data["changed_fields"] = tuple(raw_operation_fields)
        operation_data["current_state"] = _parse_state(operation_data["current_state"])
        operation_data["desired_state"] = _parse_state(operation_data["desired_state"])
        normalized["operation"] = TestSingleUpdateOperation.model_validate(
            operation_data,
            strict=True,
        )
        run_spec = TestSingleUpdateRunSpec.model_validate(normalized, strict=True)
        verify_test_single_update_run_spec(run_spec)
        canonical = render_test_single_update_run_spec_json(run_spec).encode("utf-8")
        if not hmac.compare_digest(raw_bytes, canonical):
            raise ValueError
        return run_spec
    except (TestSingleUpdateRunSpecError, TestSingleUpdateRunSpecIOError):
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
        raise TestSingleUpdateRunSpecIOError(
            "invalid_test_single_update_run_spec",
            "Test Single Update Run Spec is invalid",
        ) from exc


def load_test_single_update_run_spec(path: str | Path) -> TestSingleUpdateRunSpec:
    """Load one bounded repository-external private Run Spec."""

    try:
        return parse_test_single_update_run_spec_bytes(
            read_sensitive_bytes(path, max_size=MAX_TEST_SINGLE_UPDATE_RUN_SPEC_BYTES)
        )
    except (TestSingleUpdateRunSpecError, TestSingleUpdateRunSpecIOError):
        raise
    except SensitivePathError as exc:
        raise TestSingleUpdateRunSpecIOError(
            "unsafe_test_single_update_run_spec_path",
            "Test Single Update Run Spec path is unsafe or unavailable",
        ) from exc


def write_test_single_update_run_spec(
    run_spec: TestSingleUpdateRunSpec,
    path: str | Path,
) -> Path:
    """Atomically create one private Run Spec without overwrite."""

    rendered = render_test_single_update_run_spec_json(run_spec)
    try:
        atomic_write_private_text(
            path,
            rendered,
            overwrite=False,
            max_size=MAX_TEST_SINGLE_UPDATE_RUN_SPEC_BYTES,
        )
        return Path(path)
    except SensitivePathError as exc:
        raise TestSingleUpdateRunSpecIOError(
            "test_single_update_run_spec_write_failed",
            "Test Single Update Run Spec could not be written safely",
        ) from exc


__all__ = [
    "MAX_TEST_SINGLE_UPDATE_RUN_SPEC_BYTES",
    "TestSingleUpdateRunSpecIOError",
    "load_test_single_update_run_spec",
    "parse_test_single_update_run_spec_bytes",
    "render_test_single_update_run_spec_json",
    "write_test_single_update_run_spec",
]
