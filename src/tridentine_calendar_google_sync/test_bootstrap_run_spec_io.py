"""Strict repository-external I/O for private Bootstrap Add Run Specs."""

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
from tridentine_calendar_google_sync.test_bootstrap_run_spec import (
    TestBootstrapRunSpecError,
    private_test_bootstrap_add_run_spec_data,
    verify_test_bootstrap_add_run_spec,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec_models import (
    TestBootstrapAddOperation,
    TestBootstrapAddRunSpec,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteManagedState,
    TestWriteOperationKind,
)

MAX_TEST_BOOTSTRAP_RUN_SPEC_BYTES = 64 * 1024 * 1024


class TestBootstrapRunSpecIOError(ValueError):
    """A content-free Bootstrap Run Spec parse or I/O failure."""

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


def render_test_bootstrap_add_run_spec_json(run_spec: TestBootstrapAddRunSpec) -> str:
    """Render deterministic local-private JSON after integrity verification."""

    verify_test_bootstrap_add_run_spec(run_spec)
    return (
        json.dumps(
            private_test_bootstrap_add_run_spec_data(run_spec),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def _parse_managed_state(value: object) -> TestWriteManagedState:
    if not isinstance(value, dict):
        raise TypeError
    normalized = dict(value)
    normalized["ical_uid"] = normalized.pop("iCalUID")
    normalized["start_date"] = date.fromisoformat(normalized["start_date"])
    normalized["end_date"] = date.fromisoformat(normalized["end_date"])
    return TestWriteManagedState.model_validate(normalized, strict=True)


def parse_test_bootstrap_add_run_spec_bytes(raw_bytes: bytes) -> TestBootstrapAddRunSpec:
    """Strictly parse one exact-discriminator Bootstrap Run Spec document."""

    if len(raw_bytes) > MAX_TEST_BOOTSTRAP_RUN_SPEC_BYTES:
        raise TestBootstrapRunSpecIOError(
            "test_bootstrap_run_spec_too_large",
            "Test bootstrap Add Run Spec exceeds the size limit",
        )
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        if not isinstance(value, dict):
            raise TypeError
        normalized = dict(value)
        if normalized.get("run_type") != "test-bootstrap-add-run-spec-v1":
            raise TypeError
        raw_operation = normalized.get("operation")
        if not isinstance(raw_operation, dict):
            raise TypeError
        operation_data = dict(raw_operation)
        operation_data["operation"] = TestWriteOperationKind(operation_data["operation"])
        changed_fields = operation_data.get("changed_fields")
        if not isinstance(changed_fields, list):
            raise TypeError
        operation_data["changed_fields"] = tuple(changed_fields)
        operation_data["desired_state"] = _parse_managed_state(operation_data["desired_state"])
        normalized["operation"] = TestBootstrapAddOperation.model_validate(
            operation_data,
            strict=True,
        )
        run_spec = TestBootstrapAddRunSpec.model_validate(normalized, strict=True)
        verify_test_bootstrap_add_run_spec(run_spec)
        canonical = render_test_bootstrap_add_run_spec_json(run_spec).encode("utf-8")
        if not hmac.compare_digest(raw_bytes, canonical):
            raise ValueError
        return run_spec
    except (TestBootstrapRunSpecError, TestBootstrapRunSpecIOError):
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
        raise TestBootstrapRunSpecIOError(
            "invalid_test_bootstrap_run_spec",
            "Test bootstrap Add Run Spec is invalid",
        ) from exc


def load_test_bootstrap_add_run_spec(path: str | Path) -> TestBootstrapAddRunSpec:
    """Load one bounded repository-external Bootstrap Run Spec."""

    try:
        return parse_test_bootstrap_add_run_spec_bytes(
            read_sensitive_bytes(path, max_size=MAX_TEST_BOOTSTRAP_RUN_SPEC_BYTES)
        )
    except (TestBootstrapRunSpecError, TestBootstrapRunSpecIOError):
        raise
    except SensitivePathError as exc:
        raise TestBootstrapRunSpecIOError(
            "unsafe_test_bootstrap_run_spec_path",
            "Test bootstrap Add Run Spec path is unsafe or unavailable",
        ) from exc


def write_test_bootstrap_add_run_spec(
    run_spec: TestBootstrapAddRunSpec,
    path: str | Path,
) -> Path:
    """Atomically create one private Bootstrap Run Spec without overwrite."""

    rendered = render_test_bootstrap_add_run_spec_json(run_spec)
    try:
        atomic_write_private_text(
            path,
            rendered,
            overwrite=False,
            max_size=MAX_TEST_BOOTSTRAP_RUN_SPEC_BYTES,
        )
        return Path(path)
    except SensitivePathError as exc:
        raise TestBootstrapRunSpecIOError(
            "test_bootstrap_run_spec_write_failed",
            "Test bootstrap Add Run Spec could not be written safely",
        ) from exc


__all__ = [
    "MAX_TEST_BOOTSTRAP_RUN_SPEC_BYTES",
    "TestBootstrapRunSpecIOError",
    "load_test_bootstrap_add_run_spec",
    "parse_test_bootstrap_add_run_spec_bytes",
    "render_test_bootstrap_add_run_spec_json",
    "write_test_bootstrap_add_run_spec",
]
