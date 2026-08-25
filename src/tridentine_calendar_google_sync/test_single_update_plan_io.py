"""Strict repository-external I/O for Test Single Update Plans."""

from __future__ import annotations

import hmac
import json
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    read_sensitive_bytes,
)
from tridentine_calendar_google_sync.test_single_update_plan import (
    TestSingleUpdatePlanError,
    private_test_single_update_plan_data,
    verify_test_single_update_plan,
)
from tridentine_calendar_google_sync.test_single_update_plan_models import (
    TestSingleUpdatePlan,
)

MAX_TEST_SINGLE_UPDATE_PLAN_BYTES = 4 * 1024 * 1024


class TestSingleUpdatePlanIOError(TestSingleUpdatePlanError):
    """A safe Single Update Plan parse, canonicalization, or path failure."""


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


def render_test_single_update_plan_json(plan: TestSingleUpdatePlan) -> str:
    """Render deterministic local-private JSON after integrity verification."""

    verify_test_single_update_plan(plan)
    return (
        json.dumps(
            private_test_single_update_plan_data(plan),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )


def parse_test_single_update_plan_bytes(raw_bytes: bytes) -> TestSingleUpdatePlan:
    """Parse strict canonical JSON without echoing any input content."""

    if len(raw_bytes) > MAX_TEST_SINGLE_UPDATE_PLAN_BYTES:
        raise TestSingleUpdatePlanIOError(
            "test_single_update_plan_too_large",
            "Test Single Update Plan is too large",
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
                "plan_type",
                "test_only",
                "single_update_only",
                "production_locked",
                "executable",
                "tool_version",
                "target_fingerprint",
                "target_safe_ref",
                "target_environment",
                "target_label",
                "target_purpose",
                "baseline_hash",
                "baseline_snapshot_hash",
                "baseline_state",
                "managed_uid_count",
                "source_profile",
                "source_sha256",
                "source_event_count",
                "snapshot_hash",
                "snapshot_event_count",
                "diff_hash",
                "operation_count",
                "add_count",
                "update_count",
                "delete_count",
                "changed_fields",
                "safe_uid_ref",
                "original_guard_codes",
                "eligibility",
                "approval_required",
                "plan_content_hash",
            },
        )
        raw_fields = data["changed_fields"]
        raw_guards = data["original_guard_codes"]
        if not isinstance(raw_fields, list) or not isinstance(raw_guards, list):
            raise TypeError
        normalized = dict(data)
        normalized["changed_fields"] = tuple(raw_fields)
        normalized["original_guard_codes"] = tuple(raw_guards)
        plan = TestSingleUpdatePlan.model_validate(normalized, strict=True)
        verify_test_single_update_plan(plan)
        canonical = render_test_single_update_plan_json(plan).encode("utf-8")
        if not hmac.compare_digest(raw_bytes, canonical):
            raise ValueError
        return plan
    except TestSingleUpdatePlanError:
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
        raise TestSingleUpdatePlanIOError(
            "invalid_test_single_update_plan",
            "Test Single Update Plan is invalid or noncanonical",
        ) from exc


def load_test_single_update_plan(path: str | Path) -> TestSingleUpdatePlan:
    """Load one explicit repository-external Single Update Plan."""

    try:
        return parse_test_single_update_plan_bytes(
            read_sensitive_bytes(path, max_size=MAX_TEST_SINGLE_UPDATE_PLAN_BYTES)
        )
    except TestSingleUpdatePlanError:
        raise
    except SensitivePathError as exc:
        raise TestSingleUpdatePlanIOError(
            "unsafe_test_single_update_plan_path",
            "Test Single Update Plan path is unsafe or unavailable",
        ) from exc


def write_test_single_update_plan(plan: TestSingleUpdatePlan, path: str | Path) -> Path:
    """Atomically create one private Single Update Plan without overwrite."""

    verify_test_single_update_plan(plan)
    try:
        atomic_write_private_text(
            path,
            render_test_single_update_plan_json(plan),
            overwrite=False,
            max_size=MAX_TEST_SINGLE_UPDATE_PLAN_BYTES,
        )
        return Path(path)
    except SensitivePathError as exc:
        raise TestSingleUpdatePlanIOError(
            "test_single_update_plan_write_failed",
            "Test Single Update Plan could not be written safely",
        ) from exc


__all__ = [
    "MAX_TEST_SINGLE_UPDATE_PLAN_BYTES",
    "TestSingleUpdatePlanIOError",
    "load_test_single_update_plan",
    "parse_test_single_update_plan_bytes",
    "render_test_single_update_plan_json",
    "write_test_single_update_plan",
]
