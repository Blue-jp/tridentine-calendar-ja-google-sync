"""Strict canonical repository-external I/O for Test bootstrap add plans."""

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
from tridentine_calendar_google_sync.test_bootstrap_plan import (
    TestBootstrapPlanError,
    private_test_bootstrap_add_plan_data,
    verify_test_bootstrap_add_plan,
)
from tridentine_calendar_google_sync.test_bootstrap_plan_models import TestBootstrapAddPlan

MAX_TEST_BOOTSTRAP_PLAN_BYTES = 4 * 1024 * 1024


class TestBootstrapPlanIOError(TestBootstrapPlanError):
    """A safe bootstrap plan parse, canonicalization, or path failure."""


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


def render_test_bootstrap_add_plan_json(plan: TestBootstrapAddPlan) -> str:
    """Render deterministic local-private JSON after integrity verification."""

    verify_test_bootstrap_add_plan(plan)
    return (
        json.dumps(
            private_test_bootstrap_add_plan_data(plan),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )


def parse_test_bootstrap_add_plan_bytes(raw_bytes: bytes) -> TestBootstrapAddPlan:
    """Parse one exact canonical bootstrap plan without echoing its content."""

    if len(raw_bytes) > MAX_TEST_BOOTSTRAP_PLAN_BYTES:
        raise TestBootstrapPlanIOError(
            "test_bootstrap_plan_too_large",
            "Test bootstrap add plan is too large",
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
                "bootstrap_only",
                "executable",
                "production_locked",
                "tool_version",
                "target_fingerprint",
                "target_safe_ref",
                "target_environment",
                "target_label",
                "target_purpose",
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
                "safe_uid_ref",
                "original_guard_codes",
                "bootstrap_eligibility",
                "approval_required",
                "plan_content_hash",
            },
        )
        raw_guards = data["original_guard_codes"]
        if not isinstance(raw_guards, list):
            raise TypeError
        normalized = dict(data)
        normalized["original_guard_codes"] = tuple(raw_guards)
        plan = TestBootstrapAddPlan.model_validate(normalized, strict=True)
        verify_test_bootstrap_add_plan(plan)
        canonical = render_test_bootstrap_add_plan_json(plan).encode("utf-8")
        if not hmac.compare_digest(raw_bytes, canonical):
            raise ValueError
        return plan
    except TestBootstrapPlanError:
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
        raise TestBootstrapPlanIOError(
            "invalid_test_bootstrap_plan",
            "Test bootstrap add plan is invalid or noncanonical",
        ) from exc


def load_test_bootstrap_add_plan(path: str | Path) -> TestBootstrapAddPlan:
    """Load one explicit repository-external bootstrap plan."""

    try:
        return parse_test_bootstrap_add_plan_bytes(
            read_sensitive_bytes(path, max_size=MAX_TEST_BOOTSTRAP_PLAN_BYTES)
        )
    except TestBootstrapPlanError:
        raise
    except SensitivePathError as exc:
        raise TestBootstrapPlanIOError(
            "unsafe_test_bootstrap_plan_path",
            "Test bootstrap add plan path is unsafe or unavailable",
        ) from exc


def write_test_bootstrap_add_plan(plan: TestBootstrapAddPlan, path: str | Path) -> Path:
    """Atomically create one private bootstrap plan without overwrite."""

    verify_test_bootstrap_add_plan(plan)
    try:
        atomic_write_private_text(
            path,
            render_test_bootstrap_add_plan_json(plan),
            overwrite=False,
            max_size=MAX_TEST_BOOTSTRAP_PLAN_BYTES,
        )
        return Path(path)
    except SensitivePathError as exc:
        raise TestBootstrapPlanIOError(
            "test_bootstrap_plan_write_failed",
            "Test bootstrap add plan could not be written safely",
        ) from exc


__all__ = [
    "MAX_TEST_BOOTSTRAP_PLAN_BYTES",
    "TestBootstrapPlanIOError",
    "load_test_bootstrap_add_plan",
    "parse_test_bootstrap_add_plan_bytes",
    "render_test_bootstrap_add_plan_json",
    "write_test_bootstrap_add_plan",
]
