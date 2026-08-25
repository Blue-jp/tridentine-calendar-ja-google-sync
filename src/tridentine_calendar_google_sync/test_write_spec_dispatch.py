"""Exact-discriminator dispatch for every supported Test write Run Spec."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from tridentine_calendar_google_sync.baseline_models import TrustedBaseline
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    read_sensitive_bytes,
)
from tridentine_calendar_google_sync.test_bootstrap_plan_models import TestBootstrapAddPlan
from tridentine_calendar_google_sync.test_bootstrap_run_spec import (
    TestBootstrapRunSpecError,
    verify_test_bootstrap_add_run_spec_plan,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec_io import (
    MAX_TEST_BOOTSTRAP_RUN_SPEC_BYTES,
    TestBootstrapRunSpecIOError,
    parse_test_bootstrap_add_run_spec_bytes,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec_models import (
    TestBootstrapAddRunSpec,
)
from tridentine_calendar_google_sync.test_single_update_plan_models import (
    TestSingleUpdatePlan,
)
from tridentine_calendar_google_sync.test_single_update_run_spec import (
    TestSingleUpdateRunSpecError,
    verify_test_single_update_run_spec_bindings,
)
from tridentine_calendar_google_sync.test_single_update_run_spec_io import (
    MAX_TEST_SINGLE_UPDATE_RUN_SPEC_BYTES,
    TestSingleUpdateRunSpecIOError,
    parse_test_single_update_run_spec_bytes,
)
from tridentine_calendar_google_sync.test_single_update_run_spec_models import (
    TestSingleUpdateRunSpec,
)
from tridentine_calendar_google_sync.test_write_models import TestWriteRunSpec
from tridentine_calendar_google_sync.test_write_run_spec import (
    TestWriteRunSpecError,
    verify_test_write_run_spec,
)
from tridentine_calendar_google_sync.test_write_run_spec_io import (
    MAX_TEST_WRITE_RUN_SPEC_BYTES,
    parse_test_write_run_spec_bytes,
)

type AnyTestWriteRunSpec = TestWriteRunSpec | TestBootstrapAddRunSpec | TestSingleUpdateRunSpec
MAX_ANY_TEST_WRITE_RUN_SPEC_BYTES = max(
    MAX_TEST_WRITE_RUN_SPEC_BYTES,
    MAX_TEST_BOOTSTRAP_RUN_SPEC_BYTES,
    MAX_TEST_SINGLE_UPDATE_RUN_SPEC_BYTES,
)


class TestWriteSpecDispatchError(ValueError):
    """A safe unknown-discriminator, cross-type, or input failure."""

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


def verify_any_test_write_run_spec(
    run_spec: AnyTestWriteRunSpec,
    *,
    bootstrap_plan: TestBootstrapAddPlan | None = None,
    single_update_plan: TestSingleUpdatePlan | None = None,
    trusted_baseline: TrustedBaseline | None = None,
) -> None:
    """Dispatch integrity/policy checks without any heuristic fallback."""

    if isinstance(run_spec, TestBootstrapAddRunSpec):
        if bootstrap_plan is None or single_update_plan is not None or trusted_baseline is not None:
            raise TestWriteSpecDispatchError(
                "test_bootstrap_plan_required",
                "Bootstrap Add Run Spec requires its exact Bootstrap Plan",
            )
        verify_test_bootstrap_add_run_spec_plan(run_spec, bootstrap_plan)
        return
    if isinstance(run_spec, TestSingleUpdateRunSpec):
        if single_update_plan is None or trusted_baseline is None or bootstrap_plan is not None:
            raise TestWriteSpecDispatchError(
                "test_single_update_artifacts_required",
                "Single Update Run Spec requires its exact Plan and trusted baseline",
            )
        verify_test_single_update_run_spec_bindings(
            run_spec,
            single_update_plan,
            trusted_baseline,
        )
        return
    if isinstance(run_spec, TestWriteRunSpec):
        if (
            bootstrap_plan is not None
            or single_update_plan is not None
            or trusted_baseline is not None
        ):
            raise TestWriteSpecDispatchError(
                "normal_run_spec_bootstrap_plan_forbidden",
                "Normal Test write Run Spec cannot use a Bootstrap Plan",
            )
        verify_test_write_run_spec(run_spec)
        return
    raise TestWriteSpecDispatchError(
        "unknown_test_write_run_spec_type",
        "Test write Run Spec type is unsupported",
    )


def parse_any_test_write_run_spec_bytes(raw_bytes: bytes) -> AnyTestWriteRunSpec:
    """Read the exact run_type first, then invoke one strict canonical parser."""

    if len(raw_bytes) > MAX_ANY_TEST_WRITE_RUN_SPEC_BYTES:
        raise TestWriteSpecDispatchError(
            "test_write_run_spec_too_large",
            "Test write Run Spec exceeds the size limit",
        )
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
        )
        if not isinstance(value, dict):
            raise TypeError
        run_type = value.get("run_type")
        if run_type == "test-calendar-write-run-spec-v1":
            return parse_test_write_run_spec_bytes(raw_bytes)
        if run_type == "test-bootstrap-add-run-spec-v1":
            return parse_test_bootstrap_add_run_spec_bytes(raw_bytes)
        if run_type == "test-single-update-run-spec-v1":
            return parse_test_single_update_run_spec_bytes(raw_bytes)
        raise TestWriteSpecDispatchError(
            "unknown_test_write_run_spec_discriminator",
            "Test write Run Spec discriminator is unsupported",
        )
    except TestWriteSpecDispatchError:
        raise
    except (
        TestBootstrapRunSpecError,
        TestBootstrapRunSpecIOError,
        TestSingleUpdateRunSpecError,
        TestSingleUpdateRunSpecIOError,
        TestWriteRunSpecError,
    ) as exc:
        raise TestWriteSpecDispatchError(
            "invalid_dispatched_test_write_run_spec",
            "Test write Run Spec is invalid",
        ) from exc
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        TypeError,
        ValueError,
    ) as exc:
        raise TestWriteSpecDispatchError(
            "invalid_test_write_run_spec_envelope",
            "Test write Run Spec envelope is invalid",
        ) from exc


def load_any_test_write_run_spec(path: str | Path) -> AnyTestWriteRunSpec:
    """Load one repository-external exact-discriminator Run Spec."""

    try:
        return parse_any_test_write_run_spec_bytes(
            read_sensitive_bytes(path, max_size=MAX_ANY_TEST_WRITE_RUN_SPEC_BYTES)
        )
    except TestWriteSpecDispatchError:
        raise
    except SensitivePathError as exc:
        raise TestWriteSpecDispatchError(
            "unsafe_test_write_run_spec_path",
            "Test write Run Spec path is unsafe or unavailable",
        ) from exc


__all__ = [
    "MAX_ANY_TEST_WRITE_RUN_SPEC_BYTES",
    "AnyTestWriteRunSpec",
    "TestWriteSpecDispatchError",
    "load_any_test_write_run_spec",
    "parse_any_test_write_run_spec_bytes",
    "verify_any_test_write_run_spec",
]
