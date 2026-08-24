"""Construction and integrity for one Test bootstrap Add Run Spec."""

from __future__ import annotations

import hashlib
import hmac
import json
from collections.abc import Mapping

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.models import (
    AcceptedSourceProfile,
    CanonicalSourceEvent,
    SourceCalendarInspection,
)
from tridentine_calendar_google_sync.provenance import tool_version
from tridentine_calendar_google_sync.test_bootstrap_plan import (
    build_test_bootstrap_add_plan,
    verify_test_bootstrap_add_plan,
)
from tridentine_calendar_google_sync.test_bootstrap_plan_models import (
    ALLOWED_BOOTSTRAP_ORIGINAL_GUARDS,
    TestBootstrapAddPlan,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec_models import (
    TestBootstrapAddOperation,
    TestBootstrapAddRunSpec,
)
from tridentine_calendar_google_sync.test_calendar_prewrite import (
    verify_test_calendar_prewrite_snapshot,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_models import (
    TestCalendarPrewriteSnapshot,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteManagedState,
    TestWriteOperationKind,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetConfig,
    test_write_target_reference,
    validate_test_write_target_config,
)

_OPERATION_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-bootstrap-operation:v1\x00"
_RUN_SPEC_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-bootstrap-run-spec:v1\x00"


class TestBootstrapRunSpecError(ValueError):
    """A content-free Bootstrap Run Spec policy or integrity failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _hash_mapping(domain: bytes, value: Mapping[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def _managed_state_data(state: TestWriteManagedState) -> dict[str, object]:
    return {
        "iCalUID": state.ical_uid,
        "summary": state.summary,
        "description": state.description,
        "start_date": state.start_date.isoformat(),
        "end_date": state.end_date.isoformat(),
        "all_day": state.all_day,
        "event_type": state.event_type,
    }


def private_test_bootstrap_add_operation_data(
    operation: TestBootstrapAddOperation,
) -> dict[str, object]:
    """Return the private operation document used only for local hashing/I/O."""

    return {
        "operation": operation.operation.value,
        "source_ref": operation.source_ref,
        "changed_fields": list(operation.changed_fields),
        "desired_state": _managed_state_data(operation.desired_state),
        "operation_content_hash": operation.operation_content_hash,
    }


def private_test_bootstrap_add_run_spec_data(
    run_spec: TestBootstrapAddRunSpec,
) -> dict[str, object]:
    """Return the canonical local-private Bootstrap Run Spec document."""

    return {
        "schema_version": run_spec.schema_version,
        "run_type": run_spec.run_type,
        "planning_mode": run_spec.planning_mode,
        "bootstrap_add": run_spec.bootstrap_add,
        "test_only": run_spec.test_only,
        "production_locked": run_spec.production_locked,
        "tool_version": run_spec.tool_version,
        "target_fingerprint": run_spec.target_fingerprint,
        "target_safe_ref": run_spec.target_safe_ref,
        "target_environment": run_spec.target_environment,
        "source_profile": run_spec.source_profile,
        "source_sha256": run_spec.source_sha256,
        "source_event_count": run_spec.source_event_count,
        "current_snapshot_hash": run_spec.current_snapshot_hash,
        "snapshot_event_count": run_spec.snapshot_event_count,
        "bootstrap_plan_hash": run_spec.bootstrap_plan_hash,
        "trusted_baseline_hash": run_spec.trusted_baseline_hash,
        "operation_count": run_spec.operation_count,
        "add_count": run_spec.add_count,
        "update_count": run_spec.update_count,
        "delete_count": run_spec.delete_count,
        "operation": private_test_bootstrap_add_operation_data(run_spec.operation),
        "approval_required": run_spec.approval_required,
        "run_spec_content_hash": run_spec.run_spec_content_hash,
    }


def calculate_test_bootstrap_add_operation_hash(
    operation: TestBootstrapAddOperation,
) -> str:
    """Calculate the private Add operation hash."""

    data = private_test_bootstrap_add_operation_data(operation)
    del data["operation_content_hash"]
    return _hash_mapping(_OPERATION_HASH_DOMAIN, data)


def calculate_test_bootstrap_add_run_spec_hash(
    run_spec: TestBootstrapAddRunSpec,
) -> str:
    """Calculate the private Run Spec hash."""

    data = private_test_bootstrap_add_run_spec_data(run_spec)
    del data["run_spec_content_hash"]
    return _hash_mapping(_RUN_SPEC_HASH_DOMAIN, data)


def _desired_state(event: CanonicalSourceEvent) -> TestWriteManagedState:
    if (
        event.uid is None
        or event.summary is None
        or event.description is None
        or event.start_date is None
        or event.effective_end_date is None
        or not event.all_day
        or event.rrule_present
        or event.recurrence_id_present
    ):
        raise TestBootstrapRunSpecError(
            "bootstrap_run_spec_source_event_invalid",
            "Bootstrap Run Spec source event is invalid",
        )
    return TestWriteManagedState(
        ical_uid=event.uid,
        summary=event.summary,
        description=event.description,
        start_date=event.start_date,
        end_date=event.effective_end_date,
        all_day=True,
        event_type="default",
    )


def verify_test_bootstrap_add_run_spec(run_spec: TestBootstrapAddRunSpec) -> None:
    """Reject fixed-policy or integrity tampering without requiring a plan file."""

    if not isinstance(run_spec, TestBootstrapAddRunSpec):
        raise TestBootstrapRunSpecError(
            "invalid_test_bootstrap_run_spec",
            "Test bootstrap Add Run Spec is invalid",
        )
    operation = run_spec.operation
    uid_parts = operation.desired_state.ical_uid.rsplit("@", 1)
    fixed = (
        run_spec.schema_version == "1.0"
        and run_spec.run_type == "test-bootstrap-add-run-spec-v1"
        and run_spec.planning_mode == "test_bootstrap_add"
        and run_spec.bootstrap_add is True
        and run_spec.test_only is True
        and run_spec.production_locked is True
        and run_spec.target_environment == "test"
        and run_spec.target_safe_ref != PRODUCTION_TARGET_REFERENCE
        and run_spec.target_safe_ref == f"T-{run_spec.target_fingerprint[:12]}"
        and run_spec.source_event_count == 1
        and run_spec.snapshot_event_count == 0
        and run_spec.trusted_baseline_hash is None
        and run_spec.operation_count == 1
        and run_spec.add_count == 1
        and run_spec.update_count == 0
        and run_spec.delete_count == 0
        and run_spec.approval_required is True
        and operation.operation is TestWriteOperationKind.ADD
        and operation.changed_fields == ("summary", "description", "start_date", "end_date")
        and operation.google_ref is None
        and operation.current_state is None
        and operation.google_event_id is None
        and operation.expected_etag is None
        and len(uid_parts) == 2
        and bool(uid_parts[0])
        and uid_parts[1].casefold().endswith(".invalid")
        and operation.desired_state.summary is not None
        and operation.desired_state.description is not None
        and operation.desired_state.all_day is True
        and operation.desired_state.event_type == "default"
        and operation.desired_state.end_date > operation.desired_state.start_date
        and (
            "同期テスト" in operation.desired_state.summary
            or "test" in operation.desired_state.summary.casefold()
        )
    )
    if not fixed:
        raise TestBootstrapRunSpecError(
            "test_bootstrap_run_spec_policy_mismatch",
            "Test bootstrap Add Run Spec policy was not satisfied",
        )
    if not hmac.compare_digest(
        calculate_test_bootstrap_add_operation_hash(operation),
        operation.operation_content_hash,
    ):
        raise TestBootstrapRunSpecError(
            "test_bootstrap_operation_hash_mismatch",
            "Test bootstrap Add operation integrity verification failed",
        )
    if not hmac.compare_digest(
        calculate_test_bootstrap_add_run_spec_hash(run_spec),
        run_spec.run_spec_content_hash,
    ):
        raise TestBootstrapRunSpecError(
            "test_bootstrap_run_spec_hash_mismatch",
            "Test bootstrap Add Run Spec integrity verification failed",
        )


def verify_test_bootstrap_add_run_spec_plan(
    run_spec: TestBootstrapAddRunSpec,
    plan: TestBootstrapAddPlan,
) -> None:
    """Bind an intact Bootstrap Run Spec to its exact eligible plan."""

    verify_test_bootstrap_add_run_spec(run_spec)
    verify_test_bootstrap_add_plan(plan)
    if (
        run_spec.bootstrap_plan_hash != plan.plan_content_hash
        or run_spec.target_fingerprint != plan.target_fingerprint
        or run_spec.target_safe_ref != plan.target_safe_ref
        or run_spec.source_profile != plan.source_profile
        or run_spec.source_sha256 != plan.source_sha256
        or run_spec.current_snapshot_hash != plan.snapshot_hash
        or run_spec.operation.source_ref != plan.safe_uid_ref
        or plan.test_only is not True
        or plan.bootstrap_only is not True
        or plan.executable is not False
        or plan.production_locked is not True
        or plan.target_environment != "test"
        or plan.target_label != "test"
        or plan.target_purpose != "test_calendar_write_acceptance"
        or plan.bootstrap_eligibility != "eligible"
        or plan.original_guard_codes != ALLOWED_BOOTSTRAP_ORIGINAL_GUARDS
        or plan.operation_count != 1
        or plan.add_count != 1
        or plan.update_count != 0
        or plan.delete_count != 0
        or plan.snapshot_event_count != 0
    ):
        raise TestBootstrapRunSpecError(
            "test_bootstrap_plan_run_spec_mismatch",
            "Bootstrap Plan and Run Spec do not match",
        )


def build_test_bootstrap_add_run_spec(
    profile: AcceptedSourceProfile,
    source: SourceCalendarInspection,
    prewrite_snapshot: TestCalendarPrewriteSnapshot,
    plan: TestBootstrapAddPlan,
    target: TestWriteTargetConfig,
) -> TestBootstrapAddRunSpec:
    """Build one plan-bound Add-only Run Spec without a trusted baseline."""

    target_fingerprint = validate_test_write_target_config(target)
    target_ref = test_write_target_reference(target)
    verify_test_calendar_prewrite_snapshot(prewrite_snapshot)
    expected_plan = build_test_bootstrap_add_plan(
        profile,
        source,
        prewrite_snapshot,
        target,
    )
    if not hmac.compare_digest(plan.plan_content_hash, expected_plan.plan_content_hash):
        raise TestBootstrapRunSpecError(
            "test_bootstrap_plan_recomputation_mismatch",
            "Bootstrap Plan does not match canonical inputs",
        )
    verify_test_bootstrap_add_plan(plan)
    if (
        plan.target_fingerprint != target_fingerprint
        or plan.target_safe_ref != target_ref
        or plan.snapshot_hash != prewrite_snapshot.snapshot_content_hash
        or source.raw_sha256 != plan.source_sha256
        or source.profile_id != profile.profile_id
        or source.vevent_count != 1
        or len(source.events) != 1
    ):
        raise TestBootstrapRunSpecError(
            "test_bootstrap_run_spec_input_mismatch",
            "Bootstrap Run Spec inputs do not match",
        )
    desired = _desired_state(source.events[0])
    operation_provisional = TestBootstrapAddOperation(
        source_ref=plan.safe_uid_ref,
        desired_state=desired,
        operation_content_hash="0" * 64,
    )
    operation = operation_provisional.model_copy(
        update={
            "operation_content_hash": calculate_test_bootstrap_add_operation_hash(
                operation_provisional
            )
        }
    )
    provisional = TestBootstrapAddRunSpec(
        tool_version=tool_version(),
        target_fingerprint=target_fingerprint,
        target_safe_ref=target_ref,
        source_profile=profile.profile_id,
        source_sha256=source.raw_sha256,
        current_snapshot_hash=prewrite_snapshot.snapshot_content_hash,
        bootstrap_plan_hash=plan.plan_content_hash,
        operation=operation,
        run_spec_content_hash="0" * 64,
    )
    run_spec = provisional.model_copy(
        update={"run_spec_content_hash": calculate_test_bootstrap_add_run_spec_hash(provisional)}
    )
    verify_test_bootstrap_add_run_spec_plan(run_spec, plan)
    return run_spec


__all__ = [
    "TestBootstrapRunSpecError",
    "build_test_bootstrap_add_run_spec",
    "calculate_test_bootstrap_add_operation_hash",
    "calculate_test_bootstrap_add_run_spec_hash",
    "private_test_bootstrap_add_operation_data",
    "private_test_bootstrap_add_run_spec_data",
    "verify_test_bootstrap_add_run_spec",
    "verify_test_bootstrap_add_run_spec_plan",
]
