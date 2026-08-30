"""Guarded one-operation Test Calendar write orchestration."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import random
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Literal, Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.baseline_models import TrustedBaseline
from tridentine_calendar_google_sync.google_errors import (
    SafeGoogleError,
    safe_google_error_from_exception,
)
from tridentine_calendar_google_sync.google_fetch import FetchedGooglePages, RetryPolicy
from tridentine_calendar_google_sync.google_models import CanonicalGoogleEvent, GoogleSnapshot
from tridentine_calendar_google_sync.google_sanitize import sanitize_fetched_pages
from tridentine_calendar_google_sync.google_test_write_client import TestCalendarWriteClient
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.test_bootstrap_plan_models import TestBootstrapAddPlan
from tridentine_calendar_google_sync.test_single_update_plan_models import (
    SINGLE_UPDATE_CHANGED_FIELDS,
    TestSingleUpdatePlan,
)
from tridentine_calendar_google_sync.test_single_update_run_spec_models import (
    TestSingleUpdateRunSpec,
)
from tridentine_calendar_google_sync.test_write_approval_dispatch import (
    approve_any_test_write_run_spec,
)
from tridentine_calendar_google_sync.test_write_journal import (
    TEST_WRITE_SAFE_ERROR_CODES,
    TestWriteJournal,
    TestWriteJournalEntryStatus,
    TestWriteJournalPhase,
    TestWriteJournalState,
    append_test_write_journal_entry,
    initialize_test_write_journal,
    verify_test_write_journal,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteManagedState,
    TestWriteOperationKind,
    TestWriteRunSpec,
)
from tridentine_calendar_google_sync.test_write_spec_dispatch import (
    AnyTestWriteRunSpec,
    verify_any_test_write_run_spec,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetConfig,
    TestWriteTargetObservation,
    test_write_target_reference,
    validate_test_write_target_config,
    verify_test_write_target_metadata,
)

MAX_TEST_WRITE_API_CALLS = 10
MAX_TEST_WRITE_MUTATION_ATTEMPTS = 1
TEST_WRITE_MUTATION_RETRY_COUNT = 0
MAX_TEST_WRITE_PAGES = 100
_METADATA_HASH_DOMAIN = b"tridentine-calendar-google-sync:collection-metadata:v1\x00"
_RESULT_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-write-result:v1\x00"


class TestWriteExecutionState(StrEnum):
    """Complete terminal state vocabulary for one Test write."""

    SUCCEEDED = "succeeded"
    FAILED = "failed"
    UNCERTAIN = "uncertain"
    ETAG_CONFLICT = "etag_conflict"


class TestWriteExecutionResult(StrictFrozenModel):
    """Public-safe execution result; private identities never leave the adapter."""

    schema_version: Literal["1.0"] = "1.0"
    result_type: Literal["test-calendar-write-result-v1"] = "test-calendar-write-result-v1"
    live_test_write: Literal[True] = True
    test_only: Literal[True] = True
    production_locked: Literal[True] = True
    state: TestWriteExecutionState
    target_safe_ref: str = Field(pattern=r"^T-[0-9a-f]{12}$")
    run_spec_ref: str = Field(pattern=r"^R-[0-9a-f]{12}$")
    source_ref: str = Field(pattern=r"^U-[0-9a-f]{12}$")
    operation: TestWriteOperationKind
    success: bool
    read_back_verified: bool
    recovered_after_uncertain: bool
    api_call_count: int = Field(ge=0, le=MAX_TEST_WRITE_API_CALLS)
    read_retry_count: int = Field(ge=0)
    mutation_attempt_count: int = Field(ge=0, le=MAX_TEST_WRITE_MUTATION_ATTEMPTS)
    mutation_retry_count: Literal[0] = 0
    stopped: bool
    safe_findings: tuple[str, ...]
    journal: TestWriteJournal
    result_content_hash: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def terminal_shape(self) -> Self:
        _verify_test_write_execution_result_semantics(self)
        return self


class TestWriteTransportError(ValueError):
    """A content-free local Test write transport guard failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


def _verify_test_write_execution_result_semantics(result: TestWriteExecutionResult) -> None:
    """Bind every terminal result claim to a semantically valid journal."""

    verify_test_write_journal(result.journal)
    if result.target_safe_ref == PRODUCTION_TARGET_REFERENCE:
        raise TestWriteTransportError(
            "production_test_write_result_forbidden",
            "Production Test write results are forbidden",
        )
    if result.success is (result.state is not TestWriteExecutionState.SUCCEEDED):
        raise TestWriteTransportError(
            "test_write_result_success_mismatch",
            "Test write result success state verification failed",
        )
    if result.success and (not result.read_back_verified or result.stopped):
        raise TestWriteTransportError(
            "test_write_result_read_back_mismatch",
            "Test write result read-back verification failed",
        )
    if not result.success and not result.stopped:
        raise TestWriteTransportError(
            "test_write_result_stop_mismatch",
            "Test write result stop state verification failed",
        )
    if result.recovered_after_uncertain and not result.success:
        raise TestWriteTransportError(
            "test_write_result_recovery_mismatch",
            "Test write result recovery verification failed",
        )
    if result.mutation_retry_count != TEST_WRITE_MUTATION_RETRY_COUNT:
        raise TestWriteTransportError(
            "test_write_result_mutation_retry_mismatch",
            "Test write result mutation retry verification failed",
        )
    expected_journal_state = {
        TestWriteExecutionState.SUCCEEDED: TestWriteJournalState.COMPLETED,
        TestWriteExecutionState.FAILED: TestWriteJournalState.FAILED,
        TestWriteExecutionState.UNCERTAIN: TestWriteJournalState.UNCERTAIN,
        TestWriteExecutionState.ETAG_CONFLICT: TestWriteJournalState.ETAG_CONFLICT,
    }[result.state]
    if result.journal.state is not expected_journal_state:
        raise TestWriteTransportError(
            "test_write_result_journal_state_mismatch",
            "Test write result terminal journal state verification failed",
        )
    if (
        result.journal.target_safe_ref != result.target_safe_ref
        or result.journal.run_spec_ref != result.run_spec_ref
        or result.journal.source_ref != result.source_ref
        or result.journal.operation is not result.operation
        or result.journal.api_call_count != result.api_call_count
        or result.journal.read_retry_count != result.read_retry_count
        or result.journal.mutation_attempt_count != result.mutation_attempt_count
        or result.journal.recovered_after_uncertain != result.recovered_after_uncertain
    ):
        raise TestWriteTransportError(
            "test_write_result_journal_binding_mismatch",
            "Test write result journal binding verification failed",
        )


@dataclass
class _Counters:
    api_calls: int = 0
    read_retries: int = 0
    mutation_attempts: int = 0

    def consume_api_call(self) -> None:
        if self.api_calls >= MAX_TEST_WRITE_API_CALLS:
            raise TestWriteTransportError(
                "test_write_api_call_budget_exceeded",
                "Test write API call budget was exhausted",
            )
        self.api_calls += 1

    def consume_mutation(self) -> None:
        if self.mutation_attempts >= MAX_TEST_WRITE_MUTATION_ATTEMPTS:
            raise TestWriteTransportError(
                "test_write_mutation_attempt_exceeded",
                "A second Test write mutation is forbidden",
            )
        self.consume_api_call()
        self.mutation_attempts += 1


def _hash(domain: bytes, value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def _result_data(result: TestWriteExecutionResult) -> dict[str, object]:
    return {
        "schema_version": result.schema_version,
        "result_type": result.result_type,
        "live_test_write": result.live_test_write,
        "test_only": result.test_only,
        "production_locked": result.production_locked,
        "state": result.state.value,
        "target_safe_ref": result.target_safe_ref,
        "run_spec_ref": result.run_spec_ref,
        "source_ref": result.source_ref,
        "operation": result.operation.value,
        "success": result.success,
        "read_back_verified": result.read_back_verified,
        "recovered_after_uncertain": result.recovered_after_uncertain,
        "api_call_count": result.api_call_count,
        "read_retry_count": result.read_retry_count,
        "mutation_attempt_count": result.mutation_attempt_count,
        "mutation_retry_count": result.mutation_retry_count,
        "stopped": result.stopped,
        "safe_findings": list(result.safe_findings),
        "journal_content_hash": result.journal.journal_content_hash,
    }


def calculate_test_write_execution_result_hash(result: TestWriteExecutionResult) -> str:
    """Calculate the deterministic safe result hash."""

    return _hash(_RESULT_HASH_DOMAIN, _result_data(result))


def verify_test_write_execution_result(result: TestWriteExecutionResult) -> None:
    """Verify journal binding and the deterministic result hash."""

    _verify_test_write_execution_result_semantics(result)
    if not hmac.compare_digest(
        calculate_test_write_execution_result_hash(result),
        result.result_content_hash,
    ):
        raise TestWriteTransportError(
            "test_write_result_hash_mismatch",
            "Test write result integrity verification failed",
        )


def _default_jitter(maximum: float) -> float:
    return random.uniform(0.0, maximum)


def _read_with_retry(
    call: Callable[[], Mapping[str, object]],
    *,
    operation: Literal["events.list", "events.get"],
    counters: _Counters,
    policy: RetryPolicy,
    sleep: Callable[[float], None],
    jitter: Callable[[float], float],
) -> Mapping[str, object]:
    total_wait = 0.0
    for attempt in range(1, policy.max_attempts + 1):
        counters.consume_api_call()
        try:
            return call()
        except Exception as exc:
            safe_error = safe_google_error_from_exception(
                exc,
                attempt=attempt,
                operation=operation,
            )
        if not safe_error.retryable or attempt == policy.max_attempts:
            raise safe_error from None
        delay = min(
            policy.base_delay_seconds * (2 ** (attempt - 1)),
            policy.maximum_delay_seconds,
        )
        try:
            jitter_value = jitter(policy.maximum_jitter_seconds)
        except Exception:
            jitter_value = 0.0
        if not math.isfinite(jitter_value):
            jitter_value = 0.0
        jitter_value = min(max(jitter_value, 0.0), policy.maximum_jitter_seconds)
        delay = min(delay + jitter_value, policy.maximum_delay_seconds)
        if total_wait + delay > policy.maximum_total_wait_seconds:
            raise safe_error from None
        sleep(delay)
        total_wait += delay
        counters.read_retries += 1
    raise TestWriteTransportError(
        "test_write_read_retry_exhausted",
        "Test write read retry policy was exhausted",
    )


def _metadata(page: Mapping[str, object]) -> dict[str, object]:
    values = {
        "summary": page.get("summary"),
        "timeZone": page.get("timeZone"),
        "accessRole": page.get("accessRole"),
    }
    if not all(isinstance(value, str) and value for value in values.values()):
        raise TestWriteTransportError(
            "test_write_target_metadata_missing",
            "Test write target metadata is incomplete",
        )
    return values


def _validate_page_metadata(
    target: TestWriteTargetConfig,
    page: Mapping[str, object],
    expected: dict[str, object] | None,
) -> dict[str, object]:
    metadata = _metadata(page)
    if expected is not None and metadata != expected:
        raise TestWriteTransportError(
            "test_write_target_metadata_changed",
            "Test write target metadata changed during pagination",
        )
    verify_test_write_target_metadata(
        target,
        TestWriteTargetObservation(
            summary=str(metadata["summary"]),
            access_role=str(metadata["accessRole"]),
            time_zone=str(metadata["timeZone"]),
        ),
    )
    return metadata


def _fresh_snapshot(
    client: TestCalendarWriteClient,
    target: TestWriteTargetConfig,
    counters: _Counters,
    *,
    policy: RetryPolicy,
    sleep: Callable[[float], None],
    jitter: Callable[[float], float],
) -> GoogleSnapshot:
    pages: list[Mapping[str, object]] = []
    seen_tokens: set[str] = set()
    page_token: str | None = None
    item_count = 0
    metadata: dict[str, object] | None = None
    while True:
        if len(pages) >= MAX_TEST_WRITE_PAGES:
            raise TestWriteTransportError(
                "test_write_pagination_limit",
                "Test write snapshot pagination limit was exceeded",
            )

        def list_page(token: str | None = page_token) -> Mapping[str, object]:
            return client.list_events(
                page_token=token,
                ical_uid=None,
            )

        response = _read_with_retry(
            list_page,
            operation="events.list",
            counters=counters,
            policy=policy,
            sleep=sleep,
            jitter=jitter,
        )
        metadata = _validate_page_metadata(target, response, metadata)
        raw_items = response.get("items", [])
        if not isinstance(raw_items, list) or not all(
            isinstance(item, Mapping) for item in raw_items
        ):
            raise TestWriteTransportError(
                "invalid_test_write_snapshot_response",
                "Test write snapshot response is invalid",
            )
        pages.append(response)
        item_count += len(raw_items)
        next_token = response.get("nextPageToken")
        if next_token is None:
            break
        if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
            raise TestWriteTransportError(
                "test_write_pagination_cycle",
                "Test write snapshot pagination is invalid",
            )
        seen_tokens.add(next_token)
        page_token = next_token
    if metadata is None:
        raise TestWriteTransportError(
            "test_write_target_metadata_missing",
            "Test write target metadata is incomplete",
        )
    metadata_hash = _hash(_METADATA_HASH_DOMAIN, metadata)
    fetched = FetchedGooglePages(
        target_fingerprint=target.expected_target_fingerprint,
        pages=tuple(pages),
        page_count=len(pages),
        item_count=item_count,
        retry_count=counters.read_retries,
        refreshed_after_401=False,
        collection_metadata_hash=metadata_hash,
        collection_summary=str(metadata["summary"]),
        time_zone=str(metadata["timeZone"]),
        access_role=str(metadata["accessRole"]),
    )
    return sanitize_fetched_pages(fetched, captured_at=datetime.now(UTC))


def _managed_state_matches_event(
    state: TestWriteManagedState,
    event: CanonicalGoogleEvent,
    *,
    require_clean_observations: bool,
) -> bool:
    compatible = (
        event.ical_uid == state.ical_uid
        and event.summary == state.summary
        and event.description == state.description
        and event.start is not None
        and event.end is not None
        and event.start.date == state.start_date
        and event.end.date == state.end_date
        and event.all_day is True
        and not event.end_time_unspecified
        and event.status != "cancelled"
        and event.event_type == "default"
        and not event.recurrence
        and event.recurring_event_id is None
        and event.original_start_time is None
        and not event.locked
        and not event.private_copy
    )
    if require_clean_observations:
        compatible = compatible and event.color_id is None and event.event_label_id is None
    return compatible


def _raw_event_matches_state(
    state: TestWriteManagedState,
    raw: Mapping[str, object],
    *,
    require_clean_observations: bool,
) -> bool:
    start = raw.get("start")
    end = raw.get("end")
    compatible = (
        raw.get("iCalUID") == state.ical_uid
        and raw.get("summary") == state.summary
        and raw.get("description") == state.description
        and isinstance(start, Mapping)
        and set(start) == {"date"}
        and start.get("date") == state.start_date.isoformat()
        and isinstance(end, Mapping)
        and set(end) == {"date"}
        and end.get("date") == state.end_date.isoformat()
        and raw.get("endTimeUnspecified", False) is False
        and raw.get("status") != "cancelled"
        and raw.get("eventType") == "default"
        and not raw.get("recurrence")
        and raw.get("recurringEventId") is None
        and raw.get("originalStartTime") is None
        and raw.get("locked", False) is False
        and raw.get("privateCopy", False) is False
    )
    if require_clean_observations:
        compatible = compatible and raw.get("colorId") is None and raw.get("eventLabelId") is None
    return compatible


def _read_back_finding(
    state: TestWriteManagedState,
    raw: Mapping[str, object],
    *,
    expected_event_id: str,
) -> str | None:
    if raw.get("id") != expected_event_id or not _raw_event_matches_state(
        state,
        raw,
        require_clean_observations=False,
    ):
        return "test_write_read_back_mismatch"
    if raw.get("colorId") is not None or raw.get("eventLabelId") is not None:
        return "unexpected_event_color_or_label"
    if not isinstance(raw.get("etag"), str) or not raw.get("etag"):
        return "test_write_read_back_etag_missing"
    return None


def _import_body(state: TestWriteManagedState) -> dict[str, object]:
    if state.summary is None or state.description is None:
        raise TestWriteTransportError(
            "test_write_desired_text_missing",
            "Test write desired content is incomplete",
        )
    return {
        "iCalUID": state.ical_uid,
        "summary": state.summary,
        "description": state.description,
        "start": {"date": state.start_date.isoformat()},
        "end": {"date": state.end_date.isoformat()},
        "eventType": "default",
    }


def _patch_body(
    run_spec: TestWriteRunSpec | TestSingleUpdateRunSpec,
) -> dict[str, object]:
    operation = run_spec.operation
    desired = operation.desired_state
    body: dict[str, object] = {}
    if "summary" in operation.changed_fields:
        body["summary"] = desired.summary
    if "description" in operation.changed_fields:
        body["description"] = desired.description
    if "start_date" in operation.changed_fields or "end_date" in operation.changed_fields:
        body["start"] = {"date": desired.start_date.isoformat()}
        body["end"] = {"date": desired.end_date.isoformat()}
    return body


def _list_uid_matches(
    client: TestCalendarWriteClient,
    target: TestWriteTargetConfig,
    uid: str,
    counters: _Counters,
    *,
    policy: RetryPolicy,
    sleep: Callable[[float], None],
    jitter: Callable[[float], float],
) -> list[Mapping[str, object]]:
    matches: list[Mapping[str, object]] = []
    seen_tokens: set[str] = set()
    page_token: str | None = None
    expected_metadata: dict[str, object] | None = None
    while True:

        def list_page(token: str | None = page_token) -> Mapping[str, object]:
            return client.list_events(
                page_token=token,
                ical_uid=uid,
            )

        page = _read_with_retry(
            list_page,
            operation="events.list",
            counters=counters,
            policy=policy,
            sleep=sleep,
            jitter=jitter,
        )
        expected_metadata = _validate_page_metadata(target, page, expected_metadata)
        items = page.get("items", [])
        if not isinstance(items, list) or not all(isinstance(item, Mapping) for item in items):
            raise TestWriteTransportError(
                "invalid_test_write_lookup_response",
                "Test write identity lookup response is invalid",
            )
        matches.extend(item for item in items if isinstance(item, Mapping))
        next_token = page.get("nextPageToken")
        if next_token is None:
            return matches
        if not isinstance(next_token, str) or not next_token or next_token in seen_tokens:
            raise TestWriteTransportError(
                "test_write_pagination_cycle",
                "Test write identity lookup pagination is invalid",
            )
        seen_tokens.add(next_token)
        page_token = next_token


def _get_event(
    client: TestCalendarWriteClient,
    target: TestWriteTargetConfig,
    event_id: str,
    counters: _Counters,
    *,
    policy: RetryPolicy,
    sleep: Callable[[float], None],
    jitter: Callable[[float], float],
) -> Mapping[str, object]:
    return _read_with_retry(
        lambda: client.get_event(event_id=event_id),
        operation="events.get",
        counters=counters,
        policy=policy,
        sleep=sleep,
        jitter=jitter,
    )


def _safe_code(error: BaseException) -> str:
    if isinstance(error, SafeGoogleError):
        return error.reason
    code = getattr(error, "code", None)
    if isinstance(code, str) and code in TEST_WRITE_SAFE_ERROR_CODES:
        return code
    return "test_write_guard_failed"


def _append(
    journal: TestWriteJournal,
    counters: _Counters,
    *,
    phase: TestWriteJournalPhase,
    status: TestWriteJournalEntryStatus,
    code: str | None = None,
    recovered: bool = False,
    terminal: TestWriteJournalState | None = None,
) -> TestWriteJournal:
    return append_test_write_journal_entry(
        journal,
        phase=phase,
        status=status,
        api_call_count=counters.api_calls,
        read_retry_count=counters.read_retries,
        mutation_attempt_count=counters.mutation_attempts,
        safe_error_code=code,
        recovered_after_uncertain=recovered,
        terminal_state=terminal,
    )


def _final_result(
    run_spec: AnyTestWriteRunSpec,
    journal: TestWriteJournal,
    *,
    state: TestWriteExecutionState,
    read_back_verified: bool,
    findings: tuple[str, ...] = (),
) -> TestWriteExecutionResult:
    success = state is TestWriteExecutionState.SUCCEEDED
    provisional = TestWriteExecutionResult(
        state=state,
        target_safe_ref=run_spec.target_safe_ref,
        run_spec_ref=f"R-{run_spec.run_spec_content_hash[:12]}",
        source_ref=run_spec.operation.source_ref,
        operation=run_spec.operation.operation,
        success=success,
        read_back_verified=read_back_verified,
        recovered_after_uncertain=journal.recovered_after_uncertain,
        api_call_count=journal.api_call_count,
        read_retry_count=journal.read_retry_count,
        mutation_attempt_count=journal.mutation_attempt_count,
        mutation_retry_count=0,
        stopped=not success,
        safe_findings=findings,
        journal=journal,
        result_content_hash="0" * 64,
    )
    result = provisional.model_copy(
        update={"result_content_hash": calculate_test_write_execution_result_hash(provisional)}
    )
    verify_test_write_execution_result(result)
    return result


def _failed_result(
    run_spec: AnyTestWriteRunSpec,
    journal: TestWriteJournal,
    counters: _Counters,
    error: BaseException,
    *,
    phase: TestWriteJournalPhase,
) -> TestWriteExecutionResult:
    code = _safe_code(error)
    state = (
        TestWriteExecutionState.ETAG_CONFLICT
        if code == "etag_conflict"
        else TestWriteExecutionState.FAILED
    )
    journal_state = (
        TestWriteJournalState.ETAG_CONFLICT
        if state is TestWriteExecutionState.ETAG_CONFLICT
        else TestWriteJournalState.FAILED
    )
    journal = _append(
        journal,
        counters,
        phase=phase,
        status=TestWriteJournalEntryStatus.FAILED,
        code=code,
        terminal=journal_state,
    )
    return _final_result(
        run_spec,
        journal,
        state=state,
        read_back_verified=False,
        findings=(code,),
    )


def _preflight(
    run_spec: AnyTestWriteRunSpec,
    target: TestWriteTargetConfig,
    client: TestCalendarWriteClient,
    counters: _Counters,
    *,
    policy: RetryPolicy,
    sleep: Callable[[float], None],
    jitter: Callable[[float], float],
) -> tuple[GoogleSnapshot, CanonicalGoogleEvent | None]:
    snapshot = _fresh_snapshot(
        client,
        target,
        counters,
        policy=policy,
        sleep=sleep,
        jitter=jitter,
    )
    if not hmac.compare_digest(snapshot.content_hash, run_spec.current_snapshot_hash):
        raise TestWriteTransportError(
            "test_write_snapshot_hash_mismatch",
            "Fresh Test snapshot does not match the approved Run Spec",
        )
    desired = run_spec.operation.desired_state
    matches = [event for event in snapshot.events if event.ical_uid == desired.ical_uid]
    if run_spec.operation.operation is TestWriteOperationKind.ADD:
        if matches:
            raise TestWriteTransportError(
                "test_write_add_identity_exists",
                "Test write add identity already exists",
            )
        return snapshot, None
    if len(matches) != 1:
        code = (
            "test_write_update_identity_missing" if not matches else "test_write_duplicate_identity"
        )
        raise TestWriteTransportError(code, "Test write update identity is ambiguous")
    match = matches[0]
    operation = run_spec.operation
    if (
        operation.google_event_id is None
        or operation.expected_etag is None
        or operation.current_state is None
        or match.event_id != operation.google_event_id
        or match.etag != operation.expected_etag
        or not _managed_state_matches_event(
            operation.current_state,
            match,
            require_clean_observations=False,
        )
    ):
        raise TestWriteTransportError(
            "test_write_update_snapshot_mismatch",
            "Test write update snapshot identity changed",
        )
    return snapshot, match


def run_test_calendar_write(
    run_spec: AnyTestWriteRunSpec,
    target: TestWriteTargetConfig,
    client: TestCalendarWriteClient,
    confirmation: str,
    *,
    current_snapshot_hash: str,
    current_plan_hash: str,
    current_baseline_hash: str | None = None,
    bootstrap_plan: TestBootstrapAddPlan | None = None,
    single_update_plan: TestSingleUpdatePlan | None = None,
    trusted_baseline: TrustedBaseline | None = None,
    read_policy: RetryPolicy | None = None,
    sleep: Callable[[float], None] = time.sleep,
    jitter: Callable[[float], float] = _default_jitter,
) -> TestWriteExecutionResult:
    """Run exactly one Test add or update with no blind mutation retry."""

    # Every Production and artifact-integrity guard runs before the client is touched.
    verify_any_test_write_run_spec(
        run_spec,
        bootstrap_plan=bootstrap_plan,
        single_update_plan=single_update_plan,
        trusted_baseline=trusted_baseline,
    )
    validate_test_write_target_config(target)
    target_ref = test_write_target_reference(target)
    if (
        run_spec.target_safe_ref == PRODUCTION_TARGET_REFERENCE
        or target_ref == PRODUCTION_TARGET_REFERENCE
        or run_spec.target_safe_ref != target_ref
        or not hmac.compare_digest(
            run_spec.target_fingerprint,
            target.expected_target_fingerprint,
        )
    ):
        raise TestWriteTransportError(
            "production_or_mismatched_test_write_target",
            "Production or mismatched Calendar write access is forbidden",
        )
    approve_any_test_write_run_spec(
        run_spec,
        confirmation,
        current_snapshot_hash=current_snapshot_hash,
        current_plan_hash=current_plan_hash,
        current_baseline_hash=current_baseline_hash,
        bootstrap_plan=bootstrap_plan,
        single_update_plan=single_update_plan,
        trusted_baseline=trusted_baseline,
    )
    client.verify_bound_target(target)

    policy = read_policy or RetryPolicy()
    counters = _Counters()
    journal = initialize_test_write_journal(
        run_spec,
        bootstrap_plan=bootstrap_plan,
        single_update_plan=single_update_plan,
        trusted_baseline=trusted_baseline,
    )
    try:
        _snapshot, matched_event = _preflight(
            run_spec,
            target,
            client,
            counters,
            policy=policy,
            sleep=sleep,
            jitter=jitter,
        )
        operation = run_spec.operation
        if operation.operation is TestWriteOperationKind.UPDATE:
            if not isinstance(run_spec, (TestWriteRunSpec, TestSingleUpdateRunSpec)):
                raise TestWriteTransportError(
                    "test_bootstrap_update_forbidden",
                    "Bootstrap Run Spec cannot reach the Update transport",
                )
            if isinstance(run_spec, TestSingleUpdateRunSpec) and (
                operation.changed_fields != SINGLE_UPDATE_CHANGED_FIELDS
                or single_update_plan is None
                or trusted_baseline is None
            ):
                raise TestWriteTransportError(
                    "test_single_update_transport_policy_mismatch",
                    "Single Update transport requires exact dedicated artifacts",
                )
            assert matched_event is not None
            assert operation.google_event_id is not None
            assert operation.expected_etag is not None
            assert operation.current_state is not None
            fresh = _get_event(
                client,
                target,
                matched_event.event_id,
                counters,
                policy=policy,
                sleep=sleep,
                jitter=jitter,
            )
            if (
                fresh.get("id") != operation.google_event_id
                or fresh.get("etag") != operation.expected_etag
                or not _raw_event_matches_state(
                    operation.current_state,
                    fresh,
                    require_clean_observations=False,
                )
            ):
                raise TestWriteTransportError(
                    "etag_conflict",
                    "Fresh Test event does not match the approved ETag and state",
                )
        journal = _append(
            journal,
            counters,
            phase=TestWriteJournalPhase.PREFLIGHT,
            status=TestWriteJournalEntryStatus.SUCCEEDED,
        )
    except Exception as exc:
        return _failed_result(
            run_spec,
            journal,
            counters,
            exc,
            phase=TestWriteJournalPhase.PREFLIGHT,
        )

    desired = run_spec.operation.desired_state
    mutation_error: SafeGoogleError | None = None
    response: Mapping[str, object] | None = None
    try:
        client.verify_bound_target(target)
        counters.consume_mutation()
        if run_spec.operation.operation is TestWriteOperationKind.ADD:
            response = client.import_event(
                body=_import_body(desired),
            )
        else:
            # The Bootstrap operation type is Literal[ADD], so this branch is
            # statically narrowed to the existing normal Run Spec.
            event_id = run_spec.operation.google_event_id
            etag = run_spec.operation.expected_etag
            if event_id is None or etag is None:
                raise TestWriteTransportError(
                    "test_write_update_identity_missing",
                    "Test write update identity is incomplete",
                )
            response = client.patch_event(
                event_id=event_id,
                body=_patch_body(run_spec),
                etag=etag,
            )
        journal = _append(
            journal,
            counters,
            phase=TestWriteJournalPhase.MUTATION,
            status=TestWriteJournalEntryStatus.SUCCEEDED,
        )
    except Exception as exc:
        mutation_error = safe_google_error_from_exception(
            exc,
            attempt=1,
            operation=(
                "events.import"
                if run_spec.operation.operation is TestWriteOperationKind.ADD
                else "events.patch"
            ),
        )
        if mutation_error.reason == "etag_conflict":
            return _failed_result(
                run_spec,
                journal,
                counters,
                mutation_error,
                phase=TestWriteJournalPhase.MUTATION,
            )
        if not mutation_error.retryable:
            return _failed_result(
                run_spec,
                journal,
                counters,
                mutation_error,
                phase=TestWriteJournalPhase.MUTATION,
            )
        journal = _append(
            journal,
            counters,
            phase=TestWriteJournalPhase.MUTATION,
            status=TestWriteJournalEntryStatus.UNCERTAIN,
            code="write_outcome_uncertain",
        )

    try:
        if mutation_error is not None:
            if run_spec.operation.operation is TestWriteOperationKind.ADD:
                matches = _list_uid_matches(
                    client,
                    target,
                    desired.ical_uid,
                    counters,
                    policy=policy,
                    sleep=sleep,
                    jitter=jitter,
                )
                if len(matches) > 1:
                    raise TestWriteTransportError(
                        "duplicate_identity",
                        "Test import recovery found an ambiguous identity",
                    )
                if len(matches) != 1 or not _raw_event_matches_state(
                    desired,
                    matches[0],
                    require_clean_observations=True,
                ):
                    raise TestWriteTransportError(
                        "write_outcome_uncertain",
                        "Test import outcome could not be verified",
                    )
            else:
                event_id = run_spec.operation.google_event_id
                if event_id is None:
                    raise TestWriteTransportError(
                        "write_outcome_uncertain",
                        "Test patch outcome could not be verified",
                    )
                recovered = _get_event(
                    client,
                    target,
                    event_id,
                    counters,
                    policy=policy,
                    sleep=sleep,
                    jitter=jitter,
                )
                if (
                    recovered.get("id") != event_id
                    or not _raw_event_matches_state(
                        desired,
                        recovered,
                        require_clean_observations=True,
                    )
                    or not isinstance(recovered.get("etag"), str)
                ):
                    raise TestWriteTransportError(
                        "write_outcome_uncertain",
                        "Test patch outcome could not be verified",
                    )
            journal = _append(
                journal,
                counters,
                phase=TestWriteJournalPhase.UNCERTAIN_CHECK,
                status=TestWriteJournalEntryStatus.RECOVERED,
                recovered=True,
                terminal=TestWriteJournalState.COMPLETED,
            )
            return _final_result(
                run_spec,
                journal,
                state=TestWriteExecutionState.SUCCEEDED,
                read_back_verified=True,
            )

        if run_spec.operation.operation is TestWriteOperationKind.ADD:
            event_id_value = response.get("id") if response is not None else None
            event_id = event_id_value if isinstance(event_id_value, str) else None
        else:
            event_id = run_spec.operation.google_event_id
        if not isinstance(event_id, str) or not event_id:
            raise TestWriteTransportError(
                "test_write_read_back_identity_missing",
                "Test write read-back identity is missing",
            )
        read_back = _get_event(
            client,
            target,
            event_id,
            counters,
            policy=policy,
            sleep=sleep,
            jitter=jitter,
        )
        read_back_finding = _read_back_finding(
            desired,
            read_back,
            expected_event_id=event_id,
        )
        if read_back_finding is not None:
            raise TestWriteTransportError(
                read_back_finding,
                "Test write read-back verification failed",
            )
        journal = _append(
            journal,
            counters,
            phase=TestWriteJournalPhase.READ_BACK,
            status=TestWriteJournalEntryStatus.SUCCEEDED,
            terminal=TestWriteJournalState.COMPLETED,
        )
        return _final_result(
            run_spec,
            journal,
            state=TestWriteExecutionState.SUCCEEDED,
            read_back_verified=True,
        )
    except Exception as exc:
        if mutation_error is not None:
            if _safe_code(exc) == "duplicate_identity":
                return _failed_result(
                    run_spec,
                    journal,
                    counters,
                    exc,
                    phase=TestWriteJournalPhase.UNCERTAIN_CHECK,
                )
            journal = _append(
                journal,
                counters,
                phase=TestWriteJournalPhase.UNCERTAIN_CHECK,
                status=TestWriteJournalEntryStatus.UNCERTAIN,
                code="write_outcome_uncertain",
                terminal=TestWriteJournalState.UNCERTAIN,
            )
            return _final_result(
                run_spec,
                journal,
                state=TestWriteExecutionState.UNCERTAIN,
                read_back_verified=False,
                findings=("write_outcome_uncertain",),
            )
        return _failed_result(
            run_spec,
            journal,
            counters,
            exc,
            phase=TestWriteJournalPhase.READ_BACK,
        )


__all__ = [
    "MAX_TEST_WRITE_API_CALLS",
    "MAX_TEST_WRITE_MUTATION_ATTEMPTS",
    "TEST_WRITE_MUTATION_RETRY_COUNT",
    "TestWriteExecutionResult",
    "TestWriteExecutionState",
    "TestWriteTransportError",
    "calculate_test_write_execution_result_hash",
    "run_test_calendar_write",
    "verify_test_write_execution_result",
]
