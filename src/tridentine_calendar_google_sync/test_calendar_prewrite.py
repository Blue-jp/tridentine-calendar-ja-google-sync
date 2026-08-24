"""List-only Test Calendar prewrite inspection and readiness classification."""

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
from typing import Self

from pydantic import Field, model_validator

from tridentine_calendar_google_sync.google_errors import (
    SafeGoogleError,
    safe_google_error_from_exception,
)
from tridentine_calendar_google_sync.google_fetch import FetchedGooglePages, RetryPolicy
from tridentine_calendar_google_sync.google_sanitize import sanitize_fetched_pages
from tridentine_calendar_google_sync.google_test_prewrite_client import (
    TestCalendarPrewriteListClient,
)
from tridentine_calendar_google_sync.models import StrictFrozenModel
from tridentine_calendar_google_sync.test_calendar_prewrite_models import (
    TEST_CALENDAR_NOT_EMPTY_FINDING,
    TestCalendarPrewriteFinding,
    TestCalendarPrewriteReport,
    TestCalendarPrewriteSnapshot,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetConfig,
    TestWriteTargetObservation,
    test_write_target_reference,
    validate_test_write_target_config,
    verify_test_write_target_metadata,
)

MAX_TEST_PREWRITE_API_CALLS = 5
_METADATA_HASH_DOMAIN = b"tridentine-calendar-google-sync:collection-metadata:v1\x00"
_WRAPPER_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-prewrite-snapshot:v1\x00"
_REPORT_HASH_DOMAIN = b"tridentine-calendar-google-sync:test-prewrite-report:v1\x00"


class TestCalendarPrewriteError(ValueError):
    """A content-free local prewrite inspection failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class TestCalendarPrewriteResult(StrictFrozenModel):
    """Safe public report bound to one private sanitized snapshot wrapper."""

    snapshot: TestCalendarPrewriteSnapshot = Field(repr=False, exclude=True)
    report: TestCalendarPrewriteReport

    @model_validator(mode="after")
    def report_is_bound_to_snapshot(self) -> Self:
        if (
            self.report.result_binding_hash != self.snapshot.wrapper_content_hash
            or self.report.snapshot_hash != self.snapshot.snapshot_content_hash
            or self.report.target_safe_ref != self.snapshot.target_safe_ref
            or self.report.event_count != self.snapshot.event_count
            or self.report.page_count != self.snapshot.page_count
            or self.report.api_call_count != self.snapshot.api_call_count
            or self.report.retry_count != self.snapshot.retry_count
        ):
            raise ValueError("Test prewrite result binding is invalid")
        return self


@dataclass(slots=True)
class _Counters:
    api_calls: int = 0
    retries: int = 0
    total_wait_seconds: float = 0.0

    def consume_call(self) -> int:
        if self.api_calls >= MAX_TEST_PREWRITE_API_CALLS:
            raise _safe_error("pagination_limit", attempt=MAX_TEST_PREWRITE_API_CALLS)
        self.api_calls += 1
        return self.api_calls


def _hash(domain: bytes, value: object) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(domain + encoded).hexdigest()


def _safe_error(
    reason: str,
    *,
    attempt: int,
    status: int | None = None,
    retryable: bool = False,
) -> SafeGoogleError:
    return SafeGoogleError(
        status=status,
        reason=reason,
        retryable=retryable,
        attempt=attempt,
        operation="events.list",
    )


def _default_jitter(maximum: float) -> float:
    return random.uniform(0.0, maximum)


def _is_allowed_retry(error: SafeGoogleError) -> bool:
    if error.status in {403, 429}:
        return error.reason == "rate_limited"
    if error.status in {500, 502}:
        return error.reason == "backend_error"
    if error.status == 503:
        return error.reason in {"backend_error", "service_unavailable"}
    return False


def _list_with_retry(
    client: TestCalendarPrewriteListClient,
    target: TestWriteTargetConfig,
    *,
    page_token: str | None,
    counters: _Counters,
    policy: RetryPolicy,
    sleep: Callable[[float], None],
    jitter: Callable[[float], float],
) -> Mapping[str, object]:
    for page_attempt in range(1, policy.max_attempts + 1):
        call_attempt = counters.consume_call()
        try:
            return client.list_events(
                calendar_id=target.calendar_id,
                page_token=page_token,
            )
        except Exception as exc:
            safe_error = safe_google_error_from_exception(
                exc,
                attempt=call_attempt,
                operation="events.list",
            )
        if not _is_allowed_retry(safe_error):
            raise safe_error from None
        if page_attempt == policy.max_attempts or counters.api_calls >= MAX_TEST_PREWRITE_API_CALLS:
            raise _safe_error(
                "retry_exhausted",
                attempt=call_attempt,
                status=safe_error.status,
            ) from None
        backoff = min(
            policy.base_delay_seconds * (2 ** (page_attempt - 1)),
            policy.maximum_delay_seconds,
        )
        try:
            jitter_value = jitter(policy.maximum_jitter_seconds)
        except Exception:
            jitter_value = 0.0
        if not math.isfinite(jitter_value):
            jitter_value = 0.0
        jitter_value = min(max(jitter_value, 0.0), policy.maximum_jitter_seconds)
        delay = min(backoff + jitter_value, policy.maximum_delay_seconds)
        if counters.total_wait_seconds + delay > policy.maximum_total_wait_seconds:
            raise _safe_error(
                "retry_exhausted",
                attempt=call_attempt,
                status=safe_error.status,
            ) from None
        sleep(delay)
        counters.total_wait_seconds += delay
        counters.retries += 1
    raise _safe_error("retry_exhausted", attempt=counters.api_calls)


def _metadata(page: Mapping[str, object]) -> dict[str, str]:
    values = {
        "summary": page.get("summary"),
        "timeZone": page.get("timeZone"),
        "accessRole": page.get("accessRole"),
    }
    if not all(isinstance(value, str) and value for value in values.values()):
        raise _safe_error("invalid_response", attempt=1)
    return {key: str(value) for key, value in values.items()}


def _validated_page(
    response: Mapping[str, object],
) -> tuple[list[Mapping[str, object]], str | None, dict[str, str]]:
    items_value = response.get("items", [])
    if not isinstance(items_value, list):
        raise _safe_error("invalid_response", attempt=1)
    items: list[Mapping[str, object]] = []
    for item in items_value:
        if not isinstance(item, Mapping) or not all(isinstance(key, str) for key in item):
            raise _safe_error("invalid_response", attempt=1)
        items.append(item)
    next_token = response.get("nextPageToken")
    if next_token is not None and (not isinstance(next_token, str) or not next_token):
        raise _safe_error("invalid_response", attempt=1)
    return items, next_token, _metadata(response)


def _metadata_hash(metadata: Mapping[str, str]) -> str:
    return _hash(_METADATA_HASH_DOMAIN, dict(metadata))


def _wrapper_hash_data(snapshot: TestCalendarPrewriteSnapshot) -> dict[str, object]:
    return {
        "schema_version": snapshot.schema_version,
        "snapshot_type": snapshot.snapshot_type,
        "test_only": snapshot.test_only,
        "production_locked": snapshot.production_locked,
        "target_fingerprint": snapshot.target_fingerprint,
        "target_safe_ref": snapshot.target_safe_ref,
        "complete": snapshot.complete,
        "page_count": snapshot.page_count,
        "api_call_count": snapshot.api_call_count,
        "retry_count": snapshot.retry_count,
        "snapshot_content_hash": snapshot.snapshot_content_hash,
    }


def calculate_test_calendar_prewrite_snapshot_hash(
    snapshot: TestCalendarPrewriteSnapshot,
) -> str:
    """Hash the private wrapper without trusting its stored digest."""

    return _hash(_WRAPPER_HASH_DOMAIN, _wrapper_hash_data(snapshot))


def _report_hash_data(report: TestCalendarPrewriteReport) -> dict[str, object]:
    return {
        "schema_version": report.schema_version,
        "inspection_type": report.inspection_type,
        "read_only": report.read_only,
        "prewrite_ready": report.prewrite_ready,
        "target_safe_ref": report.target_safe_ref,
        "scope_label": report.scope_label,
        "target_metadata_validation": report.target_metadata_validation,
        "snapshot_complete": report.snapshot_complete,
        "event_count": report.event_count,
        "cancelled_count": report.cancelled_count,
        "recurring_count": report.recurring_count,
        "timed_count": report.timed_count,
        "non_default_event_type_count": report.non_default_event_type_count,
        "color_id_count": report.color_id_count,
        "event_label_id_count": report.event_label_id_count,
        "page_count": report.page_count,
        "api_call_count": report.api_call_count,
        "retry_count": report.retry_count,
        "google_write_method_count": report.google_write_method_count,
        "google_write_operation_count": report.google_write_operation_count,
        "event_changes": report.event_changes,
        "snapshot_hash": report.snapshot_hash,
        "findings": [finding.model_dump(mode="json") for finding in report.findings],
        "result_binding_hash": report.result_binding_hash,
    }


def calculate_test_calendar_prewrite_report_hash(report: TestCalendarPrewriteReport) -> str:
    """Hash the public aggregate report without its stored digest."""

    return _hash(_REPORT_HASH_DOMAIN, _report_hash_data(report))


def verify_test_calendar_prewrite_result(result: TestCalendarPrewriteResult) -> None:
    """Verify private wrapper, public report, and cross-artifact binding."""

    wrapper = result.snapshot
    report = result.report
    if not hmac.compare_digest(
        calculate_test_calendar_prewrite_snapshot_hash(wrapper),
        wrapper.wrapper_content_hash,
    ):
        raise TestCalendarPrewriteError(
            "test_prewrite_snapshot_hash_mismatch",
            "Test prewrite snapshot integrity verification failed",
        )
    if not hmac.compare_digest(
        calculate_test_calendar_prewrite_report_hash(report),
        report.report_content_hash,
    ):
        raise TestCalendarPrewriteError(
            "test_prewrite_report_hash_mismatch",
            "Test prewrite report integrity verification failed",
        )
    if (
        report.result_binding_hash != wrapper.wrapper_content_hash
        or report.snapshot_hash != wrapper.snapshot_content_hash
        or report.target_safe_ref != wrapper.target_safe_ref
        or report.event_count != wrapper.event_count
        or report.page_count != wrapper.page_count
        or report.api_call_count != wrapper.api_call_count
        or report.retry_count != wrapper.retry_count
    ):
        raise TestCalendarPrewriteError(
            "test_prewrite_result_binding_mismatch",
            "Test prewrite result binding verification failed",
        )


def _aggregate_counts(snapshot: TestCalendarPrewriteSnapshot) -> dict[str, int]:
    events = snapshot.snapshot.events
    return {
        "event_count": len(events),
        "cancelled_count": sum(event.status == "cancelled" for event in events),
        "recurring_count": sum(
            bool(event.recurrence)
            or event.recurring_event_id is not None
            or event.original_start_time is not None
            for event in events
        ),
        "timed_count": sum(event.all_day is False for event in events),
        "non_default_event_type_count": sum(event.event_type != "default" for event in events),
        "color_id_count": sum(event.color_id is not None for event in events),
        "event_label_id_count": sum(event.event_label_id is not None for event in events),
    }


def _build_result(
    *,
    target_fingerprint: str,
    target_safe_ref: str,
    fetched: FetchedGooglePages,
    captured_at: datetime,
) -> TestCalendarPrewriteResult:
    sanitized = sanitize_fetched_pages(fetched, captured_at=captured_at)
    wrapper_provisional = TestCalendarPrewriteSnapshot(
        target_fingerprint=target_fingerprint,
        target_safe_ref=target_safe_ref,
        page_count=fetched.page_count,
        api_call_count=fetched.page_count + fetched.retry_count,
        retry_count=fetched.retry_count,
        snapshot=sanitized,
        snapshot_content_hash=sanitized.content_hash,
        wrapper_content_hash="0" * 64,
    )
    wrapper = wrapper_provisional.model_copy(
        update={
            "wrapper_content_hash": calculate_test_calendar_prewrite_snapshot_hash(
                wrapper_provisional
            )
        }
    )
    counts = _aggregate_counts(wrapper)
    ready = counts["event_count"] == 0
    findings = (
        ()
        if ready
        else (
            TestCalendarPrewriteFinding(
                severity="fatal",
                code=TEST_CALENDAR_NOT_EMPTY_FINDING,
                message="Test Calendar is not empty; manual review is required.",
            ),
        )
    )
    report_provisional = TestCalendarPrewriteReport(
        prewrite_ready=ready,
        target_safe_ref=target_safe_ref,
        event_count=counts["event_count"],
        cancelled_count=counts["cancelled_count"],
        recurring_count=counts["recurring_count"],
        timed_count=counts["timed_count"],
        non_default_event_type_count=counts["non_default_event_type_count"],
        color_id_count=counts["color_id_count"],
        event_label_id_count=counts["event_label_id_count"],
        page_count=fetched.page_count,
        api_call_count=fetched.page_count + fetched.retry_count,
        retry_count=fetched.retry_count,
        snapshot_hash=sanitized.content_hash,
        findings=findings,
        result_binding_hash=wrapper.wrapper_content_hash,
        report_content_hash="0" * 64,
    )
    report = report_provisional.model_copy(
        update={
            "report_content_hash": calculate_test_calendar_prewrite_report_hash(report_provisional)
        }
    )
    result = TestCalendarPrewriteResult(snapshot=wrapper, report=report)
    verify_test_calendar_prewrite_result(result)
    return result


def inspect_test_calendar_prewrite(
    client: TestCalendarPrewriteListClient,
    target: TestWriteTargetConfig,
    *,
    retry_policy: RetryPolicy | None = None,
    sleep: Callable[[float], None] = time.sleep,
    jitter: Callable[[float], float] = _default_jitter,
    captured_at: datetime | None = None,
) -> TestCalendarPrewriteResult:
    """Fetch a complete Test snapshot using list only and classify readiness."""

    target_fingerprint = validate_test_write_target_config(target)
    target_safe_ref = test_write_target_reference(target)
    policy = retry_policy or RetryPolicy()
    counters = _Counters()
    pages: list[Mapping[str, object]] = []
    requested_tokens: set[str] = set()
    page_token: str | None = None
    item_count = 0
    expected_metadata: dict[str, str] | None = None

    while True:
        if page_token is not None:
            if page_token in requested_tokens:
                raise _safe_error("pagination_cycle", attempt=max(counters.api_calls, 1))
            requested_tokens.add(page_token)
        response = _list_with_retry(
            client,
            target,
            page_token=page_token,
            counters=counters,
            policy=policy,
            sleep=sleep,
            jitter=jitter,
        )
        items, next_page_token, metadata = _validated_page(response)
        if expected_metadata is None:
            verify_test_write_target_metadata(
                target,
                TestWriteTargetObservation(
                    summary=metadata["summary"],
                    access_role=metadata["accessRole"],
                    time_zone=metadata["timeZone"],
                ),
            )
            expected_metadata = metadata
        elif metadata != expected_metadata:
            raise _safe_error("invalid_response", attempt=counters.api_calls)
        pages.append(response)
        item_count += len(items)
        if next_page_token is None:
            break
        if next_page_token in requested_tokens:
            raise _safe_error("pagination_cycle", attempt=counters.api_calls)
        if counters.api_calls >= MAX_TEST_PREWRITE_API_CALLS:
            raise _safe_error("pagination_limit", attempt=counters.api_calls)
        page_token = next_page_token

    if expected_metadata is None:
        raise _safe_error("invalid_response", attempt=max(counters.api_calls, 1))
    fetched = FetchedGooglePages(
        target_fingerprint=target_fingerprint,
        pages=tuple(pages),
        page_count=len(pages),
        item_count=item_count,
        retry_count=counters.retries,
        refreshed_after_401=False,
        collection_metadata_hash=_metadata_hash(expected_metadata),
        collection_summary=expected_metadata["summary"],
        time_zone=expected_metadata["timeZone"],
        access_role=expected_metadata["accessRole"],
    )
    resolved_captured_at = captured_at or datetime.now(UTC)
    return _build_result(
        target_fingerprint=target_fingerprint,
        target_safe_ref=target_safe_ref,
        fetched=fetched,
        captured_at=resolved_captured_at,
    )


__all__ = [
    "MAX_TEST_PREWRITE_API_CALLS",
    "TestCalendarPrewriteError",
    "TestCalendarPrewriteResult",
    "calculate_test_calendar_prewrite_report_hash",
    "calculate_test_calendar_prewrite_snapshot_hash",
    "inspect_test_calendar_prewrite",
    "verify_test_calendar_prewrite_result",
]
