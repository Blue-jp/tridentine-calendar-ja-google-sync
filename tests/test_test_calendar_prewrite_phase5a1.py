from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest
from phase5a1_helpers import (
    SequencePrewriteClient,
    make_prewrite_target_config,
    prewrite_event,
    prewrite_page,
)

from tridentine_calendar_google_sync.google_errors import SafeGoogleError
from tridentine_calendar_google_sync.test_calendar_prewrite import (
    MAX_TEST_PREWRITE_API_CALLS,
    inspect_test_calendar_prewrite,
    verify_test_calendar_prewrite_result,
)
from tridentine_calendar_google_sync.test_calendar_prewrite_models import (
    TEST_CALENDAR_NOT_EMPTY_FINDING,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetPolicyError as TargetPolicyError,
)

pytestmark = pytest.mark.google_test_write

CAPTURED_AT = datetime(2026, 8, 24, 0, 0, tzinfo=UTC)


def _inspect(client: SequencePrewriteClient, **kwargs: object) -> Any:
    return inspect_test_calendar_prewrite(
        client,
        make_prewrite_target_config(),
        sleep=lambda _delay: None,
        jitter=lambda _maximum: 0.0,
        captured_at=CAPTURED_AT,
        **kwargs,  # type: ignore[arg-type]
    )


def _safe_error(status: int, reason: str, retryable: bool) -> SafeGoogleError:
    return SafeGoogleError(
        status=status,
        reason=reason,
        retryable=retryable,
        attempt=1,
        operation="events.list",
    )


def test_empty_test_calendar_is_complete_and_write_ready() -> None:
    client = SequencePrewriteClient([prewrite_page()])

    result = _inspect(client)

    assert result.report.prewrite_ready is True
    assert result.report.event_count == 0
    assert result.report.cancelled_count == 0
    assert result.report.recurring_count == 0
    assert result.report.timed_count == 0
    assert result.report.non_default_event_type_count == 0
    assert result.report.color_id_count == 0
    assert result.report.event_label_id_count == 0
    assert result.report.findings == ()
    assert result.report.google_write_method_count == 0
    assert result.report.google_write_operation_count == 0
    assert result.report.event_changes == 0
    assert result.snapshot.complete is True
    assert result.snapshot.snapshot.complete is True
    assert result.snapshot.event_count == 0
    assert result.snapshot.page_count == 1
    assert result.snapshot.api_call_count == 1
    assert client.calls == [(make_prewrite_target_config().calendar_id, None)]
    verify_test_calendar_prewrite_result(result)


def test_nonempty_test_calendar_is_preserved_and_requires_manual_review() -> None:
    event = prewrite_event()
    client = SequencePrewriteClient([prewrite_page([event])])

    result = _inspect(client)

    assert result.report.prewrite_ready is False
    assert result.report.event_count == 1
    assert [finding.code for finding in result.report.findings] == [TEST_CALENDAR_NOT_EMPTY_FINDING]
    assert result.report.findings[0].severity == "fatal"
    assert result.snapshot.snapshot.events[0].ical_uid == event["iCalUID"]
    assert not hasattr(client, "get_event")
    assert not hasattr(client, "import_event")
    assert not hasattr(client, "patch_event")
    assert not hasattr(client, "delete_event")


def test_nonempty_aggregate_safety_counts_are_observed_without_mutation() -> None:
    event = prewrite_event(
        status="cancelled",
        start={"dateTime": "2026-09-01T00:00:00+09:00"},
        end={"dateTime": "2026-09-01T01:00:00+09:00"},
        eventType="focusTime",
        recurrence=["RRULE:FREQ=DAILY"],
        recurringEventId="evtfixtureparent001",
        originalStartTime={"date": "2026-09-01"},
        colorId="1",
        eventLabelId="fixture-label",
    )

    result = _inspect(SequencePrewriteClient([prewrite_page([event])]))

    assert result.report.event_count == 1
    assert result.report.cancelled_count == 1
    assert result.report.recurring_count == 1
    assert result.report.timed_count == 1
    assert result.report.non_default_event_type_count == 1
    assert result.report.color_id_count == 1
    assert result.report.event_label_id_count == 1
    assert result.report.prewrite_ready is False


@pytest.mark.parametrize("page_count", (2, 3))
def test_pagination_fetches_every_page_in_order(page_count: int) -> None:
    pages = [
        prewrite_page(
            next_page_token=(f"fixture-page-{index + 2}" if index + 1 < page_count else None)
        )
        for index in range(page_count)
    ]
    client = SequencePrewriteClient(pages)

    result = _inspect(client)

    assert result.snapshot.page_count == page_count
    assert result.snapshot.api_call_count == page_count
    assert result.snapshot.retry_count == 0
    assert [token for _calendar_id, token in client.calls] == [
        None,
        *(f"fixture-page-{index}" for index in range(2, page_count + 1)),
    ]


def test_empty_page_with_next_token_continues_to_final_page() -> None:
    client = SequencePrewriteClient(
        [
            prewrite_page(next_page_token="fixture-after-empty"),
            prewrite_page(),
        ]
    )

    result = _inspect(client)

    assert result.report.prewrite_ready is True
    assert result.report.page_count == 2
    assert client.calls[1][1] == "fixture-after-empty"


@pytest.mark.parametrize(
    "responses",
    (
        [
            prewrite_page(next_page_token="fixture-cycle"),
            prewrite_page(next_page_token="fixture-cycle"),
        ],
        [
            prewrite_page(next_page_token="fixture-a"),
            prewrite_page(next_page_token="fixture-b"),
            prewrite_page(next_page_token="fixture-a"),
        ],
    ),
)
def test_repeated_or_cyclic_page_token_is_fatal(responses: list[object]) -> None:
    client = SequencePrewriteClient(responses)

    with pytest.raises(SafeGoogleError) as captured:
        _inspect(client)
    assert captured.value.reason == "pagination_cycle"
    assert len(client.calls) <= MAX_TEST_PREWRITE_API_CALLS


def test_total_api_call_hard_maximum_is_five() -> None:
    client = SequencePrewriteClient(
        [prewrite_page(next_page_token=f"fixture-page-{index + 2}") for index in range(5)]
    )

    with pytest.raises(SafeGoogleError) as captured:
        _inspect(client)
    assert captured.value.reason == "pagination_limit"
    assert len(client.calls) == 5
    assert MAX_TEST_PREWRITE_API_CALLS == 5


@pytest.mark.parametrize(
    "error",
    (
        _safe_error(429, "rate_limited", True),
        _safe_error(403, "rate_limited", True),
        _safe_error(500, "backend_error", True),
        _safe_error(502, "backend_error", True),
        _safe_error(503, "service_unavailable", True),
    ),
)
def test_allowlisted_transient_read_error_retries_once_without_real_sleep(
    error: SafeGoogleError,
) -> None:
    delays: list[float] = []
    client = SequencePrewriteClient([error, prewrite_page()])

    result = inspect_test_calendar_prewrite(
        client,
        make_prewrite_target_config(),
        sleep=delays.append,
        jitter=lambda _maximum: 0.0,
        captured_at=CAPTURED_AT,
    )

    assert result.report.retry_count == 1
    assert result.report.api_call_count == 2
    assert delays == [1.0]


@pytest.mark.parametrize(
    "error",
    (
        _safe_error(400, "bad_request", False),
        _safe_error(403, "forbidden", False),
        _safe_error(404, "not_found", False),
        _safe_error(410, "unknown", False),
        _safe_error(None if False else 422, "invalid_response", False),
    ),
)
def test_nonretryable_error_stops_after_one_call(error: SafeGoogleError) -> None:
    client = SequencePrewriteClient([error])
    delays: list[float] = []

    with pytest.raises(SafeGoogleError) as captured:
        inspect_test_calendar_prewrite(
            client,
            make_prewrite_target_config(),
            sleep=delays.append,
            jitter=lambda _maximum: 0.0,
            captured_at=CAPTURED_AT,
        )
    assert captured.value.reason == error.reason
    assert len(client.calls) == 1
    assert delays == []


def test_retry_exhaustion_never_exceeds_five_calls() -> None:
    client = SequencePrewriteClient(
        [_safe_error(503, "service_unavailable", True) for _index in range(5)]
    )

    with pytest.raises(SafeGoogleError) as captured:
        _inspect(client)
    assert captured.value.reason == "retry_exhausted"
    assert len(client.calls) == 5


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("summary", "Wrong Synthetic Test Calendar"),
        ("time_zone", "UTC"),
        ("access_role", "reader"),
    ),
)
def test_first_page_metadata_must_match_target_exactly(field: str, value: str) -> None:
    overrides = {field: value}
    client = SequencePrewriteClient([prewrite_page(**overrides)])  # type: ignore[arg-type]

    with pytest.raises(TargetPolicyError):
        _inspect(client)
    assert len(client.calls) == 1


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("summary", "Changed Synthetic Test Calendar"),
        ("time_zone", "UTC"),
        ("access_role", "reader"),
    ),
)
def test_metadata_cannot_change_between_pages(field: str, value: str) -> None:
    second_overrides = {field: value}
    client = SequencePrewriteClient(
        [
            prewrite_page(next_page_token="fixture-page-2"),
            prewrite_page(**second_overrides),  # type: ignore[arg-type]
        ]
    )

    with pytest.raises(SafeGoogleError) as captured:
        _inspect(client)
    assert captured.value.reason == "invalid_response"
    assert len(client.calls) == 2


@pytest.mark.parametrize(
    "response",
    (
        {"summary": "Synthetic Test", "timeZone": "Asia/Tokyo", "accessRole": "owner", "items": {}},
        prewrite_page(next_page_token=""),
        prewrite_page(items=[{"not": "a complete event"}]),
        {"summary": 1, "timeZone": "Asia/Tokyo", "accessRole": "owner", "items": []},
    ),
)
def test_malformed_page_never_produces_partial_success(response: dict[str, object]) -> None:
    client = SequencePrewriteClient([response])

    with pytest.raises(SafeGoogleError):
        _inspect(client)
    assert len(client.calls) == 1


def test_second_page_failure_returns_no_partial_result() -> None:
    client = SequencePrewriteClient(
        [
            prewrite_page(next_page_token="fixture-page-2"),
            _safe_error(403, "forbidden", False),
        ]
    )

    with pytest.raises(SafeGoogleError) as captured:
        _inspect(client)
    assert captured.value.reason == "forbidden"
    assert len(client.calls) == 2


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("target_environment", "production"),
        ("target_label", "production"),
        ("target_purpose", "production_calendar_sync"),
        ("calendar_id", "primary"),
        ("expected_summary", "Calendar without marker"),
        ("expected_target_fingerprint", "f" * 64),
    ),
)
def test_target_policy_failure_occurs_before_list_call(field: str, value: str) -> None:
    target = make_prewrite_target_config().model_copy(update={field: value})
    client = SequencePrewriteClient([prewrite_page()])

    with pytest.raises(TargetPolicyError):
        inspect_test_calendar_prewrite(client, target, captured_at=CAPTURED_AT)
    assert client.calls == []
