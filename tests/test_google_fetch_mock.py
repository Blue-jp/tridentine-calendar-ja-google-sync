from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from tridentine_calendar_google_sync.google_errors import SafeGoogleError
from tridentine_calendar_google_sync.google_fetch import (
    MAX_FETCH_PAGES,
    RetryPolicy,
    fetch_google_event_pages,
)

pytestmark = pytest.mark.google_read
TARGET_FINGERPRINT = "d" * 64


def _scenario(fixtures: Path, name: str) -> dict[str, object]:
    return json.loads((fixtures / f"{name}.json").read_text(encoding="utf-8"))


class SequenceClient:
    def __init__(self, responses: list[object]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str | None]] = []

    def list_events(
        self,
        *,
        calendar_id: str,
        page_token: str | None,
    ) -> Mapping[str, object]:
        self.calls.append((calendar_id, page_token))
        if not self.responses:
            raise AssertionError("mock response sequence exhausted")
        response = self.responses.pop(0)
        if isinstance(response, BaseException):
            raise response
        assert isinstance(response, Mapping)
        return response


class EndlessPagesClient:
    def __init__(self) -> None:
        self.call_count = 0

    def list_events(
        self,
        *,
        calendar_id: str,
        page_token: str | None,
    ) -> Mapping[str, object]:
        del calendar_id, page_token
        self.call_count += 1
        return {"items": [], "nextPageToken": f"fixture-page-{self.call_count}"}


def _fetch(client: object, **kwargs: object):
    return fetch_google_event_pages(
        client,  # type: ignore[arg-type]
        calendar_id="fixture-target",
        target_fingerprint=TARGET_FINGERPRINT,
        expected_target_fingerprint=TARGET_FINGERPRINT,
        sleep=lambda _delay: None,
        jitter=lambda _maximum: 0.0,
        **kwargs,  # type: ignore[arg-type]
    )


def test_one_page_fetch_has_safe_complete_metadata(google_api_pages_dir: Path) -> None:
    responses = _scenario(google_api_pages_dir, "one_page")["responses"]
    assert isinstance(responses, list)
    client = SequenceClient(responses)

    fetched = _fetch(client)

    assert fetched.page_count == 1
    assert fetched.item_count == 1
    assert fetched.retry_count == 0
    assert fetched.refreshed_after_401 is False
    assert len(fetched.collection_metadata_hash) == 64
    assert client.calls == [("fixture-target", None)]
    assert "fixture-api-001@example.invalid" not in repr(fetched)


def test_two_page_fetch_passes_next_page_token(google_api_pages_dir: Path) -> None:
    responses = _scenario(google_api_pages_dir, "two_pages")["responses"]
    assert isinstance(responses, list)
    client = SequenceClient(responses)

    fetched = _fetch(client)

    assert fetched.page_count == 2
    assert fetched.item_count == 2
    assert client.calls == [
        ("fixture-target", None),
        ("fixture-target", "fixture-page-2"),
    ]


def test_three_page_fetch_reaches_final_page() -> None:
    client = SequenceClient(
        [
            {"items": [], "nextPageToken": "fixture-page-2"},
            {"items": [], "nextPageToken": "fixture-page-3"},
            {"items": []},
        ]
    )

    fetched = _fetch(client)

    assert fetched.page_count == 3
    assert client.calls == [
        ("fixture-target", None),
        ("fixture-target", "fixture-page-2"),
        ("fixture-target", "fixture-page-3"),
    ]


def test_empty_page_with_token_does_not_end_pagination(google_api_pages_dir: Path) -> None:
    responses = _scenario(google_api_pages_dir, "empty_page_with_token")["responses"]
    assert isinstance(responses, list)
    client = SequenceClient(responses)

    fetched = _fetch(client)

    assert fetched.page_count == 2
    assert fetched.item_count == 1
    assert client.calls[1][1] == "fixture-after-empty"


def test_pagination_cycle_is_fatal() -> None:
    client = SequenceClient(
        [
            {"items": [], "nextPageToken": "fixture-cycle"},
            {"items": [], "nextPageToken": "fixture-cycle"},
        ]
    )

    with pytest.raises(SafeGoogleError) as caught:
        _fetch(client)

    assert caught.value.reason == "pagination_cycle"
    assert caught.value.retryable is False


def test_pagination_has_hard_page_limit() -> None:
    client = EndlessPagesClient()

    with pytest.raises(SafeGoogleError) as caught:
        _fetch(client)

    assert caught.value.reason == "pagination_limit"
    assert client.call_count == MAX_FETCH_PAGES


def test_collection_metadata_must_match_across_pages() -> None:
    client = SequenceClient(
        [
            {
                "items": [],
                "summary": "Synthetic A",
                "timeZone": "UTC",
                "accessRole": "owner",
                "nextPageToken": "fixture-page-2",
            },
            {
                "items": [],
                "summary": "Synthetic B",
                "timeZone": "UTC",
                "accessRole": "owner",
            },
        ]
    )

    with pytest.raises(SafeGoogleError) as caught:
        _fetch(client)

    assert caught.value.reason == "invalid_response"


@pytest.mark.parametrize(
    ("field", "changed_value"),
    [
        ("summary", "Synthetic changed summary"),
        ("timeZone", "Etc/UTC"),
        ("accessRole", "reader"),
    ],
)
def test_each_collection_metadata_field_is_consistent_across_pages(
    field: str,
    changed_value: str,
) -> None:
    first = {
        "items": [],
        "summary": "Synthetic target",
        "timeZone": "UTC",
        "accessRole": "owner",
        "nextPageToken": "fixture-page-2",
    }
    second = {
        "items": [],
        "summary": "Synthetic target",
        "timeZone": "UTC",
        "accessRole": "owner",
    }
    second[field] = changed_value

    with pytest.raises(SafeGoogleError) as caught:
        _fetch(SequenceClient([first, second]))

    assert caught.value.reason == "invalid_response"


def test_first_page_metadata_is_validated_once_and_stored_safely() -> None:
    observations: list[tuple[str | None, str | None, str | None]] = []
    page = {
        "items": [],
        "summary": "Synthetic target",
        "timeZone": "UTC",
        "accessRole": "owner",
    }

    fetched = fetch_google_event_pages(
        SequenceClient([page]),
        calendar_id="fixture-target",
        target_fingerprint=TARGET_FINGERPRINT,
        expected_target_fingerprint=TARGET_FINGERPRINT,
        validate_metadata=lambda summary, time_zone, access_role: observations.append(
            (summary, time_zone, access_role)
        ),
        sleep=lambda _delay: None,
        jitter=lambda _maximum: 0.0,
    )

    assert observations == [("Synthetic target", "UTC", "owner")]
    assert fetched.collection_summary == "Synthetic target"
    assert fetched.time_zone == "UTC"
    assert fetched.access_role == "owner"
    assert "Synthetic target" not in repr(fetched)


def test_target_fingerprint_mismatch_stops_before_client_call() -> None:
    client = SequenceClient([{"items": []}])

    with pytest.raises(SafeGoogleError) as caught:
        fetch_google_event_pages(
            client,
            calendar_id="fixture-target",
            target_fingerprint="d" * 64,
            expected_target_fingerprint="e" * 64,
            sleep=lambda _delay: None,
            jitter=lambda _maximum: 0.0,
        )

    assert caught.value.reason == "target_mismatch"
    assert client.calls == []


def test_zero_event_page_is_valid_complete_fetch() -> None:
    fetched = _fetch(SequenceClient([{"items": []}]))

    assert fetched.page_count == 1
    assert fetched.item_count == 0


def test_malformed_items_shape_is_rejected(google_api_pages_dir: Path) -> None:
    responses = _scenario(google_api_pages_dir, "malformed")["responses"]
    assert isinstance(responses, list)

    with pytest.raises(SafeGoogleError) as caught:
        _fetch(SequenceClient(responses))

    assert caught.value.reason == "invalid_response"


def _safe_error(status: int, reason: str, retryable: bool) -> SafeGoogleError:
    return SafeGoogleError(
        status=status,
        reason=reason,
        retryable=retryable,
        attempt=1,
        operation="events.list",
    )


def test_retry_uses_bounded_exponential_backoff_and_injected_jitter() -> None:
    client = SequenceClient(
        [
            _safe_error(429, "rate_limited", True),
            _safe_error(503, "service_unavailable", True),
            {"items": []},
        ]
    )
    delays: list[float] = []
    jitter_calls: list[float] = []

    fetched = fetch_google_event_pages(
        client,
        calendar_id="fixture-target",
        target_fingerprint=TARGET_FINGERPRINT,
        expected_target_fingerprint=TARGET_FINGERPRINT,
        sleep=delays.append,
        jitter=lambda maximum: jitter_calls.append(maximum) or 0.25,
    )

    assert fetched.retry_count == 2
    assert delays == [1.25, 2.25]
    assert jitter_calls == [0.5, 0.5]


@pytest.mark.parametrize(
    "error",
    [
        _safe_error(429, "rate_limited", True),
        _safe_error(500, "backend_error", True),
        _safe_error(502, "backend_error", True),
        _safe_error(503, "service_unavailable", True),
        pytest.param(
            _safe_error(403, "rate_limited", True),
            id="403-rateLimitExceeded",
        ),
        pytest.param(
            _safe_error(403, "rate_limited", True),
            id="403-userRateLimitExceeded",
        ),
    ],
)
def test_retryable_status_and_reason_matrix_executes_one_bounded_retry(
    error: SafeGoogleError,
) -> None:
    delays: list[float] = []
    client = SequenceClient([error, {"items": []}])

    fetched = fetch_google_event_pages(
        client,
        calendar_id="fixture-target",
        target_fingerprint=TARGET_FINGERPRINT,
        expected_target_fingerprint=TARGET_FINGERPRINT,
        sleep=delays.append,
        jitter=lambda _maximum: 0.0,
    )

    assert fetched.retry_count == 1
    assert len(client.calls) == 2
    assert delays == [1.0]


def test_nonretryable_error_never_sleeps() -> None:
    delays: list[float] = []
    client = SequenceClient([_safe_error(403, "forbidden", False)])

    with pytest.raises(SafeGoogleError) as caught:
        fetch_google_event_pages(
            client,
            calendar_id="fixture-target",
            target_fingerprint=TARGET_FINGERPRINT,
            expected_target_fingerprint=TARGET_FINGERPRINT,
            sleep=delays.append,
            jitter=lambda _maximum: 0.5,
        )

    assert caught.value.reason == "forbidden"
    assert delays == []
    assert len(client.calls) == 1


@pytest.mark.parametrize(
    "error",
    [
        _safe_error(400, "bad_request", False),
        _safe_error(403, "forbidden", False),
        _safe_error(410, "unknown", False),
    ],
)
def test_nonretryable_status_matrix_stops_after_one_call(error: SafeGoogleError) -> None:
    delays: list[float] = []
    client = SequenceClient([error])

    with pytest.raises(SafeGoogleError) as caught:
        fetch_google_event_pages(
            client,
            calendar_id="fixture-target",
            target_fingerprint=TARGET_FINGERPRINT,
            expected_target_fingerprint=TARGET_FINGERPRINT,
            sleep=delays.append,
            jitter=lambda _maximum: 0.0,
        )

    assert caught.value.reason == error.reason
    assert len(client.calls) == 1
    assert delays == []


def test_retry_exhaustion_is_bounded_to_five_attempts() -> None:
    delays: list[float] = []
    client = SequenceClient([_safe_error(500, "backend_error", True)] * 5)

    with pytest.raises(SafeGoogleError) as caught:
        fetch_google_event_pages(
            client,
            calendar_id="fixture-target",
            target_fingerprint=TARGET_FINGERPRINT,
            expected_target_fingerprint=TARGET_FINGERPRINT,
            sleep=delays.append,
            jitter=lambda _maximum: 0.0,
        )

    assert caught.value.reason == "retry_exhausted"
    assert caught.value.attempt == 5
    assert len(client.calls) == 5
    assert delays == [1.0, 2.0, 4.0, 8.0]


def test_invalid_jitter_is_clamped_without_real_sleep() -> None:
    delays: list[float] = []
    client = SequenceClient([_safe_error(429, "rate_limited", True), {"items": []}])

    fetched = fetch_google_event_pages(
        client,
        calendar_id="fixture-target",
        target_fingerprint=TARGET_FINGERPRINT,
        expected_target_fingerprint=TARGET_FINGERPRINT,
        sleep=delays.append,
        jitter=lambda _maximum: float("inf"),
    )

    assert fetched.retry_count == 1
    assert delays == [1.0]


def test_unauthorized_refreshes_credentials_once_without_sleep() -> None:
    delays: list[float] = []
    refresh_calls = 0
    client = SequenceClient([_safe_error(401, "unauthorized", False), {"items": []}])

    def refresh() -> None:
        nonlocal refresh_calls
        refresh_calls += 1

    fetched = fetch_google_event_pages(
        client,
        calendar_id="fixture-target",
        target_fingerprint=TARGET_FINGERPRINT,
        expected_target_fingerprint=TARGET_FINGERPRINT,
        refresh_credentials=refresh,
        sleep=delays.append,
        jitter=lambda _maximum: 0.0,
    )

    assert fetched.refreshed_after_401 is True
    assert fetched.retry_count == 1
    assert refresh_calls == 1
    assert delays == []


def test_retry_policy_rejects_unbounded_or_nonfinite_values() -> None:
    with pytest.raises(ValueError):
        RetryPolicy(max_attempts=6)
    with pytest.raises(ValueError):
        RetryPolicy(maximum_total_wait_seconds=float("inf"))
    with pytest.raises(ValueError):
        RetryPolicy(base_delay_seconds=0.0)
