"""Bounded full-pagination Google events.list orchestration."""

from __future__ import annotations

import hashlib
import json
import math
import random
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from tridentine_calendar_google_sync.google_client import ReadOnlyCalendarClient
from tridentine_calendar_google_sync.google_errors import (
    SafeGoogleError,
    safe_google_error_from_exception,
)

MAX_FETCH_PAGES = 100
_METADATA_HASH_DOMAIN = b"tridentine-calendar-google-sync:collection-metadata:v1\x00"
_COLLECTION_METADATA_KEYS = ("summary", "timeZone", "accessRole")


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Bounded exponential backoff policy for one online fetch."""

    max_attempts: int = 5
    base_delay_seconds: float = 1.0
    maximum_delay_seconds: float = 16.0
    maximum_jitter_seconds: float = 0.5
    maximum_total_wait_seconds: float = 30.0

    def __post_init__(self) -> None:
        if self.max_attempts != 5:
            raise ValueError("Phase 3A retry attempts must equal five")
        numeric_values = (
            self.base_delay_seconds,
            self.maximum_delay_seconds,
            self.maximum_jitter_seconds,
            self.maximum_total_wait_seconds,
        )
        if any(not math.isfinite(value) or value < 0 for value in numeric_values):
            raise ValueError("retry timing must be finite and nonnegative")
        if self.base_delay_seconds <= 0 or self.maximum_delay_seconds <= 0:
            raise ValueError("retry delays must be positive")


@dataclass(frozen=True, slots=True)
class FetchedGooglePages:
    """Raw in-memory pages plus safe collection-level observations."""

    target_fingerprint: str
    pages: tuple[Mapping[str, object], ...] = field(repr=False)
    page_count: int
    item_count: int
    retry_count: int
    refreshed_after_401: bool
    collection_metadata_hash: str
    collection_summary: str | None = field(default=None, repr=False)
    time_zone: str | None = field(default=None, repr=False)
    access_role: str | None = field(default=None, repr=False)


def _safe_fetch_error(
    *,
    reason: str,
    attempt: int,
    retryable: bool = False,
    status: int | None = None,
    operation: str = "events.list",
) -> SafeGoogleError:
    return SafeGoogleError(
        status=status,
        reason=reason,
        retryable=retryable,
        attempt=attempt,
        operation=operation,
    )


def _validate_target(target_fingerprint: str, expected_target_fingerprint: str) -> None:
    valid_shape = (
        len(target_fingerprint) == 64
        and len(expected_target_fingerprint) == 64
        and all(character in "0123456789abcdef" for character in target_fingerprint)
        and all(character in "0123456789abcdef" for character in expected_target_fingerprint)
    )
    if not valid_shape or target_fingerprint != expected_target_fingerprint:
        raise _safe_fetch_error(
            reason="target_mismatch",
            attempt=1,
            operation="target.validate",
        )


def _metadata_from_page(page: Mapping[str, object]) -> dict[str, object]:
    metadata: dict[str, object] = {}
    for key in _COLLECTION_METADATA_KEYS:
        value = page.get(key)
        if value is not None and not isinstance(value, str):
            raise _safe_fetch_error(reason="invalid_response", attempt=1)
        metadata[key] = value
    return metadata


def _metadata_hash(metadata: Mapping[str, object]) -> str:
    encoded = json.dumps(
        metadata,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(_METADATA_HASH_DOMAIN + encoded).hexdigest()


def _validated_page(
    response: Mapping[str, object],
    *,
    attempt: int,
) -> tuple[list[Mapping[str, object]], str | None, dict[str, object]]:
    raw_items = response.get("items", [])
    if not isinstance(raw_items, list):
        raise _safe_fetch_error(reason="invalid_response", attempt=attempt)
    items: list[Mapping[str, object]] = []
    for item in raw_items:
        if not isinstance(item, Mapping):
            raise _safe_fetch_error(reason="invalid_response", attempt=attempt)
        if not all(isinstance(key, str) for key in item):
            raise _safe_fetch_error(reason="invalid_response", attempt=attempt)
        items.append(item)
    next_page_token = response.get("nextPageToken")
    if next_page_token is not None and (
        not isinstance(next_page_token, str) or not next_page_token
    ):
        raise _safe_fetch_error(reason="invalid_response", attempt=attempt)
    return items, next_page_token, _metadata_from_page(response)


def _default_jitter(maximum: float) -> float:
    return random.uniform(0.0, maximum)


def _refresh_once(refresh_credentials: Callable[[], None], *, attempt: int) -> None:
    try:
        refresh_credentials()
    except Exception as exc:
        raise safe_google_error_from_exception(
            exc,
            attempt=attempt,
            operation="credentials.refresh",
        ) from None


def _list_with_retry(
    client: ReadOnlyCalendarClient,
    *,
    calendar_id: str,
    page_token: str | None,
    policy: RetryPolicy,
    sleep: Callable[[float], None],
    jitter: Callable[[float], float],
    refresh_credentials: Callable[[], None] | None,
    refresh_state: list[bool],
    wait_state: list[float],
) -> tuple[Mapping[str, object], int]:
    retry_count = 0
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return (
                client.list_events(calendar_id=calendar_id, page_token=page_token),
                retry_count,
            )
        except Exception as exc:
            safe_error = safe_google_error_from_exception(
                exc,
                attempt=attempt,
                operation="events.list",
            )
        if safe_error.status == 401 and refresh_credentials is not None and not refresh_state[0]:
            _refresh_once(refresh_credentials, attempt=attempt)
            refresh_state[0] = True
            retry_count += 1
            continue
        if not safe_error.retryable:
            raise safe_error from None
        if attempt == policy.max_attempts:
            raise _safe_fetch_error(
                reason="retry_exhausted",
                status=safe_error.status,
                attempt=attempt,
            ) from None
        backoff = min(
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
        delay = min(backoff + jitter_value, policy.maximum_delay_seconds)
        if wait_state[0] + delay > policy.maximum_total_wait_seconds:
            raise _safe_fetch_error(
                reason="retry_exhausted",
                status=safe_error.status,
                attempt=attempt,
            ) from None
        sleep(delay)
        wait_state[0] += delay
        retry_count += 1
    raise _safe_fetch_error(reason="retry_exhausted", attempt=policy.max_attempts)


def fetch_google_event_pages(
    client: ReadOnlyCalendarClient,
    *,
    calendar_id: str,
    target_fingerprint: str,
    expected_target_fingerprint: str,
    retry_policy: RetryPolicy | None = None,
    sleep: Callable[[float], None] = time.sleep,
    jitter: Callable[[float], float] = _default_jitter,
    refresh_credentials: Callable[[], None] | None = None,
    validate_metadata: Callable[[str | None, str | None, str | None], None] | None = None,
) -> FetchedGooglePages:
    """Fetch a complete full snapshot using only paginated events.list calls."""

    if not calendar_id:
        raise _safe_fetch_error(reason="target_mismatch", attempt=1, operation="target.validate")
    _validate_target(target_fingerprint, expected_target_fingerprint)
    policy = retry_policy or RetryPolicy()
    pages: list[Mapping[str, object]] = []
    requested_tokens: set[str] = set()
    page_token: str | None = None
    item_count = 0
    retry_count = 0
    expected_metadata: dict[str, object] | None = None
    refresh_state = [False]
    wait_state = [0.0]

    while True:
        if len(pages) >= MAX_FETCH_PAGES:
            raise _safe_fetch_error(reason="pagination_limit", attempt=1)
        if page_token is not None:
            if page_token in requested_tokens:
                raise _safe_fetch_error(reason="pagination_cycle", attempt=1)
            requested_tokens.add(page_token)
        response, page_retries = _list_with_retry(
            client,
            calendar_id=calendar_id,
            page_token=page_token,
            policy=policy,
            sleep=sleep,
            jitter=jitter,
            refresh_credentials=refresh_credentials,
            refresh_state=refresh_state,
            wait_state=wait_state,
        )
        items, next_page_token, metadata = _validated_page(response, attempt=1)
        if expected_metadata is None:
            expected_metadata = metadata
            if validate_metadata is not None:
                validate_metadata(
                    metadata["summary"] if isinstance(metadata["summary"], str) else None,
                    metadata["timeZone"] if isinstance(metadata["timeZone"], str) else None,
                    metadata["accessRole"] if isinstance(metadata["accessRole"], str) else None,
                )
        elif metadata != expected_metadata:
            raise _safe_fetch_error(reason="invalid_response", attempt=1)
        pages.append(response)
        item_count += len(items)
        retry_count += page_retries
        if next_page_token is None:
            break
        page_token = next_page_token

    collection_summary = expected_metadata["summary"]
    time_zone = expected_metadata["timeZone"]
    access_role = expected_metadata["accessRole"]
    if not (
        (collection_summary is None or isinstance(collection_summary, str))
        and (time_zone is None or isinstance(time_zone, str))
        and (access_role is None or isinstance(access_role, str))
    ):
        raise _safe_fetch_error(reason="invalid_response", attempt=1)
    return FetchedGooglePages(
        target_fingerprint=target_fingerprint,
        pages=tuple(pages),
        page_count=len(pages),
        item_count=item_count,
        retry_count=retry_count,
        refreshed_after_401=refresh_state[0],
        collection_metadata_hash=_metadata_hash(expected_metadata),
        collection_summary=collection_summary,
        time_zone=time_zone,
        access_role=access_role,
    )


fetch_google_pages = fetch_google_event_pages


__all__ = [
    "MAX_FETCH_PAGES",
    "FetchedGooglePages",
    "RetryPolicy",
    "fetch_google_event_pages",
    "fetch_google_pages",
]
