"""List-only Google adapter for Test Calendar prewrite inspection."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from typing import Any, Protocol, cast

from tridentine_calendar_google_sync.google_errors import (
    SafeGoogleError,
    safe_google_error_from_exception,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetConfig,
    validate_test_write_target_config,
)

TEST_PREWRITE_MAX_RESULTS = 2500
TEST_PREWRITE_EVENT_FIELDS = (
    "id,iCalUID,summary,description,start(date,dateTime,timeZone),"
    "end(date,dateTime,timeZone),endTimeUnspecified,status,eventType,etag,sequence,"
    "recurrence,recurringEventId,originalStartTime(date,dateTime,timeZone),"
    "colorId,eventLabelId"
)
TEST_PREWRITE_LIST_FIELDS = (
    "summary,timeZone,accessRole,nextPageToken,items(" + TEST_PREWRITE_EVENT_FIELDS + ")"
)


class TestCalendarPrewriteClientError(ValueError):
    """A content-free list-only request or target validation failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class TestCalendarPrewriteListClient(Protocol):
    """The complete Test prewrite API surface: exactly one events.list page."""

    def list_events(
        self,
        *,
        calendar_id: str,
        page_token: str | None,
    ) -> Mapping[str, object]:
        """Execute one target-bound Test Calendar events.list request."""


def _validated_mapping(response: object) -> Mapping[str, object]:
    if not isinstance(response, Mapping) or not all(isinstance(key, str) for key in response):
        raise SafeGoogleError(
            status=None,
            reason="invalid_response",
            retryable=False,
            attempt=1,
            operation="events.list",
        )
    return cast(Mapping[str, object], response)


class GoogleTestCalendarPrewriteListClient:
    """Target-bound adapter exposing list only and no mutation capability."""

    __slots__ = ("__calendar_id", "__service")

    def __init__(self, service: object, *, calendar_id: str) -> None:
        if not calendar_id or calendar_id.casefold() == "primary":
            raise TestCalendarPrewriteClientError(
                "invalid_test_prewrite_calendar_id",
                "Test prewrite Calendar identity is invalid",
            )
        self.__service = service
        self.__calendar_id = calendar_id

    def __repr__(self) -> str:
        return "GoogleTestCalendarPrewriteListClient(read_only=True, test_only=True)"

    def list_events(
        self,
        *,
        calendar_id: str,
        page_token: str | None,
    ) -> Mapping[str, object]:
        """Call events.list with the immutable Test prewrite parameter set."""

        if not isinstance(calendar_id, str) or not hmac.compare_digest(
            calendar_id.encode("utf-8", errors="strict"),
            self.__calendar_id.encode("utf-8", errors="strict"),
        ):
            raise TestCalendarPrewriteClientError(
                "test_prewrite_calendar_id_mismatch",
                "Test prewrite Calendar identity did not match",
            )
        if page_token is not None and (not isinstance(page_token, str) or not page_token):
            raise TestCalendarPrewriteClientError(
                "invalid_test_prewrite_page_token",
                "Test prewrite page token is invalid",
            )
        try:
            service = cast(Any, self.__service)
            parameters: dict[str, object] = {
                "calendarId": self.__calendar_id,
                "maxResults": TEST_PREWRITE_MAX_RESULTS,
                "singleEvents": False,
                "showDeleted": True,
                "fields": TEST_PREWRITE_LIST_FIELDS,
            }
            if page_token is not None:
                parameters["pageToken"] = page_token
            response = service.events().list(**parameters).execute(num_retries=0)
            return _validated_mapping(response)
        except (SafeGoogleError, TestCalendarPrewriteClientError):
            raise
        except Exception as exc:
            raise safe_google_error_from_exception(
                exc,
                attempt=1,
                operation="events.list",
            ) from None


def build_test_calendar_prewrite_list_client(
    credentials: object,
    *,
    target_config: TestWriteTargetConfig,
    build_service: Any | None = None,
) -> TestCalendarPrewriteListClient:
    """Apply the Test/Production lock before constructing a list-only service."""

    validate_test_write_target_config(target_config)
    try:
        if build_service is None:
            from googleapiclient.discovery import build  # type: ignore[import-untyped]

            resolved_build = build
        else:
            resolved_build = build_service
        service = resolved_build(
            "calendar",
            "v3",
            credentials=credentials,
            cache_discovery=False,
        )
        return GoogleTestCalendarPrewriteListClient(
            service,
            calendar_id=target_config.calendar_id,
        )
    except TestCalendarPrewriteClientError:
        raise
    except Exception as exc:
        raise safe_google_error_from_exception(
            exc,
            attempt=1,
            operation="client.build",
        ) from None


__all__ = [
    "TEST_PREWRITE_EVENT_FIELDS",
    "TEST_PREWRITE_LIST_FIELDS",
    "TEST_PREWRITE_MAX_RESULTS",
    "GoogleTestCalendarPrewriteListClient",
    "TestCalendarPrewriteClientError",
    "TestCalendarPrewriteListClient",
    "build_test_calendar_prewrite_list_client",
]
