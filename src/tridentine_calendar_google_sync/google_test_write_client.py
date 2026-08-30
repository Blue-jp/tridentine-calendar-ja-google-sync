"""Narrow Test Calendar Google transport with no generic service escape hatch."""

from __future__ import annotations

import hmac
from collections.abc import Mapping
from datetime import date as Date
from typing import Any, Protocol, cast

from tridentine_calendar_google_sync.google_errors import (
    SafeGoogleError,
    safe_google_error_from_exception,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetConfig,
    validate_test_write_target_config,
)

TEST_WRITE_MAX_RESULTS = 2500
TEST_WRITE_EVENT_FIELDS = (
    "id,iCalUID,summary,description,start(date,dateTime,timeZone),"
    "end(date,dateTime,timeZone),endTimeUnspecified,status,eventType,etag,sequence,"
    "recurrence,recurringEventId,originalStartTime(date,dateTime,timeZone),"
    "colorId,eventLabelId"
)
TEST_WRITE_LIST_FIELDS = (
    "summary,timeZone,accessRole,nextPageToken,items(" + TEST_WRITE_EVENT_FIELDS + ")"
)
IMPORT_BODY_FIELDS = frozenset({"iCalUID", "summary", "description", "start", "end", "eventType"})
PATCH_BODY_FIELDS = frozenset({"summary", "description", "start", "end"})


class TestWriteClientError(ValueError):
    """A content-free local request validation failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


class TestCalendarWriteClient(Protocol):
    """The complete Phase 5A Google method allowlist."""

    def verify_bound_target(self, target_config: TestWriteTargetConfig) -> None:
        """Fail before API access unless the approved target matches this capability."""

    def list_events(
        self,
        *,
        page_token: str | None,
        ical_uid: str | None = None,
    ) -> Mapping[str, object]:
        """Execute one Test-only events.list page."""

    def get_event(
        self,
        *,
        event_id: str,
    ) -> Mapping[str, object]:
        """Execute one Test-only events.get request."""

    def import_event(
        self,
        *,
        body: Mapping[str, object],
    ) -> Mapping[str, object]:
        """Execute one Test-only events.import mutation."""

    def patch_event(
        self,
        *,
        event_id: str,
        body: Mapping[str, object],
        etag: str,
    ) -> Mapping[str, object]:
        """Execute one Test-only events.patch mutation with exact If-Match."""


def _validated_mapping(response: object, *, operation: str) -> Mapping[str, object]:
    if not isinstance(response, Mapping) or not all(isinstance(key, str) for key in response):
        raise SafeGoogleError(
            status=None,
            reason="invalid_response",
            retryable=False,
            attempt=1,
            operation=operation,
        )
    return cast(Mapping[str, object], response)


def _validated_all_day_boundary(value: object, *, name: str) -> Date:
    if not isinstance(value, Mapping) or set(value) != {"date"}:
        raise TestWriteClientError(
            "invalid_test_write_payload",
            "Test write payload is invalid",
        )
    raw_date = value.get("date")
    if not isinstance(raw_date, str):
        raise TestWriteClientError(
            "invalid_test_write_payload",
            "Test write payload is invalid",
        )
    try:
        return Date.fromisoformat(raw_date)
    except ValueError:
        raise TestWriteClientError(
            "invalid_test_write_payload",
            f"Test write {name} boundary is invalid",
        ) from None


def validate_import_body(body: Mapping[str, object]) -> None:
    """Require the exact Source-managed all-day import payload."""

    if set(body) != IMPORT_BODY_FIELDS:
        raise TestWriteClientError(
            "invalid_import_payload",
            "Test import payload is not allowlisted",
        )
    if body.get("eventType") != "default":
        raise TestWriteClientError(
            "invalid_import_event_type",
            "Test import requires a default event",
        )
    if (
        not isinstance(body.get("iCalUID"), str)
        or not body.get("iCalUID")
        or not isinstance(body.get("summary"), str)
        or not isinstance(body.get("description"), str)
    ):
        raise TestWriteClientError(
            "invalid_import_payload",
            "Test import payload is invalid",
        )
    start = _validated_all_day_boundary(body.get("start"), name="start")
    end = _validated_all_day_boundary(body.get("end"), name="end")
    if end <= start:
        raise TestWriteClientError(
            "invalid_import_date_span",
            "Test import date span is invalid",
        )


def validate_patch_body(body: Mapping[str, object]) -> None:
    """Require changed Source fields only and an atomic all-day date pair."""

    keys = set(body)
    if not keys or not keys <= PATCH_BODY_FIELDS:
        raise TestWriteClientError(
            "invalid_patch_payload",
            "Test patch payload is not allowlisted",
        )
    for field in ("summary", "description"):
        if field in body and not isinstance(body[field], str):
            raise TestWriteClientError(
                "invalid_patch_payload",
                "Test patch payload is invalid",
            )
    has_start = "start" in body
    has_end = "end" in body
    if has_start is not has_end:
        raise TestWriteClientError(
            "incomplete_patch_date_pair",
            "Test patch date boundaries must be changed atomically",
        )
    if has_start:
        start = _validated_all_day_boundary(body["start"], name="start")
        end = _validated_all_day_boundary(body["end"], name="end")
        if end <= start:
            raise TestWriteClientError(
                "invalid_patch_date_span",
                "Test patch date span is invalid",
            )


class GoogleTestCalendarWriteClient:
    """Adapter exposing only list, get, import, and patch operations."""

    __slots__ = ("__service", "__target_config")

    def __init__(self, service: object, *, target_config: TestWriteTargetConfig) -> None:
        validate_test_write_target_config(target_config)
        self.__service = service
        self.__target_config = target_config.model_copy(deep=True)

    def __repr__(self) -> str:
        return "GoogleTestCalendarWriteClient(test_only=True, production_locked=True)"

    def verify_bound_target(self, target_config: TestWriteTargetConfig) -> None:
        validate_test_write_target_config(target_config)
        bound = self.__target_config
        if not (
            hmac.compare_digest(
                target_config.calendar_id.encode("utf-8", errors="strict"),
                bound.calendar_id.encode("utf-8", errors="strict"),
            )
            and hmac.compare_digest(
                target_config.expected_target_fingerprint,
                bound.expected_target_fingerprint,
            )
            and hmac.compare_digest(
                target_config.expected_summary.encode("utf-8", errors="strict"),
                bound.expected_summary.encode("utf-8", errors="strict"),
            )
            and target_config.target_environment == bound.target_environment
            and target_config.target_label == bound.target_label
            and target_config.target_purpose == bound.target_purpose
            and target_config.expected_access_role == bound.expected_access_role
            and target_config.expected_time_zone == bound.expected_time_zone
        ):
            raise TestWriteClientError(
                "test_write_target_binding_mismatch",
                "Test write client target binding did not match",
            )

    def __validated_bound_calendar_id(self) -> str:
        validate_test_write_target_config(self.__target_config)
        return self.__target_config.calendar_id

    def list_events(
        self,
        *,
        page_token: str | None,
        ical_uid: str | None = None,
    ) -> Mapping[str, object]:
        calendar_id = self.__validated_bound_calendar_id()
        if ical_uid == "":
            raise TestWriteClientError("invalid_ical_uid", "iCalendar identity is invalid")
        try:
            service = cast(Any, self.__service)
            parameters: dict[str, object] = {
                "calendarId": calendar_id,
                "maxResults": TEST_WRITE_MAX_RESULTS,
                "singleEvents": False,
                "showDeleted": True,
                "fields": TEST_WRITE_LIST_FIELDS,
            }
            if ical_uid is not None:
                parameters["iCalUID"] = ical_uid
            if page_token is not None:
                parameters["pageToken"] = page_token
            response = service.events().list(**parameters).execute(num_retries=0)
            return _validated_mapping(response, operation="events.list")
        except (SafeGoogleError, TestWriteClientError):
            raise
        except Exception as exc:
            raise safe_google_error_from_exception(
                exc,
                attempt=1,
                operation="events.list",
            ) from None

    def get_event(
        self,
        *,
        event_id: str,
    ) -> Mapping[str, object]:
        calendar_id = self.__validated_bound_calendar_id()
        if not event_id:
            raise TestWriteClientError("invalid_event_identity", "Google event identity is invalid")
        try:
            service = cast(Any, self.__service)
            response = (
                service.events()
                .get(
                    calendarId=calendar_id,
                    eventId=event_id,
                    fields=TEST_WRITE_EVENT_FIELDS,
                )
                .execute(num_retries=0)
            )
            return _validated_mapping(response, operation="events.get")
        except (SafeGoogleError, TestWriteClientError):
            raise
        except Exception as exc:
            raise safe_google_error_from_exception(
                exc,
                attempt=1,
                operation="events.get",
            ) from None

    def import_event(
        self,
        *,
        body: Mapping[str, object],
    ) -> Mapping[str, object]:
        calendar_id = self.__validated_bound_calendar_id()
        validate_import_body(body)
        try:
            service = cast(Any, self.__service)
            response = (
                service.events()
                .import_(
                    calendarId=calendar_id,
                    body=dict(body),
                    fields=TEST_WRITE_EVENT_FIELDS,
                )
                .execute(num_retries=0)
            )
            return _validated_mapping(response, operation="events.import")
        except (SafeGoogleError, TestWriteClientError):
            raise
        except Exception as exc:
            raise safe_google_error_from_exception(
                exc,
                attempt=1,
                operation="events.import",
            ) from None

    def patch_event(
        self,
        *,
        event_id: str,
        body: Mapping[str, object],
        etag: str,
    ) -> Mapping[str, object]:
        calendar_id = self.__validated_bound_calendar_id()
        if not event_id:
            raise TestWriteClientError("invalid_event_identity", "Google event identity is invalid")
        if not etag or etag == "*" or "\r" in etag or "\n" in etag:
            raise TestWriteClientError(
                "invalid_if_match",
                "An exact non-wildcard ETag is required",
            )
        validate_patch_body(body)
        try:
            service = cast(Any, self.__service)
            request = service.events().patch(
                calendarId=calendar_id,
                eventId=event_id,
                body=dict(body),
                sendUpdates="none",
                fields=TEST_WRITE_EVENT_FIELDS,
            )
            headers = getattr(request, "headers", None)
            if not isinstance(headers, dict):
                raise TestWriteClientError(
                    "request_headers_unavailable",
                    "Conditional Test patch could not be constructed",
                )
            headers["If-Match"] = etag
            response = request.execute(num_retries=0)
            return _validated_mapping(response, operation="events.patch")
        except (SafeGoogleError, TestWriteClientError):
            raise
        except Exception as exc:
            raise safe_google_error_from_exception(
                exc,
                attempt=1,
                operation="events.patch",
            ) from None


def build_test_calendar_write_client(
    credentials: object,
    *,
    target_config: TestWriteTargetConfig,
    build_service: Any | None = None,
) -> TestCalendarWriteClient:
    """Validate the Test target before constructing an internal Google service."""

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
        return GoogleTestCalendarWriteClient(service, target_config=target_config)
    except Exception as exc:
        raise safe_google_error_from_exception(
            exc,
            attempt=1,
            operation="client.build",
        ) from None


__all__ = [
    "IMPORT_BODY_FIELDS",
    "PATCH_BODY_FIELDS",
    "TEST_WRITE_EVENT_FIELDS",
    "TEST_WRITE_LIST_FIELDS",
    "TEST_WRITE_MAX_RESULTS",
    "GoogleTestCalendarWriteClient",
    "TestCalendarWriteClient",
    "TestWriteClientError",
    "build_test_calendar_write_client",
    "validate_import_body",
    "validate_patch_body",
]
