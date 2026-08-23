"""Narrow read-only Google Calendar events.list client boundary."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Protocol, cast

from tridentine_calendar_google_sync.google_errors import (
    SafeGoogleError,
    safe_google_error_from_exception,
)

EVENTS_LIST_MAX_RESULTS = 2500
EVENTS_LIST_FIELDS = (
    "summary,timeZone,accessRole,nextPageToken,"
    "items(id,iCalUID,summary,description,start(date,dateTime,timeZone),"
    "end(date,dateTime,timeZone),endTimeUnspecified,status,eventType,etag,sequence,"
    "recurrence,recurringEventId,originalStartTime(date,dateTime,timeZone),"
    "transparency,visibility,colorId,eventLabelId,reminders(useDefault,"
    "overrides(method,minutes)),location,extendedProperties(private,shared),"
    "locked,privateCopy)"
)


class ReadOnlyCalendarClient(Protocol):
    """Only the read method required by the Phase 3A full snapshot fetcher."""

    def list_events(
        self,
        *,
        calendar_id: str,
        page_token: str | None,
    ) -> Mapping[str, object]:
        """Execute one exact events.list request and return its decoded mapping."""


class GoogleEventsListClient:
    """Adapter that exposes events.list but no Google Calendar write methods."""

    __slots__ = ("_service",)

    def __init__(self, service: object) -> None:
        self._service = service

    def __repr__(self) -> str:
        return "GoogleEventsListClient(read_only=True)"

    def list_events(
        self,
        *,
        calendar_id: str,
        page_token: str | None,
    ) -> Mapping[str, object]:
        """Call events.list with the immutable Phase 3A parameter set."""

        try:
            service = cast(Any, self._service)
            parameters: dict[str, object] = {
                "calendarId": calendar_id,
                "maxResults": EVENTS_LIST_MAX_RESULTS,
                "singleEvents": False,
                "showDeleted": True,
                "fields": EVENTS_LIST_FIELDS,
            }
            if page_token is not None:
                parameters["pageToken"] = page_token
            request = service.events().list(**parameters)
            response = request.execute(num_retries=0)
            if not isinstance(response, Mapping):
                raise SafeGoogleError(
                    status=None,
                    reason="invalid_response",
                    retryable=False,
                    attempt=1,
                    operation="events.list",
                )
            return cast(Mapping[str, object], response)
        except SafeGoogleError:
            raise
        except Exception as exc:
            raise safe_google_error_from_exception(
                exc,
                attempt=1,
                operation="events.list",
            ) from None


def build_read_only_calendar_client(
    credentials: object,
    *,
    build_service: Any | None = None,
) -> ReadOnlyCalendarClient:
    """Lazily construct Calendar API v3 with discovery caching disabled."""

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
        return GoogleEventsListClient(service)
    except Exception as exc:
        raise safe_google_error_from_exception(
            exc,
            attempt=1,
            operation="client.build",
        ) from None


__all__ = [
    "EVENTS_LIST_FIELDS",
    "EVENTS_LIST_MAX_RESULTS",
    "GoogleEventsListClient",
    "ReadOnlyCalendarClient",
    "build_read_only_calendar_client",
]
