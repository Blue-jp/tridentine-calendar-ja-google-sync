from __future__ import annotations

import inspect
from typing import Any

import pytest
from phase5a1_helpers import (
    SYNTHETIC_PREWRITE_CALENDAR_ID,
    make_prewrite_target_config,
    prewrite_page,
)

from tridentine_calendar_google_sync.google_errors import SafeGoogleError
from tridentine_calendar_google_sync.google_test_prewrite_client import (
    TEST_PREWRITE_EVENT_FIELDS,
    TEST_PREWRITE_LIST_FIELDS,
    TEST_PREWRITE_MAX_RESULTS,
    GoogleTestCalendarPrewriteListClient,
    build_test_calendar_prewrite_list_client,
)
from tridentine_calendar_google_sync.google_test_prewrite_client import (
    TestCalendarPrewriteClientError as PrewriteClientError,
)
from tridentine_calendar_google_sync.google_test_prewrite_client import (
    TestCalendarPrewriteListClient as PrewriteListProtocol,
)

pytestmark = pytest.mark.google_test_write


class _Request:
    def __init__(self, response: object) -> None:
        self.response = response
        self.execute_calls: list[int] = []

    def execute(self, *, num_retries: int) -> object:
        self.execute_calls.append(num_retries)
        return self.response


class _Events:
    def __init__(self, response: object) -> None:
        self.request = _Request(response)
        self.calls: list[dict[str, object]] = []

    def list(self, **parameters: object) -> _Request:
        self.calls.append(parameters)
        return self.request

    def get(self, **_parameters: object) -> None:
        raise AssertionError("events.get is unreachable")

    def import_(self, **_parameters: object) -> None:
        raise AssertionError("events.import is unreachable")

    def patch(self, **_parameters: object) -> None:
        raise AssertionError("events.patch is unreachable")


class _Service:
    def __init__(self, response: object) -> None:
        self.resource = _Events(response)
        self.events_calls = 0

    def events(self) -> _Events:
        self.events_calls += 1
        return self.resource


def test_protocol_and_adapter_expose_exactly_one_list_method() -> None:
    expected = {"list_events"}
    protocol_methods = {
        name
        for name, value in inspect.getmembers(PrewriteListProtocol, inspect.isfunction)
        if not name.startswith("_")
    }
    adapter_methods = {
        name
        for name, value in inspect.getmembers(
            GoogleTestCalendarPrewriteListClient,
            inspect.isfunction,
        )
        if not name.startswith("_")
    }

    assert protocol_methods == expected
    assert adapter_methods == expected
    for forbidden in (
        "get_event",
        "import_event",
        "patch_event",
        "insert_event",
        "update_event",
        "delete_event",
        "move_event",
        "batch",
        "service",
    ):
        assert not hasattr(GoogleTestCalendarPrewriteListClient, forbidden)


def test_list_uses_exact_full_snapshot_parameters_and_zero_library_retries() -> None:
    service = _Service(prewrite_page())
    client = GoogleTestCalendarPrewriteListClient(
        service,
        calendar_id=SYNTHETIC_PREWRITE_CALENDAR_ID,
    )

    response = client.list_events(
        calendar_id=SYNTHETIC_PREWRITE_CALENDAR_ID,
        page_token=None,
    )

    assert response == prewrite_page()
    assert service.events_calls == 1
    assert service.resource.calls == [
        {
            "calendarId": SYNTHETIC_PREWRITE_CALENDAR_ID,
            "maxResults": 2500,
            "singleEvents": False,
            "showDeleted": True,
            "fields": TEST_PREWRITE_LIST_FIELDS,
        }
    ]
    assert TEST_PREWRITE_MAX_RESULTS == 2500
    assert service.resource.request.execute_calls == [0]


def test_pagination_adds_only_page_token_and_forbidden_filters_are_absent() -> None:
    service = _Service(prewrite_page())
    client = GoogleTestCalendarPrewriteListClient(
        service,
        calendar_id=SYNTHETIC_PREWRITE_CALENDAR_ID,
    )

    client.list_events(
        calendar_id=SYNTHETIC_PREWRITE_CALENDAR_ID,
        page_token="fixture-page-2",
    )

    parameters = service.resource.calls[0]
    assert parameters["pageToken"] == "fixture-page-2"
    assert set(parameters) == {
        "calendarId",
        "maxResults",
        "singleEvents",
        "showDeleted",
        "fields",
        "pageToken",
    }
    for forbidden in (
        "timeMin",
        "timeMax",
        "updatedMin",
        "syncToken",
        "iCalUID",
        "q",
        "orderBy",
        "privateExtendedProperty",
        "sharedExtendedProperty",
        "eventTypes",
    ):
        assert forbidden not in parameters


def test_partial_field_mask_has_required_fields_and_no_personal_content_fields() -> None:
    for required in (
        "id",
        "iCalUID",
        "summary",
        "description",
        "start",
        "end",
        "status",
        "eventType",
        "etag",
        "sequence",
        "recurrence",
        "recurringEventId",
        "originalStartTime",
        "colorId",
        "eventLabelId",
    ):
        assert required in TEST_PREWRITE_EVENT_FIELDS
    for forbidden in (
        "attendees",
        "creator",
        "organizer",
        "htmlLink",
        "conferenceData",
        "hangoutLink",
        "attachments",
        "source",
        "email",
    ):
        assert forbidden not in TEST_PREWRITE_LIST_FIELDS


@pytest.mark.parametrize("page_token", ("", 1))
def test_invalid_page_token_is_rejected_before_service_call(page_token: object) -> None:
    service = _Service(prewrite_page())
    client = GoogleTestCalendarPrewriteListClient(
        service,
        calendar_id=SYNTHETIC_PREWRITE_CALENDAR_ID,
    )

    with pytest.raises(PrewriteClientError):
        client.list_events(
            calendar_id=SYNTHETIC_PREWRITE_CALENDAR_ID,
            page_token=page_token,  # type: ignore[arg-type]
        )
    assert service.events_calls == 0


def test_calendar_mismatch_is_rejected_before_service_call() -> None:
    service = _Service(prewrite_page())
    client = GoogleTestCalendarPrewriteListClient(
        service,
        calendar_id=SYNTHETIC_PREWRITE_CALENDAR_ID,
    )

    with pytest.raises(PrewriteClientError) as captured:
        client.list_events(calendar_id="fixture-other@example.invalid", page_token=None)
    assert captured.value.code == "test_prewrite_calendar_id_mismatch"
    assert service.events_calls == 0


def test_nonmapping_response_is_safe_invalid_response() -> None:
    service = _Service(["not", "a", "mapping"])
    client = GoogleTestCalendarPrewriteListClient(
        service,
        calendar_id=SYNTHETIC_PREWRITE_CALENDAR_ID,
    )

    with pytest.raises(SafeGoogleError) as captured:
        client.list_events(
            calendar_id=SYNTHETIC_PREWRITE_CALENDAR_ID,
            page_token=None,
        )
    assert captured.value.reason == "invalid_response"
    assert captured.value.retryable is False


def test_builder_validates_target_and_hides_generic_service() -> None:
    captured: dict[str, Any] = {}
    service = _Service(prewrite_page())

    def build(api: str, version: str, **kwargs: object) -> _Service:
        captured.update({"api": api, "version": version, **kwargs})
        return service

    client = build_test_calendar_prewrite_list_client(
        object(),
        target_config=make_prewrite_target_config(),
        build_service=build,
    )

    assert isinstance(client, GoogleTestCalendarPrewriteListClient)
    assert captured["api"] == "calendar"
    assert captured["version"] == "v3"
    assert captured["cache_discovery"] is False
    assert "service" not in repr(client).casefold()
