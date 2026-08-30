from __future__ import annotations

import inspect
from collections.abc import Mapping
from typing import Any, cast

import pytest
from phase5a_helpers import (
    SYNTHETIC_ETAG,
    SYNTHETIC_EVENT_ID,
    SYNTHETIC_TEST_CALENDAR_ID,
    SYNTHETIC_UID,
    google_event_response,
    make_test_target_config,
    managed_state,
)

from tridentine_calendar_google_sync.google_target import calendar_id_fingerprint
from tridentine_calendar_google_sync.google_test_write_client import (
    IMPORT_BODY_FIELDS,
    PATCH_BODY_FIELDS,
    GoogleTestCalendarWriteClient,
    build_test_calendar_write_client,
    validate_import_body,
    validate_patch_body,
)
from tridentine_calendar_google_sync.google_test_write_client import (
    TestCalendarWriteClient as CalendarWriteProtocol,
)
from tridentine_calendar_google_sync.google_test_write_client import (
    TestWriteClientError as ClientError,
)

pytestmark = pytest.mark.google_test_write

SYNTHETIC_OTHER_CALENDAR_ID = "other-owned-target@example.invalid"


class _Request:
    def __init__(self, response: object) -> None:
        self.response = response
        self.headers: dict[str, str] = {}
        self.execute_calls: list[int] = []

    def execute(self, *, num_retries: int) -> object:
        self.execute_calls.append(num_retries)
        return self.response


class _Events:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.responses: dict[str, object] = {
            "list": {"items": [], "summary": "Synthetic Test Calendar"},
            "get": google_event_response(),
            "import": google_event_response(),
            "patch": google_event_response(),
        }
        self.requests: dict[str, _Request] = {}

    def _request(self, method: str, parameters: dict[str, object]) -> _Request:
        self.calls.append((method, parameters))
        request = _Request(self.responses[method])
        self.requests[method] = request
        return request

    def list(self, **parameters: object) -> _Request:
        return self._request("list", parameters)

    def get(self, **parameters: object) -> _Request:
        return self._request("get", parameters)

    def import_(self, **parameters: object) -> _Request:
        return self._request("import", parameters)

    def patch(self, **parameters: object) -> _Request:
        return self._request("patch", parameters)


class _Service:
    def __init__(self) -> None:
        self.event_resource = _Events()

    def events(self) -> _Events:
        return self.event_resource


def _import_body() -> dict[str, object]:
    state = managed_state()
    return {
        "iCalUID": state.ical_uid,
        "summary": state.summary,
        "description": state.description,
        "start": {"date": state.start_date.isoformat()},
        "end": {"date": state.end_date.isoformat()},
        "eventType": state.event_type,
    }


def _client(
    service: _Service,
    *,
    target_config: object | None = None,
) -> GoogleTestCalendarWriteClient:
    target = make_test_target_config() if target_config is None else target_config
    return GoogleTestCalendarWriteClient(service, target_config=cast(Any, target))


def test_protocol_and_adapter_expose_only_four_google_operations() -> None:
    expected = {
        "verify_bound_target",
        "list_events",
        "get_event",
        "import_event",
        "patch_event",
    }
    protocol_methods = {
        name
        for name, value in inspect.getmembers(CalendarWriteProtocol, inspect.isfunction)
        if not name.startswith("_")
    }
    adapter_methods = {
        name
        for name, value in inspect.getmembers(GoogleTestCalendarWriteClient, inspect.isfunction)
        if not name.startswith("_")
    }
    assert protocol_methods == expected
    assert adapter_methods == expected
    for owner in (CalendarWriteProtocol, GoogleTestCalendarWriteClient):
        for name in expected - {"verify_bound_target"}:
            assert "calendar_id" not in inspect.signature(getattr(owner, name)).parameters
    for forbidden in (
        "insert_event",
        "update_event",
        "delete_event",
        "move_event",
        "watch_events",
        "clear_calendar",
        "batch",
    ):
        assert not hasattr(GoogleTestCalendarWriteClient, forbidden)


def test_list_and_get_use_partial_fields_and_zero_library_retries() -> None:
    service = _Service()
    client = _client(service)

    client.list_events(
        page_token="fixture-page-2",
        ical_uid=SYNTHETIC_UID,
    )
    client.get_event(
        event_id=SYNTHETIC_EVENT_ID,
    )

    list_method, list_params = service.event_resource.calls[0]
    get_method, get_params = service.event_resource.calls[1]
    assert list_method == "list"
    assert list_params["calendarId"] == SYNTHETIC_TEST_CALENDAR_ID
    assert list_params["iCalUID"] == SYNTHETIC_UID
    assert list_params["pageToken"] == "fixture-page-2"
    assert list_params["singleEvents"] is False
    assert list_params["showDeleted"] is True
    assert get_method == "get"
    assert get_params["calendarId"] == SYNTHETIC_TEST_CALENDAR_ID
    assert get_params["eventId"] == SYNTHETIC_EVENT_ID
    assert "attendees" not in str(list_params["fields"])
    assert service.event_resource.requests["list"].execute_calls == [0]
    assert service.event_resource.requests["get"].execute_calls == [0]


def test_import_uses_exact_allowlisted_body_and_no_second_attempt() -> None:
    service = _Service()
    client = _client(service)
    body = _import_body()

    result = client.import_event(body=body)

    method, parameters = service.event_resource.calls[0]
    assert method == "import"
    assert parameters["calendarId"] == SYNTHETIC_TEST_CALENDAR_ID
    assert set(parameters["body"]) == IMPORT_BODY_FIELDS  # type: ignore[arg-type]
    assert parameters["body"] == body
    assert parameters["body"]["iCalUID"] == SYNTHETIC_UID  # type: ignore[index]
    assert service.event_resource.requests["import"].execute_calls == [0]
    assert result["iCalUID"] == SYNTHETIC_UID


@pytest.mark.parametrize(
    "forbidden",
    (
        "id",
        "colorId",
        "eventLabelId",
        "reminders",
        "attendees",
        "recurrence",
        "extendedProperties",
        "location",
    ),
)
def test_import_rejects_every_forbidden_payload_field(forbidden: str) -> None:
    body = _import_body()
    body[forbidden] = "fixture-forbidden"
    with pytest.raises(ClientError) as captured:
        validate_import_body(body)
    assert captured.value.code == "invalid_import_payload"
    assert SYNTHETIC_UID not in str(captured.value)


@pytest.mark.parametrize(
    "body",
    (
        {},
        {"summary": "Changed", "colorId": "1"},
        {"start": {"date": "2026-06-02"}},
        {"end": {"date": "2026-06-03"}},
        {"start": {"date": "2026-06-03"}, "end": {"date": "2026-06-02"}},
        {"summary": ["Changed"]},
    ),
)
def test_patch_rejects_empty_forbidden_array_or_invalid_date_body(
    body: Mapping[str, object],
) -> None:
    with pytest.raises(ClientError):
        validate_patch_body(body)


def test_patch_sets_exact_if_match_and_changed_fields_only() -> None:
    service = _Service()
    client = _client(service)
    body = {"description": "Changed synthetic description"}

    client.patch_event(
        event_id=SYNTHETIC_EVENT_ID,
        body=body,
        etag=SYNTHETIC_ETAG,
    )

    method, parameters = service.event_resource.calls[0]
    assert method == "patch"
    assert parameters["calendarId"] == SYNTHETIC_TEST_CALENDAR_ID
    assert set(parameters["body"]) == {"description"}  # type: ignore[arg-type]
    assert set(parameters["body"]) <= PATCH_BODY_FIELDS  # type: ignore[arg-type]
    assert parameters["sendUpdates"] == "none"
    assert service.event_resource.requests["patch"].headers == {"If-Match": SYNTHETIC_ETAG}
    assert service.event_resource.requests["patch"].execute_calls == [0]


def test_patch_wildcard_or_missing_etag_is_rejected_before_mutation() -> None:
    for etag in ("", "*"):
        service = _Service()
        client = _client(service)
        with pytest.raises(ClientError) as captured:
            client.patch_event(
                event_id=SYNTHETIC_EVENT_ID,
                body={"summary": "Changed"},
                etag=etag,
            )
        assert captured.value.code == "invalid_if_match"
        assert service.event_resource.calls == []


@pytest.mark.parametrize(
    "target_config",
    (
        make_test_target_config().model_copy(update={"calendar_id": "primary"}),
        make_test_target_config().model_copy(update={"target_environment": "production"}),
        object(),
    ),
)
def test_direct_constructor_requires_a_validated_test_target(target_config: object) -> None:
    service = _Service()
    with pytest.raises((ClientError, TypeError, ValueError)):
        _client(service, target_config=target_config)
    assert service.event_resource.calls == []


def test_direct_constructor_rejects_missing_target_binding() -> None:
    service = _Service()
    with pytest.raises(TypeError):
        cast(Any, GoogleTestCalendarWriteClient)(service)
    assert service.event_resource.calls == []


def test_bound_client_rejects_a_different_valid_test_target() -> None:
    service = _Service()
    target = make_test_target_config()
    other_target = target.model_copy(
        update={
            "calendar_id": SYNTHETIC_OTHER_CALENDAR_ID,
            "expected_target_fingerprint": calendar_id_fingerprint(SYNTHETIC_OTHER_CALENDAR_ID),
        }
    )
    client = _client(service, target_config=target)

    client.verify_bound_target(target)
    with pytest.raises(ClientError) as captured:
        client.verify_bound_target(other_target)

    assert captured.value.code == "test_write_target_binding_mismatch"
    assert service.event_resource.calls == []


@pytest.mark.parametrize("operation", ("import", "patch"))
def test_per_call_target_substitution_is_structurally_rejected(operation: str) -> None:
    service = _Service()
    client = _client(service)
    with pytest.raises(TypeError):
        if operation == "import":
            cast(Any, client).import_event(
                calendar_id=SYNTHETIC_OTHER_CALENDAR_ID,
                body=_import_body(),
            )
        else:
            cast(Any, client).patch_event(
                calendar_id=SYNTHETIC_OTHER_CALENDAR_ID,
                event_id=SYNTHETIC_EVENT_ID,
                body={"description": "Changed"},
                etag=SYNTHETIC_ETAG,
            )
    assert service.event_resource.calls == []


def test_caller_cannot_retarget_client_by_mutating_the_original_config() -> None:
    service = _Service()
    target = make_test_target_config()
    original_calendar_id = target.calendar_id
    client = _client(service, target_config=target)
    object.__setattr__(target, "calendar_id", SYNTHETIC_OTHER_CALENDAR_ID)
    object.__setattr__(
        target,
        "expected_target_fingerprint",
        calendar_id_fingerprint(SYNTHETIC_OTHER_CALENDAR_ID),
    )

    with pytest.raises(ClientError) as captured:
        client.verify_bound_target(target)
    client.import_event(body=_import_body())

    assert captured.value.code == "test_write_target_binding_mismatch"
    assert service.event_resource.calls[0][1]["calendarId"] == original_calendar_id
    assert service.event_resource.calls[0][1]["calendarId"] != SYNTHETIC_OTHER_CALENDAR_ID


def test_builder_uses_only_calendar_v3_and_hides_generic_service() -> None:
    service = _Service()
    captured: dict[str, Any] = {}

    def build(api: str, version: str, **kwargs: object) -> _Service:
        captured.update({"api": api, "version": version, **kwargs})
        return service

    client = build_test_calendar_write_client(
        object(),
        target_config=make_test_target_config(),
        build_service=build,
    )

    assert isinstance(client, GoogleTestCalendarWriteClient)
    assert captured["api"] == "calendar"
    assert captured["version"] == "v3"
    assert captured["cache_discovery"] is False
    assert "service" not in repr(client).casefold()
    assert not hasattr(client, "service")
    assert not hasattr(client, "calendar_id")
