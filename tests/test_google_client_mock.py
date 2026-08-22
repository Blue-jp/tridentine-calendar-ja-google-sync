from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tridentine_calendar_google_sync.google_client import (
    EVENTS_LIST_FIELDS,
    EVENTS_LIST_MAX_RESULTS,
    GoogleEventsListClient,
    build_read_only_calendar_client,
)
from tridentine_calendar_google_sync.google_errors import (
    SafeGoogleError,
    safe_google_error_from_exception,
)

pytestmark = pytest.mark.google_read


class FakeRequest:
    def __init__(self, response: object = None, error: BaseException | None = None) -> None:
        self.response = response
        self.error = error
        self.num_retries: int | None = None

    def execute(self, *, num_retries: int) -> object:
        self.num_retries = num_retries
        if self.error is not None:
            raise self.error
        return self.response


class FakeEventsResource:
    def __init__(self, request: FakeRequest) -> None:
        self.request = request
        self.parameters: dict[str, object] | None = None

    def list(self, **parameters: object) -> FakeRequest:
        self.parameters = parameters
        return self.request


class FakeService:
    def __init__(self, resource: FakeEventsResource) -> None:
        self.resource = resource
        self.events_calls = 0

    def events(self) -> FakeEventsResource:
        self.events_calls += 1
        return self.resource


def _client(
    response: Mapping[str, object],
) -> tuple[GoogleEventsListClient, FakeService, FakeRequest]:
    request = FakeRequest(response=response)
    service = FakeService(FakeEventsResource(request))
    return GoogleEventsListClient(service), service, request


def test_events_list_uses_exact_read_only_full_snapshot_parameters() -> None:
    client, service, request = _client({"items": []})

    response = client.list_events(calendar_id="fixture-target", page_token=None)

    assert response == {"items": []}
    assert service.events_calls == 1
    assert service.resource.parameters == {
        "calendarId": "fixture-target",
        "maxResults": 2500,
        "singleEvents": False,
        "showDeleted": True,
        "fields": EVENTS_LIST_FIELDS,
    }
    assert EVENTS_LIST_MAX_RESULTS == 2500
    assert request.num_retries == 0


def test_events_list_adds_only_supplied_page_token() -> None:
    client, service, _request = _client({"items": []})

    client.list_events(calendar_id="fixture-target", page_token="fixture-page-2")

    assert service.resource.parameters is not None
    assert service.resource.parameters["pageToken"] == "fixture-page-2"
    assert "syncToken" not in service.resource.parameters
    assert "timeMin" not in service.resource.parameters
    assert "timeMax" not in service.resource.parameters
    assert "updatedMin" not in service.resource.parameters


def test_client_exposes_no_calendar_write_method() -> None:
    client, _service, _request = _client({"items": []})

    for method_name in (
        "insert",
        "import_",
        "update",
        "patch",
        "delete",
        "move",
        "clear",
    ):
        assert not hasattr(client, method_name)
    assert repr(client) == "GoogleEventsListClient(read_only=True)"


def test_google_service_builder_is_mocked_and_disables_discovery_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    fake_service = FakeService(FakeEventsResource(FakeRequest(response={"items": []})))

    def fake_build(api: str, version: str, **kwargs: object) -> FakeService:
        captured.update({"api": api, "version": version, **kwargs})
        return fake_service

    monkeypatch.setattr("googleapiclient.discovery.build", fake_build)
    credentials = object()

    client = build_read_only_calendar_client(credentials)
    response = client.list_events(calendar_id="fixture-target", page_token=None)

    assert response == {"items": []}
    assert captured == {
        "api": "calendar",
        "version": "v3",
        "credentials": credentials,
        "cache_discovery": False,
    }


def test_nonmapping_api_response_is_safe_invalid_response() -> None:
    request = FakeRequest(response=["not", "a", "mapping"])
    client = GoogleEventsListClient(FakeService(FakeEventsResource(request)))

    with pytest.raises(SafeGoogleError) as caught:
        client.list_events(calendar_id="fixture-target", page_token=None)

    assert caught.value.reason == "invalid_response"
    assert caught.value.retryable is False


class RawGoogleLikeError(RuntimeError):
    def __init__(self, status: int, reason: str, raw_text: str) -> None:
        self.resp = SimpleNamespace(status=status)
        self.reason = reason
        self.raw_text = raw_text
        super().__init__(raw_text)


class RawHttpContentError(RuntimeError):
    def __init__(self, *, status: int, reason: str, raw_message: str) -> None:
        self.resp = SimpleNamespace(status=status)
        self.content = json.dumps(
            {
                "error": {
                    "errors": [{"reason": reason}],
                    "message": raw_message,
                }
            }
        ).encode("utf-8")
        self.uri = "synthetic raw URI value"
        super().__init__(raw_message)


@pytest.mark.parametrize(
    ("error", "reason", "retryable"),
    [
        (RawGoogleLikeError(400, "fixtureRaw", "raw-400"), "bad_request", False),
        (RawGoogleLikeError(401, "fixtureRaw", "raw-401"), "unauthorized", False),
        (RawGoogleLikeError(403, "fixtureRaw", "raw-403"), "forbidden", False),
        (RawGoogleLikeError(403, "rateLimitExceeded", "raw-rate"), "rate_limited", True),
        (
            RawGoogleLikeError(403, "userRateLimitExceeded", "raw-user-rate"),
            "rate_limited",
            True,
        ),
        (RawGoogleLikeError(404, "fixtureRaw", "raw-404"), "not_found", False),
        (RawGoogleLikeError(410, "fixtureRaw", "raw-410"), "unknown", False),
        (RawGoogleLikeError(408, "fixtureRaw", "raw-408"), "timeout", True),
        (RawGoogleLikeError(429, "rateLimitExceeded", "raw-429"), "rate_limited", True),
        (RawGoogleLikeError(500, "backendError", "raw-500"), "backend_error", True),
        (RawGoogleLikeError(502, "fixtureRaw", "raw-502"), "backend_error", True),
        (RawGoogleLikeError(503, "fixtureRaw", "raw-503"), "service_unavailable", True),
        (RawGoogleLikeError(504, "fixtureRaw", "raw-504"), "timeout", True),
        (TimeoutError("raw timeout"), "timeout", True),
        (ConnectionError("raw transport"), "transport_error", True),
    ],
)
def test_google_error_classification_matrix(
    error: BaseException,
    reason: str,
    retryable: bool,
) -> None:
    safe = safe_google_error_from_exception(error, attempt=2, operation="events.list")

    assert safe.reason == reason
    assert safe.retryable is retryable
    assert safe.attempt == 2
    assert safe.operation == "events.list"


def test_raw_google_error_details_are_not_retained_or_rendered() -> None:
    raw_text = "fixture raw body with private material"
    error = RawGoogleLikeError(403, "fixtureRawReason", raw_text)

    safe = safe_google_error_from_exception(error, attempt=1, operation="events.list")
    rendered = str(safe) + repr(safe)

    assert raw_text not in rendered
    assert error.reason not in rendered
    assert not hasattr(safe, "raw_text")
    assert not hasattr(safe, "resp")
    assert safe.__dict__ == {}


@pytest.mark.parametrize(
    ("fixture_name", "expected_reason", "expected_retryable"),
    [
        ("rate_limit_error", "rate_limited", True),
        ("permission_error", "forbidden", False),
    ],
)
def test_error_fixture_status_and_reason_are_safely_classified(
    fixture_name: str,
    expected_reason: str,
    expected_retryable: bool,
    google_api_pages_dir: Path,
) -> None:
    document = json.loads(
        (google_api_pages_dir / f"{fixture_name}.json").read_text(encoding="utf-8")
    )
    raw = document["error"]
    error = RawGoogleLikeError(raw["status"], raw["reason"], raw["message"])

    safe = safe_google_error_from_exception(error, attempt=1, operation="events.list")

    assert safe.reason == expected_reason
    assert safe.retryable is expected_retryable
    assert raw["message"] not in str(safe) + repr(safe)


@pytest.mark.parametrize(
    ("raw_reason", "expected_reason", "expected_retryable"),
    [
        ("rateLimitExceeded", "rate_limited", True),
        ("quotaExceeded", "quota_exceeded", False),
    ],
)
def test_403_http_content_reason_allowlist_controls_retry_without_raw_leak(
    raw_reason: str,
    expected_reason: str,
    expected_retryable: bool,
) -> None:
    raw_message = "synthetic raw body with credential-like private material"
    error = RawHttpContentError(status=403, reason=raw_reason, raw_message=raw_message)

    safe = safe_google_error_from_exception(error, attempt=3, operation="events.list")
    rendered = str(safe) + repr(safe)

    assert safe.status == 403
    assert safe.reason == expected_reason
    assert safe.retryable is expected_retryable
    assert safe.attempt == 3
    assert raw_message not in rendered
    assert error.uri not in rendered
    assert raw_reason not in rendered


def test_safe_google_error_rejects_unallowlisted_metadata() -> None:
    with pytest.raises(ValueError):
        SafeGoogleError(
            status=403,
            reason="raw_reason_not_allowed",
            retryable=False,
            attempt=1,
            operation="events.list",
        )
    with pytest.raises(ValueError):
        SafeGoogleError(
            status=403,
            reason="forbidden",
            retryable=False,
            attempt=1,
            operation="events.insert",
        )
