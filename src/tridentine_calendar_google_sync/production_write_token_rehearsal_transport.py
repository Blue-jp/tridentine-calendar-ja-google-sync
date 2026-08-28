"""Sealed fake transport for the Phase 6D.0 read-only rehearsal.

There is intentionally no Google SDK import, socket use, credential builder,
generic service escape hatch, or mutation method in this module.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from typing import Literal, final

from tridentine_calendar_google_sync.google_models import CanonicalGoogleEvent, GoogleSnapshot
from tridentine_calendar_google_sync.production_write_target import ProductionWriteTargetConfig
from tridentine_calendar_google_sync.production_write_token_models import (
    ProductionWriteCredentialSession,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_models import (
    ProductionWriteTokenFullSnapshotRequest,
    ProductionWriteTokenReadOnlyTransport,
    ProductionWriteTokenSnapshotPage,
)


class ProductionWriteTokenRehearsalTransportError(RuntimeError):
    """One content-free read transport failure."""

    def __init__(
        self,
        code: str,
        public_message: str = "Production write-token rehearsal read failed",
        *,
        retryable: bool = False,
    ) -> None:
        retryable_codes = {
            "rate_limit",
            "rate_limit_403",
            "server_500",
            "server_502",
            "server_503",
        }
        allowed_codes = retryable_codes | {
            "bad_request",
            "gone",
            "not_found",
            "permission_denied",
            "mock_get_contract_mismatch",
            "mock_get_script_exhausted",
            "mock_list_contract_mismatch",
            "mock_list_page_exhausted",
            "mock_list_script_exhausted",
            "production_live_rehearsal_not_available_in_phase_6d0",
            "production_rehearsal_fake_transport_required",
        }
        if code not in allowed_codes:
            raise ValueError("Production rehearsal transport code is invalid")
        if retryable != (code in retryable_codes):
            raise ValueError("Production rehearsal retry classification is invalid")
        self.code = code
        self.public_message = public_message
        self.retryable = retryable
        super().__init__(public_message)


class FakeProductionWriteTokenReadOnlyTransport:
    """Thread-safe scripted adapter exposing only list/get capability methods."""

    __slots__ = (
        "_call_log",
        "_collection_index",
        "_collections",
        "_get_events",
        "_get_failures",
        "_get_index",
        "_get_raw_calls",
        "_list_failures",
        "_list_raw_calls",
        "_lock",
        "_page_index",
        "_requests",
    )

    def __init__(
        self,
        *,
        collections: Sequence[Sequence[ProductionWriteTokenSnapshotPage]],
        get_events: Sequence[CanonicalGoogleEvent | ProductionWriteTokenRehearsalTransportError],
        list_failures: Mapping[int, ProductionWriteTokenRehearsalTransportError] | None = None,
        get_failures: Mapping[int, ProductionWriteTokenRehearsalTransportError] | None = None,
    ) -> None:
        self._collections = tuple(tuple(collection) for collection in collections)
        self._get_events = tuple(get_events)
        self._list_failures = dict(list_failures or {})
        self._get_failures = dict(get_failures or {})
        self._call_log: list[str] = []
        self._requests: list[ProductionWriteTokenFullSnapshotRequest] = []
        self._list_raw_calls = 0
        self._get_raw_calls = 0
        self._collection_index = 0
        self._page_index = 0
        self._get_index = 0
        self._lock = threading.Lock()

    @property
    def call_log(self) -> tuple[str, ...]:
        return tuple(self._call_log)

    @property
    def list_raw_calls(self) -> int:
        return self._list_raw_calls

    @property
    def get_raw_calls(self) -> int:
        return self._get_raw_calls

    @property
    def mutation_raw_calls(self) -> int:
        return 0

    @property
    def list_requests(self) -> tuple[ProductionWriteTokenFullSnapshotRequest, ...]:
        return tuple(self._requests)

    def list_events(
        self,
        *,
        request: ProductionWriteTokenFullSnapshotRequest,
    ) -> ProductionWriteTokenSnapshotPage:
        with self._lock:
            self._list_raw_calls += 1
            self._call_log.append("events.list")
            self._requests.append(request)
            failure = self._list_failures.get(self._list_raw_calls)
            if failure is not None:
                raise failure
            if request.token_role != "production_write":
                raise ProductionWriteTokenRehearsalTransportError("mock_list_contract_mismatch")
            if self._collection_index >= len(self._collections):
                raise ProductionWriteTokenRehearsalTransportError("mock_list_script_exhausted")
            pages = self._collections[self._collection_index]
            if self._page_index >= len(pages):
                raise ProductionWriteTokenRehearsalTransportError("mock_list_page_exhausted")
            expected_token = (
                None if self._page_index == 0 else f"phase6d0-page-{self._page_index + 1}"
            )
            if request.page_token != expected_token:
                raise ProductionWriteTokenRehearsalTransportError("mock_list_contract_mismatch")
            page = pages[self._page_index]
            self._page_index += 1
            if page.collection_complete:
                self._collection_index += 1
                self._page_index = 0
            return page

    def get_event(
        self,
        *,
        event_id: str,
        token_role: str,
    ) -> CanonicalGoogleEvent:
        del event_id
        with self._lock:
            self._get_raw_calls += 1
            self._call_log.append("events.get")
            if token_role != "production_write":
                raise ProductionWriteTokenRehearsalTransportError("mock_get_contract_mismatch")
            failure = self._get_failures.get(self._get_raw_calls)
            if failure is not None:
                raise failure
            if self._get_index >= len(self._get_events):
                raise ProductionWriteTokenRehearsalTransportError("mock_get_script_exhausted")
            result = self._get_events[self._get_index]
            self._get_index += 1
            if isinstance(result, ProductionWriteTokenRehearsalTransportError):
                raise result
            return result


@final
class FakeProductionWriteCredentialSessionProvider:
    """Lazy synthetic credential provider with safe logical counters."""

    mock_only: Literal[True] = True
    live_capable: Literal[False] = False
    browser_launch_count: Literal[0] = 0

    def __init__(
        self,
        result: ProductionWriteCredentialSession | Exception,
        *,
        refresh_attempt_count: int = 0,
    ) -> None:
        if refresh_attempt_count not in (0, 1):
            raise ValueError("Production rehearsal refresh accounting is invalid")
        self._result = result
        self.refresh_attempt_count = refresh_attempt_count
        self.load_count = 0

    def load_session(
        self,
        *,
        target: ProductionWriteTargetConfig,
    ) -> ProductionWriteCredentialSession:
        del target
        self.load_count += 1
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


@final
class FakeProductionWriteTokenReadOnlyTransportProvider:
    """Lazy fake client constructor used only after credential validation."""

    mock_only: Literal[True] = True
    live_capable: Literal[False] = False

    def __init__(self, transport: FakeProductionWriteTokenReadOnlyTransport) -> None:
        self._transport = transport
        self.build_count = 0

    def build_transport(
        self,
        *,
        session: ProductionWriteCredentialSession,
        target: ProductionWriteTargetConfig,
    ) -> ProductionWriteTokenReadOnlyTransport:
        del session, target
        self.build_count += 1
        return self._transport


def paginate_production_write_token_rehearsal_snapshot(
    snapshot: GoogleSnapshot,
    page_sizes: Sequence[int],
    *,
    target_summary: str,
    access_role: str = "owner",
    time_zone: str = "Asia/Tokyo",
) -> tuple[ProductionWriteTokenSnapshotPage, ...]:
    """Split an in-memory synthetic snapshot into deterministic pages."""

    if not page_sizes or any(size < 0 for size in page_sizes):
        raise ValueError("Production rehearsal page sizes are invalid")
    if sum(page_sizes) != snapshot.event_count:
        raise ValueError("Production rehearsal pages do not cover the snapshot")
    if snapshot.collection_metadata_hash is None:
        raise ValueError("Production rehearsal snapshot metadata is incomplete")
    pages: list[ProductionWriteTokenSnapshotPage] = []
    offset = 0
    for page_number, size in enumerate(page_sizes, start=1):
        final = page_number == len(page_sizes)
        pages.append(
            ProductionWriteTokenSnapshotPage.model_validate(
                {
                    "target_fingerprint": snapshot.target_fingerprint,
                    "target_summary": target_summary,
                    "access_role": access_role,
                    "time_zone": time_zone,
                    "page_number": page_number,
                    "collection_complete": snapshot.complete if final else False,
                    "next_page_token": (None if final else f"phase6d0-page-{page_number + 1}"),
                    "collection_metadata_hash": snapshot.collection_metadata_hash,
                    "events": snapshot.events[offset : offset + size],
                },
                strict=True,
            )
        )
        offset += size
    return tuple(pages)


def require_phase6d0_rehearsal_transport(
    transport: ProductionWriteTokenReadOnlyTransport,
) -> None:
    """Reject generic/mutation-capable objects at the orchestration boundary."""

    if type(transport) is not FakeProductionWriteTokenReadOnlyTransport:
        raise ProductionWriteTokenRehearsalTransportError(
            "production_rehearsal_fake_transport_required"
        )
    forbidden = (
        "patch",
        "patch_description",
        "import_event",
        "insert",
        "update",
        "delete",
        "move",
        "batch",
        "service",
        "events_resource",
    )
    if any(hasattr(transport, name) for name in forbidden):
        raise ProductionWriteTokenRehearsalTransportError(
            "production_rehearsal_fake_transport_required"
        )


def require_phase6d0_rehearsal_providers(
    credential_provider: object,
    transport_provider: object,
) -> None:
    """Accept only the two exact synthetic lazy providers in Phase 6D.0."""

    if (
        not isinstance(credential_provider, FakeProductionWriteCredentialSessionProvider)
        or not isinstance(transport_provider, FakeProductionWriteTokenReadOnlyTransportProvider)
        or credential_provider.mock_only is not True
        or credential_provider.live_capable is not False
        or credential_provider.browser_launch_count != 0
        or transport_provider.mock_only is not True
        or transport_provider.live_capable is not False
    ):
        raise ProductionWriteTokenRehearsalTransportError(
            "production_rehearsal_fake_transport_required"
        )


def phase6d0_live_rehearsal_transport_hard_off() -> None:
    """Fail closed without constructing credentials or a Calendar client."""

    raise ProductionWriteTokenRehearsalTransportError(
        "production_live_rehearsal_not_available_in_phase_6d0"
    )


__all__ = [
    "FakeProductionWriteCredentialSessionProvider",
    "FakeProductionWriteTokenReadOnlyTransport",
    "FakeProductionWriteTokenReadOnlyTransportProvider",
    "ProductionWriteTokenRehearsalTransportError",
    "paginate_production_write_token_rehearsal_snapshot",
    "phase6d0_live_rehearsal_transport_hard_off",
    "require_phase6d0_rehearsal_providers",
    "require_phase6d0_rehearsal_transport",
]
