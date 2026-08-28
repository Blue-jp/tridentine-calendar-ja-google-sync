"""Deterministic failure-injection adapters for Phase 6C mock execution.

No adapter in this module imports a Google distribution or can open a socket.
The three facades intentionally expose one capability method each.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from tridentine_calendar_google_sync.google_models import CanonicalGoogleEvent, GoogleSnapshot
from tridentine_calendar_google_sync.production_transport_models import (
    PRODUCTION_SEND_UPDATES,
    ProductionFreshEventReader,
    ProductionFullSnapshotReader,
    ProductionFullSnapshotRequest,
    ProductionPatchAcknowledgement,
    ProductionSingleUpdateMutator,
    ProductionSnapshotPage,
)


class ProductionTransportFailure(RuntimeError):
    """One content-free scripted transport failure."""

    def __init__(
        self,
        code: str,
        public_message: str = "Mock Production transport failed",
        *,
        retryable_read: bool = False,
        etag_conflict: bool = False,
        uncertain_patch_outcome: bool = False,
    ) -> None:
        allowed_codes = {
            "bad_request",
            "etag_conflict",
            "gone",
            "mock_get_script_exhausted",
            "mock_get_contract_mismatch",
            "mock_list_page_exhausted",
            "mock_list_page_token_mismatch",
            "mock_list_script_exhausted",
            "mock_patch_contract_mismatch",
            "not_found",
            "permission_denied",
            "production_live_execution_not_available_in_phase_6c",
            "production_mock_transport_required",
            "rate_limit",
            "rate_limit_403",
            "response_lost",
            "server_500",
            "server_502",
            "server_503",
        }
        if code not in allowed_codes:
            raise ValueError("Mock Production transport failure code is invalid")
        allowed_retryable_read_codes = {
            "rate_limit",
            "rate_limit_403",
            "server_500",
            "server_502",
            "server_503",
        }
        if retryable_read and code not in allowed_retryable_read_codes:
            raise ValueError("Mock Production read retry classification is invalid")
        if etag_conflict and (retryable_read or uncertain_patch_outcome):
            raise ValueError("Mock Production ETag conflict classification is invalid")
        if uncertain_patch_outcome and retryable_read:
            raise ValueError("Mock Production uncertain patch classification is invalid")
        self.code = code
        self.public_message = public_message
        self.retryable_read = retryable_read
        self.etag_conflict = etag_conflict
        self.uncertain_patch_outcome = uncertain_patch_outcome
        super().__init__(public_message)


@dataclass(frozen=True)
class ProductionPatchObservation:
    """Safe evidence about a fake patch boundary without raw request values."""

    method: str = "events.patch"
    body_fields: tuple[str, ...] = ("description",)
    if_match_present: bool = True
    if_match_wildcard: bool = False
    send_updates: str = "none"
    token_role: str = "production_write"
    write_token_generation_present: bool = True


@dataclass(frozen=True)
class ProductionListObservation:
    """Safe evidence that no subset list control was available."""

    method: str = "events.list"
    token_role: str = "production_read_only"
    single_events: bool = False
    show_deleted: bool = True
    max_results: int = 2500
    time_min_present: bool = False
    time_max_present: bool = False
    sync_token_present: bool = False
    query_present: bool = False


@dataclass(frozen=True)
class ProductionGetObservation:
    """Safe evidence that fresh reads use only the read-only role."""

    method: str = "events.get"
    token_role: str = "production_read_only"


def paginate_production_snapshot(
    snapshot: GoogleSnapshot,
    page_sizes: Sequence[int],
    *,
    access_role: str = "owner",
    time_zone: str = "Asia/Tokyo",
) -> tuple[ProductionSnapshotPage, ...]:
    """Split one in-memory canonical snapshot into strict deterministic pages."""

    if not page_sizes or any(size < 0 for size in page_sizes):
        raise ValueError("Production mock page sizes are invalid")
    if sum(page_sizes) != snapshot.event_count:
        raise ValueError("Production mock page sizes do not cover the snapshot")
    if snapshot.collection_metadata_hash is None:
        raise ValueError("Production mock snapshot metadata is incomplete")
    pages: list[ProductionSnapshotPage] = []
    offset = 0
    for page_index, size in enumerate(page_sizes, start=1):
        final = page_index == len(page_sizes)
        next_token = None if final else f"mock-page-{page_index + 1}"
        pages.append(
            ProductionSnapshotPage.model_validate(
                {
                    "target_fingerprint": snapshot.target_fingerprint,
                    "access_role": access_role,
                    "time_zone": time_zone,
                    "page_number": page_index,
                    "collection_complete": snapshot.complete if final else False,
                    "next_page_token": next_token,
                    "collection_metadata_hash": snapshot.collection_metadata_hash,
                    "events": snapshot.events[offset : offset + size],
                },
                strict=True,
            )
        )
        offset += size
    return tuple(pages)


@dataclass
class _FakeScript:
    collections: tuple[tuple[ProductionSnapshotPage, ...], ...]
    get_events: tuple[CanonicalGoogleEvent | ProductionTransportFailure, ...]
    list_failures: Mapping[int, ProductionTransportFailure]
    get_failures: Mapping[int, ProductionTransportFailure]
    patch_failure: ProductionTransportFailure | None
    expected_if_match: str | None
    call_log: list[str] = field(default_factory=list)
    list_observations: list[ProductionListObservation] = field(default_factory=list)
    get_observations: list[ProductionGetObservation] = field(default_factory=list)
    patch_observations: list[ProductionPatchObservation] = field(default_factory=list)
    list_raw_calls: int = 0
    get_raw_calls: int = 0
    patch_raw_calls: int = 0
    _collection_index: int = 0
    _page_index: int = 0
    _get_index: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def list_events(self, request: ProductionFullSnapshotRequest) -> ProductionSnapshotPage:
        with self._lock:
            self.list_raw_calls += 1
            self.call_log.append("events.list")
            self.list_observations.append(
                ProductionListObservation(
                    token_role=request.token_role,
                    single_events=request.single_events,
                    show_deleted=request.show_deleted,
                    max_results=request.max_results,
                    time_min_present=request.time_min is not None,
                    time_max_present=request.time_max is not None,
                    sync_token_present=request.sync_token is not None,
                    query_present=request.query is not None,
                )
            )
            failure = self.list_failures.get(self.list_raw_calls)
            if failure is not None:
                raise failure
            if self._collection_index >= len(self.collections):
                raise ProductionTransportFailure("mock_list_script_exhausted")
            pages = self.collections[self._collection_index]
            if self._page_index >= len(pages):
                raise ProductionTransportFailure("mock_list_page_exhausted")
            expected_token = None if self._page_index == 0 else f"mock-page-{self._page_index + 1}"
            if request.page_token != expected_token:
                raise ProductionTransportFailure("mock_list_page_token_mismatch")
            page = pages[self._page_index]
            self._page_index += 1
            if page.collection_complete:
                self._collection_index += 1
                self._page_index = 0
            return page

    def get_event(self, event_id: str, token_role: str) -> CanonicalGoogleEvent:
        del event_id
        with self._lock:
            self.get_raw_calls += 1
            self.call_log.append("events.get")
            self.get_observations.append(ProductionGetObservation(token_role=token_role))
            if token_role != "production_read_only":
                raise ProductionTransportFailure("mock_get_contract_mismatch")
            failure = self.get_failures.get(self.get_raw_calls)
            if failure is not None:
                raise failure
            if self._get_index >= len(self.get_events):
                raise ProductionTransportFailure("mock_get_script_exhausted")
            outcome = self.get_events[self._get_index]
            self._get_index += 1
            if isinstance(outcome, ProductionTransportFailure):
                raise outcome
            return outcome

    def patch_description(
        self,
        event_id: str,
        description: str,
        if_match: str,
        send_updates: str,
        token_role: str,
        write_token_generation: int,
    ) -> ProductionPatchAcknowledgement:
        del event_id, description
        with self._lock:
            self.patch_raw_calls += 1
            self.call_log.append("events.patch")
            observation = ProductionPatchObservation(
                if_match_present=bool(if_match),
                if_match_wildcard=if_match == "*",
                send_updates=send_updates,
                token_role=token_role,
                write_token_generation_present=(
                    isinstance(write_token_generation, int)
                    and not isinstance(write_token_generation, bool)
                    and write_token_generation >= 1
                ),
            )
            self.patch_observations.append(observation)
            if (
                not if_match
                or if_match == "*"
                or send_updates != PRODUCTION_SEND_UPDATES
                or token_role != "production_write"
                or isinstance(write_token_generation, bool)
                or not isinstance(write_token_generation, int)
                or write_token_generation < 1
                or (self.expected_if_match is not None and if_match != self.expected_if_match)
            ):
                raise ProductionTransportFailure("mock_patch_contract_mismatch")
            if self.patch_failure is not None:
                raise self.patch_failure
            return ProductionPatchAcknowledgement()


class _FullSnapshotReader:
    __slots__ = ("_script",)

    def __init__(self, script: _FakeScript) -> None:
        self._script = script

    def list_events(self, *, request: ProductionFullSnapshotRequest) -> ProductionSnapshotPage:
        return self._script.list_events(request)


class _FreshEventReader:
    __slots__ = ("_script",)

    def __init__(self, script: _FakeScript) -> None:
        self._script = script

    def get_event(self, *, event_id: str, token_role: str) -> CanonicalGoogleEvent:
        return self._script.get_event(event_id, token_role)


class _SingleUpdateMutator:
    __slots__ = ("_script",)

    def __init__(self, script: _FakeScript) -> None:
        self._script = script

    def patch_description(
        self,
        *,
        event_id: str,
        description: str,
        if_match: str,
        send_updates: str,
        token_role: str,
        write_token_generation: int,
    ) -> ProductionPatchAcknowledgement:
        return self._script.patch_description(
            event_id,
            description,
            if_match,
            send_updates,
            token_role,
            write_token_generation,
        )


class FakeProductionTransportBundle:
    """Script holder exposing three least-capability facade objects."""

    def __init__(
        self,
        *,
        collections: Sequence[Sequence[ProductionSnapshotPage]],
        get_events: Sequence[CanonicalGoogleEvent | ProductionTransportFailure],
        list_failures: Mapping[int, ProductionTransportFailure] | None = None,
        get_failures: Mapping[int, ProductionTransportFailure] | None = None,
        patch_failure: ProductionTransportFailure | None = None,
        expected_if_match: str | None = None,
    ) -> None:
        self._script = _FakeScript(
            collections=tuple(tuple(collection) for collection in collections),
            get_events=tuple(get_events),
            list_failures={} if list_failures is None else dict(list_failures),
            get_failures={} if get_failures is None else dict(get_failures),
            patch_failure=patch_failure,
            expected_if_match=expected_if_match,
        )
        self.full_snapshot_reader = _FullSnapshotReader(self._script)
        self.fresh_event_reader = _FreshEventReader(self._script)
        self.single_update_mutator = _SingleUpdateMutator(self._script)

    @property
    def call_log(self) -> tuple[str, ...]:
        return tuple(self._script.call_log)

    @property
    def patch_observations(self) -> tuple[ProductionPatchObservation, ...]:
        return tuple(self._script.patch_observations)

    @property
    def list_observations(self) -> tuple[ProductionListObservation, ...]:
        return tuple(self._script.list_observations)

    @property
    def get_observations(self) -> tuple[ProductionGetObservation, ...]:
        return tuple(self._script.get_observations)

    @property
    def raw_call_counts(self) -> tuple[int, int, int]:
        return (
            self._script.list_raw_calls,
            self._script.get_raw_calls,
            self._script.patch_raw_calls,
        )


class ScriptedProductionExecutionStateProvider:
    """Mock-only switch/token generations returned in deterministic order."""

    def __init__(self, *, kill_switches: Sequence[object], token_generations: Sequence[int | None]):
        if not kill_switches or not token_generations:
            raise ValueError("Mock execution state scripts must not be empty")
        self._kill_switches = tuple(kill_switches)
        self._token_generations = tuple(token_generations)
        self._switch_index = 0
        self._token_index = 0

    def current_kill_switch(self) -> object:
        index = min(self._switch_index, len(self._kill_switches) - 1)
        self._switch_index += 1
        return self._kill_switches[index]

    def current_write_token_generation(self) -> int | None:
        index = min(self._token_index, len(self._token_generations) - 1)
        self._token_index += 1
        return self._token_generations[index]


def production_live_execution_not_available() -> None:
    """Fail closed for every Phase 6C live invocation attempt."""

    raise ProductionTransportFailure(
        "production_live_execution_not_available_in_phase_6c",
        "Production live execution is not available in Phase 6C",
    )


def require_phase6c_mock_transport_capabilities(
    full_snapshot_reader: ProductionFullSnapshotReader,
    fresh_event_reader: ProductionFreshEventReader,
    single_update_mutator: ProductionSingleUpdateMutator,
) -> None:
    """Reject structural impostors; Phase 6C accepts only sealed fake facades."""

    if not (
        type(full_snapshot_reader) is _FullSnapshotReader
        and type(fresh_event_reader) is _FreshEventReader
        and type(single_update_mutator) is _SingleUpdateMutator
        and full_snapshot_reader._script is fresh_event_reader._script
        and fresh_event_reader._script is single_update_mutator._script
    ):
        raise ProductionTransportFailure(
            "production_mock_transport_required",
            "Phase 6C requires one sealed mock Production transport",
        )


__all__ = [
    "FakeProductionTransportBundle",
    "ProductionGetObservation",
    "ProductionListObservation",
    "ProductionPatchObservation",
    "ProductionTransportFailure",
    "ScriptedProductionExecutionStateProvider",
    "paginate_production_snapshot",
    "production_live_execution_not_available",
    "require_phase6c_mock_transport_capabilities",
]
