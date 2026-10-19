"""Temporary memory-only characterization of session re-entry after failed publication.

This records a missing connection, not an approval to reuse credentials. Revisit
the second-call expectation when a separately reviewed history-enforcement contract
is implemented. The independent pure policy evaluation is not injected into sessions.
"""

from __future__ import annotations

import builtins
import io
import json
import os
import socket
import subprocess
import webbrowser
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any, NoReturn

import pytest
from phase6d0_auth_helpers import (
    ISSUED_AT,
    FakeRefresher,
    oauth_credentials,
    production_target,
    production_token,
)

from tridentine_calendar_google_sync import production_write_token as tokens
from tridentine_calendar_google_sync import production_write_token_io as token_io
from tridentine_calendar_google_sync import production_write_token_rehearsal as rehearsal
from tridentine_calendar_google_sync import production_write_token_reuse_policy as policy
from tridentine_calendar_google_sync.production_write_token_models import (
    PRODUCTION_WRITE_SCOPES,
    ProductionWriteAuthorizedUserToken,
    ProductionWriteCredentialSession,
    ProductionWriteGrantEvidenceOrigin,
    ProductionWriteOAuthCredentials,
    ProductionWriteTokenGenerationState,
)

NOW = ISSUED_AT + timedelta(seconds=2)
SECOND_NOW = NOW + timedelta(seconds=1)
TOKEN_PATH = "synthetic-reentry-only/write-token.json"
STATE_PATH = "synthetic-reentry-only/generation.json"
READ_PATH = "synthetic-reentry-only/read-token.json"
TEST_PATH = "synthetic-reentry-only/test-token.json"


class _ForbiddenScenarioEffect(BaseException):
    """An effect tripwire must escape the product's ordinary Exception handlers."""


def _forbidden(*_args: Any, **_kwargs: Any) -> NoReturn:
    raise _ForbiddenScenarioEffect("Forbidden effect in memory-only scenario")


def _deny_real_effects(patch: pytest.MonkeyPatch) -> None:
    """Bounded tripwires for these preimported paths; not a general I/O sandbox."""
    patch.setattr(builtins, "open", _forbidden)
    patch.setattr(io, "open", _forbidden)
    for name in (
        "open",
        "read",
        "write",
        "stat",
        "lstat",
        "unlink",
        "remove",
        "replace",
        "rename",
        "chmod",
        "mkdir",
        "rmdir",
    ):
        patch.setattr(os, name, _forbidden)
    for name in ("pread", "pwrite"):
        if hasattr(os, name):
            patch.setattr(os, name, _forbidden)
    for name in ("open", "stat", "lstat", "resolve", "iterdir"):
        patch.setattr(Path, name, _forbidden)
    patch.setattr(socket, "socket", _forbidden)
    patch.setattr(socket, "create_connection", _forbidden)
    patch.setattr(subprocess, "Popen", _forbidden)
    patch.setattr(subprocess, "run", _forbidden)
    patch.setattr(os, "system", _forbidden)
    for name in ("open", "open_new", "open_new_tab", "get"):
        patch.setattr(webbrowser, name, _forbidden)
    patch.setattr(tokens, "load_desktop_client_config", _forbidden)
    for name in (
        "write_production_write_authorized_user_token",
        "write_production_write_token_generation_state",
        "write_production_write_token_bundle",
        "atomic_write_private_text",
        "create_private_text",
        "read_private_sensitive_bytes",
        "read_sensitive_bytes",
        "remove_sensitive_file_if_matches",
        "_remove_exact_new_artifact",
    ):
        patch.setattr(token_io, name, _forbidden)
    patch.setattr(token_io.posix_replace, "replace_posix_private_bytes", _forbidden)


class _MemoryLock:
    def __init__(self, pair: _MemoryPair) -> None:
        self.pair = pair
        self.call = pair.call
        self.error: BaseException | None = None
        self.exited = False

    def __enter__(self) -> Callable[[], None]:
        assert self.pair.active is None
        self.pair.active = self
        self.pair.note("lock_enter")
        return self.checkpoint

    def checkpoint(self) -> None:
        assert self.pair.active is self and not self.exited
        self.pair.note("checkpoint")

    def __exit__(self, _kind: object, error: BaseException | None, _tb: object) -> None:
        assert self.pair.active is self and self.call == self.pair.call
        self.error = error
        self.pair.note("lock_exit_error" if error is not None else "lock_exit_normal")
        self.pair.active = None
        self.exited = True
        # None never suppresses the original exception or invents a recovery.


class _MemoryPair:
    """One explicit synthetic pair, never a file and never a runtime adapter."""

    def __init__(self, *, expired: bool = True) -> None:
        self.target = production_target()
        self.confirmation = rehearsal.production_write_token_rehearsal_challenge(self.target)
        self.state = tokens.build_initial_production_write_token_generation_state(
            self.target, issued_at=ISSUED_AT
        )
        self.original_state = self.state
        self.old_token = production_token(
            self.state,
            expiry=ISSUED_AT + (timedelta(seconds=1) if expired else timedelta(hours=1)),
        )
        self.token = self.old_token
        self.call = 0
        self.trace: list[tuple[int, str]] = []
        self.contexts: list[_MemoryLock] = []
        self.active: _MemoryLock | None = None
        self.read_tokens: list[ProductionWriteAuthorizedUserToken] = []
        self.read_states: list[ProductionWriteTokenGenerationState] = []

    def note(self, event: str) -> None:
        self.trace.append((self.call, event))

    def begin(self, call: int) -> None:
        assert call == self.call + 1 and self.active is None
        self.call = call
        self.note("explicit_call")

    def validate_paths(
        self,
        *,
        production_write_token_path: str | Path,
        generation_state_path: str | Path,
        production_read_token_path: str | Path,
        test_write_token_path: str | Path,
        client_config_path: str | Path | None,
        write_token_exists: bool,
        generation_state_exists: bool,
    ) -> tuple[Path, Path, Path, Path, None]:
        assert self.active is None and self.call in (1, 2)
        assert (
            production_write_token_path,
            generation_state_path,
            production_read_token_path,
            test_write_token_path,
        ) == (TOKEN_PATH, STATE_PATH, READ_PATH, TEST_PATH)
        assert client_config_path is None
        assert write_token_exists is True and generation_state_exists is True
        self.note("path_check")
        # Lexical objects only; this does not establish real private-path conditions.
        return Path(TOKEN_PATH), Path(STATE_PATH), Path(READ_PATH), Path(TEST_PATH), None

    def lock(self, token_path: str | Path, state_path: str | Path) -> _MemoryLock:
        assert (token_path, state_path) == (TOKEN_PATH, STATE_PATH)
        assert self.active is None
        context = _MemoryLock(self)
        self.contexts.append(context)
        self.note("lock_create")
        return context

    def load_state(self, path: str | Path) -> ProductionWriteTokenGenerationState:
        assert path == STATE_PATH and self.active is not None
        self.note("state_read")
        self.read_states.append(self.state)
        return self.state

    def load_token(self, path: str | Path) -> ProductionWriteAuthorizedUserToken:
        assert path == TOKEN_PATH and self.active is not None
        self.note("token_read")
        self.read_tokens.append(self.token)
        return self.token

    def publish_then_fail(
        self,
        token: ProductionWriteAuthorizedUserToken,
        path: str | Path,
        *,
        expected_token: ProductionWriteAuthorizedUserToken,
    ) -> NoReturn:
        assert self.call == 1 and self.active is not None
        assert path == TOKEN_PATH
        assert expected_token is self.old_token and self.token is self.old_token
        assert token is not self.old_token and token.expiry > SECOND_NOW
        assert token.generation == self.state.generation
        self.note("save")
        self.token = token
        self.note("simulated_publish")
        self.note("writer_raise")
        raise token_io.ProductionWriteTokenIOError(
            "synthetic_reentry_publication_failure",
            "Synthetic publication failed",
            publication_possible=True,
        )

    def install(self, patch: pytest.MonkeyPatch) -> None:
        # Exactly these five boundaries simulate I/O; pure product checks remain real.
        patch.setattr(token_io, "validate_production_write_token_path_set", self.validate_paths)
        patch.setattr(token_io, "load_production_write_token_generation_state", self.load_state)
        patch.setattr(token_io, "load_production_write_authorized_user_token", self.load_token)
        patch.setattr(token_io, "persist_refreshed_production_write_token", self.publish_then_fail)
        patch.setattr(tokens, "_production_write_session_lock", self.lock)

    def counts(self, call: int) -> dict[str, int]:
        events = [event for number, event in self.trace if number == call]
        return {
            "path_checks": events.count("path_check"),
            "state_reads": events.count("state_read"),
            "token_reads": events.count("token_read"),
            "refresh": events.count("refresh"),
            "save": events.count("save"),
            "simulated_publications": events.count("simulated_publish"),
            "session_returns": events.count("session_return"),
            "lock_contexts": events.count("lock_create"),
            "lock_enters": events.count("lock_enter"),
            "lock_checkpoints": events.count("checkpoint"),
            "lock_exits": events.count("lock_exit_error") + events.count("lock_exit_normal"),
        }


class _ObservedRefresher(FakeRefresher):
    """Record, then delegate to the existing fake through the public mock argument."""

    def __init__(self, pair: _MemoryPair) -> None:
        super().__init__(
            oauth_credentials(
                expiry=NOW + timedelta(hours=1),
                evidence_origin=ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
                evidence_observed_at=NOW,
                access_token="synthetic-reentry-new-access-never-live",
                refresh_token="synthetic-reentry-new-refresh-never-live",
            )
        )
        self.pair = pair

    def refresh(
        self, token: ProductionWriteAuthorizedUserToken, scopes: tuple[str, ...]
    ) -> ProductionWriteOAuthCredentials:
        assert self.pair.active is not None and self.pair.call == 1
        assert token is self.pair.old_token and scopes == PRODUCTION_WRITE_SCOPES
        self.pair.note("refresh")
        return super().refresh(token, scopes)


FIRST_EVENTS = (
    "explicit_call",
    "path_check",
    "lock_create",
    "lock_enter",
    "state_read",
    "token_read",
    "checkpoint",
    "checkpoint",
    "refresh",
    "checkpoint",
    "state_read",
    "token_read",
    "checkpoint",
    "save",
    "simulated_publish",
    "writer_raise",
    "lock_exit_error",
    "caller_caught_persistence_error",
)
UNEXPIRED_EVENTS = (
    "explicit_call",
    "path_check",
    "lock_create",
    "lock_enter",
    "state_read",
    "token_read",
    "checkpoint",
    "checkpoint",
    "lock_exit_normal",
    "session_return",
)


def _assert_first_refusal(
    pair: _MemoryPair,
    refresher: FakeRefresher,
    error: tokens.ProductionWriteTokenRefreshPersistenceError,
) -> None:
    assert type(error) is tokens.ProductionWriteTokenRefreshPersistenceError
    assert error.code == "production_write_token_refresh_persistence_failed"
    assert error.refresh_completed is True and error.persistence_attempted is True
    assert error.publication_possible is True
    assert error.__cause__ is None and error.__suppress_context__ is True
    assert refresher.calls == refresher.refresh_attempt_count == 1
    assert refresher.calendar_api_call_count == refresher.browser_fallback_count == 0
    assert tuple(pair.trace) == tuple((1, event) for event in FIRST_EVENTS)
    assert pair.active is None and pair.contexts[0].exited
    assert pair.contexts[0].error is error
    assert pair.state is pair.original_state
    assert pair.token is not pair.old_token and pair.token.expiry > SECOND_NOW
    assert pair.token.generation == pair.original_state.generation
    assert len(pair.read_tokens) == len(pair.read_states) == 2
    assert all(token is pair.old_token for token in pair.read_tokens)
    assert all(state is pair.original_state for state in pair.read_states)


def test_failed_publication_then_independent_reentry_is_not_policy_enforcement(
    monkeypatch: pytest.MonkeyPatch, record_property: Callable[[str, object], None]
) -> None:
    pair = _MemoryPair()
    first_refresher = _ObservedRefresher(pair)
    second_refresher = FakeRefresher(None)
    # These are independently declared model assumptions, not authenticated history.
    operation = policy.OperationDefinition(
        binding=policy.SyntheticBinding("synthetic-reentry-store", "synthetic-reentry-pair"),
        operation_id="synthetic-refresh-operation-one",
        kind=policy.OperationKind.REFRESH,
        generation_ref="synthetic-generation-one",
    )
    request = policy.PolicyInput(
        target=operation,
        history=(
            policy.OperationEvent(operation, 1, policy.EventKind.START_RECORDED),
            policy.OperationEvent(operation, 2, policy.EventKind.PROGRESS),
            policy.OperationEvent(operation, 3, policy.EventKind.FAILED),
        ),
        registered=True,
        history_status=policy.HistoryStatus.COMPLETE,
        observations=policy.AppearanceObservations(
            content_matches=True,
            token_unexpired=True,
            generation_matches=True,
            publication_possible=True,
        ),
    )
    assert operation.operation_id != operation.generation_ref
    first_session = None
    with monkeypatch.context() as isolated:
        pair.install(isolated)
        _deny_real_effects(isolated)
        pair.begin(1)
        with pytest.raises(tokens.ProductionWriteTokenRefreshPersistenceError) as caught:
            first_session = tokens.prepare_production_write_rehearsal_credential_session_mock(
                TOKEN_PATH,
                STATE_PATH,
                READ_PATH,
                TEST_PATH,
                pair.target,
                pair.confirmation,
                now=NOW,
                refresher=first_refresher,
            )
        pair.note("caller_caught_persistence_error")
        assert first_session is None
        before_second = tuple(pair.trace)
        _assert_first_refusal(pair, first_refresher, caught.value)
        published = pair.token
        assert tuple(pair.trace) == before_second  # No work during the caller-owned gap.

        pair.begin(2)  # A deliberate new API invocation, never an implementation retry.
        session = tokens.prepare_production_write_rehearsal_credential_session_mock(
            TOKEN_PATH,
            STATE_PATH,
            READ_PATH,
            TEST_PATH,
            pair.target,
            pair.confirmation,
            now=SECOND_NOW,
            refresher=second_refresher,
        )
        pair.note("session_return")
        assert type(session) is ProductionWriteCredentialSession
        assert session.token is published and session.generation_state is pair.original_state
        assert session.refresh_count == 0
        assert session.browser_fallback_count == session.calendar_api_call_count == 0
        assert second_refresher.calls == second_refresher.refresh_attempt_count == 0
        assert (
            second_refresher.calendar_api_call_count == second_refresher.browser_fallback_count == 0
        )
        assert pair.state is pair.original_state and pair.token is published
        assert pair.read_tokens[-1] is published and pair.read_states[-1] is pair.original_state
        assert pair.contexts[0] is not pair.contexts[1]
        assert pair.contexts[1].error is None and pair.contexts[1].exited
        assert pair.active is None and len(pair.contexts) == 2
        assert tuple(pair.trace) == (
            tuple((1, event) for event in FIRST_EVENTS)
            + tuple((2, event) for event in UNEXPIRED_EVENTS)
        )

        # FAILED mapping is this test's assumption. No product adapter connects it.
        before_policy = tuple(pair.trace)
        decision = policy.evaluate_reuse_policy(request)
        assert tuple(pair.trace) == before_policy
        assert decision.state is policy.PolicyState.RECONCILIATION_REQUIRED
        assert decision.reasons == (
            policy.RefusalReason.POLICY_NEVER_AUTHORIZES,
            policy.RefusalReason.UNRESOLVED_FAILURE,
        )
        assert decision.unresolved_failure is True
        assert decision.unresolved_interruption is decision.unresolved_commit is False
        assert decision.transitions_valid is True and decision.reuse_authorized is False

    # No token, rendered credential, path, or session is included in diagnostics.
    record_property(
        "reentry_evidence",
        json.dumps(
            {
                "scope": "MEMORY_ONLY",
                "first": pair.counts(1),
                "second": pair.counts(2),
                "first_error": {
                    "type": type(caught.value).__name__,
                    "refresh_completed": caught.value.refresh_completed,
                    "persistence_attempted": caught.value.persistence_attempted,
                    "publication_possible": caught.value.publication_possible,
                },
                "policy": {
                    "state": decision.state.name,
                    "reasons": [reason.name for reason in decision.reasons],
                    "unresolved_failure": decision.unresolved_failure,
                    "unresolved_interruption": decision.unresolved_interruption,
                    "unresolved_commit": decision.unresolved_commit,
                    "transitions_valid": decision.transitions_valid,
                    "reuse_authorized": decision.reuse_authorized,
                },
                "trace": [f"{call}:{event}" for call, event in pair.trace],
            },
            sort_keys=True,
        ),
    )


def test_initial_unexpired_pair_returns_without_refresh_or_save(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair = _MemoryPair(expired=False)
    refresher = FakeRefresher(None)
    with monkeypatch.context() as isolated:
        pair.install(isolated)
        _deny_real_effects(isolated)
        pair.begin(1)
        session = tokens.prepare_production_write_rehearsal_credential_session_mock(
            TOKEN_PATH,
            STATE_PATH,
            READ_PATH,
            TEST_PATH,
            pair.target,
            pair.confirmation,
            now=NOW,
            refresher=refresher,
        )
        pair.note("session_return")
        assert type(session) is ProductionWriteCredentialSession
        assert session.token is pair.old_token and session.generation_state is pair.original_state
        assert (
            session.refresh_count == 0 and refresher.calls == refresher.refresh_attempt_count == 0
        )
        assert session.browser_fallback_count == session.calendar_api_call_count == 0
        assert refresher.calendar_api_call_count == refresher.browser_fallback_count == 0
        assert pair.token is pair.old_token and pair.state is pair.original_state
        assert pair.read_tokens == [pair.old_token] and pair.read_states == [pair.original_state]
        assert pair.active is None and len(pair.contexts) == 1
        assert pair.contexts[0].exited and pair.contexts[0].error is None
        assert tuple(pair.trace) == tuple((1, event) for event in UNEXPIRED_EVENTS)


def test_independent_reentry_still_rejects_a_broken_generation_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair = _MemoryPair()
    first_refresher = _ObservedRefresher(pair)
    second_refresher = FakeRefresher(None)
    first_session = second_session = None
    with monkeypatch.context() as isolated:
        pair.install(isolated)
        _deny_real_effects(isolated)
        pair.begin(1)
        with pytest.raises(tokens.ProductionWriteTokenRefreshPersistenceError) as caught:
            first_session = tokens.prepare_production_write_rehearsal_credential_session_mock(
                TOKEN_PATH,
                STATE_PATH,
                READ_PATH,
                TEST_PATH,
                pair.target,
                pair.confirmation,
                now=NOW,
                refresher=first_refresher,
            )
        pair.note("caller_caught_persistence_error")
        assert first_session is None
        _assert_first_refusal(pair, first_refresher, caught.value)
        # Deliberate test-only corruption after the first refusal, not product recovery.
        pair.token = pair.token.model_copy(update={"generation": pair.state.generation + 1})
        pair.note("test_corrupts_generation")
        pair.begin(2)
        with pytest.raises(tokens.ProductionWriteTokenConfigError) as invalid:
            second_session = tokens.prepare_production_write_rehearsal_credential_session_mock(
                TOKEN_PATH,
                STATE_PATH,
                READ_PATH,
                TEST_PATH,
                pair.target,
                pair.confirmation,
                now=SECOND_NOW,
                refresher=second_refresher,
            )
        pair.note("caller_caught_binding_error")
        assert second_session is None
        assert type(invalid.value) is tokens.ProductionWriteTokenConfigError
        assert invalid.value.code == "production_write_token_generation_mismatch"
        assert second_refresher.calls == second_refresher.refresh_attempt_count == 0
        assert (
            second_refresher.calendar_api_call_count == second_refresher.browser_fallback_count == 0
        )
        assert pair.state is pair.original_state
        assert pair.read_tokens[-1] is pair.token and pair.read_states[-1] is pair.original_state
        assert pair.contexts[0] is not pair.contexts[1] and len(pair.contexts) == 2
        assert pair.contexts[1].exited and pair.contexts[1].error is invalid.value
        assert pair.active is None
        assert tuple(pair.trace) == (
            *((1, event) for event in FIRST_EVENTS),
            (1, "test_corrupts_generation"),
            *(
                (2, event)
                for event in (
                    "explicit_call",
                    "path_check",
                    "lock_create",
                    "lock_enter",
                    "state_read",
                    "token_read",
                    "checkpoint",
                    "lock_exit_error",
                    "caller_caught_binding_error",
                )
            ),
        )
