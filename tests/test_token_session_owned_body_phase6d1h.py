"""Memory-only compatibility tests for the session-local owned credential body.

Synthetic requests and a fake lock establish no native ownership or START linkage.
The existing five credential I/O seams are replaced only inside each scenario.
"""

from __future__ import annotations

import ast
import copy
import pickle
import sys
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from types import FrameType, TracebackType
from typing import Literal

import pytest
import test_credential_session_lock_phase6d1h as lock_guards
import test_refresh_persistence_failure_phase6d1h as persistence_guards
import test_refresh_prewrite_recheck_phase6d1h as prewrite_guards
import test_refresh_replace_integration_phase6d1h as replace_guards
import test_token_session_failure_reentry_phase6d1h as memory
from phase6d0_auth_helpers import FakeRefresher, oauth_credentials

from tridentine_calendar_google_sync import production_write_token as tokens
from tridentine_calendar_google_sync import production_write_token_io as token_io
from tridentine_calendar_google_sync.production_write_token_models import (
    PRODUCTION_WRITE_SCOPES,
    ProductionWriteAuthorizedUserToken,
    ProductionWriteCredentialSession,
    ProductionWriteGrantedScopeEvidence,
    ProductionWriteGrantEvidenceOrigin,
    ProductionWriteOAuthCredentials,
    ProductionWriteTokenGenerationState,
)


class _Cancellation(BaseException):
    """Fixed, synthetic cancellation that ordinary handlers must not consume."""


class _Scenario(memory._MemoryPair):
    def __init__(self, *, expired: bool = False) -> None:
        super().__init__(expired=expired)
        self.failure_stage: str | None = None
        self.failure: BaseException | None = None
        self.exit_failure: BaseException | None = None
        self.publish = False
        self.change_second_token = False
        self.exit_probe: Callable[[], None] | None = None
        self.reader_probe: Callable[[], None] | None = None
        self.exit_details: list[tuple[object, BaseException | None, object]] = []

    def trip(self, stage: str) -> None:
        if self.failure_stage == stage:
            assert self.failure is not None
            self.note("injected_failure")
            raise self.failure

    def validate_paths(self, **values: object) -> tuple[Path, Path, Path, Path, None]:
        result = super().validate_paths(**values)
        self.trip("path")
        return result

    def lock(self, token_path: str | Path, state_path: str | Path) -> _Lock:
        assert (token_path, state_path) == (memory.TOKEN_PATH, memory.STATE_PATH)
        assert self.active is None
        self.note("lock_create")
        self.trip("acquire")
        context = _Lock(self)
        self.contexts.append(context)
        return context

    def load_state(self, path: str | Path) -> ProductionWriteTokenGenerationState:
        result = super().load_state(path)
        self.trip("state_read" if len(self.read_states) == 1 else "state_reread")
        if self.reader_probe is not None:
            probe = self.reader_probe
            self.reader_probe = None
            probe()
        return result

    def load_token(self, path: str | Path) -> ProductionWriteAuthorizedUserToken:
        result = super().load_token(path)
        self.trip("token_read" if len(self.read_tokens) == 1 else "token_reread")
        if self.change_second_token and len(self.read_tokens) == 2:
            return result.model_copy(update={"generation": result.generation + 1})
        return result

    def publish_then_fail(
        self,
        token: ProductionWriteAuthorizedUserToken,
        path: str | Path,
        *,
        expected_token: ProductionWriteAuthorizedUserToken,
    ) -> None:
        assert self.active is not None and path == memory.TOKEN_PATH
        assert expected_token is self.old_token and self.token is self.old_token
        self.note("save")
        if self.publish:
            self.token = token
            self.note("simulated_publish")
        self.trip("save")


class _Lock(memory._MemoryLock):
    pair: _Scenario

    def __init__(self, pair: _Scenario) -> None:
        super().__init__(pair)
        self.checkpoints = 0

    def __enter__(self) -> Callable[[], None]:
        self.pair.note("lock_enter")
        self.pair.trip("entry")
        assert self.pair.active is None
        self.pair.active = self
        return self.checkpoint

    def checkpoint(self) -> None:
        assert self.pair.active is self and not self.exited
        self.checkpoints += 1
        self.pair.note("checkpoint")
        self.pair.trip(f"checkpoint_{self.checkpoints}")

    def __exit__(
        self,
        kind: type[BaseException] | None,
        error: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.pair.exit_details.append((kind, error, tb))
        if self.pair.exit_probe is not None:
            self.pair.exit_probe()
        super().__exit__(kind, error, tb)
        self.pair.trip("exit")
        if self.pair.exit_failure is not None:
            raise self.pair.exit_failure


class _Refresher(FakeRefresher):
    def __init__(self, pair: _Scenario) -> None:
        super().__init__(
            oauth_credentials(
                expiry=memory.NOW + timedelta(hours=1),
                evidence_origin=ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
                evidence_observed_at=memory.NOW,
            )
        )
        self.pair = pair
        self.bad_accounting = False

    def refresh(
        self,
        token: ProductionWriteAuthorizedUserToken,
        scopes: tuple[str, ...],
    ) -> ProductionWriteOAuthCredentials:
        assert self.pair.active is not None and token is self.pair.old_token
        assert scopes == PRODUCTION_WRITE_SCOPES
        self.pair.note("refresh")
        self.pair.trip("refresh")
        result = super().refresh(token, scopes)
        if self.bad_accounting:
            self.refresh_attempt_count = 2
        return result


@contextmanager
def _installed(
    patch: pytest.MonkeyPatch,
    pair: _Scenario,
) -> Iterator[None]:
    original_constructor = tokens.ProductionWriteCredentialSession

    def construct(
        *,
        token: ProductionWriteAuthorizedUserToken,
        generation_state: ProductionWriteTokenGenerationState,
        refresh_count: Literal[0, 1],
    ) -> ProductionWriteCredentialSession:
        assert pair.active is not None
        pair.note("constructor")
        return original_constructor(
            token=token, generation_state=generation_state, refresh_count=refresh_count
        )

    with patch.context() as isolated:
        pair.install(isolated)
        isolated.setattr(tokens, "ProductionWriteCredentialSession", construct)
        memory._deny_real_effects(isolated)
        pair.begin(1)
        yield


def _public(
    pair: _Scenario,
    refresher: FakeRefresher | None = None,
    *,
    provider: bool = False,
    now: datetime = memory.NOW,
    confirmation: str | None = None,
) -> ProductionWriteCredentialSession:
    phrase = pair.confirmation if confirmation is None else confirmation
    if provider:
        result = tokens.prepare_production_write_rehearsal_credential_session(
            memory.TOKEN_PATH,
            memory.STATE_PATH,
            memory.READ_PATH,
            memory.TEST_PATH,
            pair.target,
            phrase,
            now=now,
        )
    else:
        result = tokens.prepare_production_write_rehearsal_credential_session_mock(
            memory.TOKEN_PATH,
            memory.STATE_PATH,
            memory.READ_PATH,
            memory.TEST_PATH,
            pair.target,
            phrase,
            now=now,
            refresher=refresher,
        )
    assert pair.active is None
    pair.note("session_return")
    return result


def _scope(
    pair: _Scenario,
    refresher: FakeRefresher | None = None,
) -> tokens._CredentialSessionScopeContext:
    return tokens._credential_session_scope(
        memory.TOKEN_PATH,
        memory.STATE_PATH,
        memory.READ_PATH,
        memory.TEST_PATH,
        pair.target,
        now=memory.NOW,
        evidence_mode="test",
        refresher=refresher,
    )


def _events(pair: _Scenario) -> tuple[str, ...]:
    return tuple(event for call, event in pair.trace if call == 1)


def _no_content(pair: _Scenario) -> None:
    events = _events(pair)
    assert all(
        events.count(name) == 0
        for name in (
            "state_read",
            "token_read",
            "refresh",
            "save",
            "constructor",
            "session_return",
        )
    )


def _provider_token(pair: _Scenario) -> None:
    evidence = ProductionWriteGrantedScopeEvidence(
        origin=ProductionWriteGrantEvidenceOrigin.FRESH_AUTHORIZATION_RESPONSE,
        raw_scope_tokens=PRODUCTION_WRITE_SCOPES,
        granted_scopes=PRODUCTION_WRITE_SCOPES,
        observed_at=memory.ISSUED_AT,
    )
    pair.token = pair.old_token.model_copy(update={"grant_evidence": evidence})
    pair.old_token = pair.token


@pytest.mark.parametrize("mode", ("test_unexpired", "test_refreshed", "provider"))
def test_public_paths_retain_real_construction_and_exact_checkpoint_order(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
    record_property: Callable[[str, object], None],
) -> None:
    pair = _Scenario(expired=mode == "test_refreshed")
    refresher = _Refresher(pair)
    if mode == "provider":
        _provider_token(pair)
    with _installed(monkeypatch, pair):
        session = _public(pair, refresher, provider=mode == "provider")
    assert type(session) is ProductionWriteCredentialSession
    assert session.generation_state is pair.original_state
    assert session.refresh_count == int(mode == "test_refreshed")
    prefix = (
        "explicit_call",
        "path_check",
        "lock_create",
        "lock_enter",
        "state_read",
        "token_read",
        "checkpoint",
    )
    if mode == "test_refreshed":
        expected = (
            *prefix,
            "checkpoint",
            "refresh",
            "checkpoint",
            "state_read",
            "token_read",
            "checkpoint",
            "save",
            "checkpoint",
            "constructor",
            "lock_exit_normal",
            "session_return",
        )
        assert refresher.calls == refresher.refresh_attempt_count == 1
        assert session.token is not pair.old_token
    else:
        expected = (
            *prefix,
            "checkpoint",
            "constructor",
            "lock_exit_normal",
            "session_return",
        )
        assert refresher.calls == refresher.refresh_attempt_count == 0
        assert session.token is pair.old_token
    assert _events(pair) == expected
    assert pair.active is None and len(pair.exit_details) == 1
    assert pair.exit_details[0] == (None, None, None)
    assert session.calendar_api_call_count == session.browser_fallback_count == 0
    record_property(
        "owned_body_evidence",
        {
            "scope": "MEMORY_ONLY",
            "mode": mode,
            "counts": pair.counts(1),
            "constructors": _events(pair).count("constructor"),
            "native_checkpoint_measured": False,
        },
    )


@pytest.mark.parametrize(
    "mode", ("expired_provider", "provider_test_evidence", "test_provider_evidence")
)
def test_evidence_modes_and_provider_no_refresh_remain_closed(
    monkeypatch: pytest.MonkeyPatch,
    mode: str,
) -> None:
    pair = _Scenario(expired=mode == "expired_provider")
    if mode != "provider_test_evidence":
        _provider_token(pair)
    refresher = _Refresher(pair)
    with (
        _installed(monkeypatch, pair),
        pytest.raises(tokens.ProductionWriteTokenError) as caught,
    ):
        _public(pair, refresher, provider=mode != "test_provider_evidence")
    if mode == "expired_provider":
        assert caught.value.code == "production_write_token_refresh_unavailable"
    else:
        assert caught.value.code == "production_write_token_grant_evidence_origin_mismatch"
    assert _events(pair).count("refresh") == _events(pair).count("save") == 0
    assert _events(pair).count("constructor") == _events(pair).count("session_return") == 0


@pytest.mark.parametrize("stage", ("confirmation", "utc", "path"))
def test_preflight_rejections_precede_acquisition_and_content(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    pair = _Scenario()
    error = token_io.ProductionWriteTokenIOError("synthetic_path_refusal", "Synthetic refusal")
    if stage == "path":
        pair.failure_stage, pair.failure = "path", error
    expected_error = {
        "confirmation": memory.rehearsal.ProductionWriteTokenRehearsalError,
        "utc": tokens.ProductionWriteTokenConfigError,
        "path": token_io.ProductionWriteTokenIOError,
    }[stage]
    with _installed(monkeypatch, pair), pytest.raises(expected_error) as caught:
        _public(
            pair,
            confirmation="synthetic-invalid-confirmation" if stage == "confirmation" else None,
            now=memory.NOW.replace(tzinfo=None) if stage == "utc" else memory.NOW,
        )
    if stage == "path":
        assert caught.value is error
    _no_content(pair)
    assert _events(pair).count("path_check") == int(stage == "path")
    assert _events(pair).count("lock_create") == 0


@pytest.mark.parametrize("stage", ("acquire", "entry", "state_read", "token_read"))
def test_ordinary_early_failures_keep_identity_and_exit_boundary(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    pair = _Scenario()
    error = RuntimeError("Synthetic stage failure")
    pair.failure_stage, pair.failure = stage, error
    with _installed(monkeypatch, pair), pytest.raises(RuntimeError) as caught:
        _public(pair)
    assert caught.value is error
    assert pair.active is None
    assert len(pair.exit_details) == int(stage in ("state_read", "token_read"))
    if pair.exit_details:
        assert pair.exit_details[0][0] is RuntimeError
        assert pair.exit_details[0][1] is error
        assert pair.exit_details[0][2] is not None
    assert all(
        _events(pair).count(name) == 0
        for name in ("refresh", "save", "constructor", "session_return")
    )


@pytest.mark.parametrize(
    "kind", ("generation", "refresh", "accounting", "evidence", "identity", "prewrite")
)
def test_real_validation_and_refresh_failures_preserve_codes_and_chaining(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    pair = _Scenario(expired=True)
    refresher = _Refresher(pair)
    failure = RuntimeError("Synthetic refresh failure")
    if kind == "generation":
        pair.token = pair.token.model_copy(update={"generation": pair.state.generation + 1})
    elif kind == "refresh":
        pair.failure_stage, pair.failure = "refresh", failure
    elif kind == "accounting":
        refresher.bad_accounting = True
    elif kind == "evidence":
        refresher.credentials = oauth_credentials(
            expiry=memory.NOW + timedelta(hours=1),
            evidence_origin=ProductionWriteGrantEvidenceOrigin.FRESH_REFRESH_RESPONSE,
            evidence_observed_at=memory.NOW,
        )
    elif kind == "identity":
        assert refresher.credentials is not None
        refresher.credentials = refresher.credentials.model_copy(
            update={"client_id": "synthetic-other-client"}
        )
    else:
        pair.change_second_token = True
    with (
        _installed(monkeypatch, pair),
        pytest.raises(tokens.ProductionWriteTokenError) as caught,
    ):
        _public(pair, refresher)
    expected = {
        "generation": "production_write_token_generation_mismatch",
        "refresh": "production_write_token_refresh_failed",
        "accounting": "production_write_token_refresh_accounting_invalid",
        "evidence": "unsafe_production_write_grant_evidence",
        "identity": "production_write_token_refresh_identity_mismatch",
        "prewrite": "production_write_token_refresh_prewrite_unverified",
    }
    assert caught.value.code == expected[kind]
    assert all(_events(pair).count(name) == 0 for name in ("save", "constructor", "session_return"))
    assert pair.exit_details[0][1] is caught.value
    if kind == "refresh":
        assert caught.value.__cause__ is failure
    if kind == "prewrite":
        assert type(caught.value) is tokens.ProductionWriteTokenRefreshPrewriteError
        assert caught.value.publication_possible is False
        assert caught.value.persistence_attempted is False
        assert caught.value.__cause__ is None and caught.value.__suppress_context__


@pytest.mark.parametrize("publication", (True, False, None))
def test_save_failure_keeps_publication_evidence_and_simulated_effect(
    monkeypatch: pytest.MonkeyPatch,
    publication: bool | None,
    record_property: Callable[[str, object], None],
) -> None:
    pair = _Scenario(expired=True)
    refresher = _Refresher(pair)
    pair.publish = publication is True
    pair.failure_stage = "save"
    pair.failure = token_io.ProductionWriteTokenIOError(
        "synthetic_owned_save_failure",
        "Synthetic save failure",
        publication_possible=publication,
    )
    with (
        _installed(monkeypatch, pair),
        pytest.raises(tokens.ProductionWriteTokenRefreshPersistenceError) as caught,
    ):
        _public(pair, refresher)
    assert caught.value.publication_possible is publication
    assert caught.value.refresh_completed is caught.value.persistence_attempted is True
    assert caught.value.__cause__ is None and caught.value.__suppress_context__ is True
    assert pair.exit_details[0][1] is caught.value
    assert _events(pair).count("save") == 1
    assert _events(pair).count("simulated_publish") == int(publication is True)
    assert (pair.token is not pair.old_token) is (publication is True)
    assert _events(pair).count("constructor") == _events(pair).count("session_return") == 0
    record_property(
        "owned_save_evidence",
        {
            "scope": "MEMORY_ONLY",
            "publication_possible": publication,
            "counts": pair.counts(1),
            "constructors": 0,
        },
    )


@pytest.mark.parametrize("stage", ("checkpoint_5", "exit"))
def test_post_save_or_exit_failure_withholds_delivery(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    pair = _Scenario(expired=True)
    pair.publish = True
    pair.failure_stage, pair.failure = stage, RuntimeError("Synthetic final failure")
    with _installed(monkeypatch, pair), pytest.raises(RuntimeError) as caught:
        _public(pair, _Refresher(pair))
    assert caught.value is pair.failure
    assert pair.token is not pair.old_token
    assert _events(pair).count("save") == _events(pair).count("simulated_publish") == 1
    assert _events(pair).count("constructor") == int(stage == "exit")
    assert _events(pair).count("session_return") == 0
    assert len(pair.exit_details) == 1 and pair.active is None


@pytest.mark.parametrize("body_cancel", (False, True))
@pytest.mark.parametrize("exit_cancel", (False, True))
def test_existing_context_exit_exception_precedence_is_not_replaced(
    monkeypatch: pytest.MonkeyPatch,
    body_cancel: bool,
    exit_cancel: bool,
) -> None:
    body = (
        _Cancellation("Synthetic body cancellation")
        if body_cancel
        else RuntimeError("Synthetic body failure")
    )
    cleanup = (
        _Cancellation("Synthetic exit cancellation")
        if exit_cancel
        else RuntimeError("Synthetic exit failure")
    )
    pair = _Scenario()
    pair.failure_stage, pair.failure, pair.exit_failure = "state_read", body, cleanup
    with _installed(monkeypatch, pair), pytest.raises(type(cleanup)) as caught:
        _public(pair)
    # The same test context's exit raises the latter object; no new arbitration.
    assert caught.value is cleanup and caught.value.__context__ is body
    assert pair.exit_details[0][1] is body
    assert _events(pair).count("lock_exit_error") == 1
    assert _events(pair).count("session_return") == 0


@pytest.mark.parametrize(
    "stage",
    (
        "path",
        "acquire",
        "entry",
        "state_read",
        "token_read",
        "checkpoint_1",
        "checkpoint_2",
        "refresh",
        "checkpoint_3",
        "state_reread",
        "token_reread",
        "checkpoint_4",
        "save",
        "checkpoint_5",
        "exit",
    ),
)
def test_cancellation_identity_and_no_later_effects(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    pair = _Scenario(expired=True)
    cancellation = _Cancellation("Synthetic owned-session cancellation")
    pair.failure_stage, pair.failure = stage, cancellation
    with _installed(monkeypatch, pair), pytest.raises(_Cancellation) as caught:
        _public(pair, _Refresher(pair))
    assert caught.value is cancellation
    assert pair.active is None
    events = _events(pair)
    failure_index = events.index("injected_failure")
    assert all(
        name not in events[failure_index + 1 :]
        for name in (
            "state_read",
            "token_read",
            "refresh",
            "save",
            "constructor",
            "session_return",
        )
    )
    assert len(pair.exit_details) == int(stage not in ("path", "acquire", "entry"))
    if pair.exit_details and stage != "exit":
        assert pair.exit_details[0][1] is cancellation


@pytest.mark.parametrize("shape", ("none", "plain", "partial"))
def test_unissued_owners_are_rejected_before_any_content(
    monkeypatch: pytest.MonkeyPatch,
    shape: str,
) -> None:
    pair = _Scenario()
    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        bad = None if shape == "none" else object()
        if shape == "partial":
            bad = object.__new__(tokens._CredentialSessionOwner)
        with pytest.raises(tokens._CredentialSessionUseError):
            tokens._load_production_write_credential_session_held(bad, scope._request)
        _no_content(pair)
        assert _events(pair).count("lock_create") == 0


@pytest.mark.parametrize("kind", ("different", "equivalent", "unpreflight", "partial"))
def test_request_substitution_does_not_consume_the_valid_owner(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    pair = _Scenario()
    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        if kind in ("different", "equivalent"):
            other = _scope(pair)
            bad_request = other._request
            if kind == "different":
                object.__setattr__(bad_request, "now", memory.SECOND_NOW)
        elif kind == "unpreflight":
            bad_request = object.__new__(tokens._CredentialSessionRequest)
        else:
            bad_request = object()
        with scope as owner:
            before = tuple(pair.trace)
            with pytest.raises(tokens._CredentialSessionUseError):
                tokens._load_production_write_credential_session_held(owner, bad_request)
            assert tuple(pair.trace) == before and pair.active is not None
            session = tokens._load_production_write_credential_session_held(owner, scope._request)
            assert type(session) is ProductionWriteCredentialSession
        assert len(pair.exit_details) == 1


@pytest.mark.parametrize("stage", ("acquire", "entry"))
def test_first_failed_entry_is_terminal_without_double_unwind(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    pair = _Scenario()
    failure = RuntimeError("Synthetic entry failure")
    pair.failure_stage, pair.failure = stage, failure
    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        with pytest.raises(RuntimeError) as caught:
            scope.__enter__()
        assert caught.value is failure
        pair.failure_stage = None
        before = tuple(pair.trace)
        with pytest.raises(tokens._CredentialSessionUseError):
            scope.__enter__()
        assert tuple(pair.trace) == before
        _no_content(pair)
        assert len(pair.exit_details) == 0 and pair.active is None


@pytest.mark.parametrize("cancel", (False, True))
def test_owner_issuance_failure_unwinds_acquired_context_once(
    monkeypatch: pytest.MonkeyPatch,
    cancel: bool,
) -> None:
    pair = _Scenario()
    failure = (
        _Cancellation("Synthetic issuance cancellation")
        if cancel
        else RuntimeError("Synthetic issuance failure")
    )

    def fail_issue(_scope: object) -> None:
        raise failure

    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        with monkeypatch.context() as isolated:
            isolated.setattr(tokens, "_issue_credential_session_owner", fail_issue)
            with pytest.raises(type(failure)) as caught:
                scope.__enter__()
        assert caught.value is failure
        assert len(pair.exit_details) == 1 and pair.exit_details[0][1] is failure
        before = tuple(pair.trace)
        with pytest.raises(tokens._CredentialSessionUseError):
            scope.__enter__()
        assert tuple(pair.trace) == before
        _no_content(pair)
        assert pair.active is None


@pytest.mark.parametrize("body_failure", (False, True))
def test_accepted_body_consumes_owner_even_when_caller_catches_failure(
    monkeypatch: pytest.MonkeyPatch,
    body_failure: bool,
) -> None:
    pair = _Scenario()
    if body_failure:
        pair.failure_stage, pair.failure = "state_read", RuntimeError("Synthetic body failure")
    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        with scope as owner:
            if body_failure:
                with pytest.raises(RuntimeError):
                    tokens._load_production_write_credential_session_held(owner, scope._request)
            else:
                result = tokens._load_production_write_credential_session_held(
                    owner, scope._request
                )
                assert type(result) is ProductionWriteCredentialSession
            before = tuple(pair.trace)
            with pytest.raises(tokens._CredentialSessionUseError):
                tokens._load_production_write_credential_session_held(owner, scope._request)
            assert tuple(pair.trace) == before and pair.active is not None
        before = tuple(pair.trace)
        with pytest.raises(tokens._CredentialSessionUseError):
            tokens._load_production_write_credential_session_held(owner, scope._request)
        assert tuple(pair.trace) == before and pair.active is None


def test_reentrant_body_and_context_entry_cannot_release_original_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair = _Scenario()
    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        with scope as owner:

            def probe() -> None:
                before = tuple(pair.trace)
                with pytest.raises(tokens._CredentialSessionUseError):
                    scope.__enter__()
                with pytest.raises(tokens._CredentialSessionUseError):
                    tokens._load_production_write_credential_session_held(owner, scope._request)
                assert tuple(pair.trace) == before and pair.active is not None

            pair.reader_probe = probe
            result = tokens._load_production_write_credential_session_held(owner, scope._request)
            assert type(result) is ProductionWriteCredentialSession
    assert _events(pair).count("state_read") == _events(pair).count("token_read") == 1
    assert len(pair.exit_details) == 1


def test_owner_is_unusable_during_exit_even_when_exit_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair = _Scenario()
    pair.exit_failure = RuntimeError("Synthetic exit failure")
    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        owner = scope.__enter__()

        def probe() -> None:
            before = tuple(pair.trace)
            with pytest.raises(tokens._CredentialSessionUseError):
                tokens._load_production_write_credential_session_held(owner, scope._request)
            assert tuple(pair.trace) == before

        pair.exit_probe = probe
        with pytest.raises(RuntimeError) as caught:
            scope.__exit__(None, None, None)
        assert caught.value is pair.exit_failure
        before = tuple(pair.trace)
        with pytest.raises(tokens._CredentialSessionUseError):
            scope.__exit__(None, None, None)
        with pytest.raises(tokens._CredentialSessionUseError):
            scope.__enter__()
        assert tuple(pair.trace) == before
        _no_content(pair)
        assert len(pair.exit_details) == 1


def test_different_thread_is_rejected_without_consuming_or_releasing_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair = _Scenario()
    outcome: list[bool] = []
    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        with scope as owner:
            before = tuple(pair.trace)

            def foreign_use() -> None:
                try:
                    tokens._load_production_write_credential_session_held(owner, scope._request)
                except tokens._CredentialSessionUseError:
                    outcome.append(True)
                except BaseException:
                    outcome.append(False)

            thread = threading.Thread(target=foreign_use)
            thread.start()
            thread.join(timeout=5)
            assert not thread.is_alive() and outcome == [True]
            assert tuple(pair.trace) == before and pair.active is not None
            result = tokens._load_production_write_credential_session_held(owner, scope._request)
            assert type(result) is ProductionWriteCredentialSession
    assert len(pair.exit_details) == 1


def test_synthetic_process_identity_mismatch_is_not_a_restart_test(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair = _Scenario()
    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        with scope as owner:
            before = tuple(pair.trace)
            original = tokens.getpid()
            with monkeypatch.context() as isolated:
                isolated.setattr(tokens, "getpid", lambda: original + 1)
                with pytest.raises(tokens._CredentialSessionUseError):
                    tokens._load_production_write_credential_session_held(owner, scope._request)
                with pytest.raises(tokens._CredentialSessionUseError):
                    scope.__exit__(None, None, None)
            assert tuple(pair.trace) == before and pair.active is not None
            result = tokens._load_production_write_credential_session_held(owner, scope._request)
            assert type(result) is ProductionWriteCredentialSession
    assert len(pair.exit_details) == 1


@pytest.mark.parametrize("kind", ("request", "scope", "owner"))
@pytest.mark.parametrize("operation", ("copy", "deepcopy", "pickle", "reinitialize"))
def test_private_ownership_material_cannot_be_duplicated_or_reinitialized(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
    operation: str,
) -> None:
    pair = _Scenario()
    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        with scope as owner:
            value = {"request": scope._request, "scope": scope, "owner": owner}[kind]
            before = tuple(pair.trace)
            with pytest.raises(tokens._CredentialSessionUseError):
                if operation == "copy":
                    copy.copy(value)
                elif operation == "deepcopy":
                    copy.deepcopy(value)
                elif operation == "pickle":
                    pickle.dumps(value)
                else:
                    type(value).__init__(value)
            assert tuple(pair.trace) == before and pair.active is not None
            result = tokens._load_production_write_credential_session_held(owner, scope._request)
            assert type(result) is ProductionWriteCredentialSession
    assert len(pair.exit_details) == 1


@pytest.mark.parametrize("kind", ("request", "scope", "owner"))
def test_direct_constructors_and_partial_contexts_do_not_issue_authority(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    pair = _Scenario()
    classes = {
        "request": tokens._CredentialSessionRequest,
        "scope": tokens._CredentialSessionScopeContext,
        "owner": tokens._CredentialSessionOwner,
    }
    with _installed(monkeypatch, pair):
        with pytest.raises(tokens._CredentialSessionUseError):
            classes[kind]()
        if kind == "scope":
            partial = object.__new__(tokens._CredentialSessionScopeContext)
            with pytest.raises(tokens._CredentialSessionUseError):
                partial.__enter__()
        _no_content(pair)
        assert _events(pair).count("path_check") == _events(pair).count("lock_create") == 0


def _function(tree: ast.Module, name: str) -> ast.FunctionDef:
    matches = [
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    assert len(matches) == 1
    return matches[0]


def _mutated_guard_source(source: str, mutation: str) -> str:
    """Change AST data only. This text is never imported, compiled or executed."""
    tree = ast.parse(source)
    loader = _function(tree, "_load_production_write_credential_session")
    held = _function(tree, "_load_production_write_credential_session_held")
    if mutation == "owner_bypass":
        blocks = [node for node in loader.body if isinstance(node, ast.With)]
        assert len(blocks) == 1
        block = blocks[0]
        loader.body[loader.body.index(block) : loader.body.index(block) + 1] = block.body
    elif mutation == "read_before_owner":
        owner_checks = [
            node
            for node in held.body
            if any(
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id == "_require_session_owner"
                for child in ast.walk(node)
            )
        ]
        assert owner_checks
        held.body.insert(
            held.body.index(owner_checks[0]),
            ast.Expr(
                value=ast.Call(
                    func=ast.Name(
                        id="load_production_write_token_generation_state", ctx=ast.Load()
                    ),
                    args=[ast.Name(id="generation_state_path", ctx=ast.Load())],
                    keywords=[],
                ),
            ),
        )
    elif mutation == "expected_token":
        saves = [
            node
            for node in ast.walk(held)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "persist_refreshed_production_write_token"
        ]
        assert len(saves) == 1
        keywords = [item for item in saves[0].keywords if item.arg == "expected_token"]
        assert len(keywords) == 1
        keywords[0].value = ast.Name(id="refreshed_token", ctx=ast.Load())
    elif mutation == "missing_reread":
        assignments = [
            node
            for node in ast.walk(held)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == "current_state"
                for target in node.targets
            )
        ]
        assert len(assignments) == 1
        assignments[0].value = ast.Name(id="state", ctx=ast.Load())
    else:
        assert mutation == "handler_cleanup"
        handlers = [
            node
            for node in ast.walk(held)
            if isinstance(node, ast.ExceptHandler)
            and any(
                isinstance(child, ast.Call)
                and isinstance(child.func, ast.Name)
                and child.func.id == "ProductionWriteTokenRefreshPersistenceError"
                for child in ast.walk(node)
            )
        ]
        assert len(handlers) == 1
        handlers[0].body.insert(
            0,
            ast.Expr(
                value=ast.Call(
                    func=ast.Name(id="synthetic_cleanup", ctx=ast.Load()),
                    args=[],
                    keywords=[],
                )
            ),
        )
    return ast.unparse(ast.fix_missing_locations(tree))


@pytest.mark.parametrize(
    "mutation",
    (
        "owner_bypass",
        "read_before_owner",
        "expected_token",
        "missing_reread",
        "handler_cleanup",
    ),
)
def test_updated_structural_guards_reject_specific_ast_data_mutations(
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    assert tokens.__file__ is not None
    token_path = Path(tokens.__file__)
    original_read = Path.read_text
    source = original_read(token_path, encoding="utf-8")
    checker = {
        "owner_bypass": (
            lock_guards.test_loader_lexically_holds_locks_over_reads_refresh_save_and_both_returns
        ),
        "read_before_owner": (
            lock_guards.test_loader_lexically_holds_locks_over_reads_refresh_save_and_both_returns
        ),
        "expected_token": (
            replace_guards.test_refresh_passes_original_input_and_has_no_legacy_save_at_call_site
        ),
        "missing_reread": prewrite_guards.test_added_recheck_only_reads_renders_compares_and_raises,
        "handler_cleanup": (
            persistence_guards.test_new_handler_has_no_retry_cleanup_or_new_mutation_capability
        ),
    }[mutation]
    checker()
    mutated = _mutated_guard_source(source, mutation)
    assert mutated != source

    def read_source(
        path: Path,
        encoding: str | None = None,
        errors: str | None = None,
    ) -> str:
        if path == token_path:
            return mutated
        return original_read(path, encoding=encoding, errors=errors)

    with monkeypatch.context() as isolated:
        isolated.setattr(Path, "read_text", read_source)
        with pytest.raises(AssertionError):
            checker()


def test_wrong_issuer_and_preentry_issuance_do_not_release_valid_owner(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair = _Scenario()
    with _installed(monkeypatch, pair):
        scope, other = _scope(pair), _scope(pair)
        before = tuple(pair.trace)
        with pytest.raises(tokens._CredentialSessionUseError):
            tokens._issue_credential_session_owner(scope)
        assert tuple(pair.trace) == before
        with scope as owner:
            before = tuple(pair.trace)
            owner._issuer = other
            try:
                with pytest.raises(tokens._CredentialSessionUseError):
                    tokens._load_production_write_credential_session_held(owner, scope._request)
            finally:
                owner._issuer = scope
            assert tuple(pair.trace) == before and pair.active is not None
            result = tokens._load_production_write_credential_session_held(owner, scope._request)
            assert type(result) is ProductionWriteCredentialSession
    assert len(pair.exit_details) == 1


@pytest.mark.parametrize("kind", ("request", "scope", "owner"))
def test_reconstructed_private_fields_cannot_duplicate_issued_identity(
    monkeypatch: pytest.MonkeyPatch,
    kind: str,
) -> None:
    pair = _Scenario()
    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        with scope as owner:
            original = {"request": scope._request, "scope": scope, "owner": owner}[kind]
            forged = object.__new__(type(original))
            for field in type(original).__slots__:
                object.__setattr__(forged, field, getattr(original, field))
            before = tuple(pair.trace)
            with pytest.raises(tokens._CredentialSessionUseError):
                if kind == "scope":
                    forged.__enter__()
                else:
                    tokens._load_production_write_credential_session_held(
                        forged if kind == "owner" else owner,
                        forged if kind == "request" else scope._request,
                    )
            assert tuple(pair.trace) == before and pair.active is not None
            result = tokens._load_production_write_credential_session_held(owner, scope._request)
            assert type(result) is ProductionWriteCredentialSession
    assert len(pair.exit_details) == 1


@pytest.mark.parametrize(
    "field",
    (
        "production_write_token_path",
        "generation_state_path",
        "production_read_token_path",
        "test_write_token_path",
        "target",
        "now",
        "evidence_mode",
        "refresher",
    ),
)
def test_all_eight_retained_inputs_are_checked_by_identity_before_content(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    pair = _Scenario()
    with _installed(monkeypatch, pair):
        scope = _scope(pair, _Refresher(pair))
        with scope as owner:
            request = scope._request
            value = getattr(request, field)
            before = tuple(pair.trace)
            object.__setattr__(request, field, object())
            try:
                with pytest.raises(tokens._CredentialSessionUseError):
                    tokens._load_production_write_credential_session_held(owner, request)
            finally:
                object.__setattr__(request, field, value)
            assert tuple(pair.trace) == before and pair.active is not None
            result = tokens._load_production_write_credential_session_held(owner, request)
            assert type(result) is ProductionWriteCredentialSession
    assert len(pair.exit_details) == 1


def test_request_drift_is_rechecked_before_delegating_native_checkpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair = _Scenario()
    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        request = scope._request
        old_now = request.now

        def drift() -> None:
            object.__setattr__(request, "now", memory.SECOND_NOW)

        pair.reader_probe = drift
        with scope as owner:
            try:
                with pytest.raises(tokens._CredentialSessionUseError):
                    tokens._load_production_write_credential_session_held(owner, request)
            finally:
                object.__setattr__(request, "now", old_now)
            before = tuple(pair.trace)
            with pytest.raises(tokens._CredentialSessionUseError):
                tokens._load_production_write_credential_session_held(owner, request)
            assert tuple(pair.trace) == before
        assert _events(pair).count("state_read") == _events(pair).count("token_read") == 1
        assert _events(pair).count("checkpoint") == 0
        assert all(
            _events(pair).count(name) == 0
            for name in ("refresh", "save", "constructor", "session_return")
        )


def test_private_representations_and_misuse_messages_are_fixed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair = _Scenario()
    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        with scope as owner:
            for value in (scope, owner, scope._request):
                assert repr(value) == "<private credential-session ownership>"
            with pytest.raises(tokens._CredentialSessionUseError) as caught:
                tokens._load_production_write_credential_session_held(owner, object())
            assert str(caught.value) == "Invalid credential-session ownership"
            _no_content(pair)


def test_delayed_io_aliases_are_captured_before_entry_and_not_switched_mid_body(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair = _Scenario(expired=True)

    def forbidden_reader(_path: str | Path) -> None:
        raise _Cancellation("Unexpected replacement reader")

    with _installed(monkeypatch, pair), monkeypatch.context() as isolated:

        def replace_after_first_read() -> None:
            isolated.setattr(
                token_io, "load_production_write_token_generation_state", forbidden_reader
            )
            isolated.setattr(
                token_io, "load_production_write_authorized_user_token", forbidden_reader
            )

        pair.reader_probe = replace_after_first_read
        result = _public(pair, _Refresher(pair))
    assert type(result) is ProductionWriteCredentialSession
    assert _events(pair).count("state_read") == _events(pair).count("token_read") == 2
    assert _events(pair).count("checkpoint") == 5


@pytest.mark.parametrize("cancel", (False, True))
def test_unexpected_initial_identity_check_failure_is_terminal(
    monkeypatch: pytest.MonkeyPatch,
    cancel: bool,
) -> None:
    pair = _Scenario()
    failure = (
        _Cancellation("Synthetic initial identity cancellation")
        if cancel
        else RuntimeError("Synthetic initial identity failure")
    )

    def unavailable_identity() -> int:
        raise failure

    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        with monkeypatch.context() as isolated:
            isolated.setattr(tokens, "getpid", unavailable_identity)
            with pytest.raises(type(failure)) as caught:
                scope.__enter__()
        assert caught.value is failure
        before = tuple(pair.trace)
        with pytest.raises(tokens._CredentialSessionUseError):
            scope.__enter__()
        assert tuple(pair.trace) == before
        _no_content(pair)
        assert _events(pair).count("lock_create") == 0
        assert len(pair.exit_details) == 0


@pytest.mark.parametrize("used", (False, True))
@pytest.mark.parametrize("cancel", (False, True))
def test_unexpected_exit_identity_failure_revokes_and_releases_once(
    monkeypatch: pytest.MonkeyPatch,
    used: bool,
    cancel: bool,
) -> None:
    pair = _Scenario()
    failure = (
        _Cancellation("Synthetic exit identity cancellation")
        if cancel
        else RuntimeError("Synthetic exit identity failure")
    )

    def unavailable_identity() -> int:
        raise failure

    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        owner = scope.__enter__()
        if used:
            result = tokens._load_production_write_credential_session_held(owner, scope._request)
            assert type(result) is ProductionWriteCredentialSession
        with monkeypatch.context() as isolated:
            isolated.setattr(tokens, "getpid", unavailable_identity)
            with pytest.raises(type(failure)) as caught:
                scope.__exit__(None, None, None)
        assert caught.value is failure
        assert pair.active is None
        assert pair.exit_details == [(None, None, None)]
        before = tuple(pair.trace)
        with pytest.raises(tokens._CredentialSessionUseError):
            tokens._load_production_write_credential_session_held(owner, scope._request)
        with pytest.raises(tokens._CredentialSessionUseError):
            scope.__exit__(None, None, None)
        with pytest.raises(tokens._CredentialSessionUseError):
            scope.__enter__()
        assert tuple(pair.trace) == before
        assert _events(pair).count("state_read") == _events(pair).count("token_read") == int(used)
        assert _events(pair).count("checkpoint") == 2 * int(used)
        assert _events(pair).count("constructor") == int(used)
        assert _events(pair).count("lock_exit_normal") == 1
        assert all(_events(pair).count(name) == 0 for name in ("refresh", "save", "session_return"))


def test_exit_identity_failure_delegates_the_original_body_exception_triple(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pair = _Scenario()
    body = RuntimeError("Synthetic original body failure")
    identity_failure = RuntimeError("Synthetic exit identity failure")
    try:
        raise body
    except RuntimeError as caught_body:
        original_traceback = caught_body.__traceback__
    assert original_traceback is not None

    def unavailable_identity() -> int:
        raise identity_failure

    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        scope.__enter__()
        with monkeypatch.context() as isolated:
            isolated.setattr(tokens, "getpid", unavailable_identity)
            with pytest.raises(RuntimeError) as caught:
                scope.__exit__(type(body), body, original_traceback)
        assert caught.value is identity_failure
        assert len(pair.exit_details) == 1
        kind, error, traceback = pair.exit_details[0]
        assert kind is type(body) and error is body and traceback is original_traceback
        assert pair.active is None
        _no_content(pair)


@pytest.mark.parametrize("cleanup_cancel", (False, True))
def test_exit_backend_failure_keeps_precedence_over_local_identity_failure(
    monkeypatch: pytest.MonkeyPatch,
    cleanup_cancel: bool,
) -> None:
    pair = _Scenario()
    identity_failure = RuntimeError("Synthetic exit identity failure")
    cleanup = (
        _Cancellation("Synthetic cleanup cancellation")
        if cleanup_cancel
        else RuntimeError("Synthetic cleanup failure")
    )
    pair.exit_failure = cleanup

    def unavailable_identity() -> int:
        raise identity_failure

    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        scope.__enter__()
        with monkeypatch.context() as isolated:
            isolated.setattr(tokens, "getpid", unavailable_identity)
            with pytest.raises(type(cleanup)) as caught:
                scope.__exit__(None, None, None)
        assert caught.value is cleanup and caught.value.__context__ is identity_failure
        assert pair.exit_details == [(None, None, None)]
        assert pair.active is None
        before = tuple(pair.trace)
        with pytest.raises(tokens._CredentialSessionUseError):
            scope.__exit__(None, None, None)
        assert tuple(pair.trace) == before
        _no_content(pair)


@pytest.mark.parametrize("foreign_actor", ("thread", "synthetic_process"))
def test_foreign_actor_cannot_release_via_a_failing_global_identity_probe(
    monkeypatch: pytest.MonkeyPatch,
    foreign_actor: str,
) -> None:
    pair = _Scenario()
    identity_failure = RuntimeError("Synthetic global identity failure")
    outcomes: list[bool] = []

    def unavailable_identity() -> int:
        raise identity_failure

    with _installed(monkeypatch, pair):
        scope = _scope(pair)
        with scope as owner:
            before = tuple(pair.trace)
            with monkeypatch.context() as isolated:
                isolated.setattr(tokens, "getpid", unavailable_identity)
                if foreign_actor == "synthetic_process":
                    # A test-only identity witness mismatch, never a fork/restart.
                    isolated.setattr(scope, "_pid_probe", lambda: scope._pid + 1)
                    with pytest.raises(tokens._CredentialSessionUseError):
                        scope.__exit__(None, None, None)
                else:

                    def foreign_exit() -> None:
                        try:
                            scope.__exit__(None, None, None)
                        except tokens._CredentialSessionUseError:
                            outcomes.append(True)
                        except BaseException:
                            outcomes.append(False)

                    thread = threading.Thread(target=foreign_exit)
                    thread.start()
                    thread.join(timeout=5)
                    assert not thread.is_alive() and outcomes == [True]
            assert tuple(pair.trace) == before and pair.active is not None
            assert len(pair.exit_details) == 0
            result = tokens._load_production_write_credential_session_held(owner, scope._request)
            assert type(result) is ProductionWriteCredentialSession
        assert len(pair.exit_details) == 1 and pair.active is None


class _HeldTransitionInjection:
    """Inject once in the actual held frame, without changing ownership fields."""

    def __init__(self, pair: _Scenario, stage: str, failure: BaseException) -> None:
        assert stage in ("before_used", "after_busy")
        self.pair = pair
        self.stage = stage
        self.failure = failure
        self.code = tokens._load_production_write_credential_session_held.__code__
        self.scope: tokens._CredentialSessionScopeContext | None = None
        self.owner: tokens._CredentialSessionOwner | None = None
        self.injections = 0
        self.line: int | None = None
        self.used_at_injection: bool | None = None
        self.busy_at_injection: bool | None = None

    def __call__(
        self, frame: FrameType, event: str, _argument: object
    ) -> _HeldTransitionInjection | None:
        if frame.f_code is not self.code:
            return None
        if event != "line" or self.injections:
            return self
        # Read only the issued scope; do not retain frames or copy their locals.
        scope = frame.f_locals.get("scope")
        if type(scope) is not tokens._CredentialSessionScopeContext:
            return self
        matched = (
            scope._used is False and scope._busy is False
            if self.stage == "before_used"
            else scope._used is True and scope._busy is True
        )
        if not matched:
            return self
        assert scope._phase is tokens._CredentialSessionPhase.ACTIVE
        assert type(scope._owner) is tokens._CredentialSessionOwner
        assert scope._owner._issuer is scope
        assert self.pair.active is not None
        assert _events(self.pair).count("lock_enter") == 1
        assert _events(self.pair).count("checkpoint") == 0
        _no_content(self.pair)
        self.scope = scope
        self.owner = scope._owner
        self.line = frame.f_lineno
        self.used_at_injection = scope._used
        self.busy_at_injection = scope._busy
        self.injections += 1
        raise self.failure


@pytest.mark.parametrize("stage", ("before_used", "after_busy"))
@pytest.mark.parametrize("cancel", (False, True))
def test_busy_transition_interruption_preserves_identity_and_terminal_cleanup(
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    cancel: bool,
    record_property: Callable[[str, object], None],
) -> None:
    pair = _Scenario()
    failure = (
        _Cancellation("Synthetic busy-transition cancellation")
        if cancel
        else RuntimeError("Synthetic busy-transition failure")
    )
    injection = _HeldTransitionInjection(pair, stage, failure)
    outer: BaseException | None = None
    with _installed(monkeypatch, pair):
        previous_trace = sys.gettrace()
        if previous_trace is not None:
            pytest.fail("Busy-transition test requires an inactive trace")
        try:
            sys.settrace(injection)
            try:
                _public(pair)
            except BaseException as caught:
                outer = caught
        finally:
            # Raising from a trace callback disables tracing; restore explicitly.
            sys.settrace(previous_trace)
        trace_restored = sys.gettrace() is previous_trace
        scope, owner = injection.scope, injection.owner
        events = _events(pair)
        outer_classification = (
            "ORIGINAL"
            if outer is failure
            else (
                "OWNERSHIP_REFUSAL"
                if type(outer) is tokens._CredentialSessionUseError
                else "UNEXPECTED"
            )
        )
        # Record fixed evidence before assertions, including the intended RED.
        record_property(
            "busy_transition_evidence",
            {
                "scope": "MEMORY_ONLY",
                "stage": stage,
                "kind": "CANCELLATION" if cancel else "ORDINARY",
                "injections": injection.injections,
                "line": injection.line,
                "used_at_injection": injection.used_at_injection,
                "busy_at_injection": injection.busy_at_injection,
                "outer_classification": outer_classification,
                "original_identity": outer is failure,
                "lock_entries": events.count("lock_enter"),
                "lock_exits": len(pair.exit_details),
                "lock_held": pair.active is not None,
                "phase": "NOT_OBSERVED" if scope is None else scope._phase.name,
                "busy": None if scope is None else scope._busy,
                "used": None if scope is None else scope._used,
                "effects": {
                    name: events.count(name)
                    for name in (
                        "state_read",
                        "token_read",
                        "refresh",
                        "save",
                        "constructor",
                        "session_return",
                        "checkpoint",
                    )
                },
                "trace_restored": trace_restored,
                "native_ownership_measured": False,
            },
        )
        assert trace_restored
        assert injection.injections == 1 and injection.line is not None
        assert injection.used_at_injection is (stage == "after_busy")
        assert injection.busy_at_injection is (stage == "after_busy")
        assert scope is not None and owner is not None
        assert outer is failure
        assert events.count("lock_enter") == 1
        assert len(pair.exit_details) == 1
        assert pair.exit_details[0][0] is type(failure)
        assert pair.exit_details[0][1] is failure
        assert pair.exit_details[0][2] is not None
        assert pair.active is None
        assert scope._phase is tokens._CredentialSessionPhase.CLOSED
        assert scope._busy is False
        assert scope._used is (stage == "after_busy")
        assert events.count("checkpoint") == 0
        _no_content(pair)

        # Only after tracing is restored, probe terminal owner/context refusal.
        before_reuse = tuple(pair.trace)
        with pytest.raises(tokens._CredentialSessionUseError):
            tokens._load_production_write_credential_session_held(owner, scope._request)
        with pytest.raises(tokens._CredentialSessionUseError):
            scope.__enter__()
        with pytest.raises(tokens._CredentialSessionUseError):
            scope.__exit__(None, None, None)
        assert tuple(pair.trace) == before_reuse
        assert len(pair.exit_details) == 1 and pair.active is None
        assert sys.gettrace() is previous_trace
