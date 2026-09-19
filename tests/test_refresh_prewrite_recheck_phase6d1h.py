"""Synthetic pre-save content recheck; not conditional replacement or recovery approval."""

from __future__ import annotations

import ast
import errno
import os
import traceback
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from phase6d0_auth_helpers import (
    ISSUED_AT,
    FakeRefresher,
    artifact_paths,
    oauth_credentials,
    production_target,
    production_token,
)

from tridentine_calendar_google_sync import production_write_token as tokens
from tridentine_calendar_google_sync import production_write_token_io as token_io
from tridentine_calendar_google_sync import production_write_token_rehearsal as rehearsal
from tridentine_calendar_google_sync import sensitive_paths
from tridentine_calendar_google_sync.production_write_token_models import (
    ProductionWriteGrantEvidenceOrigin,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_models import (
    ProductionWriteTokenRehearsalResultState,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_report import (
    render_production_write_token_rehearsal_report_json,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_transport import (
    FakeProductionWriteCredentialSessionProvider,
    FakeProductionWriteTokenReadOnlyTransport,
    FakeProductionWriteTokenReadOnlyTransportProvider,
)

NOW = ISSUED_AT + timedelta(seconds=2)
CODE = "production_write_token_refresh_prewrite_unverified"


def _stored(tmp_path: Path, *, expired: bool = True) -> tuple[Any, Any, Any, dict[str, Path]]:
    root = tmp_path / "private-refresh-recheck"
    root.mkdir(mode=0o700)
    paths = artifact_paths(root)
    target = production_target()
    state = tokens.build_initial_production_write_token_generation_state(
        target, issued_at=ISSUED_AT
    )
    expiry = ISSUED_AT + (timedelta(seconds=1) if expired else timedelta(hours=1))
    token = production_token(state, expiry=expiry)
    token_io.write_production_write_token_bundle(token, paths["write"], state, paths["generation"])
    return target, state, token, paths


def _refresher() -> FakeRefresher:
    return FakeRefresher(
        oauth_credentials(
            expiry=NOW + timedelta(hours=1),
            evidence_origin=ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
            evidence_observed_at=NOW,
            access_token="UNIT4J_PRIVATE_NEW_ACCESS",
            refresh_token="UNIT4J_PRIVATE_NEW_REFRESH",
        )
    )


def _prepare(target: Any, paths: dict[str, Path], refresher: FakeRefresher) -> Any:
    return tokens.prepare_production_write_rehearsal_credential_session_mock(
        paths["write"],
        paths["generation"],
        paths["read"],
        paths["test"],
        target,
        rehearsal.production_write_token_rehearsal_challenge(target),
        now=NOW,
        refresher=refresher,
    )


def _forbidden(*_args: Any, **_kwargs: Any) -> Any:
    raise AssertionError("unexpected save, retry, cleanup, session or transport")


def _safe(error: Any, root: Path) -> None:
    assert isinstance(error, tokens.ProductionWriteTokenRefreshError)
    assert not isinstance(error, tokens.ProductionWriteTokenRefreshPersistenceError)
    assert error.code == CODE
    assert error.refresh_completed is True and error.persistence_attempted is False
    assert error.publication_possible is False
    assert error.__cause__ is None and error.__suppress_context__
    rendered = "".join(traceback.format_exception(error))
    for marker in (
        str(root),
        "PRIVATE_OS_MARKER",
        "UNIT4J_PRIVATE_NEW_ACCESS",
        "UNIT4J_PRIVATE_NEW_REFRESH",
        "PRIVATE_CHANGED_ACCESS",
    ):
        assert marker not in rendered
    assert "do not retry, remove, or restore files automatically" in str(error)


@pytest.mark.parametrize("role", ("token", "state"))
@pytest.mark.parametrize("mutation", ("changed", "malformed", "missing"))
def test_changed_or_unreadable_during_refresh_stops_before_save_and_preserves_current_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str, mutation: str
) -> None:
    target, _state, token, paths = _stored(tmp_path)
    refresher = _refresher()
    native_refresh = refresher.refresh
    after: dict[str, bytes | None] = {}

    def refresh(*args: Any, **kwargs: Any) -> Any:
        result = native_refresh(*args, **kwargs)
        path = paths["write" if role == "token" else "generation"]
        if mutation == "missing":
            path.unlink()  # This synthetic competitor, never the code under test.
        elif mutation == "malformed":
            path.write_bytes(b"{PRIVATE_OS_MARKER")
        elif role == "token":
            altered = token.model_copy(update={"access_token": "PRIVATE_CHANGED_ACCESS"})
            path.write_text(
                token_io.render_production_write_authorized_user_token_json(altered),
                encoding="utf-8",
                newline="\n",
            )
        else:
            altered = tokens.build_initial_production_write_token_generation_state(
                target, issued_at=ISSUED_AT + timedelta(seconds=1)
            )
            path.write_text(
                token_io.render_production_write_token_generation_state_json(altered),
                encoding="utf-8",
                newline="\n",
            )
        for name in ("write", "generation"):
            p = paths[name]
            after[name] = p.read_bytes() if p.exists() else None
        return result

    monkeypatch.setattr(refresher, "refresh", refresh)
    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", _forbidden)
    monkeypatch.setattr(token_io, "_remove_exact_new_artifact", _forbidden)
    monkeypatch.setattr(tokens, "ProductionWriteCredentialSession", _forbidden)
    with pytest.raises(tokens.ProductionWriteTokenRefreshPrewriteError) as caught:
        _prepare(target, paths, refresher)
    _safe(caught.value, paths["write"].parent)
    assert refresher.calls == 1 and refresher.calendar_api_call_count == 0
    assert refresher.browser_fallback_count == 0
    for name in ("write", "generation"):
        p = paths[name]
        assert (p.read_bytes() if p.exists() else None) == after[name]


@pytest.mark.parametrize("role", ("token", "state"))
@pytest.mark.parametrize("failure", ("oserror", "parser", "unsafe"))
def test_reread_errors_are_suppressed_without_writer_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str, failure: str
) -> None:
    target, _state, _token, paths = _stored(tmp_path)
    name = (
        "load_production_write_authorized_user_token"
        if role == "token"
        else "load_production_write_token_generation_state"
    )
    native = getattr(token_io, name)
    calls: list[int] = []

    def load(path: Path) -> Any:
        calls.append(1)
        if len(calls) == 1:
            return native(path)
        if failure == "oserror":
            raise OSError(errno.EACCES, "PRIVATE_OS_MARKER", str(path))
        if failure == "parser":
            raise token_io.ProductionWriteTokenIOError("synthetic", "PRIVATE_OS_MARKER")
        raise sensitive_paths.SensitivePathError("synthetic", "PRIVATE_OS_MARKER")

    monkeypatch.setattr(token_io, name, load)
    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", _forbidden)
    refresher = _refresher()
    with pytest.raises(tokens.ProductionWriteTokenRefreshPrewriteError) as caught:
        _prepare(target, paths, refresher)
    _safe(caught.value, paths["write"].parent)
    assert len(calls) == 2 and refresher.calls == 1


def test_success_order_is_initial_pair_refresh_reloaded_pair_one_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, state, _token, paths = _stored(tmp_path)
    calls: list[str] = []
    for name, label in (
        ("load_production_write_authorized_user_token", "token"),
        ("load_production_write_token_generation_state", "state"),
        ("persist_refreshed_production_write_token", "save"),
    ):
        native = getattr(token_io, name)

        def recorded(*args: Any, _native: Any = native, _label: str = label, **kwargs: Any) -> Any:
            calls.append(_label)
            if _label == "save":
                assert kwargs == {"expected_token": _token}
            return _native(*args, **kwargs)

        monkeypatch.setattr(token_io, name, recorded)
    refresher = _refresher()
    native_refresh = refresher.refresh

    def refreshed(*args: Any, **kwargs: Any) -> Any:
        calls.append("refresh")
        return native_refresh(*args, **kwargs)

    monkeypatch.setattr(refresher, "refresh", refreshed)
    session = _prepare(target, paths, refresher)
    assert calls == ["state", "token", "refresh", "state", "token", "save"]
    assert session.refresh_count == 1 and session.generation_state == state
    assert session.token.access_token == "UNIT4J_PRIVATE_NEW_ACCESS"


def test_unexpired_token_does_not_reread_refresh_or_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, _state, token, paths = _stored(tmp_path, expired=False)
    calls: list[str] = []
    for name in (
        "load_production_write_authorized_user_token",
        "load_production_write_token_generation_state",
    ):
        native = getattr(token_io, name)

        def once(path: Path, _native: Any = native, _name: str = name) -> Any:
            assert _name not in calls
            calls.append(_name)
            return _native(path)

        monkeypatch.setattr(token_io, name, once)
    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", _forbidden)
    refresher = _refresher()
    session = _prepare(target, paths, refresher)
    assert session.token == token and refresher.calls == 0 and len(calls) == 2


@pytest.mark.parametrize("failure", ("request", "scope", "identity", "expiry"))
def test_invalid_refresh_does_not_enter_recheck_or_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    target, _state, _token, paths = _stored(tmp_path)
    for name in (
        "load_production_write_authorized_user_token",
        "load_production_write_token_generation_state",
    ):
        native = getattr(token_io, name)
        seen: list[int] = []

        def once(path: Path, _native: Any = native, _seen: list[int] = seen) -> Any:
            assert not _seen
            _seen.append(1)
            return _native(path)

        monkeypatch.setattr(token_io, name, once)
    refresher = _refresher()
    if failure == "request":
        refresher.fail = True
    else:
        assert refresher.credentials is not None
        updates = {
            "scope": {"scopes": ()},
            "identity": {"client_id": "other.example.invalid"},
            "expiry": {"expiry": NOW},
        }
        refresher.credentials = refresher.credentials.model_copy(update=updates[failure])
    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", _forbidden)
    with pytest.raises(tokens.ProductionWriteTokenError) as caught:
        _prepare(target, paths, refresher)
    assert not isinstance(caught.value, tokens.ProductionWriteTokenRefreshPrewriteError)
    assert refresher.calls == 1


@pytest.mark.parametrize("role", ("token", "state"))
def test_cancel_during_reread_is_not_an_ordinary_prewrite_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    target, _state, _token, paths = _stored(tmp_path)
    name = (
        "load_production_write_authorized_user_token"
        if role == "token"
        else "load_production_write_token_generation_state"
    )
    native = getattr(token_io, name)
    calls: list[int] = []

    def load(path: Path) -> Any:
        calls.append(1)
        if len(calls) == 1:
            return native(path)
        raise KeyboardInterrupt

    monkeypatch.setattr(token_io, name, load)
    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", _forbidden)
    with pytest.raises(KeyboardInterrupt):
        _prepare(target, paths, _refresher())


def test_mock_rehearsal_stops_before_calendar_and_keeps_report_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, _state, _token, paths = _stored(tmp_path)
    refresher = _refresher()
    native_refresh = refresher.refresh

    def changed(*args: Any, **kwargs: Any) -> Any:
        value = native_refresh(*args, **kwargs)
        paths["generation"].write_bytes(b"PRIVATE_OS_MARKER")
        return value

    monkeypatch.setattr(refresher, "refresh", changed)
    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", _forbidden)
    with pytest.raises(tokens.ProductionWriteTokenRefreshPrewriteError) as caught:
        _prepare(target, paths, refresher)
    provider = FakeProductionWriteCredentialSessionProvider(caught.value, refresh_attempt_count=1)
    transport = FakeProductionWriteTokenReadOnlyTransport(collections=(), get_events=())
    transport_provider = FakeProductionWriteTokenReadOnlyTransportProvider(transport)
    outcome = rehearsal.run_production_write_token_readonly_rehearsal_mock(
        credential_session_provider=provider,
        transport_provider=transport_provider,
        target=target,
        manifest=None,
        accepted_profile=None,
        accepted_source=None,
        trusted_baseline=None,
        confirmation=rehearsal.production_write_token_rehearsal_challenge(target),
    )
    assert (
        outcome.report.result_state is ProductionWriteTokenRehearsalResultState.TOKEN_REFRESH_FAILED
    )
    assert outcome.report.token_refresh_count == 1 and outcome.report.calendar_api_call_count == 0
    assert (
        transport_provider.build_count == 0
        and transport.call_log == ()
        and outcome.snapshot is None
    )
    rendered = render_production_write_token_rehearsal_report_json(outcome.report)
    assert (
        CODE in rendered
        and "publication_possible" not in rendered
        and "PRIVATE_OS_MARKER" not in rendered
    )


@pytest.mark.skipif(os.name != "posix", reason="real POSIX use-time permission recheck")
@pytest.mark.parametrize("role", ("token", "state"))
def test_posix_permissions_widened_during_refresh_refused_without_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    target, _state, _token, paths = _stored(tmp_path)
    path = paths["write" if role == "token" else "generation"]
    refresher = _refresher()
    native = refresher.refresh

    def change(*args: Any, **kwargs: Any) -> Any:
        result = native(*args, **kwargs)
        path.chmod(0o640)  # Synthetic fixture only.
        return result

    monkeypatch.setattr(refresher, "refresh", change)
    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", _forbidden)
    with pytest.raises(tokens.ProductionWriteTokenRefreshPrewriteError) as caught:
        _prepare(target, paths, refresher)
    _safe(caught.value, path.parent)
    assert path.stat().st_mode & 0o777 == 0o640


def test_identical_content_rewritten_during_refresh_is_not_claimed_as_identity_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, _state, _token, paths = _stored(tmp_path)
    refresher = _refresher()
    native = refresher.refresh

    def rewrite(*args: Any, **kwargs: Any) -> Any:
        result = native(*args, **kwargs)
        for name in ("write", "generation"):
            raw = paths[name].read_bytes()
            paths[name].write_bytes(raw)
        return result

    monkeypatch.setattr(refresher, "refresh", rewrite)
    assert _prepare(target, paths, refresher).refresh_count == 1


def test_added_recheck_only_reads_renders_compares_and_raises() -> None:
    tree = ast.parse(Path(tokens.__file__).read_text(encoding="utf-8"))
    fn = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_load_production_write_credential_session"
    )
    guarded = [n for n in fn.body if isinstance(n, ast.With)]
    assert len(guarded) == 1
    guard = guarded[0].items[0].context_expr
    assert isinstance(guard, ast.Call) and isinstance(guard.func, ast.Name)
    assert guard.func.id == "_production_write_session_lock"
    body = guarded[0].body
    blocks = [
        n
        for n in body
        if isinstance(n, ast.Try)
        and any(
            isinstance(c, ast.Call)
            and isinstance(c.func, ast.Name)
            and c.func.id == "ProductionWriteTokenRefreshPrewriteError"
            for c in ast.walk(n)
        )
    ]
    assert len(blocks) == 1
    block = blocks[0]
    assert len(block.handlers) == 1 and isinstance(block.handlers[0].type, ast.Name)
    assert block.handlers[0].type.id == "Exception"
    names = {
        n.func.id
        for n in ast.walk(block)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert names == {
        "load_production_write_token_generation_state",
        "load_production_write_authorized_user_token",
        "render_production_write_token_generation_state_json",
        "render_production_write_authorized_user_token_json",
        "ProductionWriteTokenRefreshPrewriteError",
    }
    attrs = {
        n.func.attr
        for n in ast.walk(block)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert attrs == {"encode", "compare_digest"}
    assert not any(isinstance(n, (ast.For, ast.While)) for n in ast.walk(block))
    assert block.lineno < next(
        n.lineno
        for n in body
        if isinstance(n, ast.Try)
        and any(
            isinstance(c, ast.Call)
            and isinstance(c.func, ast.Name)
            and c.func.id == "persist_refreshed_production_write_token"
            for c in ast.walk(ast.Module(body=n.body, type_ignores=[]))
        )
    )
