"""Synthetic refresh persistence evidence; not replacement or recovery approval."""

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
ERROR_CODE = "production_write_token_refresh_persistence_failed"


def _stored(tmp_path: Path, *, expired: bool = True) -> tuple[Any, Any, Any, dict[str, Path]]:
    root = tmp_path / "private-refresh"
    root.mkdir(mode=0o700)
    paths = artifact_paths(root)
    target = production_target()
    state = tokens.build_initial_production_write_token_generation_state(
        target, issued_at=ISSUED_AT
    )
    token = production_token(
        state, expiry=ISSUED_AT + (timedelta(seconds=1) if expired else timedelta(hours=1))
    )
    token_io.write_production_write_token_bundle(token, paths["write"], state, paths["generation"])
    return target, state, token, paths


def _refresher() -> FakeRefresher:
    return FakeRefresher(
        oauth_credentials(
            expiry=NOW + timedelta(hours=1),
            evidence_origin=ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
            evidence_observed_at=NOW,
            access_token="UNIT4I_PRIVATE_NEW_ACCESS",
            refresh_token="UNIT4I_PRIVATE_NEW_REFRESH",
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
    raise AssertionError("unexpected retry, cleanup, session creation or transport")


def _assert_safe(error: BaseException, root: Path) -> None:
    assert error.__cause__ is None and error.__suppress_context__
    rendered = "".join(traceback.format_exception(error))
    for marker in (
        str(root),
        "PRIVATE_OS_MARKER",
        "UNIT4I_PRIVATE_NEW_ACCESS",
        "UNIT4I_PRIVATE_NEW_REFRESH",
    ):
        assert marker not in rendered
    assert "do not retry or remove files automatically" in str(error)


@pytest.mark.parametrize(
    "evidence",
    (False, True, None, 0, 1, "invalid", "oserror"),
    ids=("before", "after", "unknown", "int-zero", "int-one", "invalid", "oserror"),
)
@pytest.mark.parametrize("output", ("old", "new", "competitor"))
def test_persistence_exception_preserves_evidence_without_session_retry_or_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, evidence: Any, output: str
) -> None:
    target, _state, _token, paths = _stored(tmp_path)
    state_before = paths["generation"].read_bytes()
    token_before = paths["write"].read_bytes()
    refresher = _refresher()
    calls: list[int] = []
    retained: list[bytes] = []

    def failed(token: Any, path: Path, *, expected_token: Any) -> Path:
        assert path == paths["write"] and expected_token == _token
        calls.append(1)
        content = (
            token_before
            if output == "old"
            else (
                token_io.render_production_write_authorized_user_token_json(token).encode()
                if output == "new"
                else b"unrelated competitor output"
            )
        )
        if output != "old":
            path.write_bytes(content)  # Only this synthetic fixture; no production files.
        retained.append(content)
        if evidence == "oserror":
            raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(path))
        raise token_io.ProductionWriteTokenIOError(
            "PRIVATE_OS_MARKER", "PRIVATE_OS_MARKER", publication_possible=evidence
        )

    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", failed)
    monkeypatch.setattr(token_io, "_remove_exact_new_artifact", _forbidden)
    monkeypatch.setattr(tokens, "ProductionWriteCredentialSession", _forbidden)
    with pytest.raises(tokens.ProductionWriteTokenRefreshPersistenceError) as caught:
        _prepare(target, paths, refresher)
    error = caught.value
    assert isinstance(error, tokens.ProductionWriteTokenRefreshError)
    assert error.code == ERROR_CODE
    assert error.refresh_completed is True and error.persistence_attempted is True
    assert error.publication_possible is (evidence if type(evidence) is bool else None)
    assert calls == [1] and refresher.calls == 1
    assert refresher.calendar_api_call_count == 0 and refresher.browser_fallback_count == 0
    assert paths["write"].read_bytes() == retained[0]
    assert paths["generation"].read_bytes() == state_before
    _assert_safe(error, paths["write"].parent)


@pytest.mark.skipif(os.name != "nt", reason="Windows retained legacy refresh writer")
@pytest.mark.parametrize(
    "after_write", (False, True), ids=("before-replacement", "after-replacement")
)
def test_windows_legacy_writer_failure_stays_unknown_and_preserves_old_or_new_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_write: bool
) -> None:
    target, _state, old_token, paths = _stored(tmp_path)
    state_before = paths["generation"].read_bytes()
    native_writer = token_io.atomic_write_private_text
    calls: list[int] = []

    def failed(*args: Any, **kwargs: Any) -> None:
        assert kwargs["overwrite"] is True
        assert kwargs["windows_require_existing_protected_acl"] is True
        calls.append(1)
        if after_write:
            native_writer(*args, **kwargs)
        raise sensitive_paths.SensitivePathError("synthetic", "PRIVATE_OS_MARKER")

    monkeypatch.setattr(token_io, "atomic_write_private_text", failed)
    refresher = _refresher()
    with pytest.raises(tokens.ProductionWriteTokenRefreshPersistenceError) as caught:
        _prepare(target, paths, refresher)
    error = caught.value
    assert error.publication_possible is None
    assert calls == [1] and refresher.calls == 1
    stored = token_io.load_production_write_authorized_user_token(paths["write"])
    assert stored.access_token == (
        "UNIT4I_PRIVATE_NEW_ACCESS" if after_write else old_token.access_token
    )
    assert paths["generation"].read_bytes() == state_before
    _assert_safe(error, paths["write"].parent)


def test_success_still_returns_one_session_after_one_persistence_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, state, old_token, paths = _stored(tmp_path)
    state_before = paths["generation"].read_bytes()
    native_writer = token_io.persist_refreshed_production_write_token
    calls: list[int] = []

    def writer(*args: Any, **kwargs: Any) -> Path:
        assert kwargs == {"expected_token": old_token}
        calls.append(1)
        return native_writer(*args, **kwargs)

    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", writer)
    refresher = _refresher()
    session = _prepare(target, paths, refresher)
    assert calls == [1] and refresher.calls == session.refresh_count == 1
    assert session.generation_state == state
    assert session.token.access_token != old_token.access_token
    assert paths["generation"].read_bytes() == state_before
    assert token_io.load_production_write_authorized_user_token(paths["write"]) == session.token


def test_unexpired_token_never_calls_refresher_or_persistence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, _state, token, paths = _stored(tmp_path, expired=False)
    refresher = _refresher()
    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", _forbidden)
    session = _prepare(target, paths, refresher)
    assert session.token == token and session.refresh_count == 0 and refresher.calls == 0


@pytest.mark.parametrize("invalid", ("scope", "expiry", "identity"))
def test_invalid_refresh_result_is_rejected_before_new_persistence_boundary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, invalid: str
) -> None:
    target, _state, _token, paths = _stored(tmp_path)
    before = paths["write"].read_bytes()
    refresher = _refresher()
    updates = {
        "scope": {"scopes": ()},
        "expiry": {"expiry": NOW},
        "identity": {"client_id": "other.example.invalid"},
    }
    assert refresher.credentials is not None
    refresher.credentials = refresher.credentials.model_copy(update=updates[invalid])
    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", _forbidden)
    with pytest.raises(tokens.ProductionWriteTokenError) as caught:
        _prepare(target, paths, refresher)
    assert not isinstance(caught.value, tokens.ProductionWriteTokenRefreshPersistenceError)
    assert refresher.calls == 1 and paths["write"].read_bytes() == before


def test_refresh_request_failure_retains_its_existing_code_and_does_not_persist(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, _state, _token, paths = _stored(tmp_path)
    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", _forbidden)
    with pytest.raises(tokens.ProductionWriteTokenRefreshError) as caught:
        _prepare(target, paths, FakeRefresher(None, fail=True))
    assert caught.value.code == "production_write_token_refresh_failed"
    assert not isinstance(caught.value, tokens.ProductionWriteTokenRefreshPersistenceError)


@pytest.mark.parametrize("evidence", (False, True, None), ids=("before", "after", "unknown"))
def test_mock_rehearsal_reports_refresh_persistence_failure_before_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, evidence: bool | None
) -> None:
    target, _state, _token, paths = _stored(tmp_path)
    refresher = _refresher()

    def failed(*_args: Any, **_kwargs: Any) -> Path:
        raise token_io.ProductionWriteTokenIOError(
            "synthetic", "PRIVATE_OS_MARKER", publication_possible=evidence
        )

    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", failed)
    with pytest.raises(tokens.ProductionWriteTokenRefreshPersistenceError) as caught:
        _prepare(target, paths, refresher)
    provider = FakeProductionWriteCredentialSessionProvider(
        caught.value, refresh_attempt_count=refresher.calls
    )
    transport = FakeProductionWriteTokenReadOnlyTransport(collections=(), get_events=())
    transport_provider = FakeProductionWriteTokenReadOnlyTransportProvider(transport)
    # These inputs are intentionally unavailable: failure must precede their use.
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
    assert outcome.report.token_refresh_count == 1
    assert outcome.report.calendar_api_call_count == 0 and transport_provider.build_count == 0
    assert outcome.snapshot is None and transport.call_log == ()
    rendered = render_production_write_token_rehearsal_report_json(outcome.report)
    assert ERROR_CODE in rendered
    assert "publication_possible" not in rendered  # No report-schema change or recovery manifest.
    assert "PRIVATE_OS_MARKER" not in rendered and str(paths["write"]) not in rendered


def test_cancellation_is_not_mislabeled_as_an_ordinary_persistence_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target, _state, _token, paths = _stored(tmp_path)

    def interrupted(*_args: Any, **_kwargs: Any) -> Path:
        raise KeyboardInterrupt

    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", interrupted)
    with pytest.raises(KeyboardInterrupt):
        _prepare(target, paths, _refresher())


def test_new_handler_has_no_retry_cleanup_or_new_mutation_capability() -> None:
    tree = ast.parse(Path(tokens.__file__).read_text(encoding="utf-8"))
    fn = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_load_production_write_credential_session"
    )
    wrapped = [
        n
        for n in ast.walk(fn)
        if isinstance(n, ast.Try)
        and any(
            isinstance(c, ast.Call)
            and isinstance(c.func, ast.Name)
            and c.func.id == "persist_refreshed_production_write_token"
            for c in ast.walk(ast.Module(body=n.body, type_ignores=[]))
        )
    ]
    assert len(wrapped) == 1 and len(wrapped[0].handlers) == 1
    handler = wrapped[0].handlers[0]
    assert isinstance(handler.type, ast.Name) and handler.type.id == "Exception"
    assert not any(isinstance(n, (ast.For, ast.While)) for n in ast.walk(handler))
    attrs = {
        n.func.attr
        for n in ast.walk(handler)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert not attrs & {"remove", "unlink", "replace", "rename", "chmod"}
    calls = {
        n.func.id
        for n in ast.walk(handler)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    assert calls == {"isinstance", "ProductionWriteTokenRefreshPersistenceError"}
    cli = ast.parse(Path(tokens.__file__).with_name("cli.py").read_text(encoding="utf-8"))
    for name in (
        "_authorize_production_write_token_command",
        "_rehearse_production_write_token_readonly_command",
    ):
        off = next(n for n in cli.body if isinstance(n, ast.FunctionDef) and n.name == name)
        assert not any(
            isinstance(n, ast.Call) and isinstance(n.func, ast.Name) for n in ast.walk(off)
        )
