"""Synthetic refresh persistence integration; not CAS, reconciliation or live approval."""

from __future__ import annotations

import ast
import errno
import os
import stat
import traceback
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
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

from tridentine_calendar_google_sync import _posix_private_replace as backend
from tridentine_calendar_google_sync import production_write_token as tokens
from tridentine_calendar_google_sync import production_write_token_io as token_io
from tridentine_calendar_google_sync import production_write_token_rehearsal as rehearsal
from tridentine_calendar_google_sync.production_write_token_models import (
    ProductionWriteGrantEvidenceOrigin,
)

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="real POSIX refresh replacement")
NOW = ISSUED_AT + timedelta(seconds=2)
CODE = "production_write_token_refresh_replace_failed"


def _pair() -> tuple[Any, Any, Any]:
    state = tokens.build_initial_production_write_token_generation_state(
        production_target(), issued_at=ISSUED_AT
    )
    old = production_token(state, expiry=ISSUED_AT + timedelta(seconds=1))
    new = old.model_copy(
        update={"access_token": "UNIT4L_PRIVATE_NEW", "expiry": NOW + timedelta(hours=1)}
    )
    return old, new, state


def _stored(tmp_path: Path, *, expired: bool = True) -> tuple[Any, Any, dict[str, Path]]:
    root = tmp_path / "private-refresh-replace"
    root.mkdir(mode=0o700)
    paths = artifact_paths(root)
    old, _new, state = _pair()
    if not expired:
        old = old.model_copy(update={"expiry": NOW + timedelta(hours=1)})
    token_io.write_production_write_token_bundle(old, paths["write"], state, paths["generation"])
    return old, state, paths


def _refresher() -> FakeRefresher:
    return FakeRefresher(
        oauth_credentials(
            expiry=NOW + timedelta(hours=1),
            evidence_origin=ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_REFRESH_RESPONSE,
            evidence_observed_at=NOW,
            access_token="UNIT4L_PRIVATE_NEW",
            refresh_token="UNIT4L_PRIVATE_REFRESH",
        )
    )


def _prepare(paths: dict[str, Path], refresher: FakeRefresher) -> Any:
    target = production_target()
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
    raise AssertionError("unexpected legacy fallback, read, retry, cleanup or session")


def _safe(error: BaseException, path: Path) -> None:
    assert error.__cause__ is None and error.__suppress_context__
    message = "".join(traceback.format_exception(error))
    for marker in (str(path), "PRIVATE_OS_MARKER", "UNIT4L_PRIVATE_NEW", "UNIT4L_PRIVATE_REFRESH"):
        assert marker not in message
    assert "do not retry" in message


def _dispatch(monkeypatch: pytest.MonkeyPatch, platform: str) -> None:
    monkeypatch.setattr(token_io, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(token_io, "validate_sensitive_output_path", lambda path, **_kw: path)
    monkeypatch.setattr(token_io, "_reject_repository_parent", lambda _path: None)


@pytest.mark.parametrize("platform", ("nt", "posix"))
def test_selected_refresh_save_passes_exact_original_bytes_or_unchanged_windows_call(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    old, new, _state = _pair()
    path = tmp_path / "dispatch-only.json"
    calls: list[int] = []
    _dispatch(monkeypatch, platform)

    def replaced(value: Path, content: bytes, *, expected_content: bytes) -> None:
        assert value == path
        assert content == token_io.render_production_write_authorized_user_token_json(new).encode()
        assert (
            expected_content
            == token_io.render_production_write_authorized_user_token_json(old).encode()
        )
        calls.append(1)

    def legacy(token: Any, value: Path, **kwargs: Any) -> Path:
        assert token is new and value == path and kwargs == {"overwrite": True}
        calls.append(1)
        return value

    monkeypatch.setattr(
        backend, "replace_posix_private_bytes", replaced if platform == "posix" else _forbidden
    )
    monkeypatch.setattr(
        token_io,
        "write_production_write_authorized_user_token",
        legacy if platform == "nt" else _forbidden,
    )
    monkeypatch.setattr(token_io, "load_production_write_authorized_user_token", _forbidden)
    assert token_io.persist_refreshed_production_write_token(new, path, expected_token=old) == path
    assert calls == [1] and not path.exists()


@pytest.mark.parametrize("evidence", (False, True, None, 0, 1, "invalid", "unexpected"))
def test_posix_error_preserves_only_boolean_evidence_without_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, evidence: Any
) -> None:
    old, new, _state = _pair()
    path = tmp_path / "PRIVATE_OS_MARKER.json"
    _dispatch(monkeypatch, "posix")
    calls: list[int] = []

    def failed(*_args: Any, **_kwargs: Any) -> Any:
        calls.append(1)
        if evidence == "unexpected":
            raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(path))
        raise backend.PosixPrivateReplaceError("PRIVATE_OS_MARKER", publication_possible=evidence)

    monkeypatch.setattr(backend, "replace_posix_private_bytes", failed)
    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", _forbidden)
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        token_io.persist_refreshed_production_write_token(new, path, expected_token=old)
    assert caught.value.code == CODE
    assert caught.value.publication_possible is (evidence if type(evidence) is bool else None)
    assert calls == [1]
    _safe(caught.value, path)


@pytest.mark.parametrize("phase", ("render", "path", "repository", "platform"))
def test_pre_backend_failure_is_false_without_any_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    old, new, _state = _pair()
    path = tmp_path / "PRIVATE_OS_MARKER.json"
    _dispatch(monkeypatch, "posix" if phase != "platform" else "unsupported")

    def failed(*_args: Any, **_kwargs: Any) -> Any:
        raise ValueError("PRIVATE_OS_MARKER")

    names = {
        "render": "render_production_write_authorized_user_token_json",
        "path": "validate_sensitive_output_path",
        "repository": "_reject_repository_parent",
    }
    if phase in names:
        monkeypatch.setattr(token_io, names[phase], failed)
    monkeypatch.setattr(backend, "replace_posix_private_bytes", _forbidden)
    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", _forbidden)
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        token_io.persist_refreshed_production_write_token(new, path, expected_token=old)
    assert caught.value.publication_possible is False and caught.value.code == CODE
    _safe(caught.value, path)


@pytest.mark.parametrize("which", ("new", "old"))
@pytest.mark.parametrize("invalid", ("type", "size"))
def test_both_tokens_are_required_and_bounded_before_path_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, which: str, invalid: str
) -> None:
    old, new, _state = _pair()
    value = old if which == "old" else new
    value = (
        object()
        if invalid == "type"
        else value.model_copy(
            update={"access_token": "x" * (token_io.MAX_PRODUCTION_WRITE_TOKEN_BYTES + 1)}
        )
    )
    _dispatch(monkeypatch, "posix")
    monkeypatch.setattr(token_io, "validate_sensitive_output_path", _forbidden)
    monkeypatch.setattr(backend, "replace_posix_private_bytes", _forbidden)
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        token_io.persist_refreshed_production_write_token(
            value if which == "new" else new,
            tmp_path / "unused",
            expected_token=value if which == "old" else old,
        )
    assert caught.value.publication_possible is False


@POSIX_ONLY
def test_real_refresh_uses_replacement_not_generic_writer_and_keeps_generation_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old, state, paths = _stored(tmp_path)
    state_before = paths["generation"].read_bytes()
    old_ino = paths["write"].stat().st_ino
    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", _forbidden)
    monkeypatch.setattr(token_io, "atomic_write_private_text", _forbidden)
    monkeypatch.setattr(token_io, "_remove_exact_new_artifact", _forbidden)
    refresher = _refresher()
    session = _prepare(paths, refresher)
    assert session.token.access_token != old.access_token and session.generation_state == state
    assert session.refresh_count == refresher.calls == 1
    assert paths["generation"].read_bytes() == state_before
    assert token_io.load_production_write_authorized_user_token(paths["write"]) == session.token
    info = paths["write"].stat()
    assert info.st_ino != old_ino and info.st_uid == os.geteuid()
    assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1
    assert not list(paths["write"].parent.glob(".private-replace-*"))
    assert refresher.calendar_api_call_count == 0 and refresher.browser_fallback_count == 0


@POSIX_ONLY
@pytest.mark.parametrize("mutation", ("changed", "missing", "hardlink", "mode", "parent_mode"))
def test_observed_change_after_unit4j_stops_at_real_backend_without_legacy_save(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    old, _state, paths = _stored(tmp_path)
    path = paths["write"]
    state_before = paths["generation"].read_bytes()
    native = token_io.persist_refreshed_production_write_token
    after: list[bytes | None] = []

    def changed(token: Any, value: Path, *, expected_token: Any) -> Path:
        assert expected_token == old
        if mutation == "changed":
            value.write_bytes(b"competitor-not-original")
        elif mutation == "missing":
            value.unlink()  # Synthetic competing actor only.
        elif mutation == "hardlink":
            os.link(value, value.with_name("synthetic-alias"))
        elif mutation == "mode":
            value.chmod(0o640)
        else:
            value.parent.chmod(0o750)
        after.append(value.read_bytes() if value.exists() else None)
        return native(token, value, expected_token=expected_token)

    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", changed)
    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", _forbidden)
    monkeypatch.setattr(tokens, "ProductionWriteCredentialSession", _forbidden)
    refresher = _refresher()
    with pytest.raises(tokens.ProductionWriteTokenRefreshPersistenceError) as caught:
        _prepare(paths, refresher)
    error = caught.value
    assert error.refresh_completed and error.persistence_attempted
    assert error.publication_possible is False
    assert (path.read_bytes() if path.exists() else None) == after[0]
    assert paths["generation"].read_bytes() == state_before
    assert refresher.calls == 1
    _safe(error, path)


@POSIX_ONLY
@pytest.mark.parametrize("when", ("before_write", "before_replace", "after_replace"))
def test_real_backend_failure_propagates_to_unit4i_without_delete_or_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, when: str
) -> None:
    old, _state, paths = _stored(tmp_path)
    path = paths["write"]
    state_before = paths["generation"].read_bytes()
    calls: list[int] = []
    proxy = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})

    def failed(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        if when == "after_replace":
            os.replace(*args, **kwargs)
        raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(path))

    if when == "before_write":
        proxy.write = failed
    else:
        proxy.replace = failed
    monkeypatch.setattr(backend, "os", proxy)
    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", _forbidden)
    monkeypatch.setattr(token_io, "_remove_exact_new_artifact", _forbidden)
    refresher = _refresher()
    with pytest.raises(tokens.ProductionWriteTokenRefreshPersistenceError) as caught:
        _prepare(paths, refresher)
    assert caught.value.publication_possible is (when != "before_write")
    stored = token_io.load_production_write_authorized_user_token(path)
    assert stored.access_token == (
        "UNIT4L_PRIVATE_NEW" if when == "after_replace" else old.access_token
    )
    assert len(list(path.parent.glob(".private-replace-*"))) == (
        0 if when == "after_replace" else 1
    )
    assert calls == [1] and refresher.calls == 1
    assert paths["generation"].read_bytes() == state_before
    _safe(caught.value, path)


def test_unexpired_session_skips_new_persistence_and_refresher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old, _state, paths = _stored(tmp_path, expired=False)
    monkeypatch.setattr(token_io, "persist_refreshed_production_write_token", _forbidden)
    monkeypatch.setattr(backend, "replace_posix_private_bytes", _forbidden)
    refresher = _refresher()
    session = _prepare(paths, refresher)
    assert session.token == old and session.refresh_count == refresher.calls == 0


def test_windows_delegate_retains_the_original_exception_object(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old, new, _state = _pair()
    _dispatch(monkeypatch, "nt")
    error = token_io.ProductionWriteTokenIOError("synthetic", "safe failure")

    def failed(*_args: Any, **_kwargs: Any) -> Any:
        raise error

    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", failed)
    monkeypatch.setattr(backend, "replace_posix_private_bytes", _forbidden)
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        token_io.persist_refreshed_production_write_token(
            new, tmp_path / "unused", expected_token=old
        )
    assert caught.value is error and caught.value.publication_possible is None


def test_cancel_is_not_converted_to_an_ordinary_replacement_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old, new, _state = _pair()
    _dispatch(monkeypatch, "posix")

    def interrupted(*_args: Any, **_kwargs: Any) -> Any:
        raise KeyboardInterrupt

    monkeypatch.setattr(backend, "replace_posix_private_bytes", interrupted)
    with pytest.raises(KeyboardInterrupt):
        token_io.persist_refreshed_production_write_token(
            new, tmp_path / "unused", expected_token=old
        )


def test_refresh_passes_original_input_and_has_no_legacy_save_at_call_site() -> None:
    tree = ast.parse(Path(tokens.__file__).read_text(encoding="utf-8"))
    fn = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "_load_production_write_credential_session"
    )
    calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
    save = [n for n in calls if n.func.id == "persist_refreshed_production_write_token"]
    assert len(save) == 1 and len(save[0].keywords) == 1
    assert save[0].keywords[0].arg == "expected_token"
    assert isinstance(save[0].keywords[0].value, ast.Name)
    assert save[0].keywords[0].value.id == "token"
    assert not any(n.func.id == "write_production_write_authorized_user_token" for n in calls)
    io_tree = ast.parse(Path(token_io.__file__).read_text(encoding="utf-8"))
    entry = next(
        n
        for n in io_tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "persist_refreshed_production_write_token"
    )
    assert len(entry.args.kwonlyargs) == 1 and entry.args.kw_defaults == [None]
    attrs = {
        n.func.attr
        for n in ast.walk(entry)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert not attrs & {"unlink", "remove", "chmod", "mkdir", "replace"}
