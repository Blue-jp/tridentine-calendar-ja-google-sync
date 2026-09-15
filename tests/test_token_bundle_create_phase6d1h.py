"""Synthetic POSIX token/state creation and error evidence; no live OAuth or refresh."""

from __future__ import annotations

import ast
import errno
import os
import stat
import traceback
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tridentine_calendar_google_sync import _posix_private_create as backend
from tridentine_calendar_google_sync import _private_create_io as adapter
from tridentine_calendar_google_sync import production_write_token_io as token_io
from tridentine_calendar_google_sync.google_target import calendar_id_fingerprint
from tridentine_calendar_google_sync.production_write_target import ProductionWriteTargetConfig
from tridentine_calendar_google_sync.production_write_token import (
    build_initial_production_write_token_generation_state,
)
from tridentine_calendar_google_sync.production_write_token_models import (
    PRODUCTION_WRITE_SCOPES,
    ProductionWriteAuthorizedUserToken,
    ProductionWriteGrantedScopeEvidence,
    ProductionWriteGrantEvidenceOrigin,
    ProductionWriteTokenGenerationState,
)

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="real POSIX token/state create")


def _pair() -> tuple[ProductionWriteAuthorizedUserToken, ProductionWriteTokenGenerationState]:
    calendar_id = "unit4h-production@calendar.example.invalid"
    target = ProductionWriteTargetConfig(
        schema_version=1,
        target_environment="production",
        target_label="production",
        target_purpose="production_calendar_single_update",
        calendar_id=calendar_id,
        expected_target_fingerprint=calendar_id_fingerprint(calendar_id),
        expected_summary="Unit 4H Production Calendar",
        expected_access_role="owner",
        expected_time_zone="Asia/Tokyo",
    )
    issued = datetime(2099, 1, 1, tzinfo=UTC)
    state = build_initial_production_write_token_generation_state(target, issued_at=issued)
    evidence = ProductionWriteGrantedScopeEvidence(
        origin=ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_AUTHORIZATION_RESPONSE,
        raw_scope_tokens=PRODUCTION_WRITE_SCOPES,
        granted_scopes=PRODUCTION_WRITE_SCOPES,
        observed_at=issued,
    )
    token = ProductionWriteAuthorizedUserToken(
        target_safe_ref=state.target_safe_ref,
        target_config_hash=state.target_config_hash,
        generation=state.generation,
        access_token="SYNTHETIC_PRIVATE_ACCESS",
        refresh_token="SYNTHETIC_PRIVATE_REFRESH",
        client_id="unit4h.example.invalid",
        client_secret="SYNTHETIC_PRIVATE_CLIENT",
        token_uri="https://oauth2.googleapis.com/token",
        scopes=PRODUCTION_WRITE_SCOPES,
        grant_evidence=evidence,
        expiry=datetime(2099, 1, 2, tzinfo=UTC),
    )
    return token, state


def _root(tmp_path: Path) -> Path:
    parent = tmp_path / "private-pair"
    parent.mkdir(mode=0o700)
    return parent


def _forbidden(*_args: Any, **_kwargs: Any) -> Any:
    raise AssertionError("unexpected legacy writer, rollback, retry, or parse")


def _safe(exc: token_io.ProductionWriteTokenIOError, root: Path) -> None:
    assert exc.__cause__ is None and exc.__suppress_context__
    rendered = "".join(traceback.format_exception(exc))
    for value in (
        str(root),
        "PRIVATE_OS_MARKER",
        "SYNTHETIC_PRIVATE_ACCESS",
        "SYNTHETIC_PRIVATE_REFRESH",
    ):
        assert value not in rendered


def _write(kind: str, path: Path) -> Path:
    token, state = _pair()
    if kind == "token":
        return token_io.write_production_write_authorized_user_token(token, path)
    return token_io.write_production_write_token_generation_state(state, path)


@pytest.mark.parametrize("kind", ("token", "state"))
@pytest.mark.parametrize("platform", ("posix", "nt"))
def test_exact_single_writer_platform_route_and_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, platform: str
) -> None:
    path = tmp_path / "dispatch-only.json"
    calls: list[tuple[str, dict[str, Any]]] = []
    token, state = _pair()
    expected = (
        token_io.render_production_write_authorized_user_token_json(token)
        if kind == "token"
        else token_io.render_production_write_token_generation_state_json(state)
    )

    def private(output: Path, content: str, **kwargs: Any) -> None:
        assert output == path and content == expected
        calls.append(("new", kwargs))

    def legacy(output: Path, content: str, **kwargs: Any) -> None:
        assert output == path and content == expected
        calls.append(("legacy", kwargs))

    monkeypatch.setattr(token_io, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(token_io, "validate_sensitive_output_path", lambda value, **_kw: value)
    monkeypatch.setattr(token_io, "_reject_repository_parent", lambda _p: None)
    monkeypatch.setattr(token_io, "create_private_text", private)
    monkeypatch.setattr(token_io, "atomic_write_private_text", legacy)
    assert _write(kind, path) == path
    options: dict[str, Any] = {"max_size": token_io.MAX_PRODUCTION_WRITE_TOKEN_BYTES}
    if platform == "nt":
        options["overwrite"] = False
        if kind == "token":
            options["windows_require_existing_protected_acl"] = True
    assert calls == [("new" if platform == "posix" else "legacy", options)]


@pytest.mark.parametrize("platform", ("posix", "nt"))
def test_explicit_refresh_overwrite_keeps_legacy_protected_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    token, _ = _pair()
    path = tmp_path / "dispatch-only.json"
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(token_io, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(token_io, "validate_sensitive_output_path", lambda value, **_kw: value)
    monkeypatch.setattr(token_io, "_reject_repository_parent", lambda _p: None)
    monkeypatch.setattr(token_io, "create_private_text", _forbidden)
    monkeypatch.setattr(token_io, "atomic_write_private_text", lambda *_a, **kw: calls.append(kw))
    assert (
        token_io.write_production_write_authorized_user_token(token, path, overwrite=True) == path
    )
    assert calls == [
        {
            "overwrite": True,
            "max_size": token_io.MAX_PRODUCTION_WRITE_TOKEN_BYTES,
            "windows_require_existing_protected_acl": True,
        }
    ]


@pytest.mark.parametrize("kind", ("token", "state"))
@pytest.mark.parametrize(
    "evidence", (False, True, None, "unexpected"), ids=("before", "after", "unknown", "unexpected")
)
def test_posix_single_writer_retains_safe_publication_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, evidence: bool | str | None
) -> None:
    path = tmp_path / "not-created.json"
    monkeypatch.setattr(token_io, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(token_io, "atomic_write_private_text", _forbidden)

    def failed(*_args: Any, **_kwargs: Any) -> None:
        if evidence == "unexpected":
            raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(path))
        raise adapter.PrivateCreateIOError(publication_possible=evidence)

    monkeypatch.setattr(token_io, "create_private_text", failed)
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        _write(kind, path)
    expected = None if evidence == "unexpected" else evidence
    assert caught.value.publication_possible is expected
    assert caught.value.completed_output_count == 0
    assert ("Outputs may exist" in str(caught.value)) is (expected is not False)
    assert caught.value.code == (
        "production_write_token_write_failed"
        if kind == "token"
        else "production_write_token_generation_write_failed"
    )
    _safe(caught.value, tmp_path)


@pytest.mark.parametrize("kind", ("token", "state"))
def test_posix_preflight_failure_never_enters_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    monkeypatch.setattr(token_io, "os", SimpleNamespace(name="posix"))

    def denied(*_a: Any, **_kw: Any) -> Path:
        raise PermissionError(errno.EACCES, "PRIVATE_OS_MARKER", str(tmp_path))

    monkeypatch.setattr(token_io, "validate_sensitive_output_path", denied)
    monkeypatch.setattr(token_io, "create_private_text", _forbidden)
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        _write(kind, tmp_path / "not-created.json")
    assert caught.value.publication_possible is False
    _safe(caught.value, tmp_path)


@pytest.mark.parametrize("index", (0, 1), ids=("state", "token"))
@pytest.mark.parametrize(
    "evidence", (False, True, None, "unexpected"), ids=("before", "after", "unknown", "unexpected")
)
def test_posix_pair_failure_preserves_outputs_stops_and_never_cleans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, index: int, evidence: bool | str | None
) -> None:
    parent = _root(tmp_path)
    token, state = _pair()
    state_path, token_path = parent / "state.json", parent / "token.json"
    paths = (state_path, token_path)
    attempts: list[Path] = []
    monkeypatch.setattr(token_io, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(token_io, "_remove_exact_new_artifact", _forbidden)

    def write(_model: Any, path: Path, **_kw: Any) -> Path:
        number = len(attempts)
        attempts.append(path)
        if number != index or evidence is not False:
            path.write_bytes(b"synthetic retained output")
        if number == index:
            if evidence == "unexpected":
                raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(path))
            raise token_io.ProductionWriteTokenIOError(
                "synthetic_failure", "PRIVATE_OS_MARKER", publication_possible=evidence
            )
        return path

    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", write)
    monkeypatch.setattr(token_io, "write_production_write_token_generation_state", write)
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        token_io.write_production_write_token_bundle(token, token_path, state, state_path)
    error = caught.value
    assert error.code == "production_write_token_bundle_write_failed"
    expected = True if index else (None if evidence == "unexpected" else evidence)
    assert error.publication_possible is expected
    assert error.completed_output_count == index
    assert attempts == list(paths[: index + 1])
    assert ("Outputs may exist" in str(error)) is (expected is not False)
    for number, path in enumerate(paths):
        assert path.exists() is (number < index or (number == index and evidence is not False))
    _safe(error, parent)


@POSIX_ONLY
def test_real_posix_pair_round_trip_without_legacy_writer_or_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = _root(tmp_path)
    token, state = _pair()
    token_path, state_path = parent / "token.json", parent / "state.json"
    monkeypatch.setattr(token_io, "atomic_write_private_text", _forbidden)
    monkeypatch.setattr(token_io, "_remove_exact_new_artifact", _forbidden)
    assert token_io.write_production_write_token_bundle(token, token_path, state, state_path) == (
        token_path,
        state_path,
    )
    assert token_io.load_production_write_authorized_user_token(token_path) == token
    assert token_io.load_production_write_token_generation_state(state_path) == state
    for path in (token_path, state_path):
        info = path.stat()
        assert (
            stat.S_IMODE(info.st_mode) == 0o600
            and info.st_nlink == 1
            and info.st_uid == os.geteuid()
        )
    assert {p.name for p in parent.iterdir()} == {"token.json", "state.json"}


@POSIX_ONLY
@pytest.mark.parametrize("index", (0, 1), ids=("state", "token"))
def test_real_posix_postpublication_error_keeps_final_outputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, index: int
) -> None:
    parent = _root(tmp_path)
    token, state = _pair()
    token_path, state_path = parent / "token.json", parent / "state.json"
    native = backend.os
    calls: list[int] = []

    def fsync(fd: int) -> None:
        if stat.S_ISDIR(native.fstat(fd).st_mode):
            count = len(calls)
            calls.append(count)
            if count == index:
                raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(parent))
        native.fsync(fd)

    proxy = SimpleNamespace(**{name: getattr(native, name) for name in dir(native)})
    proxy.fsync = fsync
    monkeypatch.setattr(backend, "os", proxy)
    monkeypatch.setattr(token_io, "_remove_exact_new_artifact", _forbidden)
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        token_io.write_production_write_token_bundle(token, token_path, state, state_path)
    assert caught.value.publication_possible is True
    assert caught.value.completed_output_count == index
    assert (
        state_path.read_bytes()
        == token_io.render_production_write_token_generation_state_json(state).encode()
    )
    assert token_path.exists() is (index == 1)
    if index == 1:
        assert (
            token_path.read_bytes()
            == token_io.render_production_write_authorized_user_token_json(token).encode()
        )
    _safe(caught.value, parent)


@POSIX_ONLY
@pytest.mark.parametrize("same_bytes", (False, True), ids=("different", "identical"))
def test_competitor_token_at_publication_is_not_deleted_even_if_bytes_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, same_bytes: bool
) -> None:
    parent = _root(tmp_path)
    token, state = _pair()
    token_path, state_path = parent / "token.json", parent / "state.json"
    expected = (
        token_io.render_production_write_authorized_user_token_json(token).encode()
        if same_bytes
        else b"unrelated"
    )
    native = backend.os

    def link(src: str, dst: str, **kwargs: Any) -> None:
        if dst == token_path.name:
            token_path.write_bytes(expected)
            token_path.chmod(0o600)
        native.link(src, dst, **kwargs)

    proxy = SimpleNamespace(**{name: getattr(native, name) for name in dir(native)})
    proxy.link = link
    monkeypatch.setattr(backend, "os", proxy)
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        token_io.write_production_write_token_bundle(token, token_path, state, state_path)
    assert caught.value.publication_possible is True and caught.value.completed_output_count == 1
    assert token_path.read_bytes() == expected and state_path.exists()
    _safe(caught.value, parent)


@pytest.mark.parametrize("existing", ("state", "token"))
def test_existing_either_name_blocks_pair_before_any_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, existing: str
) -> None:
    parent = _root(tmp_path)
    token, state = _pair()
    path = parent / (existing + ".json")
    path.write_bytes(b"preserve")
    monkeypatch.setattr(token_io, "write_production_write_token_generation_state", _forbidden)
    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", _forbidden)
    with pytest.raises(token_io.ProductionWriteTokenIOError):
        token_io.write_production_write_token_bundle(
            token, parent / "token.json", state, parent / "state.json"
        )
    assert path.read_bytes() == b"preserve" and list(parent.iterdir()) == [path]


@POSIX_ONLY
@pytest.mark.parametrize("mode", (0o750, 0o755, 0o770))
def test_posix_broad_parent_not_repaired_or_written(tmp_path: Path, mode: int) -> None:
    parent = _root(tmp_path)
    parent.chmod(mode)
    token, state = _pair()
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        token_io.write_production_write_token_bundle(
            token, parent / "token.json", state, parent / "state.json"
        )
    assert caught.value.publication_possible is False and caught.value.completed_output_count == 0
    assert stat.S_IMODE(parent.stat().st_mode) == mode and list(parent.iterdir()) == []


@pytest.mark.parametrize("role", ("token", "state"))
def test_both_documents_render_before_first_pair_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    token, state = _pair()

    def bad_render(*_args: Any) -> str:
        raise ValueError("synthetic-render-error")

    name = (
        "render_production_write_authorized_user_token_json"
        if role == "token"
        else "render_production_write_token_generation_state_json"
    )
    monkeypatch.setattr(token_io, name, bad_render)
    monkeypatch.setattr(token_io, "write_production_write_token_generation_state", _forbidden)
    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", _forbidden)
    with pytest.raises(ValueError, match="synthetic-render-error"):
        token_io.write_production_write_token_bundle(
            token, tmp_path / "token.json", state, tmp_path / "state.json"
        )
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("failure", ("binding", "collision"))
def test_pair_preconditions_never_enter_any_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    token, state = _pair()
    token_path, state_path = tmp_path / "token.json", tmp_path / "state.json"
    if failure == "binding":
        token = token.model_copy(update={"generation": state.generation + 1})
    else:
        state_path = token_path
    monkeypatch.setattr(token_io, "write_production_write_token_generation_state", _forbidden)
    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", _forbidden)
    with pytest.raises(token_io.ProductionWriteTokenIOError):
        token_io.write_production_write_token_bundle(token, token_path, state, state_path)
    assert list(tmp_path.iterdir()) == []


def test_posix_pair_helper_has_no_rollback_or_retry_calls() -> None:
    tree = ast.parse(Path(token_io.__file__).read_text(encoding="utf-8"))
    fn = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef) and node.name == "_write_posix_token_bundle"
    )
    names = {
        node.func.id
        for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    attrs = {
        node.func.attr
        for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not names & {
        "_remove_exact_new_artifact",
        "remove_sensitive_file_if_matches",
        "atomic_write_private_text",
    }
    assert not attrs & {"unlink", "remove", "replace", "rename", "chmod"}
    assert not any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(fn))
    cli = ast.parse(Path(token_io.__file__).with_name("cli.py").read_text(encoding="utf-8"))
    for name in (
        "_authorize_production_write_token_command",
        "_rehearse_production_write_token_readonly_command",
    ):
        body = next(
            node for node in cli.body if isinstance(node, ast.FunctionDef) and node.name == name
        )
        assert not any(
            isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            for node in ast.walk(body)
        )


@pytest.mark.parametrize(
    "recovery_succeeds", (False, True), ids=("recovery-fails", "recovery-succeeds")
)
def test_windows_bundle_keeps_legacy_recovery_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, recovery_succeeds: bool
) -> None:
    token, state = _pair()
    token_path, state_path = tmp_path / "token.json", tmp_path / "state.json"
    removals: list[tuple[Path, bytes, dict[str, Any]]] = []
    monkeypatch.setattr(token_io, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(token_io, "_write_posix_token_bundle", _forbidden)
    monkeypatch.setattr(token_io, "write_production_write_token_generation_state", lambda _s, p: p)

    def failed(*_a: Any, **_kw: Any) -> Path:
        raise token_io.ProductionWriteTokenIOError(
            "synthetic_windows_write_failure", "synthetic safe failure"
        )

    def remove(path: Path, content: bytes, **kwargs: Any) -> bool:
        removals.append((path, content, kwargs))
        return recovery_succeeds

    monkeypatch.setattr(token_io, "write_production_write_authorized_user_token", failed)
    monkeypatch.setattr(token_io, "_remove_exact_new_artifact", remove)
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        token_io.write_production_write_token_bundle(token, token_path, state, state_path)
    assert caught.value.code == (
        "synthetic_windows_write_failure"
        if recovery_succeeds
        else "production_write_token_bundle_recovery_failed"
    )
    assert removals == [
        (
            token_path,
            token_io.render_production_write_authorized_user_token_json(token).encode(),
            {"private": True, "integrity": False},
        ),
        (
            state_path,
            token_io.render_production_write_token_generation_state_json(state).encode(),
            {"private": False, "integrity": True},
        ),
    ]
