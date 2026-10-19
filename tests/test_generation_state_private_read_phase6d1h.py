"""Synthetic generation-state reads only; no OAuth, writes, refresh or rollback changes."""

from __future__ import annotations

import ast
import errno
import os
import stat
import subprocess
import sys
import traceback
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tridentine_calendar_google_sync import production_write_token_io as token_io
from tridentine_calendar_google_sync import sensitive_paths
from tridentine_calendar_google_sync.google_target import calendar_id_fingerprint
from tridentine_calendar_google_sync.production_write_target import ProductionWriteTargetConfig
from tridentine_calendar_google_sync.production_write_token import (
    build_initial_production_write_token_generation_state,
)
from tridentine_calendar_google_sync.production_write_token_models import (
    ProductionWriteTokenGenerationState,
)

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="real POSIX generation-state read")
ERROR_CODE = "unsafe_production_write_token_generation_path"


def _state() -> ProductionWriteTokenGenerationState:
    calendar_id = "unit4g-production@calendar.example.invalid"
    target = ProductionWriteTargetConfig(
        schema_version=1,
        target_environment="production",
        target_label="production",
        target_purpose="production_calendar_single_update",
        calendar_id=calendar_id,
        expected_target_fingerprint=calendar_id_fingerprint(calendar_id),
        expected_summary="Unit 4G Production Calendar",
        expected_access_role="owner",
        expected_time_zone="Asia/Tokyo",
    )
    return build_initial_production_write_token_generation_state(
        target, issued_at=datetime(2099, 1, 1, tzinfo=UTC)
    )


def _fixture(tmp_path: Path) -> tuple[Path, ProductionWriteTokenGenerationState]:
    state = _state()
    path = tmp_path / "generation.json"
    token_io.write_production_write_token_generation_state(state, path)
    return path, state


def _forbidden(*_a: Any, **_kw: Any) -> Any:
    raise AssertionError("unexpected generic reader, path-mode check or write")


def _reject(path: Path) -> token_io.ProductionWriteTokenIOError:
    with pytest.raises(token_io.ProductionWriteTokenIOError) as caught:
        token_io.load_production_write_token_generation_state(path)
    error = caught.value
    assert error.code == ERROR_CODE
    assert error.__cause__ is None and error.__suppress_context__
    rendered = "".join(traceback.format_exception(error))
    assert str(path) not in rendered and "PRIVATE_OS_MARKER" not in rendered
    return error


def test_canonical_generation_round_trip_does_not_change_contents_or_permissions(
    tmp_path: Path,
) -> None:
    path, state = _fixture(tmp_path)
    before = path.stat()
    content = path.read_bytes()
    assert token_io.load_production_write_token_generation_state(path) == state
    after = path.stat()
    assert path.read_bytes() == content
    assert (before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns) == (
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    )


@pytest.mark.parametrize("platform", ("posix", "nt"))
def test_loader_selects_exact_reader_and_limit_without_separate_mode_check(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    path = tmp_path / "dispatch-only.json"
    state = _state()
    raw = token_io.render_production_write_token_generation_state_json(state).encode()
    calls: list[dict[str, Any]] = []

    def selected(value: Path, **kwargs: Any) -> bytes:
        assert value == path
        calls.append(kwargs)
        return raw

    monkeypatch.setattr(token_io, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(token_io, "_reject_repository_parent", lambda _path: None)
    monkeypatch.setattr(token_io, "_require_private_file_mode", _forbidden)
    monkeypatch.setattr(
        token_io, "read_private_sensitive_bytes", selected if platform == "posix" else _forbidden
    )
    monkeypatch.setattr(
        token_io, "read_sensitive_bytes", selected if platform == "nt" else _forbidden
    )
    assert token_io.load_production_write_token_generation_state(path) == state
    expected = {"max_size": token_io.MAX_PRODUCTION_WRITE_TOKEN_BYTES}
    if platform == "nt":
        expected["windows_integrity_acl"] = True
    assert calls == [expected]


@pytest.mark.parametrize("platform", ("posix", "nt"))
def test_reader_error_is_path_free_and_never_falls_back_or_parses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    path = tmp_path / "PRIVATE_OS_MARKER.json"
    calls: list[int] = []

    def denied(*_a: Any, **_kw: Any) -> bytes:
        calls.append(1)
        try:
            raise OSError(errno.EACCES, "PRIVATE_OS_MARKER", str(path))
        except OSError as exc:
            raise sensitive_paths.SensitivePathError("synthetic", "PRIVATE_OS_MARKER") from exc

    monkeypatch.setattr(token_io, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(token_io, "_reject_repository_parent", lambda _path: None)
    monkeypatch.setattr(token_io, "_require_private_file_mode", _forbidden)
    monkeypatch.setattr(token_io, "parse_production_write_token_generation_state_bytes", _forbidden)
    monkeypatch.setattr(
        token_io, "read_private_sensitive_bytes", denied if platform == "posix" else _forbidden
    )
    monkeypatch.setattr(
        token_io, "read_sensitive_bytes", denied if platform == "nt" else _forbidden
    )
    _reject(path)
    assert calls == [1]


@POSIX_ONLY
@pytest.mark.parametrize("mode", (0o400, 0o600), ids=("owner-read", "owner-read-write"))
def test_posix_owner_only_state_still_reads_without_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    path, state = _fixture(tmp_path)
    path.chmod(mode)
    monkeypatch.setattr(token_io, "read_sensitive_bytes", _forbidden)
    monkeypatch.setattr(token_io, "_require_private_file_mode", _forbidden)
    assert token_io.load_production_write_token_generation_state(path) == state
    assert stat.S_IMODE(path.stat().st_mode) == mode


@POSIX_ONLY
@pytest.mark.parametrize("mode", (0o640, 0o604, 0o660, 0o606))
def test_posix_group_other_permissions_rejected_without_repair(tmp_path: Path, mode: int) -> None:
    path, _ = _fixture(tmp_path)
    path.chmod(mode)
    content = path.read_bytes()
    _reject(path)
    assert stat.S_IMODE(path.stat().st_mode) == mode and path.read_bytes() == content


@POSIX_ONLY
def test_posix_foreign_effective_owner_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path, _ = _fixture(tmp_path)
    uid = os.geteuid()
    proxy = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
    proxy.geteuid = lambda: uid + 1
    monkeypatch.setattr(sensitive_paths, "os", proxy)
    _reject(path)


@POSIX_ONLY
@pytest.mark.parametrize("kind", ("hardlink", "symlink"))
def test_posix_linked_state_is_rejected_and_original_retained(tmp_path: Path, kind: str) -> None:
    path, _ = _fixture(tmp_path)
    alias = tmp_path / "alias.json"
    if kind == "hardlink":
        os.link(path, alias)
    else:
        alias.symlink_to(path)
    before = path.read_bytes()
    _reject(alias)
    assert path.read_bytes() == before and alias.lstat()


@POSIX_ONLY
@pytest.mark.parametrize("when", ("before_leaf_open", "during_read"))
def test_posix_mode_change_at_use_time_rejected_before_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, when: str
) -> None:
    path, _ = _fixture(tmp_path)
    native_open, native_read = os.open, os.read
    changed: list[str] = []
    proxy = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})

    def opened(name: str, flags: int, *args: Any, **kwargs: Any) -> int:
        if name == path.name and when == "before_leaf_open":
            path.chmod(0o640)
            changed.append(when)
        return native_open(name, flags, *args, **kwargs)

    def read(fd: int, size: int) -> bytes:
        data = native_read(fd, size)
        if when == "during_read" and not changed:
            path.chmod(0o640)
            changed.append(when)
        return data

    proxy.open, proxy.read = opened, read
    monkeypatch.setattr(sensitive_paths, "os", proxy)
    monkeypatch.setattr(token_io, "parse_production_write_token_generation_state_bytes", _forbidden)
    _reject(path)
    assert changed == [when] and stat.S_IMODE(path.stat().st_mode) == 0o640


@POSIX_ONLY
def test_posix_generation_size_limit_stops_before_parser(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "too-large.json"
    path.write_bytes(b"x" * (token_io.MAX_PRODUCTION_WRITE_TOKEN_BYTES + 1))
    path.chmod(0o600)
    monkeypatch.setattr(token_io, "parse_production_write_token_generation_state_bytes", _forbidden)
    _reject(path)


@POSIX_ONLY
def test_posix_fifo_is_rejected_without_waiting_for_writer(tmp_path: Path) -> None:
    path = tmp_path / "synthetic-fifo"
    os.mkfifo(path, 0o600)
    code = """
import sys
from tridentine_calendar_google_sync.production_write_token_io import (
    ProductionWriteTokenIOError, load_production_write_token_generation_state,
)
try:
    load_production_write_token_generation_state(sys.argv[1])
except ProductionWriteTokenIOError as exc:
    sys.exit(0 if exc.code == 'unsafe_production_write_token_generation_path' else 2)
sys.exit(3)
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(token_io.__file__).resolve().parents[1])
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, "-c", code, str(path)],
        env=env,
        check=False,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=10,
    )
    assert result.returncode == 0


@pytest.mark.parametrize("kind", ("malformed", "noncanonical", "hash-tamper"))
def test_existing_parser_and_canonical_hash_rejections_preserved(tmp_path: Path, kind: str) -> None:
    raw = token_io.render_production_write_token_generation_state_json(_state()).encode()
    if kind == "malformed":
        raw = b"{"
    elif kind == "noncanonical":
        raw += b"\n"
    else:
        state = _state()
        raw = raw.replace(state.content_hash.encode(), b"f" * 64)
    path = tmp_path / "invalid-state.json"
    sensitive_paths.atomic_write_private_text(path, raw.decode())
    with pytest.raises(token_io.ProductionWriteTokenIOError) as parsed:
        token_io.parse_production_write_token_generation_state_bytes(raw)
    with pytest.raises(token_io.ProductionWriteTokenIOError) as loaded:
        token_io.load_production_write_token_generation_state(path)
    assert loaded.value.code == parsed.value.code
    assert path.read_bytes() == raw


def test_path_preflight_still_precedes_any_content_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def denied(_path: Path) -> None:
        raise sensitive_paths.SensitivePathError("synthetic", "PRIVATE_OS_MARKER")

    monkeypatch.setattr(token_io, "_reject_repository_parent", denied)
    monkeypatch.setattr(token_io, "read_private_sensitive_bytes", _forbidden)
    monkeypatch.setattr(token_io, "read_sensitive_bytes", _forbidden)
    _reject(tmp_path / "not-read.json")


def test_generation_loader_does_not_change_or_remove_files() -> None:
    tree = ast.parse(Path(token_io.__file__).read_text(encoding="utf-8"))
    fn = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "load_production_write_token_generation_state"
    )
    calls = {
        node.func.id
        for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "_require_private_file_mode" not in calls
    assert calls == {
        "Path",
        "_reject_repository_parent",
        "read_sensitive_bytes",
        "read_private_sensitive_bytes",
        "parse_production_write_token_generation_state_bytes",
        "ProductionWriteTokenIOError",
    }
    assert not any(
        isinstance(node, ast.Attribute) and node.attr in {"chmod", "unlink", "replace"}
        for node in ast.walk(fn)
    )


@pytest.mark.skipif(os.name != "nt", reason="real Windows generation-state integrity ACL")
def test_windows_metadata_allows_broad_read_but_rejects_broad_write(
    tmp_path: Path,
) -> None:
    from windows_sensitive_fs_helpers import set_private_file_acl

    path, state = _fixture(tmp_path)
    set_private_file_acl(path, broad_principal="BU")
    assert token_io.load_production_write_token_generation_state(path) == state
    with pytest.raises(sensitive_paths.SensitivePathError):
        sensitive_paths.read_private_sensitive_bytes(path)
    set_private_file_acl(path, broad_principal="BU", broad_rights="GRGW")
    _reject(path)
