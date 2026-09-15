"""Synthetic opt-in planning output tests; no live authorization or Calendar calls."""

from __future__ import annotations

import ast
import errno
import inspect
import os
import stat
import traceback
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tridentine_calendar_google_sync import _posix_private_create as backend
from tridentine_calendar_google_sync import _private_create_io as adapter
from tridentine_calendar_google_sync import production_single_update_plan_io as plan_io
from tridentine_calendar_google_sync import production_single_update_run_spec_io as run_io
from tridentine_calendar_google_sync import sensitive_paths

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="real POSIX planning create")
KINDS = ("plan", "run_spec")
TEXT = '{"synthetic":"private-planning-output"}\n'


def _role(kind: str) -> tuple[Any, Any, str]:
    if kind == "plan":
        return (
            plan_io,
            plan_io.write_production_single_update_plan,
            "ProductionSingleUpdatePlanIOError",
        )
    return (
        run_io,
        run_io.write_production_single_update_run_spec,
        "ProductionSingleUpdateRunSpecIOError",
    )


def _render_only(monkeypatch: pytest.MonkeyPatch, kind: str) -> Any:
    module, writer, _ = _role(kind)
    name = (
        "render_production_single_update_plan_json"
        if kind == "plan"
        else "render_production_single_update_run_spec_json"
    )
    monkeypatch.setattr(module, name, lambda *_a, **_kw: TEXT)
    return writer


def _private(tmp_path: Path) -> Path:
    parent = tmp_path / "private-planning-output"
    parent.mkdir(mode=0o700)
    return parent


def _no_legacy(*_args: Any, **_kwargs: Any) -> None:
    raise AssertionError("legacy writer must not be used by POSIX planning output")


def _safe(exc: Exception, path: Path) -> None:
    assert exc.__cause__ is None and exc.__suppress_context__
    rendered = "".join(traceback.format_exception(exc))
    assert str(path) not in rendered and "PRIVATE_OS_MARKER" not in rendered
    assert TEXT not in rendered


@POSIX_ONLY
@pytest.mark.parametrize("kind", KINDS)
def test_real_role_writer_uses_create_only_private_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    writer = _render_only(monkeypatch, kind)
    path = _private(tmp_path) / "artifact.json"
    monkeypatch.setattr(adapter, "atomic_write_private_text", _no_legacy)
    assert writer(object(), path) == path
    assert path.read_bytes() == TEXT.encode("utf-8")
    info = path.stat()
    assert stat.S_IMODE(info.st_mode) == 0o600
    assert info.st_uid == os.geteuid() and info.st_nlink == 1
    assert list(path.parent.iterdir()) == [path]


@POSIX_ONLY
@pytest.mark.parametrize("kind", KINDS)
def test_existing_role_output_is_not_changed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    writer = _render_only(monkeypatch, kind)
    path = _private(tmp_path) / "artifact.json"
    path.write_bytes(b"preserve-existing")
    path.chmod(0o640)
    before = path.stat()
    module, _, error = _role(kind)
    monkeypatch.setattr(adapter, "atomic_write_private_text", _no_legacy)
    with pytest.raises(getattr(module, error)) as caught:
        writer(object(), path)
    assert caught.value.publication_possible is False
    assert path.read_bytes() == b"preserve-existing"
    assert (path.stat().st_ino, path.stat().st_mode) == (before.st_ino, before.st_mode)
    _safe(caught.value, path)


@POSIX_ONLY
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("mode", (0o750, 0o755, 0o770))
def test_role_output_refuses_broad_parent_without_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, mode: int
) -> None:
    writer = _render_only(monkeypatch, kind)
    parent = _private(tmp_path)
    parent.chmod(mode)
    module, _, error = _role(kind)
    with pytest.raises(getattr(module, error)) as caught:
        writer(object(), parent / "artifact.json")
    assert caught.value.publication_possible is False
    assert stat.S_IMODE(parent.stat().st_mode) == mode and list(parent.iterdir()) == []


@POSIX_ONLY
@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("failure", ("link_after", "directory_fsync", "link_collision"))
def test_role_error_after_publication_preserves_flag_and_output_without_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, failure: str
) -> None:
    writer = _render_only(monkeypatch, kind)
    path = _private(tmp_path) / "artifact.json"
    links: list[str] = []
    native_os = backend.os

    def linked(src: str, dst: str, **kwargs: Any) -> None:
        links.append(dst)
        if failure == "link_collision":
            path.write_bytes(b"competitor")
            path.chmod(0o640)
        native_os.link(src, dst, **kwargs)
        if failure == "link_after":
            raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(path))

    def synced(fd: int) -> None:
        if failure == "directory_fsync" and stat.S_ISDIR(native_os.fstat(fd).st_mode):
            raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(path))
        native_os.fsync(fd)

    proxy = SimpleNamespace(**{name: getattr(native_os, name) for name in dir(native_os)})
    proxy.link, proxy.fsync = linked, synced
    monkeypatch.setattr(backend, "os", proxy)
    monkeypatch.setattr(adapter, "atomic_write_private_text", _no_legacy)
    module, _, error = _role(kind)
    with pytest.raises(getattr(module, error)) as caught:
        writer(object(), path)
    assert caught.value.publication_possible is True and links == [path.name]
    assert path.read_bytes() == (b"competitor" if failure == "link_collision" else TEXT.encode())
    assert "Output may exist; do not retry or remove it automatically." in str(caught.value)
    _safe(caught.value, path)


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("state", (False, True, None), ids=("before", "after", "unknown"))
def test_role_exceptions_preserve_three_way_publication_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str, state: bool | None
) -> None:
    writer = _render_only(monkeypatch, kind)
    module, _, error = _role(kind)
    calls: list[int] = []

    def failed(*_args: Any, **_kwargs: Any) -> None:
        calls.append(1)
        raise adapter.PrivateCreateIOError(publication_possible=state)

    monkeypatch.setattr(module, "create_private_text", failed)
    path = tmp_path / "private.json"
    with pytest.raises(getattr(module, error)) as caught:
        writer(object(), path)
    assert caught.value.publication_possible is state and calls == [1]
    assert ("Output may exist" in str(caught.value)) is (state is not False)
    assert caught.value.code == f"production_single_update_{kind}_write_failed"
    _safe(caught.value, path)


@pytest.mark.parametrize("kind", KINDS)
def test_render_failure_never_enters_create_adapter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    module, writer, _ = _role(kind)
    name = (
        "render_production_single_update_plan_json"
        if kind == "plan"
        else "render_production_single_update_run_spec_json"
    )

    def bad_render(*_args: Any, **_kwargs: Any) -> str:
        raise ValueError("synthetic invalid model")

    monkeypatch.setattr(module, name, bad_render)
    monkeypatch.setattr(module, "create_private_text", _no_legacy)
    with pytest.raises(ValueError, match="synthetic invalid model"):
        writer(object(), tmp_path / "not-created")


@pytest.mark.parametrize("platform", ("posix", "nt"))
def test_adapter_retains_exact_utf8_bytes_and_platform_selection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    path = tmp_path / "dispatch.json"
    calls: list[tuple[Any, ...]] = []
    text = '{"synthetic":"\u30b2"}\n'
    monkeypatch.setattr(adapter, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(adapter, "validate_sensitive_output_path", lambda *_a, **_k: path)

    def posix_writer(output: Path, content: bytes) -> None:
        calls.append(("posix", output, content))

    def windows_writer(output: Path, value: str, **kwargs: Any) -> None:
        calls.append(("nt", output, value, kwargs))

    monkeypatch.setattr(adapter.posix_create, "create_posix_private_bytes", posix_writer)
    monkeypatch.setattr(adapter, "atomic_write_private_text", windows_writer)
    adapter.create_private_text(path, text, max_size=1024)
    expected = (
        ("posix", path, text.encode("utf-8"))
        if platform == "posix"
        else ("nt", path, text, {"overwrite": False, "max_size": 1024})
    )
    assert calls == [expected]


@pytest.mark.parametrize("state", (False, True), ids=("before", "after"))
def test_adapter_preserves_posix_error_evidence_without_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: bool
) -> None:
    monkeypatch.setattr(adapter, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(adapter, "validate_sensitive_output_path", lambda value, **_kw: value)
    monkeypatch.setattr(adapter, "atomic_write_private_text", _no_legacy)

    def failed(*_args: Any) -> None:
        raise backend.PosixPrivateCreateError("posix_create_unverified", publication_possible=state)

    monkeypatch.setattr(adapter.posix_create, "create_posix_private_bytes", failed)
    path = tmp_path / "output"
    with pytest.raises(adapter.PrivateCreateIOError) as caught:
        adapter.create_private_text(path, TEXT)
    assert caught.value.publication_possible is state
    _safe(caught.value, path)


@pytest.mark.parametrize("platform", ("posix", "nt"))
def test_unspecified_writer_error_is_unknown_not_no_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    path = tmp_path / "output"
    monkeypatch.setattr(adapter, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(adapter, "validate_sensitive_output_path", lambda value, **_kw: value)
    attempts: list[int] = []

    def failed(*_args: Any, **_kwargs: Any) -> None:
        attempts.append(1)
        raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(path))

    monkeypatch.setattr(adapter.posix_create, "create_posix_private_bytes", failed)
    monkeypatch.setattr(adapter, "atomic_write_private_text", failed)
    with pytest.raises(adapter.PrivateCreateIOError) as caught:
        adapter.create_private_text(path, TEXT)
    assert caught.value.publication_possible is None and attempts == [1]
    _safe(caught.value, path)


@pytest.mark.parametrize(
    "case", ("preflight", "max_zero", "max_over", "too_large", "encoding", "platform")
)
def test_input_or_preflight_failure_stops_before_any_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    path = tmp_path / "output"
    monkeypatch.setattr(adapter.posix_create, "create_posix_private_bytes", _no_legacy)
    monkeypatch.setattr(adapter, "atomic_write_private_text", _no_legacy)
    limit = {"max_zero": 0, "max_over": adapter.MAX_SENSITIVE_FILE_BYTES + 1, "too_large": 1}.get(
        case, 1024
    )
    value = "\ud800" if case == "encoding" else TEXT
    if case == "platform":
        monkeypatch.setattr(adapter, "os", SimpleNamespace(name="unsupported"))
    elif case == "preflight":

        def failed(*_args: Any, **_kwargs: Any) -> Path:
            raise sensitive_paths.SensitivePathError("synthetic", "PRIVATE_OS_MARKER")

        monkeypatch.setattr(adapter, "validate_sensitive_output_path", failed)
    with pytest.raises(adapter.PrivateCreateIOError) as caught:
        adapter.create_private_text(path, value, max_size=limit)
    assert caught.value.publication_possible is False
    assert "PRIVATE_OS_MARKER" not in "".join(traceback.format_exception(caught.value))


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("state", (False, True, None), ids=("before", "after", "unknown"))
def test_cli_receives_role_error_and_never_prints_stored_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: Any, kind: str, state: bool | None
) -> None:
    from tridentine_calendar_google_sync import cli

    _render_only(monkeypatch, kind)
    module, _, _ = _role(kind)
    calls: list[int] = []

    def failed(*_a: Any, **_kw: Any) -> None:
        calls.append(1)
        raise adapter.PrivateCreateIOError(publication_possible=state)

    for name in (
        "load_active_accepted_production_baseline_pin",
        "load_accepted_production_source_manifest",
        "load_accepted_production_profile",
        "inspect_source",
        "load_google_snapshot",
        "load_production_trusted_baseline",
        "load_production_write_target_config",
        "load_production_single_update_plan",
        "build_production_single_update_plan",
        "build_production_single_update_run_spec",
    ):
        monkeypatch.setattr(cli, name, lambda *_a, **_kw: object())
    monkeypatch.setattr(cli, "load_google_optional_bindings", _no_legacy)
    monkeypatch.setattr(module, "create_private_text", failed)
    args = [
        "build-production-single-update-" + kind.replace("_", "-"),
        "--manifest",
        "synthetic-manifest",
        "--source",
        "synthetic-source",
        "--profile",
        "synthetic-profile",
        "--google-snapshot",
        "synthetic-snapshot",
        "--trusted-baseline",
        "synthetic-baseline",
        "--target-config",
        "synthetic-target",
        "--output",
        str(tmp_path / "output"),
    ]
    if kind == "run_spec":
        args.extend(("--production-plan", "synthetic-plan"))
    assert cli.main(args) == cli.EXIT_INVALID_SNAPSHOT
    captured = capsys.readouterr()
    assert not captured.out and "stored" not in captured.err and calls == [1]
    assert ("Output may exist" in captured.err) is (state is not False)
    assert str(tmp_path) not in captured.err


def test_only_reviewed_callers_opt_in_and_common_writer_has_no_new_backend() -> None:
    package = Path(adapter.__file__).parent
    consumers = set()
    for path in package.glob("*.py"):
        if path.name == "_private_create_io.py":
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if any(
            isinstance(node, ast.ImportFrom) and (node.module or "").endswith("._private_create_io")
            for node in ast.walk(tree)
        ):
            consumers.add(path.name)
    assert consumers == {
        "production_single_update_plan_io.py",
        "production_single_update_run_spec_io.py",
        "production_write_token_rehearsal_io.py",
        "production_write_token_io.py",
    }
    common = Path(sensitive_paths.__file__).read_text(encoding="utf-8")
    assert "_private_create_io" not in common and "_posix_private_create" not in common
    tree = ast.parse(Path(adapter.__file__).read_text(encoding="utf-8"))
    attrs = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not attrs & {"unlink", "remove", "replace", "rename", "chmod", "mkdir"}
    assert "overwrite" not in inspect.signature(adapter.create_private_text).parameters
