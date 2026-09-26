"""Synthetic evidence-output tests; no token bundle changes or live API calls."""

from __future__ import annotations

import ast
import errno
import os
import stat
import traceback
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tridentine_calendar_google_sync import _posix_private_create as backend
from tridentine_calendar_google_sync import _private_create_io as adapter
from tridentine_calendar_google_sync import production_write_token_rehearsal_io as outputs
from tridentine_calendar_google_sync import sensitive_paths

POSIX_ONLY = pytest.mark.skipif(os.name != "posix", reason="real POSIX rehearsal output")
SNAPSHOT = '{"synthetic":"snapshot"}\n'
TEXT = "Synthetic rehearsal report\n"
JSON = '{"synthetic":"report"}\n'
FAILURES = (False, True, None, "unexpected")
CASES = ((False, 0), (False, 1), (True, 0), (True, 1), (True, 2))


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "private-rehearsal"
    root.mkdir(mode=0o700)
    return root


def _payloads(with_snapshot: bool) -> list[tuple[str, str]]:
    items = [
        (outputs.PRODUCTION_REHEARSAL_TEXT_REPORT_FILENAME, TEXT),
        (outputs.PRODUCTION_REHEARSAL_JSON_REPORT_FILENAME, JSON),
    ]
    if with_snapshot:
        items.insert(0, (outputs.PRODUCTION_REHEARSAL_SNAPSHOT_FILENAME, SNAPSHOT))
    return items


def _renderers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        outputs, "render_production_write_token_rehearsal_snapshot_json", lambda *_a: SNAPSHOT
    )
    monkeypatch.setattr(
        outputs, "render_production_write_token_rehearsal_report_text", lambda *_a: TEXT
    )
    monkeypatch.setattr(
        outputs, "render_production_write_token_rehearsal_report_json", lambda *_a: JSON
    )


def _call(root: Path, with_snapshot: bool) -> outputs.ProductionWriteTokenRehearsalOutputPaths:
    # Rendering is stubbed; models and golden serialization remain covered by phase6d0 tests.
    return outputs.write_production_write_token_rehearsal_outputs(
        root, object() if with_snapshot else None, object()
    )


def _forbidden(*_a: Any, **_kw: Any) -> None:
    raise AssertionError("unexpected fallback, retry, or write")


def _safe(exc: Exception, root: Path) -> None:
    rendered = "".join(traceback.format_exception(exc))
    assert exc.__cause__ is None and exc.__suppress_context__
    for value in (str(root), "PRIVATE_OS_MARKER", SNAPSHOT, TEXT, JSON):
        assert value not in rendered


@pytest.mark.parametrize("with_snapshot", (False, True), ids=("reports", "snapshot-reports"))
def test_batch_preserves_order_bytes_role_and_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_snapshot: bool
) -> None:
    root = _root(tmp_path)
    _renderers(monkeypatch)
    calls: list[tuple[str, str, str, dict[str, Any]]] = []

    def private(path: Path, text: str, **kwargs: Any) -> None:
        calls.append(("private", path.name, text, kwargs))

    def integrity(path: Path, text: str, **kwargs: Any) -> None:
        calls.append(("integrity", path.name, text, kwargs))

    monkeypatch.setattr(outputs, "create_private_text", private)
    monkeypatch.setattr(outputs, "create_integrity_text", integrity)
    result = _call(root, with_snapshot)
    assert [(name, text) for _, name, text, _ in calls] == _payloads(with_snapshot)
    expected_roles = (
        ["private", "integrity", "integrity"] if with_snapshot else ["integrity", "integrity"]
    )
    assert [role for role, _, _, _ in calls] == expected_roles
    assert all(
        kwargs == {"max_size": outputs.MAX_PRODUCTION_REHEARSAL_OUTPUT_BYTES}
        for _, _, _, kwargs in calls
    )
    assert (result.snapshot is not None) is with_snapshot
    assert result.text_report == root / outputs.PRODUCTION_REHEARSAL_TEXT_REPORT_FILENAME
    assert result.json_report == root / outputs.PRODUCTION_REHEARSAL_JSON_REPORT_FILENAME


@pytest.mark.parametrize("with_snapshot,index", CASES, ids=("r0", "r1", "s0", "s1", "s2"))
@pytest.mark.parametrize("state", FAILURES, ids=("before", "after", "unknown", "unexpected"))
def test_batch_failure_retains_prior_and_uncertain_outputs_and_stops(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    with_snapshot: bool,
    index: int,
    state: bool | str | None,
) -> None:
    root = _root(tmp_path)
    _renderers(monkeypatch)
    attempted: list[str] = []
    payloads = _payloads(with_snapshot)

    def write(path: Path, text: str, **_kwargs: Any) -> None:
        number = len(attempted)
        attempted.append(path.name)
        if number != index or state is not False:
            path.write_text(text, encoding="utf-8", newline="\n")
        if number == index:
            if state == "unexpected":
                raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(root))
            raise adapter.PrivateCreateIOError(publication_possible=state)

    monkeypatch.setattr(outputs, "create_private_text", write)
    monkeypatch.setattr(outputs, "create_integrity_text", write)
    with pytest.raises(outputs.ProductionWriteTokenRehearsalIOError) as caught:
        _call(root, with_snapshot)
    exc = caught.value
    expected = True if index else (None if state == "unexpected" else state)
    assert exc.publication_possible is expected
    assert exc.completed_output_count == index
    assert exc.code == "production_rehearsal_output_write_failed"
    assert ("Outputs may exist" in str(exc)) is (expected is not False)
    assert attempted == [name for name, _ in payloads[: index + 1]]
    for number, (name, text) in enumerate(payloads):
        path = root / name
        exists = number < index or (number == index and state is not False)
        assert path.exists() is exists
        if exists:
            assert path.read_bytes() == text.encode()
    _safe(exc, root)


@pytest.mark.parametrize("collision", (0, 1, 2))
def test_preexisting_any_output_blocks_entire_batch_before_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, collision: int
) -> None:
    root = _root(tmp_path)
    _renderers(monkeypatch)
    name, _ = _payloads(True)[collision]
    existing = root / name
    existing.write_bytes(b"existing-synthetic-output")
    monkeypatch.setattr(outputs, "create_private_text", _forbidden)
    monkeypatch.setattr(outputs, "create_integrity_text", _forbidden)
    with pytest.raises(outputs.ProductionWriteTokenRehearsalIOError) as caught:
        _call(root, True)
    assert caught.value.publication_possible is False
    assert caught.value.completed_output_count == 0
    assert existing.read_bytes() == b"existing-synthetic-output"
    assert list(root.iterdir()) == [existing]
    _safe(caught.value, root)


@pytest.mark.parametrize("role", ("snapshot_json", "report_text", "report_json"))
def test_render_failure_occurs_before_any_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    root = _root(tmp_path)
    _renderers(monkeypatch)

    def bad_render(*_a: Any) -> str:
        raise ValueError("synthetic-render-error")

    monkeypatch.setattr(outputs, "render_production_write_token_rehearsal_" + role, bad_render)
    monkeypatch.setattr(outputs, "create_private_text", _forbidden)
    monkeypatch.setattr(outputs, "create_integrity_text", _forbidden)
    with pytest.raises(ValueError, match="synthetic-render-error"):
        _call(root, True)
    assert list(root.iterdir()) == []


@POSIX_ONLY
@pytest.mark.parametrize("with_snapshot", (False, True), ids=("reports", "snapshot-reports"))
def test_real_posix_batch_uses_private_publisher_without_legacy_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, with_snapshot: bool
) -> None:
    root = _root(tmp_path)
    _renderers(monkeypatch)
    monkeypatch.setattr(adapter, "atomic_write_private_text", _forbidden)
    monkeypatch.setattr(adapter, "atomic_write_integrity_text", _forbidden)
    _call(root, with_snapshot)
    for name, text in _payloads(with_snapshot):
        path = root / name
        assert path.read_bytes() == text.encode()
        info = path.stat()
        assert stat.S_IMODE(info.st_mode) == 0o600
        assert info.st_uid == os.geteuid() and info.st_nlink == 1
    assert sorted(p.name for p in root.iterdir()) == sorted(n for n, _ in _payloads(with_snapshot))


@POSIX_ONLY
@pytest.mark.parametrize("failure_index", (0, 1, 2))
def test_real_posix_post_link_failure_preserves_partial_batch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure_index: int
) -> None:
    root = _root(tmp_path)
    _renderers(monkeypatch)
    native = backend.os
    calls: list[int] = []

    def fsync(fd: int) -> None:
        if stat.S_ISDIR(native.fstat(fd).st_mode):
            index = len(calls)
            calls.append(index)
            if index == failure_index:
                raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(root))
        native.fsync(fd)

    proxy = SimpleNamespace(**{name: getattr(native, name) for name in dir(native)})
    proxy.fsync = fsync
    monkeypatch.setattr(backend, "os", proxy)
    with pytest.raises(outputs.ProductionWriteTokenRehearsalIOError) as caught:
        _call(root, True)
    assert caught.value.publication_possible is True
    assert caught.value.completed_output_count == failure_index
    for index, (name, text) in enumerate(_payloads(True)):
        path = root / name
        assert path.exists() is (index <= failure_index)
        if path.exists():
            assert path.read_bytes() == text.encode()
    assert calls == list(range(failure_index + 1))
    _safe(caught.value, root)


@POSIX_ONLY
@pytest.mark.parametrize("mode", (0o755, 0o750, 0o770))
def test_rehearsal_posix_parent_not_repaired(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: int
) -> None:
    root = _root(tmp_path)
    root.chmod(mode)
    _renderers(monkeypatch)
    with pytest.raises(outputs.ProductionWriteTokenRehearsalIOError) as caught:
        _call(root, True)
    assert caught.value.publication_possible is False
    assert caught.value.completed_output_count == 0
    assert stat.S_IMODE(root.stat().st_mode) == mode and list(root.iterdir()) == []


@pytest.mark.parametrize("platform", ("posix", "nt"))
@pytest.mark.parametrize("private", (False, True), ids=("integrity", "private"))
def test_adapter_selection_retains_windows_roles_and_posix_no_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str, private: bool
) -> None:
    path = tmp_path / "dispatch-only"
    calls: list[tuple[Any, ...]] = []
    monkeypatch.setattr(adapter, "os", SimpleNamespace(name=platform))

    def preflight(value: Path, **kwargs: Any) -> Path:
        assert value == path and kwargs == {"overwrite": False, "windows_private_acl": private}
        return path

    def posix_writer(output: Path, content: bytes) -> None:
        calls.append(("posix", output, content))

    def writer(output: Path, text: str, **kwargs: Any) -> None:
        calls.append(("windows", output, text, kwargs))

    monkeypatch.setattr(adapter, "validate_sensitive_output_path", preflight)
    monkeypatch.setattr(backend, "create_posix_private_bytes", posix_writer)
    monkeypatch.setattr(adapter, "atomic_write_private_text", writer if private else _forbidden)
    monkeypatch.setattr(adapter, "atomic_write_integrity_text", _forbidden if private else writer)
    selected = adapter.create_private_text if private else adapter.create_integrity_text
    text = '{"synthetic":"\u30b2"}\n'
    selected(path, text, max_size=1024)
    expected = (
        ("posix", path, text.encode())
        if platform == "posix"
        else ("windows", path, text, {"overwrite": False, "max_size": 1024})
    )
    assert calls == [expected]


@pytest.mark.parametrize("platform", ("posix", "nt"))
def test_integrity_unspecified_error_retains_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    path = tmp_path / "not-real"
    monkeypatch.setattr(adapter, "os", SimpleNamespace(name=platform))
    monkeypatch.setattr(adapter, "validate_sensitive_output_path", lambda *_a, **_kw: path)

    def failed(*_a: Any, **_kw: Any) -> None:
        raise OSError(errno.EIO, "PRIVATE_OS_MARKER", str(tmp_path))

    monkeypatch.setattr(backend, "create_posix_private_bytes", failed)
    monkeypatch.setattr(adapter, "atomic_write_integrity_text", failed)
    monkeypatch.setattr(adapter, "atomic_write_private_text", _forbidden)
    with pytest.raises(adapter.PrivateCreateIOError) as caught:
        adapter.create_integrity_text(path, TEXT)
    assert caught.value.publication_possible is None
    _safe(caught.value, tmp_path)


@pytest.mark.parametrize("state", (False, True), ids=("before", "after"))
def test_integrity_posix_error_evidence_retained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, state: bool
) -> None:
    path = tmp_path / "not-real"
    monkeypatch.setattr(adapter, "os", SimpleNamespace(name="posix"))
    monkeypatch.setattr(adapter, "validate_sensitive_output_path", lambda *_a, **_kw: path)

    def failed(*_a: Any) -> None:
        raise backend.PosixPrivateCreateError("synthetic", publication_possible=state)

    monkeypatch.setattr(backend, "create_posix_private_bytes", failed)
    monkeypatch.setattr(adapter, "atomic_write_integrity_text", _forbidden)
    with pytest.raises(adapter.PrivateCreateIOError) as caught:
        adapter.create_integrity_text(path, TEXT)
    assert caught.value.publication_possible is state


def test_rehearsal_io_has_no_legacy_writer_retry_delete_or_replace() -> None:
    tree = ast.parse(Path(outputs.__file__).read_text(encoding="utf-8"))
    names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    attrs = {
        node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert not names & {
        "atomic_write_private_text",
        "atomic_write_integrity_text",
        "remove_sensitive_file_if_matches",
    }
    assert not attrs & {"unlink", "remove", "replace", "rename", "chmod", "mkdir"}
    assert "_private_create_io" not in Path(sensitive_paths.__file__).read_text(encoding="utf-8")


def test_live_rehearsal_cli_remains_hard_off_without_new_io_calls() -> None:
    path = Path(outputs.__file__).with_name("cli.py")
    tree = ast.parse(path.read_text(encoding="utf-8"))
    fn = next(
        node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
        and node.name == "_rehearse_production_write_token_readonly_command"
    )
    strings = [
        node.value
        for node in ast.walk(fn)
        if isinstance(node, ast.Constant) and isinstance(node.value, str)
    ]
    assert any("production_live_rehearsal_not_available_in_phase_6d0" in item for item in strings)
    calls = {
        node.func.id
        for node in ast.walk(fn)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not calls


def test_preflight_error_suppresses_paths_and_marks_no_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _root(tmp_path)

    def fail(*_a: Any, **_kw: Any) -> None:
        raise sensitive_paths.SensitivePathError("synthetic", "PRIVATE_OS_MARKER " + str(root))

    monkeypatch.setattr(outputs, "validate_sensitive_output_path", fail)
    monkeypatch.setattr(outputs, "create_private_text", _forbidden)
    monkeypatch.setattr(outputs, "create_integrity_text", _forbidden)
    with pytest.raises(outputs.ProductionWriteTokenRehearsalIOError) as caught:
        _call(root, True)
    assert caught.value.publication_possible is False
    assert caught.value.completed_output_count == 0
    _safe(caught.value, root)


@pytest.mark.skipif(os.name != "nt", reason="real Windows private/integrity ACLs")
def test_windows_snapshot_private_and_report_integrity_policy_retained(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from windows_sensitive_fs_helpers import set_private_file_acl

    root = _root(tmp_path)
    _renderers(monkeypatch)
    monkeypatch.setattr(backend, "create_posix_private_bytes", _forbidden)
    paths = _call(root, True)
    assert paths.snapshot is not None
    assert sensitive_paths.read_private_sensitive_bytes(paths.snapshot) == SNAPSHOT.encode()
    set_private_file_acl(paths.text_report, broad_principal="BU")
    assert (
        sensitive_paths.read_sensitive_bytes(paths.text_report, windows_integrity_acl=True)
        == TEXT.encode()
    )
    with pytest.raises(sensitive_paths.SensitivePathError):
        sensitive_paths.read_private_sensitive_bytes(paths.text_report)
    set_private_file_acl(paths.text_report, broad_principal="BU", broad_rights="GRGW")
    with pytest.raises(sensitive_paths.SensitivePathError):
        sensitive_paths.read_sensitive_bytes(paths.text_report, windows_integrity_acl=True)
