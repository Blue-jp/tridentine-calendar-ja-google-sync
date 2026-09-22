"""Synthetic start-record checks; no credential reuse or durability approval."""

from __future__ import annotations

import ast
import copy
import inspect
import json
import os
import pickle
import stat
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, fields, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tridentine_calendar_google_sync import production_write_token_operation_record as records

LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="real Linux record persistence")
S = records.RecordState
K = records.OperationKind
LEAF = "production-write-operation-start-v1.json"
KEYS = (
    "format_version",
    "record_kind",
    "storage_ref",
    "pair_ref",
    "role",
    "token_slot",
    "state_slot",
    "operation_id",
    "predecessor_id",
    "operation_kind",
    "phase",
    "outcome",
)


def _binding(directory: Path | None = None) -> records.SyntheticBinding:
    if directory is None:
        directory = Path("C:/synthetic-record-fixture" if os.name == "nt" else "/synthetic-record")
    return records.SyntheticBinding(directory, "store-example", "pair-example", "token", "state")


def _operation(kind: records.OperationKind = K.NEW_PAIR) -> records.RecordOperation:
    return records.RecordOperation(
        "operation-b", None if kind is K.NEW_PAIR else "operation-a", kind
    )


def _data(kind: records.OperationKind = K.NEW_PAIR) -> dict[str, object]:
    return {
        "format_version": 1,
        "record_kind": "production_write_operation_start",
        "storage_ref": "store-example",
        "pair_ref": "pair-example",
        "role": "production_write",
        "token_slot": "token",
        "state_slot": "state",
        "operation_id": "operation-b",
        "predecessor_id": None if kind is K.NEW_PAIR else "operation-a",
        "operation_kind": kind.value,
        "phase": "started",
        "outcome": "incomplete",
    }


def _wire(data: object) -> bytes:
    return (
        json.dumps(data, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()


def _deny(*_args: Any, **_kwargs: Any) -> Any:
    raise AssertionError("unexpected storage or path access")


def _assert_result(
    result: records.RecordResult, state: records.RecordState, publication: bool | None = False
) -> None:
    assert result.state is state
    assert result.publication_possible is publication
    assert result.reuse_authorized is False
    assert {field.name for field in fields(result)} == {
        "state",
        "publication_possible",
        "reuse_authorized",
    }


@pytest.mark.parametrize("kind", (K.NEW_PAIR, K.REFRESH))
def test_canonical_codec_has_exact_closed_fields_and_no_directory(
    kind: records.OperationKind,
) -> None:
    binding, operation = _binding(), _operation(kind)
    raw = records._encode_start_record(binding, operation)
    assert raw == _wire(_data(kind))
    assert set(json.loads(raw)) == set(KEYS)
    assert records.RECORD_LEAF == LEAF and records.MAX_RECORD_BYTES == 4096
    assert len(raw) <= 4096 and raw.endswith(b"\n") and not raw.endswith(b"\n\n")
    assert b"\r" not in raw and not raw.startswith(b"\xef\xbb\xbf")
    assert str(binding.directory).encode() not in raw
    assert records._matches_start_record(raw, binding, operation)
    assert records._matches_start_record(raw, _binding(), _operation(kind))


@pytest.mark.parametrize("key", KEYS)
def test_every_required_field_is_required(key: str) -> None:
    data = _data()
    del data[key]
    assert not records._matches_start_record(_wire(data), _binding(), _operation())


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("value", ([], {}, True, 1.5), ids=("array", "object", "boolean", "float"))
def test_wrong_types_are_not_coerced(key: str, value: object) -> None:
    data = _data()
    data[key] = value
    assert not records._matches_start_record(_wire(data), _binding(), _operation())


@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("same", (False, True), ids=("conflicting", "identical"))
def test_duplicate_keys_never_establish_a_record(key: str, same: bool) -> None:
    data = _data()
    extra = _wire({key: data[key] if same else "unexpected"})[1:-2]
    raw = b"{" + extra + b"," + _wire(data)[1:]
    assert not records._matches_start_record(raw, _binding(), _operation())


@pytest.mark.parametrize(
    ("key", "value"),
    (
        ("format_version", 2),
        ("format_version", "1"),
        ("record_kind", "completion"),
        ("role", "production_read"),
        ("role", "test_write"),
        ("operation_kind", "recovery"),
        ("operation_kind", "retry"),
        ("phase", "completed"),
        ("outcome", "approved"),
        ("unexpected", "field"),
        ("predecessor_id", "operation-a"),
        ("predecessor_id", "operation-b"),
    ),
)
def test_unknown_and_forbidden_closed_values_are_rejected(key: str, value: object) -> None:
    data = _data()
    data[key] = value
    assert not records._matches_start_record(_wire(data), _binding(), _operation())


@pytest.mark.parametrize(
    "raw",
    (
        b"",
        b"[]\n",
        b"null\n",
        b"true\n",
        b"1\n",
        b'"record"\n',
        b"{\xff}\n",
        b"NaN\n",
        b"Infinity\n",
        b"-Infinity\n",
        b"{" + b"x" * 4096,
    ),
    ids=(
        "empty",
        "array",
        "null",
        "bool",
        "number",
        "string",
        "invalid-utf8",
        "nan",
        "infinity",
        "negative-infinity",
        "oversize",
    ),
)
def test_invalid_json_and_preparse_size_boundary(raw: bytes) -> None:
    assert not records._matches_start_record(raw, _binding(), _operation())


@pytest.mark.parametrize("constant", (float("nan"), float("inf"), float("-inf")))
def test_nonfinite_constants_inside_object_are_rejected(constant: float) -> None:
    data = _data()
    data["format_version"] = constant
    assert not records._matches_start_record(_wire(data), _binding(), _operation())


@pytest.mark.parametrize("representation", ("bom", "crlf", "no-lf", "two-lf", "spaces", "order"))
def test_noncanonical_equivalent_representations_are_rejected(representation: str) -> None:
    raw = _wire(_data())
    alternatives = {
        "bom": b"\xef\xbb\xbf" + raw,
        "crlf": raw[:-1] + b"\r\n",
        "no-lf": raw[:-1],
        "two-lf": raw + b"\n",
        "spaces": (json.dumps(_data(), sort_keys=True) + "\n").encode(),
        "order": (json.dumps(_data(), separators=(",", ":")) + "\n").encode(),
    }
    assert not records._matches_start_record(alternatives[representation], _binding(), _operation())


@pytest.mark.parametrize(
    "raw", (None, True, 1, "arbitrary-input", bytearray(b"{}"), memoryview(b"{}"))
)
def test_nonbytes_are_rejected_without_reflection(raw: object) -> None:
    assert records._matches_start_record(raw, _binding(), _operation()) is False


@pytest.mark.parametrize(
    "value",
    (
        "",
        "a" * 97,
        " padded",
        "padded ",
        ".hidden",
        "_prefix",
        "-prefix",
        "a/b",
        "a\\b",
        "a:b",
        "a\x00b",
        "a\nb",
        "caf\u00e9",
    ),
    ids=(
        "empty",
        "long",
        "leading-space",
        "trailing-space",
        "dot-prefix",
        "underscore-prefix",
        "dash-prefix",
        "slash",
        "backslash",
        "colon",
        "nul",
        "newline",
        "nonascii",
    ),
)
@pytest.mark.parametrize("field", ("storage_ref", "pair_ref", "token_slot", "state_slot"))
def test_invalid_binding_references_raise_only_fixed_codec_error(field: str, value: str) -> None:
    binding = replace(_binding(), **{field: value})
    with pytest.raises(records._RecordFormatError) as caught:
        records._encode_start_record(binding, _operation())
    assert value not in repr(binding) if value else True
    assert str(binding.directory) not in str(caught.value)
    assert not records._matches_start_record(_wire(_data()), binding, _operation())


@pytest.mark.parametrize("field", ("storage_ref", "pair_ref", "token_slot", "state_slot"))
def test_longest_allowed_references_remain_canonical(field: str) -> None:
    binding = replace(_binding(), **{field: "A" + "z._-9" * 19})
    raw = records._encode_start_record(binding, _operation())
    assert len(json.loads(raw)[field]) == 96
    assert records._matches_start_record(raw, binding, _operation())


@pytest.mark.parametrize("slot", ("state", LEAF))
def test_slot_collisions_are_rejected(slot: str) -> None:
    with pytest.raises(records._RecordFormatError):
        records._encode_start_record(replace(_binding(), token_slot=slot), _operation())
    with pytest.raises(records._RecordFormatError):
        records._encode_start_record(replace(_binding(), state_slot=LEAF), _operation())


@pytest.mark.parametrize("slot", ("token.", "CON", "NUL.json", "LPT1", "COM9.dat", ".."))
def test_unsafe_leaf_aliases_are_not_normalized(slot: str) -> None:
    with pytest.raises(records._RecordFormatError):
        records._encode_start_record(replace(_binding(), token_slot=slot), _operation())


@pytest.mark.parametrize(
    ("operation_id", "predecessor", "kind"),
    (
        ("", None, K.NEW_PAIR),
        ("bad/id", None, K.NEW_PAIR),
        ("a" * 97, None, K.NEW_PAIR),
        ("operation-b", "operation-a", K.NEW_PAIR),
        ("operation-b", None, K.REFRESH),
        ("operation-b", "operation-b", K.REFRESH),
        ("operation-b", "bad/id", K.REFRESH),
        ("operation-b", None, "new_pair"),
        (True, None, K.NEW_PAIR),
    ),
)
def test_operation_kind_and_predecessor_structure_are_not_inferred(
    operation_id: Any, predecessor: Any, kind: Any
) -> None:
    operation = records.RecordOperation(operation_id, predecessor, kind)
    with pytest.raises(records._RecordFormatError):
        records._encode_start_record(_binding(), operation)
    assert not records._matches_start_record(_wire(_data()), _binding(), operation)


@pytest.mark.parametrize("field", ("storage_ref", "pair_ref", "token_slot", "state_slot"))
def test_expected_binding_mismatch_never_matches(field: str) -> None:
    expected = replace(_binding(), **{field: "different"})
    assert not records._matches_start_record(_wire(_data()), expected, _operation())


@pytest.mark.parametrize("field", ("operation_id", "predecessor_id"))
def test_expected_refresh_operation_mismatch_never_matches(field: str) -> None:
    expected = replace(_operation(K.REFRESH), **{field: "different"})
    assert not records._matches_start_record(_wire(_data(K.REFRESH)), _binding(), expected)


def test_size_checks_precede_json_parse_and_bound_encoded_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with monkeypatch.context() as scoped:
        scoped.setattr(records.json, "loads", _deny)
        assert not records._matches_start_record(b" " * 4097, _binding(), _operation())
    with monkeypatch.context() as scoped:
        scoped.setattr(records.json, "dumps", lambda *_a, **_kw: "x" * 4096)
        with pytest.raises(records._RecordFormatError):
            records._encode_start_record(_binding(), _operation())


@pytest.mark.parametrize("state", tuple(S))
@pytest.mark.parametrize("publication", (False, True, None))
def test_all_result_states_are_frozen_and_never_authorize(
    state: records.RecordState, publication: bool | None
) -> None:
    result = records.RecordResult(state, publication)
    _assert_result(result, state, publication)
    with pytest.raises(TypeError):
        records.RecordResult(state, reuse_authorized=True)
    with pytest.raises(FrozenInstanceError):
        result.reuse_authorized = True


def test_input_reprs_and_codec_errors_do_not_echo_values_or_paths() -> None:
    marker = "SYNTHETIC_PRIVATE_DIAGNOSTIC"
    binding = replace(_binding(), storage_ref=marker + "/invalid")
    operation = records.RecordOperation(marker + "/invalid", None, K.NEW_PAIR)
    with pytest.raises(records._RecordFormatError) as caught:
        records._encode_start_record(binding, operation)
    rendered = repr(binding) + repr(operation) + str(caught.value) + repr(caught.value)
    assert marker not in rendered and str(binding.directory) not in rendered
    assert caught.value.__cause__ is None


@pytest.mark.parametrize("value", ("SYNTHETIC_PRIVATE_RESULT", 0, 1, object()))
def test_result_constructor_rejects_arbitrary_state_and_nonboolean_evidence(value: object) -> None:
    with pytest.raises(ValueError, match=r"^Invalid operation-record result$"):
        records.RecordResult(value)
    with pytest.raises(ValueError, match=r"^Invalid operation-record result$"):
        records.RecordResult(S.UNVERIFIABLE, value)


@pytest.mark.parametrize("platform", ("win32", "darwin", "freebsd14"))
def test_unsupported_platform_stops_before_even_path_or_binding_checks(
    monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    monkeypatch.setattr(records, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(records.private_lock, "acquire_posix_private_directory_lock", _deny)
    monkeypatch.setattr(records.private_create, "create_posix_private_bytes", _deny)
    monkeypatch.setattr(records, "read_private_sensitive_bytes", _deny)
    monkeypatch.setattr(records, "validate_sensitive_output_path", _deny)
    monkeypatch.setattr(Path, "lstat", _deny)
    for function in (records.create_start_record, records.read_start_record):
        _assert_result(function(object(), object()), S.UNSUPPORTED_PLATFORM)


def _imports(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            names.add(module)
            names.update(module + "." + alias.name for alias in node.names)
    return names


def test_only_exact_reviewed_modules_directly_import_lock_and_publisher() -> None:
    parent = Path(records.__file__).parent
    expected = {
        "_posix_private_lock": {"production_write_token.py", Path(records.__file__).name},
        "_posix_private_create": {
            "_private_create_io.py",
            "_posix_private_replace.py",
            Path(records.__file__).name,
        },
    }
    for dependency, allowed in expected.items():
        consumers = set()
        for path in parent.glob("*.py"):
            if path.name == dependency + ".py":
                continue
            imports = _imports(ast.parse(path.read_text(encoding="utf-8")))
            if "tridentine_calendar_google_sync." + dependency in imports:
                consumers.add(path.name)
        assert consumers == allowed


def test_component_has_no_runtime_consumer_or_dynamic_import_and_no_mutation_escape() -> None:
    path = Path(records.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    imports = _imports(tree)
    allowed_local = {
        "tridentine_calendar_google_sync",
        "tridentine_calendar_google_sync._posix_private_create",
        "tridentine_calendar_google_sync._posix_private_lock",
        "tridentine_calendar_google_sync.sensitive_paths",
        "tridentine_calendar_google_sync.sensitive_paths.read_private_sensitive_bytes",
        "tridentine_calendar_google_sync.sensitive_paths.validate_sensitive_output_path",
        "tridentine_calendar_google_sync.sensitive_paths.SensitivePathError",
    }
    assert {
        name for name in imports if name.startswith("tridentine_calendar_google_sync")
    } <= allowed_local
    assert not {name.split(".")[0] for name in imports} & {
        "importlib",
        "subprocess",
        "socket",
        "requests",
        "urllib",
        "google",
        "random",
        "secrets",
    }
    calls = {
        node.func.id if isinstance(node.func, ast.Name) else node.func.attr
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute))
    }
    assert not calls & {
        "__import__",
        "getattr",
        "eval",
        "exec",
        "compile",
        "print",
        "input",
        "open",
        "unlink",
        "remove",
        "rename",
        "replace",
        "mkdir",
        "rmdir",
        "chmod",
        "chown",
        "write_bytes",
        "write_text",
        "getenv",
        "sleep",
        "resolve",
        "authorize",
        "refresh",
        "sha256",
        "sha1",
        "run",
        "Popen",
        "connect",
        "socket",
    }
    assert not any(
        isinstance(node, (ast.Global, ast.Nonlocal, ast.While)) for node in ast.walk(tree)
    )
    for module in path.parent.glob("*.py"):
        if module != path:
            assert "production_write_token_operation_record" not in module.read_text(
                encoding="utf-8"
            )


def _private(tmp_path: Path) -> records.SyntheticBinding:
    root = tmp_path / "synthetic-start-record"
    root.mkdir(mode=0o700)
    return _binding(root)


@LINUX_ONLY
@pytest.mark.parametrize("kind", (K.NEW_PAIR, K.REFRESH))
def test_real_create_then_separate_call_read_remains_incomplete(
    tmp_path: Path, kind: records.OperationKind
) -> None:
    binding, operation = _private(tmp_path), _operation(kind)
    _assert_result(records.create_start_record(binding, operation), S.START_CONFIRMED, True)
    path = binding.directory / LEAF
    assert path.read_bytes() == _wire(_data(kind))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and path.stat().st_nlink == 1
    assert path.stat().st_uid == os.geteuid()
    assert [item.name for item in binding.directory.iterdir()] == [LEAF]
    _assert_result(
        records.read_start_record(replace(binding), replace(operation)), S.START_OBSERVED
    )


@LINUX_ONLY
@pytest.mark.parametrize(
    "occupied",
    ("same", "different", "different-id", "directory", "dangling", "symlink", "hardlink"),
)
def test_occupied_slot_is_never_overwritten_or_idempotent(tmp_path: Path, occupied: str) -> None:
    binding, operation = _private(tmp_path), _operation()
    path = binding.directory / LEAF
    target = binding.directory / "unrelated"
    if occupied == "directory":
        path.mkdir(mode=0o700)
    elif occupied in ("dangling", "symlink"):
        if occupied == "symlink":
            target.write_bytes(b"synthetic unrelated")
        path.symlink_to(target)
    else:
        raw = _wire(_data()) if occupied != "different" else b"unrelated synthetic bytes"
        path.write_bytes(raw)
        path.chmod(0o600)
        if occupied == "hardlink":
            os.link(path, target)
    if occupied == "different-id":
        operation = replace(operation, operation_id="operation-c")
    before = path.lstat()
    result = records.create_start_record(binding, operation)
    _assert_result(result, S.SLOT_OCCUPIED)
    after = path.lstat()
    assert (before.st_ino, before.st_mode, before.st_size, before.st_mtime_ns) == (
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
    )


@LINUX_ONLY
@pytest.mark.parametrize("mode", (0o400, 0o600, 0o700))
def test_reader_owner_only_policy_is_not_exact_creation_mode(tmp_path: Path, mode: int) -> None:
    binding, operation = _private(tmp_path), _operation()
    _assert_result(records.create_start_record(binding, operation), S.START_CONFIRMED, True)
    path = binding.directory / LEAF
    path.chmod(mode)
    _assert_result(records.read_start_record(binding, operation), S.START_OBSERVED)
    assert stat.S_IMODE(path.stat().st_mode) == mode


@LINUX_ONLY
@pytest.mark.parametrize(
    "kind", ("absent", "corrupt", "foreign", "large", "permissions", "hardlink", "symlink")
)
def test_reader_refuses_unverified_or_unsafe_record_without_repair(
    tmp_path: Path, kind: str
) -> None:
    binding, operation = _private(tmp_path), _operation()
    path = binding.directory / LEAF
    if kind != "absent":
        raw = _wire(_data())
        if kind == "corrupt":
            raw = b"{SYNTHETIC_PRIVATE_FAILURE"
        elif kind == "foreign":
            raw = _wire({**_data(), "pair_ref": "foreign-pair"})
        elif kind == "large":
            raw = b" " * 4097
        path.write_bytes(raw)
        path.chmod(0o640 if kind == "permissions" else 0o600)
        if kind == "hardlink":
            os.link(path, binding.directory / "alias")
        elif kind == "symlink":
            path.rename(binding.directory / "original")
            path.symlink_to(binding.directory / "original")
    _assert_result(records.read_start_record(binding, operation), S.UNVERIFIABLE)
    assert path.exists() is (kind != "absent")
    if kind == "permissions":
        assert stat.S_IMODE(path.stat().st_mode) == 0o640


@LINUX_ONLY
@pytest.mark.parametrize(
    "kind",
    (
        "relative",
        "parent",
        "nul",
        "double-root",
        "missing",
        "public",
        "symlink",
        "git-directory",
        "git-file",
    ),
)
def test_unsafe_directory_never_publishes_or_repairs(tmp_path: Path, kind: str) -> None:
    binding = _private(tmp_path)
    root = binding.directory
    if kind == "relative":
        binding = replace(binding, directory=Path("relative"))
    elif kind == "parent":
        binding = replace(binding, directory=root / ".." / root.name)
    elif kind == "nul":
        binding = replace(binding, directory=root / "bad\x00leaf")
    elif kind == "double-root":
        binding = replace(binding, directory=Path("//synthetic/record"))
    elif kind == "missing":
        binding = replace(binding, directory=root / "missing")
    elif kind == "public":
        root.chmod(0o755)
    elif kind == "symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(root, target_is_directory=True)
        binding = replace(binding, directory=alias)
    elif kind == "git-directory":
        (root / ".git").mkdir()
    else:
        (root / ".git").write_bytes(b"synthetic worktree marker")
    for function in (records.create_start_record, records.read_start_record):
        result = function(binding, _operation())
        assert result.state in {S.UNVERIFIABLE, S.LOCK_UNAVAILABLE}
        assert result.publication_possible is False and result.reuse_authorized is False
    assert not (root / LEAF).exists()
    if kind == "public":
        assert stat.S_IMODE(root.stat().st_mode) == 0o755


@LINUX_ONLY
def test_real_outer_lock_causes_busy_without_reentrant_fallback(tmp_path: Path) -> None:
    binding = _private(tmp_path)
    with records.private_lock.acquire_posix_private_directory_lock(binding.directory):
        for function in (records.create_start_record, records.read_start_record):
            _assert_result(function(binding, _operation()), S.LOCK_BUSY)
    assert list(binding.directory.iterdir()) == []


@LINUX_ONLY
@pytest.mark.parametrize("create", (False, True))
def test_one_owned_lock_covers_io_and_success_follows_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, create: bool
) -> None:
    binding, operation = _private(tmp_path), _operation()
    if not create:
        _assert_result(records.create_start_record(binding, operation), S.START_CONFIRMED, True)
    native_lock = records.private_lock.acquire_posix_private_directory_lock
    native_read = records.read_private_sensitive_bytes
    native_result = records.RecordResult
    events = []
    active = []

    @contextmanager
    def held(path: Path) -> Iterator[Any]:
        events.append("acquire")
        with native_lock(path) as lock:
            active.append(True)
            yield lock
            active.clear()
        events.append("exit")

    def read(path: Path, *, max_size: int) -> bytes:
        assert active == [True] and max_size == 4096 and path == binding.directory / LEAF
        events.append("read")
        return native_read(path, max_size=max_size)

    def result(state: records.RecordState, publication_possible: bool | None = False) -> Any:
        if state in {S.START_CONFIRMED, S.START_OBSERVED}:
            assert not active and events[-1] == "exit"
        return native_result(state, publication_possible)

    monkeypatch.setattr(records.private_lock, "acquire_posix_private_directory_lock", held)
    monkeypatch.setattr(records, "read_private_sensitive_bytes", read)
    monkeypatch.setattr(records, "RecordResult", result)
    function = records.create_start_record if create else records.read_start_record
    _assert_result(
        function(binding, operation), S.START_CONFIRMED if create else S.START_OBSERVED, create
    )
    assert events == ["acquire", "read", "exit"]


@LINUX_ONLY
@pytest.mark.parametrize(
    "code",
    (
        "posix_directory_lock_busy",
        "posix_directory_lock_unavailable",
        "posix_directory_lock_unverified",
    ),
)
def test_lock_acquisition_failure_never_enters_record_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: str
) -> None:
    binding = _private(tmp_path)

    def fail(_path: Path) -> Any:
        raise records.private_lock.PosixPrivateLockError(code)

    monkeypatch.setattr(records.private_lock, "acquire_posix_private_directory_lock", fail)
    monkeypatch.setattr(records.private_create, "create_posix_private_bytes", _deny)
    monkeypatch.setattr(records, "read_private_sensitive_bytes", _deny)
    for function in (records.create_start_record, records.read_start_record):
        _assert_result(
            function(binding, _operation()),
            S.LOCK_BUSY if code.endswith("busy") else S.LOCK_UNAVAILABLE,
        )


@LINUX_ONLY
@pytest.mark.parametrize("evidence", (False, True, None, 0, 1, "invalid"))
def test_publisher_called_once_and_only_formal_boolean_evidence_survives(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, evidence: object
) -> None:
    binding = _private(tmp_path)
    calls = []

    def fail(_path: Path, _raw: bytes) -> None:
        calls.append(1)
        error = records.private_create.PosixPrivateCreateError("synthetic")
        error.publication_possible = evidence
        raise error

    monkeypatch.setattr(records.private_create, "create_posix_private_bytes", fail)
    result = records.create_start_record(binding, _operation())
    _assert_result(result, S.PERSISTENCE_UNCERTAIN, evidence if type(evidence) is bool else None)
    assert calls == [1] and list(binding.directory.iterdir()) == []


@LINUX_ONLY
@pytest.mark.parametrize("after_publication", (False, True))
def test_unknown_publisher_exception_never_echoes_input_or_retries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, after_publication: bool
) -> None:
    binding = _private(tmp_path)
    native = records.private_create.create_posix_private_bytes
    calls = []

    def fail(path: Path, raw: bytes) -> None:
        calls.append(1)
        if after_publication:
            native(path, raw)
        raise OSError("SYNTHETIC_PRIVATE_FAILURE " + str(path))

    monkeypatch.setattr(records.private_create, "create_posix_private_bytes", fail)
    result = records.create_start_record(binding, _operation())
    _assert_result(result, S.PERSISTENCE_UNCERTAIN, None)
    assert calls == [1] and (binding.directory / LEAF).exists() is after_publication
    assert "SYNTHETIC_PRIVATE_FAILURE" not in repr(result) and str(binding.directory) not in repr(
        result
    )


@LINUX_ONLY
@pytest.mark.parametrize("failure", ("error", "mismatch", "oversize"))
def test_postpublication_readback_failure_retains_final_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    binding = _private(tmp_path)

    def read(_path: Path, *, max_size: int) -> bytes:
        assert max_size == 4096
        if failure == "error":
            raise OSError("SYNTHETIC_PRIVATE_FAILURE")
        return b" " * 4097 if failure == "oversize" else _wire({**_data(), "pair_ref": "foreign"})

    monkeypatch.setattr(records, "read_private_sensitive_bytes", read)
    _assert_result(
        records.create_start_record(binding, _operation()), S.PERSISTENCE_UNCERTAIN, True
    )
    assert (binding.directory / LEAF).read_bytes() == _wire(_data())


@LINUX_ONLY
@pytest.mark.parametrize("failure", ("checkpoint", "exit"))
def test_success_is_not_returned_before_final_checkpoint_and_context_exit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    binding = _private(tmp_path)
    native_lock = records.private_lock.acquire_posix_private_directory_lock
    original_read = records.read_private_sensitive_bytes
    observed = []

    def read(path: Path, *, max_size: int) -> bytes:
        observed.append("read")
        return original_read(path, max_size=max_size)

    @contextmanager
    def held(path: Path) -> Iterator[Any]:
        with native_lock(path) as lock:

            def checkpoint() -> None:
                lock.revalidate()
                if observed and failure == "checkpoint":
                    raise records.private_lock.PosixPrivateLockError(
                        "posix_directory_lock_unverified"
                    )

            yield SimpleNamespace(revalidate=checkpoint)
        if failure == "exit":
            raise OSError("SYNTHETIC_PRIVATE_EXIT")

    monkeypatch.setattr(records, "read_private_sensitive_bytes", read)
    monkeypatch.setattr(records.private_lock, "acquire_posix_private_directory_lock", held)
    _assert_result(
        records.create_start_record(binding, _operation()), S.PERSISTENCE_UNCERTAIN, True
    )
    assert (binding.directory / LEAF).read_bytes() == _wire(_data())


@LINUX_ONLY
def test_later_exit_error_does_not_erase_formal_publisher_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = _private(tmp_path)
    native_lock = records.private_lock.acquire_posix_private_directory_lock

    @contextmanager
    def held(path: Path) -> Iterator[Any]:
        with native_lock(path) as lock:
            try:
                yield lock
            finally:
                raise OSError("SYNTHETIC_PRIVATE_EXIT")

    def fail(_path: Path, _raw: bytes) -> None:
        raise records.private_create.PosixPrivateCreateError(
            "synthetic", publication_possible=False
        )

    monkeypatch.setattr(records.private_lock, "acquire_posix_private_directory_lock", held)
    monkeypatch.setattr(records.private_create, "create_posix_private_bytes", fail)
    _assert_result(
        records.create_start_record(binding, _operation()), S.PERSISTENCE_UNCERTAIN, False
    )


@LINUX_ONLY
@pytest.mark.parametrize("stage", ("publish", "readback"))
def test_cancellation_is_not_recast_as_success_or_an_ordinary_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    binding = _private(tmp_path)

    def interrupted(*_args: Any, **_kwargs: Any) -> Any:
        raise KeyboardInterrupt

    if stage == "publish":
        monkeypatch.setattr(records.private_create, "create_posix_private_bytes", interrupted)
    else:
        monkeypatch.setattr(records, "read_private_sensitive_bytes", interrupted)
    with pytest.raises(KeyboardInterrupt):
        records.create_start_record(binding, _operation())
    with records.private_lock.acquire_posix_private_directory_lock(binding.directory):
        assert (binding.directory / LEAF).exists() is (stage == "readback")


@LINUX_ONLY
def test_token_and_state_sentinels_are_never_read_or_modified(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = _private(tmp_path)
    sentinel_paths = {
        binding.directory / binding.token_slot,
        binding.directory / binding.state_slot,
    }
    for path in sentinel_paths:
        path.write_bytes(b"synthetic sentinel only")
    before = {path: path.stat() for path in sentinel_paths}
    native_open = os.open

    def opened(path: Any, *args: Any, **kwargs: Any) -> int:
        assert str(path) not in {binding.token_slot, binding.state_slot}
        assert path not in sentinel_paths
        return native_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", opened)
    _assert_result(records.create_start_record(binding, _operation()), S.START_CONFIRMED, True)
    _assert_result(records.read_start_record(binding, _operation()), S.START_OBSERVED)
    for path in sentinel_paths:
        assert path.stat() == before[path]


@LINUX_ONLY
def test_synthetic_downstream_failure_does_not_clear_start(tmp_path: Path) -> None:
    binding = _private(tmp_path)
    _assert_result(records.create_start_record(binding, _operation()), S.START_CONFIRMED, True)
    with pytest.raises(RuntimeError, match="synthetic downstream failure"):
        raise RuntimeError("synthetic downstream failure")
    _assert_result(records.read_start_record(replace(binding), _operation()), S.START_OBSERVED)
    _assert_result(records.create_start_record(binding, _operation()), S.SLOT_OCCUPIED)


@LINUX_ONLY
def test_separate_process_reloads_only_test_owned_record_without_suite_restart(
    tmp_path: Path,
) -> None:
    binding = _private(tmp_path)
    _assert_result(records.create_start_record(binding, _operation()), S.START_CONFIRMED, True)
    code = """
import sys
from pathlib import Path
from tridentine_calendar_google_sync import production_write_token_operation_record as records

def main():
    try:
        binding = records.SyntheticBinding(
            Path(sys.argv[1]), "store-example", "pair-example", "token", "state"
        )
        operation = records.RecordOperation("operation-b", None, records.OperationKind.NEW_PAIR)
        result = records.read_start_record(binding, operation)
        if result.state is records.RecordState.START_OBSERVED and result.reuse_authorized is False:
            print("START_OBSERVED_NOT_AUTHORIZED")
            return 0
    except BaseException:
        pass
    print("CHILD_UNVERIFIABLE")
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(Path(records.__file__).resolve().parents[1])
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    child = subprocess.run(
        [sys.executable, "-S", "-B", "-c", code, str(binding.directory)],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        env=environment,
        timeout=10,
        check=False,
    )
    assert child.returncode == 0
    assert child.stdout == b"START_OBSERVED_NOT_AUTHORIZED\n" and not child.stderr
    assert (binding.directory / LEAF).read_bytes() == _wire(_data())


class _Poison:
    @property
    def __class__(self) -> type[object]:
        raise AssertionError("unexpected class hook")

    def __repr__(self) -> str:
        raise AssertionError("unexpected repr hook")

    def __str__(self) -> str:
        raise AssertionError("unexpected str hook")

    def __bool__(self) -> bool:
        raise AssertionError("unexpected bool hook")

    def __eq__(self, _other: object) -> bool:
        raise AssertionError("unexpected equality hook")

    def __hash__(self) -> int:
        raise AssertionError("unexpected hash hook")


@pytest.mark.parametrize(
    "location",
    (
        "binding",
        "directory",
        "storage_ref",
        "pair_ref",
        "token_slot",
        "state_slot",
        "operation",
        "operation_id",
        "predecessor_id",
        "kind",
        "raw",
    ),
)
def test_unknown_input_hooks_are_not_invoked(location: str) -> None:
    poison: Any = _Poison()
    binding: Any = _binding()
    operation: Any = _operation()
    raw: Any = _wire(_data())
    if location == "binding":
        binding = poison
    elif location == "operation":
        operation = poison
    elif location == "raw":
        raw = poison
    elif location in {"directory", "storage_ref", "pair_ref", "token_slot", "state_slot"}:
        binding = replace(binding, **{location: poison})
    else:
        operation = replace(operation, **{location: poison})
    assert not records._matches_start_record(raw, binding, operation)
    if location != "raw":
        with pytest.raises(records._RecordFormatError):
            records._encode_start_record(binding, operation)


class _SimulatedScopeBackend:
    """In-memory backend fault injection, never evidence of Linux filesystem behavior."""

    def __init__(self, binding: records.SyntheticBinding) -> None:
        self.binding = binding
        self.path = binding.directory / LEAF
        self.raw: bytes | None = None
        self.active = False
        self.events: list[str] = []
        self.failures: dict[str, BaseException] = {}
        self.hooks: dict[str, Any] = {}
        self.publisher_calls = 0
        self.owner: Any = None

    def event(self, stage: str) -> None:
        self.events.append(stage)
        if stage in self.hooks:
            self.hooks[stage]()
        if stage in self.failures:
            raise self.failures[stage]

    def acquire(self, path: Path) -> Any:
        assert path == self.binding.directory
        self.event("acquire")
        return _SimulatedScopeLock(self)

    def lstat(self, path: Path) -> Any:
        assert path == self.path and self.active
        self.event("lstat")
        if self.raw is None:
            raise FileNotFoundError("synthetic absent slot")
        return SimpleNamespace()

    def validate(self, path: Path, *, overwrite: bool) -> Path:
        assert path == self.path and self.active and overwrite is False
        self.event("validate")
        return path

    def publish(self, path: Path, raw: bytes) -> None:
        assert path == self.path and self.active and self.raw is None
        self.publisher_calls += 1
        self.event("publish")
        self.raw = raw
        self.event("published")

    def read(self, path: Path, *, max_size: int) -> bytes:
        assert path == self.path and self.active and max_size == 4096
        self.event("read")
        if self.raw is None:
            raise FileNotFoundError("synthetic absent slot")
        return self.raw


class _SimulatedScopeLock:
    def __init__(self, backend: _SimulatedScopeBackend) -> None:
        self.backend = backend

    def __enter__(self) -> _SimulatedScopeLock:
        assert not self.backend.active
        self.backend.active = True
        self.backend.event("enter")
        return self

    def revalidate(self) -> None:
        assert self.backend.active
        self.backend.event("checkpoint")

    def __exit__(self, *_exception: object) -> None:
        # The owner must invalidate its issued scope before delegating release.
        if self.backend.owner is not None:
            assert self.backend.owner._phase is records._ScopePhase.CLOSED
        self.backend.active = False
        self.backend.event("exit")


@pytest.fixture
def simulated_scope_backend(monkeypatch: pytest.MonkeyPatch) -> _SimulatedScopeBackend:
    """Exercise scope contracts on any OS with all record/filesystem boundaries replaced."""
    backend = _SimulatedScopeBackend(_binding())
    monkeypatch.setattr(records, "_linux_storage_available", lambda: True)
    monkeypatch.setattr(
        records.private_lock, "acquire_posix_private_directory_lock", backend.acquire
    )
    monkeypatch.setattr(records.private_create, "create_posix_private_bytes", backend.publish)
    monkeypatch.setattr(records, "read_private_sensitive_bytes", backend.read)
    monkeypatch.setattr(records, "validate_sensitive_output_path", backend.validate)
    monkeypatch.setattr(Path, "lstat", lambda path: backend.lstat(path))
    return backend


def _held_assert(
    result: Any,
    *,
    checkpoint: Any = None,
    refusal: records.RecordState | None = None,
    publication: bool | None = False,
) -> None:
    assert result.checkpoint is checkpoint and result.refusal is refusal
    assert result.publication_possible is publication and result.reuse_authorized is False
    assert not isinstance(result, records.RecordResult)
    assert {item.name for item in fields(result)} == {
        "checkpoint",
        "refusal",
        "publication_possible",
        "reuse_authorized",
    }


def test_scope_refactor_keeps_public_signatures_enums_and_wire_contract() -> None:
    assert tuple(inspect.signature(records.create_start_record).parameters) == (
        "binding",
        "operation",
    )
    assert tuple(inspect.signature(records.read_start_record).parameters) == (
        "binding",
        "operation",
    )
    assert {item.value for item in S} == {
        "start_confirmed",
        "start_observed",
        "slot_occupied",
        "unverifiable",
        "persistence_uncertain",
        "lock_busy",
        "lock_unavailable",
        "unsupported_platform",
    }
    assert records._encode_start_record(_binding(), _operation()) == _wire(_data())
    assert {item.value for item in K} == {"new_pair", "refresh"}


@pytest.mark.parametrize("revision", (None, "revision-example"))
def test_mock_scope_create_read_uses_one_lock_and_distinct_internal_results(
    simulated_scope_backend: _SimulatedScopeBackend, revision: str | None
) -> None:
    backend = simulated_scope_backend
    context = records._record_scope(backend.binding, _operation(), revision_ref=revision)
    backend.owner = context
    assert context._phase is records._ScopePhase.NEW and context._scope is None
    with context as scope:
        assert scope._owner is context and context._scope is scope
        assert context._phase is records._ScopePhase.ACTIVE and backend.active
        created = records._create_start_record_held(
            scope, replace(backend.binding), _operation(), revision_ref=revision
        )
        _held_assert(
            created, checkpoint=records._HeldCheckpoint.HELD_START_CHECKPOINT, publication=True
        )
        assert backend.active and "exit" not in backend.events
        observed = records._read_start_record_held(
            scope, backend.binding, _operation(), revision_ref=revision
        )
        _held_assert(observed, checkpoint=records._HeldCheckpoint.HELD_START_OBSERVED)
        assert context._creation_publication is True and backend.active
        assert backend.raw == _wire(_data()) and set(json.loads(backend.raw)) == set(KEYS)
        with pytest.raises(FrozenInstanceError):
            created.reuse_authorized = True
    assert context._phase is records._ScopePhase.CLOSED and not backend.active
    assert backend.events.count("acquire") == backend.events.count("exit") == 1
    assert backend.publisher_calls == 1 and context._cancellation is None


@pytest.mark.parametrize("create", (False, True))
def test_mock_scope_public_wrappers_use_shared_held_path_and_success_after_exit(
    simulated_scope_backend: _SimulatedScopeBackend, monkeypatch: pytest.MonkeyPatch, create: bool
) -> None:
    backend = simulated_scope_backend
    if not create:
        backend.raw = _wire(_data())
    name = "_create_start_record_held" if create else "_read_start_record_held"
    original = getattr(records, name)
    original_result = records.RecordResult
    calls: list[int] = []

    def held(*args: Any, **kwargs: Any) -> Any:
        calls.append(1)
        assert backend.active
        return original(*args, **kwargs)

    def result(state: records.RecordState, publication_possible: bool | None = False) -> Any:
        if state in {S.START_CONFIRMED, S.START_OBSERVED}:
            assert not backend.active and backend.events[-1] == "exit"
        return original_result(state, publication_possible)

    monkeypatch.setattr(records, name, held)
    monkeypatch.setattr(records, "RecordResult", result)
    operation = records.create_start_record if create else records.read_start_record
    _assert_result(
        operation(backend.binding, _operation()),
        S.START_CONFIRMED if create else S.START_OBSERVED,
        create,
    )
    assert calls == [1] and backend.events.count("acquire") == 1


@pytest.mark.parametrize(
    "mismatch",
    (
        "directory",
        "storage_ref",
        "pair_ref",
        "token_slot",
        "state_slot",
        "operation_id",
        "predecessor_id",
        "kind",
        "revision",
        "no-revision",
    ),
)
def test_mock_scope_mismatch_precedes_checkpoint_without_poisoning_owner(
    simulated_scope_backend: _SimulatedScopeBackend, mismatch: str
) -> None:
    backend = simulated_scope_backend
    backend.raw = _wire(_data(K.REFRESH))
    binding, operation, revision = backend.binding, _operation(K.REFRESH), "revision-example"
    context = records._record_scope(binding, operation, revision_ref=revision)
    with context as scope:
        expected_binding, expected_operation, expected_revision = binding, operation, revision
        if mismatch == "directory":
            expected_binding = replace(binding, directory=binding.directory / "other")
        elif mismatch in {"storage_ref", "pair_ref", "token_slot", "state_slot"}:
            expected_binding = replace(binding, **{mismatch: "other"})
        elif mismatch in {"operation_id", "predecessor_id"}:
            expected_operation = replace(operation, **{mismatch: "other"})
        elif mismatch == "kind":
            expected_operation = _operation()
        else:
            expected_revision = None if mismatch == "no-revision" else "other"
        before = list(backend.events)
        with pytest.raises(records._ScopeUseError, match=r"^Invalid operation-record scope$"):
            records._read_start_record_held(
                scope, expected_binding, expected_operation, revision_ref=expected_revision
            )
        assert backend.events == before and context._phase is records._ScopePhase.ACTIVE
        _held_assert(
            records._read_start_record_held(scope, binding, operation, revision_ref=revision),
            checkpoint=records._HeldCheckpoint.HELD_START_OBSERVED,
        )


def test_mock_scope_preentry_nested_entry_and_postexit_use_are_rejected(
    simulated_scope_backend: _SimulatedScopeBackend,
) -> None:
    backend = simulated_scope_backend
    backend.raw = _wire(_data())
    context = records._record_scope(backend.binding, _operation())
    with pytest.raises(records._ScopeUseError):
        records._read_start_record_held(context._scope, backend.binding, _operation())
    assert backend.events == [] and context._phase is records._ScopePhase.NEW
    with context as scope:
        before = list(backend.events)
        with pytest.raises(records._ScopeUseError):
            context.__enter__()
        assert backend.events == before and backend.active
        _held_assert(
            records._read_start_record_held(scope, backend.binding, _operation()),
            checkpoint=records._HeldCheckpoint.HELD_START_OBSERVED,
        )
    before = list(backend.events)
    with pytest.raises(records._ScopeUseError):
        records._read_start_record_held(scope, backend.binding, _operation())
    with pytest.raises(records._ScopeUseError):
        context.__enter__()
    assert backend.events == before and context._phase is records._ScopePhase.CLOSED


@pytest.mark.parametrize(
    "method", (copy.copy, copy.deepcopy, pickle.dumps), ids=("copy", "deepcopy", "pickle")
)
def test_mock_scope_and_owner_cannot_be_copied_or_serialized(
    simulated_scope_backend: _SimulatedScopeBackend, method: Any
) -> None:
    backend = simulated_scope_backend
    context = records._record_scope(backend.binding, _operation())
    with context as scope:
        before = list(backend.events)
        for value in (context, scope):
            with pytest.raises(records._ScopeUseError, match=r"^Invalid operation-record scope$"):
                method(value)
        assert backend.events == before and backend.active


@pytest.mark.parametrize("forged", ("unknown", "uninitialized", "wrong-owner", "direct"))
def test_mock_scope_requires_factory_issued_mutual_identity(
    simulated_scope_backend: _SimulatedScopeBackend, forged: str
) -> None:
    backend = simulated_scope_backend
    context = records._record_scope(backend.binding, _operation())
    with context as scope:
        before = list(backend.events)
        if forged == "direct":
            with pytest.raises(records._ScopeUseError):
                records._HeldRecordScope()
            with pytest.raises(records._ScopeUseError):
                records._RecordScopeContext()
        else:
            value = _Poison() if forged == "unknown" else object.__new__(records._HeldRecordScope)
            if forged == "wrong-owner":
                object.__setattr__(value, "_owner", context)
            with pytest.raises(records._ScopeUseError):
                records._read_start_record_held(value, backend.binding, _operation())
        assert scope._owner is context and context._scope is scope
        assert backend.events == before and backend.active


def test_mock_scope_reentrant_operation_and_second_create_do_not_reenter_io(
    simulated_scope_backend: _SimulatedScopeBackend,
) -> None:
    backend = simulated_scope_backend
    with records._record_scope(backend.binding, _operation()) as scope:

        def reenter() -> None:
            before = list(backend.events)
            with pytest.raises(records._ScopeUseError):
                records._read_start_record_held(scope, backend.binding, _operation())
            assert backend.events == before

        backend.hooks["publish"] = reenter
        _held_assert(
            records._create_start_record_held(scope, backend.binding, _operation()),
            checkpoint=records._HeldCheckpoint.HELD_START_CHECKPOINT,
            publication=True,
        )
        before = list(backend.events)
        with pytest.raises(records._ScopeUseError):
            records._create_start_record_held(scope, backend.binding, _operation())
        assert backend.events == before and backend.publisher_calls == 1


def test_mock_scope_changed_process_is_rejected_before_io_or_owner_release(
    simulated_scope_backend: _SimulatedScopeBackend, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = simulated_scope_backend
    context = records._record_scope(backend.binding, _operation())
    process = os.getpid()
    with context as scope:
        before = list(backend.events)
        with monkeypatch.context() as changed:
            changed.setattr(
                records, "os", SimpleNamespace(name=os.name, getpid=lambda: process + 1)
            )
            with pytest.raises(records._ScopeUseError):
                records._read_start_record_held(scope, backend.binding, _operation())
            with pytest.raises(records._ScopeUseError):
                context.__exit__(None, None, None)
        assert backend.events == before and backend.active
        assert context._phase is records._ScopePhase.ACTIVE


def test_mock_scope_real_other_thread_cannot_use_or_close_the_owner(
    simulated_scope_backend: _SimulatedScopeBackend,
) -> None:
    backend = simulated_scope_backend
    backend.raw = _wire(_data())
    context = records._record_scope(backend.binding, _operation())
    outcomes: list[str] = []
    with context as scope:
        before = list(backend.events)

        def worker() -> None:
            for action in (
                lambda: records._read_start_record_held(scope, backend.binding, _operation()),
                lambda: context.__exit__(None, None, None),
            ):
                try:
                    action()
                except records._ScopeUseError:
                    outcomes.append("refused")
                else:
                    outcomes.append("unexpected")

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive() and outcomes == ["refused", "refused"]
        assert backend.events == before and backend.active
        _held_assert(
            records._read_start_record_held(scope, backend.binding, _operation()),
            checkpoint=records._HeldCheckpoint.HELD_START_OBSERVED,
        )


@pytest.mark.parametrize("evidence", (False, True, None, 0, "invalid"))
def test_mock_scope_failure_poisoning_keeps_first_formal_publication_evidence(
    simulated_scope_backend: _SimulatedScopeBackend, evidence: object
) -> None:
    backend = simulated_scope_backend
    failure = records.private_create.PosixPrivateCreateError("synthetic")
    failure.publication_possible = evidence
    backend.failures["publish"] = failure
    backend.failures["exit"] = OSError("SYNTHETIC_PRIVATE_CLEANUP")
    context = records._record_scope(backend.binding, _operation())
    expected = evidence if type(evidence) is bool else None
    with pytest.raises(records._ScopeFailure) as caught, context as scope:
        result = records._create_start_record_held(scope, backend.binding, _operation())
        _held_assert(result, refusal=S.PERSISTENCE_UNCERTAIN, publication=expected)
        assert context._phase is records._ScopePhase.FAILED
        assert context._create_attempted and context._creation_publication is expected
        first = context._first_failure
        before = list(backend.events)
        for action in (records._create_start_record_held, records._read_start_record_held):
            with pytest.raises(records._ScopeUseError):
                action(scope, backend.binding, _operation())
        assert backend.events == before and context._first_failure is first
    _assert_result(caught.value.result, S.PERSISTENCE_UNCERTAIN, expected)
    assert context._phase is records._ScopePhase.CLOSED and backend.publisher_calls == 1


def test_mock_scope_read_failure_preserves_prior_create_without_mixing_call_local_flags(
    simulated_scope_backend: _SimulatedScopeBackend,
) -> None:
    backend = simulated_scope_backend
    context = records._record_scope(backend.binding, _operation())
    with pytest.raises(records._ScopeFailure) as caught, context as scope:
        _held_assert(
            records._create_start_record_held(scope, backend.binding, _operation()),
            checkpoint=records._HeldCheckpoint.HELD_START_CHECKPOINT,
            publication=True,
        )
        backend.failures["read"] = OSError("SYNTHETIC_PRIVATE_READ")
        _held_assert(
            records._read_start_record_held(scope, backend.binding, _operation()),
            refusal=S.UNVERIFIABLE,
        )
        assert (
            context._creation_publication is True and context._phase is records._ScopePhase.FAILED
        )
    _assert_result(caught.value.result, S.UNVERIFIABLE)
    assert backend.raw == _wire(_data()) and backend.publisher_calls == 1


@pytest.mark.parametrize("stage", ("validate", "published", "read", "checkpoint", "exit"))
def test_mock_scope_failure_points_never_return_success_or_remove_record(
    simulated_scope_backend: _SimulatedScopeBackend, stage: str
) -> None:
    backend = simulated_scope_backend
    context = records._record_scope(backend.binding, _operation())
    if stage == "checkpoint":

        def checkpoint() -> None:
            if "read" in backend.events:
                raise records.private_lock.PosixPrivateLockError("posix_directory_lock_unverified")

        backend.hooks["checkpoint"] = checkpoint
    else:
        backend.failures[stage] = OSError("SYNTHETIC_PRIVATE_FAILURE")
    expected_state = S.UNVERIFIABLE if stage == "validate" else S.PERSISTENCE_UNCERTAIN
    publication = False if stage == "validate" else None if stage == "published" else True
    with pytest.raises(records._ScopeFailure) as caught, context as scope:
        result = records._create_start_record_held(scope, backend.binding, _operation())
        if stage != "exit":
            _held_assert(result, refusal=expected_state, publication=publication)
    _assert_result(caught.value.result, expected_state, publication)
    assert (backend.raw is not None) is (stage != "validate")
    assert context._phase is records._ScopePhase.CLOSED


@pytest.mark.parametrize("busy", (False, True))
def test_mock_scope_failed_acquisition_is_terminal_without_record_io(
    simulated_scope_backend: _SimulatedScopeBackend, busy: bool
) -> None:
    backend = simulated_scope_backend
    backend.failures["acquire"] = records.private_lock.PosixPrivateLockError(
        "posix_directory_lock_busy" if busy else "posix_directory_lock_unavailable"
    )
    context = records._record_scope(backend.binding, _operation())
    with pytest.raises(records._ScopeFailure) as caught, context:
        pytest.fail("failed lock must not issue a scope")
    _assert_result(caught.value.result, S.LOCK_BUSY if busy else S.LOCK_UNAVAILABLE)
    assert backend.events == ["acquire"] and context._phase is records._ScopePhase.FAILED
    with pytest.raises(records._ScopeUseError):
        context.__enter__()


@pytest.mark.parametrize("stage", ("publish", "read", "body"))
@pytest.mark.parametrize("cleanup_failure", (False, True))
def test_mock_scope_cancellation_survives_later_ordinary_cleanup_failure(
    simulated_scope_backend: _SimulatedScopeBackend, stage: str, cleanup_failure: bool
) -> None:
    backend = simulated_scope_backend
    problem = KeyboardInterrupt()
    if stage != "body":
        backend.failures[stage] = problem
    if cleanup_failure:
        backend.failures["exit"] = OSError("SYNTHETIC_PRIVATE_CLEANUP")
    context = records._record_scope(backend.binding, _operation())
    with pytest.raises(KeyboardInterrupt) as caught, context as scope:
        records._create_start_record_held(scope, backend.binding, _operation())
        if stage == "body":
            raise problem
    assert caught.value is problem and context._phase is records._ScopePhase.CLOSED
    assert context._cancellation is None and not backend.active
    assert (backend.raw is not None) is (stage != "publish")


def test_mock_scope_occupied_identical_record_fails_without_publication(
    simulated_scope_backend: _SimulatedScopeBackend,
) -> None:
    backend = simulated_scope_backend
    backend.raw = _wire(_data())
    context = records._record_scope(backend.binding, _operation())
    with pytest.raises(records._ScopeFailure) as caught, context as scope:
        _held_assert(
            records._create_start_record_held(scope, backend.binding, _operation()),
            refusal=S.SLOT_OCCUPIED,
        )
        assert context._phase is records._ScopePhase.FAILED
    _assert_result(caught.value.result, S.SLOT_OCCUPIED)
    assert backend.raw == _wire(_data()) and backend.publisher_calls == 0


@pytest.mark.parametrize("platform", ("win32", "darwin", "freebsd14"))
def test_scope_unsupported_stops_before_binding_lock_or_record_inspection(
    monkeypatch: pytest.MonkeyPatch, platform: str
) -> None:
    monkeypatch.setattr(records, "sys", SimpleNamespace(platform=platform))
    monkeypatch.setattr(records, "_valid_binding", _deny)
    monkeypatch.setattr(records.private_lock, "acquire_posix_private_directory_lock", _deny)
    monkeypatch.setattr(records, "read_private_sensitive_bytes", _deny)
    monkeypatch.setattr(records.private_create, "create_posix_private_bytes", _deny)
    with (
        pytest.raises(records._ScopeFailure) as caught,
        records._record_scope(_Poison(), _Poison()),
    ):
        pytest.fail("unsupported platform must not issue a scope")
    _assert_result(caught.value.result, S.UNSUPPORTED_PLATFORM)


def test_mock_scope_private_reprs_errors_and_revision_never_expose_inputs(
    simulated_scope_backend: _SimulatedScopeBackend,
) -> None:
    backend = simulated_scope_backend
    revision = "SYNTHETIC_PRIVATE_REVISION"
    context = records._record_scope(backend.binding, _operation(), revision_ref=revision)
    with context as scope:
        result = records._create_start_record_held(
            scope, backend.binding, _operation(), revision_ref=revision
        )
        with pytest.raises(records._ScopeUseError) as caught:
            records._read_start_record_held(
                scope, backend.binding, _operation(), revision_ref="different"
            )
        rendered = repr(context) + repr(scope) + repr(result) + repr(caught.value)
        for forbidden in (revision, str(backend.binding.directory), "store-example", "operation-b"):
            assert forbidden not in rendered
        assert backend.raw is not None and revision.encode() not in backend.raw
        assert set(json.loads(backend.raw)) == set(KEYS)


@LINUX_ONLY
def test_real_linux_held_scope_create_read_retains_one_lock_and_record(tmp_path: Path) -> None:
    binding = _private(tmp_path)
    context = records._record_scope(binding, _operation(), revision_ref="revision-example")
    with context as scope:
        _held_assert(
            records._create_start_record_held(
                scope, binding, _operation(), revision_ref="revision-example"
            ),
            checkpoint=records._HeldCheckpoint.HELD_START_CHECKPOINT,
            publication=True,
        )
        _assert_result(records.read_start_record(binding, _operation()), S.LOCK_BUSY)
        _held_assert(
            records._read_start_record_held(
                scope, binding, _operation(), revision_ref="revision-example"
            ),
            checkpoint=records._HeldCheckpoint.HELD_START_OBSERVED,
        )
        assert context._creation_publication is True
    assert (binding.directory / LEAF).read_bytes() == _wire(_data())
    _assert_result(records.read_start_record(binding, _operation()), S.START_OBSERVED)
    _assert_result(records.create_start_record(binding, _operation()), S.SLOT_OCCUPIED)


@LINUX_ONLY
def test_real_linux_held_scope_failure_stays_retained_without_sentinel_access(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    binding = _private(tmp_path)
    sentinels = {binding.directory / binding.token_slot, binding.directory / binding.state_slot}
    for path in sentinels:
        path.write_bytes(b"synthetic scope sentinel")
    before = {path: path.stat() for path in sentinels}
    native_open = os.open

    def opened(path: Any, *args: Any, **kwargs: Any) -> int:
        assert str(path) not in {binding.token_slot, binding.state_slot} and path not in sentinels
        return native_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", opened)
    with (
        pytest.raises(records._ScopeFailure),
        records._record_scope(binding, _operation()) as scope,
    ):
        _held_assert(
            records._create_start_record_held(scope, binding, _operation()),
            checkpoint=records._HeldCheckpoint.HELD_START_CHECKPOINT,
            publication=True,
        )
        raise OSError("synthetic downstream scope failure")
    assert (binding.directory / LEAF).read_bytes() == _wire(_data())
    for path in sentinels:
        assert path.stat() == before[path]
    _assert_result(records.read_start_record(binding, _operation()), S.START_OBSERVED)


@pytest.mark.parametrize(
    "revision",
    ("", "bad/revision", True, "poison-input"),
    ids=("empty", "slash", "boolean", "poison"),
)
def test_mock_scope_invalid_revision_is_terminal_before_lock(
    simulated_scope_backend: _SimulatedScopeBackend, revision: object
) -> None:
    backend = simulated_scope_backend
    if revision == "poison-input":
        revision = _Poison()
    context = records._record_scope(backend.binding, _operation(), revision_ref=revision)
    with pytest.raises(records._ScopeFailure) as caught, context:
        pytest.fail("invalid revision must not issue a scope")
    _assert_result(caught.value.result, S.UNVERIFIABLE)
    assert backend.events == [] and context._phase is records._ScopePhase.FAILED
    with pytest.raises(records._ScopeUseError):
        context.__enter__()


@pytest.mark.parametrize("change", ("same-numeric-id", "not-live"))
def test_mock_scope_requires_original_live_thread_object(
    simulated_scope_backend: _SimulatedScopeBackend,
    monkeypatch: pytest.MonkeyPatch,
    change: str,
) -> None:
    backend = simulated_scope_backend
    context = records._record_scope(backend.binding, _operation())
    with context as scope:
        before = list(backend.events)
        with monkeypatch.context() as injected:
            if change == "same-numeric-id":
                other = SimpleNamespace(ident=threading.get_ident(), is_alive=lambda: True)
                injected.setattr(
                    records, "threading", SimpleNamespace(current_thread=lambda: other)
                )
            else:
                injected.setattr(context._thread, "is_alive", lambda: False)
            with pytest.raises(records._ScopeUseError):
                records._read_start_record_held(scope, backend.binding, _operation())
        assert backend.events == before and backend.active
        assert context._phase is records._ScopePhase.ACTIVE


def test_mock_scope_successful_read_cannot_erase_creation_before_later_body_failure(
    simulated_scope_backend: _SimulatedScopeBackend,
) -> None:
    backend = simulated_scope_backend
    context = records._record_scope(backend.binding, _operation())
    with pytest.raises(records._ScopeFailure) as caught, context as scope:
        _held_assert(
            records._create_start_record_held(scope, backend.binding, _operation()),
            checkpoint=records._HeldCheckpoint.HELD_START_CHECKPOINT,
            publication=True,
        )
        _held_assert(
            records._read_start_record_held(scope, backend.binding, _operation()),
            checkpoint=records._HeldCheckpoint.HELD_START_OBSERVED,
        )
        assert context._creation_publication is True
        raise OSError("synthetic later stage failure")
    _assert_result(caught.value.result, S.PERSISTENCE_UNCERTAIN, True)
    assert backend.raw == _wire(_data())


def test_mock_scope_caught_cancellation_cannot_allow_normal_context_exit(
    simulated_scope_backend: _SimulatedScopeBackend,
) -> None:
    backend = simulated_scope_backend
    problem = KeyboardInterrupt()
    backend.failures["read"] = problem
    context = records._record_scope(backend.binding, _operation())
    with pytest.raises(KeyboardInterrupt) as caught, context as scope:
        with pytest.raises(KeyboardInterrupt):
            records._create_start_record_held(scope, backend.binding, _operation())
        assert context._phase is records._ScopePhase.FAILED
        before = list(backend.events)
        with pytest.raises(records._ScopeUseError):
            records._read_start_record_held(scope, backend.binding, _operation())
        assert backend.events == before
    assert caught.value is problem and context._cancellation is None
    assert context._phase is records._ScopePhase.CLOSED and backend.raw == _wire(_data())


def test_private_held_results_cannot_take_public_success_or_authorization() -> None:
    with pytest.raises(ValueError, match=r"^Invalid held-record result$"):
        records._HeldResult(refusal=S.START_CONFIRMED)
    with pytest.raises(TypeError):
        records._HeldResult(
            checkpoint=records._HeldCheckpoint.HELD_START_CHECKPOINT, reuse_authorized=True
        )


@LINUX_ONLY
def test_real_linux_foreign_thread_cannot_release_active_scope_lock(tmp_path: Path) -> None:
    binding = _private(tmp_path)
    outcomes: list[str] = []
    with records._record_scope(binding, _operation()) as scope:
        records._create_start_record_held(scope, binding, _operation())

        def worker() -> None:
            try:
                records._read_start_record_held(scope, binding, _operation())
            except records._ScopeUseError:
                outcomes.append("refused")

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        thread.join(timeout=5)
        assert not thread.is_alive() and outcomes == ["refused"]
        _assert_result(records.read_start_record(binding, _operation()), S.LOCK_BUSY)
        _held_assert(
            records._read_start_record_held(scope, binding, _operation()),
            checkpoint=records._HeldCheckpoint.HELD_START_OBSERVED,
        )
    _assert_result(records.read_start_record(binding, _operation()), S.START_OBSERVED)


def test_mock_scope_public_fallback_retains_publication_after_unexpected_exit_error(
    simulated_scope_backend: _SimulatedScopeBackend, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = simulated_scope_backend
    original_exit = records._RecordScopeContext.__exit__

    def unexpected_exit(context: Any, *exception: Any) -> Any:
        original_exit(context, *exception)
        raise OSError("synthetic unexpected exit wrapper failure")

    monkeypatch.setattr(records._RecordScopeContext, "__exit__", unexpected_exit)
    _assert_result(
        records.create_start_record(backend.binding, _operation()), S.PERSISTENCE_UNCERTAIN, True
    )
    assert backend.raw == _wire(_data()) and not backend.active


def test_mock_scope_public_fallback_preserves_pending_cancellation(
    simulated_scope_backend: _SimulatedScopeBackend, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = simulated_scope_backend
    problem = KeyboardInterrupt()
    backend.failures["read"] = problem
    original_exit = records._RecordScopeContext.__exit__
    owners: list[Any] = []

    def failed_exit(context: Any, *_exception: Any) -> Any:
        owners.append(context)
        raise OSError("synthetic early exit failure")

    monkeypatch.setattr(records._RecordScopeContext, "__exit__", failed_exit)
    try:
        with pytest.raises(KeyboardInterrupt) as caught:
            records.create_start_record(backend.binding, _operation())
        assert caught.value is problem and len(owners) == 1
    finally:
        # Only the legitimate test owner closes its synthetic backend after fault injection.
        if owners:
            with pytest.raises(KeyboardInterrupt):
                original_exit(owners[0], None, None, None)
    assert not backend.active and owners[0]._cancellation is None


@pytest.mark.parametrize("stage", ("acquire", "enter"))
def test_mock_scope_entry_in_progress_cannot_acquire_twice_or_release(
    simulated_scope_backend: _SimulatedScopeBackend, stage: str
) -> None:
    backend = simulated_scope_backend
    backend.raw = _wire(_data())
    context = records._record_scope(backend.binding, _operation())

    def reenter() -> None:
        before = list(backend.events)
        assert context._entering
        with pytest.raises(records._ScopeUseError):
            context.__enter__()
        with pytest.raises(records._ScopeUseError):
            context.__exit__(None, None, None)
        assert backend.events == before and context._first_failure is None

    backend.hooks[stage] = reenter
    with context as scope:
        assert not context._entering and context._phase is records._ScopePhase.ACTIVE
        _held_assert(
            records._read_start_record_held(scope, backend.binding, _operation()),
            checkpoint=records._HeldCheckpoint.HELD_START_OBSERVED,
        )
    assert backend.events.count("acquire") == backend.events.count("exit") == 1
    assert not context._entering and context._phase is records._ScopePhase.CLOSED


def test_mock_scope_reconstructed_owner_does_not_inherit_factory_identity(
    simulated_scope_backend: _SimulatedScopeBackend,
) -> None:
    backend = simulated_scope_backend
    context = records._record_scope(backend.binding, _operation())
    reconstructed = object.__new__(records._RecordScopeContext)
    for item in fields(context):
        object.__setattr__(reconstructed, item.name, getattr(context, item.name))
    with pytest.raises(records._ScopeUseError):
        reconstructed.__enter__()
    assert backend.events == [] and context._phase is records._ScopePhase.NEW
    with context:
        assert backend.active
    assert backend.events.count("acquire") == 1


@pytest.mark.parametrize("boundary", ("encode", "platform", "binding-snapshot", "exit-stack"))
@pytest.mark.parametrize(
    "fault_type",
    (KeyboardInterrupt, RuntimeError, MemoryError),
    ids=("keyboard-interrupt", "runtime-error", "raised-memory-error"),
)
def test_initial_entry_fault_is_terminal_after_injection_is_removed(
    simulated_scope_backend: _SimulatedScopeBackend,
    monkeypatch: pytest.MonkeyPatch,
    request: pytest.FixtureRequest,
    boundary: str,
    fault_type: type[BaseException],
) -> None:
    backend = simulated_scope_backend
    context = records._record_scope(backend.binding, _operation())
    marker = "SYNTHETIC_INITIAL_ENTRY_DETAIL"
    problem = KeyboardInterrupt() if fault_type is KeyboardInterrupt else fault_type(marker)
    event_names = ("acquire", "enter", "publish", "read", "lstat", "validate", "checkpoint", "exit")

    def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise problem

    with (
        pytest.raises(
            (KeyboardInterrupt, RuntimeError, MemoryError, records._ScopeFailure)
        ) as caught,
        monkeypatch.context() as injected,
    ):
        if boundary == "encode":
            injected.setattr(records, "_encode_start_record", fail)
        elif boundary == "platform":
            injected.setattr(records, "_linux_storage_available", fail)
        elif boundary == "exit-stack":
            injected.setattr(records, "ExitStack", fail)
        else:
            original_encode = records._encode_start_record

            def encode_then_fail_snapshot(binding: object, operation: object) -> bytes:
                encoded = original_encode(binding, operation)
                injected.setattr(records, "SyntheticBinding", fail)
                return encoded

            injected.setattr(records, "_encode_start_record", encode_then_fail_snapshot)
        context.__enter__()

    first_phase = context._phase
    first_entering = context._entering
    first_scope = context._scope
    first_cancellation = context._cancellation
    initial_counts = {name: backend.events.count(name) for name in event_names}
    initial_publisher_calls = backend.publisher_calls
    retry_refused = False
    retry_checkpoint = False
    # The injection is gone. The unfixed implementation can actually acquire
    # and publish here; any resulting artifact is only this simulated backend.
    try:
        with context as retried:
            result = records._create_start_record_held(retried, backend.binding, _operation())
            retry_checkpoint = result.checkpoint is records._HeldCheckpoint.HELD_START_CHECKPOINT
    except records._ScopeUseError:
        retry_refused = True
    retry_counts = {name: backend.events.count(name) - initial_counts[name] for name in event_names}
    request.node.user_properties.append(
        (
            "entry_observation",
            {
                "boundary": boundary,
                "fault": fault_type.__name__,
                "initial_phase": first_phase.value,
                "initial_entering": first_entering,
                "initial_scope_issued": first_scope is not None,
                "initial_counts": initial_counts,
                "retry_refused": retry_refused,
                "retry_checkpoint": retry_checkpoint,
                "retry_counts": retry_counts,
            },
        )
    )

    assert first_phase is records._ScopePhase.FAILED
    assert first_entering is False and first_scope is None and first_cancellation is None
    assert initial_publisher_calls == 0 and all(count == 0 for count in initial_counts.values())
    assert (
        retry_refused
        and not retry_checkpoint
        and all(count == 0 for count in retry_counts.values())
    )
    assert context._phase is records._ScopePhase.FAILED and not context._entering
    assert context._scope is None and context._held is None and context._stack is None
    assert context._cancellation is None
    if fault_type is KeyboardInterrupt:
        assert caught.value is problem
    else:
        assert isinstance(caught.value, records._ScopeFailure)
        _assert_result(caught.value.result, S.UNVERIFIABLE)
        assert marker not in repr(caught.value) and str(backend.binding.directory) not in str(
            caught.value
        )
    assert marker not in repr(context) and str(backend.binding.directory) not in repr(context)

    # A separate synthetic context can still enter; this is not retry approval.
    independent = records._record_scope(
        backend.binding, replace(_operation(), operation_id="independent-operation")
    )
    with independent:
        assert independent._phase is records._ScopePhase.ACTIVE and backend.active
    assert independent._phase is records._ScopePhase.CLOSED


@pytest.mark.parametrize(
    "fault_type",
    (KeyboardInterrupt, RuntimeError, MemoryError),
    ids=("keyboard-interrupt", "runtime-error", "raised-memory-error"),
)
@pytest.mark.parametrize("cleanup_failure", (False, True))
def test_entry_scope_issuance_fault_unwinds_once_and_stays_terminal(
    simulated_scope_backend: _SimulatedScopeBackend,
    monkeypatch: pytest.MonkeyPatch,
    fault_type: type[BaseException],
    cleanup_failure: bool,
) -> None:
    backend = simulated_scope_backend
    context = records._record_scope(backend.binding, _operation())
    problem = fault_type()
    if cleanup_failure:
        backend.failures["exit"] = OSError("SYNTHETIC_ENTRY_CLEANUP")

    def fail_allocation(_scope_type: object) -> Any:
        raise problem

    # Context construction is already complete. Only the subsequently
    # issued scope allocation is replaced; no runtime hook is added.
    with (
        pytest.raises((KeyboardInterrupt, records._ScopeFailure)) as caught,
        monkeypatch.context() as injected,
    ):
        injected.setattr(records, "object", SimpleNamespace(__new__=fail_allocation), raising=False)
        context.__enter__()

    assert backend.events == ["acquire", "enter", "exit"] and not backend.active
    assert backend.publisher_calls == 0 and backend.raw is None
    assert context._phase is records._ScopePhase.FAILED and not context._entering
    assert context._scope is None and context._held is None and context._stack is None
    assert context._cancellation is None
    if fault_type is KeyboardInterrupt:
        assert caught.value is problem
    else:
        assert isinstance(caught.value, records._ScopeFailure)
        _assert_result(caught.value.result, S.UNVERIFIABLE)
    before = list(backend.events)
    with pytest.raises(records._ScopeUseError):
        context.__enter__()
    assert backend.events == before
