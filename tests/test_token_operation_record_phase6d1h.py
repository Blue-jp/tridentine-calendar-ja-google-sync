"""Synthetic start-record checks; no credential reuse or durability approval."""

from __future__ import annotations

import ast
import json
import os
import stat
import subprocess
import sys
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
