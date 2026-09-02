"""Real-Windows reparse, identity, race, ACL, and lifecycle tests."""

from __future__ import annotations

import ctypes
import os
import sys
import threading
from pathlib import Path

import pytest
from conftest import REPOSITORY_ROOT
from windows_sensitive_fs_helpers import (
    assert_private_file,
    create_acl_directory,
    create_junction,
    has_effective_right,
    remove_junction,
    set_directory_acl,
    set_private_file_acl,
)

from tridentine_calendar_google_sync import _windows_sensitive_files as windows_files
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_integrity_text,
    atomic_write_private_text,
    read_sensitive_bytes,
    validate_sensitive_input_path,
    validate_sensitive_output_path,
)

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="requires real Win32 APIs")


@pytest.fixture
def safe_root(tmp_path: Path) -> Path:
    return create_acl_directory(tmp_path / "phase6d1f-safe")


def test_b1_normal_path_and_private_refresh_pass(safe_root: Path) -> None:
    source = safe_root / "input.bin"
    source.write_bytes(b"synthetic-input")
    assert validate_sensitive_input_path(source) == source
    assert read_sensitive_bytes(source) == b"synthetic-input"

    output = safe_root / "private.txt"
    atomic_write_private_text(output, "first-marker")
    atomic_write_private_text(output, "second-marker", overwrite=True)
    assert (
        read_sensitive_bytes(
            output,
            windows_private_acl=True,
            windows_require_protected_acl=True,
        )
        == b"second-marker"
    )
    assert_private_file(output)


def test_b2_symlink_ancestor_is_blocked(safe_root: Path) -> None:
    target = create_acl_directory(safe_root / "symlink-target")
    link = safe_root / "symlink-parent"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("ordinary symlink creation is unavailable without elevation")
    with pytest.raises(SensitivePathError) as captured:
        validate_sensitive_output_path(link / "marker.txt")
    assert captured.value.code == "sensitive_path_symlink"


def test_b3_junction_ancestor_and_b4_leaf_reparse_are_blocked(safe_root: Path) -> None:
    target = create_acl_directory(safe_root / "junction-target")
    ancestor = safe_root / "junction-parent"
    leaf = safe_root / "junction-leaf"
    create_junction(ancestor, target)
    create_junction(leaf, target)
    try:
        for candidate in (ancestor / "marker.txt", leaf):
            with pytest.raises(SensitivePathError) as captured:
                validate_sensitive_output_path(candidate)
            assert captured.value.code == "sensitive_path_reparse"
    finally:
        remove_junction(ancestor)
        remove_junction(leaf)


def test_b5_junction_redirect_into_repository_is_blocked_without_write(
    safe_root: Path,
) -> None:
    junction = safe_root / "repository-alias"
    target = REPOSITORY_ROOT / "docs"
    candidate_name = "must-not-create-phase6d1f.txt"
    candidate = target / candidate_name
    create_junction(junction, target)
    try:
        with pytest.raises(SensitivePathError) as captured:
            atomic_write_private_text(junction / candidate_name, "synthetic-marker")
        assert captured.value.code == "sensitive_path_reparse"
        assert not candidate.exists()
    finally:
        remove_junction(junction)


def test_b6_validation_then_parent_substitution_cannot_reach_new_sink(
    safe_root: Path,
) -> None:
    original = create_acl_directory(safe_root / "validated-parent")
    moved = safe_root / "validated-parent-old"
    unsafe_sink = create_acl_directory(safe_root / "unsafe-sink", broad_write=True)
    output = original / "marker.txt"
    validate_sensitive_output_path(output)
    os.replace(original, moved)
    create_junction(original, unsafe_sink)
    try:
        with pytest.raises(SensitivePathError) as captured:
            atomic_write_private_text(output, "synthetic-marker")
        assert captured.value.code == "sensitive_path_reparse"
        assert not (unsafe_sink / "marker.txt").exists()
    finally:
        remove_junction(original)


def test_combined_junction_and_broad_acl_attack_reaches_no_unsafe_sink(
    safe_root: Path,
) -> None:
    apparent = create_acl_directory(safe_root / "combined-apparent")
    original = safe_root / "combined-original"
    unsafe_sink = create_acl_directory(
        safe_root / "combined-unsafe-sink",
        broad_read=True,
        broad_write=True,
    )
    output = apparent / "secret-marker.txt"
    validate_sensitive_output_path(output)
    os.replace(apparent, original)
    create_junction(apparent, unsafe_sink)
    try:
        with pytest.raises(SensitivePathError):
            atomic_write_private_text(output, "synthetic-secret-marker")
        assert not (unsafe_sink / "secret-marker.txt").exists()
        assert not tuple(unsafe_sink.glob(".private-write-*.tmp"))
    finally:
        remove_junction(apparent)


def test_ordinary_child_swap_cannot_feed_attacker_selected_bytes(
    safe_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A swapped unopened directory is not followed after parent enumeration."""

    ancestor = create_acl_directory(safe_root / "ordinary-ancestor")
    original_child = create_acl_directory(ancestor / "child")
    moved_child = ancestor / "child-original"
    replacement_child = create_acl_directory(ancestor / "child-replacement")
    source = original_child / "input.bin"
    source.write_bytes(b"trusted-marker")
    (replacement_child / source.name).write_bytes(b"attacker-marker")

    original_lookup = windows_files._directory_child_file_id
    original_read_all = windows_files._read_all
    swap_attempted = False
    swap_succeeded = False
    read_calls = 0

    def swapping_lookup(
        parent_handle: int,
        child_name: str,
        *,
        missing_ok: bool,
    ) -> int | None:
        nonlocal swap_attempted, swap_succeeded
        file_id = original_lookup(parent_handle, child_name, missing_ok=missing_ok)
        if child_name == original_child.name and not swap_attempted:
            swap_attempted = True
            try:
                os.replace(original_child, moved_child)
                os.replace(replacement_child, original_child)
            except OSError:
                if moved_child.exists() and not original_child.exists():
                    os.replace(moved_child, original_child)
            else:
                swap_succeeded = True
        return file_id

    def recording_read_all(handle: int, max_size: int) -> bytes:
        nonlocal read_calls
        read_calls += 1
        return original_read_all(handle, max_size)

    monkeypatch.setattr(windows_files, "_directory_child_file_id", swapping_lookup)
    monkeypatch.setattr(windows_files, "_read_all", recording_read_all)

    try:
        try:
            observed = read_sensitive_bytes(source)
        except SensitivePathError:
            observed = None
        assert swap_attempted
        assert observed != b"attacker-marker"
        if swap_succeeded:
            assert observed is None
            assert read_calls == 0
        else:
            assert observed == b"trusted-marker"
            assert read_calls == 1
    finally:
        if swap_succeeded:
            os.replace(original_child, replacement_child)
            os.replace(moved_child, original_child)


def test_ordinary_leaf_swap_cannot_feed_attacker_selected_bytes(
    safe_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A swapped unopened file is not followed after parent enumeration."""

    parent = create_acl_directory(safe_root / "leaf-swap-parent")
    source = parent / "input.bin"
    moved_source = parent / "input-original.bin"
    replacement_source = parent / "input-replacement.bin"
    source.write_bytes(b"trusted-marker")
    replacement_source.write_bytes(b"attacker-marker")

    original_lookup = windows_files._directory_child_file_id
    original_read_all = windows_files._read_all
    swap_attempted = False
    swap_succeeded = False
    read_calls = 0

    def swapping_lookup(
        parent_handle: int,
        child_name: str,
        *,
        missing_ok: bool,
    ) -> int | None:
        nonlocal swap_attempted, swap_succeeded
        file_id = original_lookup(parent_handle, child_name, missing_ok=missing_ok)
        if child_name == source.name and not swap_attempted:
            swap_attempted = True
            try:
                os.replace(source, moved_source)
                os.replace(replacement_source, source)
            except OSError:
                if moved_source.exists() and not source.exists():
                    os.replace(moved_source, source)
            else:
                swap_succeeded = True
        return file_id

    def recording_read_all(handle: int, max_size: int) -> bytes:
        nonlocal read_calls
        read_calls += 1
        return original_read_all(handle, max_size)

    monkeypatch.setattr(windows_files, "_directory_child_file_id", swapping_lookup)
    monkeypatch.setattr(windows_files, "_read_all", recording_read_all)

    try:
        try:
            observed = read_sensitive_bytes(source)
        except SensitivePathError:
            observed = None
        assert swap_attempted
        assert observed != b"attacker-marker"
        if swap_succeeded:
            assert observed is None
            assert read_calls == 0
        else:
            assert observed == b"trusted-marker"
            assert read_calls == 1
    finally:
        if swap_succeeded:
            os.replace(source, replacement_source)
            os.replace(moved_source, source)


def test_temp_creation_is_bound_to_verified_parent_before_first_write(
    safe_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = safe_root / "prewrite-binding.txt"
    original_lookup = windows_files._directory_child_file_id
    original_write = windows_files._write_all
    temp_lookup_seen = False
    write_calls = 0

    def mismatching_lookup(
        parent_handle: int,
        child_name: str,
        *,
        missing_ok: bool,
    ) -> int | None:
        nonlocal temp_lookup_seen
        file_id = original_lookup(parent_handle, child_name, missing_ok=missing_ok)
        if child_name.startswith(".private-write-") and file_id is not None:
            temp_lookup_seen = True
            return file_id + 1
        return file_id

    def recording_write(handle: int, content: bytes) -> None:
        nonlocal write_calls
        write_calls += 1
        original_write(handle, content)

    monkeypatch.setattr(windows_files, "_directory_child_file_id", mismatching_lookup)
    monkeypatch.setattr(windows_files, "_write_all", recording_write)

    with pytest.raises(SensitivePathError) as captured:
        atomic_write_private_text(output, "synthetic-secret-marker")

    assert captured.value.code == "sensitive_path_identity_mismatch"
    assert temp_lookup_seen
    assert write_calls == 0
    assert not output.exists()
    assert not tuple(safe_root.glob(".private-write-*.tmp"))


def test_publication_uses_verified_absolute_destination(
    safe_root: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = safe_root / "absolute-publication.txt"
    observed: list[Path] = []
    original_rename = windows_files._rename_handle

    def recording_rename(
        handle: int,
        destination_path: Path,
        *,
        overwrite: bool,
    ) -> None:
        observed.append(destination_path)
        original_rename(
            handle,
            destination_path,
            overwrite=overwrite,
        )

    monkeypatch.setattr(windows_files, "_rename_handle", recording_rename)
    atomic_write_private_text(output, "synthetic-marker")

    assert observed == [output]
    assert observed[0].is_absolute()
    assert observed[0].parent == safe_root


def test_b7_parent_rename_is_detected_before_publication(safe_root: Path) -> None:
    parent = create_acl_directory(safe_root / "bound-parent")
    moved = safe_root / "bound-parent-moved"
    output = parent / "marker.txt"
    started = threading.Event()
    finished = threading.Event()
    results: list[str] = []

    def attacker() -> None:
        started.wait()
        try:
            os.replace(parent, moved)
        except OSError:
            results.append("blocked")
        else:
            results.append("renamed")
        finally:
            finished.set()

    thread = threading.Thread(target=attacker)
    try:
        with windows_files._locked_parent(
            output,
            REPOSITORY_ROOT,
            require_safe_parent_acl=True,
            require_persistent_acls=True,
        ) as bound:
            thread.start()
            started.set()
            assert finished.wait(timeout=5)
            assert results in (["blocked"], ["renamed"])
            if results == ["renamed"]:
                with pytest.raises(windows_files.WindowsSensitiveFileError) as excinfo:
                    windows_files._verify_bound_parent(bound)
                assert excinfo.value.code == "sensitive_path_identity_mismatch"
    finally:
        thread.join(timeout=5)
        if moved.exists() and not parent.exists():
            os.replace(moved, parent)

    assert parent.is_dir()
    assert not moved.exists()
    assert not output.exists()


def test_b8_exclusive_temp_handle_blocks_substitution(safe_root: Path) -> None:
    output = safe_root / "final.txt"
    temp = safe_root / "exclusive.tmp"
    results: list[str] = []
    started = threading.Event()
    finished = threading.Event()

    with windows_files._locked_parent(
        output,
        REPOSITORY_ROOT,
        require_safe_parent_acl=True,
        require_persistent_acls=True,
    ):
        with windows_files._private_security_attributes() as attributes:
            handle = windows_files._create_file(
                temp,
                access=(
                    windows_files._GENERIC_READ
                    | windows_files._GENERIC_WRITE
                    | windows_files._DELETE
                    | windows_files._READ_CONTROL
                    | windows_files._FILE_READ_ATTRIBUTES
                ),
                share=0,
                disposition=windows_files._CREATE_NEW,
                flags=windows_files._FILE_ATTRIBUTE_NORMAL,
                security_attributes=attributes,
            )
        assert handle is not None

        def attacker() -> None:
            started.wait()
            try:
                temp.unlink()
            except OSError:
                results.append("blocked")
            else:
                results.append("deleted")
            finally:
                finished.set()

        thread = threading.Thread(target=attacker)
        with handle:
            thread.start()
            started.set()
            assert finished.wait(timeout=5)
            assert results == ["blocked"]
            value = handle.value
            assert value is not None
            windows_files._write_all(value, b"synthetic-marker")
            windows_files._mark_for_deletion(value)
        thread.join(timeout=5)
    assert not temp.exists()
    assert not output.exists()


def test_hard_link_alias_is_rejected(safe_root: Path) -> None:
    original = safe_root / "original.txt"
    alias = safe_root / "alias.txt"
    atomic_write_private_text(original, "synthetic-marker")
    os.link(original, alias)
    with pytest.raises(SensitivePathError) as captured:
        read_sensitive_bytes(
            alias,
            windows_private_acl=True,
            windows_require_protected_acl=True,
        )
    assert captured.value.code == "sensitive_path_hardlink"


def test_c1_c2_private_file_does_not_inherit_broad_parent_read(tmp_path: Path) -> None:
    parent = create_acl_directory(tmp_path / "broad-read-parent", broad_read=True)
    private = parent / "private.txt"
    public_safe = parent / "public-safe.txt"
    atomic_write_private_text(private, "synthetic-secret-marker")
    atomic_write_integrity_text(public_safe, "sanitized aggregate marker")

    assert_private_file(private)
    assert not has_effective_right(
        private,
        windows_files._WIN_BUILTIN_USERS_SID,
        windows_files._FILE_READ_DATA,
    )
    assert has_effective_right(
        public_safe,
        windows_files._WIN_BUILTIN_USERS_SID,
        windows_files._FILE_READ_DATA,
    )


def test_intermediate_ancestor_broad_rebind_authority_is_rejected(
    safe_root: Path,
) -> None:
    ancestor = create_acl_directory(safe_root / "unsafe-ancestor", broad_write=True)
    parent = create_acl_directory(ancestor / "safe-child")
    output = parent / "marker.txt"

    with pytest.raises(SensitivePathError) as captured:
        atomic_write_private_text(output, "synthetic-marker")

    assert captured.value.code in {
        "sensitive_acl_unsafe",
        "sensitive_ancestor_acl_unsafe",
    }
    assert not output.exists()
    assert not tuple(parent.glob(".private-write-*.tmp"))


def test_c3_parent_broad_write_is_rejected_before_marker(tmp_path: Path) -> None:
    parent = create_acl_directory(tmp_path / "broad-write-parent", broad_write=True)
    output = parent / "marker.txt"
    with pytest.raises(SensitivePathError) as captured:
        atomic_write_private_text(output, "synthetic-marker")
    assert captured.value.code in {"sensitive_acl_unsafe", "sensitive_parent_acl_unsafe"}
    assert not output.exists()
    assert not tuple(parent.glob(".private-write-*.tmp"))


def test_integrity_output_strips_child_only_broad_write_but_preserves_read(
    tmp_path: Path,
) -> None:
    parent = create_acl_directory(
        tmp_path / "inherited-write-parent",
        broad_read=True,
        inherited_broad_write=True,
    )
    output = parent / "sanitized-report.txt"
    atomic_write_integrity_text(output, "sanitized aggregate marker")

    assert has_effective_right(
        output,
        windows_files._WIN_BUILTIN_USERS_SID,
        windows_files._FILE_READ_DATA,
    )
    assert not has_effective_right(
        output,
        windows_files._WIN_BUILTIN_USERS_SID,
        windows_files._INTEGRITY_UNSAFE_MASK,
    )
    handle = windows_files._open_regular_file(output, write=False, missing_ok=False)
    assert handle is not None
    with handle:
        value = handle.value
        assert value is not None
        windows_files._verify_integrity_acl(
            value,
            require_protected=True,
            require_write=False,
        )


def test_parent_acl_recheck_detects_change_before_publish(safe_root: Path) -> None:
    parent = create_acl_directory(safe_root / "recheck-parent")
    output = parent / "final.txt"
    temp = parent / "recheck.tmp"
    with windows_files._locked_parent(
        output,
        REPOSITORY_ROOT,
        require_safe_parent_acl=True,
        require_persistent_acls=True,
    ) as binding:
        with windows_files._private_security_attributes() as attributes:
            handle = windows_files._create_file(
                temp,
                access=(
                    windows_files._GENERIC_READ
                    | windows_files._GENERIC_WRITE
                    | windows_files._DELETE
                    | windows_files._READ_CONTROL
                    | windows_files._FILE_READ_ATTRIBUTES
                ),
                share=0,
                disposition=windows_files._CREATE_NEW,
                flags=windows_files._FILE_ATTRIBUTE_NORMAL,
                security_attributes=attributes,
            )
        assert handle is not None
        with handle:
            value = handle.value
            assert value is not None
            windows_files._write_all(value, b"synthetic-marker")
            set_directory_acl(parent, broad_write=True)
            with pytest.raises(windows_files.WindowsSensitiveFileError):
                windows_files._verify_parent_acl(binding.handle)
            windows_files._mark_for_deletion(value)
    assert not output.exists()


@pytest.mark.parametrize("principal", ["BU", "WD", "AU"])
def test_c4_c5_c6_broad_file_read_is_rejected(
    safe_root: Path,
    principal: str,
) -> None:
    path = safe_root / f"broad-{principal}.txt"
    atomic_write_private_text(path, "synthetic-marker")
    set_private_file_acl(path, broad_principal=principal)
    with pytest.raises(SensitivePathError) as captured:
        read_sensitive_bytes(
            path,
            windows_private_acl=True,
            windows_require_protected_acl=True,
        )
    assert captured.value.code == "sensitive_acl_unsafe"


def test_c9_temp_acl_is_private_before_first_content_byte(safe_root: Path) -> None:
    temp = safe_root / "prewrite.tmp"
    with windows_files._private_security_attributes() as attributes:
        handle = windows_files._create_file(
            temp,
            access=(
                windows_files._GENERIC_READ
                | windows_files._GENERIC_WRITE
                | windows_files._DELETE
                | windows_files._READ_CONTROL
                | windows_files._FILE_READ_ATTRIBUTES
            ),
            share=0,
            disposition=windows_files._CREATE_NEW,
            flags=windows_files._FILE_ATTRIBUTE_NORMAL,
            security_attributes=attributes,
        )
    assert handle is not None
    with handle:
        value = handle.value
        assert value is not None
        assert temp.stat().st_size == 0
        windows_files._verify_private_acl(value, require_protected=True, require_write=True)
        windows_files._mark_for_deletion(value)
    assert not temp.exists()


def test_handle_lifecycle_has_no_net_leak_and_errors_are_redacted(safe_root: Path) -> None:
    get_handle_count = windows_files._kernel32.GetProcessHandleCount
    get_handle_count.argtypes = [
        windows_files.wintypes.HANDLE,
        ctypes.POINTER(windows_files.wintypes.DWORD),
    ]
    get_handle_count.restype = windows_files.wintypes.BOOL

    def count() -> int:
        value = windows_files.wintypes.DWORD()
        assert get_handle_count(windows_files._GetCurrentProcess(), ctypes.byref(value))
        return int(value.value)

    candidate = safe_root / "missing.txt"
    validate_sensitive_output_path(candidate)
    before = count()
    for _ in range(20):
        validate_sensitive_output_path(candidate)
    after = count()
    assert after == before

    owned = windows_files._open_directory(safe_root, parent=True)
    owned.close()
    owned.close()
    assert owned.value is None
    with pytest.raises(windows_files.WindowsSensitiveFileError) as invalid_handle:
        windows_files._attributes(windows_files._INVALID_HANDLE_VALUE)
    assert invalid_handle.value.code == "sensitive_path_unavailable"
    assert "S-1-" not in str(invalid_handle.value)

    marker = "private-path-marker"
    bad = safe_root / marker
    create_acl_directory(bad, broad_write=True)
    with pytest.raises(SensitivePathError) as captured:
        atomic_write_private_text(bad / "content-marker", "secret-content-marker")
    rendered = str(captured.value)
    assert str(bad) not in rendered
    assert marker not in rendered
    assert "secret-content-marker" not in rendered
    assert "S-1-" not in rendered
