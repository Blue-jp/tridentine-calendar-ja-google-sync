"""Synthetic-only Windows ACL and junction helpers for Phase 6D.1F tests."""

from __future__ import annotations

import contextlib
import ctypes
import os
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

from tridentine_calendar_google_sync import _windows_sensitive_files as windows_files

if sys.platform == "win32":
    from ctypes import wintypes

    _CreateDirectoryW = windows_files._kernel32.CreateDirectoryW
    _CreateDirectoryW.argtypes = [wintypes.LPCWSTR, wintypes.LPVOID]
    _CreateDirectoryW.restype = wintypes.BOOL

    _SetFileSecurityW = windows_files._advapi32.SetFileSecurityW
    _SetFileSecurityW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPVOID]
    _SetFileSecurityW.restype = wintypes.BOOL

    _OWNER_SECURITY_INFORMATION = 0x00000001
    _DACL_SECURITY_INFORMATION = 0x00000004
    _PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000


def _require_windows() -> None:
    if sys.platform != "win32":
        raise RuntimeError("Windows-only synthetic test helper")


def _current_sid_text() -> str:
    _require_windows()
    sid = windows_files._current_user_sid()
    sid_buffer, sid_pointer = windows_files._sid_pointer(sid)
    sid_text = wintypes.LPWSTR()
    if (
        not windows_files._ConvertSidToStringSidW(
            sid_pointer,
            ctypes.byref(sid_text),
        )
        or not sid_text.value
    ):
        raise OSError("synthetic SID conversion failed")
    pointer = ctypes.cast(sid_text, ctypes.c_void_p).value
    if pointer is None:
        raise OSError("synthetic SID conversion failed")
    owner = windows_files._OwnedLocal(pointer)
    with owner:
        value = sid_text.value
    del sid_buffer
    return value


@contextlib.contextmanager
def _security_attributes(sddl: str) -> Iterator[object]:
    _require_windows()
    descriptor = wintypes.LPVOID()
    if (
        not windows_files._ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl,
            windows_files._SECURITY_DESCRIPTOR_REVISION,
            ctypes.byref(descriptor),
            None,
        )
        or not descriptor.value
    ):
        raise OSError("synthetic security descriptor creation failed")
    descriptor_value = descriptor.value
    if descriptor_value is None:
        raise OSError("synthetic security descriptor creation failed")
    owner = windows_files._OwnedLocal(descriptor_value)
    with owner:
        yield windows_files._SecurityAttributes(
            ctypes.sizeof(windows_files._SecurityAttributes),
            descriptor,
            False,
        )


def directory_sddl(
    *,
    broad_read: bool = False,
    broad_write: bool = False,
    inherited_broad_write: bool = False,
) -> str:
    sid = _current_sid_text()
    additions = ""
    if broad_read:
        additions += "(A;OICI;GRGX;;;BU)"
    if broad_write:
        additions += "(A;OICI;GWGXSD;;;BU)"
    if inherited_broad_write:
        additions += "(A;OICIIO;GWGXSD;;;BU)"
    return f"O:{sid}D:P(A;OICI;FA;;;{sid})(A;OICI;FA;;;SY)(A;OICI;FA;;;BA){additions}"


def create_acl_directory(
    path: Path,
    *,
    broad_read: bool = False,
    broad_write: bool = False,
    inherited_broad_write: bool = False,
) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with _security_attributes(
        directory_sddl(
            broad_read=broad_read,
            broad_write=broad_write,
            inherited_broad_write=inherited_broad_write,
        )
    ) as attributes:
        if not _CreateDirectoryW(str(path), ctypes.byref(attributes)):
            raise OSError("synthetic ACL directory creation failed")
    return path


def protect_acl_directory(path: Path) -> None:
    """Give an existing synthetic test directory a protected private DACL."""

    with _security_attributes(directory_sddl()) as attributes:
        descriptor = attributes.lpSecurityDescriptor
        information = (
            _OWNER_SECURITY_INFORMATION
            | _DACL_SECURITY_INFORMATION
            | _PROTECTED_DACL_SECURITY_INFORMATION
        )
        if not _SetFileSecurityW(str(path), information, descriptor):
            raise OSError("synthetic directory ACL update failed")


def set_directory_acl(
    path: Path,
    *,
    broad_read: bool = False,
    broad_write: bool = False,
    inherited_broad_write: bool = False,
) -> None:
    with _security_attributes(
        directory_sddl(
            broad_read=broad_read,
            broad_write=broad_write,
            inherited_broad_write=inherited_broad_write,
        )
    ) as attributes:
        descriptor = attributes.lpSecurityDescriptor
        information = (
            _OWNER_SECURITY_INFORMATION
            | _DACL_SECURITY_INFORMATION
            | _PROTECTED_DACL_SECURITY_INFORMATION
        )
        if not _SetFileSecurityW(str(path), information, descriptor):
            raise OSError("synthetic directory ACL update failed")


def set_private_file_acl(
    path: Path,
    *,
    broad_principal: str | None = None,
    broad_rights: str = "GR",
) -> None:
    sid = _current_sid_text()
    broad = f"(A;;{broad_rights};;;{broad_principal})" if broad_principal is not None else ""
    sddl = f"O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FA;;;BA){broad}"
    with _security_attributes(sddl) as attributes:
        descriptor = attributes.lpSecurityDescriptor
        information = (
            _OWNER_SECURITY_INFORMATION
            | _DACL_SECURITY_INFORMATION
            | _PROTECTED_DACL_SECURITY_INFORMATION
        )
        if not _SetFileSecurityW(str(path), information, descriptor):
            raise OSError("synthetic file ACL update failed")


def has_effective_right(path: Path, sid_type: int, mask: int) -> bool:
    handle = windows_files._open_regular_file(path, write=False, missing_ok=False)
    if handle is None:
        raise AssertionError("synthetic file is missing")
    with handle:
        value = handle.value
        if value is None:
            raise AssertionError("synthetic file handle is closed")
        with windows_files._security_info(value) as (_owner, dacl, _descriptor):
            rights = windows_files._effective_rights(
                dacl,
                windows_files._well_known_sid(sid_type),
            )
    return bool(rights & mask)


def assert_private_file(path: Path) -> None:
    handle = windows_files._open_regular_file(path, write=False, missing_ok=False)
    if handle is None:
        raise AssertionError("synthetic file is missing")
    with handle:
        value = handle.value
        if value is None:
            raise AssertionError("synthetic file handle is closed")
        windows_files._verify_private_acl(
            value,
            require_protected=True,
            require_write=False,
        )


def create_junction(link: Path, target: Path) -> None:
    completed = subprocess.run(
        ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    if completed.returncode != 0 or not link.is_junction():
        raise OSError("synthetic junction creation failed")


def remove_junction(link: Path) -> None:
    if link.is_junction():
        os.rmdir(link)


__all__ = [
    "assert_private_file",
    "create_acl_directory",
    "create_junction",
    "has_effective_right",
    "protect_acl_directory",
    "remove_junction",
    "set_directory_acl",
    "set_private_file_acl",
]
