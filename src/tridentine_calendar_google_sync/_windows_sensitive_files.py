"""Handle-bound Windows I/O for repository-external sensitive artifacts.

The public helpers in :mod:`sensitive_paths` perform policy validation.  This
module supplies the Windows-specific use-time boundary that Python's path API
cannot express: every ancestor is opened without delete sharing, every reparse
point is rejected, content is read from the verified handle, and writes publish
the exact temporary-file handle into the verified parent directory.

Only documented Win32 APIs exposed by ``kernel32`` and ``advapi32`` are used.
The module is importable on non-Windows platforms; calls there fail closed.
"""

from __future__ import annotations

import contextlib
import ctypes
import hmac
import ntpath
import secrets
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import NoReturn


class WindowsSensitiveFileError(ValueError):
    """A path-, SID-, and content-free Windows filesystem failure."""

    def __init__(self, code: str, public_message: str) -> None:
        self.code = code
        self.public_message = public_message
        super().__init__(public_message)


@dataclass(frozen=True, repr=False)
class WindowsSensitivePathIdentity:
    """Opaque filesystem identity used only for equality comparisons."""

    exists: bool
    volume_serial: int
    file_index: int
    parent_volume_serial: int
    parent_file_index: int
    leaf_key: str = field(repr=False)


if sys.platform == "win32":
    from ctypes import wintypes

    # Access, sharing, creation, attributes, and file-information classes.
    _DELETE = 0x00010000
    _READ_CONTROL = 0x00020000
    _WRITE_DAC = 0x00040000
    _WRITE_OWNER = 0x00080000
    _SYNCHRONIZE = 0x00100000
    _FILE_READ_DATA = 0x00000001
    _FILE_WRITE_DATA = 0x00000002
    _FILE_APPEND_DATA = 0x00000004
    _FILE_READ_EA = 0x00000008
    _FILE_WRITE_EA = 0x00000010
    _FILE_EXECUTE = 0x00000020
    _FILE_DELETE_CHILD = 0x00000040
    _FILE_READ_ATTRIBUTES = 0x00000080
    _FILE_WRITE_ATTRIBUTES = 0x00000100
    _GENERIC_READ = 0x80000000
    _GENERIC_WRITE = 0x40000000
    _FILE_SHARE_READ = 0x00000001
    _FILE_SHARE_WRITE = 0x00000002
    _CREATE_NEW = 1
    _OPEN_EXISTING = 3
    _FILE_ATTRIBUTE_DIRECTORY = 0x00000010
    _FILE_ATTRIBUTE_NORMAL = 0x00000080
    _FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400
    _FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
    _FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000
    _FILE_RENAME_INFO_CLASS = 3
    _FILE_DISPOSITION_INFO_CLASS = 4
    _FILE_ATTRIBUTE_TAG_INFO_CLASS = 9
    _FILE_ID_BOTH_DIRECTORY_INFO_CLASS = 10
    _FILE_ID_BOTH_DIRECTORY_RESTART_INFO_CLASS = 11
    _FILE_ID_TYPE = 0
    _FILE_TYPE_DISK = 0x0001
    _ERROR_FILE_NOT_FOUND = 2
    _ERROR_PATH_NOT_FOUND = 3
    _ERROR_FILE_EXISTS = 80
    _ERROR_ALREADY_EXISTS = 183
    _ERROR_SHARING_VIOLATION = 32
    _ERROR_NO_MORE_FILES = 18
    _MISSING_ERRORS = {_ERROR_FILE_NOT_FOUND, _ERROR_PATH_NOT_FOUND}
    _COLLISION_ERRORS = {_ERROR_FILE_EXISTS, _ERROR_ALREADY_EXISTS}
    _INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
    _MAX_IO_CHUNK = 1024 * 1024
    _DIRECTORY_ENUM_BUFFER_BYTES = 64 * 1024

    # Security information and ACL constants.
    _SE_FILE_OBJECT = 1
    _OWNER_SECURITY_INFORMATION = 0x00000001
    _DACL_SECURITY_INFORMATION = 0x00000004
    _SE_DACL_PROTECTED = 0x1000
    _TOKEN_QUERY = 0x0008
    _TOKEN_USER_CLASS = 1
    _SECURITY_DESCRIPTOR_REVISION = 1
    _ACL_SIZE_INFORMATION_CLASS = 2
    _INHERIT_ONLY_ACE = 0x08
    _ACCESS_ALLOWED_ACE_TYPES = frozenset({0, 5, 9, 11})
    _ACCESS_DENIED_ACE_TYPES = frozenset({1, 6, 10, 12})
    _ACE_OBJECT_TYPE_PRESENT = 0x1
    _ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2
    _SECURITY_MAX_SID_SIZE = 68
    _WIN_WORLD_SID = 1
    _WIN_LOCAL_SID = 2
    _WIN_INTERACTIVE_SID = 11
    _WIN_AUTHENTICATED_USER_SID = 17
    _WIN_LOCAL_SYSTEM_SID = 22
    _WIN_BUILTIN_ADMINISTRATORS_SID = 26
    _WIN_BUILTIN_USERS_SID = 27
    _WIN_CREATOR_OWNER_RIGHTS_SID = 71
    _BROAD_SID_TYPES = (
        _WIN_WORLD_SID,
        _WIN_LOCAL_SID,
        _WIN_INTERACTIVE_SID,
        _WIN_AUTHENTICATED_USER_SID,
        _WIN_BUILTIN_USERS_SID,
    )
    _FILE_GENERIC_READ = (
        _READ_CONTROL | _FILE_READ_DATA | _FILE_READ_ATTRIBUTES | _FILE_READ_EA | _SYNCHRONIZE
    )
    _FILE_GENERIC_WRITE = (
        _READ_CONTROL
        | _FILE_WRITE_DATA
        | _FILE_APPEND_DATA
        | _FILE_WRITE_ATTRIBUTES
        | _FILE_WRITE_EA
        | _SYNCHRONIZE
    )
    _FILE_GENERIC_EXECUTE = _READ_CONTROL | _FILE_READ_ATTRIBUTES | _FILE_EXECUTE | _SYNCHRONIZE
    _FILE_ALL_ACCESS = 0x001F01FF
    _PRIVATE_READ_MASK = _FILE_READ_DATA
    _PRIVATE_UNSAFE_MASK = (
        _FILE_READ_DATA | _FILE_WRITE_DATA | _FILE_APPEND_DATA | _DELETE | _WRITE_DAC | _WRITE_OWNER
    )
    _INTEGRITY_UNSAFE_MASK = (
        _FILE_WRITE_DATA | _FILE_APPEND_DATA | _DELETE | _WRITE_DAC | _WRITE_OWNER
    )
    _PARENT_MUTATION_MASK = (
        _FILE_WRITE_DATA
        | _FILE_APPEND_DATA
        | _FILE_DELETE_CHILD
        | _DELETE
        | _WRITE_DAC
        | _WRITE_OWNER
    )
    _ANCESTOR_REBIND_MASK = _FILE_DELETE_CHILD | _DELETE | _WRITE_DAC | _WRITE_OWNER
    _FILE_PERSISTENT_ACLS = 0x00000008
    _DRIVE_UNKNOWN = 0
    _DRIVE_NO_ROOT_DIR = 1
    _DRIVE_REMOTE = 4

    _INVALID_COMPONENT_CHARACTERS = frozenset('<>:"|?*')
    _RESERVED_DEVICE_NAMES = {
        "AUX",
        "CON",
        "CONIN$",
        "CONOUT$",
        "NUL",
        "PRN",
        *(f"COM{number}" for number in range(1, 10)),
        *(f"LPT{number}" for number in range(1, 10)),
        *(f"COM{number}" for number in "¹²³"),
        *(f"LPT{number}" for number in "¹²³"),
    }

    class _FileAttributeTagInfo(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", wintypes.DWORD),
            ("ReparseTag", wintypes.DWORD),
        ]

    class _FileId128(ctypes.Structure):
        _fields_ = [("Identifier", ctypes.c_ubyte * 16)]

    class _FileIdDescriptorValue(ctypes.Union):
        _fields_ = [
            ("FileId", ctypes.c_longlong),
            ("ObjectId", ctypes.c_ubyte * 16),
            ("ExtendedFileId", _FileId128),
        ]

    class _FileIdDescriptor(ctypes.Structure):
        _anonymous_ = ("Value",)
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("Type", ctypes.c_int),
            ("Value", _FileIdDescriptorValue),
        ]

    class _FileIdBothDirectoryInfo(ctypes.Structure):
        _fields_ = [
            ("NextEntryOffset", wintypes.DWORD),
            ("FileIndex", wintypes.DWORD),
            ("CreationTime", ctypes.c_longlong),
            ("LastAccessTime", ctypes.c_longlong),
            ("LastWriteTime", ctypes.c_longlong),
            ("ChangeTime", ctypes.c_longlong),
            ("EndOfFile", ctypes.c_longlong),
            ("AllocationSize", ctypes.c_longlong),
            ("FileAttributes", wintypes.DWORD),
            ("FileNameLength", wintypes.DWORD),
            ("EaSize", wintypes.DWORD),
            ("ShortNameLength", ctypes.c_byte),
            ("ShortName", wintypes.WCHAR * 12),
            ("FileId", ctypes.c_longlong),
            ("FileName", wintypes.WCHAR * 1),
        ]

    class _ByHandleFileInformation(ctypes.Structure):
        _fields_ = [
            ("FileAttributes", wintypes.DWORD),
            ("CreationTime", wintypes.FILETIME),
            ("LastAccessTime", wintypes.FILETIME),
            ("LastWriteTime", wintypes.FILETIME),
            ("VolumeSerialNumber", wintypes.DWORD),
            ("FileSizeHigh", wintypes.DWORD),
            ("FileSizeLow", wintypes.DWORD),
            ("NumberOfLinks", wintypes.DWORD),
            ("FileIndexHigh", wintypes.DWORD),
            ("FileIndexLow", wintypes.DWORD),
        ]

    class _FileDispositionInfo(ctypes.Structure):
        _fields_ = [("DeleteFile", wintypes.BOOLEAN)]

    class _FileRenameInfo(ctypes.Structure):
        _fields_ = [
            ("FlagsOrReplaceIfExists", wintypes.DWORD),
            ("RootDirectory", wintypes.HANDLE),
            ("FileNameLength", wintypes.DWORD),
            ("FileName", wintypes.WCHAR * 1),
        ]

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", wintypes.LPVOID),
            ("bInheritHandle", wintypes.BOOL),
        ]

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = [
            ("Sid", wintypes.LPVOID),
            ("Attributes", wintypes.DWORD),
        ]

    class _TokenUser(ctypes.Structure):
        _fields_ = [("User", _SidAndAttributes)]

    class _AclSizeInformation(ctypes.Structure):
        _fields_ = [
            ("AceCount", wintypes.DWORD),
            ("AclBytesInUse", wintypes.DWORD),
            ("AclBytesFree", wintypes.DWORD),
        ]

    class _AceHeader(ctypes.Structure):
        _fields_ = [
            ("AceType", wintypes.BYTE),
            ("AceFlags", wintypes.BYTE),
            ("AceSize", wintypes.WORD),
        ]

    class _GenericMapping(ctypes.Structure):
        _fields_ = [
            ("GenericRead", wintypes.DWORD),
            ("GenericWrite", wintypes.DWORD),
            ("GenericExecute", wintypes.DWORD),
            ("GenericAll", wintypes.DWORD),
        ]

    class _TrusteeW(ctypes.Structure):
        pass

    _TrusteeW._fields_ = [
        ("pMultipleTrustee", ctypes.POINTER(_TrusteeW)),
        ("MultipleTrusteeOperation", ctypes.c_int),
        ("TrusteeForm", ctypes.c_int),
        ("TrusteeType", ctypes.c_int),
        ("ptstrName", wintypes.LPWSTR),
    ]

    @dataclass(frozen=True, repr=False)
    class _FileIdentity:
        volume_serial: int
        file_index: int

    @dataclass(frozen=True, repr=False)
    class _DestinationState:
        exists: bool
        identity: _FileIdentity | None

    @dataclass(frozen=True, repr=False)
    class _BoundDirectory:
        path: Path = field(repr=False)
        handle: int
        identity: _FileIdentity

    @dataclass(frozen=True, repr=False)
    class _BoundParent:
        path: Path = field(repr=False)
        handle: int
        identity: _FileIdentity
        chain: tuple[_BoundDirectory, ...] = field(repr=False)

    class _OwnedHandle:
        """Own one Win32 HANDLE and close it exactly once."""

        def __init__(self, value: int) -> None:
            self.value: int | None = value

        def close(self) -> None:
            value = self.value
            if value is None:
                return
            self.value = None
            if not _CloseHandle(value):
                _fail("sensitive_handle_close_failed", "sensitive file handle cleanup failed")

        def __enter__(self) -> _OwnedHandle:
            return self

        def __exit__(self, *_: object) -> None:
            self.close()

    class _OwnedLocal:
        """Own one LocalAlloc-compatible pointer and free it exactly once."""

        def __init__(self, value: int) -> None:
            self.value: int | None = value

        def close(self) -> None:
            value = self.value
            if value is None:
                return
            self.value = None
            if _LocalFree(value):
                _fail("sensitive_local_free_failed", "sensitive security cleanup failed")

        def __enter__(self) -> _OwnedLocal:
            return self

        def __exit__(self, *_: object) -> None:
            self.close()

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

    _GetCurrentProcess = _kernel32.GetCurrentProcess
    _GetCurrentProcess.argtypes = []
    _GetCurrentProcess.restype = wintypes.HANDLE

    _CreateFileW = _kernel32.CreateFileW
    _CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    _CreateFileW.restype = wintypes.HANDLE

    _OpenFileById = _kernel32.OpenFileById
    _OpenFileById.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_FileIdDescriptor),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _OpenFileById.restype = wintypes.HANDLE

    _CloseHandle = _kernel32.CloseHandle
    _CloseHandle.argtypes = [wintypes.HANDLE]
    _CloseHandle.restype = wintypes.BOOL

    _LocalFree = _kernel32.LocalFree
    _LocalFree.argtypes = [wintypes.HLOCAL]
    _LocalFree.restype = wintypes.HLOCAL

    _GetFileInformationByHandleEx = _kernel32.GetFileInformationByHandleEx
    _GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _GetFileInformationByHandleEx.restype = wintypes.BOOL

    _GetFileInformationByHandle = _kernel32.GetFileInformationByHandle
    _GetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_ByHandleFileInformation),
    ]
    _GetFileInformationByHandle.restype = wintypes.BOOL

    _GetFinalPathNameByHandleW = _kernel32.GetFinalPathNameByHandleW
    _GetFinalPathNameByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    ]
    _GetFinalPathNameByHandleW.restype = wintypes.DWORD

    _GetFileType = _kernel32.GetFileType
    _GetFileType.argtypes = [wintypes.HANDLE]
    _GetFileType.restype = wintypes.DWORD

    _GetFileSizeEx = _kernel32.GetFileSizeEx
    _GetFileSizeEx.argtypes = [wintypes.HANDLE, ctypes.POINTER(ctypes.c_longlong)]
    _GetFileSizeEx.restype = wintypes.BOOL

    _ReadFile = _kernel32.ReadFile
    _ReadFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _ReadFile.restype = wintypes.BOOL

    _WriteFile = _kernel32.WriteFile
    _WriteFile.argtypes = [
        wintypes.HANDLE,
        wintypes.LPCVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPVOID,
    ]
    _WriteFile.restype = wintypes.BOOL

    _FlushFileBuffers = _kernel32.FlushFileBuffers
    _FlushFileBuffers.argtypes = [wintypes.HANDLE]
    _FlushFileBuffers.restype = wintypes.BOOL

    _SetFileInformationByHandle = _kernel32.SetFileInformationByHandle
    _SetFileInformationByHandle.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    _SetFileInformationByHandle.restype = wintypes.BOOL

    _GetVolumeInformationByHandleW = _kernel32.GetVolumeInformationByHandleW
    _GetVolumeInformationByHandleW.argtypes = [
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
        wintypes.LPWSTR,
        wintypes.DWORD,
    ]
    _GetVolumeInformationByHandleW.restype = wintypes.BOOL

    _GetDriveTypeW = _kernel32.GetDriveTypeW
    _GetDriveTypeW.argtypes = [wintypes.LPCWSTR]
    _GetDriveTypeW.restype = wintypes.UINT

    _OpenProcessToken = _advapi32.OpenProcessToken
    _OpenProcessToken.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    ]
    _OpenProcessToken.restype = wintypes.BOOL

    _GetTokenInformation = _advapi32.GetTokenInformation
    _GetTokenInformation.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _GetTokenInformation.restype = wintypes.BOOL

    _GetLengthSid = _advapi32.GetLengthSid
    _GetLengthSid.argtypes = [wintypes.LPVOID]
    _GetLengthSid.restype = wintypes.DWORD

    _CopySid = _advapi32.CopySid
    _CopySid.argtypes = [wintypes.DWORD, wintypes.LPVOID, wintypes.LPVOID]
    _CopySid.restype = wintypes.BOOL

    _IsValidSid = _advapi32.IsValidSid
    _IsValidSid.argtypes = [wintypes.LPVOID]
    _IsValidSid.restype = wintypes.BOOL

    _EqualSid = _advapi32.EqualSid
    _EqualSid.argtypes = [wintypes.LPVOID, wintypes.LPVOID]
    _EqualSid.restype = wintypes.BOOL

    _CreateWellKnownSid = _advapi32.CreateWellKnownSid
    _CreateWellKnownSid.argtypes = [
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.DWORD),
    ]
    _CreateWellKnownSid.restype = wintypes.BOOL

    _ConvertSidToStringSidW = _advapi32.ConvertSidToStringSidW
    _ConvertSidToStringSidW.argtypes = [wintypes.LPVOID, ctypes.POINTER(wintypes.LPWSTR)]
    _ConvertSidToStringSidW.restype = wintypes.BOOL

    _ConvertStringSecurityDescriptorToSecurityDescriptorW = (
        _advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
    )
    _ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = wintypes.BOOL

    _GetSecurityInfo = _advapi32.GetSecurityInfo
    _GetSecurityInfo.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
        ctypes.POINTER(wintypes.LPVOID),
    ]
    _GetSecurityInfo.restype = wintypes.DWORD

    _GetSecurityDescriptorControl = _advapi32.GetSecurityDescriptorControl
    _GetSecurityDescriptorControl.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _GetSecurityDescriptorControl.restype = wintypes.BOOL

    _GetAclInformation = _advapi32.GetAclInformation
    _GetAclInformation.argtypes = [
        wintypes.LPVOID,
        wintypes.LPVOID,
        wintypes.DWORD,
        ctypes.c_int,
    ]
    _GetAclInformation.restype = wintypes.BOOL

    _GetAce = _advapi32.GetAce
    _GetAce.argtypes = [wintypes.LPVOID, wintypes.DWORD, ctypes.POINTER(wintypes.LPVOID)]
    _GetAce.restype = wintypes.BOOL

    _BuildTrusteeWithSidW = _advapi32.BuildTrusteeWithSidW
    _BuildTrusteeWithSidW.argtypes = [ctypes.POINTER(_TrusteeW), wintypes.LPVOID]
    _BuildTrusteeWithSidW.restype = None

    _GetEffectiveRightsFromAclW = _advapi32.GetEffectiveRightsFromAclW
    _GetEffectiveRightsFromAclW.argtypes = [
        wintypes.LPVOID,
        ctypes.POINTER(_TrusteeW),
        ctypes.POINTER(wintypes.DWORD),
    ]
    _GetEffectiveRightsFromAclW.restype = wintypes.DWORD

    _MapGenericMask = _advapi32.MapGenericMask
    _MapGenericMask.argtypes = [
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(_GenericMapping),
    ]
    _MapGenericMask.restype = None

    def _fail(code: str, message: str) -> NoReturn:
        raise WindowsSensitiveFileError(code, message)

    def _fail_last_error(code: str, message: str) -> NoReturn:
        # Consume the thread-local error for deterministic diagnostics without
        # exposing a private path, account name, or localized operating-system text.
        ctypes.get_last_error()
        _fail(code, message)

    def _extended_path(path: Path) -> str:
        value = str(path)
        if value.startswith("\\\\?\\"):
            return value
        return "\\\\?\\" + value

    def _normalized_path(value: str | Path) -> str:
        text = str(value)
        if text.startswith("\\\\?\\UNC\\"):
            text = "\\\\" + text[8:]
        elif text.startswith("\\\\?\\"):
            text = text[4:]
        return ntpath.normcase(ntpath.normpath(text))

    def _is_within(candidate: str | Path, root: str | Path) -> bool:
        normalized_candidate = _normalized_path(candidate)
        normalized_root = _normalized_path(root)
        try:
            return ntpath.commonpath((normalized_candidate, normalized_root)) == normalized_root
        except ValueError:
            return False

    def _validate_path_form(path: Path) -> Path:
        absolute = path.absolute()
        if not absolute.is_absolute() or not absolute.drive or absolute.anchor.startswith("\\\\"):
            _fail(
                "nonlocal_sensitive_path",
                "sensitive data must use an absolute local filesystem path",
            )
        for component in absolute.parts[1:]:
            if (
                not component
                or any(character in _INVALID_COMPONENT_CHARACTERS for character in component)
                or any(ord(character) < 32 for character in component)
                or component.endswith((" ", "."))
            ):
                _fail("sensitive_path_alias", "sensitive path uses an unsafe Windows alias")
            device_name = component.split(".", 1)[0].upper()
            if device_name in _RESERVED_DEVICE_NAMES:
                _fail("sensitive_path_alias", "sensitive path uses an unsafe Windows alias")
        return absolute

    def _create_file(
        path: Path,
        *,
        access: int,
        share: int,
        disposition: int,
        flags: int,
        security_attributes: _SecurityAttributes | None = None,
        missing_ok: bool = False,
        sharing_is_collision: bool = False,
    ) -> _OwnedHandle | None:
        attributes_pointer = (
            ctypes.byref(security_attributes) if security_attributes is not None else None
        )
        handle = _CreateFileW(
            _extended_path(path),
            access,
            share,
            attributes_pointer,
            disposition,
            flags,
            None,
        )
        if handle == _INVALID_HANDLE_VALUE:
            error = ctypes.get_last_error()
            if missing_ok and error in _MISSING_ERRORS:
                return None
            if error in _COLLISION_ERRORS or (
                sharing_is_collision and error == _ERROR_SHARING_VIOLATION
            ):
                _fail("sensitive_output_exists", "sensitive output already exists")
            _fail_last_error("sensitive_path_unavailable", "sensitive path is unavailable")
        return _OwnedHandle(int(handle))

    def _attributes(handle: int) -> _FileAttributeTagInfo:
        info = _FileAttributeTagInfo()
        if not _GetFileInformationByHandleEx(
            handle,
            _FILE_ATTRIBUTE_TAG_INFO_CLASS,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            _fail_last_error(
                "sensitive_path_unavailable",
                "sensitive path cannot be safely inspected",
            )
        return info

    def _file_information(handle: int) -> _ByHandleFileInformation:
        info = _ByHandleFileInformation()
        if not _GetFileInformationByHandle(handle, ctypes.byref(info)):
            _fail_last_error(
                "sensitive_path_unavailable",
                "sensitive path cannot be safely inspected",
            )
        return info

    def _identity(handle: int) -> _FileIdentity:
        info = _file_information(handle)
        return _FileIdentity(
            volume_serial=int(info.VolumeSerialNumber),
            file_index=(int(info.FileIndexHigh) << 32) | int(info.FileIndexLow),
        )

    def _file_id_key(value: int) -> int:
        return int(value) & 0xFFFFFFFFFFFFFFFF

    def _final_path(handle: int) -> str:
        size = _GetFinalPathNameByHandleW(handle, None, 0, 0)
        if size == 0:
            _fail_last_error(
                "sensitive_path_unavailable",
                "sensitive path cannot be safely inspected",
            )
        buffer = ctypes.create_unicode_buffer(size + 1)
        written = _GetFinalPathNameByHandleW(handle, buffer, len(buffer), 0)
        if written == 0 or written >= len(buffer):
            _fail_last_error(
                "sensitive_path_unavailable",
                "sensitive path cannot be safely inspected",
            )
        return buffer.value

    def _verify_handle_path(handle: int, expected: Path) -> None:
        if _normalized_path(_final_path(handle)) != _normalized_path(expected):
            _fail(
                "sensitive_path_identity_mismatch",
                "sensitive path resolved outside its verified filesystem identity",
            )

    def _verify_directory(handle: int, expected: Path) -> None:
        info = _attributes(handle)
        if info.FileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            _fail("sensitive_path_reparse", "reparse points are not accepted for sensitive data")
        if not info.FileAttributes & _FILE_ATTRIBUTE_DIRECTORY:
            _fail("sensitive_output_parent_missing", "sensitive output parent is unavailable")
        _verify_handle_path(handle, expected)

    def _verify_regular_file(handle: int, expected: Path) -> _ByHandleFileInformation:
        attributes = _attributes(handle)
        if attributes.FileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            _fail("sensitive_path_reparse", "reparse points are not accepted for sensitive data")
        if (
            attributes.FileAttributes & _FILE_ATTRIBUTE_DIRECTORY
            or _GetFileType(handle) != _FILE_TYPE_DISK
        ):
            _fail("sensitive_input_not_file", "sensitive input is not a regular local file")
        _verify_handle_path(handle, expected)
        info = _file_information(handle)
        if info.NumberOfLinks != 1:
            _fail(
                "sensitive_path_hardlink", "hard-linked files are not accepted for sensitive data"
            )
        return info

    def _verify_repository_boundary(path: Path, repository_root: Path) -> None:
        canonical_repository = repository_root.resolve(strict=True)
        if _is_within(path, canonical_repository):
            _fail(
                "sensitive_path_in_git_worktree",
                "sensitive data must be stored outside every Git worktree",
            )

    def _verify_volume(
        handle: int,
        path: Path,
        *,
        require_persistent_acls: bool,
    ) -> None:
        drive_type = int(_GetDriveTypeW(path.anchor))
        if drive_type in {_DRIVE_UNKNOWN, _DRIVE_NO_ROOT_DIR, _DRIVE_REMOTE}:
            _fail(
                "nonlocal_sensitive_path",
                "sensitive data must use a verified local filesystem",
            )
        serial = wintypes.DWORD()
        max_component = wintypes.DWORD()
        flags = wintypes.DWORD()
        if not _GetVolumeInformationByHandleW(
            handle,
            None,
            0,
            ctypes.byref(serial),
            ctypes.byref(max_component),
            ctypes.byref(flags),
            None,
            0,
        ):
            _fail_last_error(
                "sensitive_volume_unavailable",
                "sensitive filesystem capabilities cannot be verified",
            )
        if require_persistent_acls and not flags.value & _FILE_PERSISTENT_ACLS:
            _fail(
                "sensitive_acl_unsupported",
                "sensitive filesystem does not support persistent access controls",
            )

    def _open_directory(
        path: Path,
        *,
        parent: bool,
    ) -> _OwnedHandle:
        # Root/trust-anchor open.  Child components are opened by file ID from
        # their already-verified parent handle below.
        access = _FILE_READ_ATTRIBUTES | _FILE_READ_DATA | _FILE_EXECUTE
        if parent:
            access |= _READ_CONTROL
        handle = _create_file(
            path,
            access=access,
            share=_FILE_SHARE_READ | _FILE_SHARE_WRITE,
            disposition=_OPEN_EXISTING,
            flags=_FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        )
        if handle is None or handle.value is None:
            _fail("sensitive_path_unavailable", "sensitive path is unavailable")
        try:
            _verify_directory(handle.value, path)
        except BaseException:
            handle.close()
            raise
        return handle

    def _directory_child_file_id(
        parent_handle: int,
        child_name: str,
        *,
        missing_ok: bool,
    ) -> int | None:
        """Resolve one direct child to a stable file ID through the parent handle."""

        target_key = ntpath.normcase(child_name)
        restart = True
        while True:
            buffer = ctypes.create_string_buffer(_DIRECTORY_ENUM_BUFFER_BYTES)
            information_class = (
                _FILE_ID_BOTH_DIRECTORY_RESTART_INFO_CLASS
                if restart
                else _FILE_ID_BOTH_DIRECTORY_INFO_CLASS
            )
            if not _GetFileInformationByHandleEx(
                parent_handle,
                information_class,
                buffer,
                len(buffer),
            ):
                error = ctypes.get_last_error()
                if error == _ERROR_NO_MORE_FILES:
                    break
                _fail_last_error(
                    "sensitive_path_unavailable",
                    "sensitive path cannot be safely inspected",
                )
            restart = False
            base = ctypes.addressof(buffer)
            offset = 0
            while True:
                if offset < 0 or offset + _FileIdBothDirectoryInfo.FileName.offset > len(buffer):
                    _fail(
                        "sensitive_path_unavailable",
                        "sensitive directory information is invalid",
                    )
                entry_address = base + offset
                entry = ctypes.cast(
                    entry_address,
                    ctypes.POINTER(_FileIdBothDirectoryInfo),
                ).contents
                name_bytes = int(entry.FileNameLength)
                wchar_bytes = ctypes.sizeof(wintypes.WCHAR)
                name_start = entry_address + _FileIdBothDirectoryInfo.FileName.offset
                name_end = name_start + name_bytes
                if (
                    name_bytes <= 0
                    or name_bytes % wchar_bytes != 0
                    or name_end > base + len(buffer)
                ):
                    _fail(
                        "sensitive_path_unavailable",
                        "sensitive directory information is invalid",
                    )
                entry_name = ctypes.wstring_at(name_start, name_bytes // wchar_bytes)
                if ntpath.normcase(entry_name) == target_key:
                    return int(entry.FileId)
                next_offset = int(entry.NextEntryOffset)
                if next_offset == 0:
                    break
                if next_offset <= 0 or next_offset % 8 != 0 or offset + next_offset >= len(buffer):
                    _fail(
                        "sensitive_path_unavailable",
                        "sensitive directory information is invalid",
                    )
                offset += next_offset
        if missing_ok:
            return None
        _fail("sensitive_input_not_file", "sensitive path component is unavailable")

    def _verify_child_binding(
        parent_handle: int,
        child_handle: int,
        child_name: str,
    ) -> None:
        file_id = _directory_child_file_id(parent_handle, child_name, missing_ok=True)
        if file_id is None:
            _fail(
                "sensitive_path_identity_mismatch",
                "sensitive path resolved outside its verified filesystem identity",
            )
        parent_identity = _identity(parent_handle)
        child_identity = _identity(child_handle)
        if (
            child_identity.volume_serial != parent_identity.volume_serial
            or child_identity.file_index != _file_id_key(file_id)
        ):
            _fail(
                "sensitive_path_identity_mismatch",
                "sensitive path resolved outside its verified filesystem identity",
            )

    def _open_file_by_id(
        volume_hint_handle: int,
        file_id: int,
        expected_path: Path,
        *,
        access: int,
        share: int,
        flags: int,
    ) -> _OwnedHandle:
        """Open the enumerated object, not a later replacement of its path name."""

        descriptor = _FileIdDescriptor()
        descriptor.dwSize = ctypes.sizeof(_FileIdDescriptor)
        descriptor.Type = _FILE_ID_TYPE
        descriptor.FileId = file_id
        handle = _OpenFileById(
            volume_hint_handle,
            ctypes.byref(descriptor),
            access,
            share,
            None,
            flags,
        )
        if handle == _INVALID_HANDLE_VALUE:
            _fail_last_error("sensitive_path_unavailable", "sensitive path is unavailable")
        owned = _OwnedHandle(int(handle))
        if owned.value is None:
            _fail("sensitive_path_unavailable", "sensitive path is unavailable")
        try:
            attributes = _attributes(owned.value)
            if not attributes.FileAttributes & _FILE_ATTRIBUTE_DIRECTORY:
                info = _file_information(owned.value)
                if info.NumberOfLinks != 1:
                    _fail(
                        "sensitive_path_hardlink",
                        "hard-linked files are not accepted for sensitive data",
                    )
            _verify_handle_path(owned.value, expected_path)
        except BaseException:
            owned.close()
            raise
        return owned

    def _open_child_directory(
        parent_handle: int,
        path: Path,
        *,
        parent: bool,
    ) -> _OwnedHandle:
        file_id = _directory_child_file_id(parent_handle, path.name, missing_ok=False)
        if file_id is None:
            _fail("sensitive_path_unavailable", "sensitive path is unavailable")
        access = _FILE_READ_ATTRIBUTES | _FILE_READ_DATA | _FILE_EXECUTE
        if parent:
            access |= _READ_CONTROL
        handle = _open_file_by_id(
            parent_handle,
            file_id,
            path,
            access=access,
            share=_FILE_SHARE_READ | _FILE_SHARE_WRITE,
            flags=_FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT,
        )
        try:
            if handle.value is None:
                _fail("sensitive_path_unavailable", "sensitive path is unavailable")
            _verify_directory(handle.value, path)
        except BaseException:
            handle.close()
            raise
        return handle

    def _close_handles(handles: list[_OwnedHandle]) -> None:
        failure: BaseException | None = None
        for handle in reversed(handles):
            try:
                handle.close()
            except BaseException as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            raise failure

    @contextlib.contextmanager
    def _locked_parent(
        path: Path,
        repository_root: Path,
        *,
        require_safe_parent_acl: bool,
        require_persistent_acls: bool,
    ) -> Iterator[_BoundParent]:
        absolute = _validate_path_form(path)
        parent_path = absolute.parent
        handles: list[_OwnedHandle] = []
        try:
            chain = (*reversed(parent_path.parents), parent_path)
            if not chain:
                _fail("sensitive_path_unavailable", "sensitive path is unavailable")
            root = chain[0]
            handles.append(
                _open_directory(
                    root,
                    parent=require_safe_parent_acl or root == parent_path,
                )
            )
            for component in chain[1:]:
                previous = handles[-1]
                if previous.value is None:
                    _fail("sensitive_path_unavailable", "sensitive path is unavailable")
                handles.append(
                    _open_child_directory(
                        previous.value,
                        component,
                        parent=require_safe_parent_acl or component == parent_path,
                    )
                )
            parent_handle = handles[-1]
            if parent_handle.value is None:
                _fail("sensitive_path_unavailable", "sensitive path is unavailable")
            bound_chain: list[_BoundDirectory] = []
            for component, handle in zip(chain, handles, strict=True):
                if handle.value is None:
                    _fail("sensitive_path_unavailable", "sensitive path is unavailable")
                bound_chain.append(
                    _BoundDirectory(
                        path=component,
                        handle=handle.value,
                        identity=_identity(handle.value),
                    )
                )
            binding = _BoundParent(
                path=parent_path,
                handle=parent_handle.value,
                identity=_identity(parent_handle.value),
                chain=tuple(bound_chain),
            )
            _verify_volume(
                parent_handle.value,
                parent_path,
                require_persistent_acls=require_persistent_acls,
            )
            _verify_repository_boundary(parent_path, repository_root)
            if require_safe_parent_acl:
                _verify_bound_parent(binding)
            yield binding
        finally:
            _close_handles(handles)

    def _current_user_sid() -> bytes:
        token = wintypes.HANDLE()
        if not _OpenProcessToken(_GetCurrentProcess(), _TOKEN_QUERY, ctypes.byref(token)):
            _fail_last_error(
                "sensitive_sid_unavailable", "current security identity is unavailable"
            )
        if token.value is None:
            _fail("sensitive_sid_unavailable", "current security identity is unavailable")
        token_handle = _OwnedHandle(int(token.value))
        with token_handle:
            size = wintypes.DWORD()
            _GetTokenInformation(token_handle.value, _TOKEN_USER_CLASS, None, 0, ctypes.byref(size))
            if size.value == 0:
                _fail_last_error(
                    "sensitive_sid_unavailable",
                    "current security identity is unavailable",
                )
            token_buffer = ctypes.create_string_buffer(size.value)
            if not _GetTokenInformation(
                token_handle.value,
                _TOKEN_USER_CLASS,
                token_buffer,
                size.value,
                ctypes.byref(size),
            ):
                _fail_last_error(
                    "sensitive_sid_unavailable",
                    "current security identity is unavailable",
                )
            sid_pointer = ctypes.cast(token_buffer, ctypes.POINTER(_TokenUser)).contents.User.Sid
            sid_length = _GetLengthSid(sid_pointer)
            if sid_length == 0:
                _fail_last_error(
                    "sensitive_sid_unavailable",
                    "current security identity is unavailable",
                )
            sid_buffer = ctypes.create_string_buffer(sid_length)
            if not _CopySid(sid_length, sid_buffer, sid_pointer):
                _fail_last_error(
                    "sensitive_sid_unavailable",
                    "current security identity is unavailable",
                )
            return bytes(sid_buffer.raw[:sid_length])

    def _sid_pointer(sid: bytes) -> tuple[ctypes.Array[ctypes.c_char], int]:
        buffer = ctypes.create_string_buffer(sid, len(sid))
        return buffer, ctypes.addressof(buffer)

    def _well_known_sid(sid_type: int) -> bytes:
        size = wintypes.DWORD(_SECURITY_MAX_SID_SIZE)
        buffer = ctypes.create_string_buffer(size.value)
        if not _CreateWellKnownSid(sid_type, None, buffer, ctypes.byref(size)):
            _fail_last_error("sensitive_acl_invalid", "sensitive access control is invalid")
        return bytes(buffer.raw[: size.value])

    def _sids_equal(left: int, right: int) -> bool:
        return bool(_EqualSid(left, right))

    def _mapped_mask(mask: int) -> int:
        value = wintypes.DWORD(mask)
        mapping = _GenericMapping(
            _FILE_GENERIC_READ,
            _FILE_GENERIC_WRITE,
            _FILE_GENERIC_EXECUTE,
            _FILE_ALL_ACCESS,
        )
        _MapGenericMask(ctypes.byref(value), ctypes.byref(mapping))
        return int(value.value)

    def _ace_mask_and_sid(ace_pointer: int, header: _AceHeader) -> tuple[int, int] | None:
        if header.AceFlags & _INHERIT_ONLY_ACE:
            return None
        if header.AceType in _ACCESS_DENIED_ACE_TYPES:
            return None
        if header.AceType not in _ACCESS_ALLOWED_ACE_TYPES:
            _fail("sensitive_acl_invalid", "sensitive access control contains an unsupported ACE")
        if header.AceSize < 12:
            _fail("sensitive_acl_invalid", "sensitive access control is malformed")
        mask = ctypes.cast(ace_pointer + 4, ctypes.POINTER(wintypes.DWORD)).contents.value
        sid_offset = 8
        if header.AceType in {5, 11}:
            object_flags = ctypes.cast(
                ace_pointer + 8,
                ctypes.POINTER(wintypes.DWORD),
            ).contents.value
            sid_offset = 12
            if object_flags & _ACE_OBJECT_TYPE_PRESENT:
                sid_offset += 16
            if object_flags & _ACE_INHERITED_OBJECT_TYPE_PRESENT:
                sid_offset += 16
        sid_pointer = ace_pointer + sid_offset
        if sid_offset >= header.AceSize or not _IsValidSid(sid_pointer):
            _fail("sensitive_acl_invalid", "sensitive access control contains an invalid SID")
        sid_length = _GetLengthSid(sid_pointer)
        if sid_length == 0 or sid_offset + sid_length > header.AceSize:
            _fail("sensitive_acl_invalid", "sensitive access control contains an invalid SID")
        return _mapped_mask(int(mask)), sid_pointer

    def _effective_rights(dacl: int, sid: bytes) -> int:
        sid_buffer, sid_pointer = _sid_pointer(sid)
        trustee = _TrusteeW()
        _BuildTrusteeWithSidW(ctypes.byref(trustee), sid_pointer)
        rights = wintypes.DWORD()
        status = _GetEffectiveRightsFromAclW(dacl, ctypes.byref(trustee), ctypes.byref(rights))
        del sid_buffer
        if status != 0:
            _fail("sensitive_acl_invalid", "sensitive access control cannot be evaluated")
        return _mapped_mask(int(rights.value))

    @contextlib.contextmanager
    def _security_info(handle: int) -> Iterator[tuple[int, int, int]]:
        owner = wintypes.LPVOID()
        dacl = wintypes.LPVOID()
        descriptor = wintypes.LPVOID()
        status = _GetSecurityInfo(
            handle,
            _SE_FILE_OBJECT,
            _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(descriptor),
        )
        if status != 0 or not descriptor.value or not owner.value or not dacl.value:
            _fail("sensitive_acl_invalid", "sensitive access control is missing or invalid")
        descriptor_value = descriptor.value
        owner_value = owner.value
        dacl_value = dacl.value
        if descriptor_value is None or owner_value is None or dacl_value is None:
            _fail("sensitive_acl_invalid", "sensitive access control is missing or invalid")
        owned = _OwnedLocal(descriptor_value)
        with owned:
            yield owner_value, dacl_value, descriptor_value

    def _verify_acl_aces(
        dacl: int,
        *,
        forbidden_mask: int,
        allowed_sids: tuple[bytes, ...],
    ) -> None:
        info = _AclSizeInformation()
        if not _GetAclInformation(
            dacl,
            ctypes.byref(info),
            ctypes.sizeof(info),
            _ACL_SIZE_INFORMATION_CLASS,
        ):
            _fail_last_error("sensitive_acl_invalid", "sensitive access control is invalid")
        allowed_buffers = tuple(_sid_pointer(sid) for sid in allowed_sids)
        for index in range(int(info.AceCount)):
            ace = wintypes.LPVOID()
            if not _GetAce(dacl, index, ctypes.byref(ace)) or not ace.value:
                _fail_last_error("sensitive_acl_invalid", "sensitive access control is invalid")
            ace_value = ace.value
            if ace_value is None:
                _fail("sensitive_acl_invalid", "sensitive access control is invalid")
            header = ctypes.cast(ace_value, ctypes.POINTER(_AceHeader)).contents
            parsed = _ace_mask_and_sid(ace_value, header)
            if parsed is None:
                continue
            mask, sid_pointer = parsed
            if mask & forbidden_mask and not any(
                _sids_equal(sid_pointer, allowed_pointer)
                for _buffer, allowed_pointer in allowed_buffers
            ):
                _fail("sensitive_acl_unsafe", "sensitive access control grants unsafe access")

    def _sid_bytes_from_pointer(sid_pointer: int) -> bytes:
        if not _IsValidSid(sid_pointer):
            _fail("sensitive_acl_invalid", "sensitive access control contains an invalid SID")
        sid_length = _GetLengthSid(sid_pointer)
        if sid_length == 0:
            _fail("sensitive_acl_invalid", "sensitive access control contains an invalid SID")
        return bytes(ctypes.string_at(sid_pointer, sid_length))

    def _is_nt_service_sid(sid: bytes) -> bool:
        return (
            len(sid) >= 12
            and sid[0] == 1
            and sid[1] >= 1
            and int.from_bytes(sid[2:8], "big") == 5
            and int.from_bytes(sid[8:12], "little") == 80
        )

    def _verify_ancestor_acl(handle: int) -> None:
        current = _current_user_sid()
        system = _well_known_sid(_WIN_LOCAL_SYSTEM_SID)
        administrators = _well_known_sid(_WIN_BUILTIN_ADMINISTRATORS_SID)
        owner_rights = _well_known_sid(_WIN_CREATOR_OWNER_RIGHTS_SID)
        trusted_owner_sids = (current, system, administrators)
        trusted_owner_buffers = tuple(_sid_pointer(sid) for sid in trusted_owner_sids)
        with _security_info(handle) as (owner, dacl, _descriptor):
            allowed_sids: tuple[bytes, ...] = (*trusted_owner_sids, owner_rights)
            if not any(
                _sids_equal(owner, allowed_pointer)
                for _buffer, allowed_pointer in trusted_owner_buffers
            ):
                owner_sid = _sid_bytes_from_pointer(owner)
                if not _is_nt_service_sid(owner_sid):
                    _fail(
                        "sensitive_ancestor_acl_owner_unsafe",
                        "sensitive ancestor owner is unsafe",
                    )
                allowed_sids = (*allowed_sids, owner_sid)
            _verify_acl_aces(
                dacl,
                forbidden_mask=_ANCESTOR_REBIND_MASK,
                allowed_sids=allowed_sids,
            )
            for broad_type in _BROAD_SID_TYPES:
                if (
                    _effective_rights(
                        dacl,
                        _well_known_sid(broad_type),
                    )
                    & _ANCESTOR_REBIND_MASK
                ):
                    _fail(
                        "sensitive_ancestor_acl_unsafe",
                        "sensitive ancestor permits unsafe path rebinding",
                    )

    def _verify_parent_acl(handle: int) -> None:
        current = _current_user_sid()
        system = _well_known_sid(_WIN_LOCAL_SYSTEM_SID)
        administrators = _well_known_sid(_WIN_BUILTIN_ADMINISTRATORS_SID)
        owner_rights = _well_known_sid(_WIN_CREATOR_OWNER_RIGHTS_SID)
        trusted_owner_sids = (current, system, administrators)
        trusted_owner_buffers = tuple(_sid_pointer(sid) for sid in trusted_owner_sids)
        allowed_sids = (*trusted_owner_sids, owner_rights)
        with _security_info(handle) as (owner, dacl, _descriptor):
            if not any(
                _sids_equal(owner, allowed_pointer)
                for _buffer, allowed_pointer in trusted_owner_buffers
            ):
                _fail(
                    "sensitive_parent_acl_owner_unsafe",
                    "sensitive output parent owner is unsafe",
                )
            _verify_acl_aces(
                dacl,
                forbidden_mask=_PARENT_MUTATION_MASK,
                allowed_sids=allowed_sids,
            )
            for broad_type in _BROAD_SID_TYPES:
                if _effective_rights(dacl, _well_known_sid(broad_type)) & _PARENT_MUTATION_MASK:
                    _fail(
                        "sensitive_parent_acl_unsafe",
                        "sensitive output parent permits unsafe mutation",
                    )

    def _verify_bound_parent(binding: _BoundParent) -> None:
        if not binding.chain or binding.chain[-1].handle != binding.handle:
            _fail(
                "sensitive_path_identity_mismatch",
                "sensitive output parent identity changed",
            )
        last_index = len(binding.chain) - 1
        for index, component in enumerate(binding.chain):
            _verify_directory(component.handle, component.path)
            if _identity(component.handle) != component.identity:
                _fail(
                    "sensitive_path_identity_mismatch",
                    "sensitive output parent identity changed",
                )
            if index < last_index:
                _verify_ancestor_acl(component.handle)
        _verify_parent_acl(binding.handle)

    def _verify_integrity_acl(
        handle: int,
        *,
        require_protected: bool,
        require_write: bool,
    ) -> None:
        current = _current_user_sid()
        current_buffer, current_pointer = _sid_pointer(current)
        system = _well_known_sid(_WIN_LOCAL_SYSTEM_SID)
        administrators = _well_known_sid(_WIN_BUILTIN_ADMINISTRATORS_SID)
        with _security_info(handle) as (owner, dacl, descriptor):
            if not _sids_equal(owner, current_pointer):
                _fail(
                    "sensitive_acl_owner_mismatch",
                    "sensitive file owner is not the current user",
                )
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not _GetSecurityDescriptorControl(
                descriptor,
                ctypes.byref(control),
                ctypes.byref(revision),
            ):
                _fail_last_error("sensitive_acl_invalid", "sensitive access control is invalid")
            if require_protected and not control.value & _SE_DACL_PROTECTED:
                _fail(
                    "sensitive_acl_not_protected",
                    "sensitive file access control must disable inheritance",
                )
            _verify_acl_aces(
                dacl,
                forbidden_mask=_INTEGRITY_UNSAFE_MASK,
                allowed_sids=(current, system, administrators),
            )
            required = _FILE_READ_DATA | (_FILE_WRITE_DATA if require_write else 0)
            if _effective_rights(dacl, current) & required != required:
                _fail(
                    "sensitive_acl_current_user_access_missing",
                    "current user lacks required sensitive file access",
                )
        del current_buffer

    def _verify_private_acl(
        handle: int,
        *,
        require_protected: bool,
        require_write: bool,
    ) -> None:
        current = _current_user_sid()
        current_buffer, current_pointer = _sid_pointer(current)
        system = _well_known_sid(_WIN_LOCAL_SYSTEM_SID)
        administrators = _well_known_sid(_WIN_BUILTIN_ADMINISTRATORS_SID)
        with _security_info(handle) as (owner, dacl, descriptor):
            if not _sids_equal(owner, current_pointer):
                _fail(
                    "sensitive_acl_owner_mismatch", "sensitive file owner is not the current user"
                )
            control = wintypes.WORD()
            revision = wintypes.DWORD()
            if not _GetSecurityDescriptorControl(
                descriptor,
                ctypes.byref(control),
                ctypes.byref(revision),
            ):
                _fail_last_error("sensitive_acl_invalid", "sensitive access control is invalid")
            if require_protected and not control.value & _SE_DACL_PROTECTED:
                _fail(
                    "sensitive_acl_not_protected",
                    "sensitive file access control must disable inheritance",
                )
            _verify_acl_aces(
                dacl,
                forbidden_mask=_PRIVATE_UNSAFE_MASK,
                allowed_sids=(current, system, administrators),
            )
            for broad_type in _BROAD_SID_TYPES:
                if _effective_rights(dacl, _well_known_sid(broad_type)) & _PRIVATE_READ_MASK:
                    _fail(
                        "sensitive_acl_unsafe",
                        "sensitive access control grants unsafe read access",
                    )
            required = _FILE_READ_DATA | (_FILE_WRITE_DATA if require_write else 0)
            if _effective_rights(dacl, current) & required != required:
                _fail(
                    "sensitive_acl_current_user_access_missing",
                    "current user lacks required sensitive file access",
                )
        del current_buffer

    def _sid_string(sid: bytes) -> str:
        sid_buffer, sid_pointer = _sid_pointer(sid)
        sid_text = wintypes.LPWSTR()
        if not _ConvertSidToStringSidW(sid_pointer, ctypes.byref(sid_text)) or not sid_text.value:
            _fail_last_error(
                "sensitive_sid_unavailable", "current security identity is unavailable"
            )
        sid_text_pointer = ctypes.cast(sid_text, ctypes.c_void_p).value
        if sid_text_pointer is None:
            _fail("sensitive_sid_unavailable", "current security identity is unavailable")
        sid_text_owner = _OwnedLocal(sid_text_pointer)
        with sid_text_owner:
            value = sid_text.value
        del sid_buffer
        return value

    @contextlib.contextmanager
    def _security_attributes_from_sddl(sddl: str) -> Iterator[_SecurityAttributes]:
        descriptor = wintypes.LPVOID()
        if (
            not _ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl,
                _SECURITY_DESCRIPTOR_REVISION,
                ctypes.byref(descriptor),
                None,
            )
            or not descriptor.value
        ):
            _fail_last_error(
                "sensitive_acl_invalid",
                "sensitive access control could not be created",
            )
        descriptor_value = descriptor.value
        if descriptor_value is None:
            _fail(
                "sensitive_acl_invalid",
                "sensitive access control could not be created",
            )
        descriptor_owner = _OwnedLocal(descriptor_value)
        with descriptor_owner:
            yield _SecurityAttributes(
                ctypes.sizeof(_SecurityAttributes),
                descriptor,
                False,
            )

    @contextlib.contextmanager
    def _private_security_attributes() -> Iterator[_SecurityAttributes]:
        current_text = _sid_string(_current_user_sid())
        sddl = f"O:{current_text}D:P(A;;FA;;;{current_text})(A;;FA;;;SY)(A;;FA;;;BA)"
        with _security_attributes_from_sddl(sddl) as attributes:
            yield attributes

    @contextlib.contextmanager
    def _integrity_security_attributes(parent_handle: int) -> Iterator[_SecurityAttributes]:
        current_text = _sid_string(_current_user_sid())
        broad_read_aces: list[str] = []
        with _security_info(parent_handle) as (_owner, dacl, _descriptor):
            for broad_type in _BROAD_SID_TYPES:
                broad_sid = _well_known_sid(broad_type)
                if _effective_rights(dacl, broad_sid) & _FILE_READ_DATA:
                    broad_read_aces.append(f"(A;;GR;;;{_sid_string(broad_sid)})")
        sddl = f"O:{current_text}D:P(A;;FA;;;{current_text})(A;;FA;;;SY)(A;;FA;;;BA)" + "".join(
            broad_read_aces
        )
        with _security_attributes_from_sddl(sddl) as attributes:
            yield attributes

    def _open_regular_file(
        path: Path,
        *,
        write: bool,
        missing_ok: bool,
        sharing_is_collision: bool = False,
    ) -> _OwnedHandle | None:
        access = _FILE_READ_ATTRIBUTES | _READ_CONTROL | _GENERIC_READ
        if write:
            access |= _GENERIC_WRITE | _DELETE
        handle = _create_file(
            path,
            access=access,
            share=_FILE_SHARE_READ if not write else 0,
            disposition=_OPEN_EXISTING,
            flags=_FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS,
            missing_ok=missing_ok,
            sharing_is_collision=sharing_is_collision,
        )
        if handle is not None:
            if handle.value is None:
                _fail("sensitive_path_unavailable", "sensitive path is unavailable")
            try:
                _verify_regular_file(handle.value, path)
            except BaseException:
                handle.close()
                raise
        return handle

    def _open_bound_regular_file(
        parent_handle: int,
        path: Path,
        *,
        write: bool,
        missing_ok: bool,
        sharing_is_collision: bool = False,
    ) -> _OwnedHandle | None:
        """Open a leaf by the file ID enumerated through its verified parent."""

        file_id = _directory_child_file_id(parent_handle, path.name, missing_ok=missing_ok)
        if file_id is None:
            return None
        access = _FILE_READ_ATTRIBUTES | _READ_CONTROL | _GENERIC_READ
        if write:
            access |= _GENERIC_WRITE | _DELETE
        try:
            handle = _open_file_by_id(
                parent_handle,
                file_id,
                path,
                access=access,
                share=_FILE_SHARE_READ if not write else 0,
                flags=_FILE_FLAG_OPEN_REPARSE_POINT | _FILE_FLAG_BACKUP_SEMANTICS,
            )
        except WindowsSensitiveFileError as exc:
            if sharing_is_collision and exc.code == "sensitive_path_unavailable":
                _fail("sensitive_output_exists", "sensitive output already exists")
            raise
        try:
            if handle.value is None:
                _fail("sensitive_path_unavailable", "sensitive path is unavailable")
            _verify_regular_file(handle.value, path)
        except BaseException:
            handle.close()
            raise
        return handle

    def _inspect_destination(
        parent_handle: int,
        path: Path,
        *,
        overwrite: bool,
        private_acl: bool,
        require_protected_acl: bool,
    ) -> _DestinationState:
        try:
            handle = _open_bound_regular_file(
                parent_handle,
                path,
                write=False,
                missing_ok=True,
                sharing_is_collision=not overwrite,
            )
        except WindowsSensitiveFileError as exc:
            if exc.code == "sensitive_input_not_file":
                _fail("sensitive_output_not_file", "sensitive output is not a regular file")
            raise
        if handle is None:
            return _DestinationState(False, None)
        with handle:
            if handle.value is None:
                _fail("sensitive_path_unavailable", "sensitive path is unavailable")
            identity = _identity(handle.value)
            if not overwrite:
                _fail(
                    "sensitive_output_exists",
                    "sensitive output already exists and overwrite is disabled",
                )
            if private_acl:
                _verify_private_acl(
                    handle.value,
                    require_protected=require_protected_acl,
                    require_write=False,
                )
            else:
                _verify_integrity_acl(
                    handle.value,
                    require_protected=require_protected_acl,
                    require_write=False,
                )
            return _DestinationState(True, identity)

    def _read_all(handle: int, max_size: int) -> bytes:
        size = ctypes.c_longlong()
        if not _GetFileSizeEx(handle, ctypes.byref(size)):
            _fail_last_error("sensitive_input_unavailable", "sensitive input is unavailable")
        if size.value < 0 or size.value > max_size:
            _fail("sensitive_input_too_large", "sensitive input exceeds the size limit")
        result = bytearray()
        while len(result) <= max_size:
            requested = min(_MAX_IO_CHUNK, max_size + 1 - len(result))
            if requested <= 0:
                break
            buffer = ctypes.create_string_buffer(requested)
            read = wintypes.DWORD()
            if not _ReadFile(handle, buffer, requested, ctypes.byref(read), None):
                _fail_last_error("sensitive_input_unavailable", "sensitive input is unavailable")
            if read.value == 0:
                break
            result.extend(buffer.raw[: read.value])
        if len(result) > max_size:
            _fail("sensitive_input_too_large", "sensitive input exceeds the size limit")
        return bytes(result)

    def _write_all(handle: int, content: bytes) -> None:
        view = memoryview(content)
        offset = 0
        while offset < len(view):
            chunk = bytes(view[offset : offset + _MAX_IO_CHUNK])
            buffer = ctypes.create_string_buffer(chunk, len(chunk))
            written = wintypes.DWORD()
            if not _WriteFile(handle, buffer, len(chunk), ctypes.byref(written), None):
                _fail_last_error("sensitive_write_failed", "sensitive output could not be written")
            if written.value == 0:
                _fail("sensitive_write_failed", "sensitive output could not be written")
            offset += int(written.value)
        if not _FlushFileBuffers(handle):
            _fail_last_error("sensitive_write_failed", "sensitive output could not be flushed")

    def _rename_handle(
        handle: int,
        destination_path: Path,
        *,
        overwrite: bool,
    ) -> None:
        destination = _validate_path_form(destination_path)
        encoded_name = str(destination).encode("utf-16-le")
        file_name_offset = _FileRenameInfo.FileName.offset
        buffer_size = max(
            ctypes.sizeof(_FileRenameInfo),
            file_name_offset + len(encoded_name) + ctypes.sizeof(wintypes.WCHAR),
        )
        buffer = ctypes.create_string_buffer(buffer_size)
        info = ctypes.cast(buffer, ctypes.POINTER(_FileRenameInfo)).contents
        info.FlagsOrReplaceIfExists = int(overwrite)
        # User-mode FileRenameInfo uses a full absolute target with a null
        # RootDirectory here.  The caller rechecks the bound ancestor chain
        # before publication and re-binds the final file ID afterward.
        info.RootDirectory = None
        info.FileNameLength = len(encoded_name)
        ctypes.memmove(ctypes.addressof(buffer) + file_name_offset, encoded_name, len(encoded_name))
        if not _SetFileInformationByHandle(
            handle,
            _FILE_RENAME_INFO_CLASS,
            buffer,
            buffer_size,
        ):
            error = ctypes.get_last_error()
            if error in _COLLISION_ERRORS:
                _fail(
                    "sensitive_output_exists",
                    "sensitive output already exists and overwrite is disabled",
                )
            _fail_last_error("sensitive_write_failed", "sensitive output could not be published")

    def _mark_for_deletion(handle: int) -> None:
        info = _FileDispositionInfo(True)
        if not _SetFileInformationByHandle(
            handle,
            _FILE_DISPOSITION_INFO_CLASS,
            ctypes.byref(info),
            ctypes.sizeof(info),
        ):
            _fail_last_error("sensitive_cleanup_failed", "sensitive temporary cleanup failed")

    def _same_destination_state(
        expected: _DestinationState,
        actual: _DestinationState,
    ) -> bool:
        return expected == actual

    def validate_windows_sensitive_input(
        path: Path,
        repository_root: Path,
        *,
        max_size: int,
        private_acl: bool,
        integrity_acl: bool,
        require_protected_acl: bool,
    ) -> None:
        with _locked_parent(
            path,
            repository_root,
            require_safe_parent_acl=private_acl or integrity_acl,
            require_persistent_acls=private_acl or integrity_acl,
        ) as parent:
            handle = _open_bound_regular_file(
                parent.handle,
                path,
                write=False,
                missing_ok=True,
            )
            if handle is None:
                _fail("sensitive_input_not_file", "sensitive input is not a regular local file")
            with handle:
                if handle.value is None:
                    _fail("sensitive_input_unavailable", "sensitive input is unavailable")
                if private_acl:
                    _verify_private_acl(
                        handle.value,
                        require_protected=require_protected_acl,
                        require_write=False,
                    )
                elif integrity_acl:
                    _verify_integrity_acl(
                        handle.value,
                        require_protected=require_protected_acl,
                        require_write=False,
                    )
                size = ctypes.c_longlong()
                if not _GetFileSizeEx(handle.value, ctypes.byref(size)):
                    _fail_last_error(
                        "sensitive_input_unavailable",
                        "sensitive input is unavailable",
                    )
                if size.value < 0 or size.value > max_size:
                    _fail("sensitive_input_too_large", "sensitive input exceeds the size limit")

    def validate_windows_sensitive_output(
        path: Path,
        repository_root: Path,
        *,
        overwrite: bool,
        private_acl: bool,
        require_existing_protected_acl: bool,
    ) -> None:
        with _locked_parent(
            path,
            repository_root,
            require_safe_parent_acl=True,
            require_persistent_acls=True,
        ) as parent:
            _inspect_destination(
                parent.handle,
                path,
                overwrite=overwrite,
                private_acl=private_acl,
                require_protected_acl=require_existing_protected_acl,
            )

    def read_windows_sensitive_bytes(
        path: Path,
        repository_root: Path,
        *,
        max_size: int,
        private_acl: bool,
        integrity_acl: bool,
        require_protected_acl: bool,
    ) -> bytes:
        with _locked_parent(
            path,
            repository_root,
            require_safe_parent_acl=private_acl or integrity_acl,
            require_persistent_acls=private_acl or integrity_acl,
        ) as parent:
            handle = _open_bound_regular_file(
                parent.handle,
                path,
                write=False,
                missing_ok=True,
            )
            if handle is None:
                _fail("sensitive_input_not_file", "sensitive input is not a regular local file")
            with handle:
                if handle.value is None:
                    _fail("sensitive_input_unavailable", "sensitive input is unavailable")
                if private_acl:
                    _verify_private_acl(
                        handle.value,
                        require_protected=require_protected_acl,
                        require_write=False,
                    )
                elif integrity_acl:
                    _verify_integrity_acl(
                        handle.value,
                        require_protected=require_protected_acl,
                        require_write=False,
                    )
                return _read_all(handle.value, max_size)

    def atomic_write_windows_sensitive_bytes(
        path: Path,
        repository_root: Path,
        content: bytes,
        *,
        overwrite: bool,
        private_acl: bool,
        require_existing_protected_acl: bool,
    ) -> None:
        with _locked_parent(
            path,
            repository_root,
            require_safe_parent_acl=True,
            require_persistent_acls=True,
        ) as parent:
            initial = _inspect_destination(
                parent.handle,
                path,
                overwrite=overwrite,
                private_acl=private_acl,
                require_protected_acl=require_existing_protected_acl,
            )
            temp_handle: _OwnedHandle | None = None
            temp_path: Path | None = None
            for _attempt in range(16):
                temp_path = parent.path / f".private-write-{secrets.token_hex(16)}.tmp"
                try:
                    if private_acl:
                        with _private_security_attributes() as security_attributes:
                            temp_handle = _create_file(
                                temp_path,
                                access=(
                                    _GENERIC_READ
                                    | _GENERIC_WRITE
                                    | _DELETE
                                    | _READ_CONTROL
                                    | _FILE_READ_ATTRIBUTES
                                ),
                                share=0,
                                disposition=_CREATE_NEW,
                                flags=_FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT,
                                security_attributes=security_attributes,
                            )
                    else:
                        with _integrity_security_attributes(parent.handle) as security_attributes:
                            temp_handle = _create_file(
                                temp_path,
                                access=(
                                    _GENERIC_READ
                                    | _GENERIC_WRITE
                                    | _DELETE
                                    | _READ_CONTROL
                                    | _FILE_READ_ATTRIBUTES
                                ),
                                share=0,
                                disposition=_CREATE_NEW,
                                flags=(_FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_OPEN_REPARSE_POINT),
                                security_attributes=security_attributes,
                            )
                except WindowsSensitiveFileError as exc:
                    if exc.code == "sensitive_output_exists":
                        continue
                    raise
                break
            if temp_handle is None or temp_handle.value is None or temp_path is None:
                _fail("sensitive_temp_unavailable", "sensitive temporary file is unavailable")
            with temp_handle:
                published = False
                try:
                    _verify_regular_file(temp_handle.value, temp_path)
                    _verify_child_binding(
                        parent.handle,
                        temp_handle.value,
                        temp_path.name,
                    )
                    if private_acl:
                        _verify_private_acl(
                            temp_handle.value,
                            require_protected=True,
                            require_write=True,
                        )
                    else:
                        _verify_integrity_acl(
                            temp_handle.value,
                            require_protected=True,
                            require_write=True,
                        )
                    # No content reaches the filesystem until the exact temp
                    # handle, parent binding, and effective ACL have passed.
                    _write_all(temp_handle.value, content)
                    current = _inspect_destination(
                        parent.handle,
                        path,
                        overwrite=overwrite,
                        private_acl=private_acl,
                        require_protected_acl=require_existing_protected_acl,
                    )
                    if not _same_destination_state(initial, current):
                        _fail(
                            "sensitive_destination_changed",
                            "sensitive output destination changed during publication",
                        )
                    _verify_bound_parent(parent)
                    _rename_handle(
                        temp_handle.value,
                        path,
                        overwrite=overwrite,
                    )
                    published = True
                    _verify_bound_parent(parent)
                    _verify_child_binding(
                        parent.handle,
                        temp_handle.value,
                        path.name,
                    )
                    _verify_regular_file(temp_handle.value, path)
                    if private_acl:
                        _verify_private_acl(
                            temp_handle.value,
                            require_protected=True,
                            require_write=True,
                        )
                    else:
                        _verify_integrity_acl(
                            temp_handle.value,
                            require_protected=True,
                            require_write=True,
                        )
                    if _identity(temp_handle.value) == parent.identity:
                        _fail(
                            "sensitive_path_identity_mismatch",
                            "sensitive output identity is invalid",
                        )
                except BaseException:
                    try:
                        _mark_for_deletion(temp_handle.value)
                    except WindowsSensitiveFileError:
                        if not published:
                            raise
                    raise

    def windows_sensitive_path_identity(
        path: Path,
        repository_root: Path,
        *,
        private_acl: bool,
        integrity_acl: bool,
        require_protected_acl: bool,
    ) -> WindowsSensitivePathIdentity:
        with _locked_parent(
            path,
            repository_root,
            require_safe_parent_acl=private_acl or integrity_acl,
            require_persistent_acls=private_acl or integrity_acl,
        ) as parent:
            handle = _open_bound_regular_file(
                parent.handle,
                path,
                write=False,
                missing_ok=True,
            )
            if handle is None:
                return WindowsSensitivePathIdentity(
                    exists=False,
                    volume_serial=0,
                    file_index=0,
                    parent_volume_serial=parent.identity.volume_serial,
                    parent_file_index=parent.identity.file_index,
                    leaf_key=ntpath.normcase(path.name),
                )
            with handle:
                if handle.value is None:
                    _fail("sensitive_path_unavailable", "sensitive path is unavailable")
                if private_acl:
                    _verify_private_acl(
                        handle.value,
                        require_protected=require_protected_acl,
                        require_write=False,
                    )
                elif integrity_acl:
                    _verify_integrity_acl(
                        handle.value,
                        require_protected=require_protected_acl,
                        require_write=False,
                    )
                identity = _identity(handle.value)
                return WindowsSensitivePathIdentity(
                    exists=True,
                    volume_serial=identity.volume_serial,
                    file_index=identity.file_index,
                    parent_volume_serial=parent.identity.volume_serial,
                    parent_file_index=parent.identity.file_index,
                    leaf_key="",
                )

    def remove_windows_sensitive_file_if_matches(
        path: Path,
        repository_root: Path,
        expected: bytes,
        *,
        max_size: int,
        private_acl: bool,
        integrity_acl: bool,
        require_protected_acl: bool,
    ) -> bool:
        """Delete only the exact verified file whose bytes match ``expected``."""

        with _locked_parent(
            path,
            repository_root,
            require_safe_parent_acl=True,
            require_persistent_acls=private_acl or integrity_acl,
        ) as parent:
            # First bind the candidate through the verified parent and read
            # the exact file-ID handle.  OpenFileById handles are retained
            # for identity/read validation, not for final deletion.
            handle = _open_bound_regular_file(
                parent.handle,
                path,
                write=False,
                missing_ok=True,
            )
            if handle is None:
                return True
            with handle:
                if handle.value is None:
                    _fail("sensitive_path_unavailable", "sensitive path is unavailable")
                if private_acl:
                    _verify_private_acl(
                        handle.value,
                        require_protected=require_protected_acl,
                        require_write=False,
                    )
                elif integrity_acl:
                    _verify_integrity_acl(
                        handle.value,
                        require_protected=require_protected_acl,
                        require_write=False,
                    )
                actual = _read_all(handle.value, max_size)
                if not hmac.compare_digest(actual, expected):
                    return False
                expected_identity = _identity(handle.value)

            # FileDispositionInfo returns ERROR_INVALID_PARAMETER for the
            # OpenFileById handle on supported real-Windows validation.
            # Reopen only after the full ancestor chain is still verified,
            # then bind the path-open handle back to the same parent/file ID.
            _verify_bound_parent(parent)
            delete_handle = _open_regular_file(
                path,
                write=True,
                missing_ok=True,
            )
            if delete_handle is None:
                return True
            with delete_handle:
                if delete_handle.value is None:
                    _fail("sensitive_path_unavailable", "sensitive path is unavailable")
                _verify_bound_parent(parent)
                _verify_child_binding(parent.handle, delete_handle.value, path.name)
                if _identity(delete_handle.value) != expected_identity:
                    _fail(
                        "sensitive_path_identity_mismatch",
                        "sensitive cleanup target identity changed",
                    )
                if private_acl:
                    _verify_private_acl(
                        delete_handle.value,
                        require_protected=require_protected_acl,
                        require_write=True,
                    )
                elif integrity_acl:
                    _verify_integrity_acl(
                        delete_handle.value,
                        require_protected=require_protected_acl,
                        require_write=True,
                    )
                actual = _read_all(delete_handle.value, max_size)
                if not hmac.compare_digest(actual, expected):
                    return False
                _verify_bound_parent(parent)
                _verify_child_binding(parent.handle, delete_handle.value, path.name)
                _mark_for_deletion(delete_handle.value)

            remaining = _open_bound_regular_file(
                parent.handle,
                path,
                write=False,
                missing_ok=True,
            )
            if remaining is None:
                return True
            remaining.close()
            return False

else:

    def _windows_unavailable() -> NoReturn:
        raise WindowsSensitiveFileError(
            "windows_sensitive_io_unavailable",
            "secure Windows sensitive-file operations require Windows",
        )

    def validate_windows_sensitive_input(
        path: Path,
        repository_root: Path,
        *,
        max_size: int,
        private_acl: bool,
        integrity_acl: bool,
        require_protected_acl: bool,
    ) -> None:
        del (
            path,
            repository_root,
            max_size,
            private_acl,
            integrity_acl,
            require_protected_acl,
        )
        _windows_unavailable()

    def validate_windows_sensitive_output(
        path: Path,
        repository_root: Path,
        *,
        overwrite: bool,
        private_acl: bool,
        require_existing_protected_acl: bool,
    ) -> None:
        del path, repository_root, overwrite, private_acl, require_existing_protected_acl
        _windows_unavailable()

    def read_windows_sensitive_bytes(
        path: Path,
        repository_root: Path,
        *,
        max_size: int,
        private_acl: bool,
        integrity_acl: bool,
        require_protected_acl: bool,
    ) -> bytes:
        del (
            path,
            repository_root,
            max_size,
            private_acl,
            integrity_acl,
            require_protected_acl,
        )
        _windows_unavailable()

    def atomic_write_windows_sensitive_bytes(
        path: Path,
        repository_root: Path,
        content: bytes,
        *,
        overwrite: bool,
        private_acl: bool,
        require_existing_protected_acl: bool,
    ) -> None:
        del (
            path,
            repository_root,
            content,
            overwrite,
            private_acl,
            require_existing_protected_acl,
        )
        _windows_unavailable()

    def windows_sensitive_path_identity(
        path: Path,
        repository_root: Path,
        *,
        private_acl: bool,
        integrity_acl: bool,
        require_protected_acl: bool,
    ) -> WindowsSensitivePathIdentity:
        del path, repository_root, private_acl, integrity_acl, require_protected_acl
        _windows_unavailable()

    def remove_windows_sensitive_file_if_matches(
        path: Path,
        repository_root: Path,
        expected: bytes,
        *,
        max_size: int,
        private_acl: bool,
        integrity_acl: bool,
        require_protected_acl: bool,
    ) -> bool:
        del (
            path,
            repository_root,
            expected,
            max_size,
            private_acl,
            integrity_acl,
            require_protected_acl,
        )
        _windows_unavailable()


__all__ = [
    "WindowsSensitiveFileError",
    "WindowsSensitivePathIdentity",
    "atomic_write_windows_sensitive_bytes",
    "read_windows_sensitive_bytes",
    "remove_windows_sensitive_file_if_matches",
    "validate_windows_sensitive_input",
    "validate_windows_sensitive_output",
    "windows_sensitive_path_identity",
]
