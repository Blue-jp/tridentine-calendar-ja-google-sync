# Windows sensitive filesystem security

## Phase 6D.1F boundary

Phase 6D.1F closes the confirmed Windows junction/reparse/TOCTOU and sensitive-file
ACL findings. It changes local filesystem safety only. Production OAuth remains
live-disabled, no Production write token is created, and no Google Calendar client or
API operation is added.

The protected boundary covers operator mistakes, pre-existing reparse points,
same-machine path substitution while an operation is running, unsafe inherited ACLs,
and non-administrator local users. Local Administrators, SYSTEM, kernel compromise,
code injection into the process, and replacement of the application itself remain
outside this boundary.

## Handle-bound path policy

Windows sensitive operations use documented Win32 APIs through the Python standard
library `ctypes`; no runtime dependency is added. The volume root is opened as the
trust anchor. Each later path component is enumerated through its already verified
parent handle and then opened by file ID with `OpenFileById`. The opened handle's final
path and attributes are checked before traversal continues. This prevents an ordinary
unopened child from being replaced between two unrelated absolute opens.

Every opened component uses `FILE_FLAG_OPEN_REPARSE_POINT`, and
`GetFileInformationByHandleEx` rejects every `FILE_ATTRIBUTE_REPARSE_POINT`, including
symbolic links, junctions, mount points, and other reparse tags. Directory handles stay
open without `FILE_SHARE_DELETE` until the read or write completes. Windows can still
permit some directory renames through parent `DELETE_CHILD` authority, so safety does
not rely on rename being impossible. For write-capable operations, every traversed
ancestor rejects non-administrator delete-child, delete, DACL-write, and owner-write
authority; the immediate operational parent keeps the stricter create/write/delete
policy. The full opened directory chain is rechecked before publication.
Filesystems that cannot support the required handle/file-ID or ACL operations fail closed.

The opened object is checked with `GetFinalPathNameByHandleW` and stable volume/file
identity. Repository containment uses the canonical opened location, not only the
caller-supplied spelling. Sensitive file hard links, remote/mapped filesystems, unsafe
Windows aliases, and filesystems without persistent ACL support for secret artifacts
fail closed.

Reads enumerate and open the leaf file by ID through the verified parent and consume
bytes from that exact handle. Writes create an unpredictable same-directory temporary
file with `CREATE_NEW`, then require that the new handle's file ID is enumerated through
the already verified parent before any content is written. After the exact handle and
ACL pass, content is flushed, the destination and complete bound ancestor chain are
rechecked, and `SetFileInformationByHandle(FileRenameInfo)` publishes to the validated
full absolute destination with `RootDirectory` set to null. Because this user-mode
rename form resolves a path, non-administrator rebinding authority is rejected on every
ancestor first; after publication, the final file ID is enumerated through the original
verified parent and must match the published handle. Initial publication never
overwrites; token refresh replaces only when explicitly requested.
There is no warning-only or unchecked publication fallback.

A path-returning preflight validator is not an authorization capability. Every content
reader, writer, refresh replacement, and exact-artifact cleanup repeats policy checks
while holding the handles used for the security-critical operation. Exact-artifact
cleanup first verifies identity, ACL, and content through the parent-bound file-ID
handle. Because real Windows rejects FileDispositionInfo on that OpenFileById handle
with ERROR_INVALID_PARAMETER, cleanup then rechecks the complete bound ancestor chain,
reopens the canonical path with CreateFile for delete access, binds that handle back
to the same verified parent/file ID, rechecks ACL and content, and only then marks the
CreateFile handle for deletion. There is no unchecked path-based delete fallback.

## Windows DACL policy

Secret token output is created with a protected DACL from the first empty-file state.
The current user SID comes from `OpenProcessToken` and `GetTokenInformation(TokenUser)`;
account names are not trusted. The DACL grants required access only to the current user,
SYSTEM, and Builtin Administrators. It disables inheritance and is verified both before
the first content byte and after final publication.

Secret input checks are handle-based. Production token files require a current-user
owner, a protected DACL, current-user read access, and no content-read or security-control
grant to another non-administrator SID. OAuth client credentials require the same
effective confidentiality, while an inherited DACL may be accepted only when it is
actually private. Everyone, Authenticated Users, and Builtin Users read access is
rejected. Legacy Production write-token files without the protected policy are not
silently repaired; explicit recreation or re-authorization is required.

The immediate operational parent may grant broad read/list/traverse access, but it must
not grant another non-administrator SID create, write, delete-child, delete, DACL-write,
or owner-write authority. Intermediate ancestors use a narrower anti-rebinding policy:
non-administrators may not hold delete-child, delete, DACL-write, or owner-write
authority. Current-user, SYSTEM, Builtin Administrators, and Windows service-owned system
anchors are accepted as trusted owners; other ancestor owners fail closed. The Windows
OWNER RIGHTS SID is accepted for directory mutation ACEs only after the directory owner
itself has passed that trusted-owner check, because that SID represents the rights of
the already verified owner rather than a separate account. A private token created
under a broad-read-only parent does not inherit that broad read grant.
The immediate parent ACL and the complete bound directory identity chain are rechecked
immediately before publication.

The integrity writer also creates a protected DACL rather than inheriting child-only
write grants. It preserves only verified broad read grants from the parent and strips
non-administrator write, delete, DACL-control, and owner-control rights. Sanitized reports
can therefore remain broadly readable without becoming broadly mutable.

## Artifact classification

- Production write token and OAuth client credentials are secrets and require private
  file ACL validation.
- `ProductionWriteTokenGenerationState` is non-secret operational metadata. It retains
  handle-based integrity ACL, safe-parent, path-identity, reparse, and
  repository-exclusion controls. Broad read is permitted, but non-administrator write or
  security-control rights are rejected; token secrecy is not inferred from its fields.
- The rehearsal snapshot is redacted operational-private evidence. It is still written
  with the private writer.
- Rehearsal text and JSON reports are sanitized public-safe aggregates. They use the
  handle-bound integrity writer and safe-parent policy without unnecessarily requiring
  token-confidential leaf ACLs.

No Calendar ID, raw UID, Event ID, ETag, SID, user name, credential, token, or absolute
private path is included in public error text.

## Cross-platform behavior

The Win32 implementation is isolated behind a platform-neutral sensitive-path API.
POSIX retains its existing symlink rejection, bounded reads, same-directory atomic
publication, explicit overwrite policy, `0600` private mode, and parent fsync behavior.
Strict Linux and Win32 type checking cover both branches.

The Windows policy deliberately rejects junction-mounted operational directories,
reparse-backed cloud placeholders, mount-point paths, and unsafe writable parents. There
is no `allow-unsafe-path`, ACL warning-only mode, `chmod` fallback, or live OAuth bypass.
