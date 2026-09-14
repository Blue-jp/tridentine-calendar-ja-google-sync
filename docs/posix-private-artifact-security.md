# POSIX private-artifact security remediation

## DS-04 / Unit 4A: secret content reads only

This increment routes desktop OAuth client, Production read-token, Test write-token,
and Production write-token content loads through `read_private_sensitive_bytes`.
On POSIX that reader validates the opened regular file's effective owner, private
mode, single-link count, bounded size, and before/after content metadata. It traverses
components with no-follow directory descriptors. The leaf open is nonblocking so a
FIFO is rejected as a non-regular file rather than waiting for a writer.

The old path-based mode check is no longer the Production token content-read boundary.
Remaining path-set preflight checks are advisory to subsequent content loaders, not
new guarantees about file identity over multiple operations.

## Windows compatibility

Windows still uses the existing handle-bound private ACL checks. Baseline, Production
target, and Production write-token readers retain the protected-DACL default. Desktop
client, Production read-token, and Test write-token readers retain their existing
acceptance of inherited DACLs only when the ACL is actually private. The Windows-only
option does not relax owner/mode checks on POSIX. No automatic permission repair is
performed.

## DS-04 / Unit 4B: descriptor-bound temporary-output permissions only

The POSIX private/integrity writer now sets permissions with `os.fchmod` on the
fresh `mkstemp` descriptor before any content is written. It verifies an empty,
regular, single-link file owned by the effective user, with no permissions other
than owner read/write, before the change. After the change it verifies the same
file identity, owner, empty size, single link, regular-file type, and exact `0600`
mode. A restrictive initial umask may remove owner permissions; only this newly
created temporary file can be set to `0600`. Unsupported or failed descriptor
permission operations stop without a path-based chmod fallback.

Neither the temporary pathname nor the published destination is passed to
`os.chmod`. This avoids applying a permission change to an object selected by a
name that may have been replaced. Windows keeps its existing handle-bound writer
and ACL policy unchanged. Text, JSON, and integrity outputs retain their previous
public interfaces, overwrite policy, and serialization.

This is NOT a complete POSIX atomic-write security redesign. The temporary name,
publication via link/replace, parent-directory fsync, and cleanup still use the
existing path-based implementation. In particular, this increment does not prove
that a name still refers to the descriptor-verified object at publication time.
Parent/ancestor substitution, concurrent destination changes, crash durability,
filesystem ACL/mount policy, and multi-artifact rollback remain unclosed work.
No existing operational file or directory is repaired or re-permissioned here.

## DS-04 / Unit 4C: retained-directory binding foundation

`_posix_sensitive_directory.open_posix_private_directory` opens one existing
private directory from `/` using no-follow directory descriptors. All ancestor
descriptors remain open for the context lifetime. Directory identities are
checked before/after open and each child's name is compared with its retained
parent descriptor. `revalidate()` repeats the identity, owner, mode, effective-UID,
and `.git` marker checks and closes the binding on failure.

The final parent must be owned by the effective user with mode exactly `0700`.
Root and intermediate directories must be owned by root or the effective user
and must not be group/other writable. A root-owned sticky directory is allowed
only as an intermediate ancestor, never as the final private parent; its next
child must also have a trusted owner. Symbolic links, untrusted owners, detected
name substitution, present `.git` markers, unsupported primitives, and inspection
errors stop without a generic-path fallback. No existing permission is repaired.
A maximum of 128 path components bounds descriptor use.

Unit 4D uses this foundation in the separately tested create-only backend.
Existing public readers, writers, and cleanup functions still do not use it. It performs only metadata inspection and directory opens/closes, and does
not create, publish, replace, delete, or change the permissions of an artifact.
Windows receives an unavailable result from this POSIX-only component; existing
Windows I/O and ACL policy are unchanged. The tests exercise the component
independently. Passing them is not approval for the current POSIX writer.

A retained descriptor prevents later relative operations from being redirected
by reparsing an absolute pathname, but revalidation is not a filesystem lock.
It does not make future link/replace/unlink calls conditional on a leaf inode,
and does not eliminate changes after a check by the same user or a privileged
actor. Integration, leaf identity/content checks, exact cleanup, concurrent
replacement semantics, mount/filesystem ACL policy, and durability still require
separate review. Inputs with `/` as their final parent, `..`, `//` anchors, or
nonabsolute paths are unsupported rather than normalized through symlinks.

## DS-04 / Unit 4D: independent create-only publication backend

`_posix_private_create.create_posix_private_bytes` uses the retained private
parent from Unit 4C and the descriptor permission preparation from Unit 4B.
It creates an unpredictable temporary relative to the held parent with
`O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, prepares/verifies `0600` before writing,
handles short writes, fsyncs the file, and reads back the expected bytes through
the same descriptor. Name-to-inode, ownership, permissions, content and parent
checks are repeated before and after publication. Content is bounded by the
existing sensitive-file size limit.

Publication uses `link` with both names relative to the retained parent and
`follow_symlinks=False`. There is no overwrite parameter, rename fallback or
pre-existing destination deletion. An existing file, directory or dangling link
blocks creation. On success the final name is bound to the verified file and
has one link, exact `0600`, and expected content; directory fsync is required.
The temporary is removed only after checking its name against the still-open
original descriptor and revalidating the parent. Cleanup never targets the
final output. No existing permissions are repaired.

Failures are NOT promised to be side-effect-free. `PosixPrivateCreateError` has
`publication_possible=True` from the first link attempt, including a reported
`FileExistsError`; an error can leave a published artifact and/or private temp.
The boolean is conservative evidence, not retry authorization. If the parent
or temporary identity cannot be verified, cleanup leaves the object alone.
Raw paths, file content and OS exception text are suppressed from public errors.

Unit 4D introduced this backend independently. Unit 4E now connects only the
Production Plan and Run Spec file writers through a dedicated adapter. Common
`atomic_write_private_text/json`, integrity writers, token refresh/rollback and
all other operational callers are NOT switched to it. Windows retains its existing
private writer. Integrating further callers requires a separate compatibility,
concurrency and failure-semantics review.

The private parent prevents other users from normal namespace mutation under the
stated owner/mode policy. It does not defend against hostile same-UID or privileged
actors, and name checks are not inode-conditional link/unlink operations. Parent
binding is not a lock. A same-UID change after inspection can still race a syscall;
post-checks can detect some changes but cannot undo an already-visible publication.
POSIX filesystem ACLs, special mounts, storage durability guarantees, replacement,
exact-artifact rollback, and multi-file transactions are not closed here. An fsync
success is not a universal power-loss guarantee. Do not interpret this independent
backend test as approval of the old public POSIX writer or Production operations.

## DS-04 / Unit 4E: first caller integration, single planning artifacts only

`write_production_single_update_plan` and `write_production_single_update_run_spec`
now use `_private_create_io.create_private_text`. Their existing CLI build commands
already invoke these writers, so the actual saved artifacts (not merely a test-only
entry point) take this route. Rendering, canonical bytes, schemas, accepted-pin
checks, lifetimes and authorization rules are unchanged. Inspection report outputs
are not migrated. No active Production pin, OAuth or live adapter is enabled.

On POSIX the adapter first performs the existing local-path/repository preflight,
then uses the retained-directory create-only backend with no legacy fallback.
The final parent must already be effective-user-owned with mode exactly `0700`;
no existing directory is created or repaired. This is an intentional tightening
for these two output writers only. Unsupported flags or filesystems stop rather
than choosing a less strict writer. On Windows the adapter delegates to the
existing private text writer with overwrite disabled and its unchanged ACL policy.

The two existing role-specific I/O exception classes retain their error codes and
now carry `publication_possible`. For write failures, `False` means no final-name
publication was attempted by that call; it does not promise no private temporary
or no output created by another process. `True` means a link attempt occurred.
`None` means the adapter cannot determine publication state (including unspecified
backend or Windows writer errors). Parse/read errors do not assign write evidence.
The boolean/unknown state is not authorization to retry, overwrite, delete, or
infer that the target name is absent. None of these writers retries or rolls back.

For `True` or `None`, the role-specific safe error message warns that output may
exist and must not be retried or removed automatically. The unchanged CLI error
handler prints that message and returns its existing nonzero error code without a
success message. OS text, paths and content are suppressed from normal traceback
chains. Cancellation/BaseException is not a new transactional guarantee.

Token-plus-generation-state bundle rollback and other multi-artifact callers are
explicitly left on their existing paths: swapping the common writer here would
silently change their failure semantics. Their correction is still required.
Unit 4E is a bounded integration, not full POSIX I/O or Production approval.

## Remaining DS-04 work (not closed by these increments)

Units 4A, 4B, 4C, 4D, and 4E do not complete POSIX writer hardening, refresh replacement, exact-artifact
cleanup, generation-state integrity, approval/evidence storage, directory ancestry
binding, filesystem ACL/mount policy, or multi-artifact transactions. These increments do not claim
that leaf checks alone protect against every concurrent ancestor substitution.

DS-04 remains OPEN. Production OAuth, live rehearsal, and Calendar writes remain
blocked. Historical Deep Security Scan is INCOMPLETE; the separate 47194b0 scan report
remains FAIL. No existing scan decision or Production authorization is upgraded here.
