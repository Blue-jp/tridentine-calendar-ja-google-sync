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

## DS-04 / Unit 4C: retained-directory binding foundation, not yet integrated

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

This foundation is NOT used by any existing reader, writer, or cleanup function
yet. It performs only metadata inspection and directory opens/closes, and does
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

## Remaining DS-04 work (not closed by these increments)

Units 4A, 4B, and 4C do not complete POSIX writer hardening, refresh replacement, exact-artifact
cleanup, generation-state integrity, approval/evidence storage, directory ancestry
binding, filesystem ACL/mount policy, or multi-artifact transactions. These increments do not claim
that leaf checks alone protect against every concurrent ancestor substitution.

DS-04 remains OPEN. Production OAuth, live rehearsal, and Calendar writes remain
blocked. Historical Deep Security Scan is INCOMPLETE; the separate 47194b0 scan report
remains FAIL. No existing scan decision or Production authorization is upgraded here.
