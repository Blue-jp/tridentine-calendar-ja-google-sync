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

## Remaining DS-04 work (not closed by this increment)

This increment does not redesign POSIX writers, refresh replacement, exact-artifact
cleanup, generation-state integrity, approval/evidence storage, directory ancestry
binding, filesystem ACL/mount policy, or multi-artifact transactions. It does not claim
that leaf checks alone protect against every concurrent ancestor substitution.

DS-04 remains OPEN. Production OAuth, live rehearsal, and Calendar writes remain
blocked. Historical Deep Security Scan is INCOMPLETE; the separate 47194b0 scan report
remains FAIL. No existing scan decision or Production authorization is upgraded here.
