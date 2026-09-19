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
Production Plan and Run Spec file writers through a dedicated adapter; Unit 4F
also connects rehearsal evidence outputs. Common
`atomic_write_private_text/json`, integrity writers, token refresh/rollback and
other operational callers are NOT switched to it. Windows retains its existing
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

## DS-04 / Unit 4F: rehearsal evidence batch, no transactional rollback

The rehearsal snapshot and text/JSON report writers now use the create-only
adapter. Existing file names, ordering (snapshot when present, text, JSON),
rendering, canonical bytes, and snapshot-optional behavior are unchanged. This
is local evidence output only; the live rehearsal CLI remains hard-off.

On POSIX all three outputs use the retained-directory publisher: existing
user-owned 0700 parent and new 0600 files, with no legacy writer fallback. Reports
remain sanitized data even though they are stored with private mode. On Windows the
snapshot retains the existing private writer and the two reports retain the
existing integrity writer. No existing ACL, owner, or directory is repaired.

This is NOT an atomic multi-file transaction. All payloads are rendered before
writing. A failure stops the sequence without retrying or deleting any final
output, including outputs whose writer already returned. The error retains
`publication_possible` and `completed_output_count` (the number of writer calls
that returned normally, not a persisted transaction record). For the batch,
`False` rules out only a final-name attempt by its writers, not temporary residue
or a competitor's output. `True` means a previous writer returned or the failed
writer reported a publication attempt. `None` means unknown when no earlier
writer returned. Unknown Windows/unspecified errors are never demoted to False.
For True or None, the safe message warns against automatic retry or removal.
Adapter/writer and recognized path-preflight errors suppress private path/content
and OS traceback context. Render errors happen before writing. Process termination
or BaseException remains outside this evidence contract.

No count/flag proves that a complete, mutually bound evidence set persists. A
successful snapshot alone must not be treated as completion of the batch. A
separate completion manifest/crash protocol would be needed before relying on
all-or-nothing batch behavior. No such protocol is enabled by this increment.
Token-plus-generation-state, refresh, exact rollback, approval/journal writes,
and common writers remain on their old paths. DS-04 remains PARTIAL.

## DS-04 / Unit 4G: generation-state content read boundary

`load_production_write_token_generation_state` now uses the strict private
reader on POSIX. The old group/other-mode policy is retained, but is checked on
the file descriptor used to read the bytes, not by a separate pathname stat.
The effective owner, regular-file type, single-link count, bounded size and
before/after content metadata are checked by the existing reader; no-follow
traversal and nonblocking leaf open are also reused. There is no generic-reader
fallback after a POSIX read error and no permission repair.

Generation state remains non-secret operational metadata. On Windows this loader
still calls the existing handle-bound integrity reader with
`windows_integrity_acl=True`; broad read permission is not newly forbidden and
private/protected secret-file ACL requirements are not imposed. The POSIX private
mode requirement is existing policy, not a reclassification of metadata as a secret.

Canonical JSON, generation hashes, role/target binding, predecessor transition
rules and parsers are unchanged. Path failures keep the existing role-specific,
path-free code; this increment does not claim new redaction for all parser errors.
Load success is not proof that the file is the newest authorized generation, that
it is signed, or that a matching token/state pair persists after the read.

The token/state writers, bundle ordering and rollback, refresh replacement,
reserved-path checks, common readers/writers, and the Unit 4C retained-directory
component are not changed. The content reader does not gain retained-ancestor
revalidation through this change. Those remaining boundaries, complete POSIX
Python 3.12 CI, and Production eligibility still need independent review.
DS-04 remains PARTIAL; no live adapter or Production authorization is enabled.

## DS-04 / Unit 4H: POSIX token/state create-only persistence, no final rollback

The Production token writer (only `overwrite=False`) and immutable generation-state
writer now use the reviewed create-only adapter on POSIX. The existing repository
and repository-parent exclusions, bounded canonical rendering, token scopes/roles
and token/state cross-binding are retained. Their parent directories must already
be effective-user-owned and exactly 0700; no permission repair, overwrite, legacy
fallback, automatic retry, or final-output deletion is introduced.

`write_production_write_token_bundle` retains state-first ordering, distinct-path
preflight and rendering of both documents before any write. On POSIX a writer
failure stops the pair without invoking the old content-check/path-unlink rollback.
A first-writer failure may leave state; a second-writer failure may leave state and
secret token material. An existing output, including a concurrently created file
with matching bytes, is not a rollback target. Do not infer absence from failure.
Private temporary cleanup internal to the publisher remains its existing policy.

Write errors retain `publication_possible` (False/True/None) and bundle errors add
`completed_output_count`, counting normally returned writer calls. If an earlier
writer returned, the pair's flag is True even when the next writer reports False.
Without earlier completion, the failed writer's flag is retained; an unspecified
failure is None. False rules out only a final-name attempt by that call, not private
temporary residue or another process's output. True is not proof of a complete
pair; None is unknown. True/None public messages prohibit automatic retry/removal.
Paths, credential values and low-level error chains are suppressed in these new
write-error boundaries. Render, input-validation and read errors do not gain a new
universal redaction/transaction guarantee; cancellation/BaseException is outside
the ordinary-exception evidence contract.

This is NOT a multi-file atomic commit, recovery manifest, generation-freshness
proof or authorization to load a failed pair. No live adapter is enabled. Windows
keeps its existing private token/state writers, protected-token ACL checks and
bundle recovery path. Existing Windows generation-state broad-read integrity policy
is unchanged. The explicit token `overwrite=True` path used by injected refresh
also remains unchanged on every platform and is NOT upgraded by this increment.
Readers, parsers, generation hashes, predecessor/target binding, common writers,
refresh logic, exact-artifact cleanup and live OAuth/rehearsal hard-offs are not
changed. Controlled reconciliation of residual files, safe replacement, ancestry,
filesystem ACL/mount policy, durability and complete POSIX Python 3.12 CI remain
required. DS-04 stays PARTIAL and Production operation remains BLOCKED.

## DS-04 / Unit 4I: refresh persistence failure evidence, not safe replacement

After an injected refresh returns and the refreshed credentials pass the existing
scope, evidence-origin, client identity and target/generation checks, persistence
still uses the existing explicit `overwrite=True` writer. This increment does not
replace that writer, make it conditional on an inode/content snapshot, or repair
its POSIX ancestry/replacement/durability limitations. Windows writer/ACL behavior,
new token/state creation, bundle ordering, read/parsing rules and generation state
are unchanged. Live authorization and rehearsal remain hard-off.

An ordinary exception from that one save call is now translated to
`ProductionWriteTokenRefreshPersistenceError`, a `ProductionWriteTokenRefreshError`
with the fixed safe code `production_write_token_refresh_persistence_failed`.
No usable credential session is returned. The refresh is not repeated; the token
and state are not removed, restored, reparsed for automatic recovery, or retried.
Raw writer error text and displayed exception context are suppressed.

The error has `refresh_completed=True` (the refresh result passed validation) and
`persistence_attempted=True` (the save function was entered). Neither proves a
particular remote provider state or a successful local replacement. Explicit
writer `publication_possible` evidence is retained only as False, True or None;
unspecified or invalid evidence remains None. The existing replacement writer
usually reports None. No exception text, errno, file existence, file content or
completed-output count is used to guess that replacement did not happen.

Even False only rules out the failed writer's own final-name attempt; it does not
establish that old credentials are still usable or that a provider did not rotate
them. Every persistence error therefore warns against automatic retry/removal.
These attributes are in-memory evidence, not a persistent reconciliation record.
An ordinary read or refresh-request failure retains its existing error contract;
BaseException/cancellation and process termination are not covered by this boundary.

The existing mock rehearsal catches the RefreshError subclass, records the
provider's existing attempt count, emits TOKEN_REFRESH_FAILED with the new safe
code, and constructs no Calendar transport. No report schema/hash is changed, and
its aggregate report does not newly serialize these in-memory evidence fields.
A report with this stop code is not proof of an intact or recoverable token/state
pair. Controlled reconciliation, safe replacement, full POSIX Python 3.12 CI and
all remaining DS-04 boundaries remain required. DS-04 remains PARTIAL.

## DS-04 / Unit 4J: refresh pre-save input recheck, not conditional replacement

After the existing refresh-result validation and before entering token persistence,
refresh reloads generation state and the original token through the existing
role-specific loaders. It compares each canonical UTF-8 serialization to the
corresponding input originally loaded before refresh. Both comparisons must match;
no credential text, digest, path or low-level exception is emitted. This check
applies to Windows and POSIX and reuses their existing read/ACL policies.

An observed content change, missing/unreadable/unsafe file, parse failure or other
ordinary exception in this recheck stops with the fixed safe code
`production_write_token_refresh_prewrite_unverified`, carried by
`ProductionWriteTokenRefreshPrewriteError` (a RefreshError subclass). The error
has `refresh_completed=True`, `persistence_attempted=False`, and
`publication_possible=False`, solely because this call has not entered its save
function. False is NOT proof of unchanged files, an intact pair, usable old tokens
or unchanged provider credentials. Refresh has already returned, so the error
always prohibits automatic retry, removal or restoration. No session is returned.
The existing mock rehearsal records TOKEN_REFRESH_FAILED and the attempt counter
before constructing a Calendar transport; no report schema or recovery manifest
is added. Unit 4I still handles ordinary exceptions from the later save call.

This is a best-effort content recheck, NOT compare-and-swap, a lock, a transaction,
generation freshness, authentication or a safe replacement backend. The reads
are sequential and their descriptors are not retained through persistence. A
same-content replacement can pass, a change after its read can be missed, and
existing overwrite=True can still overwrite a racing change after the check.
ABA changes, hostile same-UID/privileged changes, cancellation, process death and
provider-side rotation/recovery remain outside this guarantee. The check prevents
only proceeding past a mismatch or failed read that it actually observes.

Canonical formats, role/scope/evidence/identity/target/generation checks, current
unexpired-token behavior, refresh invocation count, all writers, Windows ACLs,
bundle rollback, common I/O and live hard-offs are unchanged. Reconciliation,
conditional/serialized replacement, ancestry, ACL/mount policy, durability and
complete POSIX Python 3.12 CI remain pending. DS-04 stays PARTIAL.

## DS-04 / Unit 4K: independent retained-descriptor replacement, not yet integrated

`_posix_private_replace.replace_posix_private_bytes` accepts bounded replacement
bytes AND exact expected prior bytes. It requires an existing, effective-user-owned,
single-link regular file with exact 0600 mode in an existing user-owned 0700 parent.
It uses the retained directory binding from Unit 4C and existing byte/identity checks
from Unit 4D. Root-to-parent descriptors and BOTH old/new leaf descriptors remain
open through verification. Existing public writers, token refresh, loaders,
parsers, Unit 4I/J errors, Windows ACLs and token/state bundle recovery do not use
this function yet and are unchanged by Unit 4K. There is no live authorization.

The prior file is opened read-only, no-follow and nonblocking. Expected content,
identity, ownership, permissions, link count and metadata are checked before making
a temporary and again before replace. A missing or mismatching destination is not
created or repaired. The unpredictable temporary is exclusive-created relative to
the retained parent, prepared as 0600 before content writes, fsynced and read back
through its own descriptor. Short writes/reads and empty content are supported.
Both final-name and temporary-name bindings and the ancestry are rechecked.

Publication uses one `os.replace` call with two names relative to the retained
parent. It is an overwriting syscall, NOT inode/content compare-and-swap. Expected
bytes and metadata are observations, not a kernel condition on that syscall.
Holding an old descriptor prevents its inode reuse while held, but does not lock
its name or contents. A same-UID/privileged writer may still change a name AFTER
inspection; such a change may be overwritten. Some post-checks detect races but
cannot undo an already-visible rename. No hostile-same-UID or all-race guarantee,
lock protocol, generation freshness or persistent pair consistency is claimed.

After replace, the old descriptor must be unlinked and still contain expected
bytes, and the final name must identify the new 0600 single-link file with exact
new content. Parent fsync and a final recheck are required before success. An fsync
result is not a universal durability/power-loss guarantee or an atomic pair commit.

`PosixPrivateReplaceError.publication_possible` is False until the first replace
attempt and True thereafter, even when the syscall raises. It never infers that
old credentials remain usable or that files/provider state are unchanged. All
ordinary failures suppress raw paths/content/OS exception text and prohibit
automatic retry, removal or restoration. No automatic name cleanup occurs on
failure: a private temporary, the old target, a new target or a competitor may
remain. Successful rename consumes the temporary name; failures may leave it.
Cancellation/BaseException and process death do not gain a recovery record.

Integration into refresh, retained original-input identities across refresh,
serialization/conditional replacement, controlled residue reconciliation,
ACL/mount policy, ancestry assumptions and complete locked Python 3.12 Linux CI
remain separate gates. DS-04 stays PARTIAL; Production remains BLOCKED. This
independent backend must not be described as an upgrade to overwrite=True yet.

## DS-04 / Unit 4L: POSIX refresh persistence integration, not serialized replacement

The existing credential-session refresh flow now calls
`persist_refreshed_production_write_token` with the refreshed token AND the original
pre-refresh token as required `expected_token`. Unit 4J first rechecks the token and
generation state as before. The persistence entry point receives the original
value, never a freshly adopted current target or a hash from external context.
The existing canonical token parser requires exact canonical bytes, so rendering
the original loaded token supplies the expected prior bytes without a new format.

POSIX encodes and bounds both serializations, applies existing local-path and
repository-parent exclusions, then uses Unit 4K's retained-directory/old-and-new
leaf descriptor backend. Exact 0700 user-owned parent and existing exact 0600
single-link user-owned regular target are required; no repair, missing-target
creation, or fallback to the generic overwrite writer occurs on backend failure.
An observed token change after the Unit 4J recheck but before/during Unit 4K checks
stops without knowingly replacing that observed value. This is not a kernel CAS:
same-content replacements and last-moment same-UID/privileged races can pass or be
overwritten. Original descriptors are not retained across the refresh request;
generation state is not locked or revalidated atomically with the token replace.

Windows delegates to the unchanged `write_production_write_authorized_user_token`
with `overwrite=True`, retaining its protected ACL and existing error behavior.
The generic writer remains available with unchanged create/overwrite semantics on
both platforms; only the selected refresh call site is rerouted. Token/state new
creation, bundle recovery, common I/O, and Windows backend code are unchanged.

POSIX errors use the safe `production_write_token_refresh_replace_failed` I/O code
and conservative `publication_possible`: False until backend entry for preflight
failures; exact False/True from a recognized backend error; None for unspecified
or invalid backend evidence. Unit 4I converts that to its existing dedicated refresh
persistence error without returning a usable session, repeating refresh, deleting
residue, or restoring the previous token. False never means provider state or old
credentials are unchanged. Mock rehearsal still records TOKEN_REFRESH_FAILED and
stops before Calendar transport construction; report schema/hash remain unchanged.
Cancellation/process death get no new durable recovery record. Private temporary
or new target data may remain on failure and must not be automatically removed.

Authorization/scope/evidence/client/target/generation checks, current unexpired
credentials, Unit 4I/4J evidence, and all live hard-offs remain in force. This is
only an integrated POSIX token replacement path, not serialization, safe pair
reconciliation, full ancestry/ACL/mount policy, general durability, or operational
approval. All remaining DS-04 gates and locked Python 3.12 Linux CI remain required.

## DS-04 / Unit 4M: independent nonblocking advisory directory lock

`_posix_private_lock.acquire_posix_private_directory_lock` is a new independent
component, NOT connected to token refresh, new token/state creation, writers,
readers or reconciliation. Existing application source and operational entry points
are unchanged. Passing this component's tests does not serialize any existing flow.

This first backend is explicitly limited to Linux-native `fcntl.flock` semantics.
It obtains a separate retained root-to-parent binding from Unit 4C, requires an
existing effective-user-owned exact 0700 final directory, then makes ONE
`LOCK_EX | LOCK_NB` request on that directory's open description. It revalidates
the bound name, ownership, mode and Git markers before and after acquiring the lock.
A conflict is a safe busy error, not a sleep/retry loop, success, or an unlocked
fallback. Other ordinary failures and unsupported platforms stop path-free.
Windows and other POSIX systems have no fallback in this independent backend.
No lock file/PID file is created, read, deleted or repaired; nothing is stored in
the token or state files. No existing directory permissions are changed.

The returned context retains the directory descriptors and permits explicit
revalidation. Context exit, acquisition failure and cancellation close this
attempt's descriptors; closing is idempotent and never retries descriptor close.
Nested use of the same context is rejected without unlocking its outer context.
There is no explicit LOCK_UN, so a post-fork child closing its duplicate cannot
unlock the parent's shared open description. Revalidation rejects a changed PID
and closes the child's copies. Callers must NOT fork or duplicate descriptors
while holding the lock: copies inherited before revalidation can extend lock
lifetime, including after the original holder exits. No durable crash evidence or
provider-state recovery guarantee follows from releasing a lock.

This is advisory coordination for cooperating callers using the SAME directory
inode and flock protocol, not access control or a leaf-content lock. Unrelated
directories do not contend. Renaming/recreating a directory changes the lock key:
revalidation can detect that, but does not make namespace operations atomic.
A same-UID/privileged process that ignores the lock can still modify files, names,
permissions or the directory itself. Tests explicitly demonstrate these limits.
NFS/SMB/remote/special-mount semantics are not approved by a successful syscall;
filesystem/mount qualification remains a separate gate. This Linux restriction
avoids silently claiming portable process/thread lock semantics elsewhere.

A later integration must acquire the lock BEFORE loading token/state or sending
any refresh request, retain it through refresh, input rechecks and persistence,
and coordinate every participating mutator with the same key and lock lifetime.
Acquiring a lock only around the final replace would not serialize provider
refresh. The exact integration and multi-directory policy are NOT introduced here.
Original input identity, noncooperating mutation, interrupted-refresh residue,
reconciliation, ACL/mount policy and locked Python 3.12 Linux CI remain pending.
DS-04 remains PARTIAL; Production OAuth/Calendar operations remain BLOCKED.

## DS-04 / Unit 4N: cooperative credential-session serialization on Linux

The shared credential-session loader now holds Unit 4M directory locks before
its first token/state content read, through unexpired-token validation or injected
refresh, Unit 4J recheck, Unit 4L persistence, and the final checkpoint before
return. Existing UTC and path-set metadata preflight remain before lock acquisition;
role/scope/evidence/client/target/generation validation and confirmation precede or
remain within their existing flow. Both provider-evidence and explicit mock session
entry points use the shared loader. This does not enable a live refresher or CLI.

One lock is acquired for each distinct token/state parent (one or two) in sorted
lexical absolute-path order. There is one nonblocking attempt per parent; failure
of the second releases the first and no content is loaded or refresh attempted.
A same-parent pair acquires just one lock. No lock/PID files, stale-lock cleanup,
permission repair, wait loop, automatic retry or unlocked fallback is introduced.
Linux parents must already be effective-user-owned, exactly 0700, and pass the
retained no-follow directory policy. This tightens even unexpired-token loading.
Unsupported non-Windows platforms fail before token/state content reads. Windows
bypasses this new Linux protocol and retains its existing readers/writers/ACL and
session behavior; it does NOT gain cross-process serialization from this change.

The held parents are revalidated after initial content reads, before refresh,
after refresh-result validation, immediately before persistence, and before each
normal session return. An observed directory replacement/policy failure prevents
further progression; after a refresh or save it cannot undo provider/file changes.
The safe RefreshError subclass uses production_write_token_session_busy for a
recognized acquisition conflict, otherwise production_write_token_session_lock_unverified.
It returns no usable session, exposes no path or raw lock exception, and prohibits
automatic retry/removal/restoration. It makes no false refresh/publication-absence
claim. Existing Unit 4I/4J error evidence is preserved: the context manager does not
catch or replace their exceptions. Mock rehearsal still records TOKEN_REFRESH_FAILED
and the existing refresh attempt count before building any Calendar transport.
There is no new report field or durable recovery manifest. Contexts close on normal
return, error or BaseException; fork/dup and process interruption retain Unit 4M limits.

This protocol serializes ONLY loaders following this protocol on the same retained
directory inodes. Generic writers, authorization/new-pair creation, standalone
persistence functions and noncooperating processes are not newly locked. The lock
ends when session preparation ends, not after future API use. It is not a leaf
CAS, atomic token/state snapshot, or latest-generation proof. Same-UID/privileged
writers and directory replacement can still evade or race observations; equal
contents do not prove original leaf identity. No same-UID-adversary or universal
mount/ACL/durability guarantee is added. Pair reconciliation, participation of
other writers, original identities across refresh, supported-filesystem policy,
crash recovery and complete locked Python 3.12 Linux CI remain separate gates.
DS-04 remains PARTIAL and Production remains BLOCKED.

## Remaining DS-04 work (not closed by these increments)

Units 4A, 4B, 4C, 4D, 4E, 4F, 4G, 4H, 4I, 4J, 4K, 4L, 4M, and 4N do not complete POSIX writer hardening, refresh replacement, exact-artifact
cleanup, generation-state integrity, approval/evidence storage, directory ancestry
binding, filesystem ACL/mount policy, or multi-artifact transactions. These increments do not claim
that leaf checks alone protect against every concurrent ancestor substitution.

DS-04 remains OPEN. Production OAuth, live rehearsal, and Calendar writes remain
blocked. Historical Deep Security Scan is INCOMPLETE; the separate 47194b0 scan report
remains FAIL. No existing scan decision or Production authorization is upgraded here.
