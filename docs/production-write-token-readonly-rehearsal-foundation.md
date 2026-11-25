# Production write-token read-only rehearsal foundation

## Phase 6C to Phase 6D.0 boundary

Phase 6C defines a mock-only Production single-update transport and approval state. Phase 6D.0 adds the code contracts needed to authorize a separately stored Production write token and rehearse only read operations with that token. It does not execute OAuth, create a token, open a browser, construct a live Calendar client, access a Production Calendar, or connect the Phase 6C patch capability to a live adapter.

The existing Production write hard lock remains authoritative. The authorization and rehearsal command surfaces are deliberately live-disabled in this phase. Production Add, Delete, rollback, operational ARM / EXECUTE issuance, and kill-switch enablement remain unavailable.

## Dedicated token role and exact scope

The token roles are closed and distinct:

1. `production_read`;
2. `test_write`; and
3. `production_write`.

Only `production_write` is accepted by this foundation. There is no generic write-token role, fallback search, token copying, migration, or reuse across roles. Each role has a separate explicit repository-external artifact and generation state.

The authorization request and granted scope set must both equal this one-item set exactly:

```text
https://www.googleapis.com/auth/calendar.events.owned
```

Broader Calendar scopes, the read-only scope, profile, email, OpenID, Drive scopes, multiple scopes, and incremental scope expansion are rejected. Although this Google scope can authorize mutations, the rehearsal capability exposes only list and get. The authorization layer does not import or construct a Calendar API service.

Requested scopes are policy input, not proof of the provider grant. A versioned `ProductionWriteGrantedScopeEvidence` record carries the explicitly present scope tokens, authorization-versus-refresh origin, and observation time. Missing, empty, duplicate, malformed, broader, read-only, unrelated, stale, or context-mismatched evidence fails closed. `credentials.scopes`, requested constants, and previously persisted `granted_scopes` are never fallback grant evidence.

The operational authorization entry point accepts no caller-injected authorizer and remains live-disabled. The explicit mock entry point accepts only test-origin evidence, and tokens produced by it are rejected by the operational provider-evidence verifier. Provider-origin evidence can only be consumed by the future internally constructed live adapter; Phase 6D.1D does not add that adapter.

## Repository-external token and credential handling

The credential input, token output, and nonsecret token-generation state are explicit, distinct, absolute repository-external paths. Relative or URL-like paths, repository or repository-parent paths, symlinks, overwrite, and path collisions are rejected. Credential content is read-only and is never copied or rewritten. Token creation is no-overwrite and uses private local permissions. On POSIX, token and generation-state creation now use the retained-directory publisher and require an existing effective-user-owned 0700 parent. The state-first pair is not an atomic transaction: a persistence failure may leave state and/or token material, and the POSIX bundle does not automatically delete final outputs or retry. Its safe error preserves publication uncertainty and the count of completed writer calls. Windows keeps its existing writer/ACL/recovery behavior. Explicit token replacement during refresh is unchanged and remains a separate unresolved boundary. See [POSIX private-artifact security](posix-private-artifact-security.md).

Raw access tokens, refresh tokens, client secrets, full client IDs, Authorization headers, token hashes, credential hashes, Calendar IDs, Event IDs, ETags, and absolute paths are never written to stdout, stderr, generation state, public reports, or Git.

## Token generation and refresh

`ProductionWriteTokenGenerationState` is an opaque nonsecret counter bound to the `production_write` role and target safe identity. First issuance is generation 1. Rotation must be exactly predecessor generation plus one and bind the predecessor state hash. The counter is independent of token content; no raw-token or token-file hash is an authority.

An unexpired valid token performs no refresh. An expired token permits at most one standard refresh. After refresh, exact scope, fresh refresh-response evidence, role, target binding, and unchanged generation are revalidated. A future live adapter must construct a fresh Google credential object with no carried `granted_scopes` before calling the public refresh method; if the fresh response omits its scope field, the operation stops instead of reusing the old grant. Refresh-token rotation within the same authorization identity does not increment the generation. Refresh failure never opens a browser, starts interactive OAuth, calls Calendar, deletes the old token, or overwrites it.

The private token schema is version 2 and requires the grant-evidence record. Version 1 or requested-scope-only tokens are not silently migrated; explicit re-authorization is required.

## Explicit authorization and read challenges

The future authorization confirmation is exact, case-sensitive, and whitespace-sensitive:

```text
AUTHORIZE PRODUCTION WRITE TOKEN ONLY T-<12>
```

The future rehearsal confirmation is likewise exact:

```text
READ PRODUCTION CALENDAR USING DEDICATED WRITE TOKEN T-<12>
```

The safe target reference is derived from a validated Production target config; no current Production target is hard-coded. A mismatch stops before OAuth, refresh, client construction, API calls, or writes. Phase 6D.0 exposes these command shapes for review but rejects live invocation before reading operational inputs.

## Read-only rehearsal capability

The dedicated rehearsal boundary exposes only:

- `list_events`, implementing complete unfiltered `events.list` pagination; and
- `get_event`, verifying one deterministically selected managed event with at most two `events.get` attempts for that same event.

It does not return a generic Google service or events resource. Patch, import, insert, update, delete, move, watch, batch, ACL, CalendarList mutation, and Calendar clear are absent. In particular, Phase 6C `patch_description` is not imported into or reachable from the live rehearsal layer.

The full-list request has no `timeMin`, `timeMax`, query, sync token, or subset filter. It uses deterministic canonicalization and validates Production target identity, owner access, expected timezone, complete pagination, and aggregate identity/event-shape counters.

## Snapshot, Baseline, and Source gates

The fresh canonical full-snapshot hash must exactly equal the hash bound by a trusted Production Baseline. Candidate, Test-like, tampered, mismatched-target, incomplete, duplicate, ambiguous, added, removed, managed, or unrelated drift stops before get.

The Accepted Production Source Manifest, Source, trusted Baseline, and fresh snapshot must remain exactly bound. Canonical full diff must be zero: every managed event is unchanged and add, update, delete candidate, unmanaged, duplicate, ambiguous, invalid, and fatal counts are all zero. A natural Source change yields a safe stop such as `production_source_change_detected`; it never mutates the Calendar.

Only after these gates pass is one managed event selected deterministically from canonical order. The fresh get verifies exact iCalUID, Summary, Description, all-day dates, default event type, non-cancelled state, non-recurring state, and the presence of a fresh ETag.

The Google Event ID is resolved from the fresh snapshot in memory and the ETag remains in memory. Public output records only a safe UID reference and boolean presence/verification fields.

## API budget and retry policy

The rehearsal raw Calendar API hard maximum is 5. One-, two-, and three-page collections with a single GET use 2, 3, and 4 calls respectively. List and GET share one retry slot. A sixth call is rejected before the transport is invoked.

The report counts actual transport attempts. Two GET attempts require `read_retry_count` to be 1. The retry count records consumption of the shared slot, so it can be 1 with zero or one GET attempt. This includes a list retry or a retry that consumes the slot and then hits the total call limit.

Only 429, rate-limit 403, and 500/502/503 read failures are retryable. Permission 403, 400, 404, 410, target mismatch, Baseline mismatch, Source diff, and malformed responses are terminal. No mutation method or mutation retry exists in this layer.

## Sanitized evidence

Future rehearsal output consists of a repository-external sanitized snapshot and Human/JSON reports created atomically without overwrite or reparse traversal. The snapshot is redacted operational-private evidence and uses the private writer. Human/JSON reports are sanitized public-safe aggregates and use the same handle-bound path-integrity and safe-parent policy without requiring token-confidential leaf ACLs. Safe output contains safe references, hashes, aggregate counts, scope/role/generation metadata, refresh and API counters, verification booleans, privacy findings, and a closed result state. Windows path and ACL details are defined in [Windows sensitive filesystem security](windows-sensitive-filesystem-security.md).

It excludes Calendar ID, full target fingerprint, raw UID, Summary, Description, Event ID, ETag, access/refresh token, credentials, client secret, Authorization header, local username, and absolute path.

## Operational sequence and deferred work

Phase 6D operational work, in a separate user-authorized step, will first create the dedicated token and then perform a read-only rehearsal. It must use real repository-external operational inputs, exact challenges, and a fresh security review. Phase 6E remains the only phase that may consider one naturally occurring, eligible Description-only Production patch. Add remains Phase 6F and Delete remains an independent phase.

Repository-wide Deep security scan required after merge and before Production OAuth. The Phase 6D.0 pull-request diff scan is necessary evidence for this code change, but it is not the final live-OAuth eligibility scan.

## Refresh persistence failures (DS-04 / Unit 4I)

The injected refresh path still uses the existing explicit token replacement
writer; no live refresher or safer replacement protocol is enabled. Once refreshed
credentials have passed validation, an ordinary save exception becomes
`production_write_token_refresh_persistence_failed` and no credential session is
returned. The safe exception retains conservative in-memory publication evidence
and always warns against automatically retrying, deleting, or restoring files.
The unchanged mock rehearsal classifies this as TOKEN_REFRESH_FAILED before any
Calendar transport is built. Its report contains the safe code and existing
refresh-attempt counter, not a new persisted token recovery record. A failure can
leave old or new token material; manual/controlled reconciliation and the unresolved
replacement boundary remain separate work. See [POSIX private-artifact security](posix-private-artifact-security.md).

## Refresh pre-save input recheck (DS-04 / Unit 4J)

Before saving a validated refresh result, both originally loaded token/state
contents are reloaded and compared by canonical bytes using their existing
role-specific readers. A mismatch or ordinary re-read/parse failure emits
`production_write_token_refresh_prewrite_unverified`: no save call or session,
no automatic retry, removal or restoration. Refresh has already completed, so
this is not evidence that the old token remains usable. The unchanged rehearsal
classifies it as TOKEN_REFRESH_FAILED before Calendar transport construction.
This detects observed pre-save changes only: no atomic pair snapshot, lock,
inode compare-and-swap, safe overwrite or durable recovery record is introduced.
Changes after recheck remain possible. Unit 4I persistence failure behavior and
all live hard-offs remain in force. See [POSIX private-artifact security](posix-private-artifact-security.md).

## POSIX refresh replacement integration (DS-04 / Unit 4L)

After the unchanged Unit 4J token/state content recheck, refresh passes the original
loaded token to the new persistence entry point as exact expected prior content.
POSIX uses the retained-directory and old/new descriptor replacement backend;
Windows keeps the prior protected writer. The generic overwrite API is unchanged.
No authorization checks, schemas, live adapters or operational permission change.
Unit 4I retains conservative replacement evidence and returns no usable session
on failure. No automatic retry, residue deletion or restoration is performed.
Observed changes can block a replacement, but checks and rename are not a lock or
compare-and-swap; post-check races and generation-state changes remain possible.
See [POSIX private-artifact security](posix-private-artifact-security.md) for the
remaining reconciliation, serialization, ACL/mount and durability gates.

## Linux credential-session serialization (DS-04 / Unit 4N)

The token/state parent directories are exclusively locked before content loading
and held through validation, injected refresh, recheck and persistence. A busy or
unverified lock stops without a usable session or automatic retry/cleanup. Parents
may differ: each distinct parent is locked once with immediate failure on contention.
Existing metadata path preflight remains first. This is Linux-only cooperative
serialization for these session entry points, including unexpired credentials;
Windows keeps its existing behavior and gains no new lock. Other non-Windows
platforms cannot fall back to an unlocked load. Other artifact writers do not yet
participate, no leaf compare-and-swap or durable recovery record is introduced,
and all live hard-offs remain. See [POSIX private-artifact security](posix-private-artifact-security.md).

## Linux new-pair publication serialization (DS-04 / Unit 4O)

New token/state bundle publication now shares Unit 4N's parent-directory locks on
Linux, from before state creation through token creation and the final checkpoint.
This does not acquire a second lock inside leaf writers or change refresh locking.
Busy/unverified locks stop; prior writes remain and their conservative publication
flag/count are reported. A failure after two normally returned writers is still
an error, never a completed transaction. Windows bundle recovery is unchanged.
Authorizer/provider activity before this persistence call is not newly locked, and
failed pairs gain no persistent recovery marker. Standalone writers, reconciliation,
noncooperating changes, directory replacement and filesystem/durability boundaries
remain separate work. DS-04 remains PARTIAL and all live hard-offs remain in force.
See [POSIX private-artifact security](posix-private-artifact-security.md).

## GET retry report accounting correction

On 2026-11-17 JST, the user approved recording up to two actual GET attempts for one selected event, with one shared list/GET retry slot and five total transport calls. The fixed starting HEAD was `ec3ec6a8fc1b7e288522217de6699c88f410d766`.

The preceding diagnosis is inherited evidence. It comprised six stored-result fake cases and four supplemental executions of the existing control bodies, for ten successful observations. In that diagnosis, both two-GET paths escaped report construction with a Pydantic `ValidationError` at `get_call_count` (`less_than_equal`). One path had verified the event and reached READY report construction. The other had reached a stop report with the second transport error. The original Windows `tmp_path` pytest nodes were outside the supplemental execution.

The model and saved Draft 2020-12 Schema now allow GET counts from zero through two and require a retry count of one when GET is two. The retained API budget and retry counters describe actual transport attempts and shared retry slot consumption, respectively. The wrapper, read and retry logic, fake transport, renderer, hashes, and credential preparation and ownership paths retain their existing implementation.

The tracked review covered the model, renderer, Schema, schema-related tests, and build configuration. The build configuration includes the Schema in the source distribution and wheel. No runtime loader for this specific Schema, dedicated existing instance test, mandatory version bump rule, or in-repository consumer contract requiring the old cap was identified in that scope. The v1 Schema filename, `schema_version`, `report_type`, and `$id` are preserved. Readers pinned to the old model or Schema can reject the newly representable count of two. External consumers were outside the review.

Windows Python 3.12.14 resolved the package to this worktree. Installed versions matched `uv.lock`, including pytest 8.4.2, pytest-socket 0.8.1, Pydantic 2.13.4, jsonschema 4.26.0, Ruff 0.16.4, and mypy 1.20.2. Pytest used the existing strict settings and socket guard, Python `-B`, and the disabled cache provider.

| Execution | Collected | Passed | Failed | Errors | Skipped | Deselected | Exit |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Before A and B changed, normal and both two-GET nodes | 3 | 1 | 2 | 0 | 0 | 0 | 1 |
| Final new production-write pytest nodes | 87 | 22 | 0 | 0 | 0 | 65 | 0 |
| Existing production-write pytest nodes | 17 | 17 | 0 | 0 | 0 | 0 | 0 |
| Existing base guards | 2 | 2 | 0 | 0 | 0 | 0 | 0 |
| Supplemental executions of existing test bodies | 27 | 27 | 0 | 0 | 0 | 0 | 0 |

In the before-change run, the normal control passed and the two expected report-return cases failed at the original model limit. The final real wrapper cases gave the following counts. Each loaded the provider and built the fake once, with zero mutations.

| Scenario | API / list / GET / retry | Report |
| --- | --- | --- |
| Normal | 2 / 1 / 1 / 0 | READY with snapshot |
| GET retry succeeds | 3 / 1 / 2 / 1 | READY with verified event and bound snapshot |
| Both GET attempts fail | 3 / 1 / 2 / 1 | TRANSPORT_FAILED with the second code, `server_502` |
| Non-retryable GET | 2 / 1 / 1 / 0 | INPUT_BINDING_MISMATCH with `permission_denied` |
| List consumes retry before GET failure | 3 / 2 / 1 / 1 | TRANSPORT_FAILED with `server_503` |
| GET retry hits the five-call cap | 5 / 4 / 1 / 1 | API_CALL_LIMIT_EXCEEDED with `api_call_limit_exceeded` |

The mismatched event after a retry stopped with GET_VERIFICATION_FAILED. A list failure after the shared retry produced a stopped report with GET zero and retry one. The real two-GET success and stop outputs passed saved-Schema validation, JSON and model reread, report hash and snapshot binding checks where applicable, and text rendering with the actual count. The tests separately checked the Schema itself, sensitive-value exclusion, invalid count combinations and unknown fields in both validators, and the retained terminal invariants in the model.

The 17 existing production-write nodes covered two existing structural or monitor cases, public provider refusal, the CLI, and wiring and privacy. The two base guards covered the generic schema/privacy scan and rehearsal CLI hard-off.

The 27 supplemental cases delegated to three parameter sets of the original pagination test definition, the original list retry test body, and 23 fail-closed cases from a separate test file under the production marker and socket guard. They received fresh ordinary scratch paths in place of requesting the Windows ACL-adjusting pytest fixture. They were collected as supplemental nodes, not direct executions of the original pytest nodes.

Of the original 65 cases in `tests/test_production_write_token_rehearsal_phase6d0.py`, two were executed directly and four through supplemental nodes: the three pagination parameter sets and the list retry case. These were six distinct original cases; the remaining 59 were not executed for this correction. The 23 fail-closed cases in the separate file were included in the 27 supplemental executions, not in those six cases. The new-test-only run's 65 deselected cases describe that run's selection, not the total unexecuted scope.

The two private report-output cases and the native and independent-process probes remained outside the executed scope. The broader private-storage and full regression suites were also not run.

Individual output lines and pytest display IDs for the two CLI help parameter sets and the 27 supplemental cases were not obtained. Their identification relies on the saved selectors or harness records, fixed definitions, and aggregate execution results; this is not direct individual-node log evidence. No execution counts have been revised.

Ruff lint, repository format check (290 files), strict mypy for the changed module and all 124 source files, and direct JSON Schema checks passed. Synthetic ICS fixture generation, reading, and cleanup stayed within fresh test-owned scratch. Credential and START storage, private report publication, and real Google operations were outside the exercised path.

Run 43541737935 attempt 1 and comment 6916607308 are inherited evidence for the preceding connection change. They do not cover this correction. DS-04 remains PARTIAL. The Historical Deep Security Scan remains INCOMPLETE, the separate 47194b0 scan remains FAIL, Production remains BLOCKED, live handlers remain hard-off, and the registry remains empty and fail-closed.
