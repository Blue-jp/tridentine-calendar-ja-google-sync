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

The credential input, token output, and nonsecret token-generation state are explicit, distinct, absolute repository-external paths. Relative or URL-like paths, repository or repository-parent paths, symlinks, overwrite, and path collisions are rejected. Credential content is read-only and is never copied or rewritten. Token writes are atomic, no-overwrite, fsynced where supported, and use private local permissions supported by the standard library.

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
- `get_event`, implementing one deterministic fresh `events.get`.

It does not return a generic Google service or events resource. Patch, import, insert, update, delete, move, watch, batch, ACL, CalendarList mutation, and Calendar clear are absent. In particular, Phase 6C `patch_description` is not imported into or reachable from the live rehearsal layer.

The full-list request has no `timeMin`, `timeMax`, query, sync token, or subset filter. It uses deterministic canonicalization and validates Production target identity, owner access, expected timezone, complete pagination, and aggregate identity/event-shape counters.

## Snapshot, Baseline, and Source gates

The fresh canonical full-snapshot hash must exactly equal the hash bound by a trusted Production Baseline. Candidate, Test-like, tampered, mismatched-target, incomplete, duplicate, ambiguous, added, removed, managed, or unrelated drift stops before get.

The Accepted Production Source Manifest, Source, trusted Baseline, and fresh snapshot must remain exactly bound. Canonical full diff must be zero: every managed event is unchanged and add, update, delete candidate, unmanaged, duplicate, ambiguous, invalid, and fatal counts are all zero. A natural Source change yields a safe stop such as `production_source_change_detected`; it never mutates the Calendar.

Only after these gates pass is one managed event selected deterministically from canonical order. The fresh get verifies exact iCalUID, Summary, Description, all-day dates, default event type, non-cancelled state, non-recurring state, and the presence of a fresh ETag.

The Google Event ID is resolved from the fresh snapshot in memory and the ETag remains in memory. Public output records only a safe UID reference and boolean presence/verification fields.

## API budget and retry policy

The rehearsal raw Calendar API hard maximum is 5. The nominal two-page full snapshot plus one get uses 3 calls; one-, two-, and three-page collections use 2, 3, and 4 calls respectively. At most one bounded read retry is allowed, and a predicted sixth call is rejected before transport use.

Only 429, rate-limit 403, and 500/502/503 read failures are retryable. Permission 403, 400, 404, 410, target mismatch, Baseline mismatch, Source diff, and malformed responses are terminal. No mutation method or mutation retry exists in this layer.

## Sanitized evidence

Future rehearsal output consists of a repository-external sanitized snapshot and Human/JSON reports created atomically without overwrite or symlink traversal. Safe output contains safe references, hashes, aggregate counts, scope/role/generation metadata, refresh and API counters, verification booleans, privacy findings, and a closed result state.

It excludes Calendar ID, full target fingerprint, raw UID, Summary, Description, Event ID, ETag, access/refresh token, credentials, client secret, Authorization header, local username, and absolute path.

## Operational sequence and deferred work

Phase 6D operational work, in a separate user-authorized step, will first create the dedicated token and then perform a read-only rehearsal. It must use real repository-external operational inputs, exact challenges, and a fresh security review. Phase 6E remains the only phase that may consider one naturally occurring, eligible Description-only Production patch. Add remains Phase 6F and Delete remains an independent phase.

Repository-wide Deep security scan required after merge and before Production OAuth. The Phase 6D.0 pull-request diff scan is necessary evidence for this code change, but it is not the final live-OAuth eligibility scan.
