# Test Calendar write transport foundation

## Scope and authority boundary

Phase 5A adds code for a future, explicitly approved write to one dedicated Test Calendar. Development and CI remain mock-only: they do not start OAuth, open a browser, create a token, call Google Calendar, or change an event.

The Test write token is separate from the Production owned-events read-only token. It accepts exactly one scope:

`https://www.googleapis.com/auth/calendar.events.owned`

That scope can delete events at Google's authorization layer, but this project exposes no delete model, payload, adapter method, command, or executor. Broad Calendar scopes, read-only scopes, multiple scopes, and automatic scope fallback are rejected.

## Test target policy

Every write-layer entry point requires a repository-external, non-symlink Test target configuration. The environment and label must both be `test`, the purpose must be `test_calendar_write_acceptance`, the target must not be `primary`, and the observed fingerprint, summary, owner role, and `Asia/Tokyo` timezone must match exactly. The summary must visibly identify the calendar as a test calendar.

The known Production safe reference `T-e10f0095ab8f`, a Production environment or label, and any target that fails the Test policy are blocked before write preflight. Existing Production read-only inspection remains separate.

## One operation per run

A private `TestWriteRunSpec` binds one verified source, current sanitized Test snapshot, non-executable sync plan, target identity, thresholds, and—when updating—a trusted Test baseline. It is always test-only and Production-locked, and permits exactly one operation:

- add `1`, update `0`; or
- add `0`, update `1`.

Zero operations, multiple operations, mixed add/update, delete candidates, unmanaged or ambiguous events, duplicates, and fatal findings are rejected. The exact approval phrase binds the Test target safe reference, run-spec hash, and add/update counts. It grants authority for only that single run spec.

## Read-only prewrite inspection

Phase 5B operations must begin with `inspect-test-calendar-prewrite`, not by weakening or deliberately failing `run-test-calendar-write`. The prewrite command uses the separated Test write token but passes a dedicated list-only Protocol to the application layer. That Protocol can call `events.list` and cannot reach get, import, patch, delete, clear, batch, or a generic Google service.

The prewrite command requires explicit `--online`, but it does not require a mutation approval phrase or Run Spec. It saves a sanitized snapshot and public-safe Human / JSON reports outside the repository. Empty Calendar is the only write-ready result. A non-empty Calendar is preserved unchanged, reported through aggregate counts, and requires manual review; the tool never deletes or clears it automatically.

The saved snapshot is a private `test-calendar-prewrite-snapshot-v1` wrapper that binds the canonical sanitized snapshot to the Test target, page count, total API-call budget, retry count, and hashes. A later consumer must load and verify the wrapper first, then use its nested `snapshot`; it must not pass the wrapper file directly to the ordinary Google snapshot loader.

Production identity, Production environment or label, `primary`, and every target-policy mismatch are rejected before credentials or a Google client are constructed. Development and CI exercise only mock pages and never load operational credentials, token, target, or snapshot files.

## Test-only bootstrap add planning

The normal Sync Plan and Test Bootstrap Add Plan are different artifact types with separate models, schemas, builders, and commands. Bootstrap planning does not alter or suppress the normal `zero_google_event_count`, `all_events_add`, or `mass_change_guard` behavior. Those codes are retained as explicit provenance and are accepted only by the dedicated bootstrap eligibility policy.

Bootstrap eligibility requires a complete, empty, non-Production Test prewrite snapshot and exactly one valid synthetic all-day Source event. The UID must use the reserved `.invalid` domain, the summary and profile must clearly identify a Test purpose, and every update, delete, unmanaged, ambiguous, duplicate, invalid, nonempty, recurring, timed, or Production shape is rejected.

Trusted Baseline is unnecessary only for this first add to an empty Test Calendar. The Bootstrap Plan is non-executable and produces a distinct add-only private Run Spec after independent integrity checks. It cannot contain update or delete operations and cannot reach `events.patch`.

After the first add is separately approved and verified in a later stage, the bootstrap path is no longer eligible because the Test Calendar is nonempty. The next step is to build and explicitly trust a normal Test baseline from the matching Source 1 / Google 1 state. Production targets never enter bootstrap planning, and Phase 5C.0 performs no Google API call.

## Test-only single-update planning

The normal Sync Plan and Test Single Update Plan are separate artifacts. A one-event Test Calendar with one update remains blocked by the normal `all_events_update` and `mass_change_guard` policies. Phase 5D.0 does not weaken, suppress, or override those guards. Its dedicated non-executable Plan independently verifies the canonical diff and retains exactly those two codes as original guard evidence.

Eligibility is deliberately narrow: one non-Production Test target, one complete current snapshot event, one valid synthetic Source event, and one trusted baseline that owns the same UID. The sole changed source-managed field must be `description`. Zero or multiple events, summary or date changes, add, delete, unmanaged or ambiguous identities, recurrence, timed events, missing event ID or ETag, unknown guards, and every Production shape are rejected.

The baseline remains ownership evidence and never stores Google event ID or ETag. The dedicated private Run Spec resolves both values from the current verified snapshot and binds the target, source, snapshot, trusted baseline, and single-update Plan hashes. It is fixed to add 0 / update 1 / delete 0 and can reach only the existing `events.patch` path. The public Plan and inspection output contain no raw UID, event text, Calendar ID, event ID, ETag, payload, endpoint, or local path.

The Plan is not executable. A later patch still requires the exact Test-only approval phrase, a fresh `events.get`, an exact non-wildcard `If-Match`, `sendUpdates="none"`, at most one mutation attempt, zero mutation retries, and post-patch read-back. Phase 5D.0 uses only synthetic inputs and mock transport and performs no OAuth flow or Google Calendar API call.

## Narrow Google adapter

The adapter surface is limited to `events.list`, `events.get`, `events.import`, and `events.patch`. Construction requires the fully validated Test target config, stores that target privately, and every operation uses only its Calendar identity; operation methods accept no per-call Calendar ID. The runner verifies that the approved Run Spec target matches the client binding before the first API call and again immediately before mutation. A generic Google service is not exposed to application code. There is no insert, full update, delete, move, watch, clear, ACL, CalendarList, Calendars, or batch method.

Add uses `events.import` so the source UID remains the Google `iCalUID`. The payload allowlist is `iCalUID`, `summary`, `description`, all-day `start.date`, exclusive `end.date`, and `eventType=default`. A fresh list preflight must find no matching `iCalUID`; the imported event is then read back with `events.get` and compared exactly.

Update uses `events.patch` with only changed source-managed fields. Date changes carry a valid all-day start/end pair. A fresh `events.get` supplies the exact event ID and ETag; the patch sends that ETag as `If-Match` and sets `sendUpdates="none"`. `If-Match: *` is forbidden.

## Retry, uncertain outcomes, and verification

Read-only list/get calls may use the existing bounded read retry policy. Import and patch have a maximum of one mutation attempt and zero mutation retries.

When an import response is lost, the runner performs an `iCalUID` lookup instead of a second import. When a patch response is lost, it reads the event instead of issuing a second patch. Exact desired state can be classified as recovered success; missing, duplicate, incompatible, or mismatched state stops the run as uncertain. HTTP 412 is an ETag conflict and is never retried.

Every successful mutation requires post-write read-back. A mismatch stops the run. The tool performs no automatic delete, rollback, reapply, or batch operation.

## Storage and public output

Test target config, credentials, Test write token, snapshot, trusted Test baseline, plan, run spec, journal, report, and receipt belong outside the repository. Writes are no-overwrite and atomic.

The private run spec may temporarily hold raw source and Google identity needed for the one operation. The journal and public report contain only safe target/UID references, hashes, allowlisted state, and counters. They exclude Calendar ID, raw UID, Google event ID, ETag, summary, description, payload, endpoint, token, credentials, and absolute paths.
