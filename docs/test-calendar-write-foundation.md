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

## Narrow Google adapter

The adapter surface is limited to `events.list`, `events.get`, `events.import`, and `events.patch`. A generic Google service is not exposed to application code. There is no insert, full update, delete, move, watch, clear, ACL, CalendarList, Calendars, or batch method.

Add uses `events.import` so the source UID remains the Google `iCalUID`. The payload allowlist is `iCalUID`, `summary`, `description`, all-day `start.date`, exclusive `end.date`, and `eventType=default`. A fresh list preflight must find no matching `iCalUID`; the imported event is then read back with `events.get` and compared exactly.

Update uses `events.patch` with only changed source-managed fields. Date changes carry a valid all-day start/end pair. A fresh `events.get` supplies the exact event ID and ETag; the patch sends that ETag as `If-Match` and sets `sendUpdates="none"`. `If-Match: *` is forbidden.

## Retry, uncertain outcomes, and verification

Read-only list/get calls may use the existing bounded read retry policy. Import and patch have a maximum of one mutation attempt and zero mutation retries.

When an import response is lost, the runner performs an `iCalUID` lookup instead of a second import. When a patch response is lost, it reads the event instead of issuing a second patch. Exact desired state can be classified as recovered success; missing, duplicate, incompatible, or mismatched state stops the run as uncertain. HTTP 412 is an ETag conflict and is never retried.

Every successful mutation requires post-write read-back. A mismatch stops the run. The tool performs no automatic delete, rollback, reapply, or batch operation.

## Storage and public output

Test target config, credentials, Test write token, snapshot, trusted Test baseline, plan, run spec, journal, report, and receipt belong outside the repository. Writes are no-overwrite and atomic.

The private run spec may temporarily hold raw source and Google identity needed for the one operation. The journal and public report contain only safe target/UID references, hashes, allowlisted state, and counters. They exclude Calendar ID, raw UID, Google event ID, ETag, summary, description, payload, endpoint, token, credentials, and absolute paths.
