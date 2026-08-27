# Production single-update planning foundation

## Scope and authority boundary

Phase 6B is an offline planning and inspection layer. It can describe one candidate Description update on an explicitly configured Production Calendar, but it cannot authorize or perform that update. The phase adds no OAuth flow, token loader, Google client, mutation request, approval receipt, journal, rollback, retry, or automation path.

The Production Plan and Run Spec are distinct artifact types. They are not accepted by the Test write dispatcher, normal apply bundle, fake simulation, or any generic apply/execute command. Existing Production hard locks remain in force.

## Accepted Production Source Manifest

`AcceptedProductionSourceManifest` is the provenance root for current source bytes. It is closed, immutable, and content-addressed. A valid manifest has:

- `production=true`, `acceptance_state=accepted`, and `synthetic=false`;
- an explicit repository identity, accepted tag, peeled commit, and ICS SHA-256;
- the exact Accepted profile ID and canonical source-content hash;
- nonzero event count, exact first/last dates, and coherent all-day/timed/recurring aggregates; and
- a domain-separated manifest hash over every field except that hash itself.

The builder independently verifies the Accepted profile and `SourceCalendarInspection`. Source bytes must match the profile SHA, validation must be exactly clean, aggregates and canonical content hash must match, every UID must be present and unique, and `.invalid`, Test, or synthetic identity markers are rejected. Pins are supplied by the manifest and profile; code contains no hardcoded current Production tag, commit, ICS SHA, target fingerprint, or event-count constant.

The private manifest stores full provenance. Its Human/JSON inspection report emits only safe `R-`, `A-`, `C-`, `I-`, `P-`, `S-`, and `M-` references plus aggregate counts and dates.

## Exact Production target

Planning requires a repository-external `ProductionWriteTargetConfig` with environment and label `production`, purpose `production_calendar_single_update`, owner access, and `Asia/Tokyo`. The explicit Calendar ID must hash to the configured target fingerprint. The `primary` alias and Test/synthetic target markers are rejected.

The target config is private. Public artifacts carry only its domain-separated config hash, target fingerprint internally where required for binding, and a short `T-` reference for inspection.

## Baseline and full-snapshot freshness

The Trusted Baseline remains ownership evidence. It must be in `trusted` state, pass its content hash, bind the same target, contain the exact sorted UID inventory, and have counts equal to the Accepted source and full snapshot.

The supplied sanitized Google snapshot must be complete, have collection metadata, contain at least two events, and have zero cancelled, unknown-type, dropped-property, and forbidden-field counters. Its content hash must exactly equal the baseline snapshot hash. Any change anywhere in the calendar—including an unrelated event's content or ETag—makes the snapshot stale and stops planning.

This deliberately separates two facts:

- one managed event differs because the newly Accepted source requests a Description change; and
- the observed Google pre-image is still exactly the full calendar state that was trusted.

## Plan eligibility

The canonical trusted-baseline diff is always recomputed. A caller-supplied diff is only comparison evidence and must have the same hash. Eligibility requires all of the following:

- source, snapshot, baseline, target, and manifest counts are equal and at least two;
- exactly one event is `update` and every other event is `unchanged`;
- add, delete candidate, duplicate Source UID, duplicate Google `iCalUID`, ambiguous, unmanaged, invalid, and fatal counts are zero;
- warnings are empty;
- the sole changed field is `description`; and
- the selected Source UID and Google safe event reference each resolve exactly once to compatible all-day, non-recurring, default events.

Zero updates, two or more updates, add, delete, summary/date changes, missing identity, synthetic data, and unrelated snapshot drift all fail closed. There is no mass-change override: the dedicated policy accepts exactly one update only when at least one unrelated event remains unchanged.

`ProductionSingleUpdatePlan` is `review_required`, `executable=false`, and fixed to operation 1 / add 0 / update 1 / delete 0. It records only safe references, aggregate provenance, canonical pre-image hash, Description patch hash, and domain-separated artifact hashes. It contains no raw UID, event text, Calendar ID, Google event ID, ETag, request payload, endpoint, or HTTP method.

## Short-lived Run Spec

`ProductionSingleUpdateRunSpec` independently revalidates and binds the manifest, current source/profile, trusted baseline, full snapshot, target config, and exact Production Plan. Its issued and expiry timestamps are UTC-aware. The lifetime must be positive and no greater than 86,400 seconds, and verification requires:

```text
issued_at <= now < expires_at
```

The boundary is fail closed: a Run Spec is invalid at exactly `expires_at`. Clock rollback before `issued_at`, naive timestamps, extended lifetime, and any rehashed policy change are rejected.

Parse/load are fail-safe by default and require the Run Spec to be current. Historical inspection remains possible only through an explicit inspection-only call with `require_current=false`; reports then label the temporal state as `not_yet_valid`, `current`, or `expired`. Approval and execution consumers must never opt out of current verification. Rendering or writing a newly actionable Run Spec also requires it to be current.

The Run Spec carries the safe UID reference, canonical pre-image hash, Description patch hash, fixed counts, and all cross-artifact hashes needed for a later stage. It deliberately contains no raw UID, SUMMARY, DESCRIPTION, current/desired managed state, Calendar ID, Google event ID, or ETag. A future online phase must reload and revalidate the source and fresh snapshot, resolve content and Google identity in memory, obtain a fresh ETag, and require exact `If-Match` immediately before its sole mutation attempt.

## Approval material

Phase 6B calculates deterministic approval material; it does not create a consumable approval receipt. The material binds every Run Spec field except `approval_material_hash` itself. This includes the finalized `run_spec_content_hash`, target, manifest, baseline, source, snapshot, diff, Plan, pre-image, patch, counts, operation and operation hash, issued time, and expiry time. A change to any approved bit must change the approval-material hash.

This hash is necessary but not sufficient authority. Replay prevention, nonce issuance, atomic receipt consumption, operator confirmation, credential identity, and online freshness checks belong to the later execution phase.

## Static and dynamic fail-closed mapping

Phase 6B enforces 10 static/offline invariant groups:

1. strict schemas and canonical I/O;
2. manifest/source/profile provenance;
3. exact Production target identity;
4. trusted-baseline state, content, ownership, and full-snapshot hash;
5. full-snapshot safety counters and complete aggregate equality;
6. canonical one-update/remaining-unchanged diff;
7. Description-only field policy;
8. Plan, Run Spec, operation, pre-image, patch, and approval-material hashes;
9. exact cross-artifact bindings; and
10. Run Spec issuance, maximum lifetime, and expiry.

The following 15 dynamic invariant groups are intentionally not claimed by Phase 6B:

1. dedicated credential identity and exact write scope;
2. a fresh online complete full snapshot within a bounded API budget;
3. exact and stable remote summary, owner role, and timezone metadata;
4. fresh full-snapshot equality with the approved pre-image;
5. exactly one live `iCalUID` match with no duplicate or ambiguity;
6. exact immediate Google event ID;
7. exact immediate `iCalUID`;
8. exact immediate managed pre-image and compatible event shape;
9. exact non-wildcard immediate ETag;
10. one Description-only PATCH with exact `If-Match` and zero mutation retries;
11. terminal HTTP 412 plus bounded pre-mutation 429/5xx handling;
12. response-loss evidence read without a second PATCH;
13. exact post-PATCH readback with a nonempty new ETag;
14. a complete safe postwrite full snapshot; and
15. canonical postwrite zero diff, one-time approval consumption, and a consistent mutation journal/result lifecycle.

Until a later phase implements all 15, Production mutation remains unavailable.

## Failure ownership matrix

| Failure class | Phase 6B behavior | Later online requirement |
|---|---|---|
| Manifest/source/profile mismatch, synthetic marker, reserved UID domain | Reject before Plan | None; repair and rebuild Accepted provenance |
| Candidate/tampered/wrong-target baseline | Reject before Plan | None; supply an exact trusted baseline |
| Incomplete/tampered/full-snapshot drift, including an unrelated event | Reject before Plan | Capture a new full snapshot and repeat trust/review |
| Update count 0 or greater than 1; add; delete; unsupported field | Reject before Plan | No override in this phase |
| Duplicate UID, duplicate Google `iCalUID`, ambiguous/unmanaged event | Reject before Plan | Manual read-only reconciliation |
| Plan/Run Spec/schema/hash/binding tamper | Reject before any client | Rebuild canonical artifacts |
| Not-yet-valid or expired Run Spec | Reject by default loader/verifier | Issue a new Run Spec; inspection-only loading cannot revive it |
| Approval-material bit change | Hash changes; stale material fails verification | New one-time approval receipt required |
| Wrong credential, wrong scope, live target/identity/pre-image/ETag mismatch | No credential/client exists | Future online preflight must stop before mutation |
| HTTP 412, pre-mutation 429/5xx | No request exists | Future bounded fail-closed transport |
| PATCH response loss or readback mismatch | No request exists | One evidence read, no second PATCH or rollback |
| Postwrite snapshot or zero-diff failure | No request exists | Stop as incomplete/uncertain; no compensating mutation |

## Storage and public output

Manifest, target config, Accepted source, snapshot, baseline, Plan, and Run Spec belong outside the repository. Loaders reject unsafe paths; writers are private, atomic, and no-overwrite. Inspection reports expose only safe references, counts, dates, lifetime metadata, states, and hashes. They exclude raw UID, SUMMARY, DESCRIPTION, Calendar ID, Google event ID, ETag, payload, endpoint, token, credential, absolute path, and full private provenance.

CI uses only generated, neutral, production-like fixtures with arbitrary internally coherent pins. It does not load the current Accepted asset, current Production target, operational baseline/snapshot, token, or credentials, and it performs no network call.
