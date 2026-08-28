# Production single-update transport foundation

## Phase 6B to Phase 6C boundary

Phase 6B ends at a non-executable, Description-only Production Plan and Run Spec. Phase 6C adds the execution semantics needed to test that design, but only behind injected deterministic fake transports and synthetic production-like fixtures. It does not add a Google credential loader, OAuth flow, token file, Google SDK client builder, live Production target loader, or network-capable implementation.

The existing Production write hard lock remains authoritative. Phase 6C models what a future Production single update must prove; it does not make a Production update operational. There is no generic apply, execute, or sync alias and no live mode.

## Capability boundary

Application code receives three narrow capabilities rather than a generic Google service:

- a full-snapshot reader that exposes only the logical `events.list` operation;
- a fresh-event reader that exposes only the logical `events.get` operation; and
- a single-update mutator that exposes only Description `events.patch` semantics.

Fake and scripted failure-injection adapters implement these protocols. `events.import`, `events.insert`, full `events.update`, `events.delete`, move, watch, clear, ACL, CalendarList write, and batch write are unavailable. A future real adapter is deferred to Phase 6D and must undergo a separate security review.

## Approval state machine

Phase 6C models a two-stage chain:

```text
Run Spec + approval material
  -> ARM challenge
  -> short-lived ARM receipt
  -> EXECUTE challenge
  -> one-time EXECUTE permit
  -> atomic consume before the first API call
```

The ARM receipt is valid for at most 600 seconds and cannot outlive the Run Spec. The EXECUTE permit cannot outlive either the ARM receipt or Run Spec. Both artifacts bind the target, Run Spec, Plan, Accepted Manifest, Accepted Source SHA, Trusted Baseline, snapshot, operation counts, changed field, patch hash, nonces, kill-switch generation, and opaque write-token generation. Challenges are exact, case-sensitive, and whitespace-sensitive.

The permit is consumed atomically before the first list intent. Consumption is one-time and remains consumed after success, drift, ETag conflict, transport failure, uncertain outcome, or verification failure. Replay requires a new ARM and EXECUTE cycle. Repository paths, symlink paths, overwrite, tampering, and concurrent double consumption are rejected.

Phase 6C creates no operational Production approval artifact. Models and tests use synthetic fixtures only.

## Kill switch and token generation

The Production kill switch defaults to `off`. A mock run requires an explicit synthetic `on` state and exact equality among the generation bound at ARM, the generation bound at EXECUTE, and the generation observed at execution. The switch is rechecked immediately before patch. A changed generation, wrong target, or `off` state stops the run.

The write-token generation is an opaque nonsecret integer binding. No token path, token value, OAuth client, or credential identity is present. Exact generation equality is testable now; real three-token separation and OAuth scope verification remain Phase 6D requirements.

## Nominal control flow and API budget

The nominal logical method sequence is:

1. complete pre-write full snapshot (`events.list`, paginated);
2. fresh target event (`events.get`);
3. Description-only mutation (`events.patch`);
4. immediate post-patch read-back (`events.get`); and
5. complete post-write full snapshot (`events.list`, paginated).

Raw API calls have a hard maximum of 10. Single-page pre/post snapshots use 5 calls, two-page snapshots use 7, and three-page snapshots use 9. Bounded retries are available only to read-only calls and may never predict or perform an eleventh call. Mutation retries are always zero.

A full-snapshot request has no time range, sync token, query, or subset filter and paginates until complete. Canonical content must bind the exact target and approved planning snapshot. Any drift—including an unrelated event—stops before patch. Incomplete pagination, target mismatch, duplicate identity, ambiguity, added event, or removed event also stops.

## Fresh pre-image and patch authority

After the exact full snapshot is accepted, the target event is resolved once in memory. A fresh get must confirm the exact event identity and iCalUID, default event type, non-cancelled and non-recurring state, all-day dates, Summary, current Description, and a nonempty fresh ETag. The managed pre-image is compared exactly with the Run Spec-bound pre-image before mutation.

The fresh event ID and ETag exist only in memory. They are never stored in the Plan, Run Spec, baseline, approval artifacts, journal, or public report.

The only mutation is `events.patch`. Its body contains exactly `description`, `sendUpdates` is fixed to `none`, and `If-Match` is the exact fresh-get ETag. Wildcard `If-Match`, a body/query ETag, stale artifact ETag, second patch, and mutation retry are forbidden. Maximum mutation attempts are 1.

HTTP 412 is terminal and causes no retry. After response loss, the only allowed evidence operation is a fresh get. An exact desired post-image can recover success; old, incompatible, ambiguous, or unreadable state yields `write_outcome_uncertain`. No uncertain path sends a second patch.

## Post-write verification and recovery policy

A successful patch requires immediate read-back of the exact desired Description while Summary, dates, identity, recurrence state, event type, and forbidden color/label fields remain safe. It then requires a complete post-write full snapshot. Pre/post comparison must contain only the intended Description change, and the updated Accepted Source fixture must produce a canonical zero diff against the post snapshot.

Verification failure does not cause rollback, delete, cleanup, or a second patch. The run stops for manual review. A successful mock result marks baseline renewal required, but Phase 6C neither creates nor trusts a new Production baseline automatically.

## Write-ahead journal and public report

The Production execution journal is a repository-external append-only NDJSON file. It is created without overwrite, appends exactly one hash-chained entry at a time, and fsyncs every safety entry. The `mutation_intent` entry records mutation attempt 1 and is durable before patch. Sequence, UTC timestamp, phase, previous hash, entry hash, aggregate hash, monotonic API/retry/mutation counts, approval consumption, and switch/token generations are verified.

Journal load and append use an OS-owned cross-process file lock. A reader takes a shared lock; an appender takes an exclusive lock, then re-reads and revalidates the complete chain from the locked descriptor before comparing the expected prior hash, appending one record, and fsyncing. The pre-fix security candidate was a time-of-check/time-of-use window in which two processes could validate the same prefix and both report append success. The locked transaction closes that window: exactly one contender can append, the next observes a stale prefix and cannot proceed toward patch. Locks belong to the open descriptor, so process crash releases them automatically and leaves no stale lock file or bypass state.

The closed phases are `run_start`, `approval_validated`, `execute_permit_consumed`, `kill_switch_verified`, `pre_snapshot_intent`, `pre_snapshot_verified`, `fresh_get_intent`, `pre_image_verified`, `mutation_intent`, `mutation_result`, `readback_intent`, `readback_verified`, `post_snapshot_intent`, `post_snapshot_verified`, `zero_diff_verified`, and `terminal_result`. Reordering, removal, truncation, tampering, forged success, mutation without durable intent, and API before consumption are rejected.

An append or fsync failure is itself fail closed: orchestration raises a content-free journal error and performs no later API call, second patch, rollback, or delete. If durable storage fails after the one patch attempt, the file intentionally remains nonterminal and therefore fails terminal verification; it must be treated as an interrupted run requiring manual review. The process must not forge an in-memory or rewritten terminal record when the append-only evidence sink is unavailable.

Phase 6D must keep the approval/consumption store, journal/report evidence store, and Production credential/token store in separate repository-external roots with owner-only ACL validation. Possession or writability of the evidence directory must not grant token access, and token-directory access must not permit approval-ledger replacement. Store identity and ACL checks are a live-environment gate, not authority inferred from Phase 6C paths.

The public report is bound to the verified terminal journal hash. It contains safe target/Run Spec/Plan references, approval state, permit consumption, fixed operation counts, changed field name, patch hash, counters, verification flags, baseline-renewal requirement, safe findings, terminal state, journal hash, and report hash. The journal and report exclude Calendar ID, raw UID, Google event ID, ETag, Summary, Description content, token, credentials, Authorization header, request URL/body, and absolute path.

## Static and dynamic invariants

The Phase 6A static map is updated as follows. These are code-shape and mock-runtime invariants; none claims live Google acceptance.

| Static invariant | Phase 6C enforcement | Test evidence |
|---|---|---|
| PATCH only | `ProductionSingleUpdateMutator.patch_description` is the sole mutation capability | transport capability and patch-contract tests |
| Add / Delete unavailable | operation/add/update/delete remain `1/0/1/0`; no import/insert/update/delete facade | capability and source audit tests |
| One mutation | counter maximum 1 and one durable `mutation_intent` | transport and journal lifecycle tests |
| Mutation retry 0 | model/schema literal 0; uncertain and 412 paths never call patch twice | conflict/uncertain tests |
| Exact `If-Match` | fresh non-wildcard ETag is the only patch authority | patch/ETag boundary tests |
| Fresh get | full snapshot is followed by a fresh-event capability call | nominal/pre-image tests |
| Pre-write full snapshot | closed unfiltered request plus complete pagination | request-shape, pagination, drift tests |
| Post-write full snapshot | read-back is followed by a second complete collection | post-snapshot tests |
| Approval consumption | durable one-time permit consumption precedes first list intent | approval I/O, replay, journal ordering tests |
| Kill-switch generation | ARM, EXECUTE, execution-start, and pre-patch generations must match | switch-state/generation tests |
| Token generation | opaque nonsecret generation must match ARM, EXECUTE, and execution | token-generation tests |
| API hard cap | a raw-call counter refuses a predicted eleventh call | 5/7/9/10-call boundary tests |
| Journal integrity | header-rooted append-only chain, cross-process locked revalidation, fsync, closed safe codes, required terminal topology | concurrent append/crash-release and tamper/truncation/forgery tests |
| Live hard-off | no credential/client factory or live CLI; explicit live gate raises a fixed safe code | capability, dependency, and network audits |

The 15 dynamic groups deferred by Phase 6B now map explicitly to Phase 6C evidence:

| Phase 6B dynamic group | Phase 6C status | Remaining Phase 6D/6E gate |
|---:|---|---|
| 1. Dedicated credential identity and exact scope | generation-only contract; no secret accepted | verify three real token identities and exact scope |
| 2. Fresh complete snapshot and bounded budget | enforced by fake paginated full-snapshot reader and call cap | confirm real pagination/API accounting |
| 3. Stable target metadata | owner/timezone/target binding enforced in pages | verify live Calendar identity, owner role, timezone, and metadata |
| 4. Full-snapshot equality | exact canonical planning hash required | repeat with fresh live collection |
| 5. One `iCalUID` match | exact single in-memory resolution; duplicate/ambiguity rejected | verify live response behavior |
| 6. Fresh event ID | resolved only from fresh in-memory snapshot/get flow | verify live event identity |
| 7. Fresh `iCalUID` | exact fresh-get identity comparison | verify live event representation |
| 8. Exact managed pre-image | Summary, Description, dates, status, event type, recurrence compared | verify live projection fidelity |
| 9. Fresh non-wildcard ETag | required in memory and exact at patch boundary | verify live header behavior |
| 10. One Description PATCH, retry 0 | enforced by least-capability mutator and counters | execute one separately approved live call |
| 11. 412 and bounded read failures | mock 412 terminal; read-only retry only under cap | characterize actual Google failures |
| 12. Response-loss evidence read | one get, second patch 0 | confirm real response-loss handling |
| 13. Exact post-PATCH read-back | enforced over full managed shape | confirm live read-after-write consistency |
| 14. Complete post-write snapshot | enforced with same target/structure rules | confirm live collection behavior |
| 15. Zero diff, one-time approval, journal lifecycle | enforced by canonical diff, atomic ledger, and header-rooted journal/report | explicit live human approval and baseline renewal |

## Fail-closed matrix traceability

| Condition | Safe outcome/code family | Phase 6C evidence |
|---|---|---|
| Approval mismatch | `production_*_binding_mismatch` / failed approval | approval binding mutation tests |
| Approval replay | `production_execute_permit_already_consumed`; API 0 | replay and atomic-consume tests |
| Expired approval | `production_arm_expired` or `production_execute_permit_expired`; API 0 | injectable-clock tests |
| Switch off | `production_kill_switch_off`; API 0 | switch tests |
| Switch generation mismatch | `production_kill_switch_generation_mismatch`; patch 0 | start/pre-patch recheck tests |
| Token generation mismatch | `production_write_token_generation_mismatch`; API/patch 0 | token-generation tests |
| Pre-snapshot drift | `production_full_snapshot_drift`; patch 0 | relevant/unrelated/add/remove drift tests |
| Incomplete snapshot | `production_full_snapshot_incomplete`; patch 0 | pagination completion tests |
| Target mismatch | `production_full_snapshot_target_mismatch`; patch 0 | target/access/timezone tests |
| Pre-image mismatch | `production_pre_image_mismatch`; patch 0 | field mutation matrix |
| ETag missing/mismatch | pre-image or patch-contract failure; patch 0 | ETag tests |
| HTTP 412 | `etag_conflict`; attempt 1, retry 0 | conflict test |
| Patch failure | `failed_transport`; second patch 0 | scripted failure tests |
| Uncertain outcome | recovered success or `write_outcome_uncertain`; evidence get only | response-loss tests |
| Read-back mismatch | `failed_readback`; rollback/second patch 0 | read-back matrix |
| Post-snapshot drift | `failed_post_snapshot`; rollback/second patch 0 | post-collection matrix |
| Zero-diff failure | `failed_zero_diff`; baseline auto-trust 0 | canonical diff matrix |
| API budget exceeded | `api_call_limit_exceeded`; predicted 11th call not issued | boundary tests |
| Journal tamper or append failure | content-free journal error; no later API; nonterminal evidence rejected | header/entry tamper, truncation, and append-failure tests |

The following remain dynamic Phase 6D/6E gates:

- real OAuth scope and the separate Production read, Test write, and Production write token identities;
- live Calendar target identity, access role, and timezone;
- actual Google list/get/patch behavior and pagination;
- real network rate-limit, server-failure, response-loss, and concurrency characteristics; and
- a naturally occurring legitimate Description-only Production change with explicit user approval.

Until those gates complete, Production OAuth, token creation, Calendar access, API calls, Add, Delete, rollback, and event changes remain unavailable.
