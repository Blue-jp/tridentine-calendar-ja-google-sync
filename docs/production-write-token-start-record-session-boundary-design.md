# START-Record Boundary Before Credential-Session Reentry

Status: DRAFT_DESIGN_NOT_IMPLEMENTED_NOT_OPERATIONAL_APPROVAL

## 1. Scope and evidence

This design uses HEAD 385b770a051c56c2aa54520e72255231877ee9a6, tree 41b65e26515dec6489ce82362295221d0304df9a. CURRENT_SOURCE means that implementation; CURRENT_TEST means definitions read here, not newly executed tests. HISTORICAL_DESIGN identifies earlier proposals; PROPOSED_ACCEPTANCE identifies this document's future test contract; OPEN_DECISION identifies unresolved operational/interface choices.

INHERITED_CI: the supplied record reports run 38405020184, attempt 1, pull_request, eight successful jobs, checked on 2026-10-13 JST. Both base jobs ran the three reentry cases without skips. Ubuntu/Python 3.12.15 reported 5152 collected, 4548 passed, 37 skipped, 567 deselected; Windows/Python 3.12.10 reported 5152 collected, 4132 passed, 453 skipped, 567 deselected. Each selected 4585; no failures/errors were reported. File progress and summaries are not individual passing-node lists; the other six jobs have job/step evidence only. This was not reacquired here and does not validate the proposed composition.

The [Gap review], sections D/E, retains the earlier local 306 collected / 220 passed / 75 failed / 11 skipped, exit 1, and VALIDATION_ROOT_UNAVAILABLE. The 75 individual causes remain unresolved. Those records are not rewritten. Original DS-04 text and formal closure criteria remain unavailable; this is not a finding-level closure assessment.

HISTORICAL_DESIGN references also include the [Operation design] and [Reuse design]. Their proposed session enforcement remains distinct from the implemented components.

## 2. What START establishes

The following claims are separate; none automatically grants the next:

| Claim | Meaning in this design |
| --- | --- |
| 1. Independent binding and operation supplied | Fixture setup declares expected values; their authenticity is not established by equality. |
| 2. START attempt confirmed | The public create call completed its bounded publication/readback/checkpoint and owner-exit contract. |
| 3. Later incomplete START observed | A new read matched independently supplied expectations against started/incomplete bytes. |
| 4. Later session entry refused | Proposed test-owned control stops before invoking the public mock-session API. This is not current global enforcement. |
| 5. Credential use approved | Out of scope and never established. |

CURRENT_SOURCE: [Record] 50-84 defines SyntheticBinding, RecordOperation and nonauthorizing RecordResult. Binding supplies directory, storage_ref, pair_ref, token_slot and state_slot. RecordOperation supplies operation_id, predecessor_id and kind. Validation 135-156 requires NEW_PAIR's predecessor to be None; REFRESH requires a valid non-null predecessor distinct from operation_id. The proposed REFRESH fixture must declare that predecessor independently. Its existence, completion and authentic chronology are not proved.

Wire fields at [Record] 159-173 always say phase=started and outcome=incomplete. They contain neither token generation, later persistence-error details nor normal-completion evidence. Matching uses supplied expectations at 209-234. Never extract an operation ID or predecessor from observed START, or derive it from current token generation. Equal IDs or identical bytes do not authorize repeat execution; even identical occupied slots reject creation.

The directory selects the record location; slot/reference labels do not prove physical binding to live token/state files. Independent fixture setup supplies the intended association. Missing START proves neither absence of earlier failures nor complete history or permission for initial adoption.

[Policy] 73-92 uses different SyntheticBinding/OperationDefinition types and an independent generation_ref. Its predecessor rules at 163-173 and 254-313 differ from the record API's REFRESH requirement. No adapter is implied. evaluate_reuse_policy at 316-395 remains separate; False, transitions_valid=True and normal return are never continuation permits.

## 3. First, explicitly prepared synthetic trial

PROPOSED_ACCEPTANCE: option A below uses a new test-owned fixture under explicit later test authorization. It is neither operational enrollment nor automatic adoption of existing credentials. A known-fresh fixture is a setup fact; an absent record during ordinary reentry is not equivalent.

| Order | Action | Bound and stopping rule |
| --- | --- | --- |
| 1 | Declare binding, REFRESH operation/predecessor, fixed time, target and memory credential pair independently | No observations manufacture expectations. No credential content read yet. |
| 2 | Invoke real public create_start_record | At most one API call and one publisher attempt; unchanged fixed slot/schema. |
| 3 | Observe its public return after scope exit | Require genuine START_CONFIRMED and reuse_authorized is False. Every other result stops before session invocation. |
| 4 | Finish record ownership before proceeding | Preserve the visible unlocked gap; do not retain or borrow its private scope. |
| 5 | Run the separately authorized synthetic experiment through the real public mock-session API | At most one invocation, one fake refresh and one fake save; real pure validation/rendering retained. |
| 6 | Observe publication-then-save-error or normal-return control | Keep the session outcome and retained START as different evidence. No automatic retry, cleanup or alternate slot. |

START_CONFIRMED is a necessary record checkpoint for the prepared experiment, not its authority. Authorization comes from the explicit test scope and controlled fixture, not conversion of RecordResult into a permit.

The failure scenario retains the fake writer's memory update and ProductionWriteTokenRefreshPersistenceError separately from the unchanged START. A later reader cannot infer that specific exception from START. A normal-return control also leaves started/incomplete; its later request must still stop. Successful repeated operation, normal closure and record retirement are deliberately unfinished.

Creation uncertainty also stops immediately. [Record] 237-245 and 603-627 preserve PERSISTENCE_UNCERTAIN after publisher entry, including False or unknown publication evidence. Non-Exception cancellation propagates rather than becoming confirmation. Existing first-failure/cancellation/exit rules at 459-516 remain authoritative: cleanup must not produce apparent success. No failure handler recreates, deletes or relocates the slot.

## 4. A distinct subsequent request

PROPOSED_ACCEPTANCE: reconstruct a new request from independent setup input, without the first exception, previous decision or a remembered success flag. With usable independent expectations, invoke real read_start_record at most once and preserve its actual result. Without them, stop before even that comparison. Ordinary reentry never invokes create_start_record.

| Later situation / fixture fact | Existing public observation | Proposed boundary action |
| --- | --- | --- |
| Matching incomplete START | START_OBSERVED | Retain observation; stop before mock-session invocation. |
| Different target/binding or operation | UNVERIFIABLE on comparison failure | Stop; never substitute observed identities. |
| Occupied but contents cannot be verified | Read may return UNVERIFIABLE; SLOT_OCCUPIED belongs to create only | Stop; do not call create to classify or bypass occupancy. |
| Malformed or unreadable record | UNVERIFIABLE | Stop; no repair, fallback parser or guessed completion. |
| Lock busy / unavailable | LOCK_BUSY / LOCK_UNAVAILABLE | Stop without waiting, retry or unlocked continuation. |
| Unsupported platform | UNSUPPORTED_PLATFORM | Stop; no Linux emulation reported as native support. |
| Record absent | UNVERIFIABLE | Stop; no initial-use or clean-history inference. |
| Independent expected operation absent | No record call; no new runtime enum claimed | Stop at the test-side input precondition. |

CURRENT_SOURCE: [Record] 614-627 and 653-699 deliberately collapse absent, foreign, malformed and unreadable cases; there are no separate current ABSENT or MISMATCH states. [Record tests] 563-586 exercise this collapse. SLOT_OCCUPIED at 591-597 is a create-path presence observation, not authenticated content. The table preserves these limits rather than inventing finer persisted causes.

Later mock-session calls, credential path checks, token/state reads, refreshes, saves, session-lock entries and session returns must all be zero. Record acquisition/read/checkpoint/exit I/O is counted separately; total I/O is not zero. A read's publication_possible=False concerns that read only and cannot cancel earlier publication uncertainty or failure.

An always-refusing stub is insufficient evidence. Require real record calls, actual state-dependent observations, a positive first-trial session invocation, and contrasting record fixtures. Neither public record API nor the public session API may be replaced with a canned result. Any previously retained START_CONFIRMED result is inadmissible as a later-request permit.

## 5. Ownership comparison

CURRENT_SOURCE: public create_start_record/read_start_record at [Record] 690/696 each enter their own scope through 653-664. Record lock acquisition is at 412-414; public success is mapped only after successful exit at 682-686.

The private _record_scope (519), _create_start_record_held (637) and _read_start_record_held (645) now exist. They supply owned record checkpoints, not borrowed locks. Checks at 352-370 and 547-570 bind issuance, process/thread, lifecycle and complete binding/operation/revision snapshots; initial-entry failure is terminal. No external lock/descriptor/acquired flag is accepted.

[Token] 125-179 independently owns sorted distinct lexical token/state parents, at most two. Windows 134-135 supplies a no-op checkpoint. The loader enters at 778, reads content at 781-782, and constructs either session at 790 or 883 inside its scope; delivery follows exit. It accepts no record scope. [Token I/O] 349-395 preserves call-local publication evidence; bundle checkpoints at 530-591 are not an atomic pair commit. Neither supplies a record/session ownership adapter.

| Axis | A: finish public record call, then public mock session | B: continuous combined ownership |
| --- | --- | --- |
| Current public interfaces | Sufficient for controlled test ordering | No shared-owner/session participation contract |
| Release and reacquisition | Record lock ends first; same-directory native use would reacquire sequentially | Nesting overlapping public acquisitions reacquires rather than shares |
| Existing held primitives | Not borrowed by the new test | Only operate inside their own record owner |
| Session ownership | Existing API owns its locks; candidate simulates credential lock | Needs a separately reviewed held-session/owner interface |
| Guard/source impact | Test-only public imports; no runtime or guard changes | Interface, lifetime, ordering, failure and guard review required |
| Guarantee | One fixture's observed order, assuming no concurrent mutation | Not established by current APIs |

Do not hold a session lock while calling public record APIs, or wrap the public session API in a record scope and call that shared ownership. [Record tests] 637-642 shows overlapping outer locking yields LOCK_BUSY. Different directories do not automatically establish correct multi-lock order or physical pair binding.

HISTORICAL_DESIGN: [Enrollment/lock design] sections 1-8 predate implemented private scope sections 9-10. Their old “not implemented” descriptions do not erase current held primitives. Conversely, those primitives do not implement a session coordinator.

## 6. One next candidate and acceptance

Recommend one future file: tests/test_token_start_record_session_boundary_phase6d1h.py, presently absent. Select option A, a bounded test-only composition. No new runtime wrapper, result envelope, parser, permission token, registry, journal, database or signing service is needed.

Use public create_start_record/read_start_record and SyntheticBinding, RecordOperation, RecordResult, RecordState, OperationKind; use prepare_production_write_rehearsal_credential_session_mock with its actual inner loader. Test-local initial-trial and subsequent-request helpers express ordering only. They do not become production entry points. Use no private held helper or existing low-level lock as borrowed authority.

Independent setup supplies all record expectations, an explicit non-null REFRESH predecessor and synthetic credential material. Use real Linux record I/O in an owned private fixture, but memory-only credential I/O. Separate these phases: do not apply the characterization's broad global I/O tripwires while real record APIs run.

Retain the five scoped credential boundaries in [Reentry test] 229-235: path-set checking, state read, token read, refreshed-token persistence and session lock. Each double checks the declared arguments and flags. Preserve actual target/confirmation, role/scope/grant evidence, identity/generation checks, rendering/comparison and session construction. Restore doubles before later real record reads. Forbidden-effect sentinels must not blanket-disable legitimate record readers or locks.

Acceptance should show:

- One real START creation completes before the first real mock API invocation. The publish-then-error trial has at most two state reads, two token reads, one fake refresh/save/publication, and no returned session. Keep the known exception and unchanged record separately.
- A small normal-return control keeps START and refuses the next request, exposing the deliberately unfinished normal lifecycle. Existing pure-validation tests remain relevant; do not reproduce the whole characterization matrix.
- Reconstructed later requests perform at most one real record read and zero mock-session/credential actions. Contrast matching START_OBSERVED with real absent, mismatched or corrupt UNVERIFIABLE observations and occupied-create refusal. Preserve existing fault tests for the broader record matrix.
- Record refusal/uncertainty, ordinary session errors and cancellation cannot trigger continuation, retry, deletion or alternate-slot use. Any focused dependency fault injection must leave public record dispatch/codec and session validation real; review injection targets before implementation.
- Use a bounded ordinary fresh Linux subprocess for one later read. Supply independently retained synthetic expectations, not record-extracted values, the first exception, a session or prior decision. Capture fixed classification and zero session-call counters. Keep child routing in the same test file; no persistent runner or pytest restart. This is not crash/power-loss durability or authentic deployment restart.
- Windows covers test-local input/order/accounting conditions and actual public record UNSUPPORTED_PLATFORM refusal before session entry. Its early platform gate does not validate the Linux record codec. Do not mock platform detection into a native-success claim. Linux real-record and fresh-process cases require separate actual execution evidence.

CURRENT_TEST guards at [Record tests] 392-415 retain three direct runtime lock consumers and four publisher consumers excluding the publisher itself. Source-only consumer scans at 418-487 allow this test-only addition without new runtime consumers. [Session-lock tests] 483-516 require the existing lexical lock interval; option A does not change it. No guard, marker, conftest, dependency or workflow changes are proposed. Future collection keeps the existing base marker condition; no execution occurs now.

## 7. Review gates and open decisions

Outcome: DESIGN_DRAFT_READY_FOR_REVIEW for A. Continuous-owner B remains an OPEN_DECISION, not a blocker requiring new runtime for this experiment.

Before implementing, review the fixture's independent predecessor/binding assumptions, exact phase separation, record-observation contrasts, cancellation handling, child-process scope and preservation of actual pure session checks. Stop if the experiment requires a new public/private interface, runtime consumer, guard relaxation, operational data, record retirement, or authority flag. Do not hide an import conflict.

Actual deployment still needs trustworthy enrollment, independent expected-operation supply, identity allocation, complete history, participating writers, physical START/token/state binding, approved OS/concurrency assumptions, normal completion and controlled reconciliation. Same-authority replacement/deletion, coherent rollback, path replacement across A's unlocked gap, nonparticipating writers and crash/power loss remain outside the demonstrated contract. [Bootstrap contract] 32-40 and 120-156, and [Entry design] 179-191 identify those owner decisions without assuming external authority infrastructure.

No suitable native validation root is presumed available. Future execution must use an explicitly permitted location accepted by unchanged guards; no renamed child below a rejected ancestor, marker/ACL/sandbox changes or new environment is authorized here. The prior exception permitting commit 34's fixed two files before local regression completion does not authorize this candidate's implementation, commit or push. Future CI must identify the new head/attempt and distinguish Linux native evidence from Windows refusals; inherited CI cannot fill that gap.

DS-04 remains PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 scan FAIL; Production gate BLOCKED; live handlers hard-off; packaged registry empty/fail-closed. PR #17 is Draft in inherited evidence. No implementation, test, record I/O, deployment, commit, push, PR change or audit update occurred.

[Record]: ../src/tridentine_calendar_google_sync/production_write_token_operation_record.py
[Token]: ../src/tridentine_calendar_google_sync/production_write_token.py
[Policy]: ../src/tridentine_calendar_google_sync/production_write_token_reuse_policy.py
[Record tests]: ../tests/test_token_operation_record_phase6d1h.py
[Session-lock tests]: ../tests/test_credential_session_lock_phase6d1h.py
[Reentry test]: ../tests/test_token_session_failure_reentry_phase6d1h.py
[Gap review]: production-write-token-enforcement-gap-review.md
[Enrollment/lock design]: production-write-token-enrollment-lock-design.md
[Bootstrap contract]: production-write-token-enrollment-bootstrap-contract.md
[Entry design]: production-write-token-disabled-bootstrap-entry-boundary-design.md
[Operation design]: production-write-token-operation-record-design.md
[Reuse design]: production-write-token-reuse-policy-model.md
[Token I/O]: ../src/tridentine_calendar_google_sync/production_write_token_io.py

## 8. Test-only composition and local validation evidence

### 8.1 Status and implemented boundary

LOCAL_IMPLEMENTATION: option A is now expressed only in
tests/test_token_start_record_session_boundary_phase6d1h.py. This section records
the later implementation and checks; the original 18,840-byte design, including
its original status, sections 1-7 and reference definitions, is preserved exactly.

Outcome: IMPLEMENTED_VALIDATION_INCOMPLETE. Windows checks passed; the new Linux
record I/O and ordinary-child cases have not been executed here. This is neither
product integration nor permission to use credentials, retire START, commit or
push these files.

The test-local _first_trial receives independently prepared binding, REFRESH
operation, memory credential pair and fake refresher, plus fresh measurement
state. It accepts no previous record result as a checkpoint. It calls the actual
public create_start_record once and retains the actual RecordResult. Only exact
RecordResult, START_CONFIRMED and reuse_authorized is False reach the separately
authorized experiment. Other observations stop before the session API.

The real public prepare_production_write_rehearsal_credential_session_mock then
reaches the real inner loader. START_CONFIRMED is a necessary ordering check for
this explicitly authorized synthetic experiment, never an execution permit.

The test-local _followup is shared by parent and child. It accepts only independent
binding/expected operation and fresh measurement state, without a first exception,
session, success flag or prior RecordResult. Missing expected operation stops
before record I/O. Otherwise it calls actual read_start_record once, retains its
RecordState and publication_possible, and stops before the session API even for
START_OBSERVED. It never creates a replacement START or infers initial-use
permission from absence. Its refusal is a test-owned contract; direct callers of
the existing session API remain outside this boundary.

### 8.2 Independent inputs, real processing and scoped doubles

The REFRESH operation and distinct non-null predecessor are declared before
observation, independently of generation. Labels assert neither authentic identity
nor predecessor existence, successful completion, trusted enrollment or complete
history. The record directory is a new test-owned private fixture on supported
Linux runs. Token/state slot labels describe fixture correspondence, not physical
binding to credential files. Credential models, target, confirmation and fixed
times come from the reviewed pure/test-only helpers. No token, state or client
configuration file is created by this composition.

Record public dispatch, codec, comparisons, lock and publisher remain real on
Linux. Transparent spies delegate exactly once and preserve returns/exceptions.
No private held scope is borrowed. The credential interval replaces only these
five I/O boundaries: token path-set validation, state loading, token loading,
refreshed-token persistence and the session lock. The refresher is injected through
the existing public mock argument. Target/confirmation, role, scope, grant
evidence, identity/generation, render comparison and session construction remain
real.

The broad memory-only I/O tripwires from the existing reentry test apply only
during that credential interval. They are restored before START snapshots or
later real record reads. Separate tripwires reject network, browser and real
credential writer paths throughout. Forbidden-effect sentinels derive from
BaseException so ordinary product Exception handlers cannot hide them.

Each first-trial audit owns a separate patch context. It is restored before a
new followup audit is installed, preventing later reads from changing the earlier
counts. Fixture directory creation, preparation creates, malformed-fixture writes,
snapshot reads, record API reads and internal record reader calls have separate
counters. Credential counters do not represent total process I/O.

The trace explicitly records the gap after the public record call has returned
and released ownership. The subsequent credential lock is simulated. This proves
neither continuous ownership nor native record/session serialization; replacement
or mutation during that gap remains outside the contract.

### 8.3 Implemented Linux assertions, not locally executed evidence

The following rows describe assertions in the saved tests. They are not local
Linux pass results or measured Linux counts.

| Scenario | Initial trial / fixture | Later request |
| --- | --- | --- |
| Publication then persistence failure | Real create 1, internal readback 1, session API 1; memory state/token reads 2 each, refresh/save/publication 1 each, session return 0; actual ProductionWriteTokenRefreshPersistenceError | New audit: real read 1 and internal reader 1; START_OBSERVED / False; session and all credential counters 0 |
| Normal unexpired control | Real create 1 and session API 1; actual session returned, refresh/save 0; START still started/incomplete | START_OBSERVED / False; no session or credential entry |
| Absent, independent different operation, initially malformed fixture | Separate controlled fixtures; mismatch preparation create counted separately; no deletion or replacement of a valid START | Actual UNVERIFIABLE / False; no cause inferred from that classification; no initial-use fallback |
| Same START already occupies slot | Fixture create 1 separately from tested create 1; actual SLOT_OCCUPIED / False; session and credential counters 0 | No recreation or automatic retry |
| Create readback OSError | Actual publisher runs; one injected readback; actual PERSISTENCE_UNCERTAIN / True; session 0 | Patch restored, independent real read observes START; earlier uncertainty is retained separately |
| Create readback cancellation | Original BaseException object propagates by identity; no normal RecordResult or session; published START retained | Separate real read observes START without converting cancellation into success |
| Fake-refresher cancellation | Real START confirmed, public mock session entered, original cancellation retained by identity; refresh attempt 1, save/publication/session return 0 | Independent read observes START and stops before session |
| Ordinary new Linux process | A single successful fixture create precedes the child; no session trial is needed | Same _followup performs real read 1; exact fixed START_OBSERVED / False and zero credential/session counts required |

The only injected record fault target is the module-local
records.read_private_sensitive_bytes reference during create readback. Each
injection checks the exact test record path and MAX_RECORD_BYTES and is called
once. It raises the fixed OSError or the original synthetic cancellation instead
of delegating to the real reader. Public record API, publisher, codec and ownership
remain real. Genuine reads after patch restoration are separate followup evidence.

The first session persistence error is retained independently of the record.
Its publication_possible is True in the publication-then-error fixture. The
later read's publication_possible=False concerns only that read and cannot cancel
the earlier failure. START does not encode that persistence exception; observing
it cannot identify the first failure's cause.

Snapshots compare bytes, mode, device/inode identity and link count, excluding
atime. Both the normal-return and failure/cancellation controls retain START as
started/incomplete. Normal completion, retirement and recovery are not supplied.

The single child uses the same test file's explicit test-only entry, current
Python executable, independently retained synthetic inputs on stdin, argument
arrays, captured stdout/stderr and a ten-second timeout. It checks that record and
session modules resolve to the current repository source. Nonzero exit, stderr,
timeout, malformed output or any mismatch fail the test; they are never counted as
safe refusal. Output contains only fixed classifications, counts, booleans and
fixed trace labels. No prior exception/session/result or record-derived ID is
passed. This is an ordinary process read, not crash, power-loss, rollback,
concurrency or authentic deployment-restart evidence.

### 8.4 Actual Windows observations

The completed local run used Windows (win32) and Python 3.12.14. Existing installed
metadata matched uv.lock for pytest 8.4.2, pytest-socket 0.8.1, Ruff 0.16.4, mypy
1.20.2 and pydantic 2.13.4; source resolution pointed to this repository's src.
No installation, synchronization, dependency change or environment rebuild occurred.

| Executed new scenario | Record creates | Record reads | Observation | Session API / credential effects |
| --- | ---: | ---: | --- | --- |
| Independent operation missing | 0 | 0 | Fixed test-local input refusal, no RecordResult | All 0 |
| Windows initial trial | 1 | 0 | Actual UNSUPPORTED_PLATFORM; publication_possible=False; reuse_authorized=False | All 0 |
| Windows followup | 0 | 1 | Actual UNSUPPORTED_PLATFORM; publication_possible=False; reuse_authorized=False | All 0 |

All three also measured zero fixture directories, preparation creates, malformed
writes, snapshots, internal record reads and injected readbacks. Windows sentinels
at record reader/lock/publisher recorded no forbidden calls. Credential path
checks, state/token reads, refresh, save, simulated publication, lock
creation/entry/checkpoints/exit and session returns were all zero. No platform
value was changed to emulate Linux.

This establishes actual early Windows refusal, not Linux codec, publication,
native locking or persistence behavior. There is no measured initial successful
START/session composition on this machine.

### 8.5 Executed commands and exact results

Pytest ran once in a captured in-memory wrapper invoked by Python -B, with the
new test first and the permitted regressions/guards following in the same process.
The equivalent pytest.main argument form was:

    -q -p no:cacheprovider --basetemp <new-dedicated-pytest-scratch>
    -m "not google_read and not google_test_write and not google_production_write"
    tests/test_token_start_record_session_boundary_phase6d1h.py
    tests/test_token_operation_record_phase6d1h.py
    tests/test_token_session_failure_reentry_phase6d1h.py
    tests/test_token_reuse_policy_phase6d1h.py
    tests/test_posix_private_lock_phase6d1h.py::test_component_has_no_artifact_write_no_wait_loop_and_only_approved_consumers
    tests/test_posix_sensitive_directory_phase6d1h.py::test_directory_foundation_only_has_the_reviewed_backend_consumers
    tests/test_no_network_or_google_dependencies.py::test_source_package_has_no_eager_network_google_or_oauth_imports

The existing strict configuration, conftest and socket prohibition were active.
The scratch leaf was new, dedicated and absent before invocation; no prior
basetemp or shared root was reused or deleted.

| Selected group | Collected | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| New common input case | 1 | 1 | 0 | 0 | 0 | 0 |
| New Windows cases | 2 | 2 | 0 | 0 | 0 | 0 |
| New Linux record/credential cases | 9 | 0 | 0 | 0 | 9 | 0 |
| New Linux ordinary-child case | 1 | 0 | 0 | 0 | 1 | 0 |
| Existing operation-record file | 387 | 331 | 0 | 0 | 56 | 0 |
| Existing memory reentry file | 3 | 3 | 0 | 0 | 0 | 0 |
| Existing pure reuse-policy file | 205 | 205 | 0 | 0 | 0 | 0 |
| Three requested guard nodes | 3 | 3 | 0 | 0 | 0 | 0 |
| Total | 611 | 545 | 0 | 0 | 66 | 0 |

Pytest exit code: 0. These are current measured counts after the final test
meaning/format changes. The 66 skips are explicit OS conditions: ten new Linux
cases and 56 existing Linux cases. Omitted files below are not included in that
skip total. The passing later regressions/guards provide same-process restoration
evidence for the executed Windows patches. Restoration of the new Linux
credential-phase doubles remains an unexecuted assertion.

Additional current checks, each exit 0:

    python -B -m ruff check . --no-cache --output-format json
    python -B -m ruff format --check . --no-cache
    python -B -m mypy --strict --no-incremental --cache-dir=nul --no-pretty src
    git --no-optional-locks -c safe.directory=<repository> diff --check

Ruff reported zero diagnostics; format check reported 282 files already formatted;
strict mypy reported no issues in 124 source files. Only the new test was formatted,
through captured stdin/output with unchanged AST; no other file was auto-fixed.
Untracked content was reviewed separately because ordinary git diff omits it.

### 8.6 Unexecuted validation and preserved history

VALIDATION_ROOT_UNAVAILABLE is inherited. No new native-private-root candidate
was provided, searched or tried. Pytest scratch availability does not establish
private-artifact fixture suitability.

The full required persistence, prewrite and credential-session-lock suites remain
unexecuted here:

- tests/test_refresh_persistence_failure_phase6d1h.py
- tests/test_refresh_prewrite_recheck_phase6d1h.py
- tests/test_credential_session_lock_phase6d1h.py

Their real private I/O was not retried below the previously rejected ancestry.
They have no assigned local collected/pass/skip counts in this section. The new
Linux cases and child need execution on a separately permitted, guard-compatible
native Linux environment, followed by the complete seven-file regression set and
three requested guards. No guard, marker, ACL, .git marker, sandbox or assertion
was weakened to obtain a pass.

No new CI, package build or scan ran. Inherited run 38405020184 does not include
this new test. The prior 75-failure record, unresolved causes, original DS-04
unavailability and earlier design-stage status remain unchanged; none is relabeled
as a success by this evidence.

### 8.7 Scope and next review

The only repository changes are the new test and this append-only evidence.
The original design prefix is preserved byte for byte. UTF-8/LF, Python syntax,
trailing whitespace, repository-relative links and full untracked content were
checked. No personal paths, operational identifiers, credentials, rendered
credential objects, raw exceptions or process argument dumps are included in
these review materials.

Branch remains security/deep-scan-remediation-47194b0; HEAD remains
385b770a051c56c2aa54520e72255231877ee9a6 and tree remains
41b65e26515dec6489ce82362295221d0304df9a. Index and all existing tracked files
remain unchanged, with staged count zero. No runtime consumer or schema changed.

Remaining decisions include trustworthy independent expectations and enrollment,
physical START/token/state binding, complete history and rollback resistance,
participating writers, ownership across the gap, normal completion and controlled
reconciliation. This test does not enforce refusal across existing product
callers, supply native session serialization, close operations or authorize use.

No commit, push, remote communication, PR change, deployment, OAuth, Google API or
Calendar operation occurred. DS-04 stays PARTIAL; Historical Deep Security Scan
INCOMPLETE; separate 47194b0 scan FAIL; Production gate BLOCKED; live handlers
hard-off; packaged registry empty/fail-closed. Work ends at test-only implementation,
available local checks and review; no operational integration follows automatically.
