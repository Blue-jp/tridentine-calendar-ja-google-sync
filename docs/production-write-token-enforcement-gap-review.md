# Credential Reuse Enforcement Gaps After Synthetic Bootstrap Validation

Status: DRAFT_STATIC_GAP_REVIEW_NOT_OPERATIONAL_APPROVAL

## Evidence and scope

This static review uses HEAD `43404331ebdf7f12569b0478cb1bc2df9cb5db79`, tree `1906d32522ce2dcd669b1578aa5fa2cf311370c4`. No application, CLI, test, credential read, scan or remote query was executed. References below use current source positions; private functions were read, not approved for reuse by another module.

Evidence labels are **ORIGINAL_FINDING**, **CURRENT_SOURCE**, **CURRENT_TEST** (definitions, not execution here), **HISTORICAL_DESIGN**, **INHERITED_CI**, and **PROPOSED_ACCEPTANCE**. A design requirement is not automatically an original finding or an implemented gate.

**ORIGINAL_FINDING_NOT_AVAILABLE.** The permitted tracked README, SECURITY and documents contain cumulative remediation and DS-04 status summaries, but no original finding text or identified original artifact. [Security narrative] lines 581-590 is a later summary; [Operation design] line 15 explicitly records that the original finding was not retrieved. Finding-level remediation and formal closure criteria remain undetermined. Required evidence is a sanitized original report or accessible artifact reference, scan/version and target commit, stable DS-04 identifier, original evidence and authoritative closure criteria. Private scan storage, HOME and historical logs were not searched.

**INHERITED_CI:** the supplied external record reports run 36502828546, attempt 1, pull_request, `.github/workflows/test.yml`, completed successfully with eight jobs on 2026-09-29 JST; detailed confirmation was on 2026-10-06 JST. Entry results were Ubuntu/base 435 passed plus one Windows-only skip, and Windows/base 424 passed plus twelve Linux-only skips. File progress and reviewed definitions support ten Linux connection/refusal cases and two ordinary fresh-process cases, not individual passing-node lists or twelve successful target reads. Detailed logs cover only the two base jobs; the other six have job/step success evidence. This evidence neither covers this new document nor proves deployment or session enforcement.

## A. Entry points, effects and existing gates

The table is **CURRENT_SOURCE**, not an execution trace. “No connection” means no supplied bootstrap/history/START input or direct call in the reviewed path. Tracked-source import/reference checks do not exhaust dynamic dispatch or external callers. Earlier path checks can inspect metadata even when credential content has not yet been read.

| API/CLI and current position | Category | First credential-related content read | Session/result location | Provider/refresh | Token/state save | Existing preceding gates | Bootstrap / reuse / START connection | Evidence limit |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| [CLI] 1703-1712, `_authorize_production_write_token_command`, `_rehearse_production_write_token_readonly_command`; [T] 635-661, `authorize_production_write_token` | Live hard-off | None | No session | None | None | Unconditional fixed refusal | None needed to reach current refusal | Callable lower APIs do not establish live CLI reachability. |
| [T] 664-738, `authorize_production_write_token_mock` | Explicit mock API | Client configuration at 702, through `_oauth_client_material` 623 | Authorization result 738, not a session | Injected authorizer 704 | Bundle 732 | Target, confirmation, path separation, mock/live flags before client read; accounting, grant/client identity before save | None | Mock flags are a contract, not deployment authority. |
| [T] 890-948, `prepare_production_write_rehearsal_credential_session` / `prepare_production_write_rehearsal_credential_session_mock`; `_load_production_write_credential_session` 741-887 | Provider-evidence library API / explicit mock API | State 781, token 782; bounded loaders [IO] 448-475 / 270-290 | Constructs at 790 or 883; surrounding lock exit precedes delivery | Public prepare passes None at 916; only injected fake refresh at 811 | Refreshed token 867; generation state retained | Target/confirmation, UTC/path checks, Linux parent locks, role/scope/evidence/target/generation; checkpoints and post-refresh checks | None | An unexpired provider-evidenced token can produce a session. Live refresh remains unavailable. |
| [R] 730-791, `run_production_write_token_readonly_rehearsal_mock` | Fake-provider orchestration | None in supplied FakeProvider; consumes its preloaded result | Provider load 762, session validation 775 | Fake transport construction 776; downstream synthetic read calls | No token/state save here | Confirmation 753; fake-provider class/flag checks 758; session validation before transport | None | [RT] 199-208 returns/raises stored input; it does not call public prepare. Gate 306-314 uses isinstance, not exact-type identity. |
| [E] 264-281 `bind_synthetic_disabled_bootstrap`, 210-261 `SyntheticDisabledBootstrapEntry.diagnose` | Synthetic nonauthorizing diagnostic | No credential content; lower chain reads policy/companion and preparation records | Refusal or diagnostic only | None | None | Retained representation, pair-only request, exact match; lower disabled/PREPARING checks | Calls loader [L] 333-432, then handoff [H] 254-294 / Inspection; no reuse model or START | Valid diagnosis never creates a credential session or permit. |
| [IO] 349-395 `persist_refreshed_production_write_token`; 594-686 `write_production_write_token_bundle` | Lower storage APIs | POSIX replacement compares original expected token bytes | No session | None | Token replacement; or state then token | Caller validation plus path/binding checks; Linux bundle lock/checkpoints | None | Storage success alone establishes neither enrollment nor history disposition. |

[T] 847-864 rereads and compares token/state after refresh and before saving. Checkpoint 882 precedes session construction. Matching bytes are not an atomic pair snapshot. [IO] 545-555 still checkpoints after `completed_output_count=2`; two writer returns are not bundle success. [T] 79-107 makes `publication_possible=False` evidence about this call's save attempt only, not provider or other-process inactivity.

The credential-bearing [M] 175-182 session has no administrative-history enforcement field. Existing hard-off handlers must remain intact, but they do not erase the lower library contract or the need to review future integration.

## B. Requirements, implementation, evidence and missing enforcement

All requirement origins below are **HISTORICAL_DESIGN** unless marked **PROPOSED_ACCEPTANCE**; none is attributed to unavailable ORIGINAL_FINDING text. Source entries are **CURRENT_SOURCE**, test references are **CURRENT_TEST**. CI scope is limited to the inherited record above.

| Requirement and origin | Current implementation | Test definition / inherited evidence | Applicable entry | Unconnected or unconfirmed | Next evidence needed |
| --- | --- | --- | --- | --- | --- |
| Independent expectations; [Bootstrap contract] 32-40, [Entry design] 38-66 | [E] 129-166 captures fifteen strings into detached private data; no acquisition from observations | [BT] 471-496 covers capture and caller mutation; inherited entry CI | Synthetic factory | Who approves and independently supplies the tuple is external | Approved installation/supply contract before real reads |
| Ordinary requests cannot replace configuration; [Entry design] sections 4-5 | [E] 210-261 accepts only pair reference; reinitialization 196-204 refuses replacement | [BT] 295-341, 636-665 defines API and lifetime checks | Configured entry | No control over direct factory/loader calls by arbitrary same-process callers | Separate enforcement across real entry paths |
| Disabled, unknown enrollment, unapproved deployment; [Bootstrap contract] 30-40, 120 | [Inputs] 285-301 permits only disabled/PREPARING comparison; all diagnostics remain False | [BT] platform and dependency checks; inherited CI | Synthetic chain | No authentic enrollment registry or installation verifier | Owner-reviewed source of authority; no approved Boolean default |
| ADMIN_PENDING / ADMIN_COMMIT_UNCERTAIN / ADMIN_REVOKED; [Bootstrap contract] 122-150 | [Preparation] 575-725 preserves pending/conflict/uncertainty dimensions; ACTIVE/REVOKED inputs are out of scope | Current preparation/handoff test definitions | Preparation observation | Administrative restart classifications are proposals, not all implemented output enums or session gates | Define trusted administrative evidence and coordinated disposition |
| Matching, unexpired, same-generation files must not erase unresolved history; [Reuse design] | [Policy] 316-395 prioritizes supplied uncertainty/failure/interruption over appearance; [Pair inspector] 61-141 never authorizes | [PT] 197-233, 307-338 defines benign appearances, permutations and reconstruction | Pure model and inspector only | Session loader has no history input or model call | Cross-invocation characterization proposed below |
| Operation identity differs from generation; [Reuse design], [Operation design] | [Policy] 80-92 and 254-313 check operation bindings/order; [T] 841/885 retains generation across refresh | [PT] 222-285 distinguishes previous/current operations and duplicate identities | Synthetic history; existing refresh | No authenticated operation-history producer joining these domains | Independent operation identity and complete-history contract |
| Refresh/save/return gates; documented local safety boundaries | [T] 764-887 checks before refresh, rereads before persistence, checkpoints before return; [IO] 383 uses original expected bytes | [FP] 109-189; [Prewrite tests] 110-246; [Lock tests] 252-286 | Existing session/mock paths | Same-call refusal does not persist a future-call prohibition | Explicit later-call evidence; no inference from exception flags |
| START obligation before managed effects; [Operation design] 53-74 | [Record] 573-699 creates/reads a fixed slot under its own scope | [OT] 498-518, 761-817 defines occupied-slot and fault/exit checks | Standalone record component | No session, authorizer, reuse-model or bootstrap caller; observing START never grants use | Reviewed coordinator/order and independent expected operation |
| First failure, ordinary error, cancellation, exit failure; existing contracts | Handoff [H] 119-251 retains negative dimensions; record scope [Record] 331-516 retains failure ownership; session catches ordinary refresh/save errors | [BT] 843-1004; [FP]; [Lock tests] 212-248 | Component-specific boundaries | A diagnostic's preservation is not durable global history; session cleanup semantics are separate | Failure-precedence tests at any future joining boundary |
| Restart independently resupplies configuration; [Entry design] 91 | Factory persists nothing; record read requires supplied binding/operation | [BT] fresh-process definition 1278-1332; inherited Linux evidence | Synthetic setup | Ordinary new process is not authentic deployment restart or crash durability | Owner supply/update/restart protocol; never learn expectations from stored IDs |
| Occupied START/pending remains unresolved; [Operation design], [Bootstrap contract] | Record has create/read only; preparation keeps pending; no retirement/activation/session coordinator | [OT] 518 occupied-slot check; preparation inspection definitions | Standalone components | Repeated managed operations, normal completion and controlled recovery remain unfinished | Separate lifecycle design; no deletion, alternate slot or guessed completion |
| Equal-authority replacement, rollback, Windows differences; explicit non-goals | [T] 134-135 bypasses Linux lock on Windows; [IO] 362-363 retains Windows writer; synthetic record/source I/O is Linux-gated | [Lock tests] 289-308 and native definitions; inherited per-OS CI | OS-specific components | No same-authority rollback protection, Windows serialization parity or all-writer participation | Owner threat/OS decision before expanding claims |

The review did not convert these declared limits into new findings. The [Source design] and [Operation design] remain historical contracts where their proposed integration is absent from current code.

## C. Decisions that stop later work

| Decision class | Missing decision/evidence | What it blocks | Needed for the next synthetic candidate? |
| --- | --- | --- | --- |
| Technical | Observe independent re-entry after an unresolved post-refresh failure, rather than replaying a caught error | Claims of continuous session refusal | Yes: bounded test design only |
| Original finding | Sanitized original DS-04 text, provenance and closure criteria | Finding-specific assessment and closure | No |
| Owner: deployment | Who approves all fifteen values and complete source bytes; who may invoke setup; installation/update/restart supply | Real configuration, credential reads and startup integration | No real values required |
| Owner: OS and threat scope | Participating writers, OS, directory/alias isolation, concurrency, same-authority replacement/rollback requirements | Operational guarantees and any stronger enforcement architecture | No |
| Future lifecycle | Activation, pending/START disposition, completion and controlled reconciliation | Repeated managed operation and recovery | No |

[Entry design] 179-191 assigns these responsibilities without assuming an external key, separate account, privileged service or freshness anchor. Synthetic testing can proceed independently of deployment approval.

## One recommended next candidate

**PROPOSED_ACCEPTANCE: one test-only cross-invocation characterization**, in prospective `tests/test_token_session_failure_reentry_phase6d1h.py`. Target the existing `prepare_production_write_rehearsal_credential_session_mock`, its private loader through that public call, and a separate `evaluate_reuse_policy` evaluation. No runtime module, wrapper, result type, parser, schema or consumer addition is proposed.

Why this candidate: [FP] 109-189 checks refusal within one failing invocation; 258-297 feeds that captured exception to a FakeProvider, not a new loader invocation. [Lock tests] 252-286 leaves a refreshed token after a late checkpoint failure without re-entry. Conversely, 328-355 already tests a subsequent call after a busy contender and another successful session. That is not unresolved post-refresh-failure enforcement. An additional hard-off patch lacks an identified changed predicate; owner decisions are indispensable for deployment, but need not prevent this bounded measurement.

Use independently declared synthetic credentials and memory-only read/save/path/lock doubles. First, let one fake refresh produce a same-generation, unexpired token; the fake writer exposes that value to subsequent simulated reads, then raises a persistence error with publication_possible=True. Assert refusal at the persistence-error boundary before session delivery: exactly one refresh/save, no session, no automatic retry or cleanup. Earlier simulated refresh/publication already occurred; do not report zero prior effects.

Make a separate explicit mock-prepare invocation. Current source predicts an unexpired session with refresh_count zero and no second refresh/save. Record this only as temporary characterization of missing integration, never approval or a permanent requirement to accept such reuse. Separately supply a synthetic REFRESH operation with START_RECORDED, PROGRESS and FAILED events to the pure model. Require RECONCILIATION_REQUIRED, UNRESOLVED_FAILURE and False despite matching/unexpired/same-generation appearances. Mapping the simulated error to FAILED is a test assumption, not an existing adapter; the loader must not be described as consulting that model.

After the first refusal, forbid implicit further reads/writes/provider calls; count the deliberate second invocation separately. Throughout, deny real filesystem/process/network effects, browser/Calendar access, activation, record removal and recovery. Keep existing guards, consumer sets and assertions unchanged. Run the common memory characterization on both OSes only under later authorization; fake locks prove no native serialization. Existing native Linux locking and Windows non-parity remain separate evidence.

Before implementing or committing tests, review the narrow doubles, the distinction between current behavior and desired future enforcement, and the plan to revise the characterization under a separately approved integration contract. Stop if runtime changes, new trust flags, real credentials, live gate changes or a new authority source become necessary. This document proposes the candidate; it does not authorize or execute it.

DS-04 remains PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 scan FAIL; Production gate BLOCKED; live handlers hard-off; packaged registry empty/fail-closed. PR #17 remains Draft in inherited evidence. No audit status was changed.

[T]: ../src/tridentine_calendar_google_sync/production_write_token.py
[IO]: ../src/tridentine_calendar_google_sync/production_write_token_io.py
[CLI]: ../src/tridentine_calendar_google_sync/cli.py
[R]: ../src/tridentine_calendar_google_sync/production_write_token_rehearsal.py
[RT]: ../src/tridentine_calendar_google_sync/production_write_token_rehearsal_transport.py
[M]: ../src/tridentine_calendar_google_sync/production_write_token_models.py
[E]: ../src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_entry.py
[L]: ../src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_source_loading.py
[H]: ../src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_inspection.py
[Inputs]: ../src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_inputs.py
[Preparation]: ../src/tridentine_calendar_google_sync/production_write_token_enrollment_preparation.py
[Record]: ../src/tridentine_calendar_google_sync/production_write_token_operation_record.py
[Policy]: ../src/tridentine_calendar_google_sync/production_write_token_reuse_policy.py
[Pair inspector]: ../src/tridentine_calendar_google_sync/production_write_token_pair_inspection.py
[Security narrative]: posix-private-artifact-security.md
[Operation design]: production-write-token-operation-record-design.md
[Bootstrap contract]: production-write-token-enrollment-bootstrap-contract.md
[Entry design]: production-write-token-disabled-bootstrap-entry-boundary-design.md
[Source design]: production-write-token-disabled-bootstrap-source-loading-design.md
[Reuse design]: production-write-token-reuse-policy-model.md
[BT]: ../tests/test_token_disabled_bootstrap_entry_phase6d1h.py
[PT]: ../tests/test_token_reuse_policy_phase6d1h.py
[OT]: ../tests/test_token_operation_record_phase6d1h.py
[FP]: ../tests/test_refresh_persistence_failure_phase6d1h.py
[Prewrite tests]: ../tests/test_refresh_prewrite_recheck_phase6d1h.py
[Lock tests]: ../tests/test_credential_session_lock_phase6d1h.py

## D. Test-only cross-invocation characterization and local evidence

This section records later, separately authorized test execution. The preceding 19,031 bytes, including their static-review status, tables and statements about work not executed at that earlier time, remain unchanged.

Result: CHARACTERIZATION_VALIDATION_INCOMPLETE. The final new memory-only tests and static checks passed, but the required existing I/O regression did not. Further I/O regression attempts stopped after the private-path guard rejected both selected validation locations. No runtime behavior, existing test, guard, configuration or authority boundary was changed to make those cases pass.

### D.1 Test scope and retained product behavior

[The new test](../tests/test_token_session_failure_reentry_phase6d1h.py) contains three common, unskipped cases. It directly calls prepare_production_write_rehearsal_credential_session_mock and therefore executes the actual _load_production_write_credential_session. Neither function is replaced. Real target/confirmation, role, scope, grant-evidence, client identity and generation verification remain active, as do token/state rendering and comparison. The second session is built by the real product constructor; the test does not fabricate a session or add reuse_authorized to its type.

Exactly five test-local I/O boundaries supply simulated behavior: token_io.validate_production_write_token_path_set, load_production_write_token_generation_state, load_production_write_authorized_user_token, persist_refreshed_production_write_token, and tokens._production_write_session_lock. The path double checks the declared synthetic arguments and existing flags; it does not certify real paths. Read doubles return the currently stored model objects. The writer checks the original expected_token and path, installs the refreshed object in memory, records that simulated publication, then raises ProductionWriteTokenIOError with publication_possible=True. State and generation do not change.

Each explicit invocation gets a separate lock context, with enter, checkpoints and exit recorded. Context exit preserves the original exception and releases only the simulated ownership; it is not recovery. A delegating FakeRefresher subclass records the call through the public mock argument. Fixed test time and clearly synthetic material come from the reviewed pure helpers. No token/state/client file is created by these new scenarios.

Scenario-local BaseException tripwires reject real file/descriptor I/O, process/network/browser entry points and existing real writer/removal routes. They restore before pytest reporting. Modules are imported during test preparation, not by an unrestricted live provider. These finite tripwires and observed calls are not a general sandbox or proof of native locking. Pytest's own source reads and the separately executed existing regression fixtures are outside the claim that the new scenarios use memory only.

### D.2 Measured independent invocations

The final test file measured the predicted distinction on Windows:

| Observation | First explicit invocation | Second explicit invocation |
| --- | ---: | ---: |
| Path checks | 1 | 1 |
| State reads | 2 | 1 |
| Token reads | 2 | 1 |
| Fake refresh calls | 1 | 0 |
| Fake save calls | 1 | 0 |
| Simulated publications | 1 | 0 |
| Normal session returns | 0 | 1 |
| New lock contexts / enters / exits | 1 / 1 / 1 | 1 / 1 / 1 |
| Lock checkpoints | 4 | 2 |

First-call order was: explicit invocation, checked synthetic paths, lock creation/entry, initial state/token reads, two checkpoints, fake refresh, checkpoint, state/token rereads, checkpoint, fake save, memory publication, writer exception, error unwind, caller catches the persistence error. It ended with exact ProductionWriteTokenRefreshPersistenceError and refresh_completed, persistence_attempted and publication_possible all True. The refreshed, unexpired token remained in simulated storage; the original state/generation remained unchanged. Thus first-call effects were not zero. publication_possible=True is not a real-durability claim; the harness separately observed the memory update.

The trace remained unchanged during the caller-owned gap. The test then explicitly invoked the same public API again, with a fresh refresher counter. It reread state/token in a new context, performed two checkpoints, exited normally and received an actual ProductionWriteCredentialSession with refresh_count zero. Its token was the object installed by the first fake writer; there was no second refresh or save. This is observed current behavior, not safe reuse approval.

The initially unexpired control returned a real session after one state/token read each, two checkpoints and zero refresh/save calls. The corruption control repeated the failed-publication setup, then deliberately changed only the simulated token's generation before the second invocation. Existing validation rejected it with production_write_token_generation_mismatch, after one state/token read each and one checkpoint, with no second refresh/save/session return. The deliberate test corruption is not product cleanup or recovery.

### D.3 Separate policy observation

The real evaluate_reuse_policy received independently declared SyntheticBinding, a REFRESH OperationDefinition, distinct operation_id and generation_ref, and ordinal 1-3 START_RECORDED, PROGRESS and FAILED events. registered=True and HistoryStatus.COMPLETE are explicit synthetic input assumptions, not evidence of real enrollment or authenticated complete history. Appearance observations said matching content, unexpired token, matching generation and possible publication.

The observed model result was RECONCILIATION_REQUIRED, with exactly POLICY_NEVER_AUTHORIZES and UNRESOLVED_FAILURE. unresolved_failure was True; unresolved_interruption and unresolved_commit were False; transitions_valid was True; reuse_authorized was False. This was a valid failed history, not refusal caused by malformed input.

The test maps the simulated persistence error to FAILED as an assumption. No exception-to-history adapter, durable START record, trusted history acquisition or session-policy connection was implemented. Session return and model refusal remain two separate observations. Passing these assertions characterizes the missing connection; it does not require future implementations to keep returning such sessions. A separately approved history-enforcement contract must revisit this temporary characterization and its second-call expectation.

### D.4 Local validation and the unresolved regression environment

Environment: Windows, Python 3.12.14. Source resolution matched this repository. Installed metadata matched uv.lock for pytest 8.4.2, pytest-socket 0.8.1, Ruff 0.16.4, mypy 1.20.2 and pydantic 2.13.4. No installation, frozen sync, environment reconstruction or Linux environment creation occurred. Existing conftest, strict settings and socket prohibition remained active.

After the final new-test edit and formatting, its standalone run measured 3 collected, 3 passed, 0 failed, 0 errors, 0 skipped, 0 deselected, exit 0. Both controls and the full first/second/policy trace passed. Final Ruff check across the repository exited 0; format check exited 0 for 280 files; strict mypy exited 0 for 124 src files. Only the new test was formatted. One RUF005 tuple-concatenation spelling was changed to equivalent ordered unpacking without removing assertions or cases.

The required combined attempt ran all five requested files and all three exact additional nodes, with the workflow base marker condition. Its actual results were:

| Target | Collected | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| New re-entry test | 3 | 3 | 0 | 0 | 0 | 0 |
| Existing persistence failure | 34 | 1 | 33 | 0 | 0 | 0 |
| Existing prewrite recheck | 25 | 1 | 22 | 0 | 2 | 0 |
| Existing credential session lock | 36 | 7 | 20 | 0 | 9 | 0 |
| Existing pure reuse policy | 205 | 205 | 0 | 0 | 0 | 0 |
| Three additional guard nodes | 3 | 3 | 0 | 0 | 0 | 0 |
| Total | 306 | 220 | 75 | 0 | 11 | 0 |

Combined exit was 1. The eleven skips were two native POSIX permission cases and nine native Linux session-lock cases. There were no new-test skips or unexpected skips. The direct lock-consumer, directory-backend-consumer and no-eager-network/Google/OAuth-import guards actually passed. This attempt preceded the final RUF005-only change; it is not a successful final regression run.

For diagnosis, the existing test_unexpired_token_never_calls_refresher_or_persistence was run without importing the new test: one collected, zero passed, one failed, zero errors/skips/deselections, exit 1. The captured chain was ProductionWriteTokenIOError(unsafe_production_write_token_bundle_paths) from SensitivePathError(sensitive_path_in_git_worktree). A second independent invocation using a fresh child of the tool-provided temporary directory produced the same counts and chain. These two diagnostic pytest attempts are separate from the combined totals and do not demonstrate a session reuse refusal.

Static inspection of sensitive_paths._reject_git_worktree, lines 81-112, confirms that the guard rejects package-repository paths or an ancestor .git marker without running Git or reading marker contents. The selected I/O fixture locations were unacceptable to that unchanged guard. No marker was removed, guard bypassed, setting relaxed or unauthorized location tried. A permitted new validation area accepted by the existing private-path rules remains necessary before the required I/O regression can be completed. The representative isolated failures do not certify the cause of every one of the 75 failures.

The memory-only tests passed both separately and before the failing regression tests; the isolated existing case failed without the new module. This provides no evidence that leaked monkeypatches caused that environmental refusal. Each new test uses a restoring local patch context; no process-wide zero-I/O claim follows.

Command forms used the existing venv Python with -B and an in-memory captured pytest.main collector. The combined arguments were the five specified files and three specified nodes, -q, -p no:cacheprovider, the marker expression "not google_read and not google_test_write and not google_production_write", and a fresh --basetemp. Absolute temporary locations are withheld. Static commands were python -B -m ruff check . --no-cache --output-format json; python -B -m ruff format --check . --no-cache; and python -B -m mypy --strict --no-incremental --cache-dir=nul --no-pretty src.

An intentional invalid-payload syntax probe was rejected by the captured outer compiler; it was one auxiliary check, not a product test. A separate read-helper JavaScript syntax diagnostic appeared at the tool boundary before execution, without private values; that outer tool response is not claimed to be protected. An auxiliary pre-save equivalence check also stopped before editing; raw readback confirmed unchanged bytes before its assumption was corrected. None of these helper events was counted as a product pass or used to explain away the existing regression failures. No scenario prediction was changed to obtain passing results.

Linux execution, native I/O/locking proof, package build and new CI remain unperformed for this addition. Inherited run 36502828546 did not contain this test and was not reused as its execution evidence. The original DS-04 finding and formal closure conditions remain unavailable. Production gate remains BLOCKED, live handlers hard-off, packaged registry empty/fail-closed; DS-04 remains PARTIAL, Historical Deep Security Scan INCOMPLETE and the separate 47194b0 scan FAIL. There was no commit, push, PR change, real credential use, deployment, registration, activation, record retirement, recovery or Google operation.

## E. Validation-root preflight and bounded regression follow-up

Result: VALIDATION_ROOT_UNAVAILABLE.

This later follow-up verified the fixed local starting point and inspected only currently supplied candidate metadata. The preceding 30,975 bytes are preserved exactly, including section D's incomplete result, prior failures and the unavailable original finding. No new test execution supersedes those records.

### E.1 Fixed inputs and permitted candidate scope

The local branch remained security/deep-scan-remediation-47194b0, HEAD 43404331ebdf7f12569b0478cb1bc2df9cb5db79, tree 1906d32522ce2dcd669b1578aa5fa2cf311370c4, with sole parent f366d0a0f8b9621905969a5be7cb41c70aa76de9. Staged files and existing tracked changes were zero. Only the characterization test and this document were untracked.

The test remained 23,111 bytes with SHA-256 4857268c15206a52c25a77998c1b9d3ab7da341ae57891ed29db083b0258475a and raw Git blob ef776c730e290e2e3dee8b8576732ca20cf07aa6. This document's starting 30,975 bytes matched SHA-256 a1f347b541fa12421a1d71e67244096a8120c8c96c59bfd95f49d526a73bef09 and blob d3dd26ab78bb9dcca74f249bfdfccef637a1d400. The index baseline was captured afresh for this follow-up.

Candidate origins were the current task runtime's explicitly supplied temporary root and the two writable roots declared for the task. No system temporary location, other drive or inferred writable directory was added. Absolute locations and the rejecting ancestor's identity are not published.

Static reading of [sensitive_paths.py](../src/tridentine_calendar_google_sync/sensitive_paths.py), lines 52-112 and 168-190, confirmed absolute-local-path, symlink and ancestor-marker checks. Any successful lstat of an ancestor's fixed .git name blocks; only FileNotFoundError establishes its absence. The representative test's _stored helper creates a new private-refresh fixture and invokes the real bundle writer before its unexpired-session assertion. It does not use the new test's memory I/O doubles.

Windows additionally checks actual directory/handle binding, reparse points, volume capabilities and parent/ancestor ACL conditions in the existing backend. Therefore missing markers alone would not prove full private-path suitability. No such broader suitability was established here.

### E.2 Metadata observations and conditional steps

| Fixed label / origin | Observation | Classification |
| --- | --- | --- |
| CANDIDATE_1: task-provided temporary root | Existing directory within the supplied permission scope. Nine path-component metadata checks found no symlink/reparse rejection. Seven fixed-name marker checks reached an existing directory marker in its ancestry. Marker contents were not read. | REJECTED_BY_ANCESTOR_MARKER |
| DECLARED_WORKSPACE_ROOT_1 | Its declared path is beneath the same already rejected ancestor. No additional candidate metadata walk or child-directory retry was performed. | SAME_REJECTED_ANCESTOR_FAMILY |
| DECLARED_WORKSPACE_ROOT_2 | Its declared path is also beneath that rejected ancestor. It was not counted as an independent candidate. | SAME_REJECTED_ANCESTOR_FAMILY |

Three currently provided origins were considered, but only one distinct ancestor family required filesystem inspection. This stayed below the maximum of two families. Directory enumeration, recursive search and candidate-marker content reads were all zero.

A preliminary helper rejected an unavailable optional runtime context value before inspecting candidate filesystem metadata. That was a captured auxiliary preparation result, not evidence that a marker was absent. The completed bounded check used current task-provided locations and the explicitly declared writable roots, without recovering paths from old logs or caches.

| Step | This follow-up |
| --- | --- |
| Distinct candidate families inspected | 1 |
| New validation parents created | 0 |
| Representative pytest invocations | 0 |
| Full regression pytest invocations | 0 |
| Representative collected/passed/failed/errors/skipped/deselected and exit | Not executed; no new counts or exit code |
| Full regression file counts, three new cases, OS skips and guard results | Not executed; no new results |

No acceptable candidate was established, so neither the representative test nor the combined regression was launched. There was no new basetemp, no write probe under a rejected ancestor and no repeated child-name experiment. No existing marker, ACL, guard, runtime, test, consumer set or configuration was changed.

### E.3 Evidence limits and remaining condition

The observed ancestor marker explains why the examined family is unsuitable under the unchanged guard. It does not identify every cause of the earlier 75 failures, demonstrate their resolution or prove a new session refusal. Section D's final standalone 3-case success and its unsuccessful combined 306-case attempt remain historical execution evidence.

The metadata helpers ran on Windows with the existing Python 3.12.14 interpreter. Because root preflight failed, the conditional test-environment/dependency checks and pytest commands were not run. Prior Ruff, format and strict-mypy successes are inherited results only, not rerun results. Current checks cover the fixed bytes/blobs, source/fixture reading, bounded metadata, document encoding/whitespace/links, prefix preservation and Git/index scope.

The required next condition is an explicitly permitted new validation location that satisfies the existing private-path rules and does not share the rejected ancestor. Merely changing a child name is insufficient. No real credential, Calendar identifier or operational path is needed. No alternate environment, repository copy, drive mapping, manual runner, build, CI, permission escalation or sandbox expansion was attempted.

Characterization remains a measurement of the session/policy disconnect, not authorization to reuse credentials or a repair of that disconnect. The original DS-04 finding and formal closure criteria remain unavailable. DS-04 stays PARTIAL; Historical Deep Security Scan INCOMPLETE; the separate 47194b0 scan FAIL; Production gate BLOCKED; live handlers hard-off; packaged registry empty/fail-closed. There was no commit, push, remote query, PR change, deployment, operational connection or Google operation.
