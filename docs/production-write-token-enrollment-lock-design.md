# Trusted Enrollment and Lock Ownership for Managed Production Write Tokens

Status: DRAFT_WITH_UNREVIEWED_PRIVATE_SCOPE_PROTOTYPE

## 1. Baseline and scope

Sections 1-8 preserve the original enrollment/ownership design and its fixed-HEAD evidence. Within those sections, **Current** denotes behavior at that baseline, **Proposed** denotes future work, and **Open** denotes a decision requiring separate approval. Section 9 records the subsequently authorized, unreviewed internal scope prototype. Section 10 records its limited initial-entry failure correction. Trusted enrollment and coordinator integration remain unimplemented. No new Unit number is assigned.

The fixed local HEAD is `b37d1d027af02b0c76fa1636e7c5b20e4c0db044`, tree `5dbc9b203e2a457e98c4f92a225b1b6916e7733e`. Supplied external evidence reports subsequent review, push, PR #17 Open/Draft/unmerged, an English PR/evidence update on 2026-09-22, and successful eight-job CI run `35669808808`, attempt 1, event `pull_request`. The new record-test file reportedly had Ubuntu 302 passed/0 skipped and Windows 249 passed/53 skipped, included in base totals. File-level progress plus the fixed test definitions supports inclusion of Linux reload; individual passing node IDs were not listed.

These are inherited facts, not remote queries or tests performed here. Historical incomplete-validation labels in [docs/production-write-token-operation-record-design.md](production-write-token-operation-record-design.md) remain unchanged. Neither that CI nor this document validates unimplemented enrollment or integration. Original scan findings were not consulted; no audit closure is inferred.

## 2. Trust is a sequence of separate claims

| Claim | Required basis; insufficient substitutes |
| --- | --- |
| Input has valid structure | Closed fields, types and canonical representation; no authority follows. |
| Access satisfies filesystem policy | Verified path, ownership and permissions; 0700/0600 does not authenticate enrollment. |
| Pair-to-storage mapping is approved | An independently bootstrapped operator approval, matching the pinned enrollment descriptor. |
| Necessary history is available | Independently retained operation expectations and a defined coverage policy; absence is not completeness. |
| Provider credential remains valid | Separate provider evidence, not generation or file equality. |
| Credential may actually be used | Separate authorization and Production gates; none of the preceding observations grants it. |

**Current:** `SyntheticBinding` and `RecordOperation` are caller assertions. `_matches_start_record` compares against them; it does not discover trusted expectations ([src/tridentine_calendar_google_sync/production_write_token_operation_record.py](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py), 47-81, 206-231). The reload test supplies synthetic expectations explicitly, including operation ID ([tests/test_token_operation_record_phase6d1h.py](../tests/test_token_operation_record_phase6d1h.py), 891-932). It does not implement enrollment discovery.

Likewise, `PolicyInput` defaults for registration/complete history remain synthetic assumptions. `evaluate_reuse_policy` preserves negative evidence and never authorizes ([src/tridentine_calendar_google_sync/production_write_token_reuse_policy.py](../src/tridentine_calendar_google_sync/production_write_token_reuse_policy.py), 111-145, 316-395; [policy specification](production-write-token-reuse-policy-model.md)). `TokenPairInspection` and `inspect_production_write_token_pair` remain non-authorizing ([src/tridentine_calendar_google_sync/production_write_token_pair_inspection.py](../src/tridentine_calendar_google_sync/production_write_token_pair_inspection.py), 47-141).

## 3. Recommended enrollment authority

| Candidate | Decision |
| --- | --- |
| Caller chooses a binding or a configuration file called trusted | Reject: the caller still chooses both the claim and its authority. |
| Operator-approved launch policy anchors a separate local control area | Recommend for cooperating processes and a trusted deployment owner; no new database or key service. |
| Separate privileged service, signing infrastructure or external monotonic anchor | Defer unless stronger same-user or rollback protection is required. These facilities do not already exist. |

**Proposed bootstrap:** the application owner approves a fixed launch policy through a separate offline enrollment/deployment review. That policy identifies `CONTROL_ROOT`, the enrollment slot, expected enrollment revision and a pin over the approved descriptor's canonical metadata. The pin covers no credential-derived material. The approval channel and controlled launcher installation are explicit trust assumptions, not facts inferred from that descriptor. A matching digest checks the approved document under this assumption; it does not confer provider or execution authority.

The ordinary session API accepts only an approved pair reference and an allowed requested action. It cannot override roots, slots, revision, pin, or expected operation through arguments or environment variables. Startup uses the same controlled launch policy after restart, verifies the control path, and loads only its designated descriptor. The descriptor cannot nominate a replacement trust root.

The operator owns approval, update, revocation and migration. Administrative changes require disabled managed entry points, a retained administrative-pending condition before changing approved mapping, and verified candidate/pin publication before separate activation. Missing, conflicting or uncertain administrative evidence keeps activation blocked. No automatic migration or old-version fallback is allowed. **Open:** the durable disable/activation protocol is not implemented; a failure with no surviving evidence cannot be promised detectable after restart. This blocks real enrollment, not synthetic ownership experiments.

These are API and deployment boundaries, not protection against malicious code with the same OS authority. An equally privileged actor may alter launcher, control area and artifacts together. Stronger protection requires a separately approved trust domain or anchor.

### Minimal retained information

| Location | Required information and purpose |
| --- | --- |
| Controlled launch policy | Fixed control location/slot, approved enrollment revision/pin and activation policy; bootstrap expectations unavailable to ordinary request overrides. |
| Enrollment descriptor | Format/revision, storage and pair references, fixed role, private artifact-directory binding, distinct token/state slots, fixed record slot, fixed per-pair active-intent slot in CONTROL_ROOT, and active/revoked administrative status. Binds approved destinations, not provider identity. |
| Separate active-intent descriptor in control area | Enrollment revision, pair, operation ID, predecessor and kind. Supplies expected operation independently of the start record. |

Private path material may be necessary in the first two locations; protect its confidentiality and modification rights and never copy it into public diagnostics. Examples here use only `CONTROL_ROOT`, `PAIR_ROOT` and synthetic references. Do not add Calendar IDs, credentials, token hashes, timestamps or PIDs for convenient identity. Exact encoding, update protocol and real operation-ID allocation remain open.

The Packaged Accepted Production Baseline Registry selects accepted baseline pins, not credential enrollment. Its `load_packaged_accepted_production_baseline_registry` and `active_accepted_production_baseline_pin` have a different package/code-pinned role ([src/tridentine_calendar_google_sync/accepted_production_baseline_registry.py](../src/tridentine_calendar_google_sync/accepted_production_baseline_registry.py), 285-317).

### Restart and incomplete enrollment

Confirm the independent active intent before creating START and before provider/writer activity, under the proposed coordinator's locks. On restart, select its fixed slot from the approved, pinned enrollment descriptor and compare the start against that expectation. Neither caller input nor START contents chooses the intent slot. Never learn an expected ID/predecessor solely from the suspect record.

An unverified occupied slot can justify refusal without establishing its exact operation. If the expected operation is unknown, refuse before comparison; do not invent a RecordOperation for the existing API. Never ignore the record, guess the latest ID, or allocate a replacement attempt.

| State | Required decision |
| --- | --- |
| Explicit initial-enrollment candidate | Remain inactive pending independent approval and activation checks. File absence is insufficient. |
| Existing pair without enrollment | Unregistered; no automatic adoption or invented history. |
| Enrolled pair without START | Refuse normal session preparation. Only separately established initial provisioning could explain absence; it does not authorize use. |
| START incomplete, unreadable or mismatched | Retain refusal; exact mismatch and incomplete presence are different observations. |
| Enrollment/data/record path switched | Reject against anchored mapping; copying equal bytes does not transfer approval. |
| Enrollment alone reverted | Reject revision/pin mismatch where the launch expectation survives. |
| Record alone reverted | Reject against retained active intent; revision/generation ordering alone proves nothing. |
| Administrative publication interrupted or uncertain | Keep activation blocked; preserve pending evidence and require separate review. |
| Active intent and START jointly reverted under the same enrollment | They may still match even with a current launch policy: its pin covers enrollment, not per-operation freshness. An independent operation anchor would be additional work. |
| Entire launch/control/artifact state coherently reverted | Local checks may not detect it. An independent retained anchor is required for that guarantee. |

## 4. Current lock ownership

The following abbreviations denote repository paths, not proposed APIs:

- **R:** [src/tridentine_calendar_google_sync/production_write_token_operation_record.py](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py).
- **T:** [src/tridentine_calendar_google_sync/production_write_token.py](../src/tridentine_calendar_google_sync/production_write_token.py).
- **IO:** [src/tridentine_calendar_google_sync/production_write_token_io.py](../src/tridentine_calendar_google_sync/production_write_token_io.py).
- **L:** [src/tridentine_calendar_google_sync/_posix_private_lock.py](../src/tridentine_calendar_google_sync/_posix_private_lock.py).

`record public API -> _storage_call -> own directory lock -> I/O/checkpoints -> context exit -> result`

`session loader -> _production_write_session_lock -> reads/optional refresh/save -> checkpoint -> exit`

`mock authorizer -> bundle wrapper -> session locks -> state/checkpoint/token/checkpoint -> exit`

| Current path | Acquisition, held work, checkpoints and release |
| --- | --- |
| R `create_start_record` / `read_start_record` / `_storage_call`, 249-334 | Own one lock; revalidate at 268, before create at 285 and finally at 299. Publisher/readback are inside. Result follows context exit, 319-322. |
| T `_production_write_session_lock`, 125-178 | Acquires sorted distinct token/state parents using ExitStack; releases acquired contexts on unwind. Yields a checkpoint callback. Windows yields a no-op. |
| T `_load_production_write_credential_session`, 741-887 | Owns that wrapper before reads. Unexpired path checkpoints at 789; refresh path at 809/846/865/882. Return expression precedes context exit. |
| T `authorize_production_write_token_mock`, 664-738 | Authorizer at 704 precedes bundle call/locking at 732. Live `authorize_production_write_token`, 635-661, remains hard-off. |
| IO `write_production_write_token_bundle` / `_write_posix_token_bundle`, 530-687 | Internal POSIX wrapper owns locks at 545; state, checkpoint, token, checkpoint at 549-555; exit precedes return. |
| IO `write_production_write_authorized_user_token`, 312-346; `persist_refreshed_production_write_token`, 349-395; `write_production_write_token_generation_state`, 478-505 | No shared session-lock ownership; local I/O checks do not establish participation in an operation-wide protocol. |

L `_PrivateDirectoryLock` and `acquire_posix_private_directory_lock`, 47-141, check process identity but supply no thread-owner contract. Directory close suppresses some errors ([src/tridentine_calendar_google_sync/_posix_sensitive_directory.py](../src/tridentine_calendar_google_sync/_posix_sensitive_directory.py), `_BoundPrivateDirectory.close`, 101-109).

## 5. Proposed owner and composition contract

Choose one future **ManagedOperationCoordinator**, a conceptual new layer, as owner of enrollment, intent, artifact checks and the complete protected interval. Fix the bootstrap policy before mutable enrollment is read. Acquire the fixed control-area lock, verify enrollment/intent, then acquire the enrolled artifact lock while retaining control ownership. Administrative writers must follow the same protocol; otherwise verification can race a path/revision switch.

Prefer one pair directory containing token/state/START. It still differs from the separate control area. Existing two-parent session support does not cover this combined protocol automatically. Initially refuse unsupported split-pair layouts without moving files.

For any later multiparent support, all participants must use one total order: control first, then distinct validated artifact-parent spellings in sorted order. Reject same-inode aliases rather than silently treating them as extra independent locks; unavailable identity comparison must fail closed. Acquiring a duplicate must never wait. Unwind prior acquisitions in reverse order on partial failure before effects. The current lock handles do not expose a complete identity-comparison contract; that seam requires review before any multi-directory coordinator, including the separate control/data layout.

| Proposed contract, not existing API | Required behavior |
| --- | --- |
| Operation scope | Immutable enrollment revision/pin, pair/binding, expected operation and lock set; creator process/thread; active lifetime. No credential or permit. |
| Internal held-lock record operation | Verify the same scope, run fixed-slot I/O/checkpoints without acquiring another lock, and record an internal held-start checkpoint. |
| Public record wrappers | Continue owning their own lock and returning the existing fixed result only after context exit. |
| Scope exit | Invalidate scope before release; retain first failure, suppress no success-relevant observed error, and never convert cancellation into success. |

Reject closed scopes, changed revision/root, another pair or operation, another thread/process, forked use, nested entry and duplicated ownership. Bind the live creator thread object, not only a recyclable thread ID. Never fork or duplicate held descriptors. Types, private constructors and object identity are cooperative checks, not unforgeable authority against hostile code in the same Python process.

Do not call current public record APIs inside a session lock: they reacquire. Do not create START, release its lock and later reacquire while claiming continuous protection. Refactoring an internal held-lock primitive is necessary; it is not already provided.

### Preserve the meaning of START_CONFIRMED

An internal **held-start checkpoint** means only that bounded save checks completed while the coordinator still owns its scope. Public `START_CONFIRMED` additionally follows the record API's context exit. Neither proves complete descriptor release, future provider permission or durable whole-call success. `START_OBSERVED` only describes a later read. Credential-use authorization and normal-closure/clearing approval remain separate and absent. A revalidation callback is not lock ownership.

Create uses `create_posix_private_bytes` with no final rollback ([src/tridentine_calendar_google_sync/_posix_private_create.py](../src/tridentine_calendar_google_sync/_posix_private_create.py), 112-229). `read_private_sensitive_bytes` enforces owner-only access, not exact creation mode or atomic ancestry binding ([src/tridentine_calendar_google_sync/sensitive_paths.py](../src/tridentine_calendar_google_sync/sensitive_paths.py), 328-503). Composition must preserve those limits.

## 6. Future path ordering, still blocked from live use

All rows begin with anchored control/enrollment verification and owned locks; all stop on unknown/unresolved history. Unsupported OS or busy/unavailable locks refuse without fallback. Linux serialization is not implemented for Windows by this proposal.

| Path | Required order within one operation |
| --- | --- |
| Unexpired token | Enrollment -> independent expectations/history -> existing pair/role checks -> checkpoint -> scope exit. History refusal precedes T's early return. No mutation START solely for inspection; no usable session crosses the unapproved use/closure boundary. |
| Refresh | Enrollment/history/pair -> confirm active intent -> held START check -> future approved refresher -> response validation -> existing prewrite pair recheck -> token persistence -> checkpoint -> exit with bounded non-authorizing evidence. |
| New authorization/bundle | Approved initial enrollment/intent -> held START check -> future approved authorizer -> existing scope/identity/generation checks -> state/checkpoint/token/checkpoint -> exit. Existing bundle locking starts too late for the authorizer. |
| Other write entry points | Join the same context before provider or target effects, or reject managed writes. Standalone writer signatures currently lack this participation contract. |

Failed START confirmation means zero provider and target-writer calls. Provider effects can precede local persistence. All-writer participation is required; advisory locks do not constrain arbitrary external writers.

Normally progressing synthetic work may reach a held-start or bounded data checkpoint and exit without authorization. Retained fixed slots still block subsequent attempts. Normal closure, slot retirement and controlled reconciliation are separate unfinished designs; none of these paths may return a real usable session by assuming those decisions.

Preserve `publication_possible` as call-local publication evidence and `completed_output_count` as writer-return count. Neither proves bundle completion or safe reuse. Keep model, inspector and record-result `reuse_authorized=False`. Existing role/generation validation remains additional evidence, not per-refresh identity ([src/tridentine_calendar_google_sync/production_write_token_models.py](../src/tridentine_calendar_google_sync/production_write_token_models.py), `ProductionTokenRole` 22-27, `ProductionWriteTokenGenerationState` 147-172).

## 7. Future change and guard inventory

No guard is changed now. Proposed conflicts identify later approval scope, not grounds for hiding imports.

| Proposed location | New dependency/responsibility | Existing test, function and assertion | Narrow future change | Preserve | Approval |
| --- | --- | --- | --- | --- | --- |
| Proposed `src/tridentine_calendar_google_sync/production_write_token_operation_coordinator.py` | Direct private-lock ownership | [tests/test_posix_private_lock_phase6d1h.py](../tests/test_posix_private_lock_phase6d1h.py), `test_component_has_no_artifact_write_no_wait_loop_and_only_approved_consumers`, 411-442; exact two-name list. [tests/test_token_operation_record_phase6d1h.py](../tests/test_token_operation_record_phase6d1h.py), `test_only_exact_reviewed_modules_directly_import_lock_and_publisher`, 388-406; `consumers == allowed`. | Add exactly the reviewed coordinator to both lock sets. | Publisher set, scans, negative assertions, lock AST/loop bans. | Coordinator wiring plus both named guards. |
| Coordinator -> R | Consume held-lock record primitive | Same record-test file, `test_component_has_no_runtime_consumer_or_dynamic_import_and_no_mutation_escape`, 409-478; helper-only imports and no other runtime consumer. | Permit exactly that consumer; avoid a new context-module import by keeping internal context in R. | All other negative consumers, no dynamic imports/provider/network/cleanup. | Exact consumer exception; not included in the next candidate. |
| R internal extraction | Keep public wrappers and add scoped internal composition | Same file, `test_one_owned_lock_covers_io_and_success_follows_exit`, 638-676. | Add scoped-lifetime/internal-checkpoint coverage, retain public expectations. | One acquisition and success after exit. | Two-file candidate below. |
| Directory/publisher | No new direct dependency | [tests/test_posix_sensitive_directory_phase6d1h.py](../tests/test_posix_sensitive_directory_phase6d1h.py), `test_directory_foundation_only_has_the_reviewed_backend_consumers`, 351-409; directory AST/import guards and publisher tuple. | None: coordinator uses lock revalidation and R. | Both existing exact consumer restrictions. | No broadening proposed. |
| T session extraction | Future held-lock session body | [tests/test_credential_session_lock_phase6d1h.py](../tests/test_credential_session_lock_phase6d1h.py), `test_loader_lexically_holds_locks_over_reads_refresh_save_and_both_returns`, 483-516; one top-level With, guarded required calls and two returns. | Explicit structural refactor proving equivalent complete lifetime and history-before-early-return. | Failure unwind, both-parent checks, cancellation and no unsafe helper operations. | Separate session integration review. |
| IO bundle extraction | Internal body without reacquisition | [tests/test_token_bundle_lock_phase6d1h.py](../tests/test_token_bundle_lock_phase6d1h.py), `test_only_bundle_wrapper_newly_acquires_shared_lock_and_never_cleans`, 383-403; sole acquiring wrapper. | Keep public acquiring wrapper; add held-inner ordering/ownership coverage. | Sole legacy acquiring wrapper, no cleanup/loops, count-two checkpoint failures. | Separate writer integration review. |
| Other helpers/policy | No bypass or new consumer | [replacement test](../tests/test_posix_private_replace_phase6d1h.py), `test_backend_has_only_reviewed_token_io_consumer_and_no_cleanup_or_path_repair`, 420-445; [planning-create test](../tests/test_private_planning_create_phase6d1h.py), `test_only_reviewed_callers_opt_in_and_common_writer_has_no_new_backend`, 353-372. | None for this recommendation. | Reviewed replacement/adapter consumers; no indirection to evade guards. | Separate explicit scope if later required. |
| Model/inspector/network | Remain independent | [policy test](../tests/test_token_reuse_policy_phase6d1h.py), `test_model_has_only_pure_standard_library_dependencies_and_no_runtime_consumer`, 735-792; [inspection test](../tests/test_token_pair_inspection_phase6d1h.py), `test_inspector_has_no_cli_consumer_provider_session_or_mutation_calls`, 373-409; [network test](../tests/test_no_network_or_google_dependencies.py), `test_source_package_has_no_eager_network_google_or_oauth_imports`, 81-105. | None; retain disconnected pure boundaries. | Mutation/import restrictions, socket policy, universal nonauthorization. | No integration permission inferred. |

## 8. Future acceptance and one next candidate

No tests, application imports, enrollment operations or I/O probes were performed for this document.

| Future synthetic scenario | Acceptance requirement |
| --- | --- |
| Unregistered/malformed enrollment, wrong pair/role, switched path | Refuse; no self-registration, fallback or arbitrary diagnostic text. |
| Enrollment publication interrupted/uncertain | Activation remains blocked where administrative evidence survives; test persistence gaps explicitly. |
| Unknown expected operation; missing/corrupt/stale START | Deny without guessing; distinguish existence-based refusal from exact comparison. |
| Unexpired token plus outstanding history | No early usable-session return. |
| START fails | Provider and target-writer call counts both zero. |
| Context crosses pair/revision/operation/thread/process or is closed/forked | Reject before I/O; no reused authority. |
| Double acquisition, contention, partial multilock failure | No waits/fallback; reverse unwind; no protected effects. |
| Post-save checkpoint/exit failure | Retain record and first failure; no fabricated completion or clearing. |
| Unsupported OS | Refuse before target/control I/O. |
| Fresh process restart | Obtain expected values from anchored control fixtures, not START; separately test unknown expectation. |
| Structural refactor | Exact approved import sets and public-wrapper semantics remain enforced. |

**One next candidate:** internal held-lock record composition only, in `src/tridentine_calendar_google_sync/production_write_token_operation_record.py` and `tests/test_token_operation_record_phase6d1h.py`. Factor the current record I/O into a private scoped operation, using the unchanged lock, publisher and reader. Preserve both public APIs, record bytes, fixed results and post-exit `START_CONFIRMED`.

Use only synthetic binding/revision/operation fixtures and one test-owned Linux directory. Demonstrate one acquisition covering internal create/read checkpoints, separate internal held-start meaning, identity/lifetime/thread/process checks, rejected reentry and post-exit use, retained records on failure, and unchanged public behavior. Windows retains pure validation plus pre-I/O storage refusal. Fail on uncertain scope, path, lock, publication or cleanup; never repair or retry.

Keep all existing consumer sets unchanged: no new coordinator module or runtime consumer in this candidate. Add narrowly scoped tests; do not delete or relax the public-after-exit test or isolation/import assertions. No real enrollment/control-store persistence, provider, token/state I/O, session/bundle refactor, normal closure, clearing, recovery, runner or new dependency is included.

Before this candidate, the maintainer must approve the private-scope interface, internal checkpoint vocabulary and ownership checks. Before real enrollment, the application owner must decide bootstrap provisioning, administrative activation/revocation durability, and active-intent publication/operation-ID rules. Before multiparent or session integration, maintainers must approve identity comparison, total locking order, all-writer participation and the exact guard changes above. Normal closure/reconciliation requires its own evidence and approval policy. These blockers do not prevent the bounded synthetic composition experiment.

DS-04 remains PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 scan report FAIL; Production gate BLOCKED; live handlers hard-off; Packaged Accepted Production Baseline Registry empty/fail-closed. PR #17 remains Draft in the inherited record and is not modified here. This document authorizes no implementation or production use.

## 9. Unreviewed private scope prototype

The later limited authorization implements only internal ownership composition in R and adds synthetic tests to its existing test file. It does not implement the proposed coordinator or any enrollment service. The original candidate's interface decision is now fixed for this prototype; all broader decisions in sections 3-8 remain open. The earlier operation-record design document is unchanged.

### 9.1 Interfaces and ownership

| Implemented private interface | Responsibility |
| --- | --- |
| `_record_scope(binding, operation, *, revision_ref=None)` | Creates a single-use `_RecordScopeContext`; entering it acquires one existing private-directory lock and issues its own `_HeldRecordScope`. It accepts no borrowed lock, descriptor, callback, or acquired Boolean. |
| `_create_start_record_held(scope, binding, operation, *, revision_ref=None)` | Performs one create/readback/checkpoint sequence through the shared `_held_record_io` implementation while the issued scope remains active. It never reacquires the lock. |
| `_read_start_record_held(scope, binding, operation, *, revision_ref=None)` | Performs bounded private read and expected-value comparison inside the same scope, without acquiring or transferring ownership. |

`revision_ref` is an optional synthetic memory label using the existing reference syntax. `None` explicitly claims no enrollment revision. Public wrappers supply `None` without adding an argument. Neither value is stored in the record or establishes registration, history completeness, or freshness.

The owner retains validated binding and operation snapshots and a factory-bound self identity. Every held operation checks the exact issued scope type, reciprocal owner/scope identity, creator PID, current live Thread-object identity, active lifecycle, nonreentrancy, and complete binding/operation/revision equality before lock revalidation or record I/O. Thread identity is not a recyclable numeric thread ID. No runtime thread/process creation, global scope registry, thread-local authority, random capability token, or new runtime consumer is introduced.

Direct construction, copying and serialization-based reconstruction are rejected by fixed private errors. Invalid nested entry or another owner's attempted use/exit cannot close or invalidate the legitimate owner's lock. These checks enforce cooperative lifetime rules, not unforgeability against malicious same-process attribute modification.

### 9.2 Lifecycle and result meanings

`_ScopePhase` distinguishes `NEW`, `ACTIVE`, `FAILED`, and `CLOSED`. Entry is allowed once from NEW. A separate entry-in-progress guard prevents nested entry, exit or held operations during acquisition, before ACTIVE is available to the caller. Successful acquisition issues the active scope; rejected or failed acquisition leaves no usable scope. An accepted record operation that fails or refuses the occupied slot marks FAILED and prevents further I/O. A legitimate owner exit invalidates the scope before backend release and ends it in CLOSED. Neither FAILED nor CLOSED permits reentry. Invalid ownership/expectation use is refused before an accepted operation and does not damage a still-valid owner.

Only one publisher entry is permitted per scope, including failed or uncertain attempts. A successful held create may be followed by held read under the same acquisition; it cannot be followed by another create. An occupied slot is never an idempotent success. The final record is never cleared or replaced.

`_HeldResult` carries exactly one fixed checkpoint or refusal classification, strict Boolean-or-unknown publication evidence, and constructor-excluded `reuse_authorized=False`. Internal successes are `_HeldCheckpoint.HELD_START_CHECKPOINT` and `_HeldCheckpoint.HELD_START_OBSERVED`; they do not use public success states. The public wrapper alone converts its own outcome to `START_CONFIRMED` or `START_OBSERVED` after successful owner-context exit. No caller-facing promotion function exists. Checkpoint observations grant no credential, provider permit, enrollment authority, or normal-closure approval.

### 9.3 Failure and publication evidence

Each held operation retains call-local publication evidence. A read reports `False` because that read did not publish, even after an earlier create. The owner separately retains `_creation_publication` and the first classified failure. Later read evidence therefore cannot erase an earlier create attempt or uncertainty. Formal publisher Boolean evidence retains its narrow meaning; unknown exceptions after publisher entry remain unknown. Publication followed by failed readback, checkpoint or observed exit does not become nonpublication.

An ignored held failure cannot silently become a successful context exit: `_ScopeFailure` carries a fixed safe classification. Additional ordinary cleanup errors preserve the first error. An occupied-slot observation remains retained; if exit itself fails, the public refusal follows the pre-existing exit-error classification. Cancellation propagates rather than becoming an ordinary refusal or success, and takes precedence over subsequent ordinary cleanup failure. A cancellation object is retained only as needed for active unwinding; legitimate exit clears its owner field. Closed scopes retain classifications, not stored exception/traceback objects. Public fallback handling also preserves known cancellation, first failure and call-local publication evidence.

Existing backend behavior is unchanged: verified temporary-file management is internal to the create backend; final-name rollback is absent. Advisory locks constrain only participating callers, private reads enforce owner-only rather than exact-0600 mode, and suppressed backend close errors remain unobservable. Scope checks do not attest kernel lock ownership perfectly or establish power-loss durability.

### 9.4 Compatibility and verification boundaries

Public functions, arguments, input types, enums, result fields and refusal conditions are retained. The fixed leaf, 4096-byte bound, twelve fields, canonical encoding and codec constraints are unchanged. No revision, ownership, PID, thread or completion field enters record bytes. Both public calls use the shared scope/I/O path and continue owning one acquisition through their checks, with success constructed after exit.

The existing 302-case test bodies, parameterizations, expectations and markers are retained, including `test_one_owned_lock_covers_io_and_success_follows_exit`. Existing import/consumer guards remain unchanged: two lock consumers, three publisher consumers excluding itself, no new direct directory-backend import, and no runtime consumer of R. Added standard-library ownership machinery does not relax prohibited imports or operations.

| Added verification group | Required evidence |
| --- | --- |
| Scope lifetime and identity | Entry/exit, copy/reconstruction, mismatch, nested entry and reentrant operation refusals before I/O; owner remains intact. |
| Owner checks | PID/thread fault injection distinguished from actual bounded thread/process tests; no foreign-owner cleanup. |
| Shared held sequence | One acquisition for create/read, internal checkpoints while locked, at most one publisher, unchanged public post-exit success. |
| Failure precedence | FAILED blocks further I/O; per-operation evidence remains separate from creation evidence; cancellation survives additional ordinary cleanup failure. |
| Isolation and compatibility | Original tests and guards retained, fixed diagnostics, unchanged bytes, no token/state access, unsupported-platform refusal before storage. |


Specific added tests include:

| Contract | Added test names |
| --- | --- |
| Shared held create/read and public post-exit conversion | `test_mock_scope_create_read_uses_one_lock_and_distinct_internal_results`; `test_mock_scope_public_wrappers_use_shared_held_path_and_success_after_exit`. |
| Issuance, reconstruction, binding and lifetime | `test_mock_scope_requires_factory_issued_mutual_identity`; `test_mock_scope_reconstructed_owner_does_not_inherit_factory_identity`; `test_mock_scope_mismatch_precedes_checkpoint_without_poisoning_owner`; `test_mock_scope_preentry_nested_entry_and_postexit_use_are_rejected`. |
| Acquisition-time and operation-time reentry | `test_mock_scope_entry_in_progress_cannot_acquire_twice_or_release`; `test_mock_scope_reentrant_operation_and_second_create_do_not_reenter_io`. |
| Different owners | `test_mock_scope_changed_process_is_rejected_before_io_or_owner_release`; `test_mock_scope_requires_original_live_thread_object`; `test_mock_scope_real_other_thread_cannot_use_or_close_the_owner`. |
| Retained evidence and cancellation | `test_mock_scope_failure_poisoning_keeps_first_formal_publication_evidence`; `test_mock_scope_read_failure_preserves_prior_create_without_mixing_call_local_flags`; `test_mock_scope_cancellation_survives_later_ordinary_cleanup_failure`; `test_mock_scope_caught_cancellation_cannot_allow_normal_context_exit`; `test_mock_scope_public_fallback_retains_publication_after_unexpected_exit_error`; `test_mock_scope_public_fallback_preserves_pending_cancellation`. |
| Linux-only added coverage | `test_real_linux_held_scope_create_read_retains_one_lock_and_record`; `test_real_linux_held_scope_failure_stays_retained_without_sentinel_access`; `test_real_linux_foreign_thread_cannot_release_active_scope_lock`. |

Validation status: IMPLEMENTED_VALIDATION_INCOMPLETE. The existing Windows Python 3.12.14 environment resolved the package to this repository's src directory. Installed pytest, pytest-socket, Ruff, mypy, pydantic and build metadata matched uv.lock. No installation, frozen sync, environment rebuild or Linux setup was performed.

All five required files were executed in full using the existing conftest, strict settings and socket restriction. The existing Python ran pytest.main with -q, -p no:cacheprovider and --basetemp pointing to a fresh test-owned directory inside the permitted workspace. An in-memory collector counted outcomes and captured raw diagnostics. No persistent runner was created.

| Test file | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: |
| tests/test_token_operation_record_phase6d1h.py | 313 | 0 | 0 | 56 | 0 |
| tests/test_posix_private_lock_phase6d1h.py | 4 | 0 | 0 | 24 | 0 |
| tests/test_posix_sensitive_directory_phase6d1h.py | 7 | 0 | 0 | 40 | 0 |
| tests/test_posix_private_create_phase6d1h.py | 2 | 0 | 0 | 41 | 0 |
| tests/test_token_reuse_policy_phase6d1h.py | 205 | 0 | 0 | 0 | 0 |
| Total | 531 | 0 | 0 | 161 | 0 |

Within the record-test file, all original 302 cases remain: 249 passed and 53 OS-conditioned skips. Added scope cases were 64 passed and 3 Linux-only skips. Exact source/AST comparison preserved all original non-import test nodes, including bodies and parameterizations; only four necessary imports and appended tests were added. Seventeen public/type/codec definitions remained textually and structurally unchanged.

The two external consumer guards and the record file's exact-import/no-consumer guards executed and passed. The unchanged native test_one_owned_lock_covers_io_and_success_follows_exit was OS-skipped; the separately named mock public-wrapper ordering tests passed. A bounded real second-thread test passed against the simulated backend. PID changes, same-numeric-thread-ID impostors and thread liveness were fault injections. Linux real record I/O, the new Linux thread/lock cases, the retained separate-process reload, actual fork behavior and power-loss tolerance were not executed or established here.

The first test run stopped during collection with one error because pytest inspected a poison object instantiated in a newly added parameter list. Constructing that same poison object inside the new test preserved the rejection case and allowed collection; the successful full rerun above used a different fresh temporary root. No original case was changed or excluded.

Final checks passed: ruff check --no-cache --output-format json .; ruff format --check --no-cache .; mypy --strict --no-incremental --no-pretty for the changed module and separately for all 118 src files, each with a fresh cache; and git diff --check. Earlier typing/lint findings in the modified code and added tests were corrected without ignores or reduced safety assertions. Prior validation roots/logs/caches were not reused or removed.

Run 35669808808 covers the earlier committed component. Its Linux success does not validate this uncommitted refactor; a fresh Linux run remains necessary before claiming complete validation.

Trusted bootstrap, real revision/operation expectations, CONTROL_ROOT, active-intent persistence, multiple-directory ownership, a coordinator, session/provider/writer integration, record retirement and reconciliation remain unimplemented. This prototype does not authorize those next steps, commit/push, or Production use.

## 10. Initial-entry failure correction

This limited correction starts from the uncommitted scope prototype, with HEAD and tree unchanged from section 1. Section 9's results remain historical evidence for that earlier version. The three starting files were fixed by these raw-byte values:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| src/tridentine_calendar_google_sync/production_write_token_operation_record.py | 25044 | a2338b6cfbc2ae2e73d5ea18f2685254ca029a865da2cbce17feec795da2ad2e |
| tests/test_token_operation_record_phase6d1h.py | 71897 | 3701b845f14c605b6f3d9bd3b6ee7d772ee9fb4c077508fbf40828bf883d1e1d |
| docs/production-write-token-enrollment-lock-design.md | 40117 | 92f3bb6e202364c66f56e11cf23e34424485e0ff48215eaafbe921bb1cc32a6b |

After an accepted first entry set `_entering=True`, an unexpected exception during pre-lock preparation previously left `_phase=NEW`. The finally block cleared the entry guard but did not make the attempt terminal. Removing the injected fault then allowed the same context to acquire a lock and publish a synthetic start.

The correction adds one outer failure handler around the existing accepted-entry initialization: platform, binding, operation and revision checks, encoding, snapshots, stack preparation, lock acquisition and scope issuance. Owner validation and the NEW/nonreentry preconditions remain outside it. Foreign-owner, nested-entry and entry-in-progress refusals therefore do not fail or release the legitimate owner.

Every caught initialization failure now leaves FAILED, invalidates any unpublished scope, and retains no cancellation object in the context. The existing finally still clears `_entering`. Later entry on that context refuses before acquisition or I/O without requiring a manual exit. Ordinary exceptions become a fixed `_ScopeFailure` classification without reflecting exception text, retaining any first classification already established. Cancellation propagates with its original identity. The original inner acquisition handler remains the sole cleanup owner for acquired resources; the new outer handler neither closes an unacquired lock nor duplicates release. No caught exception or traceback is newly stored in context fields.

`test_initial_entry_fault_is_terminal_after_injection_is_removed` crosses four preparation boundaries (encoding, platform check, binding snapshot and ExitStack preparation) with KeyboardInterrupt, RuntimeError and explicitly raised MemoryError. This task measured the following using the existing simulated backend on Windows/Python 3.12.14, independently of the supplied external reproduction:

| Run | Passed | Failed | Errors | Observation in each of 12 cases |
| --- | ---: | ---: | ---: | --- |
| Before correction | 0 | 12 | 0 | Initial NEW and zero I/O; after removing injection, same-context reentry reached one acquisition, one publisher, one reader and three checkpoints. |
| After correction | 12 | 0 | 0 | Initial FAILED, guard cleared and no scope; after removing injection, reentry raised `_ScopeUseError`, with all initial/reentry I/O counts zero. |

The before-correction failures were phase assertions, not collection or configuration errors. The regression also verifies fixed diagnostics, original cancellation identity and a separately constructed synthetic context's normal entry. That independence is not authorization to retry an operation.

`test_entry_scope_issuance_fault_unwinds_once_and_stays_terminal` adds six post-acquisition cases covering the same three exception types with and without an ordinary cleanup failure. It requires exactly one acquire/enter/exit sequence, no record I/O, preserved cancellation or fixed first classification, and terminal rejection after fault removal.

Validation status: IMPLEMENTED_VALIDATION_INCOMPLETE. After correction, all five required test files ran in full on Windows/Python 3.12.14 with the existing conftest, strict settings and socket restriction:

| Test file | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: |
| tests/test_token_operation_record_phase6d1h.py | 331 | 0 | 0 | 56 | 0 |
| tests/test_posix_private_lock_phase6d1h.py | 4 | 0 | 0 | 24 | 0 |
| tests/test_posix_sensitive_directory_phase6d1h.py | 7 | 0 | 0 | 40 | 0 |
| tests/test_posix_private_create_phase6d1h.py | 2 | 0 | 0 | 41 | 0 |
| tests/test_token_reuse_policy_phase6d1h.py | 205 | 0 | 0 | 0 | 0 |
| Total | 549 | 0 | 0 | 161 | 0 |

The record file retained the original 302 cases (249 passed, 53 skipped) and prior 67 scope cases (64 passed, 3 skipped); all 18 new cases passed. Both external consumer guards and the record import/no-consumer guards passed. The native success-after-exit test was OS-skipped; mock ordering and the actual second-thread test against the simulated backend passed. All skips followed retained OS conditions. No original expectation or marker was relaxed.

The existing interpreter invoked `pytest.main` with `-q -p no:cacheprovider --basetemp` and a fresh permitted test directory for each run; output was captured in memory without a persistent runner. `ruff check --no-cache --output-format json .` and `ruff format --check --no-cache .` passed. `mypy --strict --no-incremental --no-pretty` passed for the changed module and all 118 src files, using new caches. The six dependency metadata checks matched uv.lock; no installation, frozen sync, environment rebuild or Linux setup occurred. These results belong to the corrected version, separately from section 9's 531-pass history.

The public API, twelve-field canonical record, result vocabulary, nonauthorization, existing 302 plus 67 cases and exact consumer guards remain the compatibility boundary. MemoryError is explicitly injected, not actual memory exhaustion. These tests do not establish safety at every asynchronous instruction boundary, real Linux storage or process-reload behavior, fork safety, power-loss durability, or live enrollment/session integration. Earlier CI does not validate this correction. No new runtime hook, provider, recovery, record-clearing or Production permission is introduced.
