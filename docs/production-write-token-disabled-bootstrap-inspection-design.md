# Synthetic Disabled Bootstrap-to-Inspection Handoff

Status: DRAFT_WITH_UNREVIEWED_SYNTHETIC_HANDOFF_PROTOTYPE

## 1. Scope and evidence

Propose a small, explicitly invoked diagnostic adapter for test-owned synthetic records. It captures independently supplied inputs, checks them with the disabled-bootstrap validator, then conditionally gives the same retained values to the existing read-only Inspection. This is a new connection contract, not an existing permission.

entry_mode=disabled prohibits managed operational entry. INPUTS_MATCHED_UNAPPROVED is a comparison result, not an execution permit. An explicitly authorized synthetic fixture test is separate from a launcher automatically reading records or starting a session. No real policy/companion loader, deployment, activation, revocation enforcement, pending retirement, intent, START, token/state or provider operation belongs here.

A function name, type name, synthetic flag or caller-selected path cannot prove fixture ownership. A future harness must establish ownership and separation outside the diagnostic call. The adapter does not safely discover or classify real data. Applying it to actual credential-related storage still requires independent deployment, provenance and operational approval.

**Implemented** means HEAD `3eb2e2ddf2d775cd57e07be1b8d37d63eb0b8acd`, tree `5bd53d15a3f2655570215efc9aeee3620c256474`. **Existing proposal** refers to the [disabled-input design](production-write-token-disabled-bootstrap-input-design.md), especially sections 3, 5, 8 and 9, and the [bootstrap contract](production-write-token-enrollment-bootstrap-contract.md). **Recommended** means this document's new contract. **Open** decisions below block specified later work.

Inherited external evidence reports PR #17 Open/Draft/unmerged and successful run 36215261770, attempt 1, pull_request, .github/workflows/test.yml: eight jobs succeeded. Only both base logs were examined externally; each showed the new disabled-input file passing 402 cases without skips. Those file counts are included in base totals, not individual passing-node lists. Other jobs have job/step evidence only. No remote verification or tests occurred here; this adapter/document was not covered. Historical document labels remain unchanged. Original scan-finding text was not consulted; no audit closure or new Unit number follows.

| Verified fixed-HEAD source | Existing boundary |
| --- | --- |
| [disabled-input module](../src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_inputs.py), DisabledBootstrapInputResult 58-67, _capture_inputs 154-172, validate_disabled_bootstrap_inputs 267-301 | Four inputs; internal copy; fixed six-state diagnostic; no snapshot export or I/O. |
| [descriptor module](../src/tridentine_calendar_google_sync/production_write_token_enrollment_descriptor.py), SyntheticEnrollmentExpectation 50-64 | Eleven public fields, with no approval/provenance meaning. |
| [preparation module](../src/tridentine_calendar_google_sync/production_write_token_enrollment_preparation.py), _snapshot 310-324 | Independent internal expectation copy and PREPARING gate; private helper, not an adapter dependency. |
| Same, LeafObservation 528-537 and PreparationInspection 602-725 | Public constructors validate exact types and represented cross-field consistency. |
| Same, inspect_synthetic_enrollment_preparation 1006-1082 | Platform gate precedes its snapshot; Inspection owns acquisition, unwind and observation. |
| [Inspection design](production-write-token-enrollment-preparation-inspection-design.md), sections 3-6 and 9-10 | Finite observation, sticky facts, constructor checks and limited read-path proof. |

## 2. Capture once at the adapter boundary

Proposed API, not implemented:

```python
inspect_synthetic_disabled_bootstrap(
    policy_raw: object,
    expected_raw: object,
    expectation: object,
    *,
    expected_control_root: object,
) -> DisabledBootstrapInspectionResult
```

All four inputs are required. Accept no previous result, approval Boolean, history, loader, callback, borrowed lock or resume handle.

**Recommended capture order:** check policy_raw exact bytes and 1-8192-byte envelope first; then expected_raw exact bytes and the same bound; then expected_control_root exact str; then expectation exact SyntheticEnrollmentExpectation and its eleven exact-str fields. Refuse subclasses, implicit conversions and missing fields. Ordinary failure yields CAPTURE_REFUSED without calling either API; cancellation propagates. These checks establish representation only.

Copy enrollment_revision, administrative_state, storage_ref, pair_ref, artifact_directory, token_slot, state_slot, active_intent_slot, descriptor_pin, descriptor_slot and administrative_pending_slot through a locally fixed name list into a fresh public expectation instance. Retain that instance, both immutable byte objects and the root string in one private frozen/slotted container with all fields excluded from repr. No arbitrary getattr, caller-object reread, global cache or exported captured-input object is permitted.

The adapter deliberately delegates full root lexical/UTF-8 bounds, policy schema/canonicalization, disabled mode, descriptor metadata/digest consistency, six cross-input comparisons and PREPARING purpose to the existing validator. Thus an exact-str but lexically invalid root reaches validator refusal; it is not relabeled as adapter capture failure. No policy parser, descriptor schema or digest checker is copied. Neither private _capture_inputs nor preparation's _snapshot is imported.

When defects coexist, the capture sequence above wins first. After successful capture, the validator's existing refusal order remains authoritative: input capture, policy format/disabled, descriptor comparison, cross-input equality, then purpose. A valid captured policy envelope does not imply a valid policy body. Do not run later stages to select a more convenient refusal.

The original expectation is copied once by the adapter. Each existing API may copy the adapter-owned expectation internally as designed. Equal retained values at both boundaries are required; identity equality between their private internal snapshots is not. No existing copying behavior is removed.

| Boundary | Exact supplied values |
| --- | --- |
| Disabled-bootstrap validator | Retained policy_raw, expected_raw, expectation; keyword expected_control_root |
| Inspection, only after a checked match | Retained expected_control_root as control_root, retained expected_raw and the same adapter-owned expectation |

Do not reconstruct inputs from the public result, reparse policy to choose a root, derive expectations from stored records or replace the root with artifact_directory. Later caller rebinding of bytes/root variables or mutation of the original expectation cannot change the retained inputs. This is not protection against hostile mutation of all same-process objects or equivalent-authority replacement.

## 3. Gating, platform and ownership

Call validate_disabled_bootstrap_inputs directly at most once. Validate its result as described below. Its five nonmatching classifications all stop before Inspection, retaining the exact returned classification. Only a checked INPUTS_MATCHED_UNAPPROVED permits progressing within the separately authorized synthetic diagnostic procedure; it never grants filesystem or operational authority.

Call inspect_synthetic_enrollment_preparation directly at most once. There is no retry, older-result reuse, alternate root, reread-until-match loop or writer-as-inspector fallback.

**Platform decision:** do not add an adapter platform shortcut. Capture and pure validation run on either test OS. After a valid match, delegate platform handling to Inspection's existing first gate. Valid Windows input can therefore yield an observed UNSUPPORTED_PLATFORM result without storage access; bad Windows input still refuses before Inspection. Neither case enables Windows serialization.

| Responsibility | Maximum direct adapter calls |
| --- | ---: |
| Disabled-bootstrap validation | 1 |
| Inspection | 1 |
| Preparation writer | 0 |
| Publisher or output preflight | 0 |
| Private reader or lock operations | 0 |

Inspection's own descriptor validation and bounded internal I/O are counted separately. Its existing limits remain one acquisition, four caller checkpoints, four leaf lstats and two content reads. The adapter acquires no lock, passes no owner, and neither borrows nor reacquires Inspection's resource.

A call to Inspection is not proof that record I/O began: platform, input or lock gates may return first. After an exception, the adapter performs no guessed close, unlock or repair. Suppressed backend failures and atomic name-binding limitations remain unobservable; this wrapper supplies no stronger cleanup or durability guarantee.

## 4. Preserve safe results without granting authority

Recommend a new frozen/slotted DisabledBootstrapInspectionResult with exactly four fields: state, input_result, inspection_result and constructor-excluded reuse_authorized: Literal[False]. The optional nested fields contain only checked DisabledBootstrapInputResult and PreparationInspection values. Use a separate closed DisabledBootstrapInspectionState for call progress, not copies of either nested enum.

| Outer state | Checked input_result | Checked inspection_result | Direct validation / Inspection calls |
| --- | --- | --- | --- |
| CAPTURE_REFUSED | None | None | 0 / 0 |
| VALIDATION_REFUSED | Any of the five nonmatching input states | None | 1 / 0 |
| VALIDATION_UNVERIFIABLE | None | None | 1 / 0 |
| INSPECTION_FAILED | INPUTS_MATCHED_UNAPPROVED | None | 1 / 1 |
| INSPECTION_RESULT_UNVERIFIABLE | INPUTS_MATCHED_UNAPPROVED | None | 1 / 1 |
| INSPECTION_OBSERVED | INPUTS_MATCHED_UNAPPROVED | Full checked observation | 1 / 1 |

VALIDATION_UNVERIFIABLE covers an ordinary validation-call exception or an unusable returned result. INSPECTION_FAILED means the Inspection call raised an ordinary exception; INSPECTION_RESULT_UNVERIFIABLE means it returned something that failed result validation. INSPECTION_OBSERVED means a valid observation returned, not that verification completed, records matched or use was authorized. Cancellation returns no outer value.

**Public-result boundary:** require the exact existing result types before reading their fixed fields; reject subclasses, missing fields, unknown enums, truthy substitutes and original reuse_authorized values other than False. Do not convert strings into enums or normalize booleans.

For the input result, capture state and the original authorization flag once, check the flag, then reconstruct through DisabledBootstrapInputResult's public constructor. For Inspection, require exact PreparationInspection and both exact LeafObservation types. Capture each leaf's presence/content/target/changed and every outer observation field once, including non_preparing_observed, verification_complete, first_failure, exit_failure_observed and the original authorization flag. Reject a forged True before reconstruction can replace it with the default False.

Reconstruct the two leaves through LeafObservation, then the observation through PreparationInspection. Their existing constructors enforce enum/Boolean types and summary consistency; do not borrow private validators or reproduce the whole state machine. Keep the resulting safe immutable copies. The outer constructor checks its own table of combinations, exact nested types and false authorization; it accepts no private input snapshot.

Preserve every observation dimension. ADMIN_PENDING, PREPARATION_CONFLICT, PREPARATION_UNVERIFIABLE and ABSENCE_UNVERIFIABLE remain nested observations; bootstrap agreement cannot clear them. Both records matching proves neither previous writer completion nor administrative retirement or resume permission. Never reinterpret a failed read as absence or publication_possible=False. This API receives no retained ADMIN_COMMIT_UNCERTAIN/ADMIN_REVOKED history and does not claim to reevaluate or clear it. An upper caller must retain its independent refusal.

**Exceptional construction boundary:** ordinary dependency/result-check failures map to the table. If outer-result construction fails after checked negative observations, do not replace them with an empty or normal result. The implementation condition added after this design requires a zero-argument, fixed-message DisabledBootstrapInspectionResultError carrying only the already checked optional diagnostics and False authorization. Leaving the adapter's handler alone does not remove an exception actively handled by its caller; from None alone only suppresses display. Locally raise and catch the newly constructed fixed error, clear only that error's __cause__ and __context__, and use bare re-raise. Never alter the original/caller exception or a cancellation. Preserve checked diagnostics without rerunning a failed constructor/check, bypassing constructors, retrying or adding I/O. Section 8 records Python 3.12 verification of this strengthened condition. This protects the public payload and exception links, not every traceback frame's locals or hostile-debugger access; resource exhaustion may prevent even allocating the fixed error.

KeyboardInterrupt, SystemExit and other non-Exception cancellation propagate at every phase, including checking/construction. No public diagnostic includes raw bytes, root, pin, metadata, arbitrary exception text or a permit. Local capture and result reconstruction establish neither authenticity, physical directory separation nor freshness.

## 5. Exact future dependencies and guard impact

The proposed adapter imports only public names:

- DisabledBootstrapInputState, DisabledBootstrapInputResult and validate_disabled_bootstrap_inputs from the disabled-input module.
- SyntheticEnrollmentExpectation directly from the descriptor module.
- LeafObservation, PreparationInspection and inspect_synthetic_enrollment_preparation from the preparation module.

Use only the small standard-library support needed for frozen values and enums. The pure validator gains no I/O or dependency. Preparation contains writer and reader definitions; importing its public reader does not authorize calling its writer. New adapter tests must prove this restricted call boundary.

Let **A** mean the proposed filename production_write_token_disabled_bootstrap_inspection.py. These are proposed changes only:

| Future path | New dependency | Actual fixed-HEAD assertion | Limited change | Preserve | Required authorization |
| --- | --- | --- | --- | --- | --- |
| src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_inspection.py | Public symbols above | New adapter dependency/result/call tests | New small adapter | No direct backend or operational consumer | New source |
| tests/test_token_disabled_bootstrap_inspection_phase6d1h.py | Synthetic calls and fixtures | New closed boundary tests | New test module | Existing socket/strict settings | New tests and test-owned fixtures |
| [tests/test_token_disabled_bootstrap_inputs_phase6d1h.py](../tests/test_token_disabled_bootstrap_inputs_phase6d1h.py) | A consumes bootstrap and descriptor type | test_closed_public_dependencies_no_effects_and_exact_consumers: empty consumer set 887-891; descriptor set 893-901 | Empty set becomes exact singleton A; descriptor set adds A | Pure imports/effects and fixed-getattr checks 793-885; both full scans | Two exact set changes |
| [tests/test_token_enrollment_descriptor_phase6d1h.py](../tests/test_token_enrollment_descriptor_phase6d1h.py) | A imports public expectation type | test_only_pure_standard_library_dependencies_and_only_approved_runtime_consumer, set 616-624 | Add A to exact descriptor set | Purity checks 577-615 and scan | One exact set addition |
| [tests/test_token_enrollment_preparation_phase6d1h.py](../tests/test_token_enrollment_preparation_phase6d1h.py) | A consumes public Inspection/types | test_component_imports_exact_public_boundaries_and_has_no_runtime_consumer, no-consumer loop 1176-1178 | Replace only that consumer assertion with full-scan exact singleton A | Package/effect checks 1122-1175 and all writer/Inspection tests | One exact caller exception |
| docs/production-write-token-disabled-bootstrap-inspection-design.md | Evidence record | This draft | Later implementation/results append | Original proposal and limits | Limited documentation update |

Direct type imports count: both descriptor-consumer assertions must change even though A never directly calls the descriptor validator. Bootstrap consumers become one, descriptor consumers three, and preparation consumers one. Existing scans must still reject every unlisted caller; no import hiding, wildcard or reduced search scope is allowed.

Keep the [record guards](../tests/test_token_operation_record_phase6d1h.py), test_only_exact_reviewed_modules_directly_import_lock_and_publisher at 392-415 and test_component_has_no_runtime_consumer_or_dynamic_import_and_no_mutation_escape at 418-487, unchanged. Keep the [lock consumer guard](../tests/test_posix_private_lock_phase6d1h.py), test_component_has_no_artifact_write_no_wait_loop_and_only_approved_consumers at 411-443, and [directory/publisher guard](../tests/test_posix_sensitive_directory_phase6d1h.py), test_directory_foundation_only_has_the_reviewed_backend_consumers at 351-410, unchanged. Direct lock consumers remain three; publisher consumers remain four excluding itself. Record gains no consumer.

The existing _inspection_reachable_calls at preparation-test 2105-2401 and test_inspection_transitive_entry_excludes_writer_and_checks_constructors at 2404-2408 inspect the preparation entry, not A. Preserve their exact sets, constructor traversal and negative binding/callback tests. Complement them with a bounded closed test of the new entry's imports, helpers, constructors and gate-before-Inspection order, plus BaseException effect traps. Do not claim general Python alias analysis. The adapter itself must have no external runtime consumer.

## 6. Proposed verification, not executed evidence

All injected values are synthetic. No fixture, application import, storage probe or program test is performed for this document.

| Input or fault | Inspection calls | Retained result | Forbidden effect |
| --- | ---: | --- | --- |
| Wrong bytes/type/bounds; missing or poisoned capture field | 0 | CAPTURE_REFUSED; no fabricated validator result | Hooks/conversion after exact-type refusal |
| Each of five validator refusal states, including policy/non-disabled/mismatch/purpose | 0 | VALIDATION_REFUSED with original classification | Observation or cached-match shortcut |
| Checked matched input result, the sixth state | At most 1 | Subsequent observation/failure branch | Extra validation, retry or root fallback |
| Forged result/type/enum/flag, ordinary validation exception | 0 | VALIDATION_UNVERIFIABLE | Truthy acceptance or enum coercion |
| Caller mutation/rebinding after capture; attempted argument substitution | At most 1 | Boundary spies verify retained bytes/root and adapter-owned expectation at both calls | Original-object reread, public-result input recovery |
| Inspection pending/conflict/unverifiable/absence, including complete mismatch | 1 | INSPECTION_OBSERVED with every original fact | Boolean success collapse or history clearing |
| Inspection ordinary exception / invalid return | 1 | INSPECTION_FAILED / INSPECTION_RESULT_UNVERIFIABLE | Guessed cleanup, absence or publication evidence |
| Outer construction fails after checked negative observation | 1 | Fixed construction refusal retains safe nested diagnostics | Replaced normal result or dropped known refusal |
| Cancellation in any phase | 0 or 1 according to phase | Propagated cancellation | Normal-result conversion |
| Valid Windows invocation | 1 | Nested UNSUPPORTED_PLATFORM | Storage access or claimed Windows locking |

Instrument direct validator/Inspection counts independently of internal calls. Exercise original-expectation mutation and separately rebound bytes/root references; verify the adapter passes its retained values, while real callees may create distinct equal internal copies. Test constructor invariants, missing fields, forged authorization, safe repr/error fields and preservation of every observation field.

BaseException spies must keep writer, publisher, output preflight and direct backend calls at zero from A, without disabling the legitimate internal reader/lock used by real Inspection. Structural checks distinguish direct adapter calls from delegated I/O. No callback is added to the runtime API for fault injection.

Separate Windows pure/mock/platform checks, Linux real read-only connection, and ordinary fresh-process observation. Linux tests prepare private synthetic fixtures before the diagnostic call, then use real validation and real Inspection, checking retained bytes/names/modes and no mutation. Fresh-process tests supply independent expected bytes/metadata again rather than learning them from disk. These tests prove neither cross-process lock contention, forced-termination recovery nor power-loss durability.

Plan regression of existing 402/347/593/387 cases and all affected/unaffected guards, retaining their definitions and meaningful counts. Apply existing Python 3.12, socket restrictions, Ruff, strict mypy and workflow/build checks. Measure new counts rather than adding predictions to old totals. Windows mock success alone cannot complete validation of the new Linux I/O connection.

## 7. One next implementation candidate and decisions

Implement only the six proposed paths in section 5: two new source/test files, four consumer-assertion edits across three existing test files, and a limited append to this design. The four-input API, six progress states, nested diagnostics and fixed construction-error boundary form one bounded candidate. Existing validators, Inspection, writer, result constructors, backend and record implementations remain unchanged.

Completion requires demonstrated same-retained-value handoff, refusal-before-observation, at-most-once calls, negative-fact preservation, no forbidden effects and exact consumer sets. Require Linux real connection and fresh-process evidence as well as Windows checks before describing connection validation as complete; report local/CI gaps explicitly. Stop if private helper borrowing, backend/operational consumers, existing runtime edits, real data or additional files become necessary.

Maintainers must review the capture priority, delegated platform handling, public-result reconstruction, exceptional construction refusal and four exact consumer changes. The user must separately authorize implementation and synthetic fixture execution. No additional design phase is needed merely to split this candidate.

Deployment owners still decide independent source provenance, fixture-versus-operational ownership, controlled installation and permitted operational reads; maintainers decide launcher enforcement, activation and reconciliation before any real integration. Those decisions block operational use, not the explicitly scoped synthetic prototype. Coherent rollback, equivalent-authority replacement, suppressed failures and actual deployment authenticity remain outside its proof.

This task creates only the design. HEAD/index and existing files remain unchanged; no tests, real reads, deployment, commit, push, PR or Google operation occurs. DS-04 remains PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 scan FAIL; Production gate BLOCKED; live handlers hard-off; packaged registry empty/fail-closed; PR #17 Draft in inherited evidence.

## 8. Unreviewed synthetic handoff prototype

This separately authorized prototype implements the four-input handoff and exact guard changes. Sections 1-7 remain the prior design record except the permitted construction-error correction above. The strengthened exception-link rule and closed enum-member checks are implementation decisions; they were not established by the earlier design or its supplementary example. Existing runtime components, schemas and result constructors remain unchanged.

### 8.1 Capture and one-time boundary calls

inspect_synthetic_disabled_bootstrap(policy_raw, expected_raw, expectation, *, expected_control_root) requires all four inputs. _capture_inputs checks exact policy bytes and its 1-8192 envelope, then exact expected bytes and its bound, exact root str, exact SyntheticEnrollmentExpectation and the eleven exact-string fields. Original fields are obtained once through fixed names. A new adapter-owned expectation and a frozen/slotted _CapturedInputs retain both immutable byte values and root; all private fields are excluded from repr.

The adapter does not parse policy or descriptor bytes, compute a pin, normalize a root or export a snapshot. Full root lexical/UTF-8 rules and semantic checks are delegated to the existing validator. Exact-str malformed roots therefore produce a validator diagnostic after capture, not a new adapter path rule.

The validator receives the retained policy/expected bytes and expectation, with the retained root keyword. After an exact, checked INPUTS_MATCHED_UNAPPROVED, Inspection receives that same root as control_root, the same expected bytes and the same adapter-owned expectation object. The existing APIs retain their own internal-copy behavior. Caller mutation/rebinding cannot change these local retained arguments; no stale public result is accepted as input.

Direct calls are at most one validator and one Inspection. All five nonmatching validator states, malformed results and ordinary validation exceptions stop before Inspection. No adapter platform shortcut is added. A real Windows call with valid synthetic inputs invokes both public boundaries once and receives Inspection's UNSUPPORTED_PLATFORM without record I/O. The adapter does not acquire, borrow or release a lock or perform fallback/repair.

### 8.2 Checked nested diagnostics and outer results

DisabledBootstrapInspectionState has exactly the six states from section 4. The frozen/slotted DisabledBootstrapInspectionResult has exactly state, input_result, inspection_result and constructor-excluded reuse_authorized: Literal[False]. Its public constructor enforces the state/nested-result table, checks the original authorization flags and revalidates nested content. Only this new result's input_result and inspection_result fields use object.__setattr__ to install safe copies.

_copy_input_result, _copy_leaf and _copy_inspection_result require exact existing public result/leaf types before fixed-field reads. They capture the original two input-result fields, all nine observation fields and both four-field leaves once. True, zero or truthy authorization substitutes are refused before constructor defaults can hide them. Existing public constructors reconstruct safe copies and enforce their represented consistency; no private checker or alternate state machine is imported.

After the expected enum type has been established by an exact check or public constructor, _require_member also requires identity with a declared member. This refuses an exact-type forged StrEnum value, including a counterfeit with the same spelling as a real member. Enum spellings are not converted into trusted states. This additional representation check does not authenticate a result's actual execution history.

INSPECTION_OBSERVED retains the full observation, including pending/conflict/unverifiable/absence, platform and lock refusals, changed flags, non_preparing_observed, completion and both failure dimensions. It does not imply record reads occurred, prior publication completed, pending was retired or use was authorized. Unknown history is not reconstructed or cleared.

### 8.3 Ordinary failures, construction failures and cancellation

Ordinary capture failures become CAPTURE_REFUSED. Ordinary validator-call/result-check failures become VALIDATION_UNVERIFIABLE. A checked nonmatch yields VALIDATION_REFUSED with its original input classification. Ordinary Inspection-call exceptions and unusable returned observations are separately INSPECTION_FAILED and INSPECTION_RESULT_UNVERIFIABLE. A checked observation is retained under INSPECTION_OBSERVED.

_finish receives only already checked local diagnostics. If the outer result cannot be constructed, it does not rerun a failed nested check. The ordinary zero-argument DisabledBootstrapInspectionResultError constructor sets exactly the fixed args message, initially empty private diagnostics and a False property. _finish attaches only its already checked copies. Read-only public properties expose those diagnostics; no input payload or original exception is accepted by the error constructor.

The fixed message is "Disabled bootstrap inspection result construction failed". _finish raises this new error locally, catches that new error type, sets only its __cause__ and __context__ to None, then uses bare raise. It never edits the original/caller exception, transfers notes, or converts cancellation. This handles an ambient caller except/finally as well as ordinary calls. It is a fixed terminal refusal, not a successful replacement observation.

Python 3.12 tests verified six construction-failure cases spanning ordinary/except/finally callers and pending/failed-conflict observations: both links are None at the API boundary; args, str and normal repr are fixed; notes are not inherited; checked negatives survive; caller cause/context/notes remain unchanged. A persistent outer deep-revalidation failure is separately tested: fallback retains the earlier safe observation without a third validation attempt.

Sixteen cases verify KeyboardInterrupt/SystemExit at eight capture, copy, dependency, result-check and construction phases. The original cancellation object, args and notes propagate. No guessed close/unlock follows an exception. The guarantee excludes exhaustive resource failure, suppression inside an existing backend, full traceback-local erasure and hostile same-process/debugger control.

### 8.4 Dependency restrictions and specification coverage

Application imports are exactly the seven public symbols in section 5. Standard-library imports are limited to __future__, dataclasses, enum and typing. The adapter has no external runtime consumer. Bootstrap consumers are exactly the adapter; descriptor consumers are preparation, disabled-input validation and the adapter; preparation consumers are exactly the adapter. The four allowed assertions across the three existing tests are the only tracked-source changes, with original scans and other assertions preserved.

Record isolation and the direct lock/publisher/directory sets are unchanged: three direct lock consumers and four publisher consumers excluding the publisher itself. The existing preparation read-path graph, its allowlists/negative tests and all writer tests are unchanged.

The new test's closed structural check covers this adapter's actual finite forms, helper and constructor calls, exact imports, declared receiver origins and scope-limited writes. It rejects duplicate/import aliases, protected-name parameter/store/comprehension rebinding, asynchronous comprehensions, dynamic dispatch, hidden constructor callbacks and direct dependency calls moved into helpers. Public validator/Inspection call sites are each one occurrence in the main entry. It supplements the unchanged preparation graph; it is not general Python alias analysis.

| Contract | Representative test or group |
| --- | --- |
| Required API and capture priority | test_public_api_has_four_required_inputs_and_one_keyword_only_root; exact bytes/root/type and eleven-field cases |
| All validator states and zero Inspection on refusal | test_each_validator_state_has_exact_gating_and_one_call; test_real_validator_six_classifications_control_the_handoff |
| Original values, identity and single field reads | test_capture_reads_original_once_and_retained_identity_survives_caller_changes; test_dependency_original_fields_are_captured_once_before_safe_reconstruction |
| Complete negative observations and constructor invariants | test_complete_nested_observation_is_copied_without_erasing_negative_facts; all-nine-field, both-leaf and outer-table cases |
| Forged authorization/enums | test_validator_return_is_checked_before_inspection; test_enum_spelling_equality_cannot_replace_actual_member_identity |
| Construction-error privacy and persistent failure | test_fixed_construction_failure_preserves_negative_diagnostics_and_clears_links; test_persistent_outer_revalidation_failure_does_not_repeat_check_or_drop_observation |
| Cancellation and public diagnostics | test_cancellation_at_each_phase_propagates_original_unmodified; test_public_payload_and_streams_never_contain_input_or_exception_canaries |
| Closed call boundary and binding mutations | test_closed_adapter_calls_cover_helpers_constructors_and_no_external_consumer; four closed-checker negative groups |
| No forbidden effects and real Windows gate | test_mock_handoff_never_reaches_direct_storage_or_writer_effects; test_native_windows_validates_then_observes_platform_refusal_without_record_io |
| Defined Linux connection and fresh-process cases | test_linux_real_handoff_preserves_records_and_bounded_internal_schedule; input-refusal/read-failure cases; test_linux_fresh_process_uses_independent_inputs_and_keeps_records |

BaseException sentinels and counts complement source checks. The Linux tests preserve legitimate internal readers/locks, prepare fixtures before calling the adapter, compare retained bytes/names/mode/identity with atime excluded, and check subsequent lock acquisition. The test-only --handoff-observe child entry lives in the new test file, uses independent in-memory expected inputs, captures output and has a ten-second timeout. Existing --observe/--inspect paths are unchanged.

### 8.5 Local verification and remaining evidence

Local verification used Windows / Python 3.12.14 and confirmed this repository's src. Installed pytest 8.4.2, pytest-socket 0.8.1, Ruff 0.16.4, mypy 1.20.2, pydantic 2.13.4 and build 1.5.0 metadata were freshly compared with uv.lock and matched. This was not frozen installation; no dependency/environment rebuild occurred.

Checks used the previous in-memory stdout/stderr capture and allowlisted diagnostic-field approach, finite child timeouts and no raw-output fallback. No new diagnostic self-test is counted as product verification. No persistent runner or raw log was created. Pytest used -B, an in-memory collector, -q, -p no:cacheprovider and a previously absent permitted synthetic --basetemp. Existing conftest, strict configuration/markers and socket restrictions remained active.

| Final required target | Collected | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| New handoff test file, complete | 305 | 293 | 0 | 0 | 12 | 0 |
| Disabled-bootstrap inputs, complete | 402 | 402 | 0 | 0 | 0 | 0 |
| Descriptor, complete | 347 | 347 | 0 | 0 | 0 | 0 |
| Preparation/Inspection, complete | 593 | 554 | 0 | 0 | 39 | 0 |
| Operation record, complete | 387 | 331 | 0 | 0 | 56 | 0 |
| Specified lock guard | 1 | 1 | 0 | 0 | 0 | 0 |
| Specified directory guard | 1 | 1 | 0 | 0 | 0 | 0 |
| Specified eager-import guard | 1 | 1 | 0 | 0 | 0 | 0 |
| Total | 2037 | 1930 | 0 | 0 | 107 | 0 |

Pytest exited 0. All eight required existing structural-test functions ran and passed, including the three changed functions containing four consumer assertions. Existing 402/347/593/387 definitions and collection counts are retained. New-file evidence is 292 passing pure/mock/structural cases plus one passing actual Windows platform-gate case. Its ten Linux real-connection cases and two Linux fresh-process cases were skipped. The other 95 skips are the existing native-Linux conditions. No unexpected skip or deselection occurred.

Final Ruff check . --no-cache --output-format json and Ruff format --check . --no-cache exited 0, with 272 files checked for formatting. Strict mypy --strict --no-incremental --cache-dir=nul --no-pretty exited 0 for the new module and all 122 src files. Initial source line-length/formatting findings and eight new-test lint findings were corrected only in new files: a nonambiguous enum alias, explicit regex literals and an equivalent conditional assignment. No assertion, marker or type/lint setting was weakened. Full required pytest and Ruff checks were repeated after these test edits and after adding explicit asynchronous-comprehension refusal; earlier failures and interim totals are not final results.

git diff --check and separate full-file whitespace/privacy review include the untracked adapter/test/document. Exact reconstruction of the three intended guard edits verifies there are only the four authorized changes; runtime hashes and HEAD/index/scope checks remain separate from product-test results. Documentation retains the original sections except the authorized status and section-4 construction-error correction.

Status: IMPLEMENTED_VALIDATION_INCOMPLETE. Linux real connection and the new-process route have not run here; no Linux environment or new CI was created. Old run 36215261770 and the external Python 3.13.5 exception demonstration are not evidence for this adapter and are not added to these counts. No cross-process contention, forced termination, power loss or recovery guarantee follows.

The prototype remains disconnected from actual deployment, controlled startup, activation, revocation enforcement, pending retirement, sessions and providers. No commit, push, PR change, real enrollment or Google operation was performed. Existing Production/audit refusals, hard-off live handlers and empty/fail-closed registry remain unchanged.

## 9. Limited item-mutation regression-check correction

This correction changes only the handoff test and this appended record. Sections 1-8 remain historical evidence for their respective revisions. The adapter did not contain the injected operations: the gap was that _check_closed_adapter accepted forbidden item-assignment syntax in a memory-only source copy. It is not evidence of an actual writer call, dependency mutation or data deletion.

### 9.1 Missing boundary and minimal correction

The previous checker restricted Name Store and Attribute Store but did not reject Subscript Store. It also permitted attribute reads of __globals__. Consequently, a copied entry body could assign through a dependency function's namespace dictionary, directly or through a local alias, while preserving every existing definition and normal call site. Merely counting the unchanged call spellings could not detect that replacement.

Two assertions now exclude ast.Subscript with Store or Del context and any ast.Attribute whose attr is __globals__. No existing predicate or allowed-call/import set was removed or expanded. Existing rejection of Delete statements remains; the additional context rule makes the item-mutation exclusion explicit. Subscript Load is still accepted, including required type annotations and an ordinary tuple-item reference.

The original Attribute Store scope/receiver/field rules and object.__setattr__ restrictions are intact. In particular, _finish can still retain safe nested diagnostics and clear only the new fixed exception's __cause__/__context__; the outer result can still install only its designated safe copies. Protected names, constructor/property checks, duplicate definitions/imports, callback restrictions, receiver provenance, call-site limits and the no-external-consumer check remain unchanged.

The two supplied attack shapes are inserted after the real entry's docstring and before its original capture body in an AST copy. The helper uses ast.parse, AST insertion and ast.unparse only. Neither copied program is compiled or executed. No live function namespace or backend is accessed or assigned, and no unsafe code is temporarily written into the adapter.

### 9.2 Independent RED and GREEN evidence

Before modifying the checker, two new regression cases required AssertionError for the direct and aliased namespace item assignments. Actual RED: 2 collected, 0 passed, 2 failed, 0 errors, 0 skipped, 0 deselected, pytest exit 1. Both failed specifically because the expected AssertionError was not raised. Each wrongly accepted copy returned 25 call names, exactly equal to the unchanged-source baseline set. No parse, fixture, import or unrelated assertion failure was counted as reproduction.

After the correction, eight new cases pass:

| Test | Cases | Boundary |
| --- | ---: | --- |
| test_closed_checker_rejects_dependency_namespace_item_rebinding | 2 | Reject the direct and alias namespace-mutation copies |
| test_closed_checker_rejects_item_mutation_without_namespace_access | 3 | Reject assignment, annotated assignment and deletion independently of __globals__ |
| test_closed_checker_rejects_namespace_access_without_item_mutation | 2 | Reject direct and aliased namespace reads without a Store target |
| test_closed_checker_preserves_exact_reviewed_calls_and_subscript_loads | 1 | Preserve the exact reviewed 25-name set, real-source annotation loads and a harmless item Load |

The direct attack is excluded by its item-write target and forbidden namespace access; the alias form is excluded when the namespace is obtained and also contains a forbidden item target. Independent cases prevent either rule from masking absence of the other. The unmodified real source passes the original dependency and call checks. Existing binding/factory/receiver negatives and zero-effect tests remain intact.

This is a closed syntax regression check for this adapter, not general Python alias analysis or a defense against arbitrary hostile code in one process. It grants no new runtime authority.

### 9.3 Final local verification and preservation

Windows / Python 3.12.14 was confirmed with source resolution to this repository. Installed pytest 8.4.2, pytest-socket 0.8.1, Ruff 0.16.4, mypy 1.20.2, pydantic 2.13.4 and build 1.5.0 metadata were freshly checked against uv.lock and matched. No installation, frozen sync, environment rebuild or Linux setup occurred.

An in-memory collector captured stdout/stderr and emitted only fixed classifications, verified relative paths, function names and counts. Required tests retained project conftest, strict configuration/markers and socket prohibition. Runs used -B, -q, -p no:cacheprovider and separate previously absent permitted synthetic --basetemp locations; no persistent runner or raw log was created. The modified AST copies remained data throughout.

| Final required target | Collected | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Handoff test file, complete | 313 | 301 | 0 | 0 | 12 | 0 |
| Disabled-bootstrap inputs, complete | 402 | 402 | 0 | 0 | 0 | 0 |
| Descriptor, complete | 347 | 347 | 0 | 0 | 0 | 0 |
| Preparation/Inspection, complete | 593 | 554 | 0 | 0 | 39 | 0 |
| Operation record, complete | 387 | 331 | 0 | 0 | 56 | 0 |
| Specified lock guard | 1 | 1 | 0 | 0 | 0 | 0 |
| Specified directory guard | 1 | 1 | 0 | 0 | 0 | 0 |
| Specified eager-import guard | 1 | 1 | 0 | 0 | 0 | 0 |
| Total | 2045 | 1938 | 0 | 0 | 107 | 0 |

The final pytest exit was 0. The original 305 handoff cases remain 293 passed/12 skipped; the eight additions are all passing with no skips. The handoff total comprises 300 passing pure/mock/structural cases and one passing real Windows platform-gate case. Its ten Linux real-connection and two fresh-process cases remain skipped. The other 95 skips retain their existing native-Linux conditions; no unexpected skips occurred. Existing 402/347/593/387 case counts are retained, and all eight required existing structural-test functions ran and passed.

Ruff check . --no-cache --output-format json, Ruff format --check . --no-cache and strict mypy --strict --no-incremental --cache-dir=nul --no-pretty passed. Formatting covered 272 files; mypy checked the unchanged adapter and all 122 src files. An initial format-check finding was corrected only in the new test additions, followed by the final full pytest/Ruff run. RED failures and intermediate runs are not added to the final totals.

The unchanged adapter retains its starting SHA-256. All three previously modified consumer-test files retain their starting bytes and exactly their earlier four authorized changes. Other runtime/tests/configuration and direct-consumer sets are unchanged. The original handoff tests, constants and call/import sets are preserved; only the checker gains the two denials, with new test-only helpers/cases added. Full content, whitespace, privacy, permitted incremental diffs, HEAD/index and scope were checked separately. This document's starting contents are retained in full with only this section appended.

Status remains IMPLEMENTED_VALIDATION_INCOMPLETE: Linux real connection, fresh-process execution and new CI are not performed here. Old CI run 36215261770, the earlier local totals and the external isolated review/reproduction are not this revision's measured evidence and are not added to it. No commit, push, PR change, deployment, real enrollment, actual dependency namespace mutation, startup connection or Google operation occurred. The existing Production/audit refusals and empty/fail-closed registry remain unchanged.
