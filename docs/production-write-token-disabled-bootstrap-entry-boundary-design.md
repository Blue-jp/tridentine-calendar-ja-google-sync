# Installation-Fixed Bootstrap Plan and Disabled Entry Boundary

Status: IMPLEMENTED_VALIDATION_INCOMPLETE

## 1. Purpose and evidence

Recommend a small synthetic diagnostic entry whose configuration is captured before ordinary requests. The request supplies only a pair reference. For example, after setup binds pair A to source plan A, requesting pair B refuses without reading sources; requesting A cannot substitute another root or pin.

The added property is an interface constraint after configuration, not installation approval. Frozen data, factory success, pair equality, normal return and exit code zero grant no operational authority. Existing direct loader calls remain possible, so this entry cannot enforce every repository startup path.

**Implemented** means HEAD `f366d0a0f8b9621905969a5be7cb41c70aa76de9`, tree `f92017548e30a42365dddd01dfde40ecdef4a1a2`. **Existing proposals** are the [source-loading design](production-write-token-disabled-bootstrap-source-loading-design.md), especially sections 2-8; [input design](production-write-token-disabled-bootstrap-input-design.md), sections 2-3 and 6-8; and [bootstrap contract](production-write-token-enrollment-bootstrap-contract.md), sections 3-6. **Recommended** below is new work; **Open** decisions block real deployment, not an authorized synthetic prototype.

Inherited external evidence reports PR #17 Open/Draft/unmerged, its English description updated for 32 commits, and evidence comment 5871478828. Run 36425797883, attempt 1, pull_request, .github/workflows/test.yml completed successfully with eight jobs. Both base logs showed loader results: Ubuntu 493 passed/1 Windows-only skip; Windows 470 passed/24 Linux-only skips. File progress plus fixed definitions supports 22 Linux read/connection cases and two ordinary fresh-process cases, not individual passing-node lists. Counts belong within base totals. Six non-base jobs have job/step evidence only. No remote query or test was performed here. This evidence excludes the proposed entry and deployment; historical document labels remain unchanged. Original scan findings were not consulted, so no audit closure or new Unit number follows.

| Fixed-HEAD source and symbol | Existing boundary |
| --- | --- |
| [Loader](../src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_source_loading.py), _CapturedInputs 137-143; _capture_inputs 203-223; load_synthetic_disabled_bootstrap 333-432 | Copies five arguments, performs finite source acquisition, then delegates once. |
| Same, DisabledBootstrapSourceRefusal 88-105; DisabledBootstrapSourceResultError and _refuse 108-134 | Fixed refusal, False authorization and limited new-exception link clearing. |
| [Handoff](../src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_inspection.py), DisabledBootstrapInspectionResult 160-206; DisabledBootstrapInspectionResultError and _finish 209-251 | Public constructor checks nested diagnostics; fixed construction error retains checked negatives. |
| [Descriptor](../src/tridentine_calendar_google_sync/production_write_token_enrollment_descriptor.py), SyntheticEnrollmentExpectation 50-64 | Eleven hidden-repr fields, with no installation authority. |
| [Inputs](../src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_inputs.py), validate_disabled_bootstrap_inputs 267-301 | Existing policy, descriptor, equality, disabled and PREPARING checks. |

## 2. Responsibility before authority

| Role | Responsibility | What it cannot establish alone |
| --- | --- | --- |
| Preparation side | Assemble independent candidate policy, companion bytes and layout assertions | Approval by computing a digest |
| Deployment side | Review the exact complete set and choose its placement | Authentic installation merely by passing arguments |
| Configured entry | Retain one setup snapshot and constrain later requests | Provenance, freshness or global startup enforcement |
| Ordinary caller | Request diagnosis for the retained pair | Select sources, expectations or another configuration |
| Loader and handoff | Read bounded sources and preserve checked observations | Credentials, activation, retirement or recovery permission |
| Operational session/provider/writer entry | Remain outside this candidate | Treat diagnostic success as permission to start |

These are responsibilities and phases, not assumed separate people, accounts or privileged services. In synthetic tests the fixture-owning setup code calls the factory. It gives the request side a bound diagnostic method, not a configuration selector. The embedding code must keep factory invocation out of ordinary request handling. Python import visibility does not enforce that responsibility.

A caller able to run setup again, import the loader directly, replace dependencies or mutate arbitrary same-process objects can bypass this interface convention. No type name, private attribute, signed-looking label or approved Boolean cures that limitation. No operational installer or enforcing launcher is introduced.

## 3. Fifteen retained strings, one existing expectation type

The five loader arguments contain four direct strings and eleven nested strings:

| Number | Retained string | Independent setup source and role |
| --- | --- | --- |
| 1 | source_root | Fixture/deployment layout; source directory |
| 2 | policy_leaf | Layout; policy source leaf |
| 3 | expected_descriptor_leaf | Layout; complete expected-byte companion leaf |
| 4 | expected_control_root | Independently intended observation root |
| 5 | expectation.enrollment_revision | Reviewed candidate reference |
| 6 | expectation.administrative_state | Independently intended descriptor state |
| 7 | expectation.storage_ref | Reviewed storage label |
| 8 | expectation.pair_ref | Reviewed pair label and request-comparison anchor |
| 9 | expectation.artifact_directory | Intended PAIR_ROOT |
| 10 | expectation.token_slot | Pair layout |
| 11 | expectation.state_slot | Pair layout |
| 12 | expectation.active_intent_slot | Control layout assertion, not an intent read |
| 13 | expectation.descriptor_pin | Independently retained expected digest |
| 14 | expectation.descriptor_slot | Observed descriptor leaf in CONTROL_ROOT |
| 15 | expectation.administrative_pending_slot | Observed pending leaf in CONTROL_ROOT |

Each item has one retained role; equal spellings do not merge roles. In particular, the companion leaf is not the observed descriptor slot, and source_root, CONTROL_ROOT and PAIR_ROOT are not interchangeable. requested_pair_ref is a request comparison value, not a sixteenth configuration field.

Keep a private frozen/slotted plan with the four direct strings and a fresh SyntheticEnrollmentExpectation. Hide every field from repr. No public fifteen-field schema, serialization API or metadata file is needed. Preparation supplies all values independently before source/target observation. No policy content, pending/descriptor record, environment, cwd, previous diagnostic or filename search can supply a missing expectation. No real path, pin or metadata is embedded in the package.

## 4. Configuration capture and entry lifetime

Proposed setup API, not implemented:

```python
bind_synthetic_disabled_bootstrap(
    source_root: object,
    policy_leaf: object,
    expected_descriptor_leaf: object,
    expectation: object,
    *,
    expected_control_root: object,
) -> SyntheticDisabledBootstrapEntry | DisabledBootstrapEntryRefusal
```

All five arguments are required. Capture direct inputs in source_root, policy_leaf, expected_descriptor_leaf, expected_control_root order; then require the exact public expectation type and obtain its eleven fields once in table order. Refuse subclasses, conversions, missing fields and ordinary capture failures. Retain immutable strings and a newly constructed expectation, never the original caller object.

The setup boundary checks exact, nonempty, UTF-8-encodable strings and finite representation bounds: path roles at most 1024 bytes, leaf/reference/state roles at most 96, and pin exactly 64 lowercase hexadecimal characters. Require pair_ref to satisfy the existing bounded ASCII reference grammar so that a valid request can name it. These are completeness/representation checks, not a new policy or descriptor parser. Full path/slot layout, canonical-byte agreement, pin consistency and purpose remain the loader chain's responsibility; a complete bounded plan can still receive a lower semantic refusal.

An ordinary capture failure returns CONFIGURATION_UNVERIFIABLE and no configured entry. A zero-argument SyntheticDisabledBootstrapEntry() represents an unconfigured entry only; its diagnose method returns CONFIGURATION_REQUIRED before examining the request. Only the setup factory initializes a fresh private plan through the normal API, before publishing the entry. No public constructor accepts a plan; no setter, rebind or export method exists. The entry and its plan are frozen/slotted and hidden from repr; its read-only reuse_authorized is always False. This construction discipline is not hostile-process access control.

Retain source specifications, not source bytes. Setup has zero loader calls and zero I/O. Do not borrow private capture helpers, parse files, calculate digests, or call a validator with dummy bytes. Each later diagnostic obtains source bytes through the existing loader.

Recommend repeated explicit diagnosis with the same entry. Each invocation has local results and at most one loader call; no successful-result cache, automatic retry or autonomous scheduling exists. A one-use entry would add consumed-state and restart questions without improving this read-only boundary. The prototype assumes controlled fixture use and promises no new concurrent-request serialization.

Configuration changes require a separate setup operation and a different entry. Never replace values inside an existing entry or use equal revision labels to treat different roots, slots or pins as equivalent. The setup owner must review the entire changed tuple; same-revision substitution is not an update shortcut. There is no global revision registry to detect replacement of the entire entry by external code.

Restart requires the setup owner to supply the independently retained configuration again before accepting requests. The prototype persists nothing and reconstructs nothing from sources or prior observations. Configuration replacement, restart authenticity and retained administrative history remain deployment responsibilities.

## 5. Ordinary diagnosis and stopping positions

Proposed request API:

```python
entry.diagnose(
    requested_pair_ref: object,
) -> (
    DisabledBootstrapSourceRefusal
    | DisabledBootstrapInspectionResult
    | DisabledBootstrapEntryRefusal
)
```

There is no source, expectation, revision, pin, state, action, enabled flag, callback or entry-selector argument. Unsupported Python call signatures fail before the body and loader; their exception text is not a public diagnostic. Declared request values receive the fixed refusals below. No logging or generic exception-rendering layer is added.

| Ordered phase | Action | Loader calls / I/O |
| --- | --- | --- |
| Configuration presence | Missing private plan returns CONFIGURATION_REQUIRED | 0 / 0 |
| Request representation | Exact str, 1-96 ASCII characters; alphanumeric first, then alphanumeric/dot/underscore/hyphen; otherwise REQUEST_UNVERIFIABLE | 0 / 0 |
| Pair comparison | Exact equality with retained pair_ref; otherwise PAIR_MISMATCH | 0 / 0 |
| Delegation | Call load_synthetic_disabled_bootstrap once with the retained four strings and copied expectation | At most 1 / delegated |
| Result boundary | Revalidate the returned diagnostic or preserve the fixed call exception | No further I/O |

No request lookup selects another plan. An invalid/incomplete setup already failed before producing a configured entry. A representation-complete but semantically inconsistent plan may call the loader once and retain its refusal; configuration capture is not semantic approval.

The new entry adds no platform shortcut. Pure setup/request refusal works on either OS. A valid Windows request reaches the loader once and receives its platform refusal with zero source I/O. Linux delegates the existing maximum six additional metadata calls, two source reads and one handoff; reader-internal checks and target observation stay separately owned.

entry_mode=disabled still bars operational entry. Explicit fixture diagnosis is a separate procedure with no success continuation callback. It never starts credentials, active intent, START, a writer or provider. Existing direct loader and operational APIs are unchanged; this candidate does not prove that real startup has been stopped.

Fixed configuration does not freeze referenced files. Replacement, mixtures and coherent rollback retain the loader's detection limits. Passing observations do not prove atomic acquisition, current pathname contents, legitimate installation, freshness or successful cleanup hidden by lower layers.

## 6. Diagnostic and exception preservation

Propose DisabledBootstrapEntryRefusal with only a closed state and constructor-excluded reuse_authorized: Literal[False]. States are CONFIGURATION_REQUIRED, CONFIGURATION_UNVERIFIABLE, REQUEST_UNVERIFIABLE, PAIR_MISMATCH, LOADER_FAILED and LOADER_RESULT_UNVERIFIABLE. Require exact enum type, declared member identity and False identity; reject invalid construction with fixed text. This distinguishes setup/request failures without another success envelope or nested state machine.

For an exact DisabledBootstrapSourceRefusal, capture stage, reason and original authorization once; require False and rebuild through its public constructor. For an exact DisabledBootstrapInspectionResult, capture its four fields once; require the original flag to be False and reconstruct through its public constructor. Return the safe copy, retaining pending, conflict, uncertainty, first_failure and exit_failure along with all other dimensions. Do not duplicate their state machines or borrow private checkers.

Unknown/subclass returns, non-False flags or failed reconstruction yield LOADER_RESULT_UNVERIFIABLE. This means the return could not be verified, not that no earlier observation existed. Do not export an uncertain partial object or retry for a better result. No later entry envelope is constructed after a valid diagnostic copy.

Only around the direct loader invocation, distinguish exact DisabledBootstrapSourceResultError and exact DisabledBootstrapInspectionResultError and use bare re-raise. Retain identity, checked nested negatives and existing links without modifying the original. Subclasses or other ordinary call exceptions become LOADER_FAILED. Either fixed exception type arising during result reconstruction is a reconstruction refusal, not a call-origin exception. Type/origin checks classify the reviewed dependency contract; they do not authenticate arbitrary same-class forgeries.

If constructing a new entry refusal itself fails, propose zero-argument DisabledBootstrapEntryResultError with the fixed message "Disabled bootstrap entry result construction failed" and False authorization. Apply the existing local raise/catch/bare-raise technique only to this newly created error's cause/context, including ambient caller except/finally. Never copy original notes/text or alter caller, dependency or cancellation exceptions. Non-Exception cancellation propagates unchanged through setup, delegation, verification and construction.

Public results/new errors contain no paths, pins, metadata, bytes or original exception text. Exception-link protection is not complete traceback-local erasure or a resource-exhaustion guarantee. No generic sanitizer is proposed. There is no API accepting upper ADMIN_PENDING, ADMIN_COMMIT_UNCERTAIN or ADMIN_REVOKED to clear them; even repeated matching diagnoses leave those refusals with their upper owner.

## 7. Alternatives, dependencies and exact guard impact

| Alternative | Additional constraint | Decision |
| --- | --- | --- |
| Existing APIs plus test-only harness | Demonstrates separation only within that test's procedures | Useful comparison, but no reusable request-only entry |
| Small configured diagnostic entry | Ordinary requests cannot supply or select a replacement plan; mismatch stops before loader | Recommend one bounded candidate |
| Deployment loader, persistent manifest or signing service | Would address a separate installation/trust protocol | Outside authorization; availability not assumed |

The proposed entry imports six public application symbols: load_synthetic_disabled_bootstrap, DisabledBootstrapSourceRefusal and DisabledBootstrapSourceResultError from the loader; SyntheticEnrollmentExpectation from descriptor; DisabledBootstrapInspectionResult and DisabledBootstrapInspectionResultError from handoff. The last two are necessary diagnostic types, not a direct handoff-function call. The loader has no formal public result alias/re-export; borrowing its incidental imports would obscure dependencies. No validator, Inspection, reader or backend function is imported.

Let E mean production_write_token_disabled_bootstrap_entry.py.

| Current guard at fixed HEAD | Future exact change |
| --- | --- |
| [Loader test](../tests/test_token_disabled_bootstrap_source_loading_phase6d1h.py), test_closed_loader_dependencies_effect_arguments_receivers_and_external_consumers, 1808-1830 | Empty consumer set becomes {E}; keep the complete AST source scan. |
| [Handoff test](../tests/test_token_disabled_bootstrap_inspection_phase6d1h.py), test_closed_adapter_calls_cover_helpers_constructors_and_no_external_consumer, 1446-1457 | Add E to the source-loader singleton because type imports count. |
| [Descriptor test](../tests/test_token_enrollment_descriptor_phase6d1h.py), test_only_pure_standard_library_dependencies_and_only_approved_runtime_consumer, 616-626 | Add E alone to the four-consumer set. |
| [Inputs test](../tests/test_token_disabled_bootstrap_inputs_phase6d1h.py), test_closed_public_dependencies_no_effects_and_exact_consumers, 893-903 | Add E alone to its separate descriptor-consumer set. |
| Same inputs test, 887-891 | No change: inputs consumers remain handoff only. |
| Loader test, _APPLICATION_IMPORTS 1221-1231; _check_loader_bindings_and_headers 1282-1559; _check_closed_loader 1562-1805 | No allowlist/call/binding relaxation. New entry gets its own closed check. |

Preparation remains consumed only by handoff. Record isolation, three direct lock consumers, four publisher consumers excluding itself, directory restrictions and reader checks remain unchanged. No dynamic import, hidden module reference or narrower scan is proposed. No guard changes occur in this document task.

## 8. One next candidate and acceptance

Recommend one implementation unit:

- New src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_entry.py containing the factory, entry, refusals and fixed error above.
- New tests/test_token_disabled_bootstrap_entry_phase6d1h.py with synthetic setup/request and boundary tests.
- The four existing test files in section 7, each changing only the identified consumer set.
- A limited implementation/evidence append to this document.

No existing runtime, nine-key policy, twelve-key descriptor, expectation schema or loader API changes. Reviewers must approve the capture-completeness boundary, unconfigured constructor, repeated explicit diagnosis, exact exception handling and four type-aware consumer additions. Implementation and fixture execution require separate user authorization; no additional design subdivision is needed absent a concrete blocker.

Future acceptance must prove capture-once behavior under caller-object mutation; all fifteen retained roles; ordinary override rejection and zero calls on missing configuration, bad requests or pair mismatch; one call per valid request; no cached-success shortcut; separate new-entry reconfiguration; restart with independently supplied expectations; immutable nonauthorizing diagnostics and cancellation identity.

Use BaseException sentinels and bounded call accounting to exclude writes, providers, credentials, activation and retirement. Preserve negative results and fixed exceptions, including constructor faults and caller except/finally. Add exact dependency/binding/consumer checks without changing existing checker permissions.

Run existing 494/313/402/347/593/387-case suites and related guards under the existing Python 3.12, socket and strict settings. Separate pure/mock checks, Linux real entry-to-loader connection, Windows zero-I/O platform behavior, ordinary fresh-process setup and CI evidence. Measure counts after implementation; no predicted or old-CI total substitutes for execution. No real configuration or credential fixtures. Stop for required existing-runtime changes, extra consumers, private-helper borrowing, real data or broader scope.

## 9. Decisions before operational use

| Responsible role | Required decision | Blocked while unresolved |
| --- | --- | --- |
| User/deployment owner | Who reviews the exact fifteen values and complete policy/companion bytes, against which independent evidence | Operational approval |
| Deployment owner | Installation-fixed sources and expectations outside ordinary request selection; who may invoke setup | Real configuration supply |
| Deployment owner and maintainers | Complete-set installation, updates, partial failure and independent restart supply | Deployment/restart integration |
| Fixture/deployment owner | Actual source/target separation, ancestor safety, access permissions and mount aliases | Any real source read |
| User and maintainers | Trusted administrator/cooperating-process assumptions and permitted concurrent use | Operational threat-scope claims |
| User and deployment owner | Whether equal-authority replacement/rollback needs stronger protection; possible external anchor, key or service | Stronger authenticity/freshness claims |
| Maintainers with separate user approval | Enforcement across every real entry and later activation/reconciliation/retirement protocols | Startup wiring and operational use |

No key, privileged service, separate account or freshness anchor is presumed available. Synthetic tests can use explicitly owned, separated fixtures and a controlled setup harness without deciding real installation. They cannot approve deployment on the user's behalf.

Only this English design is created now. No application import/execution, test, source-read experiment, deployment, commit, push or PR operation occurs. DS-04 remains PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 scan FAIL; Production gate BLOCKED; live handlers hard-off; packaged registry empty/fail-closed; PR #17 Draft in inherited evidence.

## 10. Synthetic entry implementation and local evidence

Status for this implementation: IMPLEMENTED_VALIDATION_INCOMPLETE.

This section records implementation and validation performed after the design in sections 1-9. Those sections remain the original design record. The explicit reinitialization and damaged-plan requirements were added for this implementation; they were not already verified during design. No new Unit number, installation approval or operational continuation is established.

### 10.1 Implemented API and retained configuration

The new module is src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_entry.py. It exports the proposed bind_synthetic_disabled_bootstrap factory, zero-argument SyntheticDisabledBootstrapEntry, DisabledBootstrapEntryState, DisabledBootstrapEntryRefusal and DisabledBootstrapEntryResultError.

The factory requires all five arguments and keeps expected_control_root keyword-only. It checks source_root, policy_leaf, expected_descriptor_leaf and expected_control_root in that order, then requires the exact SyntheticEnrollmentExpectation class. A fixed eleven-name comprehension reads each original field once in the section 3 order. All fifteen values require exact, nonempty, UTF-8-encodable strings. Three path roles have a 1024-byte bound; the other leaf/reference/state roles have a 96-byte bound. The descriptor pin requires exactly 64 lowercase hexadecimal characters, and pair_ref uses the declared 1-96-character ASCII reference grammar. Pair references do not inherit source-leaf device-name or trailing-dot exclusions.

The factory constructs a new expectation and private frozen/slotted _Plan, with every retained field excluded from repr. It performs no loader call, source read, digest calculation or lower semantic validation. Complete representation is distinct from correct paths, slots, pin/descriptor agreement and disabled/PREPARING purpose, which remain lower-layer checks. Caller variable rebinding or later mutation of the original expectation cannot replace the captured strings.

A fresh entry initializes only its own private _plan slot to None. The factory binds its newly captured plan only to the fresh, unpublished entry it has just constructed. These are the two permitted object.__setattr__ sites. Calling __init__ again on an initialized entry raises a fixed ValueError without clearing or replacing its plan. No constructor accepts a plan, and no setter, rebind, export, callback or serialization interface is provided. Entry, refusal and terminal error expose only False authorization through their defined public interfaces.

### 10.2 Request order, retained-plan checks and lifetime

The ordinary method remains diagnose(requested_pair_ref). Unsupported Python argument signatures fail before its body; their TypeError text is not a public diagnostic.

| Ordered check | Result before delegation |
| --- | --- |
| Entry/plan presence | A missing slot or None yields CONFIGURATION_REQUIRED; the request is still untouched. An invalid entry receiver yields CONFIGURATION_UNVERIFIABLE. |
| Retained plan representation | Exact private plan and expectation types, field availability and the same fifteen representation conditions are checked. Detected damage yields CONFIGURATION_UNVERIFIABLE before request checking. |
| Request representation | An exact string satisfying the bounded ASCII reference grammar is required; otherwise REQUEST_UNVERIFIABLE. |
| Pair comparison | Exact comparison with the retained pair reference; mismatch yields PAIR_MISMATCH. |
| Delegation | One direct loader call with retained source specifications, a checked copy of the held expectation and retained keyword-only control root. |

The retained-plan check reads the private held values, never the original setup caller. It constructs a checked local copy for the invocation; it does not alter the entry's stored plan. Unknown objects are not repaired by conversion, equality hooks or fallback lookup. These detectable-damage checks are not protection against arbitrary hostile same-process object manipulation.

Every setup/request refusal has zero loader calls. Each valid explicit diagnosis calls the loader at most once. Repeated explicit diagnoses obtain fresh lower observations without a result cache or automatic retry. A later refusal is retained even after an earlier matching diagnostic. Reconfiguration requires a separate factory call and a distinct entry; the previous entry remains unchanged, including when revision and pair labels are identical while other retained values differ.

The entry adds no OS shortcut. A valid Windows request delegates once and preserves the loader's platform refusal before source I/O. Linux source acquisition and target observation remain owned by the existing loader/handoff chain. This entry does not add readers, locks, writes, activation or a success continuation.

### 10.3 Diagnostics, exception origin and dependencies

DisabledBootstrapEntryRefusal has only state and constructor-excluded reuse_authorized: Literal[False]. Its six classifications are CONFIGURATION_REQUIRED, CONFIGURATION_UNVERIFIABLE, REQUEST_UNVERIFIABLE, PAIR_MISMATCH, LOADER_FAILED and LOADER_RESULT_UNVERIFIABLE. Construction requires the exact enum class, declared member identity and False identity, with the specified fixed ValueError on failure.

For each recognized exact lower result type, the entry captures the public fields once, checks the original authorization is False, and reconstructs through the existing public constructor. It preserves the complete checked source refusal or handoff diagnostic, including nested pending/conflict/uncertainty and first_failure/exit_failure. No extra success envelope is constructed. Unknown or subclass results, missing fields, invalid authorization and reconstruction failures yield LOADER_RESULT_UNVERIFIABLE.

The direct loader call and result reconstruction have separate try boundaries. Only exact DisabledBootstrapSourceResultError and DisabledBootstrapInspectionResultError originating from the direct call are bare-reraised with identity, checked diagnostics and existing links retained. Exactness uses two is comparisons; tuple membership is not used to let a subclass metaclass equality hook influence classification. This refinement came from static review, not an executed RED test. Subclasses and other ordinary call exceptions yield LOADER_FAILED. The same fixed exception classes raised during reconstruction yield LOADER_RESULT_UNVERIFIABLE.

If a new entry refusal cannot be constructed, the new zero-argument terminal error has the fixed message "Disabled bootstrap entry result construction failed". Only that newly constructed error's cause/context are cleared by the local raise/catch/bare-raise pattern. Original dependency/caller exceptions are not modified. Non-Exception cancellation propagates unchanged through capture, entry creation, request processing, delegation, verification and refusal construction. This does not promise erasure of traceback locals or successful allocation under resource exhaustion.

Application dependencies remain exactly the six public symbols in section 7. The three loader symbols use an explicit level-one import from production_write_token_disabled_bootstrap_source_loading, resolving the same sibling module; the two handoff diagnostic types and the descriptor expectation use direct absolute imports. This is a visible direct dependency, not an incidental re-export or import workaround. Standard-library imports are limited to __future__, dataclasses, enum and typing.

Only the four approved consumer assertions changed: loader consumers now contain entry; handoff consumers contain loader and entry; the two descriptor-consumer assertions each add entry. The inputs-only consumer remains handoff. Full scans and existing checker permissions are preserved. Preparation, record, direct lock/publisher, directory and reader restrictions are unchanged. Existing runtime bytes, schemas and configuration are unchanged; the new entry has zero external runtime consumers.

### 10.4 Test coverage and structural review

The new test file is tests/test_token_disabled_bootstrap_entry_phase6d1h.py. Representative named coverage is mapped below; parameterized cases form part of the measured totals in section 10.5.

| Contract | New test functions |
| --- | --- |
| Exact APIs, fifteen roles, types and bounds | test_exact_public_signatures_no_override_and_no_setup_io; test_configuration_exact_types_nonempty_utf8_before_conversion; test_representation_byte_boundaries; test_utf8_byte_limits_do_not_count_characters; test_pin_representation_is_exact_lowercase_hex |
| Capture order and independence | test_capture_once_in_declared_order_detaches_every_field; test_invalid_direct_value_precedes_expectation_access; test_capture_completeness_does_not_duplicate_lower_semantics |
| Presence, damaged plan and request priority | test_unconfigured_precedes_even_poison_request; test_detected_retained_plan_corruption_precedes_request_and_loader; test_request_exact_type_has_no_conversion_or_comparison_hook; test_pair_mismatch_has_zero_loader_calls |
| Repeated diagnosis, separate configuration and reinitialization | test_explicit_rediagnosis_has_no_success_cache_or_automatic_retry; test_same_revision_and_pair_do_not_merge_distinct_entries; test_reinitialization_never_clears_or_replaces_plan; test_frozen_slotted_objects_have_no_configuration_export_or_setter |
| Lower diagnostic preservation and verification | test_all_source_refusal_pairs_are_checked_and_preserved; test_all_handoff_progress_classifications_are_preserved; test_all_observation_fields_and_negative_evidence_are_copied; test_invalid_return_fields_cannot_be_hidden_by_constructor_defaults; test_lower_result_fields_are_captured_once |
| Exception origin, link preservation and cancellation | test_exact_call_origin_fixed_error_preserves_identity_fields_and_links; test_constructor_faults_are_result_refusal_even_for_lower_fixed_errors; test_new_fixed_error_clears_only_its_own_links; test_cancellation_is_not_converted_or_mutated; test_fixed_error_subclass_metaclass_equality_hook_is_never_called |
| Fixed public diagnostics and forbidden effects | test_repr_and_public_diagnostics_do_not_disclose_retained_values; test_pure_setup_request_and_mock_delegation_have_zero_forbidden_effects |
| Native and new-process boundaries | test_windows_valid_request_reaches_real_loader_once_without_source_io; test_linux_real_entry_loader_handoff_preserve_owned_sources_and_targets; test_linux_source_refusal_is_preserved_without_target_observation; test_linux_bad_requests_do_not_access_even_existing_fixture; test_linux_explicit_rediagnosis_observes_fixture_fault_without_cached_success; test_linux_fresh_process_binds_independently_supplied_plan |
| Closed syntax/dependencies and mutation negatives | test_closed_entry_dependencies_bindings_effect_arguments_and_no_runtime_consumer; test_closed_checker_refuses_binding_namespace_dispatch_and_origin_escapes; test_closed_checker_preserves_loads_and_exact_reviewed_call_set; test_closed_checker_rejects_implicit_input_hooks |

The closed checker is specific to the reviewed entry. It checks exact imports and positions, class/function headers, decorators, approved assignments, comprehension bindings, attribute loads/calls, all named calls and their scoped arguments/counts, seven reviewed Subscript forms including annotations, and the fixed pair-comparison origin. Protected-name replacement, item mutation, dependency namespace access, unapproved attribute writes, dynamic dispatch, duplicate definitions and hidden calls are refused. Only fresh-entry plan writes and new-error link clearing have the narrowly specified mutation forms.

Independent review identified three nearby omissions in an earlier checker: extra Subscript Load, implicit f-string conversion, and extra name calls whose argument/count had not been fixed. Four AST-only negative cases represented them: requested_pair_ref[0], f"{requested_pair_ref}", len(requested_pair_ref), and raise ValueError(requested_pair_ref). Before strengthening, the isolated run measured 6 collected, 2 positive cases passed, 4 expected-AssertionError-not-raised failures, 0 errors/skips/deselections, exit 1. After the scoped Subscript/call checks and JoinedStr/FormattedValue denial were added, all four negatives and both positives passed in the final required run.

All dangerous variants are in-memory AST copies only; they were never compiled for execution, inserted into runtime files or used to rewrite real dependency namespaces. Static checks are paired with runtime call accounting and BaseException sentinels; they are not a general Python analysis framework or an authenticity proof.

### 10.5 Measured final local validation

Validation ran on Windows with Python 3.12.14 using the existing environment. Metadata for pytest 8.4.2, pytest-socket 0.8.1, Ruff 0.16.4, mypy 1.20.2, pydantic 2.13.4 and build 1.5.0 matched uv.lock. No dependency installation, frozen sync, environment reconstruction or Linux environment creation occurred. Existing conftest, strict settings and socket restrictions remained active.

The following final pytest measurements were taken after the final source/test meaning changes and formatting. No historical total was used as an execution substitute.

| Target | Collected | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| New entry test | 436 | 424 | 0 | 0 | 12 | 0 |
| Source loader test | 494 | 470 | 0 | 0 | 24 | 0 |
| Handoff test | 313 | 301 | 0 | 0 | 12 | 0 |
| Disabled inputs test | 402 | 402 | 0 | 0 | 0 | 0 |
| Descriptor test | 347 | 347 | 0 | 0 | 0 | 0 |
| Preparation/Inspection test | 593 | 554 | 0 | 0 | 39 | 0 |
| Operation-record test | 387 | 331 | 0 | 0 | 56 | 0 |
| Six required additional nodes, all parameters | 9 | 9 | 0 | 0 | 0 | 0 |
| Total | 2981 | 2838 | 0 | 0 | 143 | 0 |

Pytest exit was 0. Entry passes comprise 423 pure/mock/structural cases and one real Windows platform-gate case. Ten entry Linux native cases and two ordinary fresh-process cases were skipped and remain unexecuted locally. The existing suites' 131 OS skips are unchanged; unexpected skips were zero. The four modified consumer guards and the required related guards were actually executed and passed. The existing 494/313/402/347/593/387 collection counts were preserved.

An earlier collection attempt had one collection error, exit 2, caused by using pytest's reserved request parameter name. No product cases were executed in that attempt; it is not counted as a passing test run. A diagnostic-only hook-signature failure was also separate from product evidence. Both are distinct from the deliberate four-case structural RED and the final successful product run.

| Final static check | Result |
| --- | --- |
| Ruff check across repository | Exit 0 |
| Ruff format --check across repository | Exit 0; 278 files |
| Strict mypy on new entry | Exit 0; 1 file |
| Strict mypy on all src | Exit 0; 124 files |

The executed command forms, with private absolute locations omitted, were:

```text
.venv/Scripts/python.exe -B -c <captured in-memory pytest.main collector>
  <seven required test files and six specified nodes, all parameters>
  -q -p no:cacheprovider --basetemp ../.phase6d1h-entry-20260929-04

.venv/Scripts/python.exe -B -m ruff check . --no-cache --output-format json
.venv/Scripts/python.exe -B -m ruff format --check . --no-cache
.venv/Scripts/python.exe -B -m mypy --strict --no-incremental --cache-dir=nul --no-pretty src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_entry.py
.venv/Scripts/python.exe -B -m mypy --strict --no-incremental --cache-dir=nul --no-pretty src
```

The final pytest root was newly created for synthetic validation; previous validation roots/logs/caches were not reused or deleted. Child-process outputs and helper diagnostics were captured rather than exposing raw exceptions or personal paths. Diagnostic helper checks are not product pytest cases.

The tested runtime is 9980 bytes, SHA-256 70a061ec20133e0497e011f2ad018345a84ccf7e56de61d72706c8f41d8b6822. The tested entry test is 85487 bytes, SHA-256 45059b50a971ec2fe1f2004ddbc15f87a2f150b8bdf0144292b5e7dfb1d7d8f2. Package build and new CI were not run. Prior CI run 36425797883 concerns the existing loader and is not evidence for this entry.

### 10.6 Limits and unchanged operational status

Local Windows success does not establish the unexecuted Linux entry-to-loader connection or ordinary fresh-process cases. Even their future success would not prove installation-fixed provenance, legitimate restart configuration, durable administrative history, rollback resistance, atomic acquisition, cleanup guarantees suppressed by lower layers, crash/power-loss recovery or global startup enforcement.

The component retains a synthetic setup snapshot and provides pair-only diagnosis. Existing direct loader/factory calls remain possible; same-process hostile replacement is outside this interface constraint. No real configuration, credential, provider, deployment installer, launcher, session or operational startup path was connected. No registration, activation, retirement, record clearing, resume or recovery was implemented or approved.

This implementation/evidence task makes no commit, push, remote query, PR change or Google operation. The repository branch, fixed HEAD/tree and index are to remain unchanged. DS-04 remains PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 scan FAIL; Production gate BLOCKED; live handlers hard-off; packaged registry empty/fail-closed. Implementation stops at synthetic local validation and review material.
