# Disabled Bootstrap Policy and Independent Inspection Inputs

Status: DRAFT_WITH_UNREVIEWED_DISABLED_BOOTSTRAP_INPUT_VALIDATOR

## 1. Purpose, evidence and limits

Recommend one pure comparison component for an independently prepared, disabled bootstrap input set. It would check what the nine-field launch policy adds to the existing descriptor comparison, without reading policy files or calling Inspection. A matching set remains unapproved. For example, a policy naming target A must not become acceptable by copying target B's pending pin into its expectations.

**Implemented** below means HEAD `540e2f982c2c1c16d843f2b4f5f95bb894685d78`, tree `4dc88c1753c0969398a3547bd2270db99fc9f4dc`. **Existing proposal** means the [bootstrap contract](production-write-token-enrollment-bootstrap-contract.md), sections 3-6 and 9, [enrollment/lock design](production-write-token-enrollment-lock-design.md), section 3, and [preparation I/O contract](production-write-token-enrollment-preparation-io-design.md), sections 3 and 6. **Recommended** denotes new decisions in this document; **Open** denotes an owner decision blocking a specified later step.

The supplied external record reports PR #17 Open/Draft/unmerged and run 35989110315, attempt 1, pull_request, eight successful jobs in .github/workflows/test.yml. Reported preparation-file results are Ubuntu 593 passed/0 skipped and Windows 554 passed/39 skipped, within base totals. File progress plus fixed definitions is not a list of individually observed passing node IDs. These inherited results cover synthetic preparation/Inspection, not deployment, a controlled launcher or this document. No remote query or tests occurred here. Earlier DRAFT/unverified labels remain historical. Original scan-finding text was not consulted; no audit closure or new Unit number follows.

Verified implementation references:

| Source at fixed HEAD | Relevant existing contract |
| --- | --- |
| [descriptor module](../src/tridentine_calendar_google_sync/production_write_token_enrollment_descriptor.py), SyntheticEnrollmentExpectation, 50-64 | Eleven mandatory synthetic fields; no CONTROL_ROOT field or approval evidence. |
| Same, validate_enrollment_descriptor, 231-256; EnrollmentDescriptorResult, 67-76 | Checks expectation consistency before candidate comparison; returns fixed classifications, never decoded metadata or authority. |
| [preparation module](../src/tridentine_calendar_google_sync/production_write_token_enrollment_preparation.py), _snapshot, 310-324 | Copies eleven fields, invokes the public validator, restricts expectations to PREPARING. This private helper is evidence, not a dependency for the candidate. |
| Same, inspect_synthetic_enrollment_preparation, 1006-1031 | Requires independent control_root, expected_raw and expectation before acquiring the lock. |
| [Inspection design](production-write-token-enrollment-preparation-inspection-design.md), sections 3-6 and 9-10 | Separates presence, content and targets; retains negative evidence; records bounded observation and comparison limitations. |
| [baseline registry](../src/tridentine_calendar_google_sync/accepted_production_baseline_registry.py), load_packaged_accepted_production_baseline_registry and active_accepted_production_baseline_pin, 285-317 | Package-pinned source-calendar baseline governance; fails closed without an active baseline. It is not enrollment configuration or approval storage. |

## 2. Supply the missing inputs explicitly

The nine proposed policy keys are format_version, policy_kind, control_root, descriptor_slot, administrative_pending_slot, expected_revision, descriptor_pin, expected_state and entry_mode. Only five correspond to expectation fields. Six expectation fields and the complete expected descriptor bytes are missing.

Use three independently retained materials: the unchanged nine-field policy; complete canonical expected descriptor bytes; and a reviewed metadata/layout plan supplying all eleven expectation fields plus the intended CONTROL_ROOT. These are material roles, not newly implemented files or persistence schemas. A synthetic harness supplies them directly in memory.

In the table, **P** prepares an offline candidate from the destination plan; **O** is the deployment owner who verifies the exact combination independently of the records under inspection. Separate OS accounts or separate people are not assumed.

| Required input | In nine-field policy? | Additional independent material | Creator / verifier | Missing or inconsistent: stop | Not established by this input |
| --- | --- | --- | --- | --- | --- |
| Policy constants and disabled mode | Yes: format_version, policy_kind, entry_mode | Reviewed policy contract | Maintainer/P; O | Policy validation, before observation | Deployed enforcement |
| Inspection control_root | Yes | Intended CONTROL_ROOT from the layout plan, supplied separately as expected_control_root | P; O | Exact root comparison | Filesystem identity/provenance |
| Complete expected_raw | No | Entire offline canonical twelve-key descriptor, including final LF; retained before target inspection | P; O | Independent-input validation | Authenticity or freshness |
| enrollment_revision, administrative_state | Yes, under expected_revision/expected_state | Same values in independent expectation and bytes | P; O | Public validation/cross-comparison | Ordering or activation |
| storage_ref, pair_ref | No | Reviewed destination metadata | P; O | Public validation | Provider identity |
| artifact_directory | No | Intended PAIR_ROOT metadata | P; O | Public validation | Actual directory binding |
| token_slot, state_slot | No | Reviewed pair layout | P; O | Public validation | Safe files or credential validity |
| active_intent_slot | No | Reviewed control layout | P; O | Public validation/collision checks | Existing or authentic intent |
| descriptor_pin | Yes | Independently retained digest of the full expected canonical bytes | P; O | Public validation/cross-comparison | Approval or rollback resistance |
| descriptor_slot, administrative_pending_slot | Yes | Same two leaves in independent expectation/layout | P; O | Exact cross-comparison | Prior publication or pending resolution |

The descriptor's twelve keys include fixed format, kind, role and record_slot. They do not include CONTROL_ROOT, descriptor_slot or administrative_pending_slot. The latter two belong to the expectation's control layout; artifact_directory names PAIR_ROOT, not CONTROL_ROOT. Never compare those roots as if they were aliases. A matching descriptor pin cannot cover omitted control-location fields.

**Alternatives:** expanding policy with the six missing metadata fields still requires complete expected bytes or a new construction contract, and changes the existing closed schema. Learning expectations from CONTROL_ROOT is rejected outright. The recommended companion-material approach preserves all nine keys and existing descriptor/pending schemas. The separate expected_control_root is a new mandatory synthetic API input, not a tenth policy key. Companion locations are a future installation decision; the policy gains no discovery or alternate-file fields.

## 3. Authority and disabled deployment

Keep three claims separate: (1) syntax is valid; (2) independently supplied materials agree; (3) the exact set has legitimate, independently verified deployment provenance. The proposed pure component establishes only the first two. Separate files, private permissions, hashes, ownership by the same user, a trusted-looking type or approved=True do not establish the third. Repository test RAW constants remain synthetic fixtures.

**Recommended future deployment contract:** P creates candidate policy, descriptor bytes and layout assertions outside the inspected store. O reviews the full bytes and all metadata together, checks the LF-inclusive pin, and selects the exact combination for installation. The deployer acts under O's separately established procedure; deployment is not inferred from comparison success.

A controlled launcher must obtain the policy, expected-byte companion and layout assertions from installation-fixed locations outside ordinary request selection. The installation definition must fix all three sources and the expected control location; neither the descriptor nor pending chooses them. No command-line path override, environment override, alternate configuration, search order, current-directory discovery or older-version fallback is accepted. A requested pair must match the selected plan and cannot select another configuration set.

Restart repeats the same controlled route and comparison. Missing, unreadable or unverifiable companions stop before CONTROL_ROOT observation, intent/START, credentials, providers or writers. Never fill missing bytes, revision or pin from inspected records. Partial installation stays disabled and unavailable until separately reviewed; no atomic deployment or crash durability is promised.

entry_mode=disabled means that managed operational entry is not permitted. It is not a switch that comparison success can turn on. The next candidate has no enabled value, activation callback or session result. No launcher is connected, so this component cannot be reported to have stopped actual startup.

**Open:** O must choose installation ownership, locations, review/release procedure and how provenance is checked; maintainers must approve the enforcing launcher boundary. These block real deployment/integration, not synthetic comparison. Stronger same-user or rollback guarantees may require a separately approved trust domain, key, service or freshness anchor. None is assumed present. Do not populate or import the Accepted Production Baseline Registry for this purpose.

## 4. Policy format retained from the proposal

Propose exact bytes of length 1-8192, checked before decoding, containing one closed flat JSON object with exactly the nine keys. format_version is exact int 1, never bool or float; policy_kind is enrollment_bootstrap. Every other value is an exact string. Reject duplicate keys, including escaped equivalents, extra/missing keys, nested values, null, nonfinite numbers, malformed UTF-8, BOM and surrogate code points.

Canonical bytes use sorted keys, ASCII escaping, compact separators, no nonfinite values, UTF-8 and exactly one final LF. Re-encoding must equal supplied bytes and remain within the bound. No whitespace or newline repair is allowed.

control_root obeys the existing proposed Linux lexical rules: absolute and non-root, at most 1024 UTF-8 bytes; no backslash, colon, repeated/trailing separator, Cc/Cs characters, dot/parent/.git components, or components ending in space/dot. References use 1-96 ASCII characters, alphanumeric first, then alphanumeric/dot/underscore/hyphen. Leaves additionally reject trailing dots and reserved Windows device-name bases, including extensions. The two control leaves must differ. descriptor_pin is exactly 64 lowercase hex characters. The existing public validator checks the expectation's additional active-intent collision constraints.

expected_state is syntactically PREPARING, ACTIVE or REVOKED. The candidate admits only coherent PREPARING for this Inspection-input purpose. Matching ACTIVE/REVOKED remains outside that purpose, never a way around Inspection's PREPARING restriction. Matching REVOKED does not prove revocation enforcement.

Only disabled is an accepted entry_mode. Distinguish a well-typed canonical non-disabled value from malformed policy, but refuse both. Revision, pin and state are compared as one immutable combination; no partial update or normalization API exists. These are proposed policy-parser rules, not claims that such a parser is implemented. The descriptor's twelve keys, pending's five keys and current writer/Inspection APIs remain unchanged.

## 5. One proposed pure API and ordered results

Proposed signature, not an existing API:

```python
validate_disabled_bootstrap_inputs(
    policy_raw: object,
    expected_raw: object,
    expectation: object,
    *,
    expected_control_root: object,
) -> DisabledBootstrapInputResult
```

No source path, loader, callback, provenance Boolean or history argument is accepted. Strings describing Linux locations remain lexical data on either test OS; no Path construction or filesystem access is needed.

| Stage | Proposed check and retained input | Stop/result |
| --- | --- | --- |
| 1: capture | Check exact bytes and 1-8192 bounds for policy/expected bytes; exact string/bound for expected_control_root; exact SyntheticEnrollmentExpectation and eleven exact-string fields before hooks/comparison. Copy fields once into a private expectation; retain immutable byte/string references. | Bad policy envelope: POLICY_UNVERIFIABLE; other missing/uncheckable inputs: INPUTS_UNVERIFIABLE. |
| 2: policy | Strict schema, lexical fields and canonical encoding; then disabled-only check. | POLICY_UNVERIFIABLE or ENTRY_MODE_REFUSED. |
| 3: descriptor | Call only validate_enrollment_descriptor(expected_raw, retained_expectation). It checks expected metadata/pin self-consistency and full candidate metadata plus digest. | EXPECTATION_UNVERIFIABLE/DESCRIPTOR_UNVERIFIABLE map to INPUTS_UNVERIFIABLE; ENROLLMENT_MISMATCH maps to INPUTS_MISMATCH. |
| 4: cross-input | Compare policy root to retained expected_control_root; its two slots, revision, pin and state to the corresponding retained expectation fields. No pin-only shortcut. | INPUTS_MISMATCH. |
| 5: purpose | Require coherent expected_state PREPARING. | STATE_OUT_OF_SCOPE for ACTIVE/REVOKED. |
| 6: finish | Finish against that same private snapshot, without rereading caller objects or substituting another input version. | INPUTS_MATCHED_UNAPPROVED. |
| Future boundary | Independently verified deployment and separately authorized read adapter would precede any actual Inspection call. | Unimplemented; public comparison success does not cross it. |

Stages stop at the first applicable refusal. Missing slots and ordinary capture/validation failures receive the stage's fixed classification; input hooks and exception text never become diagnostics. Cancellation propagates. Retaining known upper-layer failures is a separate obligation, not overwritten by this ordering.

DisabledBootstrapInputResult would be a frozen/slotted public value containing only a new closed state enum and constructor-excluded reuse_authorized: Literal[False]. The six classifications above are separate from writer, validator and Inspection enums. Return no credentials, session, permit, approved object, raw bytes, paths, pins or metadata; repr/errors contain only fixed text.

The private snapshot prevents ordinary validate-then-reread substitution. It is not an authenticated capability, exported handoff object, module-global cache or proof against hostile same-process mutation. The pure candidate needs it only for one comparison. Any later adapter must own one immutable captured set, validate and consume those same values internally; it must not reconstruct inputs from the public result. No such adapter or snapshot-export API is included.

There is no expectation-only public validator to assume. Comparing the separately supplied complete expected bytes with the existing public validator is sufficient. Policy-only parsing and cross-input constraints are new work; borrowing private descriptor parsers, _snapshot or duplicating the descriptor schema is unnecessary.

## 6. Partial updates, refusal and restart limits

Deployment/history classifications below describe future gates, not additional pure-result fields.

| Observable condition | Fixed refusal or nonapproval | Stop position | Unknown |
| --- | --- | --- | --- |
| Policy only; expected descriptor missing | INPUTS_UNVERIFIABLE | Stage 1 | Intended bytes/history |
| Expected descriptor only; policy origin unverified | POLICY_UNVERIFIABLE if absent; otherwise deployment remains unverifiable even if comparison matches | Before target reads | Legitimate origin |
| Old policy/new expected descriptor | INPUTS_MISMATCH when the retained assertions expose disagreement; malformed/self-inconsistent inputs are unverifiable | Stages 3-4 | Which version is approved |
| New policy/old expected descriptor | Same refusal rules | Stages 3-4 | Update completion |
| Equal revision, different pin | INPUTS_MISMATCH or INPUTS_UNVERIFIABLE for internally inconsistent expectations | Stages 3-4 | Chronological order |
| Equal pin, different root/slots/metadata | Root/control-slot mismatch at stage 4; metadata mismatch or inconsistent expectation at stage 3 | Before observation | Physical identity |
| Different canonical spelling or final LF | POLICY_UNVERIFIABLE or INPUTS_UNVERIFIABLE | Stages 2-3 | Whether any deployment succeeded |
| Canonical non-disabled mode | ENTRY_MODE_REFUSED | Stage 2 | Actual launcher enforcement |
| Everything agrees, no independent approval/provenance | INPUTS_MATCHED_UNAPPROVED; deployment gate unresolved | Before real observation/use | Authority |
| Entire coherent old set restored | Possibly INPUTS_MATCHED_UNAPPROVED | No use authorized | Rollback/freshness |
| Caller selects another root/configuration | Disallowed future override; mismatch if independent anchors survive; otherwise a coherent replacement may compare equal | Launcher boundary/stage 4 | Same-user substitution |
| Known ADMIN_PENDING, ADMIN_COMMIT_UNCERTAIN or ADMIN_REVOKED survives | Preserve that upper refusal, regardless of comparator result | Before continuation | Unretained historical details |

The comparator neither accepts nor reconstructs history. Its output cannot clear any recognized administrative refusal. Absence of an unfinished record is not initial-enrollment permission. Do not infer earlier writer publication/exit results, completion or retry eligibility from matching inputs. A coherent rollback of policy, bytes and all expectations is undetectable without an independent freshness anchor; mtime, current time and revision-label ordering are not substitutes.

## 7. One next implementation candidate

Recommend **Synthetic Disabled Bootstrap Input Validator**, limited to pure supplied-input comparison. It adds closed policy parsing, disabled/purpose gates, root/control-slot cross-checks and private snapshot discipline to the existing descriptor comparison. It performs zero file/network/provider/credential access and never imports or calls preparation, Inspection, record, lock, publisher, private reader, registry, CLI or session modules.

Proposed paths, not created by this design:

| Future file | Exact change |
| --- | --- |
| src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_inputs.py | New pure API/result above; standard library plus the descriptor module's public expectation, result-state enum and validator only. |
| tests/test_token_disabled_bootstrap_inputs_phase6d1h.py | New synthetic positive/negative, snapshot, diagnostic and isolation tests. |
| tests/test_token_enrollment_descriptor_phase6d1h.py | One exact consumer-set addition described below; preserve every other assertion and existing case. |
| docs/production-write-token-disabled-bootstrap-input-design.md | Later limited implementation/evidence append; retain this draft as history. |

The actual [descriptor guard](../tests/test_token_enrollment_descriptor_phase6d1h.py), test_only_pure_standard_library_dependencies_and_only_approved_runtime_consumer, 573-621, currently ends with:

```python
assert consumers == {"production_write_token_enrollment_preparation.py"}
```

Future authorization must permit adding exactly production_write_token_disabled_bootstrap_inputs.py to that set. Keep the purity checks at 591-615 and consumer scan at 616-620 unchanged; use no wildcard, hidden dependency or dynamic import.

Keep these inspected guards unchanged:

- [preparation tests](../tests/test_token_enrollment_preparation_phase6d1h.py), test_component_imports_exact_public_boundaries_and_has_no_runtime_consumer, 1119-1178: no new preparation consumer.
- [record tests](../tests/test_token_operation_record_phase6d1h.py), test_only_exact_reviewed_modules_directly_import_lock_and_publisher, 392-415, and test_component_has_no_runtime_consumer_or_dynamic_import_and_no_mutation_escape, 418-487.
- [lock tests](../tests/test_posix_private_lock_phase6d1h.py), test_component_has_no_artifact_write_no_wait_loop_and_only_approved_consumers, 411-443.
- [directory tests](../tests/test_posix_sensitive_directory_phase6d1h.py), test_directory_foundation_only_has_the_reviewed_backend_consumers, 351-410.

Lock consumers stay three and publisher consumers four excluding the publisher; no new private-reader consumer is needed. Existing writer/Inspection/record implementations and their field schemas remain unchanged. The new module needs its own exact-dependency and no-runtime-consumer guard.

Acceptance requires malformed types/poison objects/bounds/schema/canonical tests; every nine-key and independent-input omission/mix/contradiction; all mode/state combinations; unchanged false authorization; fixed diagnostics; and safe snapshot behavior when the original caller object is replaced or mutated after capture. Test that target-record content is never consulted and that changing all caller-controlled inputs can match without becoming trusted. Verify filesystem/network/provider/credential calls remain zero through structural checks and spies.

Future regression scope includes all 593 preparation/Inspection, 347 validator and 387 record cases plus relevant guards, under existing Python 3.12 strict/socket settings, Ruff, strict mypy and applicable workflow checks. Pure comparison success proves neither deployment, Linux storage nor restart durability. Stop implementation if extra runtime consumers, private helper borrowing, schema changes, real inputs or broader edits become necessary; do not weaken guards.

## 8. Decisions and completion boundary

Maintainers must approve the four-input API, mandatory independent root assertion, six result classes, ordering and exact four-file future scope. The user must separately authorize implementation. This is a bounded implementation candidate; no further design phase is needed merely to subdivide it.

O owns controlled locations, companion-source provenance and exact-set review/deployment procedure before any real read adapter. Maintainers own launcher enforcement and immutable handoff before startup connection. O and maintainers must explicitly choose the same-user/rollback threat scope before operational claims; stronger anchors remain separate options. Activation, pending disposition, reconciliation, normal closure and all-writer participation still block operational use.

Only this document is created. No application import, execution, test, I/O probe, deployment, commit, push or PR change is performed. DS-04 remains PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 scan FAIL; Production gate BLOCKED; live handlers hard-off; packaged registry empty/fail-closed; PR #17 Draft in inherited evidence. Nothing here authorizes implementation or credential use.

## 9. Unreviewed synthetic disabled-input validator prototype

This separately authorized prototype implements the supplied-input comparison described above. Sections 1-8 remain the design record, including their then-current document-only statements. The exact refusal priority and defensive result checks below are implementation decisions for this prototype, not guarantees that existed at the design stage. No deployment or runtime observation adapter is added.

### 9.1 Implemented interface and isolation

validate_disabled_bootstrap_inputs(policy_raw, expected_raw, expectation, *, expected_control_root) has four required inputs and no defaults. DisabledBootstrapInputState contains exactly POLICY_UNVERIFIABLE, INPUTS_UNVERIFIABLE, ENTRY_MODE_REFUSED, INPUTS_MISMATCH, STATE_OUT_OF_SCOPE and INPUTS_MATCHED_UNAPPROVED. The frozen/slotted DisabledBootstrapInputResult contains only state and constructor-excluded reuse_authorized: Literal[False]. An invalid state is rejected with the fixed ValueError("Invalid disabled bootstrap input result").

The policy retains exactly nine keys. Its revision/state/pin and two control leaves correspond to five of the eleven expectation fields. Complete expected descriptor bytes, the six remaining metadata fields and the independently supplied expected CONTROL_ROOT remain mandatory separate inputs. CONTROL_ROOT and PAIR_ROOT have distinct input roles; this pure comparison proves no physical separation. Descriptor-pin agreement does not replace either root comparison or either control-slot comparison.

The new runtime module imports only __future__, dataclasses, enum, json, typing and unicodedata, plus SyntheticEnrollmentExpectation, EnrollmentDescriptorState and validate_enrollment_descriptor from the descriptor module. No descriptor parser, private constant, digest function or preparation helper is borrowed. There is no filesystem, network, provider, credential, environment, clock, random, logger or process operation, and no external runtime consumer of the new module.

The existing descriptor test's final consumer assertion now contains exactly production_write_token_enrollment_preparation.py and production_write_token_disabled_bootstrap_inputs.py. That filename addition and its necessary formatting are the only existing tracked-code change. Its original purity checks, scan, other assertions and 347 cases are preserved. Preparation, record, lock, publisher, reader and directory consumer boundaries remain unchanged.

### 9.2 Capture, semantic validation and first-refusal priority

Capture checks representation without claiming semantic consistency. It obtains the eleven fixed field names once, verifies exact strings, and constructs a fresh private SyntheticEnrollmentExpectation. Exact bytes and the independent root string are retained without conversion. Both private dataclasses hide every field from repr. Parsed policy remains local; the original expectation is never reread after capture. No snapshot, input, pin, path, detailed exception or approval object is returned or retained globally.

| Order | Actual check | Fixed refusal |
| --- | --- | --- |
| 1 | Exact policy bytes, length 1-8192; no other input is touched on refusal | POLICY_UNVERIFIABLE |
| 2 | Exact expected bytes and bound, then exact independent root and all lexical rules, then exact expectation type and eleven exact-string fields | INPUTS_UNVERIFIABLE |
| 3 | Complete policy schema, lexical constraints and canonical byte equality, followed by exact disabled mode | POLICY_UNVERIFIABLE for format defects; ENTRY_MODE_REFUSED only after those checks pass |
| 4 | Existing public descriptor comparison against the retained expectation | Its expectation/descriptor refusals map to INPUTS_UNVERIFIABLE; mismatch maps to INPUTS_MISMATCH; only matched-unapproved continues |
| 5 | Exact root, two control slots, revision, pin and state comparisons | INPUTS_MISMATCH; an ordinary comparison failure or invalid comparison result yields INPUTS_UNVERIFIABLE |
| 6 | Purpose check after all equality checks | Coherent ACTIVE/REVOKED yields STATE_OUT_OF_SCOPE; coherent disabled/PREPARING yields INPUTS_MATCHED_UNAPPROVED |

A bad policy envelope wins over poisoned other inputs. A valid envelope with uncapturable expectations yields INPUTS_UNVERIFIABLE before policy-body parsing. Invalid schema/canonical bytes take precedence over a non-disabled-looking mode. A well-formed non-disabled policy is refused before descriptor semantic validation, including an inconsistent expectation pin. Policy-only ACTIVE against PREPARING expectations is a mismatch; coherent ACTIVE is out of scope. These rules do not accept history or clear ADMIN_PENDING, ADMIN_COMMIT_UNCERTAIN or ADMIN_REVOKED.

Policy parsing rejects every missing/extra/duplicate key, including escaped duplicates, wrong exact types, malformed encoding, BOM, surrogates, nonfinite constants and noncanonical bytes. Size is bounded before parse and after encoding. No normalization repairs root, reference, slot, mode, state or newline spelling. Descriptor schema and digest checking remain delegated to the existing public API.

Ordinary exceptions become the current stage's fixed refusal. KeyboardInterrupt and SystemExit propagate. The dependency's state is checked as an exact EnrollmentDescriptorState and its reuse_authorized must be False; missing fields, unknown states and malformed values refuse. These public-field checks do not attest concrete dependency-object identity or defend against arbitrary hostile code in the same process.

### 9.3 Initial-draft corrections and regression coverage

The resumed initial draft reproduced one E501, a formatting failure, two redundant-cast findings and one unreachable finding. The two casts were redundant because policy root/revision had already been narrowed by their exact-type lexical checks; removing them preserved those checks. The unreachable branch checked the result of a bool-annotated private comparison directly. The implementation now validates it through an object-parameter boundary, retaining refusal of None, integers and poison values. A separate object-parameter boundary checks dependency state/authorization. Neither fix adds Any, an ungrounded cast, an ignore or a relaxed type-check setting.

New tests cover the complete contract with independent hardcoded canonical fixtures and standard-library encoding/digest calculations:

| Contract | Representative new tests |
| --- | --- |
| Four required inputs, six states, independent canonical fixtures | test_independent_fixtures_and_exact_public_contract |
| Policy/expected envelope priority and bounded malformed bodies | test_policy_envelope_precedes_capture_and_every_other_input; test_expected_envelope_precedes_root_fields_and_policy_parse; test_in_bound_bytes_do_not_bypass_policy_or_descriptor_schema |
| Every policy key, duplicates, exact types, canonical encoding | test_every_policy_key_is_required; test_every_policy_duplicate_key_is_refused; test_every_policy_field_rejects_wrong_json_types; test_policy_schema_encoding_and_canonical_refusals |
| Root byte limits, components and nonnormalization; safe leaves | test_root_lexical_constraints_apply_independently; test_valid_roots_retain_exact_spelling_without_os_normalization; test_policy_slots_reject_unsafe_or_reserved_leaves |
| Eleven-field capture, missing slots and semantic inconsistency | test_all_expectation_fields_require_exact_strings_before_policy_parse; test_each_missing_expectation_slot_is_unverifiable; test_expected_metadata_must_be_internally_consistent |
| All six comparisons and distinct root roles | test_every_cross_input_field_is_compared_even_when_descriptor_matches; test_control_root_and_pair_root_are_distinct_and_not_normalized |
| Mode/state combinations and simultaneous defects | test_coherent_mode_and_state_combinations_remain_unapproved; test_first_refusal_priority_for_simultaneous_defects |
| Retained input identity and original-object mutation | test_snapshot_and_same_input_bytes_survive_original_object_mutation |
| Invalid dependency/comparison results and cancellation | test_malformed_public_validator_results_fail_closed; test_cross_comparison_requires_an_exact_boolean; test_failures_keep_stage_and_cancellation_without_diagnostics |
| Fixed results, no runtime effects, exact public dependencies/consumers | test_result_is_exact_frozen_two_fields_without_input_in_repr; test_no_io_or_output_during_validation_call; test_closed_public_dependencies_no_effects_and_exact_consumers |

The structural test additionally constrains getattr to the fixed-field capture comprehension. Test-only source reads and fault-injection monkeypatches are not runtime inputs. The public API gains no test callback. Successful matching of a coherent older or caller-controlled set stays unapproved.

### 9.4 Local validation record

Validation used Windows / Python 3.12.14 and confirmed this repository's source module. Installed pytest 8.4.2, pytest-socket 0.8.1, Ruff 0.16.4, mypy 1.20.2, pydantic 2.13.4 and build 1.5.0 metadata were freshly compared with uv.lock and matched. This was metadata verification, not frozen installation; no dependencies or environments were rebuilt.

Before rerunning product checks, an in-memory work wrapper captured both child output streams and emitted only allowlisted diagnostic fields. Unknown formats withheld details; nonzero exits remained failures. Explicit UTF-8 byte handling avoided locale-dependent diagnostic parsing. Its final synthetic self-test had 36 passing cases and zero failures, including path shapes, hidden fields, malformed output, exceptions, nonzero child exit and parameter omission. This count is separate from pytest. No persistent runner or raw diagnostic log was created, and this does not undo the earlier display incident.

The final pytest run used the existing interpreter with -B, an in-memory collector, -q, -p no:cacheprovider and a previously absent permitted synthetic --basetemp location. Project conftest, strict configuration/markers and socket prohibition stayed active.

| Executed target | Collected | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| New disabled-bootstrap test file, complete | 402 | 402 | 0 | 0 | 0 | 0 |
| Descriptor test file, complete | 347 | 347 | 0 | 0 | 0 | 0 |
| Preparation/Inspection test file, complete | 593 | 554 | 0 | 0 | 39 | 0 |
| Operation-record test file, complete | 387 | 331 | 0 | 0 | 56 | 0 |
| Specified private-lock guard | 1 | 1 | 0 | 0 | 0 | 0 |
| Specified directory guard | 1 | 1 | 0 | 0 | 0 | 0 |
| Specified eager network/Google/OAuth import guard | 1 | 1 | 0 | 0 | 0 | 0 |
| Total | 1732 | 1637 | 0 | 0 | 95 | 0 |

Pytest exited 0. The 95 skips were verified as the existing native-Linux preparation/record conditions; the new pure tests have no OS skips. All seven required structural checks actually ran and passed: descriptor consumers; preparation dependencies/isolation; record lock/publisher sets; record isolation/mutation restrictions; lock consumers; directory consumers; and eager network imports. Existing 347/593/387 case counts are retained. No earlier run's totals are added.

Final Ruff check . --no-cache --output-format json and Ruff format --check . --no-cache exited 0; formatting covered 269 files. Strict mypy with --strict --no-incremental --cache-dir=nul --no-pretty exited 0 for the new module and all 121 src files. Two new-test SIM300 findings were corrected by reversing the operands of equivalent digest comparisons without removing assertions. Full required pytest and static checks were rerun after those corrections and the fixed-getattr assertion. Earlier static failures are not final validation results.

git diff --check, the complete permitted guard diff, untracked-file content/whitespace/privacy review, unchanged original document sections, HEAD/index preservation and exact change scope were checked separately. Review material is generated from current files and the retained starting document, without creating extra source copies or runners.

Status: IMPLEMENTED_LOCAL_CHECKS_PASSED_REVIEW_PENDING. This pure component has no OS-specific I/O. New-component execution on Linux and new CI were not performed; old run 35989110315 does not cover it. Real policy/companion deployment, controlled launcher enforcement, actual Inspection calls, authenticity and freshness remain unimplemented. No commit, push, PR change, registration, activation, revocation enforcement, record clearing, resume, recovery or Google operation occurred. Existing blocked Production and audit states remain unchanged.
