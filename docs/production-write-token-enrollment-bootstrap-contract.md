# Initial Enrollment Bootstrap and Activation Contract

Status: DRAFT_WITH_UNREVIEWED_SYNTHETIC_VALIDATOR_PROTOTYPE

## 1. Baseline and scope

This draft specifies initial enrollment of one new production-write pair on Linux, assuming cooperating processes and a trusted local administrator. Enrollment describes approved destinations; it does not authorize credential use. For example, matching a prepared descriptor after an interrupted save cannot retire the administrative obligation that preceded it.

**Current** means source inspected at HEAD `e67ac39913afe2414add0ea3b64c3aee84de512e`, tree `f8aab768a1de62e7ae0f3bbeb415524ff2a35602`. **Existing proposal** means the [enrollment/lock design](production-write-token-enrollment-lock-design.md), especially sections 3 and 5-8, or [operation-record design](production-write-token-operation-record-design.md). **Proposed here** means this contract. **Open** identifies decisions blocking later work, not permission to implement.

The supplied external record reports subsequent review and publication of the held-lock/entry correction, PR #17 Open/Draft/unmerged, and successful eight-job CI run 35736574068, attempt 1. Reported record-file totals are Ubuntu 387 passed/0 skipped and Windows 331 passed/56 skipped, included in base totals. File progress and fixed definitions do not enumerate individual passing node IDs. Historical DRAFT/Linux-unverified labels in existing documents remain development history. No remote query or test was performed here; that CI covers neither this document nor unimplemented enrollment, activation, intent or integration.

Original scan-finding text was not consulted. No audit closure follows. No new Unit number is assigned.

## 2. Current implementation evidence

Paths and symbols below were checked at the fixed HEAD; older documents' line numbers are not reused.

| Repository-relative source | Current boundary |
| --- | --- |
| [src/tridentine_calendar_google_sync/production_write_token_operation_record.py](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py), `_record_data` 159-173, `_matches_start_record` 209-234, `read_start_record` 696-699 | START compares supplied binding/operation; no enrollment revision exists in its bytes. |
| Same module, `_RecordScopeContext.__enter__` 372-457, `_record_scope` 519-544, `_storage_call` 653-687 | Owns one directory; initial-entry failure is terminal. Revision is synthetic memory metadata. Public success follows scope exit. |
| [tests/test_token_operation_record_phase6d1h.py](../tests/test_token_operation_record_phase6d1h.py), `test_initial_entry_fault_is_terminal_after_injection_is_removed`, `test_entry_scope_issuance_fault_unwinds_once_and_stays_terminal` | Existing regression definitions; not rerun here. |
| [src/tridentine_calendar_google_sync/production_write_token_reuse_policy.py](../src/tridentine_calendar_google_sync/production_write_token_reuse_policy.py), `evaluate_reuse_policy`; [pair inspector](../src/tridentine_calendar_google_sync/production_write_token_pair_inspection.py), `inspect_production_write_token_pair` | Synthetic history and local observations remain nonauthorizing. |
| [src/tridentine_calendar_google_sync/sensitive_paths.py](../src/tridentine_calendar_google_sync/sensitive_paths.py), `read_private_sensitive_bytes`; [private create](../src/tridentine_calendar_google_sync/_posix_private_create.py), `create_posix_private_bytes`; [private lock](../src/tridentine_calendar_google_sync/_posix_private_lock.py), `acquire_posix_private_directory_lock` | Bounded private reads, create-only publication and cooperative Linux locking; no enrollment authority. |
| [src/tridentine_calendar_google_sync/accepted_production_baseline_registry.py](../src/tridentine_calendar_google_sync/accepted_production_baseline_registry.py), `load_packaged_accepted_production_baseline_registry`, `active_accepted_production_baseline_pin` | Source-baseline authority, not credential enrollment; do not reuse or populate it for enrollment. |

Private reads enforce owner-only access, not exact creation mode or atomic ancestry binding. Suppressed close errors in [`_BoundPrivateDirectory.close`](../src/tridentine_calendar_google_sync/_posix_sensitive_directory.py) remain unobservable. Neither checkpoint nor normal return proves power-loss durability.

## 3. Independent bootstrap authority

**Proposed here:** the deployment owner selects the expected CONTROL_ROOT, descriptor slot, revision and pin during offline review. The owner reviews candidate metadata, computes its pin, and deploys a separate Operator-approved launch policy through controlled installation. Computing a candidate hash is preparation; independently approving and retaining that exact expectation is the authority assumption.

A controlled launcher must read one installation-fixed policy location, verify its deployment provenance and private access policy, then supply immutable expectations. Ordinary session callers may select only the enrolled pair reference and a permitted action; they cannot override roots, slots, revision, pin, administrative state or operation expectations through arguments, environment variables or alternate configuration.

Restart uses that same installation route, never a descriptor-selected policy or a pin computed from the descriptor being checked. Missing, corrupt or unverifiable launch policy stops before descriptor/intent/START access, credential loading, provider calls and writers. A Boolean named approved or a trusted-looking type supplies no approval evidence.

**Open:** the owner must approve installation ownership, review/deployment procedure and how the launcher verifies that procedure. The launcher does not exist. Until then, supplied expectations test only synthetic comparisons.

Separate files/directories owned by the same OS user are not separate trust domains. This design addresses ordinary interruption and cooperating mistakes, not malicious administrator replacement or coherent rollback of all local anchors. Stronger guarantees require separately approved authority; no service, database, signing key or external monotonic counter is assumed.

## 4. Minimal data and exact pin

**Proposed here:** include administrative state inside the pinned descriptor. Each revision is immutable. PREPARING, ACTIVE or REVOKED changes require a new revision, new canonical bytes/pin and separately approved launch-policy tuple. Revision labels are equality references, not sequence numbers.

Reject a separate mutable active/revoked record: it adds another authority and publication boundary. The separate administrative-pending obligation below records unfinished preparation; it is not an alternative active-state authority.

In the tables, **O** is the deployment owner, **C** the future controlled coordinator. Every listed field is required. All values stay private; public diagnostics expose only fixed classifications, never field values or hashes. Grouped fields share the stated rules.

### Launch policy

The installation-controlled policy is independently retained, not discovered from CONTROL_ROOT.

| Fields | Setter; expectation source | Mutability and comparison | Defect classification |
| --- | --- | --- | --- |
| `format_version=1`, `policy_kind=enrollment_bootstrap` | Maintainer; reviewed contract | Fixed; exact type/value | POLICY_UNVERIFIABLE |
| `control_root` | O; approved deployment | Immutable per deployment; exact lexical and future filesystem binding | POLICY_UNVERIFIABLE |
| `descriptor_slot`, `administrative_pending_slot` | O; deployment plan | Fixed distinct leaves; never directory search | POLICY_UNVERIFIABLE |
| `expected_revision`, `descriptor_pin`, `expected_state` | O; independently approved candidate | Replace only as one reviewed deployment tuple; exact equality | POLICY_UNVERIFIABLE |
| `entry_mode=disabled` | O; this contract | Fixed; no enabling value supported | POLICY_UNVERIFIABLE |

### Enrollment descriptor

Stored only in the designated CONTROL_ROOT descriptor slot.

| Fields | Setter; expectation source | Mutability and comparison | Defect classification |
| --- | --- | --- | --- |
| `format_version=1`, `record_kind=enrollment_descriptor` | Maintainer; contract | Fixed; exact type/value | DESCRIPTOR_UNVERIFIABLE |
| `enrollment_revision` | O; launch expectation | Immutable; exact revision equality | ENROLLMENT_MISMATCH |
| `administrative_state` | O; expected PREPARING/ACTIVE/REVOKED | Immutable within revision; exact equality | ADMIN_CONFLICT |
| `storage_ref`, `pair_ref` | O; reviewed destination plan | Immutable; pin binds both; caller pair must match | ENROLLMENT_MISMATCH |
| `role=production_write` | Maintainer; contract | Fixed; exact value | DESCRIPTOR_UNVERIFIABLE |
| `artifact_directory` | O; approved PAIR_ROOT | Immutable; exact spelling plus future bound-directory checks | BINDING_MISMATCH |
| `token_slot`, `state_slot`, `record_slot` | O; approved layout | Immutable distinct leaves; record slot equals existing RECORD_LEAF | BINDING_MISMATCH |
| `active_intent_slot` | O; approved control layout | Immutable leaf in CONTROL_ROOT; distinct from descriptor/pending slots | BINDING_MISMATCH |

The pin is exactly 64 lowercase hexadecimal characters representing SHA-256 of **the entire canonical descriptor byte sequence, including its final LF and administrative_state**, with exactly the fields above. The pin itself is absent from those bytes. It contains no credential-derived material. State, revision and digest must all agree with the independent launch tuple; partial deployment is not accepted.

### Administrative state and unfinished preparation

| Item and storage role | Setter; expectation source | Mutability and comparison | Defect classification |
| --- | --- | --- | --- |
| PREPARING/ACTIVE/REVOKED in descriptor | O; launch tuple | Pinned immutable state; ACTIVE is administrative only | ADMIN_CONFLICT or ADMIN_REVOKED |
| Pending obligation in launch-selected CONTROL_ROOT slot: `format_version=1`, `record_kind=enrollment_preparation`, `target_revision`, `target_pin`, `outcome=pending` | O's future preparation procedure; independent approved target tuple | Create-only, retained; exact target comparison; no automatic retirement | ADMIN_PENDING; mismatch ADMIN_CONFLICT; missing/unreadable ADMIN_UNKNOWN |

### Independently retained active intent

Stored in the descriptor-selected CONTROL_ROOT slot, separately from START in PAIR_ROOT.

| Fields | Setter; expectation source | Mutability and comparison | Defect classification |
| --- | --- | --- | --- |
| `format_version=1`, `record_kind=active_intent`, `outcome=incomplete` | Maintainer; contract | Fixed exact values | INTENT_UNVERIFIABLE |
| `enrollment_revision`, `descriptor_pin`, `storage_ref`, `pair_ref` | C; independently validated enrollment | Immutable for this operation; exact agreement | INTENT_MISMATCH |
| `operation_id`, `predecessor_id`, `operation_kind` | C under separately approved allocation rules | Initial kind new_pair, predecessor null; independently retained ID; no reuse or guessing | INTENT_UNVERIFIABLE or INTENT_MISMATCH |

Active intent is not administrative pending. START is neither of them. Allocation, persistence and authenticity of intent remain open; ordinary caller IDs are not independent durable expectations.

### Parser proposal

Use one flat JSON object per item: closed keys, exact integer version (not Boolean), exact strings/enums, and null only for initial intent predecessor. Reject missing/extra/duplicate keys, unknown versions, nested values, nonfinite numbers, malformed UTF-8, BOM, surrogate code points and noncanonical spelling. Canonical encoding: sorted keys, ASCII escaping, compact separators, UTF-8, exactly one final LF; re-encoding must equal supplied bytes.

Propose 8192-byte descriptor/policy caps, 2048-byte intent cap and 512-byte pending cap, checked before parsing and after encoding. References/leaves use 1-96 bounded ASCII characters; references begin alphanumeric and continue with alphanumerics, dot, underscore or hyphen. Leaves additionally reject trailing dots and Windows device-name bases. Private directory strings allow at most 1024 UTF-8 bytes: the larger descriptor bound budgets escaped path material plus references, rather than copying START's 4096-byte bound or field schema.

Directory spellings must be absolute Linux paths, not root-only, with no control characters, backslashes, colons, repeated separators, trailing separator, dot/parent/.git components, or components ending in space/dot. Reject rather than normalize. Lexical acceptance proves no filesystem identity; future private-parent, worktree and alias checks remain necessary. No real path, credential, credential hash, Calendar ID or private iCalendar URL belongs in examples or diagnostics.

## 5. Preparation order and activation boundary

All rows are **proposed**, not existing persistence APIs. Each depends on the preceding verified stage. Administrative publication requires reviewed CONTROL_ROOT ownership; any PAIR_ROOT access additionally requires the still-unimplemented multi-lock/coordinator contract.

| Stage | Preconditions and action | Retained state on failure |
| --- | --- | --- |
| 0: entry stopped | Independently deployed disabled entry; explicit owner-directed initial preparation, not inferred absence | Disabled; unverifiable deployment stops all later stages |
| 1: candidate prepared | Owner reviews metadata and independent target tuple offline | No authority; no controlled-store write |
| 2: preparation obligation | Establish and boundedly confirm pending obligation before candidate writes | Retain any residue; unknown save/failed confirmation stops candidate publication |
| 3: candidate saved | Pending matches target; create-only PREPARING descriptor, bounded readback and checkpoints under reviewed ownership | Retain pending and possible candidate; no overwrite, rollback or alternate slot |
| 4: candidate matched | Verify canonical bytes, revision, pin and PREPARING state against approved tuple | Pending survives; match proves comparison only |
| 5: approval checked | Separate deployment review confirms the tuple's approval provenance | Missing/uncertain approval remains blocked |
| 6: activation boundary | Stop for separately reviewed activation and pending-disposition protocol | No ACTIVE promotion, pending deletion or credential-use approval |

Missing pending evidence on restart is ADMIN_UNKNOWN, never proof stage 2 was unnecessary. Only an explicit future initial-preparation procedure could establish a new obligation; ordinary startup cannot self-enroll.

Activation requires a new ACTIVE descriptor revision/pin and a coordinated launch-tuple handoff, while entry remains disabled. ACTIVE plus unresolved pending still blocks. Revocation/update must likewise preserve interruption evidence. Their complete protocols and pending disposition are **open**, so real preparation and activation remain blocked; a nonauthorizing synthetic comparison can cover stages 1 and 4 only.

Two successful saves are not atomic. Visible bytes do not prove subsequent readback, checkpoint or exit succeeded. `publication_possible=False` concerns only that call's publication attempt, not provider/other-process inactivity. `completed_output_count=2` counts writer returns, not bundle completion. No normal-looking observation clears a recorded failure.

## 6. Restart classifications and stopping positions

These are proposed fixed observations, not existing API enum additions. Preserve every recognized negative classification; primary precedence is ADMIN_COMMIT_UNCERTAIN, explicit revocation, pending/conflict, unverifiable/missing evidence, then matched observations. A malformed additional input must not erase an already known failure. All outputs retain `reuse_authorized=False`; none supplies credentials, a session, a permit or recovery authority.

| Observation | Classification; stop before |
| --- | --- |
| Launch expectations absent/unverifiable | POLICY_UNVERIFIABLE; descriptor access |
| Descriptor absent, corrupt or unknown-version | DESCRIPTOR_UNVERIFIABLE; intent/START access |
| Revision/pin mismatch | ENROLLMENT_MISMATCH; operation selection |
| PREPARING with matching tuple | PREPARATION_MATCHED_UNAPPROVED; activation |
| ACTIVE contradicts expected state, or pending target differs | ADMIN_CONFLICT; activation/operation selection |
| Pending survives, or its status cannot be established | ADMIN_PENDING or ADMIN_UNKNOWN; continuation |
| Preparation/approval publication interrupted or result unknown | Current call: ADMIN_COMMIT_UNCERTAIN. Restart: ADMIN_PENDING if only pending survives, otherwise ADMIN_UNKNOWN; no further writes/activation |
| REVOKED observed | ADMIN_REVOKED; managed operation |
| Matching ACTIVE plus future independently verified administrative disposition | ADMIN_ACTIVE_OBSERVED_UNAPPROVED; unreachable here until that disposition protocol exists; credential use remains blocked |
| Approved tuple but required intent absent/unknown | INTENT_UNVERIFIABLE; START comparison |
| Intent present, START absent | START_MISSING_UNRESOLVED; new START/provider/writer |
| START present, expected operation unknown | OPERATION_EXPECTATION_UNKNOWN; existing read API |
| Intent revision/pin/pair or START operation/binding mismatch | INTENT_MISMATCH or START_MISMATCH; continuation |
| Intent and START match | START_OUTSTANDING; credential use |
| Old descriptor against surviving current tuple | ENROLLMENT_MISMATCH; continuation |
| Old intent and START together under unchanged descriptor, or entire local state coherently reverted | METADATA_MATCHED_FRESHNESS_UNPROVEN if matching; no guaranteed rollback detection |
| Equal contents copied elsewhere | BINDING_MISMATCH against anchored location; no alternate-path attempt |

An exact uncertainty subtype survives restart only if independently retained, validated evidence supports it; pending bytes alone preserve refusal, not the unwritten cause. No such additional evidence protocol is defined here. No absence means unused. No fallback, automatic registration, guessed completion, record deletion or migration is proposed.

The comparison chain is launch tuple -> descriptor -> intent's revision/pin and operation/binding -> existing START fields. START has no revision field; `revision_ref` remains a synthetic memory label. An occupied record can justify refusal without identifying its authentic operation. Never extract its ID to manufacture the expected `RecordOperation`, or call `read_start_record` with guessed values.

Current scope owns one directory. CONTROL_ROOT followed by PAIR_ROOT needs separately reviewed lock ordering, alias identity checks, partial-acquisition unwind and participating writers. Current scope cannot borrow an external lock; do not nest public record acquisition under another owner.

Future integration must stop before the valid-token return or refresh in [`_load_production_write_credential_session`](../src/tridentine_calendar_google_sync/production_write_token.py), 778-887, and before the mock authorizer at 704. [`_write_posix_token_bundle`](../src/tridentine_calendar_google_sync/production_write_token_io.py), 530-591, locks only at publication and has a checkpoint after count two. These existing boundaries do not enforce this contract; live authorization stays hard-off.

## 7. Future fault-injection plan

No tests are implemented or executed here. Every scenario requires provider, token/state-writer and credential-use call counts of zero.

| Injection | Residue and next observation | Forbidden continuation |
| --- | --- | --- |
| Before each pending/candidate/approval save | Earlier evidence retained; absent required evidence UNKNOWN | Next save without prerequisite |
| Save result unknown; readback mismatch; checkpoint/exit fails | Current ADMIN_COMMIT_UNCERTAIN; restart ADMIN_PENDING or ADMIN_UNKNOWN unless the specific cause was independently retained | Activation or inferred success |
| Only approval tuple or descriptor updated | Old/new disagreement; ENROLLMENT_MISMATCH/ADMIN_CONFLICT | Older-version fallback |
| Pending publication or later failure-observation append fails | Original cause retained in memory; surviving pending or ADMIN_UNKNOWN | Candidate effects, cause replacement, retry |
| Fresh process cannot obtain expectations | POLICY_UNVERIFIABLE | Descriptor-selected bootstrap |
| Old matching values or another destination supplied | Detectable mismatch, otherwise freshness unproven | Claimed rollback protection/path switch |
| Unregistered pair with START only | Registration unknown plus occupied evidence | Adoption, guessed operation, clearing |
| Unsupported OS, unavailable lock or missing multi-lock contract | UNSUPPORTED_PLATFORM, LOCK_UNAVAILABLE or OWNERSHIP_UNIMPLEMENTED | Storage effects or unlocked fallback |

Memory injection, ordinary process restart, forced termination and power-loss qualification are separate evidence. An unpersisted failure cannot be promised detectable next time. Disabled-entry persistence is itself an unimplemented prerequisite, not an existing crash guarantee.

## 8. One next implementation candidate

Propose only a standard-library validator of supplied synthetic descriptor bytes against independently supplied synthetic expected metadata/revision/pin. It establishes bounded canonical parsing and exact comparison, not trustworthy bootstrap. Fixed outputs: EXPECTATION_UNVERIFIABLE, DESCRIPTOR_UNVERIFIABLE, ENROLLMENT_MISMATCH and DESCRIPTOR_MATCHED_UNAPPROVED; constructor-excluded `reuse_authorized=False` throughout. Return no input text, path, digest, session or approval object.

Candidate paths: `src/tridentine_calendar_google_sync/production_write_token_enrollment_descriptor.py` and `tests/test_token_enrollment_descriptor_phase6d1h.py`. Use no real files or application-module imports. Existing contracts guide compatibility; existing runtime components are not dependencies. This avoids claiming deployment or filesystem authority before their contracts exist.

No existing guard change is needed. Preserve record tests `test_component_has_no_runtime_consumer_or_dynamic_import_and_no_mutation_escape` and `test_only_exact_reviewed_modules_directly_import_lock_and_publisher`; [lock test](../tests/test_posix_private_lock_phase6d1h.py) `test_component_has_no_artifact_write_no_wait_loop_and_only_approved_consumers`; [directory test](../tests/test_posix_sensitive_directory_phase6d1h.py) `test_directory_foundation_only_has_the_reviewed_backend_consumers`. A later record-component consumer needs explicit review of its no-runtime-consumer guard. Direct lock imports additionally require both lock-consumer reviews; direct publisher/directory imports require their corresponding exact-set reviews. [Inspector](../tests/test_token_pair_inspection_phase6d1h.py) `test_inspector_has_no_cli_consumer_provider_session_or_mutation_calls` and [policy](../tests/test_token_reuse_policy_phase6d1h.py) `test_model_has_only_pure_standard_library_dependencies_and_no_runtime_consumer` restrictions remain intact; do not hide imports.

Before implementation, maintainers must approve field names, bounds, canonicalization and output precedence; the user must separately authorize scope. Acceptance: malformed/duplicate/unknown/noncanonical inputs refuse; changes to any pinned field mismatch; matching bytes remain unapproved; no arbitrary diagnostics, I/O or runtime consumer. Run equivalent pure base-layer cases on Windows/Linux with existing socket restrictions; neither proves Linux storage. Stop if existing guards/runtime require modification or secrets/real inputs become necessary.

The deployment owner separately decides launcher provenance and activation/pending disposition before real preparation; maintainers decide intent allocation, locking and restart evidence before integration. Existing-pair migration, repeated operations, normal closure, reconciliation, anti-rollback guarantees, Windows storage, providers and session wiring remain excluded.

DS-04 remains PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 scan FAIL; Production gate BLOCKED; live handlers hard-off; Packaged Accepted Production Baseline Registry empty/fail-closed. PR #17 remains Draft in inherited evidence. This draft authorizes no implementation, activation or Production use.

## 9. Independently reviewed scope, unreviewed validator prototype

This separately authorized prototype implements only synthetic descriptor comparison. The detailed interface, ordering and string rules below are new prototype decisions, not facts previously established by sections 1-8. Those proposals and unresolved deployment decisions remain unchanged. In particular, section 8's broad field-change acceptance statement is refined: valid variable changes mismatch; schema defects are unverifiable.

### 9.1 Public inputs and output

`validate_enrollment_descriptor(raw: object, expectation: object)` returns frozen, slotted `EnrollmentDescriptorResult`: exactly `state` and constructor-excluded `reuse_authorized: Literal[False]`. No metadata, digest, path, approval object or detailed reason is returned.

`SyntheticEnrollmentExpectation` is an exact-type, frozen, slotted synthetic input; all eleven fields are mandatory exact strings and hidden from repr.

| Expectation fields | Descriptor relationship |
| --- | --- |
| enrollment_revision, administrative_state, storage_ref, pair_ref, artifact_directory, token_slot, state_slot, active_intent_slot | The eight variable descriptor fields, compared exactly |
| descriptor_pin | Independent lowercase 64-hex SHA-256 expectation; never a descriptor field |
| descriptor_slot, administrative_pending_slot | Independent synthetic control-layout leaves; only constrain the active-intent leaf |

The twelve-key descriptor adds exactly four constants: integer version 1, enrollment_descriptor kind, production_write role, and production-write-operation-start-v1.json record slot. It remains a different schema from START. No runtime component supplies these constants.

Raw input must be exact bytes, 1-8192 bytes before decoding. Closed keys, exact types, all duplicates including escaped duplicate keys, UTF-8/BOM/surrogates, fixed values, and canonical sorted/ASCII-escaped compact JSON with one LF are checked. The entire canonical sequence, including state and LF, is pinned.

References use the specified 1-96 ASCII grammar. Leaves reject trailing dots and the exact reserved device-name bases, including extensions. Pair leaves and synthetic control leaves are distinct within their respective directories, using case-sensitive equality. Linux path strings reject unsafe components, separators, Cc/Cs characters and more than 1024 UTF-8 bytes without Path conversion or normalization. Equality across synthetic layouts establishes no actual directory identity, permissions, symlink, worktree or mount safety.

### 9.2 Ordered comparisons and limits

| Order | Observation | Classification |
| --- | --- | --- |
| 1 | Invalid expectation type, field, layout, or inconsistency between expected metadata's canonical digest and supplied pin | EXPECTATION_UNVERIFIABLE; raw is untouched |
| 2 | Candidate type, size, schema, string constraints or canonical encoding invalid | DESCRIPTOR_UNVERIFIABLE |
| 3 | Well-formed candidate differs in metadata/pin or conflicts with expected control leaves | ENROLLMENT_MISMATCH |
| 4 | All comparisons match | DESCRIPTOR_MATCHED_UNAPPROVED |

Ordinary expectation-stage failures remain expectation refusals; ordinary parsing, encoding or hashing failures during candidate handling remain descriptor refusals. KeyboardInterrupt/SystemExit propagate. No exception or input is retained globally; fixed errors and repr do not reflect supplied text. These checks do not guarantee actual memory-exhaustion handling or arbitrary-instruction cancellation safety.

PREPARING, ACTIVE and REVOKED are data, not authorization decisions. Matching REVOKED also returns DESCRIPTOR_MATCHED_UNAPPROVED and cannot clear ADMIN_REVOKED, ADMIN_PENDING or ADMIN_COMMIT_UNCERTAIN. This is not section 6's restart policy. A caller controlling both inputs can make them match; neither authenticity nor freshness follows. No public candidate-to-expectation factory or pin completion exists.

### 9.3 Specification coverage

All new tests are in [tests/test_token_enrollment_descriptor_phase6d1h.py](../tests/test_token_enrollment_descriptor_phase6d1h.py); parameterization produces 347 cases, with no OS skip.

| Contract | Test functions or groups |
| --- | --- |
| Independent canonical fixture, fields, LF pin | test_independent_canonical_fixture_and_complete_public_contract |
| Valid variable changes versus malformed schema | test_each_well_formed_variable_change_is_mismatch; test_schema_defects_are_unverifiable; per-key missing/type cases |
| Expectation priority, exact types, poison hooks and stale pin | test_expectation_fields_require_exact_strings_before_hooks; test_expectation_exact_type_and_missing_slots_precede_candidate; test_expectation_pin_and_metadata_must_be_self_consistent |
| Duplicates, encoding and size-before-parse | test_invalid_serialization_and_noncanonical_forms; test_raw_size_is_checked_before_json_parse; test_in_bound_size_never_bypasses_schema |
| References, leaves, layouts and Linux strings | Grammar, collision, reserved-name, UTF-8-boundary and nonnormalization groups |
| Nonauthorization and freshness limit | test_administrative_matches_never_authorize_or_clear_upper_policy; test_controlling_both_inputs_proves_neither_authenticity_nor_freshness |
| Fixed results, ordinary failures and cancellation | test_result_and_expectation_are_frozen_slots_with_no_input_in_repr; test_failures_are_phase_specific_and_cancellation_propagates |
| Isolation | test_validation_calls_do_not_read_files_or_print; test_only_pure_standard_library_dependencies_and_no_runtime_consumer |

Poison objects are constructed inside tests and raise a BaseException subclass when touched. I/O spies cover only validator calls. Hardcoded synthetic bytes and independent standard-library encoding/hash calculations avoid checking the implementation solely against itself.

### 9.4 Local validation and remaining work

Local verification used Windows and existing Python 3.12.14, resolving the package to this repository's src. Installed pytest 8.4.2, pytest-socket 0.8.1, Ruff 0.16.4, mypy 1.20.2, pydantic 2.13.4 and build 1.5.0 metadata matched uv.lock. This was metadata comparison, not frozen installation; no dependency/environment change occurred.

The existing interpreter ran with -B. An in-memory pytest collector captured diagnostics, using `pytest.main(["-q", "-p", "no:cacheprovider", ...targets])`; no runner file or fixture file was created. Targets were the complete new test file and these unchanged existing nodes:

- tests/test_token_operation_record_phase6d1h.py::test_only_exact_reviewed_modules_directly_import_lock_and_publisher
- tests/test_token_operation_record_phase6d1h.py::test_component_has_no_runtime_consumer_or_dynamic_import_and_no_mutation_escape
- tests/test_token_reuse_policy_phase6d1h.py::test_model_has_only_pure_standard_library_dependencies_and_no_runtime_consumer
- tests/test_token_pair_inspection_phase6d1h.py::test_inspector_has_no_cli_consumer_provider_session_or_mutation_calls
- tests/test_posix_private_lock_phase6d1h.py::test_component_has_no_artifact_write_no_wait_loop_and_only_approved_consumers
- tests/test_posix_sensitive_directory_phase6d1h.py::test_directory_foundation_only_has_the_reviewed_backend_consumers
- tests/test_no_network_or_google_dependencies.py::test_source_package_has_no_eager_network_google_or_oauth_imports

Result: new tests 347 passed; existing structural checks 7 passed; total 354 passed, 0 failed, 0 errors, 0 skipped, 0 deselected. Existing conftest, strict configuration/markers and socket prohibition remained active. All seven guards executed and passed without edits.

Commands `python -B -m ruff check --no-cache --output-format json .` and `python -B -m ruff format --check --no-cache .` succeeded; formatting covered 262 files. Strict mypy used `--strict --no-incremental --cache-dir=nul --no-pretty` for the new module and separately all src (119 files). Initial lint findings in the new test were corrected without ignores or weakened assertions. Document/source review and whitespace checks are separate from these program-test results.

The validator imports only standard-library modules, performs no runtime I/O and has no runtime consumer. No existing source/test/guard or configuration was changed. Real bootstrap, activation/revocation enforcement, administrative pending, active intent, history/restart policy, lock coordination, session/provider/writer wiring, normal closure and reconciliation remain unimplemented.

Status: IMPLEMENTED_LOCAL_CHECKS_PASSED_REVIEW_PENDING. New-component Linux execution and new CI were not performed; run 35736574068 does not cover this prototype. No Linux/Windows filesystem validation, actual enrollment, commit, push, PR operation or Google operation was performed. Review of this standalone prototype is still required; no next implementation or operational action is authorized.
