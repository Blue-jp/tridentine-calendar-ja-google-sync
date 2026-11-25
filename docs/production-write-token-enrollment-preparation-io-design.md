# Single-Directory Synthetic Enrollment Preparation I/O Contract

Status: DRAFT_WITH_UNREVIEWED_SYNTHETIC_PREPARATION_PROTOTYPE

## 1. Scope and evidence

This draft proposes one initial synthetic preparation in one explicitly supplied Linux CONTROL_ROOT: retain administrative pending first, verify it, then create a PREPARING descriptor. Both remain outstanding. A successful observation grants no enrollment, activation, credential use or recovery.

**Current** identifies code at HEAD 3d5badbcb10eb17fc5bdfe36934c8060d9d7e283, tree 16618bcbc490fcb1a8a20fed368c24cbbe694755. **Existing proposal** refers to the [bootstrap contract](production-write-token-enrollment-bootstrap-contract.md), sections 4-8, and [enrollment/lock design](production-write-token-enrollment-lock-design.md). **Proposed** below specifies new preparation behavior; **Open** marks decisions before implementation or integration. No new Unit number is assigned.

Inherited external evidence reports reviewed/published validator code, PR #17 Open/Draft/unmerged and run 35808486277, attempt 1, pull_request, eight successful jobs. Ubuntu and Windows each reportedly executed 347 validator cases without skips, evidenced by file-level progress, not individual passing-node lists. This task retrieved no remote evidence and ran no tests. Existing DRAFT/CI-pending passages remain historical. Neither that CI nor this document validates preparation persistence, administrator approval or restart durability. Original scan-finding text was not consulted; no audit closure follows.

## 2. Current components and limits

Line references were checked against this HEAD.

| Repository-relative source and symbol | Reusable behavior and limit |
| --- | --- |
| [src/tridentine_calendar_google_sync/production_write_token_enrollment_descriptor.py](../src/tridentine_calendar_google_sync/production_write_token_enrollment_descriptor.py), validate_enrollment_descriptor, 231-256 | Exact expectation-first canonical comparison; four classifications, always unapproved. Public expectation fields suffice; no private codec reuse is needed. |
| [src/tridentine_calendar_google_sync/_posix_private_lock.py](../src/tridentine_calendar_google_sync/_posix_private_lock.py), acquire_posix_private_directory_lock, 102-141; _PrivateDirectoryLock, 47-99 | One nonblocking cooperative Linux directory lock; no wait, lockfile or fallback. Revalidation is not kernel-lock attestation; there is no thread-owner contract. |
| [src/tridentine_calendar_google_sync/_posix_private_create.py](../src/tridentine_calendar_google_sync/_posix_private_create.py), create_posix_private_bytes, 112-229 | Create-only publication with file/parent synchronization and checks. Opens its own bound-directory context, but acquires no additional flock. Component-specific 512/8192-byte bounds remain caller responsibilities. |
| [src/tridentine_calendar_google_sync/sensitive_paths.py](../src/tridentine_calendar_google_sync/sensitive_paths.py), validate_sensitive_output_path, 168-216; read_private_sensitive_bytes, 472-503 | Output preflight and bounded private reading, not authority or a shared held-directory read. |
| [src/tridentine_calendar_google_sync/_posix_sensitive_directory.py](../src/tridentine_calendar_google_sync/_posix_sensitive_directory.py), open_posix_private_directory, 155-223; revalidate, 111-152 | Retained ancestry/name/owner checks, exact 0700 final parent, Git/worktree rejection; no permission repair. |
| [src/tridentine_calendar_google_sync/production_write_token_operation_record.py](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py), _record_scope, 519-544; _storage_call, 653-687 | Existing START-specific scope and post-exit results are reference boundaries only. They are neither imported nor generalized. |

The POSIX reader requires a regular, single-link, effective-user-owned file without group/other permission bits, not exact 0600. It closes earlier ancestors during traversal and does not borrow the lock's descriptor or atomically bind its final pathname. Surrounding revalidation detects some changes; it cannot eliminate equivalent-user races.

Publisher and directory cleanup suppress some errors. Normal exit is not attestation of every close. Advisory locks constrain cooperating writers on the same inode, not arbitrary writers, renamed-directory replacements or privileged changes. These limits remain unchanged.

## 3. Proposed interface, inputs and pending bytes

**New API proposal, not existing code:** prepare_synthetic_enrollment(control_root: object, raw: object, expectation: object) -> PreparationResult.

This synchronous function owns its context internally. It accepts no borrowed lock, callback, owner Boolean, resume handle or synthetic=True authority flag. It returns no reusable scope. It does not use dummy token/state bindings or operations to access _record_scope.

| Input | Proposed admission contract |
| --- | --- |
| control_root | Exact string naming one existing test-owned Linux directory. Before Path construction, require absolute, non-root spelling, at most 1024 UTF-8 bytes; reject repeated/trailing separators, backslash, colon, Cc/Cs characters, dot/parent/.git components and trailing space/dot components. Never normalize or discover alternatives. |
| raw | Retain the exact immutable bytes accepted by the existing validator; no reserialization before publication. |
| expectation | Exact SyntheticEnrollmentExpectation with eleven exact-string public fields. Snapshot those original fields privately, validate against the retained raw, and reuse the same snapshot throughout. Never derive expectations from candidate or readback. |

Dispatch unsupported platforms before input hooks, control-directory I/O or locking. On Linux, safe type/snapshot checks and the existing validator precede storage. Only DESCRIPTOR_MATCHED_UNAPPROVED with snapshot administrative_state PREPARING proceeds. Matching ACTIVE/REVOKED is refused here without altering the validator's meanings.

Only snapshot descriptor_slot and administrative_pending_slot select output leaves beneath CONTROL_ROOT. Existing validation requires single safe leaves, distinct from one another and active_intent_slot. Root/private/worktree checks are additional caller obligations. No destination comes from artifact_directory, token/state/record slots or intent contents. They stay metadata; PAIR_ROOT, START, active intent and credentials receive zero accesses.

An explicit initial test-fixture preparation is a different operation from normal startup. Empty slots are a necessary local precondition, never proof of unused history or real enrollment eligibility. No runtime entry point calls this API. A caller-selected root or type name cannot prove test ownership or administrator approval; test ownership is an externally enforced fixture precondition.

### Pending format

Retain the existing five-field proposal, now with concrete codec requirements:

| Key | Exact type/value and comparison |
| --- | --- |
| format_version | int 1, excluding bool and float |
| record_kind | string enrollment_preparation |
| target_revision | Exact snapshot enrollment_revision; 1-96 ASCII characters, alphanumeric first, then alphanumeric or dot/underscore/hyphen |
| target_pin | Exact snapshot descriptor_pin; 64 lowercase hexadecimal characters |
| outcome | string pending |

Use one flat object, precisely these required keys, 1-512 bytes checked before parsing and after encoding. Reject extra/missing/duplicate keys, including escaped equivalent duplicates, nested values, null, nonfinite numbers, unknown versions, malformed UTF-8, BOM and surrogates. Canonical encoding is sorted keys, ensure_ascii=True, compact separators, allow_nan=False, UTF-8 and exactly one final LF. Readback must equal retained expected pending bytes and strictly match this schema.

target_pin covers the candidate descriptor, including its LF and administrative state; it does not authenticate pending or certify its publication. These fields identify a proposed enrollment target, not a unique preparation attempt. Add no attempt ID, timestamp, PID, signature or operation field. Identical target_revision/pin never permits idempotence or retry. Any future attempt-identification requirement needs a separate design decision.

## 4. One owned interval and ordered writes

There is exactly one acquisition of acquire_posix_private_directory_lock(CONTROL_ROOT) per admitted call. Retain it through both publications and all readbacks/checkpoints. Publishers' internal directory opens are not lock reacquisitions. Do not export ownership, spawn work, transfer handles or invoke START/session wrappers.

| Stage | Preconditions, operation and checkpoint | Failure boundary |
| --- | --- | --- |
| 1 | Platform admission; immutable input snapshots; matching PREPARING descriptor; encode bounded expected pending | No lock or publisher on invalid inputs |
| 2 | Acquire the existing private-root lock once; revalidate | Busy/unavailable stops without unlocked fallback |
| 3 | Non-following lstat of exactly the two expected leaves, surrounded by revalidation | Any occupied entry refuses both publishers; only FileNotFoundError plus valid parent checks supports absence |
| 4 | Validate pending output with overwrite=False; require unchanged destination; revalidate immediately before its one publisher call | Preflight failure never enters pending publisher; publisher entry starts pending evidence |
| 5 | Read pending with max_size=512; strict schema/target/raw equality; revalidate | Any failure means descriptor publisher count zero |
| 6 | In the same context, recheck descriptor absence and pending expected bytes, preflight descriptor output, revalidate, then call descriptor publisher once | No reuse of a previously occupied pending; no second pending publisher |
| 7 | Read descriptor with max_size=8192; require exact retained raw and validator match against the original snapshot; revalidate | No successful preparation classification |
| 8 | Exit the owner context; release resources through existing backend behavior | Observable exit failure prevents success |
| 9 | Construct success-like public result only after normal exit; refusals follow unwind | Neither record is retired |

The second pending read in stage 6 detects observed substitution between stages; it does not turn path-based reads into an atomic binding guarantee. Rechecking descriptor absence narrows an observed collision window; exclusive publication remains decisive. Parent disappearance/rebinding is not interpreted as two fresh empty slots.

An initially existing regular file, directory, symlink or dangling symlink is occupied. Do not read those pre-existing contents to establish success. If occupancy and inspection failure compete, retain known occupancy; unreadability cannot erase that refusal.

**Same-call progress** requires this invocation's successful pending publisher/readback/checkpoint while it still holds the original lock. **Later-call resumption** is prohibited even when pending matches exactly. No startup adapter, retry loop, alternate directory, overwrite, restore, final-record deletion or resume API is provided. Publisher-internal bounded temporary-name collision handling and verified cleanup of its own temporary files remain unchanged; they are not extra preparation attempts.

The proposed function retains both final files after apparent success. Descriptor equality never resolves pending. Two normal publisher returns are not a two-file transaction or evidence that the surrounding invocation returned successfully.

## 5. Results, publication evidence and exceptions

**Proposed new types:** immutable, slotted PreparationResult with a closed state, pending_attempted, pending_publication_possible, descriptor_attempted, descriptor_publication_possible, exit_failure_observed and constructor-excluded reuse_authorized=False. Attempt/exit fields are exact Booleans; publication fields are exact Boolean or None. Return only these nonsecret classifications, never references, raw bytes, paths, pins, credentials or permissions. Do not extend existing validator/policy enums.

| Proposed state | Meaning |
| --- | --- |
| INPUT_UNVERIFIABLE | Root, expectation or candidate invalid, or comparison does not match; no publisher entered by this call |
| PREPARING_REQUIRED | Valid matching administrative state is ACTIVE/REVOKED; no storage |
| UNSUPPORTED_PLATFORM | No supported Linux storage dispatch |
| LOCK_BUSY / LOCK_UNAVAILABLE | Contention or lock verification failure before pending publisher entry |
| PENDING_OCCUPIED / DESCRIPTOR_OCCUPIED / BOTH_OCCUPIED | Observed existing reserved entries; no idempotent success |
| PREWRITE_UNVERIFIABLE | Slot inspection/output preflight failed before pending publisher entry |
| PENDING_PERSISTENCE_UNCERTAIN | Pending publisher entered; preparation stopped before descriptor entry, possibly after an earlier pending confirmation |
| DESCRIPTOR_PERSISTENCE_UNCERTAIN | Descriptor publisher was entered but readback/checkpoint/observable exit did not finish |
| PREPARATION_OBSERVED_UNAPPROVED | Both bounded confirmation intervals and normal owner exit observed; pending still outstanding |

Local internal checkpoints PENDING_HELD_CONFIRMED and DESCRIPTOR_HELD_CONFIRMED are sequencing facts, never public success, persistent certificates or capabilities.

Classify newly observed ordinary storage/path/revalidation failures by latest publisher entry: before pending, LOCK_UNAVAILABLE for lock errors or PREWRITE_UNVERIFIABLE otherwise; after pending but before descriptor, PENDING_PERSISTENCE_UNCERTAIN; after descriptor, DESCRIPTOR_PERSISTENCE_UNCERTAIN. Explicit occupancy and earlier classified failures retain precedence. These labels locate failed progression, not proof that previously confirmed bytes disappeared.

For each artifact independently: before publisher entry, attempted=False/publication=False; at entry, attempted=True/publication=None; formal PosixPrivateCreateError contributes only its exact Boolean evidence; normal publisher return gives True. Unknown ordinary exceptions retain None. Backend True begins before its link attempt and means possible publication, not certain creation. A pending True survives a later descriptor False, read failure or cleanup failure. Neither False proves global absence or other-process/provider inactivity. No aggregate completed-output count replaces the two evidence records.

Retain the first classified failure reaching this component's boundary and stop further publishers. Later ordinary exit failure sets exit_failure_observed without replacing that cause or erasing publication evidence. If exit is the first failure after both held confirmations, return DESCRIPTOR_PERSISTENCE_UNCERTAIN, retaining both True values. A pre-descriptor failure with pending intact remains refusal, not rollback.

Observed KeyboardInterrupt/SystemExit or other cancellation propagates, never a successful/fixed ordinary result. Preserve an observed original cancellation across subsequent ordinary outer-cleanup failure. Do not claim recovery of exceptions already suppressed or replaced inside a backend, or immunity to another asynchronous interruption during cleanup. Keep no global exception/history store and expose no arbitrary exception text.

## 6. Later calls and restart observations

No restart-reader API is included in the next candidate. The table specifies future read-only classification against independently supplied expectations, not permission to rerun the writer as an inspection tool.

| Later observation | Fixed classification and permitted inference |
| --- | --- |
| Neither entry exists | ABSENCE_UNVERIFIABLE; ordinary startup/retry stops, never self-enrolls |
| Pending only | ADMIN_PENDING; target obligation remains, detailed unpublished failure may be unknowable |
| Descriptor only | ORPHAN_DESCRIPTOR; preparation sequence cannot be established |
| Both match expected target | PREPARATION_RETAINED_UNAPPROVED; no proof prior call completed or pending was resolved |
| Both exist with different targets | PREPARATION_CONFLICT; refuse without repair |
| One/both corrupt or unreadable | PREPARATION_UNVERIFIABLE; retain any separately known occupancy/pending/conflict |
| Old normal-looking records | Detectable mismatch is PREPARATION_CONFLICT; coherent matching rollback is FRESHNESS_UNPROVEN |
| Equal bytes copied elsewhere | BINDING_UNVERIFIABLE against retained expected location; equality cannot transfer approval |
| Exit failed previously but both now look normal | Retained unapproved preparation; exact exit uncertainty only if independently preserved evidence survives |

The writer itself refuses occupied entries before parsing them, so it need not distinguish every row. Future separate-process tests may use a test-only observer restricted to these two leaves; it must never resume or clear them.

If failure leaves neither artifact, a later process cannot reliably identify the previous attempt from these five fields. The standalone API cannot authenticate caller intent or detect coherent deletion, both-record/expectation rollback, or an externally chosen fresh root. Its lack of automatic retry/path fallback is a control-flow property, not an anti-bypass authority. Stronger registration/history/rollback guarantees remain outside this synthetic prototype. Memory faults, process restart, forced termination and power loss are distinct evidence.

## 7. Future dependency and guard changes

The single proposed implementation comprises six paths below. No existing runtime module changes. In this table P means the proposed preparation module; all exceptions require separate implementation authorization.

| Future changed file | New dependency | Existing test/assert | Narrow change | Preserve | Separate permission |
| --- | --- | --- | --- | --- | --- |
| src/tridentine_calendar_google_sync/production_write_token_enrollment_preparation.py | Public validator, private lock/create, sensitive_paths reader/output preflight | New component isolation tests | Implement only this contract | No record/scope/direct-directory/session imports | New module |
| tests/test_token_enrollment_preparation_phase6d1h.py | Synthetic component tests | New exact dependency/no-consumer/effect assertions | Add bounded tests below | Socket restriction, no real data | New tests |
| [tests/test_token_enrollment_descriptor_phase6d1h.py](../tests/test_token_enrollment_descriptor_phase6d1h.py) | First validator caller P | test_only_pure_standard_library_dependencies_and_no_runtime_consumer, 577-618 | Replace final no-consumer assertion with exact singleton P | All validator purity/AST/effect checks, 577-615; 347 existing cases | Sole caller exception |
| [tests/test_token_operation_record_phase6d1h.py](../tests/test_token_operation_record_phase6d1h.py) | P imports lock and publisher | test_only_exact_reviewed_modules_directly_import_lock_and_publisher, 392-410 | Add P to both exact sets; retain consumers == allowed | Entire test_component_has_no_runtime_consumer_or_dynamic_import_and_no_mutation_escape, 413-482 | Two set additions only |
| [tests/test_posix_private_lock_phase6d1h.py](../tests/test_posix_private_lock_phase6d1h.py) | P imports lock | test_component_has_no_artifact_write_no_wait_loop_and_only_approved_consumers, 411-442 | Add only P to allowed_consumers | No-write/repair/wait-loop restrictions | One filename addition |
| [tests/test_posix_sensitive_directory_phase6d1h.py](../tests/test_posix_sensitive_directory_phase6d1h.py) | P imports publisher | test_directory_foundation_only_has_the_reviewed_backend_consumers, 351-409 | Add only P to publisher tuple, 399-409 | Direct directory-consumer tuple, 374-389; directory AST and publisher dependency checks | Publisher exception only |

Direct lock consumers become three, publisher consumers four excluding the publisher itself. Validator purity stays unchanged despite one explicit caller. Record runtime consumers and direct directory consumers do not increase. No dynamic-import hiding, widened wildcard exception or guard removal is proposed.

Keep the [private-create structural test](../tests/test_posix_private_create_phase6d1h.py), test_backend_not_wired_to_common_writer_and_no_replace_or_path_chmod, and [network restriction](../tests/test_no_network_or_google_dependencies.py), test_source_package_has_no_eager_network_google_or_oauth_imports, unchanged. Planning-create, replacement, bundle-lock, reuse-policy, inspector, phase6b import-graph and phase6d0 network/privacy restrictions likewise need no alteration.

## 8. Future verification and one next candidate

No implementation, tests, application imports or I/O probes occurred for this document.

| Injection/scenario | Expected refusal/evidence and remaining records | Forbidden next call |
| --- | --- | --- |
| Invalid/unknown input; matching ACTIVE/REVOKED | INPUT_UNVERIFIABLE/PREPARING_REQUIRED; no records created by this call | Lock or either publisher |
| Unsupported OS; busy/unavailable lock | Platform/lock classification; unchanged entries | Reader, publisher or fallback |
| Before pending save; occupied/corrupt/symlink entries | Prewrite/occupancy refusal; existing entries retained | Either publisher after refusal |
| Pending save unknown, readback/target/checkpoint failure | PENDING_PERSISTENCE_UNCERTAIN; possible pending, descriptor absent in controlled fixture | Descriptor publisher: exactly zero |
| Before descriptor publication after confirmed pending | PENDING_PERSISTENCE_UNCERTAIN for ordinary failures; pending retained, descriptor_attempted=False | Retry or replacement |
| Descriptor save/readback/checkpoint fails | DESCRIPTOR_PERSISTENCE_UNCERTAIN; pending plus possible descriptor | Another publisher or final cleanup |
| Exit fails after both confirmations | Descriptor uncertainty; both retained | Success or pending retirement |
| Earlier failure plus later cleanup/cancellation | First observed cause/evidence retained, or observed cancellation propagates | Fabricated success |
| Same-call ordered success | One acquisition spans both saves; result only after exit | Nested acquisition, scope transfer |
| Reinvoke with matching/mismatching/corrupt occupied records | Occupancy refusal even after prior success; bytes retained | Resume/idempotent publication |
| Separate-process observation, old values, copied paths | Section 6 observations; no inferred freshness | Writer as reader or path retry |

Instrument zero accesses to PAIR_ROOT/token/state/START/intent/provider; immutable original expectation reuse; per-slot publisher counts at most one; no overwrite, final deletion or automatic retry. Exercise existing publisher temporary cleanup separately from final-record retention.

**One next candidate:** implement this standalone PREPARING-only function and pending codec in the two new files, with exactly the four narrow guard updates above. No restart-reader API, new scope framework, descriptor-schema change, validator rewrite, backend alteration or dependency is included.

Acceptance requires Windows pure/mocked sequencing and unsupported-storage refusal; real Linux private-directory I/O and cross-process residual observation; the unchanged 347 validator cases; record/scope/private-backend and all affected structural regressions; existing strict/socket settings, Ruff, mypy and applicable CI/build checks. Windows mocks do not establish Linux persistence. Forced termination and power-loss qualification remain separately scoped, not inferred from orderly process tests.

Before implementation, maintainers must approve the API/result vocabulary, snapshot/codec details and exact six-file scope; the user must authorize those edits and synthetic test locations. If stronger atomic reader-to-lock binding or fully observable cleanup is required, existing components cannot supply it: stop that stronger claim pending a separate backend design. Trusted deployment, activation, pending retirement and complete restart/reconciliation authority block real enrollment, not this narrowly assumed synthetic trial.

README, SECURITY.md, existing source/tests/docs, HEAD and index remain unchanged by this document. DS-04 stays PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 scan FAIL; Production gate BLOCKED; live handlers hard-off; Registry empty/fail-closed; PR #17 Draft in inherited evidence. No implementation, commit, push or operational step is authorized.

## 9. Unreviewed synthetic preparation prototype

The separately authorized implementation adds the preparation module and test, makes four exact consumer-guard changes, and appends this section: seven files in total. Sections 1-8 retain the original proposal and its limitations. The added resource-management and result-consistency rules below are prototype decisions, not previously implemented guarantees.

### 9.1 Implemented API and retained inputs

[prepare_synthetic_enrollment](../src/tridentine_calendar_google_sync/production_write_token_enrollment_preparation.py) accepts the explicit control-root string, immutable candidate bytes and exact SyntheticEnrollmentExpectation. Unsupported storage dispatch precedes input inspection, Path construction and effects. Root spelling is checked without normalization. All eleven original expectation fields require exact strings and are copied into a private frozen snapshot; candidate/readback metadata never supplies expectations.

The unchanged public validator must match that snapshot and the candidate. Only PREPARING proceeds; matching ACTIVE/REVOKED returns PREPARING_REQUIRED. Descriptor bytes are saved unchanged. The independent pending codec enforces the five closed fields, exact types, revision/pin constraints, duplicate rejection, canonical encoding and 512-byte bound. Neither format changes the existing descriptor or START schemas.

Only the two expectation-selected control leaves are accessed. Artifact-directory and token/state/START/intent metadata is never expanded into additional I/O. Test ownership and separation of CONTROL_ROOT from PAIR_ROOT remain external fixture assumptions, not properties established by caller assertions.

The implementation owns one acquisition, checks both leaves without following symlinks, preflights and publishes pending, reads and confirms pending, rechecks descriptor absence and pending content, then preflights/publishes/reads/revalidates the original descriptor. Each publisher can be entered at most once. The private progress object requires pending confirmation before descriptor entry. Initially occupied entries are not read for success. Later descriptor occupancy retains this call's earlier pending evidence. No retry, alternate root, overwrite, final deletion, resume or retirement is implemented.

### 9.2 Ownership and result consistency

Acquisition failure leaves cleanup to the backend, which transfers no owner. Because successful acquisition already holds resources, failed __enter__ triggers one caller-level public close(). The existing close contract detaches ownership first: an already-invalidated owner makes this call a no-op, not a low-level close retry. The component inspects neither private handles nor descriptors.

Successful entry receives exactly one __exit__, including after body failure or cancellation. No additional close follows exit. The actual observed body exception is supplied to the context exit. Backend-suppressed cleanup failures remain unobservable. An ordinary exit failure reaching this layer sets exit_failure_observed and preserves the first classified refusal; observed cancellation propagates and survives later ordinary cleanup failure.

PreparationResult is frozen/slotted with exactly the seven fields in section 5. Exact Boolean/optional-Boolean types and reachable state/evidence combinations are checked. No attempt implies False publication evidence; descriptor attempt requires preceding pending attempt/publication True; success requires both attempts/publications True and no observed exit failure. Constructor consistency cannot independently attest a historical checkpoint absent from its fields: actual pending confirmation is enforced by private sequencing, and the result remains nonauthorizing.

The final public result is built after ownership unwinds. Pending and descriptor publication evidence remain independent across readback, checkpoint and exit failures. False is call-local, not proof of absence or safe retry. An exit flag of False records only that this layer observed no exit failure. No persistent failure-observation record or restart-reader API has been added.

### 9.3 Tests and exact guard scope

All new cases are in [tests/test_token_enrollment_preparation_phase6d1h.py](../tests/test_token_enrollment_preparation_phase6d1h.py). Their synthetic fixtures independently encode canonical descriptor/pending bytes.

| Contract | Named coverage |
| --- | --- |
| Platform/input ordering and snapshots | test_platform_refusal_precedes_every_input_hook_and_effect; test_platform_dispatch_requires_both_linux_and_posix; test_every_snapshot_field_is_exact_string_before_storage; test_one_owned_interval_exact_bytes_snapshot_and_postexit_result |
| Strict pending schema, encoding and limits | test_pending_closed_schema_and_duplicate_rejection; test_pending_strict_encoding_bounds_and_target_equality; test_pending_size_refusal_precedes_json_parse; test_pending_encoder_applies_cap_after_encoding |
| Refusal and per-artifact evidence | test_each_storage_failure_retains_per_artifact_evidence; test_every_checkpoint_failure_prevents_next_publication; test_formal_publisher_evidence_requires_exact_boolean; test_late_descriptor_occupancy_keeps_pending_evidence |
| Acquisition, entry, exit and cancellation | test_acquire_failure_has_no_owned_resource_or_fallback; test_failed_entry_closes_acquired_owner_once; test_cancellation_propagates_and_owned_resources_unwind; test_later_exit_cancellation_is_not_hidden_by_earlier_ordinary_failure |
| Fixed results and isolation | test_every_result_state_is_frozen_slotted_and_unapproved; test_result_constructor_rejects_inconsistent_progress; test_component_imports_exact_public_boundaries_and_has_no_runtime_consumer |
| Linux storage and separate process | test_native_success_retains_private_records_and_refuses_new_call; test_native_occupied_entry_never_reads_overwrites_or_deletes; test_native_root_guards_refuse_without_repair; test_native_failures_retain_residue_and_separate_observer_never_resumes; test_native_one_lock_blocks_contenders_through_all_writes_and_reads |

The descriptor guard is renamed test_only_pure_standard_library_dependencies_and_only_approved_runtime_consumer; only its final consumer check becomes the exact preparation-module singleton. Its purity/AST restrictions and other cases remain intact. The record guard adds the preparation filename to both exact dependency sets; the lock guard adds the same filename once; the directory test adds it only to the final publisher tuple with a minimal comment update.

No direct directory consumer or record consumer is added. Existing validator cases remain 347 and record/scope cases remain 387. All other fixture, parameterization, marker, assertion and runtime boundaries remain unchanged. The new component has no runtime consumer.

### 9.4 Local verification and limits

Verification used the existing Windows Python 3.12.14 environment with package resolution to this repository's src. Installed pytest 8.4.2, pytest-socket 0.8.1, Ruff 0.16.4, mypy 1.20.2, pydantic 2.13.4 and build 1.5.0 metadata matched uv.lock. This is metadata comparison, not frozen installation; no dependencies or environment were installed/rebuilt.

The interpreter ran with -B and an in-memory diagnostic collector. pytest.main used -q, -p no:cacheprovider and --basetemp targeting a previously absent, dedicated synthetic test location within the permitted workspace. No persistent runner was created. Existing conftest, strict settings and socket prohibition stayed active.

| Executed target | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: |
| tests/test_token_enrollment_preparation_phase6d1h.py | 247 | 0 | 0 | 18 | 0 |
| tests/test_token_enrollment_descriptor_phase6d1h.py | 347 | 0 | 0 | 0 | 0 |
| tests/test_token_operation_record_phase6d1h.py | 331 | 0 | 0 | 56 | 0 |
| tests/test_posix_private_lock_phase6d1h.py | 4 | 0 | 0 | 24 | 0 |
| tests/test_posix_sensitive_directory_phase6d1h.py | 7 | 0 | 0 | 40 | 0 |
| tests/test_posix_private_create_phase6d1h.py | 2 | 0 | 0 | 41 | 0 |
| tests/test_token_reuse_policy_phase6d1h.py | 205 | 0 | 0 | 0 | 0 |
| tests/test_no_network_or_google_dependencies.py::test_source_package_has_no_eager_network_google_or_oauth_imports | 1 | 0 | 0 | 0 | 0 |
| Total | 1144 | 0 | 0 | 179 | 0 |

All seven listed full test files ran in full. All four amended guards executed and passed. New pure/mock/structural cases: 247 passed. New Linux native cases: 18 OS-conditioned skips, including the separate-process observer scenarios; those behaviors remain unexecuted here. The observer helper is inside the test file, has a __main__ guard and finite child timeout, reads only test-owned leaves and never reruns pytest or resumes preparation.

Ruff check --no-cache --output-format json . and Ruff format --check --no-cache . passed; formatting checked 265 files. Strict mypy with --strict --no-incremental --cache-dir=nul --no-pretty passed for the new module and separately all 120 src files. Three initial lint findings in the new test were corrected without ignores, skips or weakened assertions. git diff --check, direct untracked-file whitespace/content inspection and exact allowed-guard-delta checks are separate source/document checks.

Status: IMPLEMENTED_VALIDATION_INCOMPLETE. Windows mocks do not validate Linux storage. Linux real I/O, separate-process observation, forced termination, power loss and new CI were not executed; run 35808486277 covers the prior HEAD only. Real enrollment/approval, activation, revocation enforcement, active intent, multi-lock coordination, session/provider access, pending release, recovery and a restart reader remain unimplemented. No commit, push, PR operation or Google operation was performed. Implementation review and the missing Linux evidence remain required; this prototype grants no operational permission.
