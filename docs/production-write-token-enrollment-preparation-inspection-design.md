# Read-Only Inspection of Retained Synthetic Enrollment Preparation

Status: DRAFT_WITH_UNREVIEWED_READ_ONLY_INSPECTION_PROTOTYPE

## 1. Scope, recommendation and baseline

Propose a nonauthorizing inspection of exactly two retained synthetic CONTROL_ROOT leaves: administrative pending and descriptor. Observe presence, bounded validation and target agreement separately. Never call preparation to discover state, and never authorize enrollment, activation, resumption, clearing or credential use.

**Recommend placement A:** add a separate read-only public entry to the existing preparation module, sharing only its pure snapshot/codec functions. Preserve the writer unchanged and prove the read entry's reachable calls exclude writing. Section 7 compares the alternative.

**Current** means source at HEAD 2baf36076caf936f9d481a48614c80dc4240fed4, tree d9ba2b663236678478c8cd09b4be41fc5277394d. **Existing proposal** means [preparation design](production-write-token-enrollment-preparation-io-design.md), especially section 6, and the [bootstrap](production-write-token-enrollment-bootstrap-contract.md) and [enrollment/lock](production-write-token-enrollment-lock-design.md) contracts. **Proposed here** denotes the following new observation contract; **Open** denotes a blocking decision, not approval.

Inherited evidence reports PR #17 Open/Draft/unmerged and successful eight-job run 35856042144, attempt 1, pull_request. Preparation-file results reportedly were Ubuntu 265 passed/0 skipped and Windows 247 passed/18 skipped, included in base totals. File progress and definitions are not individual passing-node evidence. Lock contention used a separate acquisition in the same process; the child observer only read residual records. This proves neither cross-process contention nor forced-termination/power-loss recovery. Existing DRAFT/old-CI labels remain historical. No remote query, test or application import occurred here; this design was not in that CI. Original scan findings were not consulted; no audit closure follows.

## 2. Existing boundaries

References below were checked at this fixed HEAD.

| Repository-relative source and symbol | Current fact affecting the design |
| --- | --- |
| [src/tridentine_calendar_google_sync/production_write_token_enrollment_preparation.py](../src/tridentine_calendar_google_sync/production_write_token_enrollment_preparation.py), _snapshot 308-322 | Copies eleven exact-string expectation fields, validates supplied bytes with the public validator, requires PREPARING, then constructs Path and expected pending bytes without content I/O. |
| Same module, _valid_pending 230-247, _canonical_pending 250-257, _unique_object 275-281, _matches_pending 288-305 | Pure codec exists; _matches_pending collapses malformed, uncheckable and mismatched input into False. It is insufficient for richer observations. |
| [src/tridentine_calendar_google_sync/production_write_token_enrollment_descriptor.py](../src/tridentine_calendar_google_sync/production_write_token_enrollment_descriptor.py), validate_enrollment_descriptor 231-256 | No expectation-only public API or decoded metadata result. MATCHED and MISMATCH follow strict canonical validation; DESCRIPTOR_UNVERIFIABLE also includes ordinary parsing/encoding/hash failures. |
| [tests/test_token_enrollment_preparation_phase6d1h.py](../tests/test_token_enrollment_preparation_phase6d1h.py), _observer_main 1093-1116; _observe_child 1078-1090 | Test-only fixed-fixture comparison without owned lock/root checkpoints; ten-second child timeout. It is not a runtime inspector or startup policy. |
| [src/tridentine_calendar_google_sync/_posix_private_lock.py](../src/tridentine_calendar_google_sync/_posix_private_lock.py), acquire_posix_private_directory_lock 102-141; _PrivateDirectoryLock 55-99 | Acquisition returns an already-owned resource. Entry can fail; close detaches ownership; failed revalidation may already invalidate it. |
| [src/tridentine_calendar_google_sync/sensitive_paths.py](../src/tridentine_calendar_google_sync/sensitive_paths.py), read_private_sensitive_bytes 472-503; POSIX reader 328-453 | Bounded regular/single-link/effective-owner/private-permission reads; no borrowed lock descriptor or atomic final-name identity evidence. Some close errors are suppressed. |

Do not reuse writer _Progress/PreparationResult, _occupied or _read_pending as inspection observations: they respectively describe publication, lose entry kind, or collapse validation distinctions.

## 3. Independent inputs before I/O

**Proposed API:** inspect_synthetic_enrollment_preparation(control_root: object, expected_raw: object, expectation: object) -> PreparationInspection.

All three arguments are mandatory. CONTROL_ROOT is an exact Linux-path string under the existing lexical restrictions, not a trusted deployment assertion. Expectation is the exact SyntheticEnrollmentExpectation with eleven exact-string fields. expected_raw is independent, exact immutable canonical descriptor bytes, at most 8192 bytes, supplied alongside the expectation by a test harness from independently prepared synthetic fixtures.

Reuse _snapshot with expected_raw: the existing public validator verifies both expectation consistency and the expected descriptor before any content read or lock. This is meaningful independent input, not a dummy candidate. It explicitly restricts the expected administrative state to PREPARING; a matched ACTIVE/REVOKED expectation yields PREPARING_REQUIRED before I/O. Other defects yield INPUT_UNVERIFIABLE. Unsupported Linux/OS combinations stop before hooks, Path construction and I/O.

Privately retain the copied expectation, expected bytes, root and encoded expected pending. Derive the two leaf names only from snapshot administrative_pending_slot and descriptor_slot, retaining their validated collision rules. Never change expectations from stored descriptor, pending target_pin or later reads. No writer-result/history argument, approved Boolean, callback or global history store is accepted. A new process without independent expectations stops here rather than learning them from disk.

Root and ancestor metadata needed by existing private guards are allowed. Content access is limited to those two leaves: no directory enumeration, root search, PAIR_ROOT/token/state/START/active-intent access, or expansion of artifact_directory into an additional path.

The caller-selected root supplies no independently approved location. Equal spelling is not filesystem identity or authenticated deployment. This API intentionally has no separate expected-location input; consequently it cannot detect a copied pair merely because the caller selects its destination. Private checks test current access policy/binding, not registration. Controlled launcher provenance, administrator approval and protection against equal-authority replacement remain unimplemented.

## 4. Fixed observations and internal comparisons

**Proposed new frozen/slotted result:** PreparationInspection contains state, pending, descriptor, target_relation, non_preparing_observed, verification_complete, first_failure, exit_failure_observed and constructor-excluded reuse_authorized=False. Each leaf is a frozen LeafObservation with the fields below. No raw bytes, paths, references, pins, metadata, stat values, prior publication flags or permits escape.

| Leaf field | Closed values and meaning |
| --- | --- |
| presence | UNKNOWN, ABSENT, PRESENT. PRESENT becomes sticky whenever an entry is seen. ABSENT requires both planned metadata checks to report absence and the root checks to succeed; otherwise unresolved absence is UNKNOWN. |
| content | NOT_READ, READ_UNVERIFIABLE, SCHEMA_UNVERIFIABLE, SCHEMA_VALID. Unsafe kinds/private-read errors do not establish valid pending. SCHEMA_UNVERIFIABLE deliberately does not assert proven corruption. |
| target | NOT_COMPARED, MATCH, MISMATCH. Comparison requires SCHEMA_VALID. |
| changed | Boolean indicating an observed disappearance, appearance or signature change; never proof of freshness when False. |

A new pure pending classifier may share the unchanged codec primitives. It strictly checks the five keys, exact types, duplicate/unknown keys, canonical UTF-8/LF and 512-byte bound before comparing target_revision/target_pin with the retained expectation. Do not infer which check failed from _matches_pending=False.

For descriptor bytes, use only the public validator for schema/canonical acceptance and target comparison. DESCRIPTOR_UNVERIFIABLE maps to SCHEMA_UNVERIFIABLE, not SCHEMA_INVALID; unexpected expectation refusal during reading also fails verification without replacing the snapshot. Ordinary helper failures remain fixed refusals; cancellation propagates.

After schema validity is established, a new bounded, pure extraction step may decode the same validated bytes to obtain descriptor revision/state privately and compute SHA-256 of those bytes. Compare pending's validated revision/pin to that observed descriptor revision/digest. This is observed-to-observed comparison, never a new expectation or a second descriptor-schema implementation. Hash no unvalidated payload or credential. Extraction failure retains established schema/mismatch facts but leaves target_relation=NOT_COMPARED and verification incomplete.

target_relation is NOT_COMPARED, MATCH or MISMATCH. It distinguishes mutually inconsistent records from two mutually consistent records that both disagree with expectations. A canonical ACTIVE/REVOKED descriptor conflicts with the PREPARING expectation and sets non_preparing_observed=True. That flag does not execute activation or revocation.

first_failure records the first failing stage from a fixed set: NONE, INPUT, ACQUIRE, ENTRY, PENDING_ENTRY, DESCRIPTOR_ENTRY, PENDING_READ, DESCRIPTOR_READ, PENDING_SCHEMA, DESCRIPTOR_COMPARE, TARGET_EXTRACTION, ENTRY_CHANGED, ROOT_CHECK, EXIT. Later exit failure additionally sets its Boolean flag. Leaf facts retain later observable defects without replacing earlier facts. No exception text is returned or retained globally.

verification_complete means all planned metadata, safe-read/schema, comparison, root and exit requirements completed. It may be True for stable absence or well-formed mismatches; it never means authorized. Any failed required step makes it permanently False. Constructor checks must reject target comparisons without PRESENT/SCHEMA_VALID, complete results with failures/changes, and any reuse authorization.

## 5. Finite owned observation

Use one existing exclusive, nonblocking private-directory lock. Read-only does not justify omitting cooperative exclusion, using another mode or falling back unlocked. No borrowed scope, multiple lock, publisher or output-preflight call belongs here.

| Stage | Proposed operation and failure behavior |
| --- | --- |
| 1 | Platform gate and independent snapshot validation; no storage on refusal. |
| 2 | Acquire once, enter once, then caller checkpoint K1. Acquisition failure transfers no owner. |
| 3 | lstat pending then descriptor without following final symlinks. Record presence/kind independently; only FileNotFoundError is an absence candidate. Other errors remain unknown. Run K2. |
| 4 | If initially regular and not already unsafe, read pending once with max_size=512, classify and retain facts. Unsafe/nonregular/symlink/hardlink entries are refusal observations without ordinary-reader fallback. Run K3. |
| 5 | If eligible, read descriptor once with max_size=8192; run the public validator and bounded extraction/cross-target comparison. An ordinary leaf failure does not erase the other leaf's known facts. |
| 6 | Repeat lstat once per leaf, compare known signatures, then caller checkpoint K4 immediately before exit. Newly appeared entries are not content-read. |
| 7 | Release through the owned context; construct the public result after unwind. Only normal completed exit can support verification_complete=True. |

Maximum per call: one acquisition, four caller root checkpoints, four leaf lstats and two private content reads. Backend-internal finite checks are separate. Stop further leaf operations immediately after a root-checkpoint failure: revalidation may have invalidated ownership. A pending content-read/classification failure still requires successful K3 before the single descriptor read. Scheduled initial/final metadata checks may finish while no root-check failure has been observed; they never repair an earlier failure. Never reread content until a convenient match appears.

Keep initial signatures privately, using device/inode, mode, ownership, link count, size and mtime/ctime. Exclude atime because reading may change it. A PRESENT-to-absent transition retains PRESENT plus changed=True; absent-to-PRESENT also sets changed and records PRESENT without a late content read. Metadata/read exceptions never manufacture absence. Preserve prior successful schema/target observations as bounded earlier facts, not current-state guarantees.

Following successful acquisition, failed __enter__ requires one public close(), whose existing detachment semantics safely handle prior internal invalidation. Successful entry receives exactly one __exit__, with no fallback close/retry or raw descriptor access. Preserve first ordinary failure and observed cancellation across later ordinary cleanup failures. Backend-suppressed or already-replaced exceptions cannot be recovered; exit_failure_observed=False is not a certificate that every close succeeded.

Read-only excludes content, permissions and configuration mutation, not OS-managed metadata changes such as atime. The reader returns no final-name identity tied to the outer lock. Before/after lstat and root checkpoints do not create atomic binding or detect every same-user substitution-and-restore. No mtime, ctime or current clock proves freshness.

## 6. Summary precedence and old classification mapping

The new result type is distinct from writer and validator enums. Gate classifications are INPUT_UNVERIFIABLE, PREPARING_REQUIRED, UNSUPPORTED_PLATFORM, LOCK_BUSY and LOCK_UNAVAILABLE; their leaf observations remain unknown/unread.

After access, known expected-target mismatch, cross-target mismatch or non-PREPARING observation takes precedence as PREPARATION_CONFLICT, even if later verification fails. Otherwise any incomplete/unsafe/changed observation yields PREPARATION_UNVERIFIABLE. Only completed stable observations select the absence/match rows below. This preserves known negative facts while preventing a half-known pair from becoming a one-record conclusion.

| Observations | Proposed summary and retained qualifications |
| --- | --- |
| Both leaves stably absent | ABSENCE_UNVERIFIABLE; observed absence grants no initial enrollment or retry. |
| Pending valid/matching; descriptor definitely absent | ADMIN_PENDING; target obligation observed, not previous completion. |
| Descriptor valid/matching; pending definitely absent | ORPHAN_DESCRIPTOR; preparation sequence unestablished. |
| Both valid/matching | PREPARATION_RETAINED_UNAPPROVED; retained pending remains unresolved. |
| Any valid target mismatch | PREPARATION_CONFLICT; retain each independently observed match/mismatch. |
| Both valid but their targets differ | PREPARATION_CONFLICT with target_relation=MISMATCH. |
| Corrupt/unreadable/unsafe leaf; other leaf absent, known or unknown | PREPARATION_UNVERIFIABLE unless conflict already known; never label mere broken pending presence ADMIN_PENDING. |
| Entry disappears/changes after presence | Keep PRESENT/earlier content facts, changed=True and incomplete verification; no empty-store inference. |
| Matching contents then root/exit failure | PREPARATION_UNVERIFIABLE with earlier facts and failure flags; prior conflict still wins. |
| Canonical ACTIVE/REVOKED observed | PREPARATION_CONFLICT plus non_preparing_observed; no administrative execution. |

ABSENCE_UNVERIFIABLE, ADMIN_PENDING, ORPHAN_DESCRIPTOR, PREPARATION_RETAINED_UNAPPROVED, PREPARATION_CONFLICT and PREPARATION_UNVERIFIABLE retain their purposes with these completion/per-leaf qualifications. FRESHNESS_UNPROVEN is a universal limitation of matching observations, not a detected-rollback state or extra permission flag. Self-consistent old records and old expectations are observationally indistinguishable from currently intended ones without an independent freshness anchor.

BINDING_UNVERIFIABLE cannot mean copied-location detection with this input set. Root-check failure leaves verification incomplete and yields PREPARATION_UNVERIFIABLE unless known conflict takes precedence. Record first_failure=ROOT_CHECK only when it is the first failure; otherwise retain the earlier cause. An independently retained expected location would require a separate trust/input contract; matching caller-controlled paths would still not authenticate deployment. This explicitly narrows the earlier proposal's unspecified binding label.

Upstream ADMIN_PENDING, ADMIN_COMMIT_UNCERTAIN and ADMIN_REVOKED are never cleared. This API accepts no prior PreparationResult and reconstructs none of its attempted/publication/exit evidence. Current successful reading cannot establish an earlier writer's normal return, vanished failure details or completed history. Its output is a possible future policy input, not implemented startup/session enforcement.

## 7. Placement and precise guard impact

| Choice | Read-only proof, sharing and review cost |
| --- | --- |
| A: existing preparation module, recommended | Share unchanged pure helpers; add independent observation state and entry. No writer body or consumer-set change. Publisher import remains present, so entry-specific reachability and zero-call spies are required. Smallest contained review. |
| B: new inspection module | No publisher/writer dependency makes import-level isolation clearer. Must independently implement the small pending classifier and snapshot checks, or separately extract shared code with additional writer/guard changes. Three existing consumer guards need exact new-caller additions. |

Do not import private writer helpers from B. Do not extract a general framework for A. Leave _Progress, PreparationResult, _read_pending, _preflight, _publish, _run_owned and prepare_synthetic_enrollment outside the new entry's reachable call graph. Reuse only the pure platform/root/snapshot/codec helpers and existing lock/private-reader boundaries.

B would add src/tridentine_calendar_google_sync/production_write_token_enrollment_preparation_inspection.py and tests/test_token_enrollment_preparation_inspection_phase6d1h.py, plus the three guard files below and a design evidence append. These are hypothetical future paths, not current edits.

| Future path | New dependency | Current test/assert | Limited change | Preserve | Separate permission |
| --- | --- | --- | --- | --- | --- |
| src/tridentine_calendar_google_sync/production_write_token_enrollment_preparation.py | A: new entry, stdlib metadata hashing, existing reader/lock | Preparation test's exact package imports | Append observer/types/pure classifier; no package import additions | Writer API, bodies, bytes, result meanings | A implementation |
| [tests/test_token_enrollment_preparation_phase6d1h.py](../tests/test_token_enrollment_preparation_phase6d1h.py) | A: read-entry tests | test_component_imports_exact_public_boundaries_and_has_no_runtime_consumer, 1119-1178 | Append reachable-call and fault tests; no existing assertion relaxation | Package set, public-validator imports, no consumer; existing 265 cases and test-only observer | A tests |
| [tests/test_token_enrollment_descriptor_phase6d1h.py](../tests/test_token_enrollment_descriptor_phase6d1h.py) | B only: additional validator caller | test_only_pure_standard_library_dependencies_and_only_approved_runtime_consumer, 573-621 | A: none; B: add exact filename to final singleton set | Validator purity/AST and 347 cases | Only if B selected |
| [tests/test_token_operation_record_phase6d1h.py](../tests/test_token_operation_record_phase6d1h.py) | B only: additional lock caller | test_only_exact_reviewed_modules_directly_import_lock_and_publisher, 392-415 | A: none; B: lock set only | Publisher set and test_component_has_no_runtime_consumer_or_dynamic_import_and_no_mutation_escape, 418-487 | Only if B selected |
| [tests/test_posix_private_lock_phase6d1h.py](../tests/test_posix_private_lock_phase6d1h.py) | B only: direct lock import | test_component_has_no_artifact_write_no_wait_loop_and_only_approved_consumers, 411-443 | A: none; B: one allowed_consumer | No-write/repair/wait-loop assertions | Only if B selected |
| [tests/test_posix_sensitive_directory_phase6d1h.py](../tests/test_posix_sensitive_directory_phase6d1h.py) | No new direct dependency | test_directory_foundation_only_has_the_reviewed_backend_consumers, 351-410 | None for either choice | Both direct-directory and publisher sets | No expansion proposed |

Keep [test_source_package_has_no_eager_network_google_or_oauth_imports](../tests/test_no_network_or_google_dependencies.py), record isolation and related network/privacy checks unchanged. No publisher allowance is added under either option.

For A, new tests must statically follow the read entry's transitive helper calls using a closed allowlist and reject dynamic/hidden dispatch. Install BaseException spies on every writer/publisher/output-preflight path for successful and failing inspections; ordinary exception handling must not conceal a forbidden call. Existing module-wide import checks alone do not prove this boundary.

## 8. Verification plan and one implementation candidate

No tests or storage experiments were performed for this design.

| Input/fault injection | Required retained facts/classification | Forbidden effect |
| --- | --- | --- |
| Bad independent inputs, pin contradiction, unsupported OS | Gate refusal before effects | Lock/read/hooks on unsupported platform |
| Every presence combination, unsafe kind, oversized/hardlinked file | Distinct presence/content/target; unknown never absent | General-reader fallback |
| Valid matching, malformed, foreign pending/descriptor | Match/conflict/schema-unverifiable distinctions | Expectations from stored values |
| Known pending/conflict then other read/root/exit failure | Earlier facts and conflict retained; completion False | Failure clearing |
| Appearance/disappearance/signature change | Sticky presence, changed flag, no retry | Convenient-match reread |
| Stable absence, matching old values or copied root | Absence remains refusal; freshness/location limits | Enrollment/resume/clear permission |
| Entry/exit failure and cancellation | Correct ownership unwind; cancellation propagates | Double close/reacquisition |
| New-process pending-only/both-record observation | Independent fixture expectations; fixed nonauthorizing output | Writer reuse or pytest-suite restart |

Instrument publisher, preparation writer, output preflight, deletion, permission repair and resume calls at zero, and compare retained record bytes/names/modes before and after. Preserve existing writer 265, validator 347 and record 387 cases plus private-backend/guard regressions. Separate Windows pure/mock/platform checks, Linux actual read-only I/O, orderly new-process observation, and independently scoped forced-termination/power-loss qualification.

**One next candidate:** implement A in the existing preparation source and test files, with a limited implementation/evidence append to this design file, docs/production-write-token-enrollment-preparation-inspection-design.md: three paths, zero consumer-set relaxations. Preserve the old writer and _observer_main; add dedicated inspection tests rather than promote that helper.

Before work, maintainers approve the result vocabulary, finite schedule, validated-byte extraction and reachable-call proof; the user separately authorizes those three paths and synthetic test locations. Acceptance requires all negative/zero-effect cases, retained evidence, existing regressions and applicable Python 3.12 strict/socket, Ruff, mypy and CI/build checks. Stop if the read entry needs any writer effect, private cross-module borrowing, extra guard relaxation or unapproved file change.

No concrete blocker requires another design phase for this bounded candidate. Trusted expected-location provenance, freshness anchors, atomic reader/name binding and stronger cleanup/durability guarantees remain **Open**, owned by maintainers/deployment owners and blocking real startup/operational claims. Exclude actual registration, activation/revocation execution, clearing, recovery, active intent, coordinator, launcher, session and provider integration.

DS-04 remains PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 scan FAIL; Production gate BLOCKED; live handlers hard-off; Registry empty/fail-closed; PR #17 Draft in inherited evidence. This document authorizes no implementation, commit, push or operational use.

## 9. Unreviewed read-only inspection prototype

This separately authorized prototype implements option A in the existing preparation source/test and appends this section. The original design above remains historical; the additional interpretation, constructor and reachability rules here describe the current unreviewed implementation. No writer, backend, validator or existing consumer guard was relaxed.

### 9.1 Interface and fixed observations

inspect_synthetic_enrollment_preparation(control_root, expected_raw, expectation) now returns PreparationInspection with the nine fields specified in section 4. InspectionState, Presence, ContentStatus, TargetRelation and InspectionFailure are separate closed enums; LeafObservation and PreparationInspection are frozen/slotted and never authorize reuse.

The unchanged _snapshot validates the independent expected bytes and copies the eleven original expectation fields. The read path never learns expectations from records, reserializes a candidate as authority, or accepts a prior writer result. Expected ACTIVE/REVOKED is an input gate refusal; schema-valid stored ACTIVE/REVOKED is instead a conflict observation with non_preparing_observed=True.

Existence, safe reading, schema confirmation and expected-target comparison remain separate. Empty bytes returned by a successful bounded private read proceed to schema verification and become SCHEMA_UNVERIFIABLE; reader errors, unsafe entry metadata and invalid reader return types do not establish a safe schema observation. Descriptor validation uses only the existing public API. Its ordinary verification failures are not asserted to prove corrupt bytes.

Only schema-valid descriptor bytes enter _inspection_extract_descriptor and _inspection_digest. The former reads revision/state from the same already-validated immutable bytes; the latter hashes only those bytes. Pending target values and observed descriptor revision/digest are compared privately. Schema and expected-target mismatch survive later extraction failure. Two foreign but mutually consistent records may both mismatch expectations while target_relation=MATCH.

### 9.2 Schedule, failures and ownership

The implemented schedule is K1, initial pending/descriptor metadata, K2, at most one pending read/classification, K3, at most one descriptor read/comparison/extraction, final pending/descriptor metadata, K4, then context exit. One acquisition, four caller checkpoints, four leaf lstats and two content reads are the maxima. Root failure escapes the body to abort every later metadata/read step. Locally classified leaf failures allow only the remaining scheduled observations; they are never cleared.

PRESENT is sticky. Confirmed appearance/disappearance/signature differences set changed; initial UNKNOWN followed by PRESENT does not claim an appearance. ABSENT requires both absence observations and K4 success. Later exit failure may retain that bounded absence fact while verification_complete remains False. Signatures remain private and exclude atime; matching signatures prove neither freshness nor atomic read/name binding.

| Failure boundary | first_failure when no earlier failure exists |
| --- | --- |
| Invalid/mismatched independent input or non-PREPARING expectation | INPUT |
| Acquire / failed entry | ACQUIRE / ENTRY |
| Unknown/unsafe pending or descriptor metadata | PENDING_ENTRY / DESCRIPTOR_ENTRY |
| Private read or invalid reader return | PENDING_READ / DESCRIPTOR_READ |
| Pending schema/canonical verification | PENDING_SCHEMA |
| Descriptor public comparison cannot verify | DESCRIPTOR_COMPARE |
| Validated-byte extraction or digest failure | TARGET_EXTRACTION |
| Observed appearance/disappearance/signature change | ENTRY_CHANGED |
| Caller root checkpoint / observed exit failure | ROOT_CHECK / EXIT |

A fully observed target mismatch is not a processing failure: PREPARATION_CONFLICT may have verification_complete=True and first_failure=NONE. Known conflict wins the summary even when later verification fails. All other post-entry incomplete observations are PREPARATION_UNVERIFIABLE. Only complete stable observations select ABSENCE_UNVERIFIABLE, ADMIN_PENDING, ORPHAN_DESCRIPTOR or PREPARATION_RETAINED_UNAPPROVED.

Constructor checks validate exact enum/Boolean/leaf types before comparison and enforce represented consistency. They reject comparisons without valid present content, complete results with failures/changes, incompatible gate causes, and EXIT as first failure without an observed exit failure. They allow two expected-target mismatches with mutual agreement. These checks cannot certify the actual I/O history or approval.

Inspection's private work state is allocated before acquisition. Acquisition failure has no caller-owned cleanup; failed entry triggers one idempotent public close. Successful entry receives one exit with the actual escaping body exception, if any, never an exception fabricated from mismatch. No extra close follows. Observed cancellation propagates despite later ordinary cleanup failure. Earlier failures are retained and later exit failure adds its flag. Suppressed backend close errors remain unobservable.

### 9.3 Writer separation and preservation

Only standard-library hashlib/stat imports and new definitions were added to source. Its original 21 function/class definitions and two constants remain identical by literal range and AST comparison; removing the two added imports restores the complete original source prefix. The original test's 50 function/class definitions, six constants and pre-main prefix remain unchanged, preserving the existing 265 cases, _Harness, _observer_main and _observe_child. The only changed main dispatch selects the new helper for --inspect and otherwise calls the unchanged old observer.

The new closed call-graph test follows local helpers, methods, constructors, __post_init__ and dataclass factories. It explicitly handles the unchanged snapshot's fixed-field getattr and trusted standard-library/private reader/lock boundaries. It rejects unknown callees, protected-name/namespace rebinding, hidden aliases, dynamic dispatch, unreviewed JSON callbacks and dynamic type construction; synthetic AST negative cases verify those checks without editing runtime source. These checks cover the reviewed call forms, not a general Python alias-analysis proof.

BaseException sentinels and counts cover the preparation writer, writer result/progress, occupancy/read-pending helpers, publisher and output preflight. They cannot be hidden by ordinary exception handling. No forbidden path is called during the inspection tests. Existing application import/public-validator symbol sets, validator purity, exact lock/publisher consumers, record isolation and preparation's no-external-consumer guard remain unchanged.

### 9.4 Verification record

Local validation used Windows / Python 3.12.14 and the existing environment, with package resolution to this repository's src. Installed pytest 8.4.2, pytest-socket 0.8.1, Ruff 0.16.4, mypy 1.20.2, pydantic 2.13.4 and build 1.5.0 metadata matched uv.lock. This was metadata comparison, not frozen installation; no installation or environment rebuild occurred.

An in-memory diagnostic collector ran the existing interpreter with -B and pytest.main using -q, -p no:cacheprovider and --basetemp in a previously absent, dedicated permitted workspace location. The existing conftest, strict settings and socket prohibition remained active. No persistent runner or new test file was created.

The final run included all seven required test files in full plus the specified network-import node:

| Target | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: |
| tests/test_token_enrollment_preparation_phase6d1h.py | 433 | 0 | 0 | 39 | 0 |
| tests/test_token_enrollment_descriptor_phase6d1h.py | 347 | 0 | 0 | 0 | 0 |
| tests/test_token_operation_record_phase6d1h.py | 331 | 0 | 0 | 56 | 0 |
| tests/test_posix_private_lock_phase6d1h.py | 4 | 0 | 0 | 24 | 0 |
| tests/test_posix_sensitive_directory_phase6d1h.py | 7 | 0 | 0 | 40 | 0 |
| tests/test_posix_private_create_phase6d1h.py | 2 | 0 | 0 | 41 | 0 |
| tests/test_token_reuse_policy_phase6d1h.py | 205 | 0 | 0 | 0 | 0 |
| tests/test_no_network_or_google_dependencies.py::test_source_package_has_no_eager_network_google_or_oauth_imports | 1 | 0 | 0 | 0 | 0 |
| Total | 1330 | 0 | 0 | 200 | 0 |

The preparation file collected 472 cases: its original 265 produced 247 passed/18 skipped; the 207 added inspection cases produced 186 passed/21 skipped. Groups were identified from original HEAD test names in the final collector. Validator 347 and record 387 cases were retained. All six specified existing structural guards executed and passed without modification.

Inspection coverage includes independent inputs/snapshot mutation, every presence combination, valid foreign targets, cross-target disagreement, strict schema failures, unsafe metadata, every root checkpoint, changing entries, extraction faults, constructor contradictions, ownership/cancellation and the closed no-writer graph. The Linux-only tests define real read-only fixtures, private guards including owner-readable 0400 files, same-process competing lock acquisition and a dedicated --inspect child with independent fixtures, fixed output and a finite timeout. None of those 21 native cases ran on Windows.

Ruff check --no-cache --output-format json . and Ruff format --check --no-cache . passed; formatting checked 266 files. Strict mypy with --strict --no-incremental --cache-dir=nul --no-pretty passed for the changed module and all 120 src files. Initial constructor-review findings and the new test alias lint finding were corrected only in added code/tests. Additional graph-negative cases prompted the final full rerun; earlier totals are not added to it. git diff --check, content/privacy review and literal/AST preservation checks are separate from program testing.

Status: IMPLEMENTED_VALIDATION_INCOMPLETE. New inspection Linux I/O, the new child-process route, cross-process lock contention, forced termination, power loss and new CI remain unexecuted here. Prior run 35856042144 does not validate this API. Actual startup enforcement, administrative resolution, resumption, prior-writer history reconstruction, true deployment provenance and freshness remain absent. No commit, push, PR change, actual registration or Google operation was performed. The result grants no operational authority.

## 10. Limited result-consistency and binding-regression correction

Sections 1-9 are retained as the preceding design and prototype validation record. This correction addresses two gaps in that uncommitted prototype: one contradictory result could be constructed, and the test-only reachability checker missed callee rebinding through iteration targets. Neither finding establishes that the normal inspection path invoked a writer, granted use authority or changed operational data.

### 10.1 Represented target consistency

Let E be the independent expected revision/pin tuple, P the pending target tuple and D the observed descriptor revision/digest tuple. The normal PreparationInspection constructor now rejects pending.target=MISMATCH, descriptor.target=MATCH and target_relation=MATCH. These observations would require P != E, D == E and P == D simultaneously. Rejection is the fixed ValueError("Invalid preparation inspection"), after the existing exact-type checks. No input value is interpolated, no mismatch is erased and no relation is normalized.

The same contradiction is rejected for complete observations, later ROOT_CHECK failure and later EXIT failure. Incomplete verification cannot make contradictory represented facts consistent. The existing both-expected-MATCH/mutual-MISMATCH rejection remains in force.

The following remain representable, with complete=True/first_failure=NONE or with the separately represented later failure:

| Pending versus expectation | Descriptor versus expectation | Mutual relation | Interpretation |
| --- | --- | --- | --- |
| MATCH | MATCH | MATCH | Consistent expected target |
| MISMATCH | MISMATCH | MATCH | The same foreign target |
| MISMATCH | MATCH | MISMATCH | Foreign pending and expected descriptor |
| MATCH | MISMATCH | MATCH | Tuple agreement does not imply all descriptor metadata agree |
| MATCH | MISMATCH | MISMATCH | Expected pending and differing descriptor |
| MISMATCH | MISMATCH | MISMATCH | Two different foreign observations |

The added rule is deliberately asymmetric: descriptor comparison covers all metadata, while pending and mutual comparisons concern tuples. The constructor checks represented consistency, not authenticity, actual I/O history, cryptographic collision impossibility or approval. All results still have reuse_authorized=False.

### 10.2 Bounded name-binding checks

The test-only _inspection_reachable_calls now checks Store/Del targets recursively. This includes ordinary, annotated, augmented and named assignments, for targets, tuple/list/starred destructuring and the common target structure of list, set, dict and generator comprehensions. Approved callee and namespace names cannot be rebound or deleted. Attribute/subscript targets cannot replace protected namespace contents or the reviewed receiver methods.

All positional-only, positional, keyword-only, variadic positional and variadic keyword parameter names are checked. Exception-handler as names cannot shadow protected callees, namespaces or the owned/work receivers. Local imports, nested definitions, with statements, asynchronous forms, pattern matching and type aliases are explicitly unsupported and rejected. They are not silently treated as safe. Ordinary safe loop/comprehension locals remain supported, including the existing codec iterations and _snapshot's fixed-field getattr.

At module scope, protected imports must retain their exact reviewed origin and alias, with no wildcard or relative substitution. External callee/namespace names cannot be replaced by module-level function/class definitions. Other unreviewed module-level statements are refused. This does not replace the unchanged application-import guard.

Receiver rebinding is also constrained: owned/work Store targets must be the existing direct assignment forms from their respective reviewed factories; for/comprehension/destructuring/deletion/walrus/exception rebinding is refused. The existing annotated-parameter and factory-origin checks still apply when their methods are visited. Constructor, __post_init__, dataclass default_factory and JSON callback traversal remain intact. The local/external call sets, external attribute set and forbidden set are unchanged.

This is a closed regression check for the explicitly reviewed syntax and dispatch forms. It is not a general Python alias-analysis framework, whole-process integrity proof or defense against arbitrary hostile code in the same process. No runtime source was temporarily replaced and no injected writer source was executed.

### 10.3 RED reproduction and GREEN coverage

New regression tests were added before either correction. The unchanged constructor/checker produced the required RED results: 0 passed, 33 failed, 0 errors, 0 skipped and 0 deselected. Three constructor cases failed specifically because ValueError was not raised. Thirty iteration cases failed specifically because AssertionError was not raised: five forms (for/list/set/dict/generator), three target shapes (name/tuple/nested list), and two source forms (minimal synthetic source and an in-memory AST copy of the real module). The real AST copies retained the original call graph. No collection, fixture or dependency failure was counted as reproduction.

The final additional regression group contains 121 cases, all passing. It includes the RED cases, starred targets, the six representable target combinations with three completion/failure outcomes, the existing opposite contradiction, the other parameter/binding/dispatch forms, alternate receiver bindings, safe local iteration and module binding substitutions. Two additional real-source AST-copy cases reject replacement json/private_lock classes while retaining the original imports and call graph. The untouched real source continues to produce the exact original allowed local reachability set, with no forbidden intersection.

| Contract | Regression test |
| --- | --- |
| New asymmetric contradiction; complete/root/exit outcomes | test_inspection_constructor_rejects_foreign_pending_equal_to_expected_descriptor |
| Six retained target combinations; no authorization | test_inspection_constructor_preserves_representable_target_relations |
| Existing both-MATCH/mutual-MISMATCH refusal | test_inspection_constructor_still_rejects_equal_targets_with_mutual_mismatch |
| Five iteration forms; four target shapes; both source forms | test_inspection_reachability_rejects_loop_bound_reader |
| Store/Del, exception/import/definition and unsupported dispatch | test_inspection_reachability_rejects_other_binding_and_dispatch_forms |
| Parameter binding categories | test_inspection_reachability_rejects_shadowing_parameters |
| Alternate owned/work bindings | test_inspection_reachability_rejects_alternate_receiver_bindings |
| Module import/definition substitution | test_inspection_reachability_rejects_module_binding_substitution |
| Namespace classes in copies of the real AST | test_inspection_reachability_rejects_namespace_class_in_real_ast_copy |
| Safe local iterations | test_inspection_reachability_preserves_safe_local_iteration |

The original graph-negative tests, exact-type-before-hook tests, no-writer sentinels and ownership/I/O-bound tests remain unchanged and pass where executable on Windows.

### 10.4 Local validation and preservation

Validation used the existing Windows / Python 3.12.14 environment and repository src resolution. Installed pytest 8.4.2, pytest-socket 0.8.1, Ruff 0.16.4, mypy 1.20.2, pydantic 2.13.4 and build 1.5.0 metadata matched uv.lock. This was not a frozen installation. No dependency installation, environment rebuild or Linux environment creation occurred.

The in-memory collector invoked the existing interpreter with -B and pytest.main, -q, -p no:cacheprovider and --basetemp pointing to a new permitted synthetic workspace location. It retained the project conftest, strict configuration/markers and socket prohibition. Diagnostics were captured before fixed classifications and counts were displayed. No persistent runner was created, and prior roots/logs/caches were not reused or deleted.

| Final full-file target | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: |
| tests/test_token_enrollment_preparation_phase6d1h.py | 554 | 0 | 0 | 39 | 0 |
| tests/test_token_enrollment_descriptor_phase6d1h.py | 347 | 0 | 0 | 0 | 0 |
| tests/test_token_operation_record_phase6d1h.py | 331 | 0 | 0 | 56 | 0 |
| tests/test_posix_private_lock_phase6d1h.py | 4 | 0 | 0 | 24 | 0 |
| tests/test_posix_sensitive_directory_phase6d1h.py | 7 | 0 | 0 | 40 | 0 |
| tests/test_posix_private_create_phase6d1h.py | 2 | 0 | 0 | 41 | 0 |
| tests/test_token_reuse_policy_phase6d1h.py | 205 | 0 | 0 | 0 | 0 |
| tests/test_no_network_or_google_dependencies.py::test_source_package_has_no_eager_network_google_or_oauth_imports | 1 | 0 | 0 | 0 | 0 |
| Total | 1451 | 0 | 0 | 200 | 0 |

The preparation file retains the original 265 cases (247 passed/18 skipped) and preceding 207 inspection cases (186 passed/21 skipped), plus 121 passing new cases. Validator 347 and record 387 cases are retained. These are this correction's measured results; earlier Codex results, supplemental ChatGPT isolated tests and prior CI are not added to these counts. The RED failures are not final regression failures.

Ruff check . --no-cache --output-format json and Ruff format --check . --no-cache pass, with 266 files checked for formatting. Strict mypy with --strict --no-incremental --cache-dir=nul --no-pretty passes for the changed module and all 120 src files. Added-test formatting findings were corrected without relaxing assertions. git diff --check and separate full-content, privacy, scope and literal/AST preservation reviews complete the local checks.

The original source's 21 definitions/two constants and original test's 50 definitions/six constants remain identical to HEAD by literal ranges and AST. Prior inspection tests remain intact. All six existing consumer guards execute and pass unchanged: preparation isolation/imports, pure validator consumers, exact record lock/publisher imports, record isolation, lock consumers and directory-backend consumers. Existing writer/codec/_snapshot/platform/root bodies, public field/enum values, schedule and I/O bounds are unchanged. Lock consumers remain three, publisher consumers excluding the publisher remain four, and the validator has one approved runtime consumer. Record and preparation still have no external runtime consumer.

Status remains IMPLEMENTED_VALIDATION_INCOMPLETE. New inspection Linux real I/O and its separate-process path were not executed on Windows; the 21 inspection native cases remain skipped. No new CI was run. Old run 35856042144 is not evidence for this corrected inspection code. The correction does not implement actual enrollment, startup enforcement, use authorization, administrative resolution, pending removal, resume or recovery.

Only the authorized preparation source/test and this appended design record were changed. HEAD, tree, branch and index remain unchanged, with zero staged files. No commit, push, PR change, remote communication, actual registration, OAuth, token refresh, Google API or Calendar operation occurred. DS-04 remains PARTIAL; Historical Deep Security Scan remains INCOMPLETE; the separate 47194b0 scan report remains FAIL; Production gate remains BLOCKED; live handlers remain hard-off; the packaged registry remains empty/fail-closed.
