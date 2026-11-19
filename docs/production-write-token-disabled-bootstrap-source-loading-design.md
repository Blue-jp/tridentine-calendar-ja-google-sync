# Synthetic Disabled Bootstrap Source Loading Boundary

Status: DRAFT_WITH_UNREVIEWED_SYNTHETIC_SOURCE_LOADER

## 1. Scope and evidence

Recommend one explicitly invoked Linux-only loader for test-owned synthetic sources. It reads two independently prepared files, retains their bytes with independently supplied expectations, then calls the existing nonauthorizing handoff at most once. For example, policy A and companion B may both be readable yet disagree with the retained plan; reading them does not approve B or authorize startup.

**Implemented** refers to HEAD `bc4491a09ab840e63881a53bb52cc0330c49ef50`, tree `13b5b445d47c106d7f64cc5e21fb54c039a83b10`. **Existing proposal** refers to the [input design](production-write-token-disabled-bootstrap-input-design.md), sections 2-3 and 6-8, and [bootstrap contract](production-write-token-enrollment-bootstrap-contract.md), sections 3-6. **Recommended** below is new loader work. **Open deployment decisions** do not block this separately authorized synthetic candidate.

Inherited external evidence reports PR #17 Open/Draft/unmerged, its English description updated, and CI evidence comment 5856525801. Run 36316289138, attempt 1, pull_request, .github/workflows/test.yml completed successfully with eight jobs. Both base logs showed handoff results: Ubuntu 312 passed/1 Windows-only skip; Windows 301 passed/12 Linux-only skips. File progress reconciled with fixed definitions supports ten Linux connection and two ordinary fresh-process cases, not individually listed passing node IDs. Counts are included in base totals. Six non-base jobs have job/step evidence only. Nothing was remotely rechecked here; none of this validates a loader or deployment. Historical document labels remain unchanged. Original scan-finding text was not consulted; no audit closure or Unit number follows.

| Fixed-HEAD evidence | Existing boundary |
| --- | --- |
| [Handoff source](../src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_inspection.py), _capture_inputs 59-79; inspect_synthetic_disabled_bootstrap 254-294 | Four retained inputs; checked validation precedes at most one Inspection. |
| Same, DisabledBootstrapInspectionResult 160-206; DisabledBootstrapInspectionResultError and _finish 209-251 | Checked nested diagnostics, fixed False, terminal construction error preserving checked negatives. |
| [Input source](../src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_inputs.py), validate_disabled_bootstrap_inputs 267-301 | Existing parsing, descriptor comparison, cross-input equality and PREPARING purpose gates. |
| [Descriptor source](../src/tridentine_calendar_google_sync/production_write_token_enrollment_descriptor.py), SyntheticEnrollmentExpectation 50-64 | Eleven public synthetic fields, not deployment authority. |
| [Reader source](../src/tridentine_calendar_google_sync/sensitive_paths.py), read_private_sensitive_bytes 472-503; POSIX implementation 328-453 | Public bounded private read, with limited identity and cleanup guarantees. |

The full [handoff design](production-write-token-disabled-bootstrap-inspection-design.md) and [Inspection design](production-write-token-enrollment-preparation-inspection-design.md), sections 3-6 and 9-10, supply the retained-input, negative-evidence and ownership boundaries.

## 2. Separate material roles

| Role | Recommended source | Meaning and exclusion |
| --- | --- | --- |
| Policy bytes | Explicit policy_leaf under source_root | Existing nine-field policy; cannot choose another source. |
| Complete expected descriptor bytes | Explicit expected_descriptor_leaf under that root | Independently prepared companion, never the observed descriptor. |
| Eleven-field SyntheticEnrollmentExpectation | Independent in-memory argument | Retain every field; never derive metadata or pin from either read. |
| expected_control_root | Independent in-memory argument | Comparison anchor, not the policy's own authority assertion. |
| Pending and descriptor under CONTROL_ROOT | Existing Inspection only after handoff validation | Observations, never bootstrap expectations. |
| PAIR_ROOT | Captured expectation.artifact_directory | Metadata for exclusion checks; no loader access. |

Choose one explicit source root and two distinct leaves as the smallest placement contract. Their preparation is independent of observed records; sharing a directory does not make them separate trust domains. Distinct source roots would add layout and metadata cases without establishing authority.

Retain the existing nine-key policy and complete companion format. A third metadata file would add parsing, partial-publication and provenance obligations for information already supplied independently. A new bundle schema changes compatibility and still cannot authenticate its origin. Neither is needed.

Proposed API, not created here:

```python
load_synthetic_disabled_bootstrap(
    source_root: object,
    policy_leaf: object,
    expected_descriptor_leaf: object,
    expectation: object,
    *,
    expected_control_root: object,
) -> DisabledBootstrapInspectionResult | DisabledBootstrapSourceRefusal
```

All five inputs are mandatory. Capture source_root, policy_leaf, expected_descriptor_leaf, expected_control_root, then expectation fields in that order. The fixed field list is enrollment_revision, administrative_state, storage_ref, pair_ref, artifact_directory, token_slot, state_slot, active_intent_slot, descriptor_pin, descriptor_slot and administrative_pending_slot. No callback, history, permit, borrowed lock, alternate root or previous result is accepted. Copy the exact public expectation's eleven exact-string fields once through a fixed local list into a fresh instance. Retain exact source/root/leaf strings, copied expectation and later both immutable byte objects in a private frozen/slotted container with every field excluded from repr. Export no snapshot; use no module-global cache. Existing handoff/API internal copies remain intact.

## 3. Capture and placement refusal

Before filesystem operations, require exact strings and the exact expectation class; refuse subclasses, implicit conversions and missing fields. Apply the documented Linux absolute-path lexical rules to source_root, expected_control_root and captured artifact_directory: at most 1024 UTF-8 bytes, non-root, no control/surrogate characters, backslash, colon, repeated/trailing separator, dot/parent/.git components or components ending in space/dot. This is a source-placement gate, not policy/descriptor parsing. Never borrow private validators.

Leaves are distinct single components of 1-96 ASCII characters: alphanumeric first, then alphanumeric, dot, underscore or hyphen; reject trailing dots and Windows device-name bases, including extensions. Join only retained root/leaf values. Reject relative paths instead of resolving them against cwd. No environment lookup, discovery, search order, alternate configuration, normalization or older-version fallback exists.

Using component boundaries, reject source_root equal to, containing, or contained by either captured CONTROL_ROOT or PAIR_ROOT. Distinct leaves reject identical source paths. These are lexical exclusions; never stat either target root to establish them. They do not prove mount identity or trust separation.

The fixture owner must establish actual source/target separation, safe ancestor placement, absence of mount aliases and no concurrent source replacement. These are external test conditions, not an approved Boolean accepted by the API. Metadata checks below detect some aliases and changes; they cannot certify those conditions. Without physical separation, a caller-selected source spelling could alias operational storage, which this prototype cannot safely discover.

Synthetic naming, private permissions, owner equality, a digest or a caller's source plan supplies no deployment provenance. Real installation must fix sources outside ordinary caller selection under a separately reviewed procedure; this proposal hardcodes no production location.

## 4. Finite read schedule and ownership

Recommend Linux-only source loading. Pure capture precedes a platform gate requiring Linux/POSIX; unsupported platforms return before metadata, private reading or handoff. The existing handoff is unchanged: directly calling it on Windows still performs capture/validation before Inspection's platform refusal. Adding Windows source reads would enlarge ownership and ACL coverage without enabling supported observation.

| Stage | Action and retained evidence | Maximum direct calls |
| --- | --- | ---: |
| Capture | Copy fixed inputs; validate lexical placement | No I/O |
| Platform | Refuse unsupported OS | No I/O |
| Precheck | lstat source root, policy leaf, companion leaf in that order | 3 metadata calls |
| Policy read | Public private reader; retain exact bounded bytes | 1 read |
| Companion read | Same reader and bound; retain exact bytes | 1 read |
| Recheck | Repeat root, policy, companion lstat; compare signatures and returned lengths | 3 metadata calls |
| Handoff | Pass retained policy bytes, companion bytes, expectation and keyword root | 1 handoff |

Stop immediately on the first acquisition refusal; do not continue the schedule to seek a convenient result. Root must be a nonsymlink directory owned by the effective user with mode 0700. Each leaf must be nonsymlink regular, effective-user-owned, single-link, owner-only, and 1-8192 bytes. Refuse equal leaf device/inode pairs. Both passes enforce these conditions. Privately compare device/inode, type/mode, uid/gid, link count, size, mtime_ns and ctime_ns; exclude atime. Require returned byte lengths to match retained leaf sizes. Any disappearance, changed signature or unavailable metadata stops before handoff. Maximum additional metadata calls is six; reader-internal checks are separate.

Use only read_private_sensitive_bytes(path, max_size=8192), once per source. Require exact bytes of length 1-8192 afterward. Its possible 8193rd byte detects overflow; accepted payload remains at most 8192. No generic read_sensitive_bytes, Path.read_bytes, permission repair, private-helper borrowing or replacement reader backend is proposed.

The public reader rejects nonlocal/unsafe paths, symlink components and Git worktrees (reader source 38-112). POSIX traversal uses no-follow directory/file descriptors and checks the opened file's owner, link count, mode, size and before/after identity/mtime (328-439). It does not enforce private ancestor permissions, require a 0700 parent, return final-name identity, or provide an atomic two-file snapshot. The loader's root/leaf metadata passes are new bounded detection, not those stronger guarantees or a cryptographic binding to bytes.

No source lock is added: externally immutable synthetic fixtures are the assumption. A cooperative lock would neither establish provenance nor exclude nonparticipants. The reader owns its descriptors; the loader owns only returned bytes and metadata. Allow each reader to unwind before proceeding and intentionally retain no source resource when Inspection acquires its CONTROL_ROOT lock. Holding source resources into Inspection would introduce acquisition ordering, alias and multi-directory unwind questions; do not borrow or nest existing scopes.

Reader finally blocks attempt closes but suppress some OSError failures (447-453). Normal return therefore cannot certify every close succeeded. Never guess descriptor numbers, retry cleanup or claim complete release. Ordinary reported acquisition errors become fixed refusal; cancellation propagates after existing unwind.

Policy semantics are checked only inside handoff, after both reads and rechecks. An invalid policy may therefore coexist with a completed companion read. It still cannot pass the handoff's validator gate into target observation. On any source-stage refusal there are zero handoff calls and no intentional CONTROL_ROOT, PAIR_ROOT or credential access, subject to the external separation condition.

## 5. Failure and uncertainty contract

Source-stage refusal is sticky for this call. No wait, repair, reread-until-match or retry exists.

| Observable condition | Stop / handoff calls | Retained public diagnostic | Still unknown |
| --- | --- | --- | --- |
| Missing/unreadable policy | Precheck or policy read / 0 | Stage-specific SOURCE_UNVERIFIABLE | Intended content and history |
| Missing/unreadable companion | Precheck or companion read / 0 | SOURCE_UNVERIFIABLE | Intended complete pair |
| Directory, symlink, hardlink, nonprivate or oversized leaf | Precheck/read / 0 | SOURCE_UNVERIFIABLE | Whether legitimate bytes exist elsewhere |
| Lexical overlap or equal observed leaf identity | Capture/precheck / 0 | SOURCE_OVERLAP | Undetected mount aliases |
| First read succeeds, second fails | Companion read / 0 | SOURCE_UNVERIFIABLE; no partial byte export | Pair consistency |
| Visible identity/content-metadata change during checks | Read/recheck / 0 | SOURCE_UNVERIFIABLE for reader refusal; SOURCE_CHANGED for explicit comparison | Unobserved substitution-and-restore |
| Only one source updated; expectations expose disagreement | Handoff validation / 1 | Complete existing refusal result | Which version was approved |
| Both readable but independent expectations disagree | Handoff validation / 1 | Existing mismatch/unverifiable diagnostic | Provenance |
| Entire coherent old set, including expectations, restored | May reach handoff / 1 | Existing unapproved result | Rollback and freshness |
| Pathname changes after final recheck | No further source check / at most 1 | Result concerns retained bytes | Current pathname contents |
| Ordinary handoff refusal | Handoff / 1 | Full checked four-field result | Operational eligibility |
| Invalid return or unexpected ordinary exception | Handoff / 1 | HANDOFF_RESULT_UNVERIFIABLE or HANDOFF_FAILED | Any unreported observation |
| Fixed handoff construction error | Handoff / 1 | Existing fixed exception and checked nested diagnostics | Suppressed backend failures |
| Cancellation at any phase | Immediate unwind / 0 or 1 | Original cancellation; no normal result | Unreported progress |
| Known upper ADMIN_PENDING, ADMIN_COMMIT_UNCERTAIN or ADMIN_REVOKED | Upper continuation remains stopped / 0 normally | Upper refusal retained independently | History absent from this API |

Two successful reads are not atomic same-version acquisition. Retained independent expectations detect exposed mixtures; coherent replacement of all anchors can compare equal. Revision labels, timestamps and current time cannot establish freshness. Missing sources never authorize initial enrollment or prove no unfinished history. A separately authorized diagnostic call may run while an upper refusal exists, but its result cannot replace or clear that refusal.

## 6. Public results and exception boundary

Avoid another envelope copying the handoff state machine. Return either the existing checked DisabledBootstrapInspectionResult or a new frozen/slotted DisabledBootstrapSourceRefusal containing only stage, reason and constructor-excluded reuse_authorized: Literal[False]. No success state or execution permit is added.

Closed stages are CAPTURE, PLATFORM, PRECHECK, POLICY_READ, COMPANION_READ, RECHECK and HANDOFF. Closed reasons are INPUT_UNVERIFIABLE, UNSUPPORTED_PLATFORM, SOURCE_OVERLAP, SOURCE_UNVERIFIABLE, SOURCE_CHANGED, HANDOFF_FAILED and HANDOFF_RESULT_UNVERIFIABLE. The constructor accepts only represented combinations from sections 4-5: capture input/overlap, platform unsupported, precheck unverifiable/overlap, either read unverifiable, recheck unverifiable/changed, handoff failed/invalid-result. Unknown combinations refuse.

For a handoff return, require its exact public type, capture its four fields once and check the original authorization is False. Reconstruct through the existing public result constructor to validate nested values and state consistency; do not import private checkers or duplicate nested schemas. Return that safe result without dropping pending, conflict, uncertainty or failure fields. Invalid returns contain no safely established diagnostic to export.

Catch the exact DisabledBootstrapInspectionResultError separately and propagate it with bare re-raise, retaining its already checked diagnostics and cleared links. Do not replace it with a source error. Other ordinary handoff exceptions yield HANDOFF_FAILED without original text. Preserve all non-Exception cancellations unchanged, including during checking/construction.

If constructing a source refusal fails, raise a zero-argument DisabledBootstrapSourceResultError with the fixed message `Disabled bootstrap source result construction failed` and False authorization, no raw payload. Clear only this newly created exception's cause/context using the handoff's documented local raise/catch/bare-raise pattern, including ambient caller except/finally. Never mutate caller, dependency or cancellation exceptions. This protects public diagnostics, not every traceback frame, hostile debugger or resource-exhaustion case.

No normal result or newly constructed source exception exposes a path, root, pin, metadata, bytes, original exception text, credential or acquired-input object. Acquisition success, private-read checks, semantic agreement and legitimate deployment remain separate claims.

## 7. Exact future dependencies and guard impact

Application dependencies are only inspect_synthetic_disabled_bootstrap, DisabledBootstrapInspectionResult and DisabledBootstrapInspectionResultError from handoff; SyntheticEnrollmentExpectation from descriptor; and read_private_sensitive_bytes from sensitive_paths. Standard-library capture, path/stat, enum and dataclass support suffices. No direct validator, Inspection, writer, record, lock, publisher or private directory dependency is needed.

Let A mean production_write_token_disabled_bootstrap_source_loading.py. References below were checked at the fixed HEAD.

| Existing test and location | Future change or preservation |
| --- | --- |
| [Handoff test](../tests/test_token_disabled_bootstrap_inspection_phase6d1h.py), test_closed_adapter_calls_cover_helpers_constructors_and_no_external_consumer, 1453-1457 | Empty consumer set becomes exactly {A}; preserve full scan. |
| Same, _APPLICATION_IMPORTS 1134-1148; _check_closed_adapter 1168-1443 | No change to closed imports/calls, receiver rules, item/namespace denials or 25-name positive test. New loader needs its own structural check. |
| [Descriptor test](../tests/test_token_enrollment_descriptor_phase6d1h.py), test_only_pure_standard_library_dependencies_and_only_approved_runtime_consumer, 616-625 | Add A alone to existing three-consumer set; preserve purity and scan. |
| [Disabled-input test](../tests/test_token_disabled_bootstrap_inputs_phase6d1h.py), test_closed_public_dependencies_no_effects_and_exact_consumers, 887-902 | Add A only to descriptor set at 893-902; bootstrap's handoff singleton stays unchanged. |
| [Private-read tests](../tests/test_private_secret_reads_phase6d1h.py), test_secret_loaders_have_no_generic_read_fallback, 247-264 | Existing selected-caller checks unchanged; add loader-specific coverage in new tests. |
| [Target tests](../tests/test_production_write_target_private_io_phase6d1h.py), test_production_target_loader_uses_only_strict_private_reader, 143-160; [generation tests](../tests/test_generation_state_private_read_phase6d1h.py), test_generation_loader_does_not_change_or_remove_files, 300-325 | Unchanged; inspected tests contain no package-wide exact private-reader consumer set. |
| [Preparation tests](../tests/test_token_enrollment_preparation_phase6d1h.py), test_component_imports_exact_public_boundaries_and_has_no_runtime_consumer, 1176-1181; _inspection_reachable_calls, 2108-2404; test_inspection_transitive_entry_excludes_writer_and_checks_constructors, 2407-2411 | Handoff-only consumer and existing reader graph unchanged; neither covers the new loader entry. |
| [Record tests](../tests/test_token_operation_record_phase6d1h.py), consumer/isolation guards 392-487; [lock tests](../tests/test_posix_private_lock_phase6d1h.py), consumer guard 411-443; [directory tests](../tests/test_posix_sensitive_directory_phase6d1h.py), backend guard 351-410 | Unchanged: no new record caller; direct lock consumers three, publisher consumers four excluding itself. |
| [Import guard](../tests/test_no_network_or_google_dependencies.py), test_source_package_has_no_eager_network_google_or_oauth_imports, 81-105 | Preserve whole-source scan and network/OAuth exclusion. |

Use direct public imports, never dynamic imports or disguised names to evade consumer checks.

## 8. One implementation candidate and acceptance

Next candidate: one new module at src/tridentine_calendar_google_sync/production_write_token_disabled_bootstrap_source_loading.py, one new test at tests/test_token_disabled_bootstrap_source_loading_phase6d1h.py, the three exact consumer assertions above, and a limited implementation/evidence append to this document. No existing runtime or configuration change is expected.

Reviewers must approve the shared source root, Linux gate after capture, six-metadata/two-read schedule, external fixture assumptions, result union and exception rules. Separate user authorization is required for implementation and synthetic fixtures. No further design subdivision is needed unless a concrete blocker emerges.

Acceptance must separately establish:

- Exact types, path/leaf bounds, overlap, private conditions, missing/unsafe/changed sources and partial acquisition; every source refusal keeps handoff calls at zero.
- Independent expectations never learned from files; caller mutation after capture cannot replace retained inputs; both byte values reach one handoff without reacquisition.
- Mixed versions, semantic refusals, malformed returns, retained nested negatives, fixed exceptions and cancellation.
- Closed dependencies, no external loader consumer, no writer/publisher/permission repair/fallback/retry, and unchanged existing guard scope.
- Linux real private reads and real handoff connection using isolated fixtures; ordinary fresh-process observation with independently supplied expectations, finite timeout and unchanged fixtures.
- Windows pure/mock coverage and real loader platform refusal without source I/O/handoff; existing direct handoff Windows behavior unchanged.
- Existing 313/402/347/593/387-case suites and related guards, Python 3.12/socket restrictions, frozen dependencies, Ruff/format, strict mypy and package build through the authorized local/CI workflow.

Measure counts rather than promise them. Fixture creation belongs to test setup, never loader behavior. Separate pure/mock, native reads, fresh-process and CI evidence; inherited CI proves none of this new work. Stop implementation for unexpected runtime edits, additional consumers, private-helper borrowing, real data or broader scope.

Before operational use, deployment owners must establish installation-fixed sources, review/release provenance, actual source/target isolation and any required freshness anchor. Maintainers still need controlled launcher enforcement, activation, pending disposition, reconciliation and all-writer participation. Matching synthetic reads cannot decide those matters.

Only this design is created now; no application execution, tests, source-read experiments, deployment, commit, push or PR change occurs. DS-04 remains PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 scan FAIL; Production gate BLOCKED; live handlers hard-off; packaged registry empty/fail-closed; PR #17 Draft in inherited evidence.

## 9. Unreviewed synthetic source-loading prototype

This separately authorized implementation adds the loader and its synthetic tests. Sections 1-8 remain the design record. The precise RECHECK classification order and fixed-exception catch boundaries below are implementation conditions verified locally where stated, not guarantees established during document drafting. Existing runtime components, schemas and public constructors are unchanged.

### 9.1 Captured inputs and platform boundary

load_synthetic_disabled_bootstrap(source_root, policy_leaf, expected_descriptor_leaf, expectation, *, expected_control_root) requires all five inputs and accepts no callback, authorization flag, cached bytes, previous result, history or borrowed resource.

_capture_inputs checks the source root, policy leaf, companion leaf and independent control-root string in that order. It then requires the exact public expectation class, obtains all eleven declared fields once through the fixed list, checks their exact string types, creates a fresh expectation and checks its artifact_directory spelling. _CapturedInputs is frozen/slotted with every field excluded from repr. Ordinary capture failure yields CAPTURE / INPUT_UNVERIFIABLE.

Only after successful representation checks does the entry reject identical leaves or component-boundary overlap with either target root as CAPTURE / SOURCE_OVERLAP. Adjacent component spellings are not overlap. No value is normalized; no target is statted for this comparison. Fixture ownership, physical separation, safe ancestors and absence of mount aliases remain external test conditions.

The Linux/POSIX gate follows pure capture and overlap checks. A real Windows call returns PLATFORM / UNSUPPORTED_PLATFORM before Path construction, owner acquisition, metadata, reader or handoff. The existing handoff's direct Windows behavior is unchanged. Original caller objects are never reread after capture.

### 9.2 Finite acquisition and precise recheck precedence

The loader obtains the effective UID once, requiring an exact nonnegative integer. Its only metadata primitive is the local _lstat boundary over Path.lstat. PRECHECK visits root, policy and companion in order, stopping immediately on failure. Each _Signature captures device, inode, mode, uid, gid, link count, size, mtime_ns and ctime_ns as exact integers; atime is excluded. Root requires effective-owner directory mode 0700. Leaves require effective-owner regular files, one link, no group/other permission and size 1-8192; owner-readable 0400 is accepted. Equal checked leaf device/inode pairs yield PRECHECK / SOURCE_OVERLAP.

The two public private-reader calls use max_size=8192, policy first and companion second. Returned objects must be exact bytes of length 1-8192. Failure yields that read stage's SOURCE_UNVERIFIABLE and stops subsequent calls. The existing reader may consume one extra detection byte; this does not enlarge accepted payloads. The loader parses neither source and computes no digest or expectations from their contents.

RECHECK visits root, policy and companion once each. For each entry, metadata acquisition/field validation failure yields SOURCE_UNVERIFIABLE, including disappearance causing lstat failure. A comparable signature difference yields SOURCE_CHANGED before private-condition revalidation. Failure to re-establish private conditions yields SOURCE_UNVERIFIABLE. A leaf's returned byte length differing from its retained size yields SOURCE_CHANGED immediately after that leaf's metadata/private checks. No remaining metadata is collected after refusal; there is no RECHECK / SOURCE_OVERLAP, retry, fallback or cleanup.

Thus the maximum direct schedule is six metadata calls, two content reads and one handoff. The private captured container holds the source plan and copied expectation/root. Both exact byte objects remain immutable entry-local values; no byte-bearing snapshot is exported. They and the copied expectation/root reach handoff only after all source checks. A malformed policy can still follow both independent source reads; semantic refusal occurs inside the existing handoff before Inspection. No source-stage refusal intentionally accesses a target or credential region.

The loader opens no descriptor and acquires no lock itself. It relies on reader ownership/unwind and intentionally carries no source resource into Inspection. Suppressed close errors remain unobservable. Stable signatures do not provide atomic pathname binding, atomic pair acquisition, current contents after return, freshness, rollback resistance or deployment provenance.

### 9.3 Refusals, retained diagnostics and exception provenance

DisabledBootstrapSourceRefusal has exactly stage, reason and constructor-excluded reuse_authorized: Literal[False]. Its frozen/slotted constructor checks exact enum types, declared member identity, False identity and exactly the eleven allowed combinations. Invalid inputs receive a fixed ValueError, without coercion or input text. All returned diagnostics remain nonauthorizing.

The entry uses separate try boundaries for the handoff invocation and returned-object reconstruction. _copy_handoff requires the exact existing result class, captures all four original fields once, rejects authorization other than False, and invokes the existing public constructor for safe nested copies. Valid observations and ordinary handoff refusals retain all their diagnostic dimensions. A reconstruction failure yields HANDOFF / HANDOFF_RESULT_UNVERIFIABLE, not proof that no observation or failure occurred; the uncertain original is not exported.

Only an exact DisabledBootstrapInspectionResultError raised by the direct handoff call is propagated with bare re-raise. Its safe nested diagnostics, identity and existing exception links are preserved. Subclasses and other ordinary call exceptions yield HANDOFF_FAILED. The same exception class raised during returned-result reconstruction instead yields HANDOFF_RESULT_UNVERIFIABLE. This preserves the normal dependency contract without authenticating arbitrary forged same-class exceptions.

_refuse alone handles ordinary source-refusal construction failure by creating the zero-argument DisabledBootstrapSourceResultError with the fixed message "Disabled bootstrap source result construction failed". It clears only this new error's cause/context through the local raise/catch/bare-raise pattern, including ambient caller except/finally. Original exceptions and notes are not copied or edited. Non-Exception cancellation propagates as the original object at capture, acquisition, reading, recheck, handoff and result processing. Resource exhaustion and complete traceback-local erasure are not guaranteed.

No normal result or new source exception exposes bytes, paths, root, pin, metadata or original exception text. Upper ADMIN_PENDING, ADMIN_COMMIT_UNCERTAIN and ADMIN_REVOKED are neither accepted as inputs nor cleared.

### 9.4 Dependencies, guards and specification coverage

The runtime imports exactly the five public application symbols selected in section 7 and only the permitted standard-library support. It imports no parser, digest implementation, private helper or operational entry. The only existing test edits are the three authorized consumer-set additions. Bootstrap and preparation consumers remain the handoff alone; descriptor consumers become four; the loader has no external runtime consumer. Record isolation, three direct lock consumers, four publisher consumers excluding itself and directory-backend restrictions remain unchanged.

The new closed structural check covers the actual finite helper calls, public-call arguments, receiver origins, protected bindings and exception-link assignment scope. It supplements the existing checks rather than modifying their permissions. Dangerous source copies are parsed and inspected as AST data only, never executed. This is not a general Python alias-analysis framework or a same-process adversary guarantee.

| Contract | New test coverage |
| --- | --- |
| Exact API, capture priority and independent fields | Required-input/signature tests; wrong types, poison objects, all eleven missing/invalid fields, single-field-read accounting |
| Placement and gate | Linux string/leaf bounds, reserved names, no normalization, component overlap, real Windows zero-I/O gate |
| Finite acquisition | Exact normal schedule, each metadata failure/private defect, both reader failures, size bounds, identity aliases and immediate recheck stops |
| Retained values and semantic delegation | Caller mutation, original byte/root identity, real handoff semantic refusal after both reads, coherent old materials remaining unapproved |
| Nonapproval and negative evidence | Eleven refusal combinations, forged enum members/flags, full observations and all other valid handoff progress states |
| Exception provenance and cancellation | Exact direct fixed error versus subclass/result-check error; source construction error in ordinary/except/finally callers; original cancellation across phases |
| Structural and effect boundary | Exact imports, calls/arguments/receivers/bindings, memory-only AST mutations, BaseException effect sentinels and direct/delegated call accounting |
| Defined native verification | Linux private reads and real handoff, unsafe sources, controlled fixture changes, partial negative observations, ordinary fresh-process route |

The Linux test setup creates disjoint synthetic source, control and pair roots from independent values. Setup/fault-injection mutations are distinguished from loader behavior; fingerprints compare names, bytes, modes and identity while excluding atime. The test-only child route stays in the new test file, supplies independent expectations, invokes the loader once, captures output and uses a finite ten-second timeout. It does not rerun pytest or establish crash/power-loss recovery.

### 9.5 Structural-check completion and safe resumption

The preceding implementation turn stopped after an editing-tool failure exposed a personal absolute path in its diagnostic. No path or original error is retained here. The runtime and three consumer-test files were left unchanged during resumption. Their stopping hashes were verified before work. The 84412-byte test was partially hardened, not finally validated.

Resumption used the existing captured Python process for explicit content updates, without the native patch tool. Before each update, expected bytes/hash, unique replacement targets, candidate syntax/encoding and scope were checked in memory; saved bytes were read back. Formatter output was captured through stdin/stdout, checked for identical AST, then saved by the same route. Eight synthetic in-memory cases covered hash mismatch, missing/ambiguous targets, invalid syntax, write/readback failures, readback mismatch and stdout/stderr containment. All eight passed without writing real files. These are editing-path checks, not product tests or a claim that every possible tool/transport failure is harmless. The earlier exposure is not undone.

The stopping checker already rejected all twelve inherited AST cases when measured on resumption: 12 collected, 12 passed, no failures/errors/skips/deselection, exit 0. It was not rolled back to reproduce the earlier RED. The actual cases and retained checks are:

| Case | Retained refusal boundary |
| --- | --- |
| annotated-path | Entry permits only its reviewed Assign forms and argument origins. |
| annotated-failure | _refuse bindings, including AnnAssign, must match the fixed new-error construction. |
| duplicate-from | A module cannot be imported again to hide earlier symbols. |
| nested-from | Imports must remain at module level. |
| duplicate-import | Imported local names cannot be rebound by another import. |
| exception-binding | Only the declared handoff error binding is permitted. |
| match-binding | Unsupported Match syntax is refused. |
| capture-receiver | Capture assignments must retain the original checked receiver. |
| capture-field-list | The eleven-field declaration must match exactly. |
| duplicate-capture-getattr | Comprehension forms and multiplicities remain closed. |
| namespace-getattr | Only the fixed expectation-field getter is allowed. |
| decorator-call | Only the reviewed dataclass and property decorators are allowed. |

Two final restrictions made the finite proof explicit: exactly one getter must be the value of the fixed DictComp directly assigned to values, and ClassDef count must equal the class-name map count. One nearby regression rejects a preceding same-name class with an implicit decorator call. It is AST data only. Necessary Subscript Load, string/stat operations, constructors and scope-limited new-error link removal remain permitted.

Only _check_closed_loader and _check_loader_bindings_and_headers changed structurally from the stopping test, with one new regression function. All other 77 existing definitions, all 52 existing test functions with their decorators/parameterization, and all 24 top-level constants/aliases retain their original AST. Formatting and adjacent-literal splitting preserve their meaning. Existing assertions and negative cases were not removed. This remains an implementation-specific closed regression check, not exhaustive analysis of arbitrary Python dispatch.

### 9.6 Measured local verification and remaining work

Windows / Python 3.12.14 and resolution to this repository's src were freshly confirmed. Installed pytest 8.4.2, pytest-socket 0.8.1, Ruff 0.16.4, mypy 1.20.2, pydantic 2.13.4 and build 1.5.0 metadata were freshly compared with uv.lock and matched. No install, frozen sync, environment rebuild or Linux setup occurred.

Keep these evidence stages separate:

| Evidence stage | Collected | Passed | Failed | Errors | Skipped | Deselected | Exit |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Inherited full regression before structural hardening | 2532 | 2401 | 0 | 0 | 131 | 0 | 0 |
| Inherited twelve-case RED against the older checker | 12 | 1 | 11 | 0 | 0 | 0 | 1 |
| Stopping 84412-byte test as a whole | Not finally run | - | - | - | - | - | - |
| This resumption: current twelve cases before edits | 12 | 12 | 0 | 0 | 0 | 0 | 0 |
| This resumption: final complete required regression | 2545 | 2414 | 0 | 0 | 131 | 0 | 0 |

The inherited new-file total was 481 collected/457 passed/24 skipped. Those prior counts and external source/syntax review are not new product-test executions here. The preceding eleven RED failures specifically meant an expected AssertionError was not raised, not parse/import/fixture failures.

Final results after the last test edit and formatting:

| Required target | Collected | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Source loader, complete | 494 | 470 | 0 | 0 | 24 | 0 |
| Handoff, complete | 313 | 301 | 0 | 0 | 12 | 0 |
| Disabled bootstrap inputs, complete | 402 | 402 | 0 | 0 | 0 | 0 |
| Descriptor, complete | 347 | 347 | 0 | 0 | 0 | 0 |
| Preparation/Inspection, complete | 593 | 554 | 0 | 0 | 39 | 0 |
| Operation record, complete | 387 | 331 | 0 | 0 | 56 | 0 |
| Additional six specified nodes, all parameters | 9 | 9 | 0 | 0 | 0 | 0 |
| Total | 2545 | 2414 | 0 | 0 | 131 | 0 |

The final source-file evidence is 469 passing pure/mock/structural cases and one real Windows platform gate. Its 22 Linux native read/connection/fault cases and two Linux fresh-process cases are skipped, not passing. The other 107 skips preserve the existing OS conditions. No unexpected skip or deselection occurred. Native grouping uses the actual test definitions; tests of Linux path strings on Windows remain pure tests.

The final run included the twelve resumed cases (12 passed), the new duplicate-class case (1 passed), the unchanged-loader structural positive, all previous positive/negative checks and the related existing guards. The twelve existing guard functions ran successfully; the private-secret reader guard contributes four parameter cases. File/subgroup counts are already included in the total.

Final Ruff check . --no-cache --output-format json and Ruff format --check . --no-cache passed; formatting covered 275 files. Strict mypy --strict --no-incremental --cache-dir=nul --no-pretty passed for the unchanged loader and all 123 src files. A remaining long test literal was split without AST change, followed by the final complete regression and static checks; the earlier intermediate pass is not substituted for this final evidence.

Pytest used the existing Python with -B, the in-memory capture/collector, -q, -p no:cacheprovider and new synthetic --basetemp locations. Existing conftest, strict settings and socket prohibition remained active. Captured diagnostics expose only allowed classifications, paths, names, codes and counts, with no raw fallback. No persistent runner or raw log was created. Editing-path checks are not added to pytest totals.

Full content, whitespace, relative links, privacy and permitted diffs were reviewed separately, including the untracked files. HEAD/tree/index remained unchanged, staged count stayed zero, and the three old test differences still reverse exactly to their starting HEAD blobs. This resumption changed only the new test and this document; the loader and three old tests retain their stopping bytes.

Status: IMPLEMENTED_VALIDATION_INCOMPLETE. Linux real reads/handoff connection and fresh-process execution, package build and new CI are not performed here. Old run 36316289138 is not evidence for the loader. No real source deployment, startup/session connection, enrollment, pending retirement, recovery, commit, push, PR change, OAuth or Google operation occurred. DS-04 remains PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 scan FAIL; Production gate BLOCKED; live handlers hard-off; packaged registry empty/fail-closed.
