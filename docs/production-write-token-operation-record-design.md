# Persistent Incomplete-Operation Evidence for Production Write Tokens

Status: DRAFT_WITH_UNREVIEWED_STANDALONE_PROTOTYPE

This document proposes a small persistence boundary for remembering that an operation started and has not been conclusively closed. Sections 1-11 retain the original design and its fixed-HEAD evidence; their **Current** statements refer to that baseline, **Proposed** statements describe future work, and **Open** statements identify unresolved decisions. Section 12 records the separately authorized, unreviewed standalone prototype. Existing runtime behavior and credential-use authority are unchanged. No new Unit number is assigned.

For example, refresh operation `operation-b` can fail after an earlier `operation-a` completed, even though both use the same generation. A later matching, unexpired token/state pair must not erase the outstanding obligation for `operation-b`. The proposed first component preserves that obligation; it does not decide that the credentials are safe.

## 1. Baseline and evidence limits

The local design baseline is branch `security/deep-scan-remediation-47194b0`, HEAD `bd88f88fd7d0629d949354e7efa1b1a2337a8c4f`, tree `a1316c5dcc6420a7397710c7df256dafa9446134`, with sole parent `64e835390f8de828d456706a0ccc0e818127cba1`. The reference base is `47194b000e1edc2bf590d3c764595ba26c260039`.

The supplied external verification record reports PR #17 Open/Draft/unmerged, its English description updated for 24 commits, and English CI evidence comment 5760502613 posted while the older September 20 comment remains. It reports Actions run 35598888487, attempt 1, event `pull_request`, workflow `.github/workflows/test.yml`, completed/success for all eight Ubuntu/Windows layers. Dependency installation, Ruff, formatting, selected pytest layers, and package builds succeeded; mypy succeeded in six non-base jobs and was skipped in two base jobs. The reported virtual merge is `42e5c1bc0de054578c1b6b0cd07279f5bdc6762e` with the baseline tree.

These are inherited external records, not queries or tests performed for this document. That CI did not include this new document and does not validate the proposed persistence protocol. Original security-scan finding text was not retrieved or reviewed in this task; no finding-level or audit-wide closure is inferred.

The following remain unchanged: DS-04 PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 scan report FAIL; Production operational gate BLOCKED; Production live handlers hard-off; Packaged Accepted Production Baseline Registry empty/fail-closed.

## 2. Source evidence map

Line ranges refer to the fixed HEAD above. Test entries are source evidence read during design, not tests executed for this change.

| Ref | Repository source, symbol, and lines | Current fact relevant to this proposal |
| --- | --- | --- |
| E1 | [src/tridentine_calendar_google_sync/production_write_token_reuse_policy.py](../src/tridentine_calendar_google_sync/production_write_token_reuse_policy.py), `PolicyInput` 110-116, `ReusePolicyDecision` 119-145, `_advance` 210-227, `_check_history` 254-313, `evaluate_reuse_policy` 316-395 | Synthetic defaults are registered/complete assumptions. Negative evidence is retained before other validation. Normal completion never authorizes reuse. |
| E2 | [docs/production-write-token-reuse-policy-model.md](production-write-token-reuse-policy-model.md), 28-56, 105-174, 214-226; [tests/test_token_reuse_policy_phase6d1h.py](../tests/test_token_reuse_policy_phase6d1h.py), 197-248, 307-365, 501-578, 735-792 | Same-generation operations remain distinct; appearances cannot clear failures; reconstruction is memory-only; model and inspector integration are absent. |
| E3 | [src/tridentine_calendar_google_sync/production_write_token.py](../src/tridentine_calendar_google_sync/production_write_token.py), `_production_write_session_lock` 125-178, `_load_production_write_credential_session` 741-887 | Linux locks cover reads through session construction and checkpoints. Valid-token return is at 788-794; refresh is at 811, recheck at 850-864, persistence at 867-871, final checkpoint at 882. Windows uses a no-op lock callback. |
| E4 | [src/tridentine_calendar_google_sync/production_write_token.py](../src/tridentine_calendar_google_sync/production_write_token.py), `authorize_production_write_token` 635-661, `authorize_production_write_token_mock` 664-738, `prepare_production_write_rehearsal_credential_session` 890-917 | Live authorization is hard-off. The mock authorizer runs before bundle persistence/locking. The live session wrapper supplies no refresher. These are boundaries to review, not live capabilities to enable. |
| E5 | [src/tridentine_calendar_google_sync/production_write_token_io.py](../src/tridentine_calendar_google_sync/production_write_token_io.py), `ProductionWriteTokenIOError` 51-64, `write_production_write_authorized_user_token` 312-346, `persist_refreshed_production_write_token` 349-395, `write_production_write_token_generation_state` 478-505, `_write_posix_token_bundle` 530-591, `write_production_write_token_bundle` 594-687 | Leaf writers do not own the shared session lock. Bundle order is state, checkpoint, token, checkpoint, context exit. Count two precedes the last checkpoint. Error evidence is in memory, not a transaction journal. |
| E6 | [src/tridentine_calendar_google_sync/production_write_token_io.py](../src/tridentine_calendar_google_sync/production_write_token_io.py), `validate_production_write_token_path_set` 726-824; [src/tridentine_calendar_google_sync/production_write_token_models.py](../src/tridentine_calendar_google_sync/production_write_token_models.py), `ProductionTokenRole` 22-27, `ProductionWriteTokenGenerationState` 147-172 | Explicit role-separated paths and generation binding exist. They do not register an operation-record namespace or identify each refresh. |
| E7 | [src/tridentine_calendar_google_sync/production_write_token_pair_inspection.py](../src/tridentine_calendar_google_sync/production_write_token_pair_inspection.py), `TokenPairInspection` 47-58, `inspect_production_write_token_pair` 61-141 | Read-only pair observations always have `reuse_authorized=False`. Matching bytes do not prove previous publication, provider validity, freshness, or Windows serialization. |
| E8 | [src/tridentine_calendar_google_sync/_posix_private_create.py](../src/tridentine_calendar_google_sync/_posix_private_create.py), `create_posix_private_bytes` 112-229; [src/tridentine_calendar_google_sync/_posix_private_replace.py](../src/tridentine_calendar_google_sync/_posix_private_replace.py), `replace_posix_private_bytes` 54-195 | Create uses retained descriptors, exclusive publication, file/parent synchronization and content/name checks, without final-name rollback. Replace checks expected bytes but is not compare-and-swap. Either can publish and subsequently fail. |
| E9 | [src/tridentine_calendar_google_sync/sensitive_paths.py](../src/tridentine_calendar_google_sync/sensitive_paths.py), `_read_posix_private_bytes` 328-453, `read_private_sensitive_bytes` 472-503; [src/tridentine_calendar_google_sync/_posix_sensitive_directory.py](../src/tridentine_calendar_google_sync/_posix_sensitive_directory.py), `_BoundPrivateDirectory.close` 101-109, `_revalidate` 111-135, `open_posix_private_directory` 155-223 | Reader checks private opened-file metadata but does not retain every ancestor. Directory binding has stronger retained-ancestry checks. Directory close suppresses OSError; normal return is not positive close attestation. |
| E10 | [src/tridentine_calendar_google_sync/_posix_private_lock.py](../src/tridentine_calendar_google_sync/_posix_private_lock.py), `_lock_once` 33-44, `_PrivateDirectoryLock` 47-99, `acquire_posix_private_directory_lock` 102-141 | Linux-only nonblocking cooperative directory-inode lock; no lock file, polling, or unlocked fallback. Revalidation is not kernel lock attestation. |
| E11 | [docs/windows-sensitive-filesystem-security.md](windows-sensitive-filesystem-security.md), 16-97; [src/tridentine_calendar_google_sync/_windows_sensitive_files.py](../src/tridentine_calendar_google_sync/_windows_sensitive_files.py), `_locked_parent` 1000-1062, `atomic_write_windows_sensitive_bytes` 1801-1940 | Windows has handle/path/ACL protections, not the shared Linux serialization protocol. Exception cleanup calls deletion marking even after publication may have occurred; POSIX final-record retention must not be assumed for this writer. |
| E12 | [docs/posix-private-artifact-security.md](posix-private-artifact-security.md), 229-268, 395-437, 487-579, 592-639; [docs/production-write-token-readonly-rehearsal-foundation.md](production-write-token-readonly-rehearsal-foundation.md), 100-166 | Historical increments must be read cumulatively: replacement is integrated by Unit 4L, session locking by 4N, and new-pair publication locking by 4O. Earlier exclusions and pending-CI statements do not override later source or inherited CI. |

Additional inspected test evidence:

| Test source | Named test or bounded source range |
| --- | --- |
| [tests/test_credential_session_lock_phase6d1h.py](../tests/test_credential_session_lock_phase6d1h.py) | `test_both_parents_held_before_reads_until_session_return`, 140-173; checkpoint failures 252-286; Windows bypass 289-295. |
| [tests/test_token_bundle_lock_phase6d1h.py](../tests/test_token_bundle_lock_phase6d1h.py) | Lock coverage 103-125; checkpoint failures with counts 0/1/2 at 154-176; only bundle wrapper acquires at 383-403. |
| [tests/test_refresh_persistence_failure_phase6d1h.py](../tests/test_refresh_persistence_failure_phase6d1h.py) | Retained old/new/competitor outputs 109-154; same-generation refresh 192-212; unexpired path 215-222; no retry/cleanup handler 313-346. |
| [tests/test_refresh_prewrite_recheck_phase6d1h.py](../tests/test_refresh_prewrite_recheck_phase6d1h.py) | Changed/missing/unreadable inputs 110-190; read-refresh-reread-save ordering 193-223; unexpired path 226-246. |
| [tests/test_token_pair_inspection_phase6d1h.py](../tests/test_token_pair_inspection_phase6d1h.py) | Matching residue after failed checkpoint stays unapproved, 413-443; no runtime consumer/mutation calls, 373-409. |
| [tests/test_posix_private_create_phase6d1h.py](../tests/test_posix_private_create_phase6d1h.py) | Prepublication failures 163-188; failures after possible publication 193-224; no-overwrite collision 228-244. |
| [tests/test_posix_private_replace_phase6d1h.py](../tests/test_posix_private_replace_phase6d1h.py) | Before-replace failures 179-205; replacement/flush/check failures without rollback 212-243. |
| [tests/test_posix_private_lock_phase6d1h.py](../tests/test_posix_private_lock_phase6d1h.py) | Nonparticipating writes 276-283; renamed directory/new lock inode 287-302; abrupt process exit 306-344. The latter checks lock behavior, not crash durability of records. |

## 3. Intended guarantee and explicit limits

**Proposed:** establish an incomplete-operation obligation before any provider operation or managed token/state modification. Every future managed session preparation must examine that obligation before treating a currently consistent pair as reusable. A failure to obtain trustworthy history is a refusal, never an empty successful history.

| Situation | Intended treatment and boundary |
| --- | --- |
| Ordinary exception after confirmed start | Retain the start obligation even if recording the failure reason fails. The current call returns no session. |
| Process interruption after confirmed start | A subsequent cooperating process seeing the retained record refuses continuation. It need not guess where the interruption occurred. |
| Power loss or storage failure | File and directory synchronization are required checkpoints, not universal power-loss guarantees. Filesystem, mount, device and crash-recovery behavior need separate qualification. |
| Nonparticipating writer | Advisory locks cannot stop it. Managed entry points must participate or reject managed writes. Arbitrary external filesystem writers remain outside enforcement. |
| Same-user or privileged modification | Mode/owner/path checks do not authenticate against an actor with equivalent authority. Deletion, forged enrollment and replacement remain trust assumptions or separately detectable defects. |
| Whole-store rollback | Without an independently trusted retained expectation, restoring a self-consistent old directory and records is undetectable. This proposal supplies no such external anchor. |

The narrow first component deliberately keeps all recorded starts outstanding. This favors refusal over availability and is not a deployable lifecycle for repeated successful operations. Designing normal closure is a separate integration prerequisite, not an excuse to omit the useful start-record component.

## 4. Record strategy and minimum data

| Candidate | Assessment |
| --- | --- |
| Write a failure marker only in an exception handler | Reject. Termination may bypass the handler; marker creation may fail after provider effects. There is no earlier persistent refusal fact. |
| Replace one mutable status file from pending to completed | Do not select initially. Existing replacement is not CAS. A visible completed replacement can erase the only pending fact before a later checkpoint fails. |
| Create an immutable start obligation first; retain it, with separate bounded observations later | Recommend. Fits private create-only publication, retains the refusal basis, and does not need a database, dependency, or service. A later observation never implicitly removes the obligation. |

Use one fixed start-record slot per registered pair for the first component. An occupied slot blocks another operation; neither a new operation ID nor an alternate filename bypasses it. This is not an append-only complete-history service. Multi-operation retention and normal closure require a separately reviewed lifecycle. Do not reuse the execution journal: this design does not establish its suitability and does not depend on it.

The following is a **proposed field/constraint table**, not an approved production schema or a serialization of `PolicyInput`.

| Item | Purpose and constraint |
| --- | --- |
| Format version and record kind | Closed version/kind values; reject unknown versions, extra fields and duplicate keys. Distinguish a start obligation from any future observation. |
| Storage and pair references | Opaque non-secret references resolved against separately trusted enrollment. They are not paths, credential fingerprints, or proof of ownership. |
| Token role and artifact slots | Fix `production_write` and the distinct token/state slots through enrollment. Prevent substitution of production-read, test-write, or unrelated state records. |
| Operation ID | Distinguish this attempt from every other refresh, even at the same generation. Bounded non-secret identifier; conflicting or repeated occupancy is refused, not treated as idempotent success. |
| Predecessor relationship | An explicit prior-operation reference when applicable; absence only for separately established initial enrollment. It is not inferred from directory order, timestamp, generation or the greatest ID. |
| Operation kind | Closed distinction between new-pair creation and refresh. Other kinds are unsupported until reviewed. |
| Phase and outcome | Start record means START/PENDING. Future separate observations may record bounded progress, failure or commit uncertainty using fixed categories; they cannot replace START or clear it. |

Target leaf names and the fixed record slot belong to the enrollment binding, not freely supplied record-controlled paths. The first codec should have a small fixed byte limit, bounded ASCII references, a single canonical UTF-8 representation and strict types; 4096 bytes is a review candidate, not an existing configured limit.

Do not store token bytes, credential-derived hashes, provider response bodies, account identifiers, process IDs, clocks, exception text, or arbitrary notes. Generation remains an existing pair-validation input, not the operation key or a new authority field. Operation-ID generation/collision policy is still open for real enrollment; synthetic callers supply explicit IDs in the first component.

`registered=True` and `history_status=COMPLETE` in E1 are synthetic defaults. A future adapter must establish registration and the scope/completeness of retrieved evidence explicitly. This one-slot component cannot assert complete historical coverage or fabricate `COMPLETION_EVIDENCE`.

## 5. Enrollment, binding and rollback

**Proposed management boundary:** one explicitly enrolled pair in one private, repository-external directory, with fixed, distinct token, state and start-record slots. The coordinator chooses the enrolled directory; an operation record cannot choose it. This narrower layout is a proposal, not a restriction already imposed by E6. Existing cross-directory pairs must not be silently moved into it.

| Observed case | Required decision |
| --- | --- |
| Truly new pair | A separate approved enrollment must establish the intended role, slots, storage/pair references and initial lifecycle before any provider call. Merely asserting that files are absent is insufficient. |
| Existing pair with no record | Unregistered/history unknown. No automatic enrollment, migration, clean-history assumption or refresh. |
| Registered pair with missing, corrupt, unreadable or mismatched evidence | Refuse. Do not recreate an empty record store. Absence is not a normal-completion signal. |
| Different record path or copied pair | Reject against the enrolled location. Equal bytes at a different path do not transfer enrollment or retire the original obligation. |

Before initial authorization, the intended local destination, role, reserved slots, operation ID and predecessor policy can be fixed. Provider-granted scopes, returned credential identity and resulting generation cannot be certified in advance. After the response, existing exact-scope, role, identity and generation validation must still run before storage. Failure at that point retains the start obligation despite no token having been saved.

Equal content proves only that the compared content matched; an equal filename proves neither parent identity nor authority; equal generation does not identify a refresh; equal operation ID does not authenticate a record or prove successful execution. Filesystem object identity observed under retained descriptors helps bind a current access, but is not permanent identity across restore, migration or inode reuse.

A trusted enrollment source must survive ordinary invocation and constrain caller path choices. Its establishment, protection, changes and migration approval are **not implemented or fully specified here**. A synthetic enrollment object in the standalone component tests only the stated local assumptions. Without independently trusted enrollment, protection against arbitrary record-root switching is not an achieved property.

Missing predecessor references, contradictory definitions, duplicate IDs and a mismatch with a separately retained expected operation can reveal defects. A hash chain could reveal some internal alterations relative to a trusted endpoint, but not deletion of the entire chain, a coherent truncated prefix, or rollback of both records and their local anchor. No hash chain or independent anti-rollback service is proposed for the first component.

## 6. Proposed sequencing at existing function boundaries

The following describes **future integration requirements**, not changes made by this document or by the next standalone component.

A future coordinator owns the complete operation context: enrolled binding, unique operation ID, predecessor, kind, held-lock ownership and established-start classification. Lower layers receive that same explicit context; they must not allocate another ID or silently enroll a new target. It is bookkeeping, not credentials or an execution permit.

For the proposed single-directory layout, the coordinator acquires one Linux directory lock before record/pair content reads and retains it through provider activity, writes and final checkpoints. It verifies that each reserved slot belongs to that directory. Existing multi-parent support in E3 does not automatically cover an additional record parent. A broader layout would need a reviewed total acquisition order and alias policy.

| Path and current boundary | Proposed order and stopping rule |
| --- | --- |
| Unexpired-token preparation, E3 `_load_production_write_credential_session` 778-794 | Acquire managed lock, validate enrollment, read/classify the fixed record, then perform the existing pair and scope/role checks. Refuse unresolved or unverifiable evidence **before** the expiry branch and early return. No new mutation-start record is needed solely for a read-only inspection. Lack of a pending record is not permission to return a usable session. |
| Refresh, E3 795-887 | Under the same coordinator lock, check history and current pair, establish START, confirm it, then call the injected refresher. Validate the response; retain the existing pair re-read immediately before persistence; save through the current replacement boundary; perform subsequent checkpoints. If START cannot be confirmed, do not call refresher or writer. Stop after later failure without retry or old-token restoration. |
| New authorization and bundle, E4/E5 | Approved enrollment and existing confirmations first; acquire the outer managed lock and establish START **before** authorizer invocation. Validate returned evidence, then save state followed by token with checkpoints. The existing bundle lock alone is too late to cover authorization effects. A future ownership-aware internal composition is needed; wrapping the current locking bundle in another lock is not the solution. |
| Standalone token/state/refresh writers, E5 | Managed targets must require participation in the coordinator-owned context or reject the write. Check history and START before the first target mutation, and before any upstream provider activity. Lower-level writers must not reacquire an already-held lock. Their current signatures do not implement this enforcement. Other writers need an inventory and explicit adoption or managed-target refusal before integration. |

There is no existing borrowed-lock API or persistent-operation context in E3/E5. The revalidation callback is neither a durable start receipt nor proof of all-writer participation. Integration must not introduce a double-acquisition path.

Linux locking remains cooperative and keyed to the same directory inode. Renaming/replacing a directory, duplicated descriptors, and nonparticipants are not solved by an operation ID. Windows handle/ACL protection is different; E3's Windows lock is a no-op, and E11 does not provide the proposed retention contract. Unsupported OS or lock unavailability must refuse the proposed managed operation without an unlocked fallback. Existing live hard-off paths remain hard-off.

## 7. Commit points, failures and the last-observation problem

Define separate facts, with deliberately different meanings:

| Fact | What it establishes |
| --- | --- |
| Writer returned normally | That writer's implemented steps returned. It does not certify a bundle or the surrounding call. |
| Completion-looking record is visible | Some bytes are observable. The publishing call may still have failed after publication. |
| START commitment S | The start create operation, its file/parent synchronization and checks, a bounded readback and the coordinator checkpoint returned successfully under the held lock. This is the earliest point after which a future coordinator may attempt the protected effect, subject to every other gate. |
| Bounded data/evidence commitment C | Proposed later checkpoint: required pair writers, existing pair validation/readback, any separate observation publication and its checks, and the under-lock final checkpoint have all succeeded for the same operation. It covers only that defined prefix. |
| Whole invocation returned normally | An in-process fact observed by its caller after context exit; a file written earlier cannot attest to that future return. |
| Credential reuse authorized | A separate, currently blocked authority decision. Neither S, C, a record reader, the model nor the inspector grants it. |

S is the commitment point for preserving the start obligation. C is only a proposed **bounded protocol commit point**, not a completed-operation or reusable-credential commit point. There is no approved persistent normal-closure commit point in this design. The first implementation contains S only, with no provider, pair write or C.

If failure occurs before S, stop before provider or target mutation. A partially published start may remain; do not remove it or infer that another actor did nothing. A missing start on a later call is still unknown/unverifiable unless a separate enrollment/lifecycle authority establishes more.

After S, never overwrite or remove the start obligation in response to success, error, interruption, elapsed time or process disappearance. A best-effort separate failure observation can preserve a more specific reason. If that write also fails, the intact START/PENDING record remains a sufficient conservative refusal basis, although the next process may know only incompleteness and not the exact failure.

Before C, writer or checkpoint failures prohibit claiming bounded commit. At or after a visible completion observation, failed flush, readback, final checkpoint or observable context/lock cleanup leaves commit/finalization uncertain. Retain both known failure and visibility observations; do not convert the failure to generic unknown or success. Even after the caller observed C, a later error can make whole-call success uncertain without proving the earlier data publication was undone.

E9/E10 suppress some descriptor-close errors, and E3 has no extra exit-time revalidation. Consequently current normal context exit supplies no positive lock-release attestation. A future completion protocol must decide which finalization facts it requires and how they are observable. Writing an additional confirmation file simply moves the last fallible step; it does not prove subsequent cleanup or return succeeded.

The next process can inspect retained start/observation bytes and trusted binding expectations. It cannot recover information that existed only in the failed process. If evidence was never persisted, was removed by an out-of-scope actor, or was rolled back with its anchor, detection is not guaranteed. Loss of the specific cause must not become permission to reuse.

Preserve the current exception meanings:

- `publication_possible=False` describes only that call's local publication attempt. It does not establish unchanged provider or other-process state, an absent output, or safe retry.
- `completed_output_count=2` counts normally returned writer calls; E5 still has a subsequent checkpoint and context exit.
- Stopping after refresh but before local save does not prove the provider left credentials unchanged.

Normal progress of one never-failed operation and controlled reconciliation after failure are distinct. The pure model can represent normal completion from strong synthetic evidence; this proposed record component cannot manufacture that evidence. Normal closure needs a later reviewed lifecycle. Controlled reconciliation would additionally require trusted enrollment/history, independent assessment of actual local and provider effects, retained negative evidence, and explicit approval by the responsible authority. No clearing function, recovery procedure, automatic retry, token restore, failure-record deletion, or reauthentication-based reset is proposed here.

## 8. Classification and information protection

The model and inspector continue to return `reuse_authorized=False`. A future collector may report fixed classifications such as UNREGISTERED_OR_UNKNOWN, INPUT_UNVERIFIABLE, START_RECORDED, IN_PROGRESS, RECONCILIATION_REQUIRED, COMMIT_UNCERTAIN, and COMPLETION_OBSERVED. Mapping to the model requires explicit validated inputs; the first record component is not connected to it.

Preserve the model's precedence: recognized commit uncertainty first; then failure/interruption; then invalid binding/history; then absent/unregistered history; only then normal observed progress. Keep all applicable fixed reasons. The first component must describe an outstanding obligation without inventing an explicit failure cause. No output contains credentials, a session, an execution permit or reconciliation authority.

| Information surface | Proposed policy |
| --- | --- |
| Private record | Minimal non-secret metadata still needs access control and integrity protection. Create in an effective-user-owned private directory with private files, reject symlinks/aliases and unverified binding, and never repair permissions automatically. |
| Private diagnostics | Bounded fixed phase/outcome codes and operation references only when necessary. Do not persist raw exceptions, arbitrary input text, credentials, sensitive or account identifiers, or response bodies. Diagnostic failure must not destroy the start fact. |
| Public summary | Fixed status/reason classifications and safe counts only. Do not reflect record references, filesystem paths, account details or exception strings into repr, chained exceptions, logs or reports. |

E8 creates exact 0600 files in a checked 0700 parent. E9's private reader checks ownership, single-link regular files, bounds and private permissions, but does not itself promise exact 0600 or retained ancestry. The proposed first component can compose that reader with lock-held directory revalidation under its trusted/cooperating-writer assumptions. It must not claim an atomic read/binding guarantee against same-user races. Stronger requirements need a separate descriptor-bound reader review before runtime integration.

No real token, credential, Calendar identifier, private iCalendar URL, UID, event identifier, ETag, personal path, name, email or SID is an example or design input here. Example references such as `store-example`, `pair-example` and `operation-b` are synthetic and carry no authority.

## 9. Future verification plan

No tests, I/O probes or crash experiments are implemented or executed for this document. In this table, **L** means the proposed Linux-only backend under the stated filesystem/trust assumptions. **U** means Windows and other unsupported platforms must refuse before protected effects. “Next process” means a separately started test process with explicitly supplied synthetic enrollment, not just reconstruction of Python objects.

| Injection or scenario | Expected current-call stop | Expected next-process observation | OS and limit |
| --- | --- | --- | --- |
| Start create, file flush, parent flush, readback or checkpoint fails | No provider/target writer is called; no retry or final-record cleanup | Retained start means outstanding; absence/unreadability means unverifiable, never clean | L; pre-S residue may vary |
| Interrupted after S, before provider | No assumed completion | Retained obligation refuses continuation; provider inactivity is known only from controlled test instrumentation | L; termination test, not power loss |
| Provider returns, then interruption before token save | No session or restore | Outstanding start; cannot infer unchanged provider | L; synthetic provider effects only |
| State/token save fails midway | Stop bundle, preserve failure classification and start | Refusal even if one or both target files exist | L; no transactional rollback claim |
| Both writers return, then checkpoint fails | Count two does not yield success | Matching pair plus start still refuses | L; exercise existing count semantics |
| Completion record visible, then flush/readback/context exit fails | COMMIT_UNCERTAIN; never clear start | Completion visibility cannot defeat the retained obligation | L; injected observable failure is not proof current close errors are reported |
| Failure-observation write itself fails | Preserve original failure in memory; do not replace it with a diagnostic error | Start remains sufficient to refuse; exact cause may be unavailable | L; no guaranteed reason persistence |
| Missing, corrupt, unreadable, other-pair or other-operation record; conflicting duplicate ID | Fixed refusal; no repair or coercion | Same refusal under the trusted expected binding | L; parser/reader tests use synthetic bytes |
| Switch record path or replace it with an older record | Reject enrollment/path/expected-operation mismatch where independently known | Refuse detectable mismatch; coherent whole-store rollback may be undetectable | L; no local-chain anti-rollback claim |
| Unexpired token with outstanding history | Stop before valid-token early return | Obligation persists across calls | Future L integration; not part of first component |
| Lock busy, acquisition failure or path revalidation failure | Stop without provider/write or unlocked retry | Evidence remains unchanged or unverifiable | L |
| Nonparticipating writer | Managed API rejects missing participation; test demonstrates external advisory-lock bypass | Refuse observed defect; undetected same-user mutation is outside guarantee | Future L integration and explicit trust limit |
| Unsupported platform | Fixed unsupported classification before storage/provider effects | No claim of established start or managed serialization | U; never dispatch to Windows fallback |
| Separate process reload after orderly writer exit | Reader reports outstanding start without module-global state | Fixed refusal classification | L; stronger than memory reconstruction only |
| Forced process termination around publication/S/C | Stop and inspect only test-owned artifacts from a new process | Distinguish absent/unverifiable, outstanding and observed evidence; never synthesize completion | L; phase-specific real-process experiment |
| Device/power-loss or filesystem rollback experiment | No assumed guarantee from mocked fsync success | Qualification-specific result; may lose evidence | Separate platform/storage research, outside initial acceptance |

Keep four evidence levels separate: memory reconstruction, actual process restart, forced termination, and power-loss/storage qualification. Mocked success or failure injection establishes control flow and classification, not actual durability. Existing lock subprocess tests do not substitute for record-persistence experiments.

## 10. Open decisions and their blocking scope

| Decision | Work it blocks |
| --- | --- |
| Fixed record-slot name, codec version/byte bounds, and synthetic binding contract | The prototype-only choices are now specified in section 12. They do not approve real enrollment or a production schema; filesystem and durability qualification remain open. |
| Trusted real enrollment, operation-ID allocation, persistent binding and authorized migration | Blocks real management and protection against caller-selected path switching; does not block synthetic standalone create/read work. |
| Normal closure criteria, C's exact validation set, finalization/lock-release observations and caller-return semantics | Blocks automatic completion closure, repeated managed operation lifecycle and session integration. A visible terminal record is insufficient. |
| All writer entry points and explicit lock-ownership composition | Blocks runtime enforcement, especially authorization-before-bundle and standalone writers. |
| Stronger read binding, Windows retention/serialization, and durability qualification | Blocks the corresponding stronger claim or platform. No unlocked or weaker fallback. |
| Independent anti-rollback trust and controlled reconciliation authority/evidence | Blocks those guarantees and any recovery/clearing feature; they are not prerequisites for the bounded denial-only prototype. |

This is reviewable design, not implementation-ready approval for a production protocol.

## 11. Original next implementation candidate

**Candidate: an independent Linux-only create/read component for one immutable incomplete-operation record, using synthetic data only in its acceptance tests.** It establishes and reloads a refusal fact; it neither closes operations nor controls credentials.

The original candidate files, subsequently authorized only for the independent prototype in section 12:

- `src/tridentine_calendar_google_sync/production_write_token_operation_record.py`
- `tests/test_token_operation_record_phase6d1h.py`

The original candidate assumed no existing-file changes. Subsequent explicit authorization permits only the two structural consumer restrictions detailed in section 12 to admit the new module. Existing runtime helpers remain unchanged. Any need to change an existing helper or another assertion remains a stop condition. No new Unit number is assigned.

The component would use E8's create-only publisher, E9's bounded private reader and E10's Linux lock. It would own one lock per public create/read call, use a fixed record slot beneath an explicitly supplied synthetic enrollment binding, revalidate the directory around I/O, and reject reentrant/borrowed-context use rather than silently acquiring twice. It must explicitly reject repository/worktree and unrelated artifact locations using a reviewed path contract; it must not import token/session runtime modules merely to borrow their configuration validation.

New responsibilities are a strict bounded metadata codec, binding/operation comparison, fixed safe outcomes, and preservation of the occupied slot. Its result never authorizes reuse. A create success means the defined S prefix was observed; a later read means outstanding evidence was observed, not that the original caller necessarily observed success. Existing identical bytes, duplicate IDs or a different ID in the occupied slot all stop; absent evidence yields an absent/unverifiable classification, not permission.

Acceptance requires synthetic temporary-directory tests for successful create/read, refusal to overwrite/remove, strict malformed/foreign/duplicate inputs, private/path failures, lock contention, failures before and after publication, preservation of the start despite later diagnostic failure, safe repr/exception output, and a separate-process reload without global state. Simulated downstream failures exercise retained-obligation behavior without invoking real token writers or providers. Pure codec tests should run in the base layer with existing socket restrictions and no Google extras. Linux I/O tests and unsupported-OS refusal tests must be reported separately; Windows success is not implied.

Reject invalid input, unknown binding, an occupied slot, unsupported OS, unavailable/busy lock, or an unsafe path detected during preflight before attempting record publication. A later readback, path revalidation or checkpoint failure stops further work; it may follow publication. Preserve any final record and return a fixed refusal/uncertainty classification. A future coordinator must not cross the protected provider/token boundary without confirmed S. No automatic retry, deletion, permission repair or alternate-path attempt is allowed.

The prototype-only choices and reader/path contract authorized after this design are recorded in section 12. The component still excludes real enrollment or migration, provider calls, token/state reads or writes, session/writer/inspector/CLI wiring, changes to the memory-only model, terminal observations or normal closure, reconciliation, Windows persistence, anti-rollback authority, new dependencies, schema files, a manual PowerShell runner, and Production approval. Those exclusions limit its claim; they do not require waiting for every future system problem to be solved.

The original design did not authorize implementation. The later limited authorization described below does not authorize runtime integration, record clearing, or Production use.

## 12. Unreviewed standalone prototype

This section describes the new [operation-record module](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py) and its [synthetic tests](../tests/test_token_operation_record_phase6d1h.py). It supersedes only the original proposal's bounded prototype choices. The threat limits, historical evidence, and production decisions in sections 1-11 remain applicable. The record is retained indefinitely; repeated successful operational use does not have a completed lifecycle.

### 12.1 Fixed record format and synthetic binding

The only record destination is the fixed leaf `production-write-operation-start-v1.json`, immediately inside the caller-supplied existing private directory. An operation ID never becomes a filename. There is one occupied slot per supplied pair binding; the component neither allocates another slot nor follows a path from parsed record contents.

The following closed JSON object is a prototype format, not an approved production schema. These are its complete keys:

| Key | Exact value or constraint |
| --- | --- |
| `format_version` | JSON integer `1`; Boolean `true` is not accepted as an integer. |
| `record_kind` | `production_write_operation_start`. |
| `storage_ref` | Explicit synthetic storage reference matching the expected binding. |
| `pair_ref` | Explicit synthetic pair reference matching the expected binding. |
| `role` | `production_write`. |
| `token_slot` | Expected synthetic token leaf label. Its contents are never accessed. |
| `state_slot` | Expected synthetic state leaf label. Its contents are never accessed. |
| `operation_id` | Explicit synthetic identifier for this attempt. |
| `predecessor_id` | Explicit JSON `null` for `new_pair`; a different, non-null synthetic reference for `refresh`. |
| `operation_kind` | Exactly `new_pair` or `refresh`. |
| `phase` | `started`. |
| `outcome` | `incomplete`. |

References have 1-96 ASCII characters, begin with an ASCII letter or digit, and contain only ASCII letters, digits, `.`, `_`, or `-` thereafter. There is no trimming, case conversion, or value completion. Token/state labels satisfy the same bound and character rule, do not end in a period, and reject Windows device-name bases such as `CON`, `NUL`, `COM1`-`COM9`, and `LPT1`-`LPT9`, including suffixed forms. Both labels and the fixed record leaf must be pairwise distinct. The predecessor check is structural only: it does not prove that a preceding operation existed, completed, or belongs to a complete history.

Canonical encoding uses sorted keys, ASCII escaping, compact comma/colon separators, no nonfinite numbers, UTF-8 without BOM, and exactly one final LF. The limit is 4096 bytes, checked after encoding, before parsing, and at the private-reader boundary. Parsing rejects unknown, extra, missing, or duplicate keys, including identical duplicates; non-object or nested values; wrong exact types; unknown fixed values; malformed UTF-8; BOM; NaN/Infinity; and noncanonical representations. The parsed mapping and canonical bytes must match the explicit expected binding and operation. Malformed inputs return a fixed negative match or a fixed private codec error, without including input text.

The directory is an explicit native `Path`, absolute and local. Root-only paths, parent references, `.git` components, NUL, network/double-root anchors, and unsafe trailing-dot/space or separator aliases are refused. The component never calls `resolve` to repair input. A `Path` may already have normalized some original spelling; this check does not claim to recover rejected spellings that no longer exist in the object. Existing lock and sensitive-I/O checks enforce filesystem path/private-parent/worktree policy. The component does not create directories, repair permissions, migrate data, infer enrollment from token/state existence, or authenticate the caller.

Only the record leaf is read or written. The token/state labels are metadata comparisons, not filesystem destinations. No token contents, credential-derived hash, provider response, generation-derived secret, account identifier, clock, PID, arbitrary note, or exception text is stored. Matching synthetic references are not genuine enrollment, binding authority, anti-rollback protection, or proof of provider validity.

### 12.2 API and fixed results

| API/type | Contract |
| --- | --- |
| `SyntheticBinding(directory, storage_ref, pair_ref, token_slot, state_slot)` | Frozen caller-supplied synthetic metadata. All fields are hidden from `repr`. No defaults assert registration or history completeness. |
| `RecordOperation(operation_id, predecessor_id, kind)` | Frozen explicit operation metadata, with all fields hidden from `repr`; `kind` is `OperationKind.NEW_PAIR` or `OperationKind.REFRESH`. |
| `create_start_record(binding, operation)` | Own one lock and attempt at most one create-only publication to the fixed leaf. Return only `RecordResult`. |
| `read_start_record(binding, operation)` | Own one lock and inspect the expected incomplete record without writing. Return only `RecordResult`. |
| `RecordResult(state, publication_possible=False)` | Frozen fixed classification plus strictly Boolean-or-unknown local publication evidence. `reuse_authorized` is `Literal[False]`, excluded from constructor arguments. Arbitrary state values or non-Boolean publication values are rejected. |

The codec helpers are private implementation/test boundaries, not public persistence or approval APIs. `_encode_start_record` emits bounded canonical metadata or a fixed `_RecordFormatError`; `_matches_start_record` returns only a Boolean. There is no arbitrary-record-path argument, borrowed-lock argument, environment-derived directory, retry, registration, migration, completion, clearing, or recovery API.

| `RecordState` | Meaning |
| --- | --- |
| `START_CONFIRMED` | This create call observed its specified publication/readback/checkpoint interval and normal context exit. It grants no effect or credential permit. |
| `START_OBSERVED` | A read observed the expected incomplete record. It does not prove that the original create caller observed success. |
| `SLOT_OCCUPIED` | A directory entry already occupies the fixed leaf. Identical bytes or IDs are not idempotent success. |
| `UNVERIFIABLE` | Input, binding, path, content, or an ordinary prepublication/read failure could not be verified. Missing evidence is not clean history. |
| `PERSISTENCE_UNCERTAIN` | A create reached the publisher and then failed, or a subsequent check/context exit failed. Consult only the limited publication evidence; no completion or retry permission follows. |
| `LOCK_BUSY` | The existing cooperative lock reports contention. No waiting or unlocked fallback is attempted. |
| `LOCK_UNAVAILABLE` | The lock could not be acquired or revalidated, unless an already-attempted publication requires the more conservative persistence classification. |
| `UNSUPPORTED_PLATFORM` | The storage API stopped before binding/path inspection, locking, or record I/O because the platform is not Linux/POSIX. |

All results have `reuse_authorized=False` and contain no path or arbitrary input reference. `publication_possible` describes only this call's attempted publication: `False` before publisher entry; `None` after entry until stronger evidence exists; an exact Boolean carried by the publisher's formal error is retained; a normal publisher return gives `True`. A later failed readback/checkpoint/context exit does not negate that publication. An unknown publisher exception stays `None`, even if a test can observe residual bytes. A persistence failure may therefore coexist with `False`: the save attempt failed, and the formal backend evidence is limited to its publication boundary. This field never proves absence of a previous record, other-actor inactivity, unchanged provider state, safe retry, or credential usability.

### 12.3 Storage sequence and failure boundaries

Both public functions reject unsupported platforms before inspecting even the supplied binding. Pure codec and result tests remain runnable on Windows. Linux storage uses unchanged `acquire_posix_private_directory_lock`, `create_posix_private_bytes`, and `read_private_sensitive_bytes`; output preflight uses the unchanged `validate_sensitive_output_path`. The new module does not import the directory backend directly and does not borrow token/session validation.

For each Linux call, structural binding/operation checks and bounded encoding precede one lock acquisition. Under that owned context, directory revalidation surrounds the fixed record access. Create uses non-following entry inspection: every occupied entry, including a directory or dangling symlink, refuses publication without accepting existing content as success. For an absent slot, output preflight and a checkpoint precede the single publisher call. A normal publisher return is followed by private readback with `max_size=4096`, strict canonical/binding/operation matching, and a final directory checkpoint. Read uses the same owned lock, bounded private reader and expected matching, followed by its final checkpoint. Success is constructed only after context exit.

An ordinary failure produces a fixed classification. The first classified failure is retained if a later observable ordinary cleanup error occurs. Cancellation propagates and cannot be converted into success; callers must not expose arbitrary exception text as public diagnostics. A failure after publication leaves the final record untouched. There is no separate failure-observation file, diagnostic write, rollback, final-name deletion, overwrite, alternate path, or caller-level retry. The existing publisher's bounded temporary-name collision handling and verified cleanup of its own temporary files are unchanged and are not additional operation attempts.

The lock is owned by each call, not transferred to its caller. An outer lock on the same directory produces contention rather than a borrowed-lock/reentrant path. Linux advisory locks constrain only cooperating users of the same directory inode. This component is not directly composable inside existing session locks without separately reviewed ownership changes.

Publication creates exact 0600 files in the existing checked private parent. The reader enforces its actual effective-owner, single-link, owner-only policy, which is not an exact-0600 requirement; an owner-readable 0400 file may still be observed. No permission repair occurs. Reader composition plus directory checkpoints does not give atomic ancestor/leaf binding against same-user races. Existing suppressed close errors remain unobservable; normal context exit is not positive attestation of every descriptor release. S remains a bounded observation, not a durable certificate of the entire invocation, power-loss resistance, or permission to call a provider. Windows storage remains unsupported with no fallback to its existing writers.

### 12.4 Precisely authorized dependency-test changes

Existing runtime modules, helpers, model, inspector, session, writer, CLI, schemas, registry, and configuration remain unchanged. Only two existing structural consumer restrictions are amended to recognize the new explicit dependency:

- In [tests/test_posix_private_lock_phase6d1h.py](../tests/test_posix_private_lock_phase6d1h.py), the renamed `test_component_has_no_artifact_write_no_wait_loop_and_only_approved_consumers` admits exactly `production_write_token.py` and `production_write_token_operation_record.py`, excluding the lock implementation itself. Its prohibited-operation AST check, loop prohibition, scan scope, and negative assertion for other modules remain unchanged, as do all other tests, fixtures and markers in that file.
- In [tests/test_posix_sensitive_directory_phase6d1h.py](../tests/test_posix_sensitive_directory_phase6d1h.py), only the final publisher-consumer exception tuple in `test_directory_foundation_only_has_the_reviewed_backend_consumers` adds `production_write_token_operation_record.py`. Excluding the publisher itself, direct consumers are exactly `_private_create_io.py`, `_posix_private_replace.py`, and the new module. The earlier directory-backend direct-consumer restriction is unchanged; the new module is not added to it. The directory AST prohibition, publisher-to-directory assertion, negative consumer assertion, other tests, fixtures and markers remain unchanged.

The new tests independently inspect actual imports for those exact two/three consumer sets, reject dynamic import hiding, verify that the new module does not import the directory backend or token/session/inspector/CLI/provider components, and check that no other runtime module refers to the new component. This is a specifically authorized dependency addition, not a relaxation of lock or publisher runtime safety conditions.

### 12.5 Specification-to-test map

All named tests below reside in [tests/test_token_operation_record_phase6d1h.py](../tests/test_token_operation_record_phase6d1h.py). Parameterization expands cases; the table does not predict executed test counts. The Linux storage tests carry an explicit Linux-only condition and use new pytest-owned synthetic directories.

| Requirement | Named tests |
| --- | --- |
| Exact canonical fields and fresh-object matching | `test_canonical_codec_has_exact_closed_fields_and_no_directory`; `test_every_required_field_is_required`. |
| Exact types, duplicate keys, unknown fields/values | `test_wrong_types_are_not_coerced`; `test_duplicate_keys_never_establish_a_record`; `test_unknown_and_forbidden_closed_values_are_rejected`. |
| JSON shape, encoding, nonfinite constants and limits | `test_invalid_json_and_preparse_size_boundary`; `test_nonfinite_constants_inside_object_are_rejected`; `test_noncanonical_equivalent_representations_are_rejected`; `test_nonbytes_are_rejected_without_reflection`; `test_size_checks_precede_json_parse_and_bound_encoded_output`. |
| Reference, slot, operation and predecessor constraints | `test_invalid_binding_references_raise_only_fixed_codec_error`; `test_longest_allowed_references_remain_canonical`; `test_slot_collisions_are_rejected`; `test_unsafe_leaf_aliases_are_not_normalized`; `test_operation_kind_and_predecessor_structure_are_not_inferred`. |
| Expected binding and operation are not interchangeable | `test_expected_binding_mismatch_never_matches`; `test_expected_refresh_operation_mismatch_never_matches`. |
| Frozen fixed results and nonreflective diagnostics | `test_all_result_states_are_frozen_and_never_authorize`; `test_input_reprs_and_codec_errors_do_not_echo_values_or_paths`; `test_result_constructor_rejects_arbitrary_state_and_nonboolean_evidence`; `test_unknown_input_hooks_are_not_invoked`. |
| Unsupported-platform refusal before path/I/O | `test_unsupported_platform_stops_before_even_path_or_binding_checks`. |
| Exact imports and no runtime integration | `test_only_exact_reviewed_modules_directly_import_lock_and_publisher`; `test_component_has_no_runtime_consumer_or_dynamic_import_and_no_mutation_escape`. |
| Real create/read and persistent incomplete meaning | `test_real_create_then_separate_call_read_remains_incomplete`; `test_synthetic_downstream_failure_does_not_clear_start`. |
| Occupied file/ID/link/directory is never overwritten | `test_occupied_slot_is_never_overwritten_or_idempotent`. |
| Private read policy, unsafe paths, links and worktrees | `test_reader_owner_only_policy_is_not_exact_creation_mode`; `test_reader_refuses_unverified_or_unsafe_record_without_repair`; `test_unsafe_directory_never_publishes_or_repairs`. |
| Owned lock, contention, final result after exit | `test_real_outer_lock_causes_busy_without_reentrant_fallback`; `test_one_owned_lock_covers_io_and_success_follows_exit`; `test_lock_acquisition_failure_never_enters_record_io`. |
| One publisher call and conservative publication evidence | `test_publisher_called_once_and_only_formal_boolean_evidence_survives`; `test_unknown_publisher_exception_never_echoes_input_or_retries`. |
| Readback/checkpoint/exit failures retain final record | `test_postpublication_readback_failure_retains_final_record`; `test_success_is_not_returned_before_final_checkpoint_and_context_exit`; `test_later_exit_error_does_not_erase_formal_publisher_failure`. |
| Cancellation is never manufactured success | `test_cancellation_is_not_recast_as_success_or_an_ordinary_failure`. |
| Token/state contents are not accessed | `test_token_and_state_sentinels_are_never_read_or_modified`. |
| Independent process reload | `test_separate_process_reloads_only_test_owned_record_without_suite_restart` launches a minimal guarded entry point with a finite timeout and fixed output. It reads only the new test-owned record and does not restart pytest. |

Independent process reload, forced termination and power-loss qualification remain different evidence levels. The subprocess test checks ordinary process independence; it is not a power-loss experiment. Source/AST inspection and mock fault injection are not substitutes for Linux filesystem execution. The existing model and inspector retain their independent `reuse_authorized=False` boundary, and the new component does not connect to either.

### 12.6 Verification record and remaining decisions

Validation status: IMPLEMENTED_VALIDATION_INCOMPLETE. Local verification used the existing Windows Python 3.12.14 environment with the package resolved to this repository's src directory. Installed metadata for pytest, pytest-socket, Ruff, mypy, pydantic and build matched uv.lock; this is metadata comparison, not a frozen installation. No installation, environment rebuild or Linux setup was performed.

The five required files were passed in full to pytest through an in-memory report collector, using the existing conftest and strict/socket settings. Cacheprovider was disabled, bytecode writing was disabled, and temporary artifacts used a new test-owned directory within the permitted workspace. The invocation was the existing Python with -B and pytest.main(["-q", "-p", "no:cacheprovider", "--basetemp", FRESH_TEST_DIRECTORY, ...the five files below]); the collector only counted outcomes and suppressed raw diagnostic output.

| Test file | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: |
| tests/test_token_operation_record_phase6d1h.py | 249 | 0 | 0 | 53 | 0 |
| tests/test_posix_private_lock_phase6d1h.py | 4 | 0 | 0 | 24 | 0 |
| tests/test_posix_sensitive_directory_phase6d1h.py | 7 | 0 | 0 | 40 | 0 |
| tests/test_posix_private_create_phase6d1h.py | 2 | 0 | 0 | 41 | 0 |
| tests/test_token_reuse_policy_phase6d1h.py | 205 | 0 | 0 | 0 | 0 |
| Total | 467 | 0 | 0 | 158 | 0 |

Both amended structural guards ran and passed, rather than being skipped or deselected. The skipped cases retain explicit OS conditions. In particular, the 53 new Linux I/O cases, including separate-process reload, were not executed on Windows. No Windows result is claimed as Linux storage or Windows persistence validation. Forced termination, power loss, actual provider effects and real registration were not tested.

Final static checks succeeded: ruff check --no-cache --output-format json .; ruff format --check --no-cache .; mypy --strict --no-incremental --no-pretty with a fresh cache for the new module; and the same strict mypy check over src, covering 118 source files. Early findings in the new files were corrected without ignores, assertion removal, relaxed safety conditions or changes to existing runtime. Fresh validation/cache locations were used; older validation roots, logs and caches were not reused or removed.

Prior run 35598888487 applies only to the fixed HEAD and does not validate these uncommitted changes. Linux real I/O and subprocess execution remain required before the stronger local-checks-passed result can be used.

Prototype-only choices now fixed are the one-slot leaf, twelve keys and values, version, 4096-byte cap, canonical encoding, lexical reference/slot/binding/predecessor constraints, independent per-call lock ownership, fixed result model, and Linux-only storage dispatch. Those choices do not decide real registration, migration, operation-ID allocation, complete-history acquisition, rollback anchoring, trusted same-user protection, all-writer participation, session integration, stronger reader binding, Windows persistence, durable normal closure, reconciliation authority, or Production approval. The relevant blocking scopes in section 10 remain in force.

The prototype and tests require review. This work does not authorize a next runtime integration step, a record-clearing lifecycle, commit/push/PR operations, or use of real credentials. DS-04 remains PARTIAL, Historical Deep Security Scan remains INCOMPLETE, the separate 47194b0 scan report remains FAIL, and the Production gate remains BLOCKED.
