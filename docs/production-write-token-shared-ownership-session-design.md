# Shared Ownership for START and Credential-Session Processing

Status: DRAFT_INTERFACE_DESIGN_NOT_IMPLEMENTED_NOT_OPERATIONAL_APPROVAL

## 1. Evidence and decision

CURRENT_SOURCE means HEAD 095326d9db4ee387d0c935b40a5d4d6bfbcd6019, tree 850553c21ab1f1c1a2dc52a6460e754a4784517c, parent 385b770a051c56c2aa54520e72255231877ee9a6. References below use positions at that HEAD. CURRENT_TEST means definitions inspected, not tests executed here.

INHERITED_CI is the supplied run 38745599347, attempt 1, eight successful jobs, inspected on 2026-10-15 JST; PR #17's 35-commit description and comment 6204527303 were externally rechecked on 2026-10-16 JST. The existing composition reports Ubuntu 11 passed / 2 skipped and Windows 3 passed / 10 skipped. Detailed logs cover base jobs only; six other jobs have job/step evidence. This design was not tested by that CI.

Historical local 611 collected / 545 passed / 66 skipped, exit 0, retains then-unexecuted Linux ten cases and three complete I/O regression files. VALIDATION_ROOT_UNAVAILABLE and the separate earlier 75 failures remain historical; CI does not establish retrospective local success or diagnose every earlier cause.

HISTORICAL_DESIGN: [Sequential design] describes option A and its later implementation. [Enrollment design] section 5 predates its implemented private-scope sections 9-10. [Reuse design]'s independent model does not erase the newer record component.

Decision: SHARED_OWNERSHIP_DESIGN_READY_FOR_REVIEW. Recommend one session-local preparatory split, then separately reviewed START integration. Neither is implemented here.

## 2. Current ownership intervals

| Boundary | CURRENT_SOURCE order and ownership |
| --- | --- |
| Public record | [R] 653-699 rejects unsupported platforms, then enters _record_scope. Entry validates binding/operation/revision and acquires one directory lock (372-457); held I/O runs at 573-634. Only after normal owner exit does the wrapper map success to START_CONFIRMED/START_OBSERVED (682-687). |
| Public session preflight | Both public prepare functions validate target and confirmation ([T] 890-948). Loader validates UTC and the complete path set before locking (764-777; [IO] 726-806). Metadata/identity inspection is distinct from credential-content reads. |
| Held session | [T] 778-887: acquire; read state/token; checkpoint and verify. Unexpired: checkpoint, construct session. Expired: adapter checks, checkpoint, refresh once, accounting/evidence/identity checks, checkpoint, reread both, render/compare, checkpoint, save once with original token, final checkpoint, construct session. Constructors are inside ownership; delivery to the caller follows normal exit. |
| Other helper users | [IO] 530-591 uses _production_write_session_lock around state write, checkpoint, token write, checkpoint. completed_output_count=2 does not make a later failure successful. [Inspector] 23,97 also uses this helper. |
| Platform boundary | [T] 125-179 sorts distinct lexical token/state parents and acquires each through ExitStack; partial acquisition unwinds prior locks in reverse order. Windows yields a no-op checkpoint. Record storage and native [L] acquisition are Linux-only; Windows bundle retains its existing separate path ([IO] 648-686). |

CURRENT_TEST: [Composition] 245-315 finishes the public record call before the mock-session phase, explicitly recording the gap at 266. It provides sequential ordering, not continuous ownership.

Putting a public record call inside the session lock reacquires its directory; putting the public session call inside a record scope similarly reacquires overlapping parents. Independent opens of the same directory can yield LOCK_BUSY; lexical sorting does not deduplicate aliases. Foreign owners also fail [R] _require_scope, rather than becoming borrowed authority.

Static inference: after held creation, passing a session ordinary exception into existing [R] __exit__ (459-516) invokes record _failure_result (237-245), yielding PERSISTENCE_UNCERTAIN and _ScopeFailure instead of preserving the session exception contract. This was not experimentally reproduced here.

## 3. Two interface options

| PROPOSED_INTERFACE | Files, ownership and compatibility |
| --- | --- |
| A: extend existing record ownership, preferred destination | [R] gains private _shared_start_session_scope and a shared finalizer; [T] gains a closed record-linked session adapter. Keep legacy _record_scope, public wrappers and classifications intact. One record owner acquires/releases; session work uses an issued child capability without acquisition. Separate record/session diagnostics are mandatory. |
| B: separate ownership core | Add PROPOSED _production_write_shared_ownership.py, adapt [R] and [T], and move acquisition responsibility there. A new direct lock consumer requires both exact-consumer guards to admit that module; removing old imports changes their expected sets too. More adapters and failure contracts make this too broad for the next unit. |

For A, the later token-to-record dependency requires exactly production_write_token.py as an approved record runtime consumer in [Record tests] 418-487. No reverse import is proposed: record importing token would violate its local-import allowlist. Existing direct lock and publisher sets remain unchanged. B additionally affects [Record tests] 392-415 and [Lock tests] 411-443; the record module's local-import allowlist at [Record tests] 418-433 must explicitly admit the proposed core. Direct directory-backend access would require [Directory tests] 351-389 approval. No such changes are authorized now.

## 4. Shared-owner contract

PROPOSED_INTERFACE: initially accept only a synthetic Linux fixture where START directory, token parent and state parent are the same declared directory, with distinct reserved leaves and independently supplied binding/REFRESH operation/predecessor. Reject different-directory shared requests before acquisition. Preserve the existing public session API's different-parent support.

Existing directory guards check descriptor/name identity, ownership/mode policy and Git markers ([D] 111-135); fixture setup supplies intended association. Equal paths or slots do not prove physical credential binding, trusted enrollment, complete history, resistance to equal-authority replacement, or rollback protection. Revalidation remains bounded; nonparticipating writers and changes after checks remain outside the guarantee.

[R] already checks factory identity, reciprocal owner/scope identity, PID, original live thread, ACTIVE lifecycle, binding/operation/revision snapshots and non-reentry (352-457, 519-570). It lacks a completed-held-START latch and credential-request binding. A shared extension must add both, plus one session-phase latch and child revocation.

The child issuer must validate the actual record owner and these snapshots, then retain the complete session request, including paths, target, time, evidence mode and refresher identity. A standalone session owner cannot satisfy this START-linked contract. No supplied result object, type name/private attribute alone, already_locked flag, arbitrary checkpoint Callable, descriptor or borrowed lock suffices.

Checks occur before content access and alongside every existing checkpoint. Reject wrong issuer/request/operation, wrong process/thread, entry failure, duplicate entry, concurrent/reentrant use, a second held invocation and use after exit. Initial entry failure is terminal. During the session phase, independent record reentry is forbidden. This prevents ordinary misuse among cooperating participants, not hostile mutation within the same Python process.

The future shared entry must perform the existing target/exact-confirmation checks and UTC/full path-set preflight before entering ownership or creating START. Only then retain the validated request for the child issuer. These checks remain real; the bridge must not bypass them or call the public session API inside the scope.

All new names in this responsibility sketch are PROPOSED; only the marked held-record call currently exists:

    with R._shared_start_session_scope(binding, operation, request) as joint:
        start = R._create_start_record_held(  # CURRENT private primitive
            joint.record_scope, binding, operation
        )
        joint.require_held_start(start)  # checks owner latch, not just the result
        child = T._session_owner_from_record(joint, request)
        candidate = T._load_production_write_credential_session_held(child, request)
        joint.final_checkpoint()
    return joint.deliver(candidate)

HELD_START_CHECKPOINT is the internal milestone; requiring public START_CONFIRMED here would require premature exit. Neither milestone authorizes credential use. The adapter performs no second acquisition and accepts no caller-supplied checkpoint. Its closed issuer is validated against the record owner on every use.

The shared finalizer must retain session failures separately and must not feed them through legacy record exception classification. It revokes child/parent access and attempts release exactly once. No public result or candidate leaves the owning wrapper before the final checkpoint and normal exit. No owner remains usable during subsequent caller processing. START stays started/incomplete on success; absence never becomes ordinary reuse permission.

## 5. Failure and cancellation rules

PROPOSED_INTERFACE for the later shared path, not retroactive changes to existing public exceptions:

| Event | Required result and retained evidence |
| --- | --- |
| Acquisition/context entry failure | No usable owner, content reads or subsequent effects; unwind only acquired resources; terminal entry. |
| START refusal/uncertainty | Stop before session. Keep actual record classification and its publication evidence; no retry, repair, alternate slot or deletion. |
| Credential read/validation failure | Preserve the session exception; START evidence remains separate; no refresh/save after the rejection. |
| Refresh/prewrite failure | Preserve existing refresh/prewrite diagnosis. Prewrite publication_possible=False describes only this call's absent save attempt. |
| Save exception | Preserve ProductionWriteTokenRefreshPersistenceError and credential publication_possible independently of record publication. No later observation clears it. |
| Final checkpoint failure | Withhold candidate even after save; retain any earlier publication evidence. |
| Exit failure after normal body | Withhold candidate; report the observed exit failure without claiming rollback. |
| Earlier ordinary exception plus ordinary exit failure | Earlier record/session failure remains primary; keep a separate fixed cleanup classification without altering the original exception. |
| Earlier cancellation plus ordinary exit failure | Propagate the same cancellation object; no session and no conversion to normal failure or success. |

First cancellation wins; without an earlier cancellation, cleanup cancellation takes precedence over an ordinary failure. Ordinary cleanup cannot erase an earlier persistence diagnosis. Retain distinct internal record evidence, credential evidence and delivery outcome, not one success flag. Do not manually rewrite exception notes, cause/context, or traceback to attach secondary diagnostics; no exception objects or credentials enter public diagnostics.

CURRENT_SOURCE has narrower observability: [L] 63-81 suppresses ordinary close exceptions while unwinding a body error; [D] 101-109 suppresses os.close OSError even after normal body completion. Record exit adds no final revalidation. A reported exit failure must block delivery, but normal exit cannot attest every descriptor close or kernel lock state. The session helper's acquisition mapping does not cover every exit error. The new arbitration requires its own acceptance tests; current APIs are not declared repaired.

## 6. One next implementation unit

PROPOSED_INTERFACE: extract a private, ownership-checked credential body within [T], without connecting START. This removes the monolithic loader's acquisition/body coupling and prevents extraction from creating an unchecked no-lock entry. It does not close the current record/session gap.

Exact source candidate: production_write_token.py only. PROPOSED symbols:

    _CredentialSessionRequest                 # retained private invocation inputs
    _CredentialSessionScopeContext(request)   # acquires existing session lock itself
    _CredentialSessionOwner                  # issued only after successful entry
    _require_session_owner(owner, request)
    _load_production_write_credential_session_held(owner, request)

Existing public wrappers and _load_production_write_credential_session signatures remain. Keep target/confirmation checks in the wrappers and UTC/path checks before ownership. Move loader 781-887 into the held body. The private context internally captures the checkpoint yielded by _production_write_session_lock; neither construction nor issuance accepts a checkpoint argument.

    # PROPOSED replacement inside the existing loader, after unchanged preflight:
    request = _CredentialSessionRequest(current_arguments)
    with _CredentialSessionScopeContext(request) as owner:
        return _load_production_write_credential_session_held(owner, request)

The context owns entry through exit, with a reciprocal issuer seal, retained request identity/snapshot, PID/thread, active/busy/single-use state and terminal revocation. Check validity before the first read and at existing checkpoints; distinguish permitted in-progress checkpoints from forbidden held-function reentry. A standalone invocation has no invented START operation. Windows preserves current no-op locking semantics and cannot issue START-linked authority.

Keep _production_write_session_lock bytes unchanged, including its yielded-checkpoint contract, acquisition/unwind and Windows behavior. Leave [IO], [Inspector], record module, publisher, schemas and public exports unchanged. Preserve provider/test evidence selection, provider refresher=None, role/scope/target/identity/generation checks, both constructor paths, at-most-one refresh/save, original expected_token, exception types/evidence/chaining, and cancellation propagation. Do not add native checkpoints or stronger exit arbitration in this preparatory unit.

Proposed test changes are one new tests/test_token_session_owned_body_phase6d1h.py plus narrowly retargeting these four existing structural guards, each requiring explicit approval:

| Existing file under tests/ | Existing function |
| --- | --- |
| test_credential_session_lock_phase6d1h.py:483 | test_loader_lexically_holds_locks_over_reads_refresh_save_and_both_returns |
| test_refresh_persistence_failure_phase6d1h.py:313 | test_new_handler_has_no_retry_cleanup_or_new_mutation_capability |
| test_refresh_prewrite_recheck_phase6d1h.py:397 | test_added_recheck_only_reads_renders_compares_and_raises |
| test_refresh_replace_integration_phase6d1h.py:367 | test_refresh_passes_original_input_and_has_no_legacy_save_at_call_site |

Retarget location assumptions to the issuer-to-held-body chain while retaining every protected semantic assertion: ownership around both constructions, exact reread/render/compare operations before the single save, original-token argument, ordinary-Exception persistence handler and no retry/cleanup. Do not reduce scanning or hide imports.

No consumer-set change belongs to this first unit. Retain the record no-consumer guard, [Bundle tests] test_only_bundle_wrapper_newly_acquires_shared_lock_and_never_cleans (383), and lock/directory/publisher consumer guards unchanged. Approval of new private interfaces and those four test retargets is required before implementation; no new common module is needed.

PROPOSED_ACCEPTANCE: common memory-only tests must traverse real public validation and held processing successfully for unexpired and fake-refresh inputs, including provider/test modes, and verify bounded effects. Negative tests cover forged/wrong/expired/reentered owners, swapped requests, entry/checkpoint/exit failures and original cancellation identity, with zero subsequent effects after rejection. Preserve existing persistence/prewrite diagnostics and both return paths.

Linux-native acceptance separately covers same/different-parent ownership, partial acquisition unwind, contention, actual persistence and release. Windows preserves current public behavior without claiming native shared START storage. Existing [Session tests] tests at 140,177,212,252,289,466 and native cases at 328-424,554, [Persistence tests] 109,192,300, [Prewrite tests] 193,226,250,286, replacement integration, bundle/session exclusion (296), [Reentry tests] and [Composition] remain regression requirements. Keep conftest, strict/socket settings and base markers unchanged. No validation root is presumed available.

## 7. Remaining boundaries

OPEN_DECISION: the later closed record-child issuer and separate shared finalizer need interface/guard review before START integration. Operational approval authority, independent expected-operation supply, physical binding, rollback requirements and participating writers remain deployment decisions. Normal closure, START retirement, recovery, crash durability and all-caller enforcement are excluded.

Original DS-04 text and formal close criteria remain unavailable; this design is not a quotation or closure assessment. Earlier fixed-file commit-before-CI approvals do not authorize this document's commit or future implementation.

Only this new document was created. No application/test imports, tests, native scope acquisition, START I/O, credential reads, environment changes or remote requests occurred. DS-04 remains PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 report FAIL; Production gate BLOCKED; handlers hard-off; registry empty/fail-closed. PR #17 Draft is inherited evidence. No commit, push, PR change or Google operation is authorized here.

[T]: ../src/tridentine_calendar_google_sync/production_write_token.py
[R]: ../src/tridentine_calendar_google_sync/production_write_token_operation_record.py
[IO]: ../src/tridentine_calendar_google_sync/production_write_token_io.py
[L]: ../src/tridentine_calendar_google_sync/_posix_private_lock.py
[D]: ../src/tridentine_calendar_google_sync/_posix_sensitive_directory.py
[Inspector]: ../src/tridentine_calendar_google_sync/production_write_token_pair_inspection.py
[Sequential design]: production-write-token-start-record-session-boundary-design.md
[Enrollment design]: production-write-token-enrollment-lock-design.md
[Reuse design]: production-write-token-reuse-policy-model.md
[Composition]: ../tests/test_token_start_record_session_boundary_phase6d1h.py
[Record tests]: ../tests/test_token_operation_record_phase6d1h.py
[Lock tests]: ../tests/test_posix_private_lock_phase6d1h.py
[Directory tests]: ../tests/test_posix_sensitive_directory_phase6d1h.py
[Bundle tests]: ../tests/test_token_bundle_lock_phase6d1h.py
[Session tests]: ../tests/test_credential_session_lock_phase6d1h.py
[Persistence tests]: ../tests/test_refresh_persistence_failure_phase6d1h.py
[Prewrite tests]: ../tests/test_refresh_prewrite_recheck_phase6d1h.py
[Reentry tests]: ../tests/test_token_session_failure_reentry_phase6d1h.py

## 8. Session-local owned-body implementation and validation evidence

### 8.1 Implemented scope and issuance

LOCAL_IMPLEMENTATION at the unchanged HEAD records a preparatory refactor in
production_write_token.py, four narrowly retargeted structural tests, and the new
test_token_session_owned_body_phase6d1h.py. The original 19,366-byte design prefix,
including its status, sections 1-7 and references, is unchanged.

Outcome: IMPLEMENTED_VALIDATION_INCOMPLETE. The available Windows memory/static
checks pass. Native Linux ownership and complete real-I/O regressions were not
run here. No START adapter, record child issuer, shared finalizer, runtime history
gate, public permission, retirement or recovery path was added.

The existing loader calls _credential_session_scope with its original eight
inputs. This private factory performs the original delayed I/O imports, UTC check
and path-set preflight once, in their original order. Only after successful
preflight does it allocate the reciprocal _CredentialSessionRequest and
_CredentialSessionScopeContext. Ordinary constructors refuse construction. An
unexamined request cannot be handed to a public or private context constructor as
a substitute for preflight.

The request retains the exact eight input references, including the same mutable
refresher. Request retention introduces no additional deepcopy, path resolution
or input normalization and confers no new target approval; existing preflight
remains unchanged. The factory retains the original delayed reader/writer/render/error
aliases, including their lookup before preflight and context entry. TYPE_CHECKING
provides only the I/O error annotation; no runtime top-level I/O import was added.

The context calls the unchanged _production_write_session_lock itself. It captures
the yielded checkpoint internally and issues _CredentialSessionOwner only after
entry succeeds. Constructor, factory and held entry accept no external checkpoint,
descriptor or borrowed lock. Reciprocal factory/context/request/owner identity,
the eight-reference snapshot, creator PID, original live Thread object, lifecycle
and active resources are checked. Type or equal input values alone are insufficient.

The loader invokes _load_production_write_credential_session_held inside this
context. _require_session_owner precedes the first content read. Accepted work
sets its used/busy latches before credential effects; finally consumes the owner
even after a caught body failure. An in-progress checkpoint rechecks ownership and
then delegates exactly once to the retained checkpoint. Nested or repeated held
entry is refused before further effects. The local checkpoint closure is created
before the busy interval, which is protected by try/finally.

Copy/deepcopy/serialization and reinitialization are refused. Entry failure is
terminal, including unexpected initial identity-check errors on a genuine fresh
context. Fixed foreign/nested misuse refusals do not revoke an active legitimate
owner. Acquisition/entry failure does not double-unwind the underlying context.
Failure after successful inner entry but during owner issuance unwinds that
acquired context once. Accepted exit uses _check_exit_actor and
_exit_owned_context to verify the actor, revoke ownership, detach resources and
delegate the original exception triple once. Internally retained standard-library
PID/thread probes establish cleanup origin if the ordinary identity check raises
unexpectedly; they are not caller-supplied checkpoints. Fixed foreign refusals
leave the valid owner unchanged. An unconfirmed actor is never assumed entitled
to release another owner. A verified local failing exit becomes terminal. If the
backend returns, the original local check exception propagates; if backend exit
raises, ordinary Python exception precedence remains in force.

These are invocation/lifecycle controls among cooperating Python participants,
not isolation from hostile mutation within the same process. The retained request
does not certify target/confirmation beyond the existing public wrapper checks,
and this standalone owner contains no START operation.

### 8.2 Compatibility evidence

| Original responsibility | Implemented boundary and preserved behavior |
| --- | --- |
| Target and exact confirmation | Both public prepare definitions remain byte-identical. |
| UTC/path preflight | Original import/check statements are AST-identical in the factory; one invocation before acquisition. |
| Acquisition and exit | Existing lock helper remains byte-identical. The new context owns its entry/exit and preserves exception delegation. |
| Initial state/token reads and verification | Original credential-body AST is retained in the held body's protected interval. |
| Unexpired return | Existing checkpoint and real constructor remain inside ownership; delivery follows exit. |
| Refresh, reread/compare and save | Existing accounting, scope/evidence/identity/generation checks, original expected_token, one refresh/save, and explicit raise origins are retained. |
| Refreshed return | Existing final checkpoint and real constructor remain inside ownership. |
| Failure and cancellation | Existing ordinary handlers, publication evidence and cancellation propagation are retained; no stronger shared-finalizer arbitration is installed. |

Static byte comparison confirmed all 33 previous non-loader definitions,
including decorators, unchanged. This includes the lock helper, public exceptions,
both public prepare functions, authorization and validation functions. Existing
constants, module docstring and __all__ are unchanged; the private loader signature
is unchanged. The original credential statement sequence and preflight statement
sequence are AST-identical after their extraction.

Token I/O, bundle, pair inspector, record/backend modules and consumer sets remain
unchanged. The shared helper's Windows no-op and different-parent behavior are
preserved by keeping its definition intact. A normal exit still cannot attest
suppressed backend close failures. New private misuse errors are fixed,
input-free classifications; existing public errors are not replaced with them.

### 8.3 Four structural checks and negative controls

Only the four previously approved functions changed in their existing files.
Imports, fixtures, other definitions, parameterizations and markers outside those
function spans were compared byte for byte against HEAD and match.

| Existing structural test | Preserved assertions and retargeting |
| --- | --- |
| test_loader_lexically_holds_locks_over_reads_refresh_save_and_both_returns | Follows loader factory/context/held arguments, preflight before issuance, lock entry before owner issuance, owner check before content, both constructor/return paths and checkpoint closure; retains lock-helper forbidden-effect checks. |
| test_new_handler_has_no_retry_cleanup_or_new_mutation_capability | Finds the held persistence handler; keeps ordinary Exception, exact call set, no retry/cleanup and CLI hard-off assertions. |
| test_added_recheck_only_reads_renders_compares_and_raises | Keeps exact reread/render/encode/compare/error operations, targets and refusal condition; requires the reread comparison before the unique save. |
| test_refresh_passes_original_input_and_has_no_legacy_save_at_call_site | Keeps one save, expected_token bound to the first-read token, no legacy writer and the original I/O-module assertions. |

The same checks run against five AST-data mutations: owner bypass, content read
before ownership validation, substituted expected_token, missing state reread,
and cleanup added to the persistence handler. Each actual structural test first
accepts current source and then rejects its applicable mutation. Mutant runtime
programs are never executed. This is a bounded structural regression, not general
Python alias analysis.

The record no-consumer, direct-lock/publisher consumer, directory-foundation and
bundle guards were not edited. Their applicable executions pass.

### 8.4 Current measured memory-only behavior

The final new file collected and passed 106 cases with no failures, errors, skips or
deselections. Tests use the actual public APIs, loader, issued owner, held body,
pure validation and real constructor. The constructor spy delegates once.
Credential substitution uses the existing five seams; fake refresh enters through
the existing mock argument. Scoped tripwires prevent real credential/file,
network, browser and provider effects during scenarios and are restored afterward.

| Successful public path | Path checks | Fake lock entry / exit | State / token reads | Fake checkpoints | Refresh / save | Constructors / returned sessions |
| --- | ---: | --- | --- | ---: | --- | --- |
| Test evidence, unexpired | 1 | 1 / 1 | 1 / 1 | 2 | 0 / 0 | 1 / 1 |
| Test evidence, fake refresh | 1 | 1 / 1 | 2 / 2 | 5 | 1 / 1 | 1 / 1 |
| Synthetic provider evidence, unexpired | 1 | 1 / 1 | 1 / 1 | 2 | 0 / 0 | 1 / 1 |

These checkpoint counts belong to the fake session context. They are not a
measurement of the native helper's additional acquisition-time revalidation.
Provider mode retains refresher=None; expired provider input and cross-mode grant
evidence are refused.

Passing cases cover missing/forged/incomplete owners, foreign issuers, distinct
or unpreflighted requests, input-reference substitution, pre-entry/failed-entry/
exit-in-progress/post-exit misuse, joined foreign-thread attempts, simulated PID
changes, recursive and second held calls, cloning and reinitialization. PID
substitution is not a fork or restart test. Refused misuse produces no subsequent
credential effects and does not release another valid owner.

Failure cases retain preflight ordering, original reader/refresh errors, refresh
accounting/evidence/identity diagnoses, prewrite refusal, save publication evidence
True/False/None, final-checkpoint failure, exit failure and existing competing-exit
exception behavior. Major-stage BaseException cases preserve cancellation
identity. Simulated publication before a save error is counted as an effect,
not described as an effect-free first call. Normal body completion cannot expose
the constructed session before exit succeeds.

### 8.5 Executed selection, commands and limits

Environment: Windows/win32, Python 3.12.14. Import resolution points to this
repository's src. Existing installed metadata matches uv.lock for pytest 8.4.2,
pytest-socket 0.8.1, Ruff 0.16.4, mypy 1.20.2 and pydantic 2.13.4. No install,
frozen sync or environment rebuild occurred.

The final captured in-memory pytest.main invocation ran after the final code/test
meaning and formatting changes, with the new file first and existing checks
following in the same process:

    python -B -c <captured-in-memory-pytest-wrapper>
    pytest.main: -q -p no:cacheprovider --basetemp <new-dedicated-scratch>
    -m "not google_read and not google_test_write and not google_production_write"

Existing conftest, strict configuration and socket prohibition remained active.
The scratch leaf was new and absent before invocation; no prior basetemp was
reused or deleted. No private-artifact validation-root search occurred.

| Actual selection | Collected | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| New owned-body file | 106 | 106 | 0 | 0 | 0 | 0 |
| Existing memory reentry file | 3 | 3 | 0 | 0 | 0 | 0 |
| Existing START/session composition file | 13 | 3 | 0 | 0 | 10 | 0 |
| Existing operation-record file | 387 | 331 | 0 | 0 | 56 | 0 |
| Four changed structural nodes | 4 | 4 | 0 | 0 | 0 | 0 |
| Two safe session-lock nodes, all parameters | 5 | 5 | 0 | 0 | 0 | 0 |
| Four requested unchanged guards plus pair-inspector guard | 5 | 5 | 0 | 0 | 0 | 0 |
| Two additional public-contract nodes | 2 | 0 | 0 | 0 | 0 | 2 |
| Total | 525 | 457 | 0 | 0 | 66 | 2 |

Exit code: 0. The full files were tests/test_token_session_owned_body_phase6d1h.py,
tests/test_token_session_failure_reentry_phase6d1h.py,
tests/test_token_start_record_session_boundary_phase6d1h.py and
tests/test_token_operation_record_phase6d1h.py. The four changed nodes are listed
in section 8.3. Additional exact selected nodes were:

- tests/test_credential_session_lock_phase6d1h.py::test_invalid_lock_paths_rejected_before_acquisition
- tests/test_credential_session_lock_phase6d1h.py::test_mock_rehearsal_classifies_safe_lock_error_before_calendar_transport
- tests/test_posix_private_lock_phase6d1h.py::test_component_has_no_artifact_write_no_wait_loop_and_only_approved_consumers
- tests/test_posix_sensitive_directory_phase6d1h.py::test_directory_foundation_only_has_the_reviewed_backend_consumers
- tests/test_no_network_or_google_dependencies.py::test_source_package_has_no_eager_network_google_or_oauth_imports
- tests/test_token_bundle_lock_phase6d1h.py::test_only_bundle_wrapper_newly_acquires_shared_lock_and_never_cleans
- tests/test_token_pair_inspection_phase6d1h.py::test_inspector_has_no_cli_consumer_provider_session_or_mutation_calls
- tests/test_production_write_token_refresh_phase6d0.py::test_oauth_and_refresh_protocols_expose_no_calendar_or_mutation_methods
- tests/test_production_write_grant_provenance_phase6d1d.py::test_operational_entry_points_expose_no_arbitrary_authorizer_or_refresher

The last two nodes were deselected by existing module markers under the required
base condition; they did not pass or fail. The 66 skips are existing Linux-only
conditions in the two complete files, not newly added environment skips.

The complete credential-session-lock, refresh-persistence-failure,
refresh-prewrite-recheck, refresh-replace-integration and token-bundle-lock files
were not run; only the listed safe nodes ran. The complete pair-inspection,
production-write-token-refresh and grant-provenance files also remain unexecuted.
Their real-I/O runtime cases require suitable fixtures. No omitted file is counted
as a pytest skip. Linux native same/different-parent acquisition, contention,
partial unwind, real synthetic persistence, release and bundle/session exclusion
remain unverified for this change.

Final static commands all exited 0:

    python -B -m ruff check . --no-cache --output-format json
    python -B -m ruff format --check . --no-cache
    python -B -m mypy --strict --no-incremental --cache-dir=nul --no-pretty src/tridentine_calendar_google_sync/production_write_token.py
    python -B -m mypy --strict --no-incremental --cache-dir=nul --no-pretty src
    git --no-optional-locks -c safe.directory=<repository> diff --check

Final Ruff diagnostics: 0. Format check: 284 files already formatted. Strict mypy:
one selected module and all 124 source files succeeded. Only permitted definition/
function spans and the new test were formatted. No ignore, Any annotation,
assert removal, unsafe fix or consumer-set expansion was used.

Earlier Ruff checking reported 15 style diagnostics in the new test, exit 1;
these were corrected before the initial pytest run. That intermediate run passed
97 new cases and reported 516 collected / 448 passed / 66 skipped / 2 deselected,
with zero failures/errors and exit 0. Subsequent review identified the unexpected
exit-identity-check failure path; it was hardened and nine focused regressions
were added before the final run above. Those cases cover ACTIVE/USED local
ordinary/cancellation failures, original exception-triple forwarding, backend
exception precedence, and foreign thread/PID refusal without invalid release. Preparation helpers also
encountered a pre-write parse error, a pre-write formatting guard stop, a
post-save lint-classification assertion, and an AST-comparison selection error.
Readback established unchanged or complete known bytes; no partial write was
rolled back or blindly reapplied. These were helper diagnostics, not product-test
failures. The comparison helper was corrected to include the original preflight
expression statement. There were no product pytest collection errors or failures.

### 8.6 Preserved history and completion boundary

VALIDATION_ROOT_UNAVAILABLE remains a local constraint. Existing directories,
markers, ACLs, settings and guards were not changed to bypass it. The passing
same-process regressions demonstrate restoration for the executed patches, not
native ownership or the unexecuted I/O suites.

Run 38745599347 and the earlier local 545-pass record predate this implementation.
They are not evidence for the new owned-body contract. The historical 75 failures,
their unresolved individual causes, original-finding unavailability and sections
1-7 are preserved. No new CI or package build ran.

The source change remains session-local. The unlocked START/session interval
remains. Runtime history enforcement, normal-operation closure, record retirement
and recovery remain unimplemented. The future shared-finalizer failure
rules in section 5 were not adopted by this refactor.

The final review checks the seven-file scope, unchanged HEAD/index, byte-identical
protected definitions/test regions, unchanged 19,366-byte document prefix, UTF-8/
LF/no-BOM/final-newline formatting, relative links and full content privacy.
No commit, push, remote communication, PR update, CI operation, deployment,
OAuth, live refresh, Google API or Calendar operation was performed. DS-04 stays
PARTIAL; Historical Deep Security Scan INCOMPLETE; separate 47194b0 report FAIL;
Production gate BLOCKED; live handlers hard-off; registry empty/fail-closed.

## 9. Busy-transition interruption correction and validation evidence

### 9.1 Corrected boundary and inherited auxiliary evidence

LOCAL_CORRECTION: section 8's statement that the busy interval was protected was
too broad. The prior held function set _used=True and _busy=True before entering
its try suite. An exception at the following try-header line event could therefore
bypass the held finally. The outer context refused exit while busy, masking the
original exception with _CredentialSessionUseError and retaining the fake lock.

The supplied ChatGPT auxiliary check used Linux/Python 3.13.5, twelve unchanged
extracted definitions and simulated dependencies. It reported two pre-used
controls with cleanup and two after-busy failures without cleanup. It did not run
the complete repository or product pytest, native locks or OS signals. Those four
auxiliary cases are inherited evidence, not this task's Python 3.12 RED and not
additional product-test passes.

This task reproduced the boundary through the actual public API, loader, owner
and held function in the existing Windows/Python 3.12.14 environment, before
changing production source. No extracted or mutated runtime implementation was
executed to manufacture the failure.

### 9.2 Bounded injection and measured RED/GREEN

The new test-only _HeldTransitionInjection uses sys.settrace for the actual
_load_production_write_credential_session_held code object only. It reads the
issued scope from that matching frame and retains only the required scope/owner
references, fixed stage, line number, flags and injection count. Unrelated frame
locals are neither collected nor printed.

At the first matching line event, it verifies reciprocal ownership, ACTIVE phase,
one fake lock entry and zero content/refresh/save/construction/return/checkpoint
effects. The control selects used=False/busy=False; the fault case selects
used=True/busy=True. It raises one pre-created RuntimeError or synthetic
BaseException cancellation object exactly once. It changes no scope/request fields
or dependency references.

The test refuses an already-active trace instead of silently replacing coverage
or another tracer. It preserves and restores the prior trace in finally, asserts
restoration, and records fixed evidence before asserting the expected cleanup
contract. Terminal reuse checks occur only after tracing is off. These are line
trace exceptions, not OS signals, process termination or native-lock injections.

| Current product-path scenario | Pre-fix result | Post-fix result |
| --- | --- | --- |
| Before-used / ordinary exception | PASS: original identity, entry 1 / exit 1, CLOSED, not busy | PASS: same conditions |
| Before-used / cancellation | PASS: original identity, entry 1 / exit 1, CLOSED, not busy | PASS: same conditions |
| After-busy / ordinary exception | Intended RED: ownership refusal replaced original; entry 1 / exit 0, ACTIVE, busy and held | PASS: original identity, entry 1 / exit 1, CLOSED, not busy or held |
| After-busy / cancellation | Intended RED: ownership refusal replaced original; entry 1 / exit 0, ACTIVE, busy and held | PASS: original identity, entry 1 / exit 1, CLOSED, not busy or held |

All eight current observations had exactly one injection, zero credential reads,
refresh, save, constructors, session returns and checkpoints, and restored tracing.
The controls observed used=False; after-busy cases observed used=True. Post-fix
cases retained those values while closing the scope, and rejected subsequent held,
entry and exit reuse without further effects.

Observed source line events were 1130 for the control in both versions, 1138
(the unprotected try header) for pre-fix after-busy, and 1139 (the protected first
retained-input statement) post-fix. These are recorded observations, not hardcoded
injection targets; the test selects code identity and state rather than a fixed
line number.

Pre-fix pytest, restricted to the four new regression parameters, measured:
4 collected / 2 passed / 2 failed / 0 errors / 0 skipped / 0 deselected, exit 1.
The source retained its starting SHA-256 throughout that run. The two failures
were accepted as reproduction only after confirming the injection count,
classification, retained busy state and missing exit. Discarding their memory-only
fixtures is not evidence of product cleanup. No real lock or credential was used.

### 9.3 Minimal source correction and retained contracts

The correction moves only the two latch assignments into the existing protected
suite:

    try:
        scope._used = True
        scope._busy = True
        # Existing retained-input and credential processing, unchanged.
    finally:
        scope._busy = False
        scope._phase = _CredentialSessionPhase.USED

Owner/request checks, misuse refusal and checkpoint-closure preparation still
precede this suite. The credential-body and finally ASTs are unchanged. The source
outside the held function is byte-identical to this task's start, including the
entire owner/context implementation, exit actor checks, busy-exit refusal, factory,
issuance/validation, lock helper, public functions, imports and __all__.

No busy refusal was removed, no used latch is reset, and no external force-release,
retry, new exception priority, finally-return or manual cause/context/notes change
was introduced. Native checkpoint positions/counts, refresh/save bounds and
expected_token remain unchanged.

The four existing structural-test files retain their complete starting bytes.
The new test file adds only sys/FrameType imports, the bounded trace helper and
four parameterized cases. All 44 pre-existing top-level definitions, including the
106 existing cases, retain their bytes and meaning.

### 9.4 Final validation and historical separation

Final outcome: OWNED_BODY_TRANSITION_FIXED_VALIDATION_INCOMPLETE.

The final GREEN used a new dedicated pytest scratch distinct from the RED scratch.
The new test file ran first, followed by the same explicit full-file/node selection
listed in section 8.5, in one pytest process. No selection or marker was relaxed:

    python -B -c <captured-in-memory-pytest-wrapper>
    pytest.main: -q -p no:cacheprovider --basetemp <new-dedicated-scratch>
    -m "not google_read and not google_test_write and not google_production_write"

| Final measured selection | Collected | Passed | Failed | Errors | Skipped | Deselected |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Owned-body file, including the four new cases | 110 | 110 | 0 | 0 | 0 | 0 |
| Existing memory reentry file | 3 | 3 | 0 | 0 | 0 | 0 |
| Existing START/session composition file | 13 | 3 | 0 | 0 | 10 | 0 |
| Existing operation-record file | 387 | 331 | 0 | 0 | 56 | 0 |
| Four unchanged structural nodes | 4 | 4 | 0 | 0 | 0 | 0 |
| Two safe session-lock nodes, all parameters | 5 | 5 | 0 | 0 | 0 | 0 |
| Four requested unchanged guards plus pair-inspector guard | 5 | 5 | 0 | 0 | 0 | 0 |
| Two additional public-contract nodes | 2 | 0 | 0 | 0 | 0 | 2 |
| Total | 529 | 461 | 0 | 0 | 66 | 2 |

Exit code: 0. The four new parameters all passed inside that final run. Counts
were measured from reports, not calculated by adding cases to old totals.
The existing 106 cases and all four fixed structural tests passed. Global trace
state at process end matched its initial state; later regressions and guards
passed after the trace and local monkeypatch contexts were restored.

Positive public controls still measured fake checkpoints 2 for unexpired test
evidence, 2 for synthetic provider evidence and 5 for fake refresh. They returned
real session objects after one fake lock entry/exit. The refreshed path retained
two state/token reads each and one refresh/save; the other paths had one read
each and no refresh/save. Native acquisition checkpoints were not measured.

Environment was Windows/win32, Python 3.12.14. Source resolution matched this src;
installed pytest 8.4.2, pytest-socket 0.8.1, Ruff 0.16.4, mypy 1.20.2 and pydantic
2.13.4 metadata matched uv.lock. No installation or environment reconstruction
occurred. Existing conftest, strict settings and socket prohibition stayed active.

Final static commands:

    python -B -m ruff check . --no-cache --output-format json
    python -B -m ruff format --check . --no-cache
    python -B -m mypy --strict --no-incremental --cache-dir=nul --no-pretty src/tridentine_calendar_google_sync/production_write_token.py
    python -B -m mypy --strict --no-incremental --cache-dir=nul --no-pretty src
    git --no-optional-locks -c safe.directory=<repository> diff --check

All exited 0: Ruff had zero diagnostics; format check reported 284 formatted files;
strict mypy passed the selected module and all 124 source files. Formatting was
limited to the changed held definition and added test definitions. One editing
orchestration call yielded no recognized completion record; immediate raw
readback showed A/G unchanged and F equal to the already-saved regression.
A smaller checked source-save operation then completed with exact readback.
This helper-channel event is separate from the product RED/GREEN evidence.

VALIDATION_ROOT_UNAVAILABLE remains unchanged; there was no native-root search.
The same eight real-I/O file groups remain unexecuted as complete suites:
credential-session-lock, persistence-failure, prewrite-recheck,
refresh-replace-integration, token-bundle-lock, pair-inspection,
production-write-token-refresh and grant-provenance. Only the section 8.5 selected
safe nodes ran; its last two nodes were again deselected. Omitted suites are not
included in the 66 OS skips. Linux native and new-commit CI evidence remain absent.
No package build or CI operation ran.

Section 8's 106-pass and 525-collected result remains its historical result.
Run 38745599347, the older local 545 passes, the earlier 75 failures and the
inherited Python 3.13.5 auxiliary experiment are not substituted for this run.

### 9.5 Preservation and limits

The full starting 36,846 bytes remain an exact prefix, including the original
19,366-byte design and section 8's earlier claims and results. Only A, F and this
appendix changed during this task; B-E, HEAD, tree, branch, staged count zero,
index and consumer sets remain unchanged. Current tracked changes remain the
pre-existing source plus four tests, with only the owned-body test and design
untracked. Full diffs and raw-content checks cover those untracked files too.

This fixes the demonstrated one-shot transition boundary. It is not a guarantee
against repeated interruption at arbitrary instructions, interruption throughout
cleanup, hostile debuggers, real fork/restart, power loss or complete native lock
release. START sharing, continuous record/session ownership, all-caller history
enforcement, normal closure, record clearance and recovery remain unconnected.

No commit, push, remote communication, PR update, operational integration, OAuth,
live refresh, Google API or Calendar operation occurred. DS-04 remains PARTIAL;
Historical Deep Security Scan INCOMPLETE; separate 47194b0 report FAIL; Production
gate BLOCKED; handlers hard-off; packaged registry empty/fail-closed.
