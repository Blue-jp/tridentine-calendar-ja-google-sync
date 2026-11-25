# START-Linked Session Ownership and Finalization Contract

Status: DRAFT_INTERFACE_CONTRACT_NOT_IMPLEMENTED_NOT_OPERATIONAL_APPROVAL

Date: 2026-11-03 JST. Fixed HEAD:
`e3c5f32295b594b7ed3692fc54060915ad22472d`; tree:
`59027d3871396eaf2a06c3602fda648c6ee6ea90`; sole parent:
`99ff2cefea7314ff20681e2bcf19f1bb6de72ffa`.
Branch: `security/deep-scan-remediation-47194b0`.

## 1. Evidence and present barriers

CURRENT_SOURCE means static inspection at that HEAD; CURRENT_TEST means a
definition, not a new execution. INHERITED_EVIDENCE is history.
PROPOSED_INTERFACE and PROPOSED_ACCEPTANCE below describe unimplemented work.

[T] denotes [production_write_token.py](../src/tridentine_calendar_google_sync/production_write_token.py);
[R] denotes [production_write_token_operation_record.py](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py).

| CURRENT_SOURCE barrier | Reference |
|---|---|
| Request/context are reciprocal, retaining eight input identities. | [T:797–890](../src/tridentine_calendar_google_sync/production_write_token.py#L797) |
| Exact owner/context/request checks cannot accept a record scope. | [T:1007–1041](../src/tridentine_calendar_google_sync/production_write_token.py#L1007) |
| Session entry acquires its own lock; nesting it inside record ownership reacquires. | [T:892–938](../src/tridentine_calendar_google_sync/production_write_token.py#L892) |
| Record ownership lacks START-success, request-binding, and session-use latches. | [R:331–350, 519–544](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py#L331) |
| Legacy record exit can classify a session exception as record PERSISTENCE_UNCERTAIN. | [R:481–492, 237–245](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py#L481) |
| Public START_CONFIRMED/START_OBSERVED occur after owner exit. | [R:653–687](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py#L653) |

The preparation split proposed in
[shared-ownership design](production-write-token-shared-ownership-session-design.md)
§6 is already implemented (§8.1); its §3–5 shared-child/finalizer proposal is not.
[Record busy review](production-write-token-record-busy-transition-review.md)
documents the protected latch.
[Sequential boundary design](production-write-token-start-record-session-boundary-design.md)
and [enforcement gap review](production-write-token-enforcement-gap-review.md)
remain historical context.

CURRENT_TEST: the boundary test deliberately has an unlocked gap
([definition](../tests/test_token_start_record_session_boundary_phase6d1h.py#L245)).
Standalone session cleanup precedence is separately fixed by
[this test](../tests/test_token_session_owned_body_phase6d1h.py#L534);
the new arbitration below must not change it.

## 2. Chosen bounded connection

PROPOSED_INTERFACE: record owns acquisition; a dedicated child serves only a
closed, test-invoked Linux mock path. No general ownership module. START directory and both credential parents must equal
one explicitly supplied directory; token/state/START leaves must be distinct,
and token/state leaves must match the binding slots.

Use independently supplied, valid REFRESH operation/predecessor references.
Never learn expectations from the stored record or derive operation IDs from
generation. REFRESH is a label: unexpired credentials perform zero refresh/save;
expired fixtures retain the existing maximum of one fake refresh/save.

Reject different parents, NEW_PAIR, enrollment, and real deployment.
The existing public session APIs retain their different-parent/provider behavior.
Path-set preflight still receives production-read/test-write exclusion inputs;
these do not become additional credential readers.

Layout rejects lexical mismatch, not physical aliasing. Path/identity/private-directory
checks and fixture provisioning supply bounded association only: no trusted
enrollment, rollback/history completeness, or nonparticipating-writer protection.

## 3. Responsibilities and exact interfaces

All new names in this section and subsequent new-symbol references are
**PROPOSED_INTERFACE**, not existing functions. Public APIs and `__all__` stay
unchanged. Dependency direction is T → R only.

The sole new entry has this signature:

```text
PROPOSED T._prepare_start_linked_session_mock(
    production_write_token_path: str|Path, generation_state_path: str|Path,
    production_read_token_path: str|Path, test_write_token_path: str|Path,
    target: ProductionWriteTargetConfig, confirmation: str, *,
    now: datetime, refresher: ProductionWriteTokenRefresher,
    binding: R.SyntheticBinding, operation: R.RecordOperation
) -> ProductionWriteCredentialSession
```

PROPOSED T._start_linked_session_context takes those same named parameters and
returns a fresh `_StartLinkedSessionContext`. It performs target and exact
confirmation checks, rejects non-Linux before filesystem preflight, then performs
UTC/full path-set validation with `client_config_path=None`, existing-pair settings.
The returned write/state Paths become context.checked_token_path/checked_state_path
for layout, separate from retained input identities. It checks the explicit fake
refresher's mock-only/no-live/no-browser contract; evidence_mode is fixed to `"test"`.

### 3.1 Independent expectations and one sealed parent

A fresh request/context retains reciprocal factory provenance, actor, and the
legacy eight input identities plus confirmation/binding/operation. T separately
constructs immutable R._LinkedExpected from independent inputs:

| Expected fields | Origin retained by T |
|---|---|
| directory, storage_ref, pair_ref, token_slot, state_slot | Supplied binding snapshot |
| operation_id, predecessor_id, kind | Supplied operation snapshot |
| checked_token_path, checked_state_path | First two path-set validator returns, preserving role order |

T copies these fields as immutable values; R retains its own creation snapshot.
No expectation is learned from the parent/child being checked. These metadata
values are not authority. Before returning any usable context, T's factory
creates a fresh R parent, validates its NEW state/provenance/Q/metadata/layout,
enforces valid binding, REFRESH/predecessor and same-directory/slot layout,
obtains that parent's attempt state, and seals a private
T._LinkedParentAssociation containing request Q, that exact parent instance,
the independent expectations, and attempt-state identity. Request/context
reference that one association. T._seal_start_linked_parent is factory-only
and refuses every second binding, including rebinding to the same parent.
No unbound context escapes and the coordinator cannot supply a replacement parent.

```text
PROPOSED factory continuation after real preflight:
expected = R._LinkedExpected(binding_snapshot, operation_snapshot,
                             checked_token_path, checked_state_path)
request, context = fresh_linked_request_context(input_identities)
parent = R._shared_start_session_scope(binding_snapshot, operation_snapshot, request,
                                      token_path=checked_token_path,
                                      state_path=checked_state_path)
R._verify_linked_parent_binding(parent, request, expected=expected)
state = R._linked_attempt_state(parent, request,
                               expected_parent=parent, expected=expected)
T._seal_start_linked_parent(context, request, parent, expected, state)
return context
```

`fresh_linked_request_context` denotes inline factory construction, not an
additional API. Parent, attempt state and fallback diagnostic storage are
allocated before entry. A factory failure exposes no usable context and acquires
no lock. Legacy contexts are never repurposed through attribute replacement.

### 3.2 Binding-aware private interfaces

In this PROPOSED signature table, P is exact R._SharedStartSessionContext,
C is exact R._LinkedSessionChild, X is R._LinkedExpected, and S is
R._LinkedAttemptState. B abbreviates the **explicit keyword-only parameters**
`expected_parent: object, expected: X`. Implementation expands those names;
B is not arbitrary kwargs, a Boolean permit, callback, or selectable phase policy.

| PROPOSED symbol | Arguments → return |
|---|---|
| R._shared_start_session_scope | (binding: SyntheticBinding, operation: RecordOperation, request_key: object, *, token_path: Path, state_path: Path) → P |
| R._verify_linked_parent_binding | (parent: object, request_key: object, *, expected: X) → None; NEW-only |
| R._linked_attempt_state | (parent: object, request_key: object, *, B) → S; NEW-only factory access |
| T._seal_start_linked_parent | (context: _StartLinkedSessionContext, request: _StartLinkedSessionRequest, parent: P, expected: X, state: S) → None |
| T._bound_linked_parent | (context: object) → P; verifies sealed association before entry |
| R._create_linked_start | (parent: P, request_key: object, *, B) → None |
| R._linked_session_phase | (parent: P, request_key: object, *, B) → AbstractContextManager[C] |
| R._issue_linked_child | (parent: P, request_key: object, *, B) → C |
| R._require_linked_child | (child: object, request_key: object, *, B) → None |
| R._checkpoint_linked_child | (child: C, request_key: object, *, B) → None |
| R._note_linked_candidate | (parent: P, request_key: object, *, B) → None |
| R._final_linked_checkpoint | (parent: P, request_key: object, *, B) → None |
| R._copy_linked_failure_annotations | (parent: P, request_key: object, *, B, classification: _SessionFailureClass\|None = None) → None |
| R._copy_linked_publication_annotations | (parent: P, request_key: object, *, B) → None |
| R._build_linked_diagnostics | (facts: _LinkedCoreFacts, notes: _LinkedAnnotations) → _LinkedDiagnosticsSnapshot |
| R._finalize_linked_scope | (parent: P, exc_type: type[BaseException]\|None, exc: BaseException\|None, traceback: TracebackType\|None) → Literal[False] |
| R._read_linked_diagnostics | (parent: object, request_key: object, *, B) → _LinkedDiagnosticsSnapshot |
| T._issue_start_linked_session_owner | (context: _StartLinkedSessionContext, child: C) → _StartLinkedSessionOwner |
| T._require_start_linked_session_owner | (owner: object, request: object) → _StartLinkedSessionContext |
| T._classify_linked_session_failure | (error: Exception) → R._SessionFailureClass |

T always supplies B from its sealed association. Parent-level operations with B
require `parent is expected_parent`, exact provenance, Q identity, attempt-state
ownership, PID, original live thread identity, and every independent
binding/operation/path field. NEW
validation requires no issued child. Issuance checks START_READY and no current
child before mutating a latch. Child admission additionally requires
`child.parent is expected_parent` and `expected_parent.current_child is child`.
Checked parents equal expected directory; each checked filename matches its
ordered slot. T additionally verifies its own factory,
request/context/association reciprocals and input snapshots. Q alone never
certifies T preflight.

Checks run before owner issuance, first held admission and each existing
checkpoint. They are memory checks, not extra native checkpoints.
R._checkpoint_linked_child checks first, then revalidates the directory handle
at an existing checkpoint position. Active admission requires SESSION_RUNNING;
final checking uses CONSUMED with retained issued-child identity; diagnostic
reading uses CLOSED/sealed facts. No child is reactivated for inspection.

Same-Q foreign-directory children fail parent identity/layout; equal metadata
on another parent fails identity; other operations/predecessors/kinds and
storage/pair/slot swaps fail independent field comparison. Consumed/closed
children fail lifecycle. Rebinding fails the factory-only single seal.
All comparisons precede owner/use-latch mutation. A rejected direct call neither
consumes nor releases a legitimate owner; uncaught escape through the genuine
coordinator's scope may separately trigger that owner's normal abort cleanup.

Refuse manual construction, copying/deepcopy/pickling and partially fabricated
objects. No arbitrary Protocol, caller checkpoint, raw descriptor, borrowed lock,
or already_locked/preflight_ok Boolean establishes admission.
Physical aliasing, same-authority replacement and hostile in-process mutation
remain outside these interface-mixup checks.

T._require_session_owner adds an exact linked branch returning the two concrete
context types' union; its legacy branch stays intact. The existing held body,
handlers, checkpoints, two candidate constructions and `expected_token=token`
remain unchanged. Neither child nor linked T context owns acquisition/release.
PROPOSED `_revalidate(owner, request) -> None` uses sealed B; ordinary checkpoint
failure retains the session lock-error mapping, cancellation its identity.
PROPOSED `_persist_linked(token, path, *, expected_token) -> Path` delegates once
to the captured writer under section 5; it does not duplicate credential processing.

## 4. START provenance, ownership, and delivery

The R shared context privately owns a real _RecordScopeContext and its single
existing directory-lock acquisition. A factory-created reciprocal link
distinguishes it from legacy `link=None`; caller Booleans cannot select the mode.

Only the actual _held_record_io create path, after successful publication,
readback/matching, and its final held checkpoint, records an internal START
latch on that same owner/link. _create_linked_start accepts no result argument.
Issuance additionally requires successful return, unchanged binding/operation,
no failure/cancellation, and cleared record busy state. Forged _HeldResult,
equal values, successful read alone, occupied slots, or absence cannot issue a
child. Occupation refuses even identical bytes/operation.

HELD_START_CHECKPOINT is the retained internal observation.
START_CONFIRMED and START_OBSERVED remain legacy post-exit public observations.
None supplies credential-use authority.

| PROPOSED shared state | Allowed transition; refused work |
|---|---|
| NEW | Entry once; no I/O/child use. |
| ENTERING | Acquire/enter; failure terminal; reject reentry. |
| RECORD_HELD | Actual create once; no session before its proof. |
| START_READY | Accept one session phase; no independent read/recreate. |
| SESSION_RUNNING | Exact child checkpoints and held session only; reject record operations/reentry. |
| CONSUMED | Final checkpoint or unwind only; no second session after caught failure. |
| FAILED | Authorized finalization only; no further work. |
| EXITING | Revoke/detach, delegate exit once; all entry/use refused. |
| CLOSED | Fixed diagnostic snapshot only; no parent/child reuse. |

Phase entry consumes the single session allowance inside its protected
try/finally. It revokes child use and records CONSUMED/FAILED even if an exception
is caught later. All new busy/phase mutations have established cleanup protection;
this is not an all-instruction interruption proof. Wrong actor/reentrant refusal
happens before detaching resources and never releases a genuine other owner.
Standalone record create→held-read remains valid.

The shared controller alone uses the real held START primitive. The coordinator
uses the factory-sealed parent, never constructs a second one. Here a is that
association; B expands to its expected_parent/expected keyword pair.

```text
PROPOSED flow; minimal capture is inline, not a retention-helper call:
context = T._start_linked_session_context(all_entry_arguments)
a = context.sealed_association
parent = T._bound_linked_parent(context)
q, s = a.request, a.attempt_state
candidate = None
try:
    with parent:
        R._create_linked_start(parent, q, **B)
        with R._linked_session_phase(parent, q, **B) as child:
            owner = T._issue_start_linked_session_owner(context, child)
            try:
                candidate = T._load_production_write_credential_session_held(owner, q)
            except BaseException as E:
                body_triple = (type(E), E, E.__traceback__)
                s.session_body_triple = body_triple
                if isinstance(E, Exception):
                    if s.primary is None:
                        s.primary = E
                        s.facts.first_ordinary_domain = SESSION
                        s.facts.session_failure = SESSION_OTHER
                elif s.first_cancel is None:
                    s.first_cancel = E
                    s.facts.first_cancel_phase = SESSION
                try:
                    R._copy_linked_failure_annotations(parent, q, **B)
                    if isinstance(E, Exception) and s.primary is E:
                        kind = T._classify_linked_session_failure(E)
                        s.facts.session_failure = kind
                        R._copy_linked_failure_annotations(parent, q, **B,
                                                          classification=kind)
                except Exception:
                    s.facts.diagnostic_status = INCOMPLETE
                except BaseException as C:
                    s.facts.diagnostic_status = INCOMPLETE
                    if s.first_cancel is None:
                        s.first_cancel = C
                        s.facts.first_cancel_phase = ANNOTATION
                if s.first_cancel is not None: raise s.first_cancel
                raise
            s.facts.candidate_constructed = True
            R._note_linked_candidate(parent, q, **B)
        R._final_linked_checkpoint(parent, q, **B)
except BaseException:
    candidate = None
    raise
return candidate
```

The held call is CURRENT_SOURCE; orchestration is PROPOSED. Child revocation
invalidates T admission too; no separate post-finalizer retirement can override
the selected failure.

Existing session checkpoints use that held directory handle.
One linked-only final checkpoint checks CONSUMED parent, retained issued-child
identity, request/operation and candidate latches, then revalidates that handle.
It does not reuse active-child admission. PROPOSED R._LinkedCheckpointFailure is the fixed ordinary final-check refusal.
No extra START/credential read or legacy checkpoint change. Candidate construction is not delivery: retain it
only locally, discard on failure, and return only after final check and normal
exit. No callback, global, diagnostic, or exception payload receives it.
Lock ownership does not continue after return; START stays started/incomplete.

## 5. Primary protection, writer boundary, and finalization

### 5.1 Minimal retention and fallible diagnostic projection

R._LinkedAttemptState is allocated before entry and bound to the unique
parent/Q/association. Private plain slots hold primary, first cancellation,
separate session-body, phase-exit and record-exit triples, and writer-origin references. R._LinkedCoreFacts
holds only fixed scalar facts. T already holds this state when work begins;
R phase exit/finalizer read it directly, independently of failed diagnostic
transfer. Raw reference slots start empty. On diagnostic failure, plain slots
retain the first failed step (initial copy, classification, refinement,
pre-/post-writer note or snapshot) and ordinary/cancellation kind, as well
as INCOMPLETE. The section 4 catch retains E locally and writes its reference before the
first additional note. No traversal of __context__ is used.

The bounded fault model covers ordinary failure/cancellation at initial note,
classifier, refinement, publication-note and snapshot-builder call boundaries.
Minimal local capture, preallocated plain-slot writes, fixed-schema field reads
and fixed scalar updates are the protected bookkeeping, not an allegedly
infallible retention helper. Memory exhaustion, arbitrary repeated
instruction-level interruption, forced termination, damaged interpreters and
hostile slot/exception-property replacement are outside this guarantee.

If the first note fails before copying anything, E still reaches phase exit:
ordinary D marks INCOMPLETE and the outer catch's bare raise forwards E.
Diagnostic cancellation fills first_cancel only if empty and propagates that
object. Known exact session types refine to PERSISTENCE/PREWRITE/LOCK/REFRESH;
otherwise SESSION_OTHER remains. No message, arbitrary error code or reflected
type name is recorded. The two copy helpers, classifier and snapshot builder cannot replace primary,
first_cancel, ownership latches or observed publication facts. Only completed
fixed projections enter R._LinkedAnnotations; stale/missing detail is NOT_REPORTED
and cannot override current core facts. A successful detailed build never
clears an earlier INCOMPLETE status. A successfully classified fixed kind is
retained before refinement transfer.

R phase exit/finalizer perform the same minimal capture before their own
diagnostic calls. If an ordinary diagnostic D follows a healthy body and no
eligible primary exists, capture D in the primary slot before marking INCOMPLETE;
do not let a later ordinary cleanup error take its place. Core finally paths
consume the phase, revoke children, clear
busy state and detach owned resources even if annotations fail. Optional
diagnostics cannot strand SESSION_RUNNING or prevent the one legitimate exit.

### 5.2 Preserve W to the existing handler, then preserve P

CURRENT_SOURCE [save handler](../src/tridentine_calendar_google_sync/production_write_token.py#L1237)
takes an ordinary writer exception W and creates
ProductionWriteTokenRefreshPersistenceError P with its publication evidence.
The adapter preserves W by identity **to that handler**. Shared ordinary-primary
retention starts with the actual P emitted by the unchanged held body.
W, adapter-local diagnostic D, and an adapter error carrier belong to
writer-origin evidence, not s.primary. Cancellation bypasses this ordinary
conversion; do not claim that P was generated when it was not.

In the following PROPOSED pseudocode, IOE(v) abbreviates construction of the
existing ProductionWriteTokenIOError with fixed non-secret code/message and
publication_possible=v. It is not a new public API. note_publication abbreviates
the fixed R._copy_linked_publication_annotations(parent, q, **B) call, not a caller
callback. Each first-cancel assignment also retains its fixed boundary tag.

```text
PROPOSED _persist_linked(token, path, *, expected_token):
    s.facts.logical_save_called = True
    s.facts.writer_phase, s.facts.credential_publication = NOT_CALLED, False
    try:
        note_publication
    except Exception as D:
        s.writer_diagnostic = D
        s.facts.diagnostic_status = INCOMPLETE
        raise IOE(False)                 # unchanged held handler creates P(False)
    except BaseException as C:
        s.facts.diagnostic_status = INCOMPLETE
        if s.first_cancel is None: s.first_cancel = C
        raise s.first_cancel

    s.facts.writer_phase, s.facts.credential_publication = CALL_STARTED, None
    try:
        result = captured_writer(token, path, expected_token=expected_token)
    except BaseException as W:
        s.writer_error = W               # never s.primary
        s.facts.writer_failure_kind = ORDINARY if isinstance(W, Exception) else CANCELLATION
        s.facts.writer_phase = RAISED
        if isinstance(W, captured_IOError):
            s.facts.credential_publication = W.publication_possible
        if not isinstance(W, Exception) and s.first_cancel is None:
            s.first_cancel = W
        try:
            note_publication
        except Exception as D:
            s.writer_diagnostic = D
            s.facts.diagnostic_status = INCOMPLETE
        except BaseException as C:
            s.facts.diagnostic_status = INCOMPLETE
            if s.first_cancel is None: s.first_cancel = C
        if s.first_cancel is not None: raise s.first_cancel
        raise                            # same W; existing handler then creates P
    else:
        s.facts.writer_phase, s.facts.credential_publication = RETURNED, True
        try:
            note_publication
        except Exception as D:
            s.writer_diagnostic = D
            s.facts.diagnostic_status = INCOMPLETE
            raise IOE(True)              # no second save; existing handler creates P(True)
        except BaseException as C:
            s.facts.diagnostic_status = INCOMPLETE
            if s.first_cancel is None: s.first_cancel = C
            raise s.first_cancel
        return result
```

Known IOError evidence is read from its declared plain bool/None field; other W
leaves None. Pre-call preparation failure means underlying writer NOT_CALLED/0,
not uncertain execution. CALL_STARTED/None denotes a call attempt with publication
unresolved. RETURNED/True precedes post-return annotation and cannot be replaced
by False if annotation fails. False concerns this call, not provider inactivity.
Recording failure never means no effect or success.

P's existing `persistence_attempted=True`
([definition](../src/tridentine_calendar_google_sync/production_write_token.py#L87))
remains unchanged, even for pre-writer diagnosis failure: the logical adapter
call occurred, while the underlying writer did not. Ordinary IOE carriers are
converted by the existing handler; D is not incorrectly promised as the outward
session exception. Arguments, expected_token, single writer call and existing
handler stay intact. No additional refresh/save occurs.

### 5.3 One release and protected snapshot construction

R._finalize_linked_scope first authenticates actor/lifecycle. It captures the
actual triple entering the record context's __exit__, before helpers, and
retains any incoming eligible primary/cancellation not already captured.
This original exit triple is delegated once to the backend. It is distinct
from T's earlier session triple and from a cancellation selected after cleanup;
never reconstruct it from __context__ or substitute the final selection into it.

Core protected cleanup revokes the child, detaches the inner stack, marks EXITING,
delegates once, retains observed cleanup failure and marks CLOSED in finally.
Linked inner legacy __exit__ remains refused. An inner-entry failure does not
repeat its own unwind; failure after successful inner entry unwinds that entered
stack once through this finalizer. Wrong-actor refusal precedes detachment.

The first cancellation wins; without cancellation, the first eligible ordinary
primary wins. Writer-origin W/D are not session primaries; P is. Later ordinary
diagnostic/cleanup failure cannot replace P. A first cleanup/diagnostic
cancellation outranks P while its fixed ordinary diagnosis/publication remains.
With no earlier failure, an ordinary phase/final-check/exit/snapshot error becomes
primary. Candidate delivery requires all finalization conditions, not just a
normal held-body return.

Record refusals keep their existing fixed classification (_ScopeFailure); no
unavailable underlying exception identity is invented. Session ordinary identity
means the object emitted by the existing held body.

| PROPOSED event | Primary/outcome; independent evidence |
|---|---|
| Acquisition/entry failure | Terminal; unwind only entered resources; no session reads. |
| Occupied/create refusal/readback uncertainty | Record classification; no child/read/refresh; retain record publication. |
| Session read/validation failure | Same session exception; no subsequent refresh/save. |
| Fake refresh/prewrite recheck failure | Existing session exception; no further refresh/save. |
| Credential save failure | Existing persistence exception and publication_possible; record publication separate. |
| Candidate then final-check failure | Withhold candidate, retain prior publication facts. |
| Normal body then exit failure | Exit failure primary; candidate withheld. |
| Ordinary primary then ordinary cleanup | Preserve primary; fixed secondary cleanup observation. |
| Earlier cancellation then cleanup failure/cancellation | Preserve first cancellation object. |
| Ordinary primary then cleanup cancellation | Cleanup cancellation wins; retain ordinary diagnosis separately. |

After the release attempt, make a provisional selection and set scalar
selected_outcome/delivery accordingly. R._build_linked_diagnostics consumes
only fixed scalar facts and completed fixed projections, inside the finalizer's
guard. Ordinary build failure preserves an existing primary/cancellation;
otherwise that D becomes primary. Build cancellation follows first-cancel
precedence. Mark INCOMPLETE and reselect. Write the final selected_outcome and
WITHHELD into scalar facts **before** sealing the fallback; never release or
save again.

Factory-preallocated fallback storage receives retained scalar facts through core
slot copying and is sealed as an immutable INCOMPLETE snapshot. It contains no
parent, attempt-state, exception or traceback references. This copying uses the
stated primitive-bookkeeping model; it is not a claim that builders cannot fail.
Before fallback sealing, an incomplete/missing diagnostic with no captured
exception selects the factory-preallocated fixed _LinkedDiagnosticIncompleteFailure
instead of success.

Detailed/fallback snapshots preserve independent record classification/publication,
logical-save/underlying-writer phase and failure kind, credential publication, candidate/delivery
state, first ordinary fixed domain/classification, selected outcome,
first-cancel phase, observed cleanup and COMPLETE/INCOMPLETE. Unknown
refinement due to diagnostic failure remains INCOMPLETE; known publication
facts remain known. Return-path-selected is not proof of caller receipt.

Move the selected object into a finalizer local before clearing all raw exception
references and triples from attempt state; retain only scalar facts there.
With no selected error, return False. If selection is the incoming error,
return False; otherwise raise that selected object. No notes/cause/context/traceback is manually altered.
Only the issuing actor may read cached, sealed diagnostics for the authentic
CLOSED parent with B. Reading neither rebuilds snapshots nor admits a child.
A test-local real-factory spy retains that parent and independently expected
inputs. No persistent logger, journal or global exception registry is added.

Existing backend suppression remains:
[lock exit](../src/tridentine_calendar_google_sync/_posix_private_lock.py#L63)
can suppress ordinary close failure during body unwind;
[directory close](../src/tridentine_calendar_google_sync/_posix_sensitive_directory.py#L101)
suppresses os.close OSError. Only observed errors are reported; normal exit
proves neither every descriptor close nor kernel lock state. Legacy record
and standalone session exception contracts are unchanged.

## 6. One next implementation unit

PROPOSED_INTERFACE: implement this bridge in T and R, with one new test,
`tests/test_token_start_linked_session_phase6d1h.py`. Only that test invokes the
new private entry; CLI and public prepare functions remain disconnected.

| Proposed change | Exact boundary |
|---|---|
| T | Add linked request/context/owner, sealed association, named factory/sealing/admission functions and new adapter/coordinator diagnostic guards above. Extend _require_session_owner with exact dispatch only. |
| R | Add shared context/child, expected metadata, attempt-state/core-facts/snapshot types and all named binding/annotation/finalization functions above. Initialize private link in _record_scope; gate linked lifecycle in _require_scope and _RecordScopeContext.__exit__; add the held-create success latch in _held_record_io. |
| Record consumer test | In `test_component_has_no_runtime_consumer_or_dynamic_import_and_no_mutation_escape`, replace only [483–487](../tests/test_token_operation_record_phase6d1h.py#L483)'s empty runtime-reference consumer assertion, using the same reference-detection predicate, with exact `{"production_write_token.py"}`. Keep its local imports, dynamic-import/mutation prohibitions unchanged. |
| Existing direct consumers | Preserve lock/publisher and directory-backend sets; no new direct consumer. |

Four CURRENT_TEST structural checks have **no planned assertion changes**, conditional on retaining their fixed-HEAD conditions:
[session-lock](../tests/test_credential_session_lock_phase6d1h.py#L483)::`test_loader_lexically_holds_locks_over_reads_refresh_save_and_both_returns`,
[persistence](../tests/test_refresh_persistence_failure_phase6d1h.py#L313)::`test_new_handler_has_no_retry_cleanup_or_new_mutation_capability`,
[prewrite](../tests/test_refresh_prewrite_recheck_phase6d1h.py#L397)::`test_added_recheck_only_reads_renders_compares_and_raises`, and
[replacement](../tests/test_refresh_replace_integration_phase6d1h.py#L367)::`test_refresh_passes_original_input_and_has_no_legacy_save_at_call_site`.
Preserve the legacy loader’s two calls and factory→with→held structure, one UTC
and one path-set check before issuance, one lock entry, the held checkpoint
closure, outer try/finally and two candidate returns. The save handler retains
one Exception clause and only isinstance/ProductionWriteTokenRefreshPersistenceError
as named calls, without loops or mutation. Preserve prewrite read/render/UTF-8
compare order, one save and original expected_token. New catches belong outside
the existing held body. These are compatibility requirements, not a guarantee
that unwritten code passes. Schema, backends, legacy diagnostics and no-retry
rules stay intact.

## 7. Proposed acceptance and remaining boundaries

PROPOSED_ACCEPTANCE, not executed here:

| Group | Required evidence |
|---|---|
| Normal | Real START codec; unexpired 0 refresh/save, expired one fake refresh/save; acquisition/entry/exit each one; return after exit; retained START makes next request occupied. |
| Preflight | Bad target/confirmation, UTC/path-set/layout stop before START; Windows new entry rejects early, standalone behavior preserved. |
| START | Occupied/create/readback/checkpoint failures stop before session contents; read-only or forged-result issuance refuses. |
| Ownership | Forged/foreign issuer, request, operation, thread/process, second use, reentry, closed use and session-phase record operations refuse without releasing another owner. |
| Failures | Inject each read/validation/refresh/recheck/save/final-check/exit boundary; preserve publication/object evidence, withhold candidate, never delete START or retry effects; exercise all cleanup precedence rows. |
| Memory | Real factories/validators/held body; double permitted I/O only. Keep record-only 21 tests' eleven entries at zero; separately count permitted linked synthetic reads/refresh/save while refusing real provider/network. |
| Linux native | Observe competitor refusal after START and during session, not merely acquisition counts; distinguish reacquisition after success/failure from independent-process observation. |
| Compatibility | Preserve record 387, owned-body 110, structural/consumer guards and direct-call memory reentry characterization; no claim of all-caller enforcement. |

Additional **PROPOSED_ACCEPTANCE** for the two corrections:

| Parent-association case | Required refusal or control |
|---|---|
| Factory-sealed parent, actual START success, its child | Normal connection protects the checked credential directory. |
| Same Q, genuine parent/child in another directory | Parent identity/layout refuses before credential effects. |
| Same directory, other operation/predecessor/kind | Every independent operation field is checked. |
| Equal metadata, different parent instance | Parent identity refuses despite equal values. |
| Storage/pair mismatch or token/state slot swap | Full binding and checked role/path correspondence refuses. |
| Rebinding or substituted/consumed/closed child | Single seal, reciprocal identity and lifecycle refuse. |

Use the correct parent with an isolated field mismatch to exercise each value
comparison; a foreign instance may refuse earlier on identity. Catch each
negative call inside the legitimate scope and observe unchanged
lock, phase, use latch and exit count. Refusal itself does not release/consume
that owner. Separately distinguish legitimate coordinator abort cleanup when
a refusal escapes.

In the next table sR is independently retained START publication and sC is the
credential fact at failure. Every row requires **no additional refresh/save,
no candidate, one exit by a legitimately entered owner**, and INCOMPLETE when
diagnostics fail. No entered owner means no invented exit. These are future
tests, not executions or claims of a newly reproduced product bug.

| Diagnostic fault | Primary and independent evidence |
|---|---|
| Initial note fails before copying, classifier fails, or refinement fails after session P | Same P; sR/sC preserved by minimal state; SESSION_OTHER if refinement is unavailable. |
| Pre-writer preparation raises D | Existing P(False); sR retained; underlying writer NOT_CALLED/0, logical save invoked. |
| Writer W then publication note D | Same W reaches existing handler; its actual P escapes. Preserve sR and W’s bool/None publication. |
| Normal writer return then note D | Existing P(True); sR retained, RETURNED/True remains; no successful candidate. |
| Ordinary P then diagnostic cancellation C | Same first C; preserve earlier ordinary fixed diagnosis and sR/sC. |
| Ordinary W then diagnostic cancellation C | Same C; retain writer-origin W/evidence; do not claim P generation. |
| Cancellation C1 then ordinary failure or C2 | Same C1; retained publication unchanged, later failure secondary. |
| Snapshot builder D | Prior primary/C1 remains; without one, same D is primary. Sealed INCOMPLETE fallback preserves known scalar facts. |
| Snapshot builder cancellation | First cancellation wins; prior ordinary diagnosis and publication survive. |

Also cancel pre-writer and post-return annotation: expect NOT_CALLED/False and
RETURNED/True respectively, with the first cancellation object.
Retain the preceding normal/occupied/preflight/Linux/Windows, record 387,
owned-body 110, record-only 21, reentry and four structural-test conditions.

INHERITED_EVIDENCE: run 41597584318/attempt 1/pull_request, executed and reviewed
2026-11-03 JST, eight jobs successful; detailed logs covered only both base jobs.
New record tests: 21 passed each; operation record: Ubuntu 387 passed,
Windows 331 passed/56 skipped; owned-body: 110 passed each.
Comment 6598942659 and the 37-commit Open/Draft/unmerged PR report are inherited,
not re-fetched. This CI contains no proposed connection. Local 537/471/66,
record RED four failures, session RED two, and earlier 75 failures remain
separate histories.

OPEN_DECISION: no blocking synthetic-interface choice remains. Implementation
must stop if this exact two-module/guard scope proves insufficient.
Operational approval, trusted deployment, physical binding/rollback requirements,
all-writer/caller participation, normal-operation closure, START retirement,
and recovery remain separate work. The original DS-04 finding and formal close
criteria are unavailable. VALIDATION_ROOT_UNAVAILABLE persists; necessary native
acceptance is not currently demonstrated locally. Commit-first/CI transfer
requires separate authorization.

DS-04 remains PARTIAL; Historical Deep Security Scan INCOMPLETE; separate
47194b0 report FAIL; Production BLOCKED; live handlers hard-off; registry
empty/fail-closed. Document/static work only; no product execution, I/O experiments, Git writes,
remote, or Google operations.

## 8. Review correction — 2026-11-04 JST

Sections 3–7 now bind one parent and retain original failure facts before fallible
diagnostics. This is an unimplemented interface correction, not a product
reproduction or passing execution result. Sections 1–2, the original design date,
fixed revision, inherited evidence and operational exclusions retain their
original meaning. No additional source module, public API, dependency or guard
relaxation is proposed.


## 9. START-linked implementation and validation evidence

Implementation and local validation date: 2026-11-07 JST.
Result: START_LINKED_SESSION_IMPLEMENTED_VALIDATION_INCOMPLETE.


### 9.1 Implementation and preserved boundaries

The private entry is T._prepare_start_linked_session_mock. Its only caller
is the new [START-linked acceptance test](../tests/test_token_start_linked_session_phase6d1h.py).
The public prepare functions, CLI and bootstrap have no connection to this entry.

| Contract section | Implementation |
|---|---|
| §3 preflight | T._start_linked_session_context checks the existing target and exact confirmation, Linux, UTC and the full existing-pair path set before ownership. It requires the explicit mock-only refresher and independently supplied REFRESH metadata. The checked write and state paths preserve role order and supply the actual held read and save paths. The two exclusion paths only enter path-set validation. |
| §3 association and admission | T._seal_start_linked_parent binds the factory request and context to one R parent, immutable independent expectations and the exact attempt state. T._bound_linked_parent, T._issue_start_linked_session_owner and T._require_start_linked_session_owner check reciprocal identities. R._check_linked_binding and R._require_linked_child check actor, provenance, ordered path and metadata values, and the applicable lifecycle. |
| §4 START and continuous ownership | R._shared_start_session_scope owns the existing record scope and its single acquisition. R._create_linked_start requires the exact latch from the real held create after publication, matching readback and the last record checkpoint. The create must return normally. R._linked_session_phase admits one child and revokes it in its protected exit. T calls the existing held body and delegates its checkpoints to the same directory handle. |
| §4 delivery | The coordinator keeps the candidate local. R._final_linked_checkpoint checks the consumed phase, retained child identity and candidate latches, then revalidates the held handle once. Successful finalization and exit precede return. The START remains started/incomplete. A later independent request refuses the occupied slot. |
| §5 writer and diagnostics | T._persist_linked delegates once to the captured writer with the existing expected_token argument. It preserves writer exception W by identity to the existing handler. Shared primary retention starts with P emitted by that handler. Fixed core facts keep record publication, logical save, writer phase, credential publication, ordinary failure, first cancellation and cleanup observations independently. |
| §5 arbitration | R._finalize_linked_scope delegates the original exit triple once and detaches the owned stack. The first cancellation object takes precedence, followed by the first ordinary primary. The selected exception is preserved as raw references are cleared. R._build_linked_diagnostics projects fixed facts into a sealed snapshot. A build failure reselects the outcome before sealing the preallocated incomplete fallback. |
| §6 compatibility | The new application edge is T to R. The record consumer assertion uses the original predicate over the original module set and expects exactly production_write_token.py. Record local-import, dynamic-import and mutation checks, direct lock and publisher checks, and directory-backend consumer checks passed. |

The writer adapter records NOT_CALLED and False when pre-writer annotation
fails. A normal writer return records RETURNED and True before further
annotation. An ordinary annotation failure at either boundary reaches the
existing handler through a fixed I/O error carrier with the corresponding
publication fact. A later ordinary note failure after W leaves W available to
the handler. Writer-origin errors stay separate from the emitted P.
Cancellation keeps the first cancellation object and its boundary. The logical
persistence attempt in P is independent of the underlying writer count.

The session held body, legacy loader, scope factory, context, request and owner,
lock helper, public prepare functions, and all other existing T definitions
outside the admission dispatch were checked against HEAD as bytes. The check
removed the added region and import and reversed the dispatch change before
comparison. In R, reversing the bounded link field, initializer, exit and scope
guards, held-create latch and imports reproduced the HEAD bytes. This preserves
the legacy record entry and unwind, codec, schema, held-I/O checkpoints and
standalone precedence. Reversing the single assertion in C reproduced its
entire HEAD file. Both separately pinned existing test blobs matched.
The four original structural nodes each passed.

The shared finalizer records cleanup errors that reach it. Backend-suppressed
close errors remain outside that observation. Successful exit demonstrates the
observed release path. The bounded cancellation tests cover specific transitions
and fallible helper calls.

### 9.2 Acceptance nodes and local observations

Node names below are in
[test_token_start_linked_session_phase6d1h.py](../tests/test_token_start_linked_session_phase6d1h.py).
All listed memory and Windows nodes passed in the final specified process.
The native group was collected and skipped by its existing platform condition.

| Group | Node and parameter coverage |
|---|---|
| Normal flow and retained START | test_normal_retains_start_and_returns_only_after_exit [unexpired, expired]. Each branch exercises the real factory, START codec, held body, session constructor and shared finalizer. |
| Preflight and Windows | test_real_preflight_order_precedes_parent_factory; test_preflight_rejects_before_start [target, confirmation, utc, path_set, directory, storage, pair, swap, record_collision, new_pair, same_predecessor, missing_predecessor, unsafe_refresher]; test_real_windows_gate_precedes_preflight_and_standalone_refuses. |
| START proof and refusal | test_start_failure_never_reaches_credential_reads [occupied, publish, readback, checkpoint_3, forged_result, after_latch, owner_mismatch]; test_legacy_held_read_does_not_issue_shared_child. |
| Independent expected values | test_exact_parent_checks_independent_field_without_consuming [directory, storage_ref, pair_ref, token_slot, state_slot, operation_id, predecessor_id, kind, token_path, state_path, swapped_paths]. Each case uses the legitimate parent. |
| Parent identity and misuse | test_genuine_foreign_child_is_refused_before_owner_issuance [equal_metadata, foreign_directory]; test_misuse_does_not_revoke_valid_actor_and_closed_child_cannot_resume. The latter covers construction, partial and fabricated material, copying, pickling, resealing, child substitution, active reentry, unrelated record use, wrong thread and synthetic PID, repeated held use and consumed or closed use. |
| Entry and abort | test_failed_entry_does_not_finalize_an_unentered_backend [acquire, entry]; test_interruption_unwinds_a_real_entered_scope_once [shared_initialization, issued_child]. The latter faults after successful inner entry or after issuing a genuine child. |
| Held failures and candidate withholding | test_failure_boundaries_preserve_primary_and_withhold_candidate [read_state, read_token, validation, refresh, prewrite, checkpoint_4, writer, checkpoint_9, phase_exit, exit]. |
| Diagnostic failure table | test_diagnostic_fault_matrix [initial, classification, refinement, pre_writer, writer_raised, writer_raised_false, writer_raised_unknown, writer_returned, p_then_cancel, w_then_cancel, pre_writer_cancel, writer_returned_cancel, cancel_then_ordinary, cancel_then_cancel, snapshot_after_p, snapshot_after_success, snapshot_cancel_after_p, snapshot_cancel_after_cancel]. |
| Exit arbitration | test_backend_receives_original_triple_and_cancellation_precedes_cleanup [ordinary/ordinary, ordinary/cancel, cancel/ordinary, cancel/cancel, healthy/cancel]; test_phase_exit_failure_retains_prior_session_and_original_backend_triple [persistence/ordinary, persistence/cancellation, cancellation/ordinary, cancellation/cancellation]. |
| Forbidden effect calibration | test_forbidden_effect_monitor_calibrates_every_entry_and_restores. |
| Linux native, skipped locally | test_native_lock_excludes_competitor_until_exit_and_retains_start [success, writer_fault, cancel]. The test owns its synthetic directory and pair. It uses real record I/O and locks, competitor observations after START and during the session, and independent child processes with finite timeouts. It distinguishes real synthetic persistence on success from a writer double on failure and checks reacquisition after each outcome. |

The memory tests replace record acquisition and its handle methods, the START
leaf probe, record output validation, private byte publication and readback, the
full credential path-set validator, and the two credential readers and writer.
The Windows memory fixtures replace only the record module's platform
predicate, which the new entry also uses. The separate Windows test uses the
unchanged platform predicate. Target and confirmation validation, the record
codec, session validation, render comparison, held body and candidate
construction run through the existing code. Memory preflight establishes only
the returned lexical paths in those tests. The Windows run leaves native
directory and private credential path validation open.

The preflight spy observed one parent factory before acquisition. Each normal
memory branch observed one acquisition, entry,
record publication, readback, exit, candidate construction and caller return.
The unexpired branch counted six combined checkpoints, one state and one token
read, zero refreshes and zero saves. The expired branch counted nine
checkpoints, two state and two token reads, one fake refresh and one underlying
memory save. The expired branch simulated publication in memory. Its record
stayed occupied after exit. Publication flags in fault cases report evidence
from the specific call. The writer double can report uncertainty or a supplied
publication flag without a corresponding memory save.

The linked tests use twelve finite non-delegating tripwires covering public
provider or session entry, desktop client loading, the separate session lock,
socket construction, connect helper and address resolution, and browser entry.
Each was calibrated for a single call, refusal by BaseException, no delegation
and restoration. The linked memory and real Windows gate scenarios observed
zero calls to these entries. Existing pytest socket restrictions remained on.
The 21 record-busy tests passed with their own eleven monitored entry points
and separate calibration. Permitted linked fixture effects are accounted for
separately from these prohibited entry points.

### 9.3 Local validation and remaining execution

Windows, Python 3.12.14. Both imported source modules resolved to the selected
worktree. The installed versions of icalendar 6.3.2, pydantic 2.13.4,
pydantic-core 2.46.4, pytest 8.4.2, pytest-socket 0.8.1, pytest-mock 3.15.1,
Ruff 0.16.4 and mypy 1.20.2 matched uv.lock. Its Python constraint is 3.12.
The existing environment was used without installation or synchronization.

The final single pytest process used Python -B, pytest -q with per-node
verbosity, no cacheprovider, a new dedicated scratch path and the three
Google-marker exclusions. Exit 0. Total 558 passed, 69 skipped, 0 failed and
0 deselected within this set.

| File or group | Passed | Skipped |
|---|---:|---:|
| New START-linked acceptance | 81 | 3 |
| Operation record | 331 | 56 |
| Owned session body | 110 | 0 |
| Record busy transition | 21 | 0 |
| Session failure reentry | 3 | 0 |
| Existing START/session boundary | 3 | 10 |
| Nine selected structural and consumer nodes | 9 | 0 |

The three new skips cover the Linux-native suite, including its independent
child process probes. Native acquisition, competition, real synthetic
publication, release and child process execution have no local success result.
The synthetic PID and real thread misuse tests ran locally.

Full-file regression remains unrun for credential-session-lock,
refresh-persistence-failure, refresh-prewrite-recheck, refresh-replace-integration,
token-bundle-lock and pair-inspection. The selected structural node from each
passed. These files contain private storage fixtures, and the local private
credential validation root was not available. The production-write-token-refresh
and grant-provenance files are outside the base marker selection and were
unrun. These eight full-file gaps are separate from the 69 skips above.

Ruff check and format check passed for the repository, with 288 files already
formatted. Strict mypy passed for the two changed modules and all 124 source
files. Git diff --check passed. The existing test and consumer boundaries
passed. Earlier local iterations surfaced line-length and exception-raise lint,
three type-narrowing diagnostics, and one test failure from treating a Pydantic
model as a dataclass. The initial mypy invocation used an unsuitable cache
device spelling, and the first record write command exceeded the launcher
limit before saving. The candidate was checked before the successful save.
These intermediate tool or fixture failures are separate from product RED
evidence.

The review scope is three tracked changes and two untracked files, with no
staged changes. Branch, HEAD, tree and index matched the captured start.
The original 40,097-byte contract is preserved as an exact prefix. Existing
test run 41597584318 predates this connection, and its results remain historical.
No package build, CI, stage, commit, push, remote access or production operation
was performed.

This work covers the test-owned START-linked entry. Trusted enrollment, physical
binding and rollback guarantees, all-caller history enforcement, START retirement,
recovery and deployment approval remain open. DS-04 is PARTIAL. Historical Deep
Security Scan is INCOMPLETE. The separate 47194b0 report is FAIL. Production gate
is BLOCKED. Live handlers are hard-off and the registry is empty/fail-closed.


## 10. Phase-manager actor-boundary correction and validation evidence

Correction and local validation date: 2026-11-08 JST.
Result: START_LINKED_PHASE_ACTOR_BOUNDARY_FIXED_VALIDATION_INCOMPLETE.

### 10.1 Starting bytes and independent reproduction

The local starting document matched E_ATTACHMENT, 54,255 bytes. It contained
one additional LF between the section 9 Result line and heading 9.1 compared
with E_REPORT. Removing that LF in comparison data reproduced E_REPORT's
54,254 bytes and both reported digests. The entire E_ATTACHMENT version and
the 40,097-byte contract are exact prefixes of this document.

The reviewer's ChatGPT reproduction used Linux and Python 3.13.5, the real
record module and in-memory lock and storage doubles. It was a separate
observation. The preceding 558 passed and 69 skipped describe the November 7
run and exclude the actor-boundary regressions added here.

On Windows with Python 3.12.14, the new regression entered the real parent,
completed the actual held START path against memory doubles, and called the
phase manager itself. Both a different live thread and a synthetic PID
mismatch were exercised. For each actor, the same three exit triples produced
the following local observations on the original B bytes.

| Foreign exit input | Immediate phase and child | Retained failure |
|---|---|---|
| Normal triple | CONSUMED, same child identity, child inactive, issuing cleared | No primary or cancellation |
| Ordinary exception triple | FAILED, same child identity, child inactive, issuing cleared | Foreign ordinary exception retained as primary |
| Cancellation triple | FAILED, same child identity, child inactive, issuing cleared | Foreign cancellation retained as first cancellation |

All six exit calls returned without a usage refusal. Publication facts
remained the same. Each foreign call added zero record or credential effects
and zero backend exits. The issuing actor released the parent once during
controlled cleanup. A foreign enter in either actor mode raised the fixed
scope-use error and kept the parent in START_READY with zero added effects or
exits. The owner's attempt to enter that same manager raised AttributeError
because the generator manager had already been consumed.

The pre-fix RED selected the six exit and two entry cases. It collected eight
tests and reported zero passed, eight failed, zero errors, zero skipped and
zero deselected, with exit 1. All eight failures reported the phase
observation after controlled cleanup.

### 10.2 Correction and regression coverage

R._linked_session_phase now returns the exact private
R._LinkedSessionPhaseContext. It binds the parent, request and independent
expected values. Entry verifies actor and start-ready state before consuming
the internal generator. Exit verifies the active manager, actor, bound
parent and actual issued child before forwarding the original exit triple.
Both paths reject invalid lifecycle transitions before delegation. The same
manager remains usable by the issuing actor after a foreign entry refusal or
a foreign exit refusal. Construction, partial handles, copy, deepcopy,
pickle, active reentry and reuse after exit are refused.

One internal generator retains the existing phase transitions, exception
capture, child revocation and single-use cleanup. The phase manager delegates
no lock acquisition or release. The parent finalizer owns backend release and
keeps its original triple, exception precedence, independent publication
facts and snapshot/fallback behavior. The byte comparison found the B prefix
and suffix outside the phase region unchanged. A and C matched their full
starting bytes. The original D file is an exact prefix of the updated test.

The new nodes are in
[test_token_start_linked_session_phase6d1h.py](../tests/test_token_start_linked_session_phase6d1h.py).

| Node | Local outcome |
|---|---|
| test_phase_actor_foreign_exit_preserves_the_same_manager [normal, ordinary, cancel] by [thread, pid] | Six passed. Fixed refusal, unchanged phase, child, use and failure state, unchanged publication and zero added effects or exits. The issuing actor then ran the real held body and completed the same phase and parent. |
| test_phase_actor_foreign_entry_leaves_same_manager_usable [thread, pid] | Two passed. Fixed refusal without consuming the manager. The issuing actor entered that same manager and completed the held body and exit. |
| test_phase_manager_cannot_be_duplicated_reentered_or_reused | Passed. Usage refusals preserved the legitimate phase and its single backend release. |
| test_phase_manager_owner_failure_retains_identity_until_parent_exit [ordinary, cancel] | Two passed. Phase exit retained the exact exception or cancellation and revoked the child while the parent remained held. The parent forwarded the original exception to the backend once and withheld delivery. |

The successful issuing-actor controls used one synthetic START publication and
readback, one state read and one token read, and zero refreshes or saves.
Ordinary failure and cancellation controls used one state read and no token
read, refresh or save. These are memory effects and actor-boundary checks.
The synthetic PID case changes the captured PID under the test fixture.
The thread case runs a separate live thread. Neither launches a process.
The existing expired-session fixture still exercises fake refresh and memory
publication as recorded in section 9.

### 10.3 Final local evidence and remaining execution

The existing Windows Python 3.12.14 interpreter loaded both source modules
from the selected worktree. The eight related installed dependency versions
listed in section 9 matched uv.lock again. The run used Python -B, pytest -q
with per-node verbosity, no cacheprovider, a fresh dedicated scratch path and
the base Google-marker exclusions. The final process collected 638 tests and
reported 569 passed, zero failed, zero errors, 69 skipped and zero deselected,
with exit 0. An earlier post-fix run had the same pytest totals. Two lint
findings in the appended test were then corrected and the full final set was
rerun.

| File or group | Passed | Skipped |
|---|---:|---:|
| Original START-linked tests | 81 | 3 |
| New phase actor-boundary tests | 11 | 0 |
| Operation record | 331 | 56 |
| Owned session body | 110 | 0 |
| Record busy transition | 21 | 0 |
| Session failure reentry | 3 | 0 |
| Existing START/session boundary | 3 | 10 |
| Nine selected structural and consumer nodes | 9 | 0 |

Ruff check and format check passed for the repository. The formatter reported
288 files already formatted. Strict mypy passed for B and for all 124 source
files. Git diff --check passed. The four original structural nodes and the
direct lock, publisher and directory-backend consumer guards passed.

The three Linux-native START-linked cases were collected and skipped by their
platform condition. Native locks, real synthetic persistence and independent
child process observations remain unexecuted locally. Full-file validation
remains unrun for credential-session-lock, refresh-persistence-failure,
refresh-prewrite-recheck, refresh-replace-integration, token-bundle-lock and
pair-inspection. Their selected nodes passed. Production-write-token-refresh
and grant-provenance remain outside the base marker selection. These eight
full-file gaps are separate from the reported pytest skips.

The branch, HEAD, tree and sole parent matched the fixed start. The index
matched the captured starting bytes and staged changes were zero. Tracked
changes relative to HEAD were A, B and C, and the two untracked files were D
and E. This correction changed only B, D and E. Git reads used the single
command-scoped safe.directory value, with zero configuration file changes.

DS-04 is PARTIAL. Historical Deep Security Scan is INCOMPLETE. The separate
47194b0 report is FAIL. Production gate is BLOCKED. Live handlers are hard-off
and the registry is empty/fail-closed.


## 11. Accepted phase-transition interruption correction

Correction and local validation date: 2026-11-08 JST.
Result: START_LINKED_PHASE_TRANSITION_FIXED_VALIDATION_INCOMPLETE.

### 11.1 Independent local reproduction

The section 10 foreign-actor correction is retained. This correction covers
a different boundary, an interruption after the issuing actor has passed
admission and while it hands off an accepted entry or exit.

The separate ChatGPT observation used Linux and Python 3.13.5 with the real
record code and in-memory lock and storage doubles. It was record-only. It
did not exercise the held session, native locking, or product pytest.

The local reproduction used Windows and Python 3.12.14. The existing memory
fixture ran the real coordinator, parent, held START create, phase manager,
and, for exit cases, the real held credential body against synthetic effects.
Each case raised its prepared RuntimeError or BaseException cancellation once
from the exact manager method frame. The trace matched lifecycle and child
state rather than a fixed line number and restored the prior trace state.

| Injection point on the starting B | Result before test cleanup |
|---|---|
| Entry after internal child issuance, before the manager retained the child | The manager closed, the parent remained SESSION_RUNNING with issuing true, and the issued child remained active. |
| Exit after marking the manager exiting, before delegating phase termination | The manager closed, the parent remained SESSION_RUNNING with issuing true, and the issued child remained active. |

Both exception kinds reproduced each row. Parent exit refused the unfinished
phase, and the outward exception was _ScopeUseError instead of the prepared
object. The simulated backend remained held and product exit count was zero.
The test captured these observations before a separate harness-only release
of the synthetic backend, which occurred once per failing case. The two
entry controls injected before phase issuance. They kept the original object
and completed one product exit. No candidate reached the caller in these
six interrupted attempts.

The RED run collected six cases and reported two passed, four failed, zero
errors, zero skipped and zero deselected with exit 1. All four failures
reported the intended handoff observation. The earlier 638 collected,
569 passed and 69 skipped, and the earlier actor-boundary RED of eight,
remain separate historical runs.

### 11.2 Correction and observations

The exact phase manager keeps its prior actor, request, expected-binding,
child and lifecycle checks ahead of state mutation. Accepted transitions
now issue and finish the phase directly in the same private context.
Entry abort can revoke the child retained by the parent even before the
manager has assigned its own child field. Exit places phase termination
inside the protected transition and aborts a phase still marked
SESSION_RUNNING if interrupted at the handoff. A terminal phase is left
terminal. Both handoff cases revoke the child, clear issuing, and leave the
parent eligible for its existing finalizer. The phase context has no backend
acquisition or release responsibility.

The phase retains an incoming ordinary failure or first cancellation before
exit handoff, and records the interruption separately. In a coincident
failure, the backend receives the exception that actually reached parent
exit. Final selection preserves the first cancellation, or the first
ordinary failure when no cancellation occurred. Writer W and the existing
held handler's P are unchanged. The parent finalizer and the original
backend triple tests are byte-identical to their starting versions.

The added nodes are in
[test_token_start_linked_session_phase6d1h.py](../tests/test_token_start_linked_session_phase6d1h.py).

| Node | Local result |
|---|---|
| test_accepted_phase_handoff_interruption [before_entry, entry, exit] by [ordinary, cancel] | Six passed. The original injected object escaped, any issued child became inactive, the manager closed and refused reuse, and the product parent released the backend once. Harness exits and post-injection effects were zero. |
| test_accepted_phase_exit_interruption_preserves_first_failure [persistence, cancel] by [ordinary, cancel] | Four passed. The parent backend received the actual exit interruption, while final exception selection and independent publication facts followed the prior P or cancellation rules. |
| Previous foreign-actor and lifecycle tests | All eleven passed, including legitimate continuation after foreign entry or exit refusal. |

All new cases retained the synthetic START, with one record publication and
one readback. The entry and pre-entry cases had zero credential effects.
The otherwise successful exit cases had already performed two state reads,
two token reads, one fake refresh and one memory save before interruption.
They retained the simulated credential publication fact and withheld the
candidate. No additional read, refresh or save followed the injection.
For the prior P cases, the writer double reported publication possible
without simulating a completed save. The prior cancellation cases stopped
during the first synthetic state read. These counts concern the memory
fixture. The native tests were not executed.

### 11.3 Final validation and review scope

The existing Python 3.12.14 environment resolved both modules to the selected
worktree and matched the eight dependency versions in uv.lock. The final
specified pytest process used Python -B, no cacheprovider, a fresh dedicated
scratch path and the base Google-marker exclusions. It collected 648 tests
and reported 579 passed, zero failed, zero errors, 69 skipped and zero
deselected with exit 0. The original 95 D cases contributed 92 passes and
three skips. All ten new D cases passed. The original 387 record, 110
owned-body, 21 record-busy, three reentry and 13 START/session cases were
retained. The nine selected nodes passed, including the four fixed
structural checks. A first post-fix run had the same totals. Exit termination
was then moved directly inside its protected transition and the final
suite was rerun.

Ruff check and format check passed, with 288 files already formatted.
Strict mypy passed for B and all 124 source files. Git diff --check passed.
Only the phase definitions and their obsolete imports changed in B.
A and C were byte-identical to their starting versions. The previous D
bytes are an exact prefix of the updated test, and all 62,211 starting E
bytes and the 40,097-byte contract prefix were preserved.

The three Linux-native START-linked cases were collected and skipped on
Windows. Native lock competition and reacquisition, native synthetic
persistence and independent child-process probes remain unexecuted locally.
The selected nodes passed for credential-session-lock,
refresh-persistence-failure, refresh-prewrite-recheck,
refresh-replace-integration, token-bundle-lock and pair-inspection.
Those six full files were not run. Production-write-token-refresh and
grant-provenance were outside the base marker selection. These eight
full-file gaps are separate from the 69 skips.

Branch, HEAD, tree, sole parent and the captured index matched the start.
Staged changes were zero. The only tracked changes from HEAD were A, B and C,
and the only untracked files were D and E. This correction wrote B, D and E.
Git used one command-scoped safe.directory value and changed zero settings.

DS-04 is PARTIAL. Historical Deep Security Scan is INCOMPLETE. The separate
47194b0 report is FAIL. Production gate is BLOCKED. Live handlers are hard-off
and the registry is empty/fail-closed.
