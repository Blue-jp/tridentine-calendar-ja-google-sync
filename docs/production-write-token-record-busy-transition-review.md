# START-Record Busy-Transition Interruption Review

Status: RECORD_BUSY_TRANSITION_FIXED_VALIDATION_INCOMPLETE.

Work date: 2026-11-03 JST. This review concerns the uncommitted change based on
HEAD `99ff2cefea7314ff20681e2bcf19f1bb6de72ffa`, tree
`0518c1069aff9a0293807d47676a67805e775e06`, whose sole parent is
`095326d9db4ee387d0c935b40a5d4d6bfbcd6019`.
The branch remains `security/deep-scan-remediation-47194b0`.

## Boundary and existing contracts

The target is `_held_record_io` in
`src/tridentine_calendar_google_sync/production_write_token_operation_record.py`,
lines 573–634. At the starting HEAD, line 583 set `owner._busy = True`;
initialization followed at lines 584–585, and the protecting try began at
line 586. An interruption after the assignment could therefore bypass the
held handler and its finally. The unchanged owner exit rejects a busy owner.

That placement was a static concern before this work. The record-specific
execution below establishes the observed problem independently of the earlier
session reproduction. See the existing
[shared ownership design, section 9](production-write-token-shared-ownership-session-design.md#9-busy-transition-interruption-correction-and-validation-evidence)
for that separate session history.

Ordinary exceptions retain the record API's fixed refusal contract:
`UNVERIFIABLE`, `publication_possible=False`, and
`reuse_authorized=False` at this pre-publication boundary. Synthetic cancellation,
derived directly from BaseException, must propagate as the same object without
becoming a RecordResult. A refusal result alone cannot establish successful exit.
Public START_CONFIRMED and START_OBSERVED remain results generated after owner exit.
Private create followed by held read remains supported; no session-style
single-use read rule or new used flag was introduced.

## Reproduction harness and counters

The new test file is
`tests/test_token_record_busy_transition_phase6d1h.py`.
It follows the actual public create/read API, storage wrapper, real scope
factory and context, real held implementation, real codec and classification,
and real owner exit. Factory and codec spies delegate exactly once per call.
Only the Linux-availability predicate and storage seams are replaced.
The memory lock never suppresses an exception. Synthetic REFRESH operations
have an independent valid predecessor, and no real directory or START is used.

The eight interruption combinations are create/read × before/after busy ×
RuntimeError/synthetic cancellation. Two additional normal public create/read
controls use actual codec validation and result construction.

The trace matches the running held function's code object. AST and source
inspection locate the actual True assignment instead of a fixed line number.
Before-busy injection requires that line with busy=False. After-busy injection
requires busy=True at the next matching line. Both verify a reciprocal issued
scope, ACTIVE owner, one acquisition and entry, and zero held checkpoints and
record effects. The prepared exception is raised once. No owner field or
dependency is changed by the trace, and no frame-local collection is retained.

Factory, acquisition, lower-context entry/exit, held checkpoints, lstat,
output preflight, reader, and publisher have distinct counters. Entry codec
work is separate from storage effects. Read fixture preparation encodes once;
each interrupted API performs one runtime entry-codec call. Those pure operations
are not record publication or reading.

Credential/provider/network activity was not separately instrumented.
The exercised record path contains no such entry point, storage seams are
replaced in memory, and the unchanged socket prohibition remains active.
These facts are not measured zero-call counters for those three categories.
The requested separate external-effect instrumentation remains a validation
limitation; the diagnostic label does not pretend otherwise.

## Observed RED

With the original record source, pytest reported **10 collected, 6 passed,
4 failed, 0 errors, 0 skipped, 0 deselected; exit 1**. The four before-busy
controls and both normal controls passed. All eight injections occurred once,
before any held checkpoint or record effect; none of the failures was an
import, collection, fixture, or missing-injection failure.

| Boundary and error | Both public APIs |
|---|---|
| Before busy, RuntimeError | UNVERIFIABLE; entry/exit 1/1; CLOSED, non-busy, not held |
| Before busy, cancellation | Same cancellation object; entry/exit 1/1; CLOSED, not held |
| After busy, RuntimeError | UNVERIFIABLE but entry/exit 1/0; ACTIVE, busy, still held |
| After busy, cancellation | Cancellation did not propagate; ordinary UNVERIFIABLE; entry/exit 1/0; ACTIVE, busy, still held |

The original assignment was line 583; after-busy injection occurred at 584.
Both after-busy cancellation cases returned a refusal with publication and
authorization False, demonstrating why the public classification alone was
insufficient. Discarding the failed memory fixture is not successful product
cleanup and does not establish anything about a native lock.

## Minimal correction and GREEN

Only the busy assignment moved: it is now the first statement inside the
existing try, at line 586. The evidence variables initialize before that try,
and the first held checkpoint remains line 587. All other statements, handlers,
checkpoint ordering, publication evidence, and the finally are unchanged.
The owner exit's busy refusal was preserved.

The same eight injection conditions now pass. Before-busy injection occurs at
586 and after-busy at 587, before checkpoint execution. Every interrupted case
has factory/acquisition/entry/exit 1/1/1/1, CLOSED and non-busy owner, detached
held/stack references, and no held memory lock. Every held checkpoint and
record-effect counter is zero. RuntimeErrors produce the existing refusal;
cancellations propagate by identity without returning a result.

Closed-context reentry and closed-scope read are refused without more effects.
The normal create control measures three checkpoints, three runtime codec calls,
one lstat/preflight/publication/read each. Normal read measures two checkpoints,
two runtime codec calls, one read, and zero lstat/preflight/publication.
These controls return their real success classification only after exit.

The previous trace is captured; an active trace is explicitly rejected.
Finally restores it, and all eight seam/spy identities are checked after
monkeypatch restoration. Fixed observation properties are recorded before
assertions; raw exceptions, tracebacks, private paths, and synthetic payloads
are withheld by the invocation helper.

## Final local validation

Windows, Python 3.12.14, expected repository src reference. Installed metadata
matched uv.lock for pytest 8.4.2, pytest-socket 0.8.1, Ruff 0.16.4,
mypy 1.20.2, and pydantic 2.13.4. Nothing was installed.

The final single pytest process ran the new file first, followed by the full
record, session-owned-body, failure-reentry, and START/session-boundary files,
then the three specified lock/directory/network-import guards:

| Group | Collected | Passed | Skipped |
|---|---:|---:|---:|
| New record busy transition | 10 | 10 | 0 |
| Existing operation record | 387 | 331 | 56 |
| Existing session owned body | 110 | 110 | 0 |
| Failure reentry | 3 | 3 | 0 |
| START/session boundary | 13 | 3 | 10 |
| Three additional guards | 3 | 3 | 0 |

Measured total: **526 collected, 460 passed, 0 failed, 0 errors, 66 skipped,
0 deselected; exit 0**. The record file's two consumer guards were included.
Existing OS skips were retained; no skip, xfail, assertion, or guard was relaxed.

Both RED and GREEN used Python `-B`, pytest `-q -p no:cacheprovider`,
the existing conftest/strict settings/socket ban, and marker expression
`not google_read and not google_test_write and not google_production_write`.
Each invocation used a newly created dedicated pytest scratch, never an old
basetemp or private credential-validation root.

Whole-repository Ruff check passed with zero diagnostics; format check passed
for 285 files. Strict mypy passed for the changed module (1 file) and all src
(124 files). Git whitespace checking passed. Dedicated temporary mypy caches
were used. Three synthetic helper diagnostic checks are separate from pytest.

## Preservation and limits

The target function's outside bytes and every other existing tracked file
remain unchanged, including owner lifecycle, tests, session implementation,
schema, consumer sets, workflows, and the historical design. Only this review
and the new test are added. HEAD, tree, and the freshly captured index remain
unchanged; nothing is staged.

Native record persistence, real lock release, competing processes, and Linux
execution were not performed. VALIDATION_ROOT_UNAVAILABLE remains unresolved.
One trace interruption is not OS-signal injection, repeated interruption safety,
cleanup coverage at every instruction, power-loss safety, deployment restart,
or crash durability.

Inherited run 39336582787/attempt 1 and comment 6595814856 concern the prior
session change, not this patch. CI execution/detail review occurred on
2026-10-20 JST; PR restoration was confirmed on 2026-11-03 JST in the supplied
history. None was re-fetched here. The local 529/461/66/2 history, session RED's
two failures, and the earlier 75 failures remain separate historical evidence.

START-linked shared ownership, continuous record/session ownership, all-caller
history enforcement, normal-operation closure, START retirement, and recovery
remain unimplemented. DS-04 stays PARTIAL; Historical Deep Security Scan stays
INCOMPLETE; the separate 47194b0 report stays FAIL; Production stays BLOCKED,
live handlers hard-off, and the registry empty/fail-closed. No commit, push,
remote/PR/CI operation, build, Google operation, or operational approval occurred.

## External-effect guard supplement — 2026-11-03 JST

Current supplement status: RECORD_BUSY_EFFECT_GUARDS_VERIFIED_NATIVE_PENDING.

The preceding 9,920 bytes are preserved verbatim. Their statement that
credential/provider/network calls were not separately instrumented is accurate
for that earlier validation and is not retroactively rewritten. This supplement
adds measured counters for a finite set of entry points; it does not turn the
earlier static label into historical execution evidence.

Only the test and this appended review changed in this step. The record source
remains exactly 25,727 bytes, SHA-256
`c1f35e2f1dbfe37d1ceb9cee43e5ed7db5d7c47c55c2de1d457bb819d16483b2`,
Git blob `61e9e9aad6622296e03727222044231d25c9db61`.
The source was not reverted and RED was not rerun.

### Fixed monitored attributes

For the project modules below, the common package prefix is
`tridentine_calendar_google_sync.`. Every listed project symbol was confirmed
in the fixed source; these modules are already imported by existing base-layer
memory tests. No provider SDK, authentication client, or refresher was newly
constructed for this monitoring.

| Category | Module | Attribute |
|---|---|---|
| Credential | production_write_token_io | load_production_write_authorized_user_token |
| Credential | production_write_token_io | load_production_write_token_generation_state |
| Credential | production_write_token_io | persist_refreshed_production_write_token |
| Credential | production_write_token_io | write_production_write_token_bundle |
| Provider-facing entry | production_write_token | authorize_production_write_token |
| Provider-facing entry | production_write_token | authorize_production_write_token_mock |
| Provider-facing entry | production_write_token | prepare_production_write_rehearsal_credential_session |
| Provider-facing entry | production_write_token | prepare_production_write_rehearsal_credential_session_mock |
| Network | socket | socket |
| Network | socket | create_connection |
| Network | socket | getaddrinfo |

The provider-facing category is named `provider_entry` in observations.
It measures entry through these four authorization/session attributes, not
direct calls to arbitrary `provider.refresh` implementations. The record
memory reader and publisher remain valid storage doubles and are not included
in the credential category.

### Refusal, calibration, and restoration

Each monitor instance initializes all three category counters and all eleven
fully qualified entry counters explicitly to zero. Each installed callback
first increments its category and entry counters, then raises the same
instance-local `_ExternalEffectBlocked`, derived directly from BaseException.
It neither retains call arguments nor delegates to the original implementation.
The public-call caller checks counters after the monitor has exited, so a
sentinel being caught or converted inside a product path cannot hide an attempt.

All imports, fixture codec preparation, and AST/inspect lookup occur before
monitoring. The guard surrounds the actual public API call, including its owner
cleanup. Pytest observation recording and result assertions run after the guard
has restored the attributes. Normal create/read also record and assert counters
in an outer finally, including an unexpected-exception path.

Eleven parameterized calibration cases use fresh monitor and counter state.
Each calls the installed, actual module attribute with no credentials, host,
or connection arguments. Attribute identity is checked when all sentinels are
installed. A protective underlying probe replaces only the selected original
attribute before the guard is installed: even an accidental forwarding bug
would reach that refusing probe, never a product or network implementation.

In every calibration, exactly the selected category and entry reached one;
all other counters stayed zero. The raised object was the monitor's sentinel.
The protective probe's call count stayed zero. Exiting the guard restored its
saved attributes, then exiting the protective context restored all original
identities. This separately checks installation, triggering, nondelegation,
and restoration rather than treating an untouched counter as evidence.

Each guard saves the current attribute objects, including the socket replacement
already installed by pytest-socket. It restores those exact objects, not an
assumed standard-library default. The existing socket prohibition, strict
settings, and conftest are unchanged. No audit hook, global profiler, socket
allow option, or new skip/xfail was added.

### Measured results for the original ten cases

The original eight interruption combinations and two normal controls are
retained, with all original assertions and parameterization. The seven original
fixture/injection/terminal helper definitions are byte-identical. Public result
classification, cancellation identity, entry/exit 1/1, CLOSED/non-busy/non-held
state, record counters, closed-scope refusal, trace restoration, and normal codec
checks remain in place.

For each of those ten public calls, each of the eleven monitored entry counters
was zero. Each category counter was also zero: credential 0, provider_entry 0,
network 0. Thus there were 110 explicitly recorded zero entry observations across
ten trials, with the separate eleven calibrations establishing triggerability.
That observation count is not an additional pytest count.

All eight interrupted trials still recorded zero held checkpoints, lstat,
preflight, reader, and publisher calls. These record counters are separate from
the external-entry counters. The normal record doubles continued their expected
create/read effects, demonstrating that legitimate memory record operations
were not accidentally blocked. Trace and all local patch identities were restored.

### Final verification for this supplement

Windows/Python 3.12.14 and the expected src reference were rechecked. Installed
pytest 8.4.2, pytest-socket 0.8.1, Ruff 0.16.4, mypy 1.20.2, and pydantic 2.13.4
matched uv.lock. No installation or environment reconstruction occurred.

One final pytest process ran the updated test first, followed by the same full
record, owned-body, reentry, and START/session-boundary files and the three
specified consumer/network-import guards. It used Python `-B`, pytest
`-q -p no:cacheprovider`, the unchanged base marker expression, and a new
dedicated scratch. No previous basetemp or validation root was reused.

| Group | Collected | Passed | Failed/errors | Skipped | Deselected |
|---|---:|---:|---|---:|---:|
| Original interruption/normal cases | 10 | 10 | 0 / 0 | 0 | 0 |
| External-entry calibration | 11 | 11 | 0 / 0 | 0 | 0 |
| Existing operation record | 387 | 331 | 0 / 0 | 56 | 0 |
| Existing owned body | 110 | 110 | 0 / 0 | 0 | 0 |
| Existing reentry | 3 | 3 | 0 / 0 | 0 | 0 |
| Existing START/session boundary | 13 | 3 | 0 / 0 | 10 | 0 |
| Three additional guards | 3 | 3 | 0 / 0 | 0 | 0 |

Measured summary: **537 collected, 471 passed, 0 failed, 0 errors, 66 skipped,
0 deselected; exit 0**. This is the final run's own measurement, not arithmetic
applied to a historical summary. Three synthetic helper-diagnostic checks were
separate from the 21 tests in the updated file.

Whole-repository Ruff check passed with zero diagnostics; format check reported
286 files already formatted. Strict mypy passed for all 124 src files, and Git
whitespace checking passed. An intermediate new-import ordering diagnostic was
corrected only in this test's import block before final execution. No assertions
or checks were weakened.

### Limits and unchanged scope

This monitor observes only the eleven currently bound module attributes during
the selected calls. Previously captured aliases, pre-existing owners holding
references, alternative network entry points, arbitrary provider implementations,
native internals, and adversarial dynamic code are outside its coverage.
It is not a process-wide I/O audit or a general sandbox.

Native record persistence, real lock release, competing processes, and new CI
remain unexecuted; VALIDATION_ROOT_UNAVAILABLE remains unresolved. Existing OS
skips are not native successes. Prior RED, the 526/460/66 result, session-local
history, and the earlier 75 failures retain their original meanings. Run
39336582787 includes neither this record fix nor this measurement supplement.

START-linked and continuous shared ownership, all-caller history enforcement,
normal-operation closure, START retirement, and recovery remain unconnected.
The audit and Production gates above are unchanged. No stage, commit, push,
remote/PR/CI operation, real credential/provider/network operation, Google
operation, or operational approval was performed.
