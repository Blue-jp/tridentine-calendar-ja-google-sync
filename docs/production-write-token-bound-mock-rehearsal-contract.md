# Bound Synthetic Rehearsal Session Admission Contract

- **Status** `DRAFT_CONNECTION_CONTRACT_NOT_IMPLEMENTED_NOT_OPERATIONAL_APPROVAL`
- **Design date** 2026-11-12 JST
- **Repository and branch** `Blue-jp/tridentine-calendar-ja-google-sync` · `security/deep-scan-remediation-47194b0`
- **Fixed HEAD** `1c4f1d40a477f27bbaf868bccbd28bddd89bca1e`
- **Fixed tree** `79ef4b2f239de0c8d50679bdb3820a7c975b99bc`
- **Sole parent** `b8856853555d3de5d1bc79176756468db5cbc6a8`

## Decision and evidence

**PROPOSED.** Admit one test-owned configuration through the existing `run_production_write_token_readonly_rehearsal_mock` caller. Add a private provider that calls the real `_prepare_start_linked_session_mock` once per admitted request. The selected scenario gains START admission before credential reads or refresh, while retaining the rehearsal's session validation and fake list/get. Existing stored-result callers remain available through their existing route.

**CURRENT_SOURCE** identifies fixed-HEAD code. **CURRENT_TEST** identifies fixed-HEAD test definitions read statically. **INHERITED_EVIDENCE** identifies earlier execution and PR records. **PROPOSED** describes work for a separately authorized implementation. **OPEN** identifies decisions that block later work.

The [earlier enforcement plan](production-write-token-post-start-enforcement-plan.md) was verified as 50,732 bytes, SHA-256 `72544b3a6aed39a5758c7d448e6b67be1eb40f23db9683490305f92188666cf0`, blob `716a6aaf2aa939bac2edc1b157ac617247821afd`. Its opening describes the earlier public success path. Option 2 is deferred there and the later implementation record documents completed Option 1. At this HEAD, the public provider prepare validates target and exact confirmation, then raises `ProductionWriteTokenConfigError` with code `production_write_token_provider_session_enforcement_unavailable` and message `Production write-token provider session preparation is unavailable` before UTC, path, lock, credential or session work. [Option 2](production-write-token-post-start-enforcement-plan.md#L74-L85), [Option 1 implementation](production-write-token-post-start-enforcement-plan.md#L165-L171), [current public wrappers](../src/tridentine_calendar_google_sync/production_write_token.py#L1296-L1354)

## Fixed-HEAD connection points

| Evidence and fixed-HEAD source | Current interface and caller | Gap or test impact |
| --- | --- | --- |
| **CURRENT_SOURCE** [Rehearsal wrapper](../src/tridentine_calendar_google_sync/production_write_token_rehearsal.py#L730-L791), blob `92760926acab301a26308e2c9033620f2f67e21a` | Keyword-only `run_production_write_token_readonly_rehearsal_mock(credential_session_provider, transport_provider, target, manifest, accepted_profile, accepted_source, trusted_baseline, confirmation) -> ProductionWriteTokenRehearsalOutcome`. The [existing fixture caller](../tests/phase6d0_rehearsal_helpers.py#L114-L129), blob `414be69866151fd45389d0a90f67d5738e1405ed`, passes a stored-result provider. | It validates target first and exact read confirmation next. After both provider checks it calls `load_session(target=target)` once. It supplies neither pair nor operation nor confirmation to the provider method. |
| **CURRENT_SOURCE** [Provider protocol](../src/tridentine_calendar_google_sync/production_write_token_rehearsal_models.py#L248-L263), blob `c7e705a59c2cadd8cb4421784c391db1f6a63b98`, and [fake providers](../src/tridentine_calendar_google_sync/production_write_token_rehearsal_transport.py#L179-L230), blob `9827f37a97c929f0fc35fdbd2abe8d6e3bc367a5` | `load_session(*, target: ProductionWriteTargetConfig) -> ProductionWriteCredentialSession`. The existing fake ignores target, increments `load_count`, then returns the stored session or raises the stored exception. `build_transport(*, session, target)` counts a build and returns the scripted transport already held by the fixture. | [Provider gate](../src/tridentine_calendar_google_sync/production_write_token_rehearsal_transport.py#L300-L317) uses `isinstance` for both fake providers, requires mock-only and non-live flags, and checks zero browser launches on the credential provider. Add explicit admission for the new private concrete type. |
| **CURRENT_SOURCE** [Session check](../src/tridentine_calendar_google_sync/production_write_token_rehearsal.py#L180-L236) and [inner rehearsal](../src/tridentine_calendar_google_sync/production_write_token_rehearsal.py#L602-L697) | The wrapper checks session type, role, exact scopes, generation and target binding, mock grant origin and counters before building the transport. The inner call rechecks session and confirmation, checks the [exact fake transport and forbidden capabilities](../src/tridentine_calendar_google_sync/production_write_token_rehearsal_transport.py#L273-L297), then checks manifest/source and baseline before the [first list](../src/tridentine_calendar_google_sync/production_write_token_rehearsal.py#L370-L385). Snapshot and source verification precede get. | Today manifest/baseline refusal follows provider load and build. The bound route needs an earlier in-memory check before START can be published. The existing legacy order stays in place. |
| **CURRENT_SOURCE** [Linked coordinator](../src/tridentine_calendar_google_sync/production_write_token.py#L1828-L1948), blob `33fe17c21c4bfbd11c1b9a913a8864e64a6f3b0d` | `_prepare_start_linked_session_mock(production_write_token_path, generation_state_path, production_read_token_path, test_write_token_path, target, confirmation, *, now, refresher, binding, operation) -> ProductionWriteCredentialSession`. The [direct test caller](../tests/test_token_start_linked_session_phase6d1h.py#L309-L337), blob `5b617735923aa58a3273a298f2ea76b7a6cfbb1c`, supplies all inputs. | The rehearsal currently supplies none of the binding, operation, ordered paths, clock or refresher required here. The [context factory](../src/tridentine_calendar_google_sync/production_write_token.py#L1612-L1729) checks target, confirmation, platform, UTC, path set, fake refresher and linked layout before record ownership. |
| **CURRENT_SOURCE** [Binding and operation](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py#L49-L84) and [linked layout](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py#L935-L990), blob `73a830c5952bbf03314328e34f596387f641262b` | Token and state paths share the bound directory and match ordered slot names. The operation is REFRESH with an explicit predecessor. The linked coordinator owns entry, START and finalization. | Carry independent expectations from fixture setup. An observation, including `reuse_authorized=False`, grants no permit. |

## Setup and request boundary

**PROPOSED.** Keep the new configuration and provider private in `production_write_token.py`. The fixture author passes independent expectations to the factory before exposing a request through the selected rehearsal.

```python
def _bind_mock_rehearsal_session_provider(
    *,
    binding: records.SyntheticBinding,
    operation: records.RecordOperation,
    production_write_token_path: Path,
    generation_state_path: Path,
    production_read_token_path: Path,
    test_write_token_path: Path,
    target: ProductionWriteTargetConfig,
    confirmation: str,
    now_utc: Callable[[], datetime],
    make_refresher: Callable[[], ProductionWriteTokenRefresher],
) -> _BoundMockRehearsalSessionProvider: ...


class _BoundMockRehearsalSessionProvider:
    def load_session(
        self, *, target: ProductionWriteTargetConfig
    ) -> ProductionWriteCredentialSession: ...
```

| Fixture retains | Ordinary request and refusal |
| --- | --- |
| One detached snapshot of `SyntheticBinding` (directory, storage reference, pair reference and ordered token/state slots), the four exact ordered path values, and a detached REFRESH `RecordOperation` with explicit, distinct operation and predecessor IDs. | The provider handle selects one pair. The request supplies no pair, path, storage, operation or predecessor argument. At setup check exact value types, valid binding and operation, REFRESH, lexical directory/leaf equality in order, and the distinct role paths before any storage effect. The real linked path still performs its own path and layout checks. |
| A detached, validated target reconstructed from its full field values and its exact read confirmation. Keep the full target hash privately for comparison. | The wrapper still accepts and checks the caller's target and confirmation. At provider entry compare the fully validated target hash with the retained hash before linked preparation. The provider passes its own retained target and confirmation to linked prepare. A short target reference or the confirmation alone cannot bind all target fields. Copy the excluded Calendar ID, expected fingerprint and summary fields explicitly when reconstructing the target. [Full target hash and target validation](../src/tridentine_calendar_google_sync/production_write_target.py#L78-L147) |
| A fixture-owned clock and factory for an in-memory fake refresher. Keep these adapter references distinct from the immutable configuration. Each admitted call obtains one aware UTC value after request binding checks and before linked entry. The fixture supplies a fresh fake with zero initial attempts and calendar/browser activity for each call. | The caller supplies neither time nor refresher. The linked preflight still validates platform, time and fake flags, and the held loader uses the sampled time for expiry and refresh validation. The test clock is under fixture control. Mutable fake counters belong to one attempt, and the provider supplies the wrapper's safe per-call refresh count of 0 or 1 and browser count of 0. The held loader still checks the fake's own counters. [Held loader](../src/tridentine_calendar_google_sync/production_write_token.py#L1129-L1266) |
| The fixture selects the exact transport provider and holds the bound provider it injects. The immutable snapshot owns its value fields. The clock, factory and per-attempt fake have a fixture ownership contract. | The wrapper accepts ordinary manifest, profile, source and baseline values. Check their existing in-memory provenance contract before the bound load. Reject a mismatched target, swapped layout or invalid setup before START or credential content effects. Credential/state facts and conflicts with a retained START can only be observed later at their existing lower checkpoints. |

Capture value fields without consulting token, state or START and without deriving operation ID from generation. Caller rebinding or mutation of the original value objects must not alter the retained values. The clock and factory references are deliberately retained and must stay fixture-owned. The setup contract excludes arbitrary in-process mutation and live-capable adapters. Fixture equality checks establish expected values for this synthetic test. Deployment authority requires independent provenance.

Confine the provider to its creating process and thread. Reject overlapping or recursive entry before clock, refresher or linked entry. Keep the active guard through linked return or unwind and clear it without throwing. The provider exposes the per-request fake's attempt count through a nonthrowing bounded observation. Counter reporting and active-guard cleanup must never replace the linked outcome. Keep no session, owner, context or exception for reuse. An independent later request can run the same immutable setup with fresh attempt state, but the occupied START slot rejects it before credential reads. Replace configuration only by constructing a new provider while the fixture is quiescent and retiring the old reference. Replacement neither clears START nor automatically selects a different directory, slot or operation.

## Call order and ownership

```text
CURRENT
rehearsal wrapper -> target / confirmation -> existing fake-provider gate
  -> load stored session or raise stored error -> validate session
  -> fake transport build -> inner checks -> fake list / get

PROPOSED BOUND ROUTE
fixture setup -> rehearsal wrapper -> target / confirmation -> explicit provider gate
  -> early manifest / source / baseline checks -> bound load(target)
  -> full target match, fresh time and fake -> real linked preflight
     [record lock acquired by parent entry
      -> START exclusive create and readback -> held child / owner
      -> credential reads and expiry branch -> optional fake refresh and writer
      -> child exit -> final checkpoint -> parent backend exit / lock release]
  -> linked finalization completes -> session returns -> wrapper validates session
  -> fake transport build -> existing inner checks -> fake list / get
```

The shared lock protects preparation from parent entry through backend exit. Parent exit invalidates ownership and releases the backend before session delivery. The later rehearsal checks and synthetic reads run outside that lock. START remains after a successful exit. An occupied slot refuses even when the recorded operation matches. The bound provider has one linked invocation per admitted request, zero preparation retries and zero fallback. The existing bounded fake-read retry remains a separate behavior. [Parent entry and exit](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py#L886-L909), [START creation](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py#L1077-L1125), [release and finalization](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py#L1475-L1608), [read retry](../src/tridentine_calendar_google_sync/production_write_token_rehearsal.py#L309-L322)

The provider lets the linked outcome reach the wrapper without substitution. Preserve writer exception **W** through the persistence boundary, the held loader's persistence exception **P** and its publication value (true, false or unknown), the first cancellation object, the original backend exit triple, and the parent's diagnostic and candidate-withholding rules. The wrapper maps refresh errors, including P, to `TOKEN_REFRESH_FAILED` with the existing code and safe counters. Other ordinary exceptions follow the existing safe-code mapping. `_ScopeFailure` has a typed result and no code, so lower `SLOT_OCCUPIED` and `UNSUPPORTED_PLATFORM` become upper `INPUT_BINDING_MISMATCH` with `production_rehearsal_token_session_failed`. Non-`Exception` cancellation propagates. Tests can observe lower identity and publication with a delegating probe and assert the upper result separately. [Writer boundary](../src/tridentine_calendar_google_sync/production_write_token.py#L1774-L1825), [scope failure](../src/tridentine_calendar_google_sync/production_write_token_operation_record.py#L291-L299), [upper mapping](../src/tridentine_calendar_google_sync/production_write_token_rehearsal.py#L524-L547), [W/P contract](production-write-token-start-linked-session-contract.md#L355-L437)

## Implementation review scope

| Planned path | Proposed edit and preserved boundary |
| --- | --- |
| [production_write_token.py](../src/tridentine_calendar_google_sync/production_write_token.py#L1828-L1948) | Add private snapshot, `_bind_mock_rehearsal_session_provider` and final `_BoundMockRehearsalSessionProvider` next to the linked coordinator. Keep existing prepare signatures/exports, public refusal, explicit mock and private provider-origin paths, linked lifecycle, held loader and writer bodies intact. Use fixed content-free refusal codes `production_rehearsal_bound_target_mismatch` and `production_rehearsal_bound_provider_use_invalid` for target mismatch and provider misuse. |
| [production_write_token_rehearsal_transport.py](../src/tridentine_calendar_google_sync/production_write_token_rehearsal_transport.py#L300-L317) | Extend `require_phase6d0_rehearsal_providers` to accept the exact new type alongside the current fake branch. Keep legacy predicates. For the bound route require the exact existing fake transport provider and check its already-retained adapter with the existing capability guard without calling build. Keep mock-only, non-live and browser-zero checks. Reject generic, spoofed and inherited bound provider types. |
| [production_write_token_rehearsal.py](../src/tridentine_calendar_google_sync/production_write_token_rehearsal.py#L730-L791) | After confirmation and the provider gate, run existing manifest/source and baseline verification early for the bound type only. Reuse the full target fingerprint for baseline verification. Preserve the existing post-load validation and inner recheck, public signature and report schema. |
| [test_production_write_token_rehearsal_phase6d0.py](../tests/test_production_write_token_rehearsal_phase6d0.py#L52-L99), blob `228424cdf70f421d5abdee7ea8347220f317799a` | Add bound admission, real-wrapper connection, failure and platform acceptance plus an exact bridge guard in the existing `google_production_write` layer. Retain the stored-fake pagination and failure tests. Reuse the existing fixture data and actual fake transport. |

The wrapper already imports token and transport modules. Transport can import the new class from token inside the gate. Token keeps its existing function-local import of rehearsal confirmation, reached after module initialization during setup or linked prepare. The record module gains no import or consumer. Keep the exact `{"production_write_token.py"}` consumer guard and the lock/publisher allowlists. The new bridge guard should allow one runtime call to `_prepare_start_linked_session_mock` from `_BoundMockRehearsalSessionProvider.load_session` in token, verify the wrapper's one `load_session(target=target)` and reject other routes from the bridge to the legacy loader or direct record, writer and backend functions. Keep the existing legacy loader ownership guard. [Record consumer and backend guards](../tests/test_token_operation_record_phase6d1h.py#L392-L488), blob `d3f96b2b6e2e5df8f58eda8f1f225c39e430a142`. [Legacy ownership guard](../tests/test_credential_session_lock_phase6d1h.py#L483-L619), blob `a304108b8041551193afd2f3a30d50c86ab17104`.

Implementation requires separate approval for the new concrete admission, the bound-only earlier refusals, the fixture's clock/fake and actor contract, and the bridge guard. The packaged registry, bootstrap, CLI, startup and live paths remain outside the connection.

## Proposed acceptance

| Layer | Required assertions |
| --- | --- |
| Memory-only refusal and setup | Exercise actual wrapper target/confirmation order, generic/spoofed providers, unsafe transport, mismatched manifest/baseline, a fully valid other target and a changed target field with the same short reference. Reject swapped slots, another pair's path set, invalid operation/predecessor and caller override keywords before record or credential effects. Test invalid UTC before lower effects on the supported platform path. Verify snapshot detachment, same-provider reentry from a fixture adapter, actor refusal and idle setup replacement. A valid different operation over an occupied slot must still refuse. |
| Memory-only real connection | Use the existing four-event, single-page rehearsal data and its zero-diff baseline. The bound branch must have no stored-session input. Seed synthetic token/state for that same target and inject only the bound provider into the actual wrapper. Run unexpired and expired cases with separate fresh fixture state. Delegate to the actual linked coordinator, replacing only storage seams. Assert START create/readback before credential reads, one parent entry/exit, and exit before build and list. Expect READY, one build, one list, one get and zero mutation. Expect zero refresh/writes for unexpired and one fake refresh and one save for expired. The expired response uses test-fixture refresh provenance, future expiry and matching client identity. |
| Memory-only terminal cases | Occupancy, writer fault, and pre-save cancellation with zero build/read, zero legacy fallback and zero preparation retry. Check the lower record state, W/P and publication evidence, first cancellation identity and parent cleanup separately from the upper report or propagated object. After a successful return run a second independent request against the same retained START. Require occupancy, no extra credential reads or save, and unchanged START. Check reentry and exceptions do not leave the provider busy. |
| Linux native and independent process | In an authorized test-owned private scratch directory, use real POSIX locking, real START publication/readback and real token/state I/O. On expired success delegate to the real writer. Keep writer-fault injection and pre-save cancellation as separate cases. Check same-process and independent-process contention after START while preparation holds the lock. Verify backend exit and independent reacquisition at or before fake build. In another fresh child, construct the same independent fixture expectations and use the real wrapper with the retained START. Require lower occupancy, safe upper refusal and zero new credential reads, refresh, writes or fake reads. The lock-only child probe and the full fresh-request child prove different properties. |
| Actual Windows and existing regressions | Run the real platform gate without substituting Linux availability. Require unsupported platform before path preflight, START, credentials, fake build or reads. Preserve the public provider fixed-refusal and private provider-origin controls, explicit mock, ownership/W/P/finalization, and existing rehearsal read, retry and hard-off tests. Keep platform-substituted memory results separate from native evidence. |

**CURRENT_TEST.** The [one-page rehearsal](../tests/test_production_write_token_rehearsal_phase6d0.py#L74-L99) supplies a READY reference. The [fixture builder](../tests/phase6d0_rehearsal_helpers.py#L46-L111) currently also prepares a stored-result session. The bound scenario reuses its rehearsal data and scripted reads while passing only the bound provider. The linked tests define [memory order and retention](../tests/test_token_start_linked_session_phase6d1h.py#L389-L424), [Windows refusal](../tests/test_token_start_linked_session_phase6d1h.py#L486-L504) and [native child and fault controls](../tests/test_token_start_linked_session_phase6d1h.py#L1225-L1344). Keep the [public and private controls](../tests/test_token_session_owned_body_phase6d1h.py#L377-L716) and run the future integration under the existing [production-write selector](../.github/workflows/test.yml#L48-L55).

Count logical effects at named seams and distinguish the fake list/get counts from network activity. Use calibrated tripwires on session fallback, auth/browser, sockets and Google client/API construction or calls, plus the existing socket-disabled test boundary. Account for fixture seeding outside the observed attempt. The only proposed subprocesses are test-owned, bounded probes. Record platform, selectors and which seams were real or substituted. These acceptance cases have not been run for the proposal.

## Inherited evidence and open decisions

**INHERITED_EVIDENCE.** PR #17 was checked at 2026-11-12 09:42:30 JST as 39 commits, Open, Draft, unmerged and auto-merge null. At the fixed head, run 43036202148 attempt 1 recorded eight successful jobs. Both base and both production-write logs were reviewed. The remaining four jobs were `METADATA_ONLY`. Both OSes recorded 29 grant-provenance and 123 owned-body passes in their applicable jobs. The two migrated storage cases and three Linux native cases are `FILE_LEVEL_SUPPORTED`. Individual node/JUnit `DIRECT_NODE_RESULT` was unavailable. Local Windows/Python 3.12.14 runs (base 661 collected, 592 passed, 69 skipped, selected production-write 12/12, before-change control 1/1) retain their separate history, including locally unrun storage, native and full regression cases. This CI predates the proposed connection. [Run](https://github.com/Blue-jp/tridentine-calendar-ja-google-sync/actions/runs/43036202148/attempts/1), [saved evidence comment](https://github.com/Blue-jp/tridentine-calendar-ja-google-sync/pull/17#issuecomment-6810827122)

| OPEN decision | What it blocks |
| --- | --- |
| Maintainer approval for the bound setup and earlier ordinary-input refusal | Implementation of this one synthetic connection. The protocol still allows direct calls by holders of the private provider object and retains the legacy fake branch. Exclusivity or all-caller enforcement requires a separate contract. |
| Whether later rehearsal reads require continuous ownership | Any extension of the parent's lifetime through transport work. The current session-return interface ends ownership before the wrapper reads. |
| Deployment provenance, authorized setup/restart, Windows parity and durable operation disposition | Live setup, START retirement or recovery, repeated managed operations and re-enabling the public prepare entry. Pair inspection, reuse policy and disabled-bootstrap observations do not supply approval. |
| Original DS-04 finding and formal close criteria | Finding-specific validation and audit closure. Both remain unconfirmed. |

DS-04 remains PARTIAL. Historical Deep Security Scan remains INCOMPLETE. The separate 47194b0 scan report remains FAIL. Production remains BLOCKED, live handlers hard-off, and the packaged registry empty / fail-closed.

## Authorized bound-provider connection: implementation and validation evidence

**Implementation date** 2026-11-12 JST. The user authorized one connection through the existing mock rehearsal wrapper, the exact new provider gate, bound-only early validation, and synthetic acceptance. The preceding design is the historical 25,489-byte prefix.

### Implementation

The private `_bind_mock_rehearsal_session_provider(*, binding, operation, production_write_token_path, generation_state_path, production_read_token_path, test_write_token_path, target, confirmation, now_utc, make_refresher) -> _BoundMockRehearsalSessionProvider` issues one final concrete provider. Its request is `load_session(*, target: ProductionWriteTargetConfig) -> ProductionWriteCredentialSession`. It holds a frozen snapshot of copied binding and explicit REFRESH operation/predecessor, four ordered paths, all nine independently reconstructed target fields, the full target hash and the exact confirmation. Setup checks the binding and operation, lexical layout and distinct role paths, including the reserved START leaf. The bound factory and request require the exact target model so custom subclass descriptors cannot enter the provider during validation. The factory validates and reconstructs the target and verifies confirmation. It does no path inspection or credential/record I/O and calls neither fixture adapter. No ID is learned from state, generation or START.

The provider retains fixture-owned clock and fake factory references separately from the snapshot. Their behavior and fresh fake identity are a fixture contract. Implementation checks callability and each returned fake's initial mock/live flags, callable refresh and exact zero integer refresh, browser and Calendar counts. The real linked preflight and held loader still inspect the fake's forwarded attributes. The provider compares the requested full target hash before clock or fake creation, samples time once and creates one attempt fake. The existing linked preflight retains its platform-before-UTC/path order. The provider accepts its creating PID and live Thread object, denies reentry or use by another actor before mutating state, and clears the active marker in the accepted try/finally. Supported replacement uses a new provider. A second independent use of the same setup starts a fresh attempt and remains subject to the retained START slot.

The private dispatch adapter counts one logical refresh immediately before delegating to the fake. The upper wrapper reads the provider's plain per-attempt integer. This records an attempted dispatch, including one that raises or leads to failed persistence. It makes no claim about completion of a fake or a remote refresh. No adapter getter is called to collect a report or to clear active state. The held loader still reads the underlying fake's own flags and counters at its existing checks. The provider forwards the linked return or exception and retains no session, owner, context or exception. This covers accepted synchronous attempts and their observed cancellations under the fixture contract. Arbitrary in-process mutation and asynchronous interruptions of Python cleanup itself are outside that contract.

The new fixed errors use `ProductionWriteTokenConfigError`.

| Code | Public message | Wrapper result |
| --- | --- | --- |
| `production_rehearsal_bound_target_mismatch` | Bound synthetic rehearsal target does not match | `TARGET_MISMATCH` |
| `production_rehearsal_bound_provider_use_invalid` | Bound synthetic rehearsal provider use is invalid | `INPUT_BINDING_MISMATCH` |

The gate accepts the exact initialized bound type and exact existing fake transport provider, checks flags and browser-zero, and inspects the retained adapter through the existing fake-transport guard without loading or building. Legacy stored-result admission keeps its existing predicates. The wrapper checks target, confirmation, provider gate and then the existing manifest/source and baseline validators for the exact bound type before the single load. The existing post-load session validation, transport build and inner verification precede list/get. The public provider prepare refusal and explicit mock prepare remain as before. [Provider](../src/tridentine_calendar_google_sync/production_write_token.py#L1971-L2066), [factory](../src/tridentine_calendar_google_sync/production_write_token.py#L2128-L2209), [gate](../src/tridentine_calendar_google_sync/production_write_token_rehearsal_transport.py#L300-L349), [wrapper](../src/tridentine_calendar_google_sync/production_write_token_rehearsal.py#L731-L801)

The actual linked coordinator acquires the record-owned lock on parent entry, publishes and verifies START, runs held preparation, performs the final checkpoint and exits the backend before delivering a session. The wrapper's build and synthetic list/get happen after that exit. The bridge invokes no legacy loader, record primitive, writer or backend directly. The existing lower W/P, publication, first cancellation, exit triple and candidate withholding remain authoritative. A lower `_ScopeFailure` still becomes the generic `INPUT_BINDING_MISMATCH` with `production_rehearsal_token_session_failed`; refresh P remains a `TOKEN_REFRESH_FAILED` report and a non-`Exception` cancellation propagates. [Linked coordinator](../src/tridentine_calendar_google_sync/production_write_token.py#L1828-L1948)

### Local validation

The existing Windows virtual environment reported Python 3.12.14 and resolved the package to this worktree. Installed metadata matched `uv.lock` for pytest, pytest-socket, Ruff, mypy, Pydantic and its core, icalendar, google-api-python-client, google-auth, google-auth-httplib2, google-auth-oauthlib, httplib2, requests, tzdata and typing-extensions. Pytest used Python `-B`, no cache provider, existing strict configuration and markers, and the existing socket prohibition. Each process used a fresh ordinary test-owned scratch location. No independently authorized, guard-compliant private validation root was established in this turn.

| Execution | Collected | Passed | Failed | Errors | Skipped | Deselected | Exit |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Preliminary base, before the exact bound target type check | 661 | 592 | 0 | 0 | 69 | 0 | 0 |
| Final base, six named files and nine specified guard nodes | 661 | 592 | 0 | 0 | 69 | 0 | 0 |
| Preliminary related production-write selection | 39 | 39 | 0 | 0 | 0 | 0 | 0 |
| Initial rehearsal production-write selection | 65 | 59 | 1 | 0 | 3 | 2 | 1 |
| Windows refusal diagnosis, single node | 1 | 0 | 1 | 0 | 0 | 0 | 1 |
| Final rehearsal production-write selection | 65 | 60 | 0 | 0 | 3 | 2 | 0 |
| Final related production-write selection | 39 | 39 | 0 | 0 | 0 | 0 | 0 |

The initial rehearsal total is the sum of its measured outcome categories. Its real Windows test trapped the context function that contains the platform gate. The revised test permits both linked entry functions and monitors the downstream path and record seams. The final rehearsal selection covered 21 existing stored-fake cases, 36 new memory, pure or structural cases and one actual Windows refusal. The two deselections were `test_refresh_failure_returns_safe_stop_without_client_or_api` and `test_report_snapshot_and_output_are_redacted_atomic_and_no_overwrite`, which use the guarded private report writer. Their definitions remain intact. Linux native success, writer fault and cancellation were three OS skips. Their independent lock and fresh-wrapper child probes did not run locally.

The final related production-write run included the full rehearsal fail-closed file and the following exact nodes. Other grant-provenance and token-refresh cases that use real guarded storage remain locally unrun for this change.

- Grant provenance: `test_exact_fresh_provider_response_evidence_is_separate_from_requested_scope`, `test_missing_empty_duplicate_broad_readonly_or_ambiguous_evidence_is_rejected`, `test_operational_entry_points_expose_no_arbitrary_authorizer_or_refresher`, and `test_public_provider_prepare_refuses_before_provenance_reload`.
- Token refresh: `test_rehearsal_confirmation_mismatch_precedes_token_load_and_refresh` and `test_oauth_and_refresh_protocols_expose_no_calendar_or_mutation_methods`.
- CLI hard-off: `test_authorization_command_stops_before_reading_inputs_or_network` and `test_rehearsal_command_stops_before_refresh_inputs_or_calendar`.

The memory cases exercised the real wrapper, provider, linked coordinator, held loader and fake transport. They substituted the supported-platform predicate, synthetic path checks, record lock, START leaf lookup, publisher and reader, state/token readers and writer. Role, scope, generation and grant checks, rendering, construction and lower finalization were real. Both fresh expiry branches produced READY with one build, list and get, zero mutations and one parent acquisition/exit. Unexpired made zero refresh/save calls. Expired made one dispatch and one save with test-fixture refresh evidence. The tests observed START before the credential reads and backend exit before delivery, build and read. A second request and a newly configured provider with a different operation both received lower SLOT_OCCUPIED and the fixed upper input refusal before additional credential, refresh, write, build or read. No session fallback or preparation retry was observed. [Connection and repeat refusal](../tests/test_production_write_token_rehearsal_phase6d0.py#L962-L1039)

The writer-fault tests observed W, held P, all three publication values and the retained dispatch count. Pre-save cancellation preserved the first object through a second exit cancellation. Clock and fake-factory ordinary and cancellation outcomes cleared accepted activity, with no lower entry. Reentry, a real other thread and a synthetic PID mismatch were refused without resetting the accepted actor. The actual Windows node observed lower UNSUPPORTED_PLATFORM and the generic upper refusal before paths, START, credentials, build or reads. The Linux definitions retain real lock and START/storage, real success writer, fault double, and pre-save cancellation, plus bounded child lock contention/reacquisition and a fresh bound request against retained START. [Failure and actor cases](../tests/test_production_write_token_rehearsal_phase6d0.py#L1081-L1310), [Windows and Linux cases](../tests/test_production_write_token_rehearsal_phase6d0.py#L1313-L1551)

The monitor calibration fired every named sentinel once with zero delegation and verified restoration. It covers the finite legacy/fallback, live authorization, browser, socket, Google client/API and setup/storage seams named in D. Accepted memory tests separately count synthetic effects and reported zero monitored forbidden effects. The monitors and pytest socket prohibition describe the observed entrances and windows. Fixture seeding is separate from the request counts. [Calibration](../tests/test_production_write_token_rehearsal_phase6d0.py#L539-L601), [bridge guard](../tests/test_production_write_token_rehearsal_phase6d0.py#L1554-L1669)

Full Ruff lint passed. Ruff format passed for all 261 source and test files. Full format check reported one historical change at line 44 of this document's preserved prefix, a blank line in the Python example. That prefix is intentionally byte-for-byte preserved. Strict mypy passed on the three changed source modules and all 124 source files. `git diff --check` passed. Byte and AST checks preserve A's existing definitions and export list, B's legacy branch and other definitions, C's other definitions and wrapper signature, and D's existing marker and tests. The record component, writer, backend and consumer allowlists retain their fixed-HEAD bytes.

Run 43036202148 attempt 1 and evidence comment 6810827122 are inherited public-refusal evidence. This connection was tested only in the local runs above. The earlier local unrun history remains historical. A holder can still call the private provider directly, and the legacy stored-result and explicit mock paths remain. Continuous ownership through later reads, deployment authority, START removal or recovery, public provider reopening, and audit closure require separate decisions. DS-04 stays PARTIAL, the historical scan INCOMPLETE, the separate 47194b0 report FAIL, Production BLOCKED, live handlers hard-off and the registry empty / fail-closed.

## Review correction: validation accounting and format evidence

This section supersedes the earlier inaccurate category subtotal in the implementation validation record. The previous subtotal of 21 existing passes was incorrect.

The verified final rehearsal production-write selection remains 65 collected, 60 passed, zero failed, zero errors, three skipped, two deselected, exit code 0.

| Category | Collected | Passed | Skipped | Deselected |
|---|---:|---:|---:|---:|
| Existing rehearsal tests | 25 | 23 | 0 | 2 |
| New memory, pure validation and structural guard tests | 36 | 36 | 0 | 0 |
| Actual Windows refusal | 1 | 1 | 0 | 0 |
| Linux native tests | 3 | 0 | 3 | 0 |
| Total | 65 | 60 | 3 | 2 |

The existing 25 cases consist of 12 non-parameterized test definitions and parameter expansions of 3, 3 and 7 cases. The two deselected cases are `test_refresh_failure_returns_safe_stop_without_client_or_api` and `test_report_snapshot_and_output_are_redacted_atomic_and_no_overwrite`.

The new test definitions comprise 36 memory, pure validation and structural guard cases, one actual Windows refusal case, and three Linux native cases. The Linux native cases were skipped on Windows and were not executed locally. Their independent child-process and native lock behavior remains unverified by this local run.

The correct successful subtotal is 23 + 36 + 1 = 60. This correction does not change the aggregate pytest result or imply any additional test execution.

### Ruff format evidence

The targeted source/test command `python -B -m ruff format --check src tests` completed with exit code 0 and reported 261 files already formatted.

The repository-wide command `python -B -m ruff format --check --no-cache .` completed with exit code 1 and reported one file would be reformatted and 289 files already formatted.

The diagnostic command `python -B -m ruff format --check --no-cache --diff .` also completed with exit code 1. Its only affected file was `docs/production-write-token-bound-mock-rehearsal-contract.md`. Ruff proposed one additional blank line between the factory function signature ending at line 45 and the following class declaration at line 47 in the preserved Python example.

No formatting was applied. The discrepancy is inherited from the preserved original documentation prefix. The targeted source/test formatting check passes, but repository-wide formatting remains unsuccessful. The original 25,489-byte design prefix remains unchanged.

This correction is documentation-only. It does not change the implementation, test definitions, test outcomes, operational authorization, audit status or Production gate.

## Authorized one-line formatting correction

On 2026-11-13 JST, the user explicitly authorized one LF insertion in the original design's Python example. The insertion adds a second blank line between the factory signature and the provider class declaration. The rest of the existing document, including the earlier validation and correction records, was retained byte for byte.

The pre-edit document was 40,607 bytes. Its SHA-256 was `7069f3fe9a32eaef7856ba955b128d164669617e8180416ffdf4a985e87c485c` and its raw Git blob was `98c42854586c76cb413f77acae2309b06c346998`. After the insertion and before this entry, the document was 40,608 bytes. Removing the inserted LF from a comparison copy restored all 40,607 original bytes and the recorded SHA-256 hashes of the historical 37,958-byte and 25,489-byte prefixes.

The earlier repository-wide format failure remains part of the historical record. After the insertion and before appending this entry, Ruff 0.16.4 ran `python -B -m ruff format --check --no-cache .`. It exited 0 and reported `290 files already formatted`. A separate repository-wide format check will verify the final saved document, with the result reported in the task summary.

Runtime code, test definitions, historical pytest results and unrun cases, audit findings, and the Production gate remain unchanged.
