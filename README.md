# 1960 Roman Liturgical Calendar – Japanese Edition: Google Calendar Differential Sync Tool

`Google Calendar Differential Sync Tool for the 1960 Roman Liturgical Calendar – Japanese Edition`

This repository provides a dedicated tool for future safe differential synchronization of the Accepted Japanese Roman liturgical calendar with Google Calendar.

## Scope of Phase 6D.0

Phase 6D.0 adds only the code foundation for dedicated Production write-token authorization and read-only rehearsal using that token, without connecting the Phase 6C mock-only transport to live patch operations. Token roles, the exact `calendar.events.owned` scope, storage outside the repository, opaque generations, cross-binding between a full snapshot and a Trusted Baseline, zero differences from the Accepted Source, and a deterministic fresh get are verified using only mock OAuth, fake services, and synthetic data.

The authorization and rehearsal CLI surfaces remain live hard-off in Phase 6D.0. Real OAuth, token creation, browser authorization, Calendar API calls, Production Calendar access, operational ARM / EXECUTE, and patch operations cannot be performed. The existing Production write hard lock, default-off kill switch, and unavailability of Add / Delete also remain in place. See [Production single-update planning foundation](docs/production-single-update-planning-foundation.md) for the Phase 6B artifact boundaries, [Production single-update transport foundation](docs/production-single-update-transport-foundation.md) for the Phase 6C mock execution semantics, and [Production write-token read-only rehearsal foundation](docs/production-write-token-readonly-rehearsal-foundation.md) for the Phase 6D.0 boundaries. A repository-wide Deep Security Scan is required after merge and before Production OAuth.

Sensitive runtime artifacts on Windows require handle-based verification of every ancestor, including junctions/reparse points, preservation of identity throughout the operation, a protected DACL for the current user in place before any secret is written, and rejection of unsafe parent ACLs. See [Windows sensitive filesystem security](docs/windows-sensitive-filesystem-security.md) for details.

### Implemented

- Verification of the SHA-256 of raw bytes before parsing
- VEVENT parsing with an RFC-compliant parser
- Validation of counts, UIDs, date ranges, and property structure against an Accepted source profile
- Human-readable and JSON reports that keep content confidential
- Closed-schema validation of sanitized snapshots and a canonical Google event model
- Deterministic difference classification using Source UIDs and Google `iCalUID`
- Aggregate counts of `unchanged`, `add`, `update`, `delete_candidate`, duplicate, ambiguous, unmanaged, and fatal guard results
- Diff reports without raw UIDs, Google event IDs, titles, or descriptions
- A base installation fully separated from the optional `google-read` dependency extra
- A desktop OAuth boundary that permits only `calendar.events.owned.readonly`
- An `events.list`-only client, full pagination, bounded retries, and a target identity guard
- Conversion of raw API responses into sanitized snapshots using an allowlist
- Private atomic snapshot writes outside the repository, with no overwrite by default
- Candidate baseline creation from an exact zero-difference audit
- A candidate-to-trusted transition using an exact confirmation phrase
- Offline diff that uses only trusted baselines as ownership evidence
- A non-executable sync plan with threshold, mass-change, ambiguity, and unmanaged guards
- An integrity-pinned private apply bundle containing only Add/update operations
- An exact test-only approval challenge and a stale plan hash guard
- Fake mutation simulation with bounded abstract retries
- A hash-chain journal that records partial failures and the skipped remainder
- Redacted bundle/simulation/journal reports
- Synthetic fixture tests without Production data
- A Test write authorization boundary separated from Production read tokens that permits only `calendar.events.owned`
- A 1-operation run spec bound to the Test target config, Production hard lock, and exact approval
- A Google adapter restricted to `events.import` for Add and `events.patch` for Update
- Preservation of Source UID / Google `iCalUID`, fresh event ID / ETag, and exact `If-Match`
- Post-write read-back, read-after-check for uncertain outcomes, and a prohibition on blind mutation retries
- Test write journals / reports that exclude raw identities, ETags, and content
- Mock-only Test write safety tests that cannot reach Production
- A dedicated prewrite inspection boundary that uses a Test write token and exposes only `events.list`
- Write-readiness validation for an empty Test Calendar
- A sanitized Test prewrite snapshot and Human / JSON reports without mutations
- A fatal guard that does not automatically delete / clear a non-empty Calendar
- Test-only bootstrap add planning restricted to an empty Test Calendar and a synthetic one-event Source
- A dedicated Bootstrap Plan that does not change the normal Sync Plan guards
- A dedicated Bootstrap Run Spec that requires no baseline only for the first Test add
- A Production hard lock and a policy fixed to 1 add, with update / delete unreachable
- Test-only single-update planning that requires a Trusted Test Baseline
- A dedicated Plan fixed to 1 managed synthetic event and 1 DESCRIPTION-only update
- A policy that preserves original guard evidence without changing the normal global guards
- A dedicated single-update Run Spec bound to the event ID / ETag from the current Test snapshot
- A Production-locked update boundary that cannot reach Add / Delete
- Exact pinning of repository/tag/commit/ICS/source aggregates through an Accepted Production Source Manifest
- Planning of 1 DESCRIPTION-only update from a full Production source, Trusted Baseline, and full sanitized snapshot
- A Production Plan that requires at least 1 unrelated event to remain unchanged and rejects adds/deletes, 0 updates, and 2 or more updates
- A Production Run Spec without raw UID, SUMMARY, DESCRIPTION, Calendar ID, Google event ID, or ETag
- A Run Spec valid for at most 24 hours from a UTC-aware `issued_at`, with an approval material hash binding all bits subject to approval
- Closed schemas, domain-separated hashes, repository-external atomic/no-overwrite I/O, and redacted inspection reports for Production planning artifacts
- Separate capabilities for the Production full-snapshot reader / fresh-event reader / Description-only mutator, and a deterministic fake transport
- Full pre-snapshot drift STOP, fresh get / ETag / exact non-wildcard `If-Match`, mutation 1 attempt / retry 0
- Immediate read-back, a post-write full snapshot, and canonical zero-diff verification against the Accepted Source
- A closed approval-state model that progresses from an ARM receipt valid for at most 10 minutes to a one-time EXECUTE permit
- Atomic permit consumption outside the repository, replay prevention, a default-off kill switch, and switch/token generation binding
- An append-only hash-chain journal requiring fsync before patching, and a redacted public execution report
- A hard maximum of 10 raw API calls, no rollback, unreachable Production Add / Delete, and live Production execution hard-off
- A dedicated Production write-token authorization foundation isolated in `google-production-write`
- Separation into the 3 roles `production_read` / `test_write` / `production_write`, an exact owned-events scope, and opaque token-generation state
- Separation of requested scopes from fresh provider-granted evidence, with missing / stale / test-origin evidence rejected for Production operational acceptance
- No-overwrite token storage outside the repository and a bounded refresh foundation that revalidates provider evidence / scope / role / generation
- List/get-only capabilities for Production write-token rehearsal, full snapshot / Baseline cross-binding, Source zero-diff verification, and one deterministic fresh get
- Event ID / ETag memory-only, redacted rehearsal report, raw Calendar API call hard max 5, live patch hard-off

### Not implemented

- Execution of Test write OAuth, browser authorization, or token acquisition
- Execution of live Test Calendar prewrite reads
- Live connections to the Test Calendar API and execution of add/update operations
- Execution of a Test Calendar single update
- Production Calendar write
- Execution of Production OAuth, creation of Production write tokens, or browser authorization
- Execution of Production Calendar read-only rehearsal or the live ARM / EXECUTE operational flow
- live Production patch, real Production execution adapter
- automatic rollback, Production Add, Production Delete
- A Delete operation model, payload, or transport method
- `syncToken`, incremental state, automation

The Phase 4B bundle/simulation also neither connects to nor modifies Google Calendar. A private bundle holds payloads for future safety assessment, but execution enabled is always false, and it contains no method, endpoint, or Authorization header.

Do not commit Production ICS, Production snapshots, or runtime state to the repository. Inputs must be supplied explicitly as local files outside the repository.

## Requirements

- Python `>=3.12,<3.13`
- Supported platforms: Windows and Linux

The only base runtime dependencies are `icalendar` and `pydantic`. Official Google Python packages are isolated in the optional `google-read`, `google-test-write`, and `google-production-write` extras and are not included in the base installation. The three Google extras reuse the same existing dependency set; installation alone does not initiate OAuth or API calls.

## Setup

### uv

```powershell
uv sync --extra dev --frozen
uv run tridentine-calendar-google-sync --help
```

### Standard Windows venv and pip

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
tridentine-calendar-google-sync --help
```

Add the optional extra only when validating the mock-only Google read layer during development. Installation itself does not initiate authorization or API calls.

```powershell
uv sync --extra dev --extra google-read --frozen
uv run pytest -m google_read
```

The following optional extras can be used to validate the mock layer with standard Windows venv and pip.

```powershell
python -m pip install -e ".[dev,google-read]"
python -m pytest -m google_read
```

Use the separate optional extra only when validating the Test write mock layer. Installation alone does not initiate OAuth or API calls.

```powershell
uv sync --extra dev --extra google-test-write --frozen
uv run pytest -m google_test_write
```

Use the dedicated extra to validate the Production write-token authorization / read-only rehearsal foundation using mocks only. The Phase 6D.0 CLI handlers remain live hard-off; neither installation nor tests use OAuth, a browser, or the Calendar API.

```powershell
uv sync --extra dev --extra google-production-write --frozen
uv run pytest -m google_production_write
uv run tridentine-calendar-google-sync authorize-production-write-token --help
uv run tridentine-calendar-google-sync rehearse-production-write-token-readonly --help
```

## CLI

Inputs must be ordinary local filesystem paths. HTTP(S) URLs, `file://` URLs, and symbolic links are rejected, and the file size limit is 64 MiB. Input files are not modified, copied, or written out again.

### Inspecting Source structure

```powershell
tridentine-calendar-google-sync inspect-source `
  --source "<Accepted HTML ICS path outside the repository>" `
  --profile accepted-20260814
```

### Strict validation against an Accepted profile

```powershell
tridentine-calendar-google-sync validate-source `
  --source "<Accepted HTML ICS path outside the repository>" `
  --profile accepted-20260814
```

Both commands accept `--format text` or `--format json`. Without `--output <path>`, they write to standard output and do not automatically save reports inside the repository. Normal reports contain no local absolute paths, raw UIDs, lists of SUMMARY values, or DESCRIPTION content.

### Comparing against a sanitized snapshot

```powershell
tridentine-calendar-google-sync diff-snapshot `
  --source "<Accepted HTML ICS path outside the repository>" `
  --profile accepted-20260814 `
  --google-snapshot "<sanitized snapshot JSON path outside the repository>" `
  --format text
```

`diff-snapshot` reads only local files and does not connect to the network. Snapshots use the `sanitized-google-calendar-v1` format, and targets are identified by SHA-256 fingerprints rather than secret Calendar IDs. Normal reports exclude raw `iCalUID`, Google event IDs, event titles, descriptions, and local paths.

### Creating and inspecting a candidate baseline

```powershell
tridentine-calendar-google-sync create-baseline-candidate `
  --source "<Accepted HTML ICS path outside the repository>" `
  --profile accepted-20260814 `
  --google-snapshot "<sanitized snapshot path outside the repository>" `
  --output "<candidate baseline path outside the repository>"

tridentine-calendar-google-sync inspect-baseline `
  --baseline "<baseline path outside the repository>" `
  --format text
```

A candidate can be created only with an exact zero-difference result, every event unchanged, 0 warnings, and snapshot safety counters of 0. Baseline files are sensitive runtime data containing a raw Source UID inventory. `inspect-baseline` does not display raw UIDs.

### Explicit trust transition

```powershell
tridentine-calendar-google-sync trust-baseline `
  --candidate "<candidate baseline path outside the repository>" `
  --output "<trusted baseline path outside the repository>" `
  --confirmation "<exact confirmation phrase for this candidate>"
```

A candidate is not ownership evidence. A new trusted baseline file is created without overwriting only when the hash-verified candidate matches the exact confirmation phrase shown.

### Non-executable sync plan

```powershell
tridentine-calendar-google-sync plan-sync `
  --source "<Accepted HTML ICS path outside the repository>" `
  --profile accepted-20260814 `
  --google-snapshot "<sanitized snapshot path outside the repository>" `
  --trusted-baseline "<trusted baseline path outside the repository>" `
  --output "<sync plan path outside the repository>" `
  --format json
```

The default thresholds for add/update/delete are all `0`. The Plan state is one of `draft`, `review_required`, or `blocked`, but `executable=false` in every state. Delete candidates are always shown as destructive and requiring separate approval.

### Offline apply safety

The Phase 4B commands are `build-apply-bundle`, `inspect-apply-bundle`, `simulate-apply`, and `inspect-operation-journal`.

An apply bundle can be created only from a `draft` zero-action plan based on a trusted baseline, or a `review_required` add/update plan without fatal guards. Plans with even 1 delete, blocked plans, plans with warnings, and stale plans are rejected.

A nonzero test bundle can transition to `approved_for_simulation` only after the exact challenge and current plan hash are checked again. Simulation accepts only `FakeMutationTransport` and processes add/update operations sequentially in memory. Retries default to a maximum of 5 attempts, with no real-time sleep. Failures, uncertain outcomes, and ETag conflicts cause an immediate stop, and subsequent operations are recorded in the journal as `skipped`. Rollback is not provided.

Bundle creation requires an explicit test target label. Production environments, Production labels, and known Production target safe references are rejected before bundle generation even when the operation count is 0. Production bundle file writes, approval, simulation, and journal creation are also always rejected. See [Offline apply safety](docs/offline-apply-safety.md) for details.

### Test Calendar write foundation

The Phase 5A commands are `authorize-test-google-write`, `build-test-write-run-spec`, `inspect-test-write-run-spec`, and `run-test-calendar-write`. OAuth and the write runner require `--online`, dedicated token / target config files outside the repository, the exact Test target policy, and an exact approval phrase.

A run spec contains exactly 1 add or update. Add preserves the Source UID as `iCalUID` and is restricted to `events.import`. Update changes only the changed fields with `If-Match` set to the exact ETag and is restricted to `events.patch`. Mutations have only 1 attempt with no automatic retry, followed by verification through read-back or read-after-uncertain. Delete, batch, and rollback are not provided.

These live commands were not executed in Phase 5A. Future use of a Test Calendar requires separate, explicit approval for OAuth / API / event changes. See [Test Calendar write transport foundation](docs/test-calendar-write-foundation.md) for details.

### Test Calendar read-only prewrite inspection

`inspect-test-calendar-prewrite` uses a Test target config outside the repository and a separate Test write token to retrieve metadata and event counts through `events.list` only. It saves 3 outputs outside the repository without overwriting: a sanitized snapshot, a Human report, and a JSON report. It declares write-readiness only when the event count is 0.

```powershell
# REFERENCE ONLY — REQUIRES SEPARATE ONLINE APPROVAL
tridentine-calendar-google-sync inspect-test-calendar-prewrite `
  --online `
  --target-config "<Test target TOML path outside the repository>" `
  --token-file "<Test write token path outside the repository>" `
  --production-read-token-file "<Production read token path outside the repository>" `
  --snapshot-output "<prewrite snapshot path outside the repository>" `
  --human-report-output "<Human report path outside the repository>" `
  --json-report-output "<JSON report path outside the repository>"
```

For a non-empty Calendar, the command reports only safe aggregate counts and stops at a fatal guard. It does not print event content to the console or perform delete, clear, import, or patch operations. This command requires neither mutation approval nor a Run Spec, but `--online` is mandatory as the network boundary. No live command was executed during Phase 5A.1 development.

The snapshot output is a private `test-calendar-prewrite-snapshot-v1` wrapper. When using the canonical Google snapshot later, use the internal `snapshot` after validating the wrapper with the strict loader; do not read the wrapper file directly as an ordinary `google-snapshot-v1`.

### Test-only bootstrap add planning

`build-test-bootstrap-add-plan` generates a dedicated, non-executable Bootstrap Plan offline from a strictly validated empty Test prewrite snapshot and 1 synthetic Source event with an `.invalid` UID and Test marker. The `zero_google_event_count`, `all_events_add`, and `mass_change_guard` results reported by the normal plan are not suppressed; they are recorded in the dedicated plan as permitted original guard codes.

`inspect-test-bootstrap-add-plan` displays only safe references, aggregate counts, and hashes, without raw UIDs or event content. `build-test-bootstrap-add-run-spec` creates a dedicated private Run Spec from that plan with add 1 / update 0 / delete 0. The first add to a completely empty Test Calendar is the only case that does not require a Trusted Baseline.

After a successful bootstrap, the plan is to create a normal Test baseline from a matching Source 1 / Google 1 state rather than reuse this path. Phase 5C.0 does not execute Google API calls or Test Calendar writes.

### Test-only single-update planning

`build-test-single-update-plan` generates a non-executable Plan offline for 1 DESCRIPTION-only update from a strictly validated non-Production Test snapshot, a Trusted Test Baseline, and 1 synthetic Source event. The normal `plan-sync` continues to block the same 1 / 1 diff with `all_events_update` and `mass_change_guard`; the dedicated Plan preserves both as original guard evidence instead of removing them.

`inspect-test-single-update-plan` displays only safe references, fixed counts, changed fields, guard evidence, and hashes. A Plan contains no raw UID, content, Calendar ID, Google event ID, ETag, or request payload.

`build-test-single-update-run-spec` creates a private Run Spec rebound to the Trusted Test Baseline and current snapshot. The Run Spec is fixed to planning mode, DESCRIPTION-only, and add 0 / update 1 / delete 0; the event ID and exact ETag are obtained only from the current snapshot. Add, Delete, and Production are unreachable. An actual patch requires exact approval in a separate Stage, and Phase 5D.0 does not call the Google API.

### Production single-update planning foundation

`inspect-accepted-production-source-manifest` strictly validates a separately created Accepted Production Source Manifest and displays repository/tag/commit/ICS/profile/source hashes as safe references. The Manifest has `production=true`, `acceptance_state=accepted`, and `synthetic=false`; it permits only exact provenance and aggregates from a clean Accepted source.

`build-production-single-update-plan` revalidates the manifest, Accepted source/profile, Trusted Production Baseline, a full sanitized snapshot matching that baseline's snapshot hash, and an explicit Production target config offline. Only Production profiles code-pinned to the reviewed package/repository are used; Production commands do not accept an external `--profiles-dir`. The Source repository identity is also pinned to `Blue-jp/tridentine_calendar`. A non-executable Plan is created only when exactly 1 event requires a DESCRIPTION update, at least 1 unrelated event is unchanged, and add/delete/duplicate/ambiguous/unmanaged/fatal/warning counts are all 0.

`build-production-single-update-run-spec` rebinds the same inputs and Plan to create a short-lived Run Spec with UTC-aware `issued_at <= now < expires_at` and a maximum lifetime of 24 hours. The Run Spec holds a safe UID reference, canonical pre-image hash, and Description patch hash, but no raw UID, SUMMARY, DESCRIPTION, current/desired body, Calendar ID, Google event ID, ETag, payload, endpoint, or HTTP method. Actual identity/content resolution and ETag acquisition will occur only in a separate future Phase, after fresh inputs are revalidated in memory.

The following are the 5 inspection commands. All operate offline; build outputs and optional inspection outputs are saved outside the repository atomically and without overwriting.

```powershell
tridentine-calendar-google-sync inspect-accepted-production-source-manifest `
  --manifest "<Accepted Production manifest path outside the repository>" `
  --format json

tridentine-calendar-google-sync build-production-single-update-plan `
  --manifest "<manifest path outside the repository>" `
  --source "<Accepted ICS path outside the repository>" `
  --profile "<package-pinned Accepted profile id>" `
  --google-snapshot "<full sanitized snapshot path outside the repository>" `
  --trusted-baseline "<trusted baseline path outside the repository>" `
  --target-config "<Production target TOML path outside the repository>" `
  --output "<Production Plan path outside the repository>"

tridentine-calendar-google-sync inspect-production-single-update-plan `
  --plan "<Production Plan path outside the repository>" `
  --format text

tridentine-calendar-google-sync build-production-single-update-run-spec `
  --manifest "<manifest path outside the repository>" `
  --source "<Accepted ICS path outside the repository>" `
  --profile "<package-pinned Accepted profile id>" `
  --google-snapshot "<full sanitized snapshot path outside the repository>" `
  --production-plan "<Production Plan path outside the repository>" `
  --trusted-baseline "<trusted baseline path outside the repository>" `
  --target-config "<Production target TOML path outside the repository>" `
  --output "<Production Run Spec path outside the repository>"

tridentine-calendar-google-sync inspect-production-single-update-run-spec `
  --run-spec "<Production Run Spec path outside the repository>" `
  --format json
```

These commands have no `--online`, token, credential, approval phrase, or apply/execute option. Phase 6B does not construct a Google client or dispatch a Production Run Spec to the existing `run-test-calendar-write`.

### Google read-only commands

`authorize-google-readonly` and `fetch-google-snapshot` are explicit online commands added in Phase 3A. Both require `--online` and are used only in a separately approved read-only workflow. They are never called from the Phase 4A baseline/plan commands. See [Google read-only setup](docs/google-readonly-setup.md) for prerequisites and the policy on where secrets are stored.

The command syntax for future use after approval is shown below. These examples are for reference and are not executed in Phase 3A.

```powershell
# REFERENCE ONLY — REQUIRES SEPARATE ONLINE APPROVAL
tridentine-calendar-google-sync authorize-google-readonly `
  --online `
  --credentials-file "<Desktop OAuth client JSON path outside the repository>" `
  --token-file "<read-only token JSON path outside the repository>"

# REFERENCE ONLY — REQUIRES SEPARATE ONLINE APPROVAL
tridentine-calendar-google-sync fetch-google-snapshot `
  --online `
  --token-file "<read-only token JSON path outside the repository>" `
  --target-config "<private target TOML path outside the repository>" `
  --output "<sanitized snapshot JSON path outside the repository>"
```

## Accepted asset integration test

The full Accepted HTML ICS is not a tracked fixture. Integration tests run only when a verified asset is provided outside the repository and the following environment variable is explicitly set.

```powershell
$env:TRIDENTINE_ACCEPTED_HTML_ICS_PATH = "<verified Accepted HTML ICS path outside the repository>"
uv run pytest tests/test_accepted_asset_integration.py `
  tests/test_offline_diff_accepted_integration.py
```

If the environment variable is unset, the tests are skipped and the offline unit test suite succeeds. Environment variable values are not displayed in reports or test failures. CI does not set this environment variable or download Production assets.

The Phase 2 opt-in integration test converts the Accepted source into synthetic Google events in memory to validate the diff engine. It neither saves the generated snapshot to a file nor calls the Google API.

The Phase 4A Production candidate integration runs only when both of the following environment variables are explicitly set.

- `TRIDENTINE_ACCEPTED_HTML_ICS_PATH`
- `TRIDENTINE_PRODUCTION_GOOGLE_SNAPSHOT_PATH`

This test only validates the candidate in memory. It performs no trust transition or baseline/plan file write.

The Phase 4B Production lock integration runs only when all 4 of the following environment variables are explicitly set.

- `TRIDENTINE_ACCEPTED_HTML_ICS_PATH`
- `TRIDENTINE_PRODUCTION_GOOGLE_SNAPSHOT_PATH`
- `TRIDENTINE_PRODUCTION_TRUSTED_BASELINE_PATH`
- `TRIDENTINE_PRODUCTION_SYNC_PLAN_PATH`

This test strictly loads the 4 inputs, reconstructs the zero-difference plan in memory, and verifies both that Production bundle generation is rejected even with an operation count of 0 and that input bytes are preserved. It does not create or save a Production bundle, journal, or simulation result.

## Exit code

| Code | Meaning |
|---:|---|
| `0` | The Source is valid against the profile |
| `1` | Safely classified offline differences exist |
| `2` | CLI argument or configuration error |
| `3` | Source parsing or validation error |
| `4` | Sanitized snapshot input or schema error |
| `5` | Fatal guard for SHA, UID, counts, date ranges, or similar checks |
| `6` | Safe error during Google read-only retrieval or authorization |
| `8` | Unexpected internal error |

Validation mismatches do not display Python tracebacks or file content during normal use.

## Safety and privacy

- Do not include credentials, tokens, Calendar IDs, private iCal URLs, Google event IDs, Production snapshots, or state in commits, logs, issues, or Pull Requests.
- Do not commit Accepted HTML ICS or Plain ICS. ICS files inside the repository are restricted to synthetic test fixtures using fictional data only.
- Google snapshot fixtures inside the repository use only fictional UIDs, event IDs, and fingerprints, and contain no URLs or personal information.
- Preserve UIDs exactly only during internal parsing. Reports use safe references in the `U-<12 hexadecimal characters>` format, derived from domain-separated SHA-256.
- Google event IDs are also retained only for internal comparison. Reports use the `G-<12 hexadecimal characters>` format with a separate domain.
- Do not trim, apply Unicode normalization or HTML formatting, modify URLs, or remove line breaks in SUMMARY and DESCRIPTION. Only RFC parser line unfolding and ICS escape decoding are performed as transport processing.
- Store runtime data outside the repository.
- Keep OAuth client JSON, authorized-user tokens, target configs, and sanitized Production snapshots outside both the repository and Git worktrees.
- Even after sanitization, snapshots are sensitive runtime data containing event content and opaque IDs. Do not make them public artifacts or CI artifacts.
- Candidate/trusted baselines are private data because they contain raw Source UID inventories. Do not include them in the repository, CI artifacts, issues, or Pull Requests.
- Sync plan reports use only safe references and contain no raw UID, Google event ID, ETag, event content, payload, method, or endpoint.
- Private apply bundles contain raw UIDs, Google event IDs, ETags, and managed-field payloads, making them sensitive data equivalent to baselines and snapshots.
- Public apply reports and operation journals use only safe references, hashes, and allowlisted outcome codes.
- Store Test write tokens in separate files from Production read-only tokens; scope additions, overwriting, and reuse are rejected.
- A Test Write Run Spec is a private artifact. Public reports / journals contain no raw UID, Google event ID, ETag, SUMMARY, DESCRIPTION, or payload.
- Accepted Production manifests, Production target configs, sources, snapshots, baselines, Plans, and Run Specs are private runtime artifacts kept outside the repository. Production Plan/Run Spec inspection displays only safe references, aggregates, hashes, and lifetimes.
- Production Run Specs do not store raw UID, SUMMARY, DESCRIPTION, Calendar ID, Google event ID, ETag, or current/desired body.

See also the [Security Policy](SECURITY.md) for details.

## Development checks

```powershell
uv run ruff check .
uv run ruff format --check .
uv run mypy --strict src
uv run pytest
uv run python -m build
```

Network sockets are disabled during tests as well. CI separates the base layer and the optional `google-read`, `google-test-write`, and `google-production-write` mock layers on both Linux and Windows, without using credentials or Production data.

## Roadmap

By Phase 6C, the following had been implemented: offline diff, trusted baselines, non-executable plans, fake-only apply safety simulation, Test Calendar write transport, Test-only planning, Accepted Production manifests, Production single-update Plans/Run Specs, and the foundation for mock-only approval state, list/get/patch transport, and write-ahead journals / reports. The following have not yet been carried out or approved.

1. Separate Production write OAuth / token creation and read-only rehearsal
2. Verification of real Production target / scope / token identity and a Google client adapter
3. An explicitly approved live update for 1 legitimate, naturally occurring Description-only change
4. Separate Phase design, security review, and acceptance for Production Add
5. Independent review of Production Delete, rollback, syncToken, batch, and automation

## Provenance and license

The liturgical calendar is generated by [Blue-jp/tridentine_calendar](https://github.com/Blue-jp/tridentine_calendar) and officially distributed by [Blue-jp/tridentine-calendar-ja](https://github.com/Blue-jp/tridentine-calendar-ja). This tool treats the Accepted source as input and does not generate or correct the liturgical data itself.

This repository is published under the [MIT License](LICENSE).
