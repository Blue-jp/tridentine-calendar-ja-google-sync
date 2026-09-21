## Purpose

Draft PR for the reviewed Phase 6D.1H security-remediation branch.

This PR records and validates a set of fail-closed credential-storage and reuse-safety foundations. It is **not** a declaration of merge readiness, Production operational approval, credential reuse authorization, or recovery approval.

## Reviewed scope

The branch currently contains 20 commits beyond the pinned base.

The first 19 commits cover Units 1–3 and 4A–4P. They establish or strengthen:

- accepted Production source authority;
- strict private input reads;
- fail-closed Git-worktree exclusion;
- POSIX private create and replace boundaries;
- conservative persistence-failure evidence;
- pre-save rereads and stale-content rejection;
- cooperative Linux directory locking for credential sessions and token/state bundle publication;
- independent read-only token/state pair inspection.

The token/state inspector never authorizes credential reuse.

The 20th commit adds a **memory-only, non-authorizing token reuse policy model**:

- `docs/production-write-token-reuse-policy-model.md`
- `src/tridentine_calendar_google_sync/production_write_token_reuse_policy.py`
- `tests/test_token_reuse_policy_phase6d1h.py`

The model explicitly distinguishes operation identity from generation and preserves unresolved failure, interruption, and commit uncertainty. It always returns `reuse_authorized=False`.

It does **not** implement persistent operation history, controlled reconciliation, recovery approval, or runtime integration with the existing credential session, writers, inspector, or CLI.

## Pinned review references

- Base: `47194b000e1edc2bf590d3c764595ba26c260039`
- Previous reviewed head before the reuse-policy model: `40756ca0056613fa3be81c2896a08bcee854ea6f`
- Current head: `51e845a8df5dc4f238b06ff3a9ac545547c14226`
- Current head tree: `a186a433741af7028c14358e03187224a61ef177`

For the current head, GitHub's temporary PR merge checkout is:

- Temporary PR merge checkout: `6c91051dd2af7789ae148cd3d5853100af44d50c`
- Temporary PR merge tree: `a186a433741af7028c14358e03187224a61ef177`

The temporary PR merge tree matches the current head tree. This is PR validation evidence and is **not** a merge into `main`.

## Validation status

### Local Windows validation

The newly added reuse-policy model was validated on Windows with Python 3.12.14.

The dedicated model test file completed with:

- 205 passed
- 0 failed
- 0 errors
- 0 skipped

The base regression layer completed with:

- 1292 passed
- 0 failed
- 0 errors
- 318 skipped
- 567 deselected

Ruff check, Ruff format check, and strict mypy for the new module also passed.

This local validation used installed dependencies whose required versions matched project metadata and `uv.lock`; it was not itself a fresh `uv sync --frozen` environment.

### GitHub Actions validation

The current head was validated by:

- Workflow: `Offline and mocked calendar safety tests`
- Workflow path: `.github/workflows/test.yml`
- Run ID: `35577796090`
- Attempt: `1`
- Event: `pull_request`
- Result: `completed / success`

All eight matrix jobs succeeded:

| Layer | Ubuntu | Windows |
|---|---|---|
| base | success | success |
| google-read | success | success |
| google-test-write | success | success |
| google-production-write | success | success |

Across the eight jobs:

- Python 3.12 was used;
- dependencies were installed with `uv sync --frozen`;
- Ruff linting passed;
- Ruff formatting checks passed;
- each selected pytest layer passed;
- package builds passed;
- strict mypy passed in the six non-base jobs;
- the two base jobs skipped mypy as configured.

Observed base-layer summaries for the current run include:

- Ubuntu base: `1576 passed / 34 skipped / 567 deselected`
- Windows base: `1300 passed / 310 skipped / 567 deselected`

Skipped and deselected cases are not counted as passed evidence.

The Google-related layer names refer to offline/mocked validation layers. They do not indicate live Google Calendar access or mutation.

The workflow, `uv.lock`, pytest configuration, and packaged empty Accepted Production Baseline Registry were not changed by the reuse-policy-model commit.

## Important limits

The current changes do not establish:

- an atomic token/state transaction;
- persistent failure or incomplete-operation history;
- authenticated or rollback-resistant operation history;
- controlled reconciliation or recovery approval;
- protection against non-participating writers;
- equivalent new Windows serialization to the Linux cooperative locking model;
- Production credential reuse authorization.

A matching token/state pair, an unexpired token, the same generation, a visible completion-like record, or successful writer returns must not by themselves be treated as proof that a previous operation completed safely.

The memory-only policy model is deliberately non-authorizing. Persistent history and runtime enforcement remain separate future work.

## Unresolved security and operational gates

The following statuses remain unchanged:

- DS-04: `PARTIAL`
- Historical repository-wide Deep Security Scan: `INCOMPLETE`
- Separate scan report for `47194b0`: `FAIL`
- Production operational gate: `BLOCKED`

The successful CI runs do not replace or upgrade those security assessments.

The packaged Accepted Production Baseline Registry remains empty and fail-closed.

No Production OAuth, live rehearsal, real token refresh, Google Calendar API operation, event mutation, deployment, ARM/EXECUTE activation, credential reuse, or recovery action is authorized by this PR or its CI results.

## Review constraints

Keep this PR in Draft while the remaining security boundaries are designed and reviewed.

Do not:

- merge or enable auto-merge;
- mark the PR ready for review solely because CI passed;
- deploy or release;
- add operational credentials;
- expand workflow permissions;
- enable Production handlers;
- interpret matching credential files or successful CI as reuse authorization.

The next design step is to define the boundary for persistent incomplete-operation evidence before implementing any runtime persistence or credential-reuse enforcement.
