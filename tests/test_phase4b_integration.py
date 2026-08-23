from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from conftest import PROFILES_DIR

from tridentine_calendar_google_sync.apply_approval import apply_approval_challenge
from tridentine_calendar_google_sync.apply_bundle import build_apply_bundle
from tridentine_calendar_google_sync.apply_bundle_io import write_apply_bundle
from tridentine_calendar_google_sync.apply_models import (
    ApplyBundleState,
    ApplyEnvironment,
)
from tridentine_calendar_google_sync.apply_policy import ApplyGuardError
from tridentine_calendar_google_sync.apply_simulation import run_apply_simulation
from tridentine_calendar_google_sync.baseline_engine import verify_baseline_content_hash
from tridentine_calendar_google_sync.baseline_io import load_baseline
from tridentine_calendar_google_sync.baseline_models import BaselineState
from tridentine_calendar_google_sync.fake_mutation_transport import FakeMutationTransport
from tridentine_calendar_google_sync.google_snapshot import load_google_snapshot
from tridentine_calendar_google_sync.google_target import short_target_reference
from tridentine_calendar_google_sync.operation_journal import initialize_operation_journal
from tridentine_calendar_google_sync.plan_engine import (
    build_sync_plan,
    verify_sync_plan_content_hash,
)
from tridentine_calendar_google_sync.plan_io import load_sync_plan_report
from tridentine_calendar_google_sync.plan_models import PlanState
from tridentine_calendar_google_sync.plan_report import build_plan_json_report
from tridentine_calendar_google_sync.profiles import load_profile
from tridentine_calendar_google_sync.source_ics import inspect_source

ENV_NAMES = (
    "TRIDENTINE_ACCEPTED_HTML_ICS_PATH",
    "TRIDENTINE_PRODUCTION_GOOGLE_SNAPSHOT_PATH",
    "TRIDENTINE_PRODUCTION_TRUSTED_BASELINE_PATH",
    "TRIDENTINE_PRODUCTION_SYNC_PLAN_PATH",
)


@pytest.mark.integration
def test_production_inputs_build_memory_only_zero_bundle_without_outputs(
    tmp_path: Path,
) -> None:
    configured = {name: os.environ.get(name) for name in ENV_NAMES}
    if not all(configured.values()):
        pytest.skip("Production Phase 4B input paths are not configured")
    paths = {name: Path(value) for name, value in configured.items() if value}
    before_bytes = {
        name: hashlib.sha256(path.read_bytes()).digest() for name, path in paths.items()
    }

    try:
        profile = load_profile("accepted-20260814", profiles_dir=PROFILES_DIR)
        source = inspect_source(paths[ENV_NAMES[0]], profile)
        snapshot = load_google_snapshot(paths[ENV_NAMES[1]])
        baseline = load_baseline(paths[ENV_NAMES[2]])
        verify_baseline_content_hash(baseline)
        stored_plan = load_sync_plan_report(paths[ENV_NAMES[3]])
        verify_sync_plan_content_hash(stored_plan)
        plan = build_sync_plan(profile, source, snapshot, baseline)
        bundle = build_apply_bundle(
            profile,
            source,
            snapshot,
            baseline,
            plan,
            ApplyEnvironment.PRODUCTION,
        )
    except Exception as exc:  # Broad catch prevents Production values in failure output.
        pytest.fail(f"Production zero-bundle validation failed safely: {type(exc).__name__}")

    if plan.state is not PlanState.DRAFT or plan.proposed_actions or plan.safety_guards:
        pytest.fail("Production plan was not an exact zero-action draft")
    if build_plan_json_report(plan) != build_plan_json_report(stored_plan):
        pytest.fail("Production plan file did not match deterministic reconstruction")
    counts = plan.diff_summary.counts
    if counts.unchanged != 4938 or any(
        getattr(counts, name) != 0
        for name in (
            "add",
            "update",
            "delete_candidate",
            "duplicate_source_uid",
            "duplicate_google_icaluid",
            "ambiguous",
            "unmanaged_google_event",
            "invalid_source",
            "fatal_guard",
        )
    ):
        pytest.fail("Production plan classifications were not exactly unchanged")
    if plan.thresholds.model_dump(mode="json") != {
        "max_add": 0,
        "max_update": 0,
        "max_delete": 0,
    }:
        pytest.fail("Production plan thresholds were not all zero")
    if bundle.state is not ApplyBundleState.DRAFT:
        pytest.fail("Production zero bundle was not left in draft state")
    if bundle.generated_operation_count != 0 or bundle.operations:
        pytest.fail("Production bundle contained an operation")
    if bundle.environment is not ApplyEnvironment.PRODUCTION:
        pytest.fail("Production zero bundle environment was not preserved")
    if bundle.execution_enabled or not bundle.production_locked:
        pytest.fail("Production zero bundle safety lock was invalid")
    if source.raw_sha256 != "1c0ee8a19769f9ff26b1a40d03d0280afdcbde1d7d50642ad3f2123c117dd552":
        pytest.fail("Production source SHA did not match the accepted profile")
    if snapshot.content_hash != "b90316adc611e2bc44b9a4bb2f29ca5e117f1dc41277b27c7ed0921865490b8d":
        pytest.fail("Production snapshot content hash did not match the expected value")
    if (
        not snapshot.complete
        or short_target_reference(snapshot.target_fingerprint) != "T-e10f0095ab8f"
    ):
        pytest.fail("Production snapshot completeness or target reference was invalid")
    if baseline.state is not BaselineState.TRUSTED or baseline.managed_uid_count != 4938:
        pytest.fail("Production trusted baseline state or UID count was invalid")
    if snapshot.event_count != 4938 or source.vevent_count != 4938:
        pytest.fail("Production zero bundle inputs did not have the pinned count")
    with pytest.raises(ApplyGuardError):
        apply_approval_challenge(bundle, plan.plan_content_hash)
    with pytest.raises(ApplyGuardError):
        run_apply_simulation(bundle, FakeMutationTransport(events={}))
    with pytest.raises(ApplyGuardError):
        initialize_operation_journal(bundle)
    bundle_output = tmp_path / "must-not-write-production.apply-bundle.json"
    with pytest.raises(ApplyGuardError):
        write_apply_bundle(bundle, bundle_output)
    if bundle_output.exists():
        pytest.fail("Production bundle output was unexpectedly created")
    after_bytes = {name: hashlib.sha256(path.read_bytes()).digest() for name, path in paths.items()}
    if before_bytes != after_bytes:
        pytest.fail("Production input bytes changed during memory-only validation")
    if list(tmp_path.iterdir()):
        pytest.fail("Production zero-bundle validation persisted an artifact")
