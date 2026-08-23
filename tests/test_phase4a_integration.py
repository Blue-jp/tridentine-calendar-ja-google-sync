from __future__ import annotations

import os
from pathlib import Path

import pytest
from conftest import PROFILES_DIR

from tridentine_calendar_google_sync.baseline_engine import (
    build_baseline_candidate,
    render_baseline_inspection_json,
)
from tridentine_calendar_google_sync.baseline_models import BaselineState
from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.google_snapshot import load_google_snapshot
from tridentine_calendar_google_sync.plan_engine import PlanInputError, baseline_to_managed_scope
from tridentine_calendar_google_sync.profiles import load_profile
from tridentine_calendar_google_sync.source_ics import inspect_source

EXPECTED_PRODUCTION_SNAPSHOT_HASH = (
    "b90316adc611e2bc44b9a4bb2f29ca5e117f1dc41277b27c7ed0921865490b8d"
)


@pytest.mark.integration
def test_production_inputs_build_memory_only_candidate_never_trusted_or_written(
    tmp_path: Path,
) -> None:
    source_value = os.environ.get("TRIDENTINE_ACCEPTED_HTML_ICS_PATH")
    snapshot_value = os.environ.get("TRIDENTINE_PRODUCTION_GOOGLE_SNAPSHOT_PATH")
    if not source_value or not snapshot_value:
        pytest.skip("Production source and snapshot paths are not configured")

    try:
        profile = load_profile("accepted-20260814", profiles_dir=PROFILES_DIR)
        source = inspect_source(Path(source_value), profile)
        snapshot = load_google_snapshot(Path(snapshot_value))
        if snapshot.content_hash != EXPECTED_PRODUCTION_SNAPSHOT_HASH:
            pytest.fail("Production snapshot hash did not match the verified Phase 3B value")
        diff = diff_source_to_snapshot(source, snapshot)
        candidate = build_baseline_candidate(profile, source, snapshot, diff)
        safe_report = render_baseline_inspection_json(candidate)
    except Exception as exc:  # Broad catch keeps Production values out of failure output.
        pytest.fail(f"Production candidate validation failed safely: {type(exc).__name__}")

    if candidate.state is not BaselineState.CANDIDATE:
        pytest.fail("Production baseline object was not left in candidate state")
    if candidate.managed_uid_count != 4938 or source.vevent_count != 4938:
        pytest.fail("Production candidate count did not match the pinned profile")
    if diff.counts.unchanged != 4938 or diff.has_changes or diff.fatal:
        pytest.fail("Production candidate inputs were not an exact zero-difference audit")
    if snapshot.event_count != 4938 or not snapshot.complete:
        pytest.fail("Production snapshot was not complete at the pinned count")
    if candidate.snapshot_content_hash != snapshot.content_hash:
        pytest.fail("Production candidate did not pin the exact snapshot content hash")
    if source.events[0].uid and source.events[0].uid in safe_report:
        pytest.fail("Safe candidate report exposed a raw source UID")
    if source_value in safe_report or snapshot_value in safe_report:
        pytest.fail("Safe candidate report exposed a configured path")
    with pytest.raises(PlanInputError):
        baseline_to_managed_scope(candidate)
    if list(tmp_path.iterdir()):
        pytest.fail("Production candidate integration persisted an unexpected file")
