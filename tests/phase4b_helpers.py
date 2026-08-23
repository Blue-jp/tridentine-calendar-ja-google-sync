from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from test_sync_plan import _current_source, _large_bundle

from tridentine_calendar_google_sync.apply_approval import (
    apply_approval_challenge,
    approve_apply_bundle,
)
from tridentine_calendar_google_sync.apply_bundle import build_apply_bundle
from tridentine_calendar_google_sync.apply_models import ApplyBundle, ApplyEnvironment
from tridentine_calendar_google_sync.google_snapshot import parse_google_snapshot_bytes
from tridentine_calendar_google_sync.plan_engine import build_sync_plan
from tridentine_calendar_google_sync.plan_models import PlanThresholds, SyncPlan


@dataclass(frozen=True)
class SyntheticApplyBundle:
    profile: Any
    source: Any
    snapshot: Any
    baseline: Any
    plan: SyncPlan
    bundle: ApplyBundle


def build_update_apply_bundle(
    tmp_path: Path,
    profile_factory: Any,
) -> SyntheticApplyBundle:
    profile, source, _snapshot, document, baseline = _large_bundle(
        tmp_path,
        profile_factory,
        count=101,
    )
    for index, event in enumerate(document["events"]):
        event["etag"] = f"fixture-etag-apply-{index:04d}"
    document["events"][0]["summary"] = "Changed synthetic apply summary"
    snapshot = parse_google_snapshot_bytes(json.dumps(document, ensure_ascii=False).encode("utf-8"))
    plan = build_sync_plan(
        profile,
        source,
        snapshot,
        baseline,
        thresholds=PlanThresholds(max_update=1),
    )
    bundle = build_apply_bundle(
        profile,
        source,
        snapshot,
        baseline,
        plan,
        ApplyEnvironment.TEST,
        target_label="test",
    )
    return SyntheticApplyBundle(profile, source, snapshot, baseline, plan, bundle)


def build_add_apply_bundle(
    tmp_path: Path,
    profile_factory: Any,
) -> SyntheticApplyBundle:
    _old_profile, _old_source, snapshot, _document, baseline = _large_bundle(
        tmp_path,
        profile_factory,
        count=101,
    )
    profile, source = _current_source(tmp_path, profile_factory, 102)
    plan = build_sync_plan(
        profile,
        source,
        snapshot,
        baseline,
        thresholds=PlanThresholds(max_add=1),
    )
    bundle = build_apply_bundle(
        profile,
        source,
        snapshot,
        baseline,
        plan,
        ApplyEnvironment.TEST,
        target_label="test",
    )
    return SyntheticApplyBundle(profile, source, snapshot, baseline, plan, bundle)


def build_multi_apply_bundle(
    tmp_path: Path,
    profile_factory: Any,
) -> SyntheticApplyBundle:
    _old_profile, _old_source, _snapshot, document, baseline = _large_bundle(
        tmp_path,
        profile_factory,
        count=303,
    )
    profile, source = _current_source(tmp_path, profile_factory, 305)
    for index, event in enumerate(document["events"]):
        event["etag"] = f"fixture-etag-multi-{index:04d}"
    document["events"][0]["summary"] = "Changed synthetic multi summary"
    snapshot = parse_google_snapshot_bytes(json.dumps(document, ensure_ascii=False).encode("utf-8"))
    plan = build_sync_plan(
        profile,
        source,
        snapshot,
        baseline,
        thresholds=PlanThresholds(max_add=2, max_update=1),
    )
    bundle = build_apply_bundle(
        profile,
        source,
        snapshot,
        baseline,
        plan,
        ApplyEnvironment.TEST,
        target_label="test",
    )
    return SyntheticApplyBundle(profile, source, snapshot, baseline, plan, bundle)


def build_two_update_apply_bundle(
    tmp_path: Path,
    profile_factory: Any,
) -> SyntheticApplyBundle:
    profile, source, _snapshot, document, baseline = _large_bundle(
        tmp_path,
        profile_factory,
        count=202,
    )
    for index, event in enumerate(document["events"]):
        event["etag"] = f"fixture-etag-two-update-{index:04d}"
    document["events"][0]["summary"] = "Changed first synthetic update summary"
    document["events"][1]["summary"] = "Changed second synthetic update summary"
    snapshot = parse_google_snapshot_bytes(json.dumps(document, ensure_ascii=False).encode("utf-8"))
    plan = build_sync_plan(
        profile,
        source,
        snapshot,
        baseline,
        thresholds=PlanThresholds(max_update=2),
    )
    bundle = build_apply_bundle(
        profile,
        source,
        snapshot,
        baseline,
        plan,
        ApplyEnvironment.TEST,
        target_label="test",
    )
    return SyntheticApplyBundle(profile, source, snapshot, baseline, plan, bundle)


def approved_bundle(value: SyntheticApplyBundle) -> ApplyBundle:
    challenge = apply_approval_challenge(
        value.bundle,
        value.plan.plan_content_hash,
    )
    return approve_apply_bundle(
        value.bundle,
        challenge,
        value.plan.plan_content_hash,
    )
