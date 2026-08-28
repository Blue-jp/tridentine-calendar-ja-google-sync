from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from phase6b_helpers import (
    ProductionPlanningInputs,
    build_production_planning_inputs,
    build_production_snapshot,
)

from tridentine_calendar_google_sync.production_approval_state import (
    build_production_arm_receipt,
    build_production_execute_permit,
    build_production_kill_switch,
    production_arm_challenge,
    production_execute_challenge,
    transition_production_kill_switch,
)
from tridentine_calendar_google_sync.production_approval_state_io import (
    build_phase6c_mock_approval_store,
)
from tridentine_calendar_google_sync.production_approval_state_models import (
    ProductionArmReceipt,
    ProductionExecutePermit,
    ProductionKillSwitch,
    ProductionMockApprovalStore,
)
from tridentine_calendar_google_sync.production_fake_transport import (
    FakeProductionTransportBundle,
    ScriptedProductionExecutionStateProvider,
    paginate_production_snapshot,
)
from tridentine_calendar_google_sync.production_single_update_plan import (
    build_production_single_update_plan,
)
from tridentine_calendar_google_sync.production_single_update_plan_models import (
    ProductionSingleUpdatePlan,
)
from tridentine_calendar_google_sync.production_single_update_run_spec import (
    build_production_single_update_run_spec,
)
from tridentine_calendar_google_sync.production_single_update_run_spec_models import (
    ProductionSingleUpdateRunSpec,
)

PHASE6C_NOW = datetime(2099, 1, 1, 12, 0, tzinfo=UTC)
PHASE6C_TOKEN_GENERATION = 7


@dataclass(frozen=True)
class ProductionTransportArtifacts:
    inputs: ProductionPlanningInputs
    plan: ProductionSingleUpdatePlan
    run_spec: ProductionSingleUpdateRunSpec
    kill_switch: ProductionKillSwitch
    initial_kill_switch: ProductionKillSwitch
    approval_store: ProductionMockApprovalStore
    approval_store_directory: Path
    arm_receipt: ProductionArmReceipt
    execute_permit: ProductionExecutePermit
    execute_confirmation: str


def build_production_transport_artifacts(
    tmp_path: Path,
    *,
    event_count: int = 4,
) -> ProductionTransportArtifacts:
    inputs = build_production_planning_inputs(tmp_path, event_count=event_count)
    plan = build_production_single_update_plan(
        inputs.manifest,
        inputs.updated.profile,
        inputs.updated.source,
        inputs.snapshot,
        inputs.baseline,
        inputs.target,
    )
    run_spec = build_production_single_update_run_spec(
        inputs.manifest,
        inputs.updated.profile,
        inputs.updated.source,
        inputs.snapshot,
        plan,
        inputs.baseline,
        inputs.target,
        issued_at=PHASE6C_NOW,
    )
    initial_kill_switch = build_production_kill_switch(
        run_spec.target_safe_ref,
        issued_at=PHASE6C_NOW - timedelta(seconds=2),
    )
    kill_switch = transition_production_kill_switch(
        initial_kill_switch,
        state="on",
        issued_at=PHASE6C_NOW - timedelta(seconds=1),
    )
    approval_store_directory = tmp_path / "approval-store"
    approval_store_directory.mkdir()
    approval_store = build_phase6c_mock_approval_store(approval_store_directory)
    arm_receipt = build_production_arm_receipt(
        run_spec,
        plan,
        kill_switch,
        approval_store,
        write_token_generation=PHASE6C_TOKEN_GENERATION,
        arm_nonce="1" * 32,
        issued_at=PHASE6C_NOW,
    )
    execute_permit = build_production_execute_permit(
        arm_receipt,
        run_spec,
        plan,
        kill_switch,
        approval_store,
        arm_confirmation=production_arm_challenge(arm_receipt),
        write_token_generation=PHASE6C_TOKEN_GENERATION,
    )
    return ProductionTransportArtifacts(
        inputs=inputs,
        plan=plan,
        run_spec=run_spec,
        kill_switch=kill_switch,
        initial_kill_switch=initial_kill_switch,
        approval_store=approval_store,
        approval_store_directory=approval_store_directory,
        arm_receipt=arm_receipt,
        execute_permit=execute_permit,
        execute_confirmation=production_execute_challenge(execute_permit),
    )


def make_transport_bundle(
    artifacts: ProductionTransportArtifacts,
    *,
    page_sizes: tuple[int, ...],
    **kwargs: object,
) -> FakeProductionTransportBundle:
    pre_snapshot = artifacts.inputs.snapshot
    post_snapshot = build_production_snapshot(
        artifacts.inputs.updated.source,
        artifacts.inputs.target,
    )
    pre_event = next(
        event
        for event in pre_snapshot.events
        if event.safe_ical_uid_reference == artifacts.run_spec.operation.safe_uid_ref
    )
    post_event = next(
        event
        for event in post_snapshot.events
        if event.safe_ical_uid_reference == artifacts.run_spec.operation.safe_uid_ref
    )
    return FakeProductionTransportBundle(
        collections=(
            paginate_production_snapshot(pre_snapshot, page_sizes),
            paginate_production_snapshot(post_snapshot, page_sizes),
        ),
        get_events=(pre_event, post_event),
        expected_if_match=pre_event.etag,
        **kwargs,
    )


def make_state_provider(
    artifacts: ProductionTransportArtifacts,
    *,
    kill_switches: tuple[object, ...] | None = None,
    token_generations: tuple[int | None, ...] | None = None,
) -> ScriptedProductionExecutionStateProvider:
    return ScriptedProductionExecutionStateProvider(
        kill_switches=kill_switches or (artifacts.kill_switch,),
        token_generations=token_generations or (PHASE6C_TOKEN_GENERATION,),
    )
