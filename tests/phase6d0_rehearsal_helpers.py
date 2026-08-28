from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

from phase6b_helpers import ProductionPlanningInputs, build_production_planning_inputs
from phase6d0_auth_helpers import ISSUED_AT, production_token

from tridentine_calendar_google_sync.baseline_engine import (
    baseline_confirmation_phrase,
    build_baseline_candidate,
    trust_baseline,
)
from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.google_models import GoogleSnapshot
from tridentine_calendar_google_sync.production_write_token import (
    build_initial_production_write_token_generation_state,
)
from tridentine_calendar_google_sync.production_write_token_models import (
    ProductionWriteCredentialSession,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal import (
    ProductionWriteTokenRehearsalOutcome,
    production_write_token_rehearsal_challenge,
)
from tridentine_calendar_google_sync.production_write_token_rehearsal_transport import (
    FakeProductionWriteCredentialSessionProvider,
    FakeProductionWriteTokenReadOnlyTransport,
    FakeProductionWriteTokenReadOnlyTransportProvider,
    ProductionWriteTokenRehearsalTransportError,
    paginate_production_write_token_rehearsal_snapshot,
)


@dataclass(frozen=True)
class RehearsalArtifacts:
    inputs: ProductionPlanningInputs
    session: ProductionWriteCredentialSession
    transport: FakeProductionWriteTokenReadOnlyTransport
    credential_provider: FakeProductionWriteCredentialSessionProvider
    transport_provider: FakeProductionWriteTokenReadOnlyTransportProvider
    confirmation: str


def build_rehearsal_artifacts(
    tmp_path: Path,
    *,
    event_count: int = 4,
    updated_indexes: tuple[int, ...] = (),
    page_sizes: tuple[int, ...] | None = None,
    snapshot_override: GoogleSnapshot | None = None,
    list_failures: Mapping[int, ProductionWriteTokenRehearsalTransportError] | None = None,
    get_failures: Mapping[int, ProductionWriteTokenRehearsalTransportError] | None = None,
) -> RehearsalArtifacts:
    inputs = build_production_planning_inputs(
        tmp_path,
        event_count=event_count,
        updated_indexes=updated_indexes,
    )
    if not updated_indexes:
        current_diff = diff_source_to_snapshot(inputs.updated.source, inputs.snapshot)
        candidate = build_baseline_candidate(
            inputs.updated.profile,
            inputs.updated.source,
            inputs.snapshot,
            current_diff,
        )
        inputs = replace(
            inputs,
            baseline=trust_baseline(candidate, baseline_confirmation_phrase(candidate)),
        )
    state = build_initial_production_write_token_generation_state(
        inputs.target,
        issued_at=ISSUED_AT,
    )
    session = ProductionWriteCredentialSession(
        token=production_token(state),
        generation_state=state,
        refresh_count=0,
    )
    snapshot = snapshot_override or inputs.snapshot
    sizes = page_sizes or (snapshot.event_count,)
    pages = paginate_production_write_token_rehearsal_snapshot(
        snapshot,
        sizes,
        target_summary=inputs.target.expected_summary,
    )
    selected = min(
        snapshot.events,
        key=lambda event: (
            event.safe_ical_uid_reference or "",
            event.safe_event_reference,
        ),
    )
    transport = FakeProductionWriteTokenReadOnlyTransport(
        collections=(pages,),
        get_events=(selected,),
        list_failures=list_failures,
        get_failures=get_failures,
    )
    credential_provider = FakeProductionWriteCredentialSessionProvider(session)
    transport_provider = FakeProductionWriteTokenReadOnlyTransportProvider(transport)
    return RehearsalArtifacts(
        inputs=inputs,
        session=session,
        transport=transport,
        credential_provider=credential_provider,
        transport_provider=transport_provider,
        confirmation=production_write_token_rehearsal_challenge(inputs.target),
    )


def run_rehearsal(artifacts: RehearsalArtifacts) -> ProductionWriteTokenRehearsalOutcome:
    from tridentine_calendar_google_sync.production_write_token_rehearsal import (
        run_production_write_token_readonly_rehearsal_mock,
    )

    inputs = artifacts.inputs
    return run_production_write_token_readonly_rehearsal_mock(
        credential_session_provider=artifacts.credential_provider,
        transport_provider=artifacts.transport_provider,
        target=inputs.target,
        manifest=inputs.manifest,
        accepted_profile=inputs.updated.profile,
        accepted_source=inputs.updated.source,
        trusted_baseline=inputs.baseline,
        confirmation=artifacts.confirmation,
    )
