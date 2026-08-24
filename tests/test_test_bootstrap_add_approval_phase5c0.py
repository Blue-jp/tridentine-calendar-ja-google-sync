from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from phase5c0_helpers import build_bootstrap_bundle

from tridentine_calendar_google_sync.test_bootstrap_approval import (
    TestBootstrapApprovalError as ApprovalError,
)
from tridentine_calendar_google_sync.test_bootstrap_approval import (
    approve_test_bootstrap_add_run_spec,
)
from tridentine_calendar_google_sync.test_bootstrap_approval import (
    test_bootstrap_add_approval_challenge as approval_challenge,
)
from tridentine_calendar_google_sync.test_bootstrap_plan import (
    TestBootstrapPlanError as BootstrapError,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec import (
    TestBootstrapRunSpecError as RunSpecError,
)
from tridentine_calendar_google_sync.test_bootstrap_run_spec import (
    build_test_bootstrap_add_run_spec,
    calculate_test_bootstrap_add_run_spec_hash,
)
from tridentine_calendar_google_sync.test_write_approval_dispatch import (
    any_test_write_approval_challenge,
    approve_any_test_write_run_spec,
)
from tridentine_calendar_google_sync.test_write_spec_dispatch import (
    TestWriteSpecDispatchError as DispatchError,
)


def _inputs(tmp_path: Path) -> tuple[Any, Any]:
    bundle = build_bootstrap_bundle(tmp_path)
    run_spec = build_test_bootstrap_add_run_spec(
        bundle.profile,
        bundle.source,
        bundle.prewrite_snapshot,
        bundle.plan,
        bundle.target,
    )
    return bundle, run_spec


def _kwargs(bundle: Any, run_spec: Any) -> dict[str, object]:
    return {
        "current_snapshot_hash": run_spec.current_snapshot_hash,
        "current_plan_hash": bundle.plan.plan_content_hash,
        "current_baseline_hash": None,
    }


def test_exact_bootstrap_challenge_keeps_existing_format_and_approves(
    tmp_path: Path,
) -> None:
    bundle, run_spec = _inputs(tmp_path)
    challenge = approval_challenge(run_spec, bundle.plan, **_kwargs(bundle, run_spec))

    assert challenge == (
        f"AUTHORIZE TEST CALENDAR WRITE {run_spec.target_safe_ref} "
        f"R-{run_spec.run_spec_content_hash[:12]} A-1 U-0"
    )
    assert (
        approve_test_bootstrap_add_run_spec(
            run_spec,
            bundle.plan,
            challenge,
            **_kwargs(bundle, run_spec),
        )
        is run_spec
    )


def test_union_dispatch_requires_exact_bootstrap_plan_and_returns_same_challenge(
    tmp_path: Path,
) -> None:
    bundle, run_spec = _inputs(tmp_path)
    direct = approval_challenge(run_spec, bundle.plan, **_kwargs(bundle, run_spec))
    dispatched = any_test_write_approval_challenge(
        run_spec,
        bootstrap_plan=bundle.plan,
        **_kwargs(bundle, run_spec),
    )

    assert dispatched == direct
    assert (
        approve_any_test_write_run_spec(
            run_spec,
            direct,
            bootstrap_plan=bundle.plan,
            **_kwargs(bundle, run_spec),
        )
        is run_spec
    )
    with pytest.raises(DispatchError):
        any_test_write_approval_challenge(run_spec, **_kwargs(bundle, run_spec))


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value + " ",
        lambda value: value.lower(),
        lambda value: value.replace("T-", "T-f"),
        lambda value: value.replace("R-", "R-f"),
        lambda value: value.replace("A-1", "A-0"),
        lambda value: value.replace("U-0", "U-1"),
    ),
)
def test_every_nonexact_confirmation_is_rejected(
    tmp_path: Path,
    mutation: Any,
) -> None:
    bundle, run_spec = _inputs(tmp_path)
    challenge = approval_challenge(run_spec, bundle.plan, **_kwargs(bundle, run_spec))

    with pytest.raises(ApprovalError) as captured:
        approve_test_bootstrap_add_run_spec(
            run_spec,
            bundle.plan,
            mutation(challenge),
            **_kwargs(bundle, run_spec),
        )
    assert captured.value.code == "test_bootstrap_approval_mismatch"


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("current_snapshot_hash", "f" * 64),
        ("current_plan_hash", "e" * 64),
        ("current_baseline_hash", "d" * 64),
    ),
)
def test_stale_snapshot_plan_or_any_baseline_is_rejected(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    bundle, run_spec = _inputs(tmp_path)
    kwargs = _kwargs(bundle, run_spec)
    kwargs[field] = value

    with pytest.raises(ApprovalError):
        approval_challenge(run_spec, bundle.plan, **kwargs)


def test_tampered_plan_or_run_spec_cannot_generate_challenge(tmp_path: Path) -> None:
    bundle, run_spec = _inputs(tmp_path)
    plan = bundle.plan.model_copy(update={"plan_content_hash": "f" * 64})
    provisional = run_spec.model_copy(
        update={"snapshot_event_count": 1, "run_spec_content_hash": "0" * 64}
    )
    tampered_run_spec = provisional.model_copy(
        update={"run_spec_content_hash": calculate_test_bootstrap_add_run_spec_hash(provisional)}
    )

    with pytest.raises(BootstrapError):
        approval_challenge(run_spec, plan, **_kwargs(bundle, run_spec))
    with pytest.raises(RunSpecError):
        approval_challenge(
            tampered_run_spec,
            bundle.plan,
            **_kwargs(bundle, tampered_run_spec),
        )
