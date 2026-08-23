from __future__ import annotations

from typing import Any

import pytest
from phase4b_helpers import build_add_apply_bundle, build_update_apply_bundle
from phase5a_helpers import make_test_target_config

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.test_write_approval import (
    TestWriteApprovalError as ApprovalError,
)
from tridentine_calendar_google_sync.test_write_approval import approve_test_write_run_spec
from tridentine_calendar_google_sync.test_write_approval import (
    test_write_approval_challenge as approval_challenge,
)
from tridentine_calendar_google_sync.test_write_run_spec import (
    TestWriteRunSpecError as RunSpecError,
)
from tridentine_calendar_google_sync.test_write_run_spec import build_test_write_run_spec

pytestmark = pytest.mark.google_test_write


def _run_spec(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    *,
    update: bool,
) -> Any:
    import tridentine_calendar_google_sync.test_write_run_spec as run_spec_module

    bundle = (
        build_update_apply_bundle(tmp_path, synthetic_profile_factory)
        if update
        else build_add_apply_bundle(tmp_path, synthetic_profile_factory)
    )
    fingerprint = bundle.snapshot.target_fingerprint
    monkeypatch.setattr(
        run_spec_module,
        "validate_test_write_target_config",
        lambda _target: fingerprint,
    )
    monkeypatch.setattr(
        run_spec_module,
        "test_write_target_reference",
        lambda _target: f"T-{fingerprint[:12]}",
    )
    spec = build_test_write_run_spec(
        bundle.profile,
        bundle.source,
        bundle.snapshot,
        bundle.plan,
        make_test_target_config(),
        trusted_baseline=bundle.baseline if update else None,
    )
    return spec


def _challenge_kwargs(spec: Any) -> dict[str, str | None]:
    return {
        "current_snapshot_hash": spec.current_snapshot_hash,
        "current_plan_hash": spec.plan_hash,
        "current_baseline_hash": spec.trusted_baseline_hash,
    }


@pytest.mark.parametrize("update", (False, True))
def test_exact_challenge_binds_target_run_hash_and_counts(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    update: bool,
) -> None:
    spec = _run_spec(tmp_path, synthetic_profile_factory, monkeypatch, update=update)
    challenge = approval_challenge(spec, **_challenge_kwargs(spec))

    assert challenge == (
        f"AUTHORIZE TEST CALENDAR WRITE {spec.target_safe_ref} "
        f"R-{spec.run_spec_content_hash[:12]} A-{spec.add_count} U-{spec.update_count}"
    )
    assert approve_test_write_run_spec(spec, challenge, **_challenge_kwargs(spec)) is spec


@pytest.mark.parametrize(
    "mutation",
    (
        lambda value: value + " ",
        lambda value: value.lower(),
        lambda value: value.replace("A-1", "A-0"),
        lambda value: value.replace("U-0", "U-1"),
        lambda value: value.replace("R-", "R-f"),
        lambda value: value.replace("T-", "T-f"),
    ),
)
def test_approval_rejects_every_nonexact_confirmation(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    mutation: Any,
) -> None:
    spec = _run_spec(tmp_path, synthetic_profile_factory, monkeypatch, update=False)
    challenge = approval_challenge(spec, **_challenge_kwargs(spec))
    with pytest.raises(ApprovalError) as captured:
        approve_test_write_run_spec(
            spec,
            mutation(challenge),
            **_challenge_kwargs(spec),
        )
    assert captured.value.code == "test_write_approval_mismatch"


@pytest.mark.parametrize(
    "field",
    ("current_snapshot_hash", "current_plan_hash"),
)
def test_approval_rejects_stale_snapshot_or_plan(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    spec = _run_spec(tmp_path, synthetic_profile_factory, monkeypatch, update=False)
    kwargs = _challenge_kwargs(spec)
    kwargs[field] = "f" * 64
    with pytest.raises(ApprovalError):
        approval_challenge(spec, **kwargs)


def test_update_approval_rejects_missing_or_stale_baseline(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _run_spec(tmp_path, synthetic_profile_factory, monkeypatch, update=True)
    for baseline in (None, "f" * 64):
        with pytest.raises(ApprovalError) as captured:
            approval_challenge(
                spec,
                current_snapshot_hash=spec.current_snapshot_hash,
                current_plan_hash=spec.plan_hash,
                current_baseline_hash=baseline,
            )
        assert captured.value.code == "test_write_baseline_stale_or_mismatched"


def test_production_target_cannot_generate_approval(
    tmp_path: Any,
    synthetic_profile_factory: Any,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    spec = _run_spec(tmp_path, synthetic_profile_factory, monkeypatch, update=False)
    production = spec.model_copy(update={"target_safe_ref": PRODUCTION_TARGET_REFERENCE})
    with pytest.raises(RunSpecError):
        approval_challenge(production, **_challenge_kwargs(production))
