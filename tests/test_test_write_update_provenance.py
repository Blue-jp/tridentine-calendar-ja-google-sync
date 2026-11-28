from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from unittest.mock import Mock

import pytest
from conftest import build_synthetic_profile, write_profile_directory
from phase5a1_helpers import SequencePrewriteClient, prewrite_page
from phase5a_helpers import make_test_target_config
from phase5d0_helpers import write_test_target_config
from test_sync_plan import _calendar_bytes, _profile_overrides, _snapshot_document
from test_test_write_transport_phase5a import _Client

from tridentine_calendar_google_sync import cli
from tridentine_calendar_google_sync.baseline_engine import (
    baseline_confirmation_phrase,
    build_baseline_candidate,
    trust_baseline,
)
from tridentine_calendar_google_sync.baseline_io import write_baseline
from tridentine_calendar_google_sync.baseline_models import TrustedBaseline
from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.google_models import GoogleSnapshot
from tridentine_calendar_google_sync.google_sanitize import render_sanitized_snapshot
from tridentine_calendar_google_sync.models import AcceptedSourceProfile, SourceCalendarInspection
from tridentine_calendar_google_sync.plan_engine import (
    build_sync_plan,
    calculate_sync_plan_content_hash,
)
from tridentine_calendar_google_sync.plan_models import PlanThresholds, SyncPlan
from tridentine_calendar_google_sync.plan_report import render_plan_json_report
from tridentine_calendar_google_sync.source_ics import inspect_source
from tridentine_calendar_google_sync.test_calendar_prewrite import inspect_test_calendar_prewrite
from tridentine_calendar_google_sync.test_write_approval import (
    test_write_approval_challenge as approval_challenge,
)
from tridentine_calendar_google_sync.test_write_models import (
    TestWriteOperationKind as OperationKind,
)
from tridentine_calendar_google_sync.test_write_models import TestWriteRunSpec as RunSpec
from tridentine_calendar_google_sync.test_write_run_spec import (
    TestWriteRunSpecError as RunSpecError,
)
from tridentine_calendar_google_sync.test_write_run_spec import (
    build_test_write_run_spec,
    calculate_test_write_operation_hash,
    calculate_test_write_run_spec_hash,
)
from tridentine_calendar_google_sync.test_write_run_spec_io import write_test_write_run_spec
from tridentine_calendar_google_sync.test_write_target import TestWriteTargetConfig as Target
from tridentine_calendar_google_sync.test_write_transport import run_test_calendar_write

pytestmark = pytest.mark.google_test_write


@dataclass
class ApprovedUpdate:
    profile: AcceptedSourceProfile
    source: SourceCalendarInspection
    source_path: Path
    snapshot: GoogleSnapshot
    plan: SyncPlan
    baseline: TrustedBaseline
    target: Target
    page: dict[str, object]
    before: dict[str, object]
    after: dict[str, object]


@pytest.fixture
def approved(tmp_path: Path) -> ApprovedUpdate:
    # One change among 101 events satisfies the normal Plan's mass-change guard.
    count = 101
    path = tmp_path / "source.ics"
    path.write_bytes(_calendar_bytes(count))
    profile = build_synthetic_profile(path, _profile_overrides(count))
    source = inspect_source(path, profile)
    target = make_test_target_config()
    events = _snapshot_document(count)["events"]
    for index, event in enumerate(events):
        event.pop("allDay")
        event["etag"] = f"fixture-etag-{index}"
    unchanged_page = prewrite_page(events, summary=target.expected_summary)
    previous = inspect_test_calendar_prewrite(SequencePrewriteClient([unchanged_page]), target)
    previous_snapshot = previous.snapshot.snapshot
    candidate = build_baseline_candidate(
        profile, source, previous_snapshot, diff_source_to_snapshot(source, previous_snapshot)
    )
    baseline = trust_baseline(candidate, baseline_confirmation_phrase(candidate))

    after = events[0]
    before = {**after, "summary": "Earlier synthetic value", "end": {"date": "2026-01-17"}}
    page = prewrite_page([before, *events[1:]], summary=target.expected_summary)
    snapshot = inspect_test_calendar_prewrite(
        SequencePrewriteClient([page]), target
    ).snapshot.snapshot
    plan = build_sync_plan(
        profile, source, snapshot, baseline, thresholds=PlanThresholds(max_update=2)
    )
    return ApprovedUpdate(
        profile, source, path, snapshot, plan, baseline, target, page, before, after
    )


def _candidate(inputs: ApprovedUpdate, case: str) -> tuple[SyncPlan, RunSpec, str]:
    plan = inputs.plan
    if case == "unreproducible-plan":
        action = plan.proposed_actions[0].model_copy(update={"changed_fields": ("summary",)})
        plan = plan.model_copy(update={"proposed_actions": (action,)})
        plan = plan.model_copy(update={"plan_content_hash": calculate_sync_plan_content_hash(plan)})
    spec = build_test_write_run_spec(
        inputs.profile,
        inputs.source,
        inputs.snapshot,
        plan,
        inputs.target,
        trusted_baseline=inputs.baseline,
    )
    op = spec.operation
    if case == "wrong-event":
        other = next(
            event for event in inputs.snapshot.events if event.event_id != op.google_event_id
        )
        op = op.model_copy(update={"google_event_id": other.event_id})
    elif case == "wrong-fields":
        op = op.model_copy(update={"changed_fields": ("summary",)})
    elif case == "wrong-value":
        desired = op.desired_state.model_copy(update={"summary": inputs.before["summary"]})
        op = op.model_copy(update={"desired_state": desired})
    elif case == "candidate-add":
        op = op.model_copy(
            update={
                "operation": OperationKind.ADD,
                "changed_fields": ("summary", "description", "start_date", "end_date"),
                "google_ref": None,
                "current_state": None,
                "google_event_id": None,
                "expected_etag": None,
            }
        )
        spec = spec.model_copy(
            update={"add_count": 1, "update_count": 0, "trusted_baseline_hash": None}
        )
    op = op.model_copy(update={"operation_content_hash": calculate_test_write_operation_hash(op)})
    spec = spec.model_copy(update={"operation": op})
    spec = spec.model_copy(
        update={"run_spec_content_hash": calculate_test_write_run_spec_hash(spec)}
    )
    challenge = approval_challenge(
        spec,
        current_snapshot_hash=inputs.snapshot.content_hash,
        current_plan_hash=plan.plan_content_hash,
        current_baseline_hash=spec.trusted_baseline_hash,
    )
    return plan, spec, challenge


def _cli_args(
    inputs: ApprovedUpdate, plan: SyncPlan, spec: RunSpec, challenge: str, directory: Path
) -> dict[str, str]:
    write_test_write_run_spec(spec, directory / "spec.json")
    (directory / "plan.json").write_bytes(render_plan_json_report(plan).encode("utf-8"))
    (directory / "snapshot.json").write_bytes(render_sanitized_snapshot(inputs.snapshot))
    write_baseline(inputs.baseline, directory / "baseline.json")
    write_test_target_config(inputs.target, directory / "target.toml")
    profiles = write_profile_directory(inputs.profile, directory / "profiles")
    return {
        "--run-spec": str(directory / "spec.json"),
        "--plan": str(directory / "plan.json"),
        "--profile": inputs.profile.profile_id,
        "--profiles-dir": str(profiles),
        "--source": str(inputs.source_path),
        "--google-snapshot": str(directory / "snapshot.json"),
        "--trusted-baseline": str(directory / "baseline.json"),
        "--target-config": str(directory / "target.toml"),
        "--token-file": str(directory / "unused-write.json"),
        "--production-read-token-file": str(directory / "unused-read.json"),
        "--confirmation": challenge,
        "--journal-output": str(directory / "journal.json"),
        "--report-output": str(directory / "report.json"),
        "--format": "json",
    }


def _run_cli(args: dict[str, str]) -> int:
    return cli.main(
        ["run-test-calendar-write", "--online", *(s for pair in args.items() for s in pair)]
    )


def test_update_uses_only_approved_patch_arguments(
    approved: ApprovedUpdate, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    plan, spec, challenge = _candidate(approved, "approved")
    client = _Client(
        list_queue=[approved.page],
        get_queue=[approved.before, approved.after],
        patch_queue=[approved.after],
    )
    monkeypatch.setattr(cli, "load_google_optional_bindings", Mock())
    monkeypatch.setattr(cli, "load_test_write_credentials", Mock())
    monkeypatch.setattr(cli, "build_test_calendar_write_client", Mock(return_value=client))
    assert _run_cli(_cli_args(approved, plan, spec, challenge, tmp_path)) == cli.EXIT_VALID
    assert [name for name, _ in client.calls] == ["list", "get", "patch", "get"]
    # Expected ID/ETag come from the approved snapshot; new values come from the independent ICS.
    action = plan.proposed_actions[0]
    original = next(
        e for e in approved.snapshot.events if e.safe_event_reference == action.google_refs[0]
    )
    desired = next(e for e in approved.source.events if e.safe_uid_reference == action.source_ref)
    assert set(action.changed_fields) == {"summary", "end_date"}
    assert client.calls[2][1] == {
        "event_id": original.event_id,
        "etag": original.etag,
        "body": {
            "summary": desired.summary,
            "start": {"date": desired.start_date.isoformat()},
            "end": {"date": desired.effective_end_date.isoformat()},
        },
    }
    report = json.loads((tmp_path / "report.json").read_bytes())
    assert report["success"] and report["read_back_verified"]
    assert report["mutation_attempt_count"] == 1 and report["mutation_retry_count"] == 0


@pytest.mark.parametrize(
    ("case", "code"),
    [
        ("wrong-event", "test_write_update_evidence_mismatch"),
        ("wrong-fields", "test_write_update_evidence_mismatch"),
        ("wrong-value", "test_write_update_evidence_mismatch"),
        ("candidate-add", "test_write_plan_operation_mismatch"),
        ("unreproducible-plan", "test_write_plan_recomputation_mismatch"),
        ("normal_plan", "test_write_normal_plan_required"),
        ("update_profile", "test_write_update_inputs_required"),
        ("update_source", "test_write_update_inputs_required"),
        ("update_snapshot", "test_write_update_inputs_required"),
        ("trusted_baseline", "test_write_update_inputs_required"),
    ],
)
def test_update_rejects_before_client_or_credentials(
    case: str,
    code: str,
    approved: ApprovedUpdate,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    plan, spec, challenge = _candidate(approved, case)
    evidence: dict[str, Any] = {
        "normal_plan": plan,
        "update_profile": approved.profile,
        "update_source": approved.source,
        "update_snapshot": approved.snapshot,
        "trusted_baseline": approved.baseline,
    }
    cli_args = _cli_args(approved, plan, spec, challenge, tmp_path)
    cli_options = {
        "normal_plan": "--plan",
        "update_profile": "--profile",
        "update_source": "--source",
        "update_snapshot": "--google-snapshot",
        "trusted_baseline": "--trusted-baseline",
    }
    if case in cli_options:
        del evidence[case]
        del cli_args[cli_options[case]]
    client = Mock(spec=_Client)
    with pytest.raises(RunSpecError) as stopped:
        run_test_calendar_write(
            spec,
            approved.target,
            client,
            challenge,
            current_snapshot_hash=approved.snapshot.content_hash,
            current_plan_hash=plan.plan_content_hash,
            current_baseline_hash=spec.trusted_baseline_hash,
            **evidence,
        )
    assert stopped.value.code == code
    assert not client.mock_calls

    bindings, credentials, build_client = Mock(), Mock(), Mock(return_value=client)
    monkeypatch.setattr(cli, "load_google_optional_bindings", bindings)
    monkeypatch.setattr(cli, "load_test_write_credentials", credentials)
    monkeypatch.setattr(cli, "build_test_calendar_write_client", build_client)
    exit_code = _run_cli(cli_args)
    err = capsys.readouterr().err
    if case == "normal_plan":
        assert exit_code == cli.EXIT_CLI_ERROR and "--plan" in err
    else:
        assert exit_code == cli.EXIT_FATAL_GUARD
        assert stopped.value.public_message in err
    bindings.assert_not_called()
    credentials.assert_not_called()
    build_client.assert_not_called()
    assert not client.mock_calls
    assert not (tmp_path / "journal.json").exists()
    assert not (tmp_path / "report.json").exists()
