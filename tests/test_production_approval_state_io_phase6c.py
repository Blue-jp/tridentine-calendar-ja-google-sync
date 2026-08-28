from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Any

import jsonschema  # type: ignore[import-untyped]
import pytest
from conftest import REPOSITORY_ROOT
from test_production_approval_state_phase6c import (
    _artifacts,
    _rehash_permit,
)

from tridentine_calendar_google_sync.production_approval_state import (
    ProductionApprovalStateError,
)
from tridentine_calendar_google_sync.production_approval_state_io import (
    ProductionApprovalStateIOError,
    build_phase6c_mock_approval_store,
    consume_production_execute_permit,
    load_production_arm_receipt,
    load_production_execute_permit,
    load_production_execute_permit_consumption,
    load_production_kill_switch,
    production_execute_permit_consumption_filename,
    render_production_permit_consumption_json,
    write_production_arm_receipt,
    write_production_execute_permit,
    write_production_kill_switch,
)
from tridentine_calendar_google_sync.production_approval_state_models import (
    ProductionExecutePermit,
)
from tridentine_calendar_google_sync.sensitive_paths import SensitivePathError


def test_artifacts_are_atomic_private_no_overwrite_and_repository_external(
    tmp_path: Path,
) -> None:
    artifacts = _artifacts(tmp_path / "fixtures")
    switch_path = artifacts.approval_store_directory / "switch.json"
    arm_path = artifacts.approval_store_directory / "arm.json"
    permit_path = artifacts.approval_store_directory / "permit.json"

    write_production_kill_switch(
        artifacts.kill_switch,
        switch_path,
        approval_store=artifacts.approval_store,
    )
    write_production_arm_receipt(
        artifacts.receipt,
        arm_path,
        approval_store=artifacts.approval_store,
    )
    write_production_execute_permit(
        artifacts.permit,
        permit_path,
        approval_store=artifacts.approval_store,
    )
    assert (
        load_production_kill_switch(
            switch_path,
            approval_store=artifacts.approval_store,
        )
        == artifacts.kill_switch
    )
    assert (
        load_production_arm_receipt(
            arm_path,
            approval_store=artifacts.approval_store,
            now=artifacts.receipt.issued_at,
        )
        == artifacts.receipt
    )
    assert (
        load_production_execute_permit(
            permit_path,
            approval_store=artifacts.approval_store,
            now=artifacts.permit.issued_at,
        )
        == artifacts.permit
    )
    if os.name != "nt":
        assert switch_path.stat().st_mode & 0o077 == 0
        assert arm_path.stat().st_mode & 0o077 == 0
        assert permit_path.stat().st_mode & 0o077 == 0

    for writer, artifact, path in (
        (write_production_kill_switch, artifacts.kill_switch, switch_path),
        (write_production_arm_receipt, artifacts.receipt, arm_path),
        (write_production_execute_permit, artifacts.permit, permit_path),
    ):
        with pytest.raises(ProductionApprovalStateIOError):
            writer(  # type: ignore[call-arg]
                artifact,
                path,
                approval_store=artifacts.approval_store,
            )

    repository_path = REPOSITORY_ROOT / "forbidden-production-approval-state.json"
    with pytest.raises(ProductionApprovalStateIOError):
        write_production_execute_permit(
            artifacts.permit,
            repository_path,
            approval_store=artifacts.approval_store,
        )
    assert not repository_path.exists()


def test_atomic_consumption_has_exactly_one_concurrent_winner(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path / "fixtures")
    state_path = (
        artifacts.approval_store_directory
        / production_execute_permit_consumption_filename(artifacts.permit)
    )
    consumed_at = artifacts.permit.issued_at + timedelta(seconds=1)

    def consume() -> str:
        try:
            result = consume_production_execute_permit(
                artifacts.permit,
                state_path,
                approval_store=artifacts.approval_store,
                consumed_at=consumed_at,
            )
            return result.state
        except ProductionApprovalStateIOError as exc:
            return exc.code

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = tuple(executor.map(lambda _: consume(), range(2)))

    assert sorted(results) == ["consumed", "production_execute_permit_already_consumed"]
    durable = load_production_execute_permit_consumption(
        state_path,
        approval_store=artifacts.approval_store,
        permit=artifacts.permit,
    )
    assert durable.state == "consumed"
    assert durable.permit_hash == artifacts.permit.content_hash
    assert durable.approval_store_hash == artifacts.approval_store.content_hash
    with pytest.raises(ProductionApprovalStateIOError) as replay:
        consume_production_execute_permit(
            artifacts.permit,
            state_path,
            approval_store=artifacts.approval_store,
            consumed_at=consumed_at + timedelta(seconds=1),
        )
    assert replay.value.code == "production_execute_permit_already_consumed"


def test_consumed_state_is_fsynced_before_return(tmp_path: Path, monkeypatch: Any) -> None:
    artifacts = _artifacts(tmp_path / "fixtures")
    state_path = (
        artifacts.approval_store_directory
        / production_execute_permit_consumption_filename(artifacts.permit)
    )
    calls = 0
    original_fsync = os.fsync

    def counting_fsync(descriptor: int) -> None:
        nonlocal calls
        calls += 1
        original_fsync(descriptor)

    monkeypatch.setattr(
        "tridentine_calendar_google_sync.sensitive_paths.os.fsync",
        counting_fsync,
    )
    consumption = consume_production_execute_permit(
        artifacts.permit,
        state_path,
        approval_store=artifacts.approval_store,
        consumed_at=artifacts.permit.issued_at + timedelta(seconds=1),
    )
    assert calls >= 1
    assert (
        load_production_execute_permit_consumption(
            state_path,
            approval_store=artifacts.approval_store,
            permit=artifacts.permit,
        )
        == consumption
    )


def test_consumption_tamper_and_noncanonical_state_are_detected(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path / "fixtures")
    state_path = (
        artifacts.approval_store_directory
        / production_execute_permit_consumption_filename(artifacts.permit)
    )
    consumption = consume_production_execute_permit(
        artifacts.permit,
        state_path,
        approval_store=artifacts.approval_store,
        consumed_at=artifacts.permit.issued_at + timedelta(seconds=1),
    )
    schema = json.loads(
        (
            REPOSITORY_ROOT / "schemas" / "production-execute-permit-consumption-v1.schema.json"
        ).read_text("utf-8")
    )
    document = json.loads(render_production_permit_consumption_json(consumption))
    jsonschema.validate(document, schema)
    assert schema["additionalProperties"] is False

    document["content_hash"] = "f" * 64
    state_path.write_text(
        json.dumps(document, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(ProductionApprovalStateError):
        load_production_execute_permit_consumption(
            state_path,
            approval_store=artifacts.approval_store,
            permit=artifacts.permit,
        )


def test_consumption_rejects_wrong_permit_binding(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path / "fixtures")
    state_path = (
        artifacts.approval_store_directory
        / production_execute_permit_consumption_filename(artifacts.permit)
    )
    consume_production_execute_permit(
        artifacts.permit,
        state_path,
        approval_store=artifacts.approval_store,
        consumed_at=artifacts.permit.issued_at + timedelta(seconds=1),
    )
    alternate = _rehash_permit(
        artifacts.permit,
        "run_spec_hash",
        "e" * 64,
    )
    with pytest.raises(ProductionApprovalStateError):
        load_production_execute_permit_consumption(
            state_path,
            approval_store=artifacts.approval_store,
            permit=alternate,
        )


def test_symlink_paths_are_rejected_when_supported(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path / "fixtures")
    real_directory = tmp_path / "real"
    real_directory.mkdir()
    linked_directory = tmp_path / "linked"
    try:
        linked_directory.symlink_to(real_directory, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(ProductionApprovalStateIOError) as captured:
        consume_production_execute_permit(
            artifacts.permit,
            linked_directory / production_execute_permit_consumption_filename(artifacts.permit),
            approval_store=artifacts.approval_store,
            consumed_at=artifacts.permit.issued_at + timedelta(seconds=1),
        )
    assert isinstance(captured.value.__cause__, SensitivePathError)


def test_expired_or_not_yet_valid_permit_is_never_consumed(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path / "fixtures")
    for now in (
        artifacts.permit.issued_at - timedelta(microseconds=1),
        artifacts.permit.expires_at,
    ):
        path = artifacts.approval_store_directory / production_execute_permit_consumption_filename(
            artifacts.permit
        )
        with pytest.raises(ProductionApprovalStateError):
            consume_production_execute_permit(
                artifacts.permit,
                path,
                approval_store=artifacts.approval_store,
                consumed_at=now,
            )
        assert not path.exists()


def test_no_permit_state_api_accepts_overwrite_or_repository_paths() -> None:
    import inspect

    signatures = (
        inspect.signature(write_production_kill_switch),
        inspect.signature(write_production_arm_receipt),
        inspect.signature(write_production_execute_permit),
        inspect.signature(consume_production_execute_permit),
    )
    assert all("overwrite" not in signature.parameters for signature in signatures)


def test_consumption_filename_is_content_addressed_and_mismatch_is_rejected(
    tmp_path: Path,
) -> None:
    artifacts = _artifacts(tmp_path / "fixtures")
    filename = production_execute_permit_consumption_filename(artifacts.permit)
    assert artifacts.permit.content_hash in filename
    with pytest.raises(ProductionApprovalStateIOError) as captured:
        consume_production_execute_permit(
            artifacts.permit,
            artifacts.approval_store_directory / "alternate-ledger-key.json",
            approval_store=artifacts.approval_store,
            consumed_at=artifacts.permit.issued_at + timedelta(seconds=1),
        )
    assert captured.value.code == "production_execute_consumption_path_mismatch"


def test_alternate_store_directory_is_rejected_before_consumption(tmp_path: Path) -> None:
    artifacts = _artifacts(tmp_path / "fixtures")
    alternate_directory = tmp_path / "alternate-store"
    alternate_directory.mkdir()
    alternate_store = build_phase6c_mock_approval_store(alternate_directory)
    alternate_path = alternate_directory / production_execute_permit_consumption_filename(
        artifacts.permit
    )

    with pytest.raises(ProductionApprovalStateIOError) as bound:
        consume_production_execute_permit(
            artifacts.permit,
            alternate_path,
            approval_store=alternate_store,
            consumed_at=artifacts.permit.issued_at + timedelta(seconds=1),
        )
    assert bound.value.code == "phase6c_mock_approval_store_binding_mismatch"
    assert not alternate_path.exists()

    with pytest.raises(ProductionApprovalStateIOError) as directory:
        consume_production_execute_permit(
            artifacts.permit,
            alternate_path,
            approval_store=artifacts.approval_store,
            consumed_at=artifacts.permit.issued_at + timedelta(seconds=1),
        )
    assert directory.value.code == "phase6c_mock_approval_store_directory_mismatch"
    assert not alternate_path.exists()


def test_model_contains_generation_only_not_token_or_path() -> None:
    fields = set(ProductionExecutePermit.model_fields)
    assert "write_token_generation" in fields
    assert fields.isdisjoint(
        {
            "token",
            "token_path",
            "credentials",
            "client",
            "calendar_id",
            "event_id",
            "etag",
        }
    )
