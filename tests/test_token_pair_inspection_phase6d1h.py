"""Synthetic read-only observations; matching files never authorize recovery."""

from __future__ import annotations

import ast
import sys
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, asdict
from datetime import timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from phase6d0_auth_helpers import ISSUED_AT, production_target, production_token

from tridentine_calendar_google_sync import production_write_token as tokens
from tridentine_calendar_google_sync import production_write_token_io as io
from tridentine_calendar_google_sync import production_write_token_pair_inspection as inspection
from tridentine_calendar_google_sync.production_write_token_models import (
    ProductionWriteGrantEvidenceOrigin,
)

S = inspection.PairInspectionState
LINUX_ONLY = pytest.mark.skipif(sys.platform != "linux", reason="real Linux inspection flock")
NOW = ISSUED_AT + timedelta(seconds=2)


def _fixture(tmp_path: Path, *, split: bool = False, expired: bool = False) -> tuple[Any, ...]:
    root = tmp_path / "private-pair"
    root.mkdir(mode=0o700)
    other = tmp_path / "private-state" if split else root
    if split:
        other.mkdir(mode=0o700)
    token_path, state_path = root / "token.json", other / "state.json"
    target = production_target()
    state = tokens.build_initial_production_write_token_generation_state(
        target, issued_at=ISSUED_AT
    )
    expiry = ISSUED_AT + timedelta(seconds=1) if expired else NOW + timedelta(hours=1)
    token = production_token(state, expiry=expiry)
    # Synthetic claimed provider-origin data: local validation is NOT attestation.
    token = token.model_copy(
        update={
            "grant_evidence": token.grant_evidence.model_copy(
                update={
                    "origin": ProductionWriteGrantEvidenceOrigin.FRESH_AUTHORIZATION_RESPONSE,
                }
            ),
        }
    )
    io.write_production_write_token_bundle(token, token_path, state, state_path)
    return target, token_path, state_path, token, state


def _inspect(f: tuple[Any, ...], *, now: Any = NOW) -> inspection.TokenPairInspection:
    target, token_path, state_path, *_ = f
    return inspection.inspect_production_write_token_pair(
        token_path,
        state_path,
        token_path.with_name("read.json"),
        token_path.with_name("test.json"),
        target,
        now=now,
    )


def _deny(*_a: Any, **_kw: Any) -> Any:
    raise AssertionError("unexpected mutation, provider activity or credential session")


def _assert_summary(result: inspection.TokenPairInspection, state: S, f: tuple[Any, ...]) -> None:
    assert result.state is state and result.reuse_authorized is False
    assert set(asdict(result)) == {"state", "token_expired", "reuse_authorized"}
    text = repr(result) + str(asdict(result))
    target, token_path, state_path, token, generation = f
    for value in (
        str(token_path),
        str(state_path),
        target.calendar_id,
        token.access_token,
        token.refresh_token,
        token.client_secret,
        token.client_id,
        generation.content_hash,
        generation.target_config_hash,
        "PRIVATE_FAILURE",
    ):
        assert value not in text
    if state is not S.LOCAL_CONTENTS_CONSISTENT_NOT_APPROVED:
        assert result.token_expired is None


@pytest.mark.parametrize("split", (False, True))
@pytest.mark.parametrize("expired", (False, True))
def test_real_pair_observation_is_read_only_and_never_approved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, split: bool, expired: bool
) -> None:
    f = _fixture(tmp_path, split=split, expired=expired)
    before = [
        (p.read_bytes(), p.stat().st_ino, p.stat().st_mode, p.stat().st_mtime_ns) for p in f[1:3]
    ]
    for name in (
        "write_production_write_token_bundle",
        "write_production_write_authorized_user_token",
        "write_production_write_token_generation_state",
        "persist_refreshed_production_write_token",
        "_remove_exact_new_artifact",
    ):
        monkeypatch.setattr(io, name, _deny)
    monkeypatch.setattr(tokens, "_load_production_write_credential_session", _deny)
    monkeypatch.setattr(tokens, "authorize_production_write_token", _deny)
    result = _inspect(f)
    _assert_summary(result, S.LOCAL_CONTENTS_CONSISTENT_NOT_APPROVED, f)
    assert result.token_expired is expired
    assert [
        (p.read_bytes(), p.stat().st_ino, p.stat().st_mode, p.stat().st_mtime_ns) for p in f[1:3]
    ] == before
    expected = {"token.json"} if split else {"token.json", "state.json"}
    assert {p.name for p in f[1].parent.iterdir()} == expected


@pytest.mark.parametrize(
    "clock",
    (
        None,
        "2099-01-01",
        NOW.replace(tzinfo=None),
        NOW.astimezone(timezone(timedelta(hours=9))),
    ),
)
def test_invalid_clock_stops_before_paths_locks_or_reads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clock: Any
) -> None:
    f = _fixture(tmp_path)
    monkeypatch.setattr(inspection, "validate_production_write_token_path_set", _deny)
    monkeypatch.setattr(inspection, "_production_write_session_lock", _deny)
    _assert_summary(_inspect(f, now=clock), S.INPUT_UNVERIFIED, f)


@pytest.mark.parametrize("role", (1, 2))
@pytest.mark.parametrize("defect", ("missing", "malformed"))
def test_missing_or_noncanonical_is_unverified_not_absence(
    tmp_path: Path, role: int, defect: str
) -> None:
    f = _fixture(tmp_path)
    if defect == "missing":
        f[role].unlink()
    else:
        f[role].write_bytes(b'{"PRIVATE_FAILURE":')
    _assert_summary(_inspect(f), S.INPUT_UNVERIFIED, f)


@pytest.mark.parametrize("mismatch", ("generation", "target", "fixture_evidence"))
def test_locally_parseable_pair_can_fail_existing_provider_mode_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mismatch: str
) -> None:
    f = _fixture(tmp_path)
    token = f[3]
    if mismatch == "generation":
        token = token.model_copy(update={"generation": 2})
    elif mismatch == "target":
        token = token.model_copy(update={"target_config_hash": "a" * 64})
    else:
        token = token.model_copy(
            update={
                "grant_evidence": token.grant_evidence.model_copy(
                    update={
                        "origin": (
                            ProductionWriteGrantEvidenceOrigin.TEST_FIXTURE_AUTHORIZATION_RESPONSE
                        ),
                    }
                )
            }
        )
    monkeypatch.setattr(inspection, "load_production_write_authorized_user_token", lambda _p: token)
    _assert_summary(_inspect(f), S.PAIR_REJECTED, f)


@pytest.mark.parametrize("which", ("token", "state"))
def test_second_sample_change_is_reported_without_repair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, which: str
) -> None:
    f = _fixture(tmp_path)
    calls = []
    first = f[3] if which == "token" else f[4]
    if which == "token":
        second = first.model_copy(update={"access_token": "changed-synthetic"})
        name = "load_production_write_authorized_user_token"
    else:
        second = tokens.build_next_production_write_token_generation_state(
            first,
            f[0],
            issued_at=NOW,
        )
        name = "load_production_write_token_generation_state"

    def read(_p: Path) -> Any:
        calls.append(1)
        return first if len(calls) == 1 else second

    monkeypatch.setattr(inspection, name, read)
    _assert_summary(_inspect(f), S.CONTENTS_CHANGED, f)
    assert len(calls) == 2


@pytest.mark.parametrize("stage", ("preflight", "read", "render", "verify", "second_read"))
def test_ordinary_errors_return_only_fixed_summary_not_private_exception_details(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    f = _fixture(tmp_path)

    def fail(*_a: Any, **_kw: Any) -> Any:
        raise OSError("PRIVATE_FAILURE " + str(f[1]) + f[3].refresh_token)

    if stage == "preflight":
        monkeypatch.setattr(inspection, "validate_production_write_token_path_set", fail)
    elif stage == "read":
        monkeypatch.setattr(inspection, "load_production_write_authorized_user_token", fail)
    elif stage == "render":
        monkeypatch.setattr(inspection, "render_production_write_authorized_user_token_json", fail)
    elif stage == "verify":
        monkeypatch.setattr(inspection, "verify_production_write_authorized_user_token", fail)
    else:
        calls = []

        def read(_p: Path) -> Any:
            calls.append(1)
            return f[3] if len(calls) == 1 else fail()

        monkeypatch.setattr(inspection, "load_production_write_authorized_user_token", read)
    expected = S.INSPECTION_UNVERIFIED if stage in ("render", "verify") else S.INPUT_UNVERIFIED
    _assert_summary(_inspect(f), expected, f)


@pytest.mark.parametrize("failure", ("busy", "acquisition", "checkpoint", "exit"))
def test_lock_failures_never_yield_positive_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    f = _fixture(tmp_path)
    events = []

    @contextmanager
    def lock(*_a: Any) -> Any:
        if failure in ("busy", "acquisition"):
            raise tokens.ProductionWriteTokenSessionLockError(busy=failure == "busy")
        events.append("enter")

        def checkpoint() -> None:
            if failure == "checkpoint":
                raise tokens.ProductionWriteTokenSessionLockError()

        try:
            yield checkpoint
            if failure == "exit":
                raise tokens.ProductionWriteTokenSessionLockError()
        finally:
            events.append("close")

    monkeypatch.setattr(inspection, "_production_write_session_lock", lock)
    _assert_summary(_inspect(f), S.LOCK_BUSY if failure == "busy" else S.LOCK_UNVERIFIED, f)
    assert events == ([] if failure in ("busy", "acquisition") else ["enter", "close"])


@pytest.mark.parametrize("cancel", (KeyboardInterrupt, SystemExit))
def test_cancellation_unwinds_lock_and_does_not_manufacture_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, cancel: type[BaseException]
) -> None:
    f = _fixture(tmp_path)
    events = []

    @contextmanager
    def lock(*_a: Any) -> Any:
        events.append("enter")
        try:
            yield lambda: None
        finally:
            events.append("close")

    def interrupted(_p: Path) -> Any:
        raise cancel()

    monkeypatch.setattr(inspection, "_production_write_session_lock", lock)
    monkeypatch.setattr(inspection, "load_production_write_token_generation_state", interrupted)
    with pytest.raises(cancel):
        _inspect(f)
    assert events == ["enter", "close"]


@LINUX_ONLY
@pytest.mark.parametrize("role", (1, 2))
def test_inspection_contends_with_session_and_bundle_protocol_before_content_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, role: int
) -> None:
    from tridentine_calendar_google_sync import _posix_private_lock as locking

    f = _fixture(tmp_path, split=True)
    monkeypatch.setattr(inspection, "load_production_write_token_generation_state", _deny)
    with locking.acquire_posix_private_directory_lock(f[role].parent):
        _assert_summary(_inspect(f), S.LOCK_BUSY, f)


@LINUX_ONLY
@pytest.mark.parametrize("role", (1, 2))
def test_real_posix_permissions_are_not_repaired(tmp_path: Path, role: int) -> None:
    f = _fixture(tmp_path)
    f[role].chmod(0o644)
    before = f[role].read_bytes()
    _assert_summary(_inspect(f), S.INPUT_UNVERIFIED, f)
    assert f[role].read_bytes() == before and f[role].stat().st_mode & 0o777 == 0o644


def test_windows_shared_context_does_not_claim_or_attempt_linux_serialization(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tridentine_calendar_google_sync import _posix_private_lock as locking

    f = _fixture(tmp_path)
    monkeypatch.setattr(tokens, "os", SimpleNamespace(name="nt"))
    monkeypatch.setattr(locking, "acquire_posix_private_directory_lock", _deny)
    _assert_summary(_inspect(f), S.LOCAL_CONTENTS_CONSISTENT_NOT_APPROVED, f)


@LINUX_ONLY
def test_same_content_replacement_can_pass_but_never_authorizes_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = _fixture(tmp_path)
    reader = inspection.load_production_write_authorized_user_token
    calls = []
    first_inode = f[1].stat().st_ino

    def read(path: Path) -> Any:
        calls.append(1)
        if len(calls) == 2:
            saved = path.with_name("synthetic-old-inode.json")
            path.rename(saved)
            io.write_production_write_authorized_user_token(f[3], path)
        return reader(path)

    monkeypatch.setattr(inspection, "load_production_write_authorized_user_token", read)
    result = _inspect(f)
    _assert_summary(result, S.LOCAL_CONTENTS_CONSISTENT_NOT_APPROVED, f)
    assert f[1].stat().st_ino != first_inode


def test_matching_residue_after_reported_bundle_failure_is_not_recovery_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Simulate a caller receiving an error AFTER both local files were created.
    f = _fixture(tmp_path)
    failure = io.ProductionWriteTokenIOError(
        "synthetic_postpublication_failure",
        "synthetic",
        publication_possible=True,
        completed_output_count=2,
    )
    assert failure.completed_output_count == 2
    monkeypatch.setattr(tokens, "_load_production_write_credential_session", _deny)
    result = _inspect(f)
    _assert_summary(result, S.LOCAL_CONTENTS_CONSISTENT_NOT_APPROVED, f)
    assert not result.reuse_authorized


def test_summary_frozen_and_only_non_sensitive_fields(tmp_path: Path) -> None:
    f = _fixture(tmp_path)
    result = _inspect(f)
    with pytest.raises(FrozenInstanceError):
        result.reuse_authorized = True
    assert result.reuse_authorized is False


def test_inspector_has_no_cli_consumer_provider_session_or_mutation_calls() -> None:
    path = Path(inspection.__file__)
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names = {
        n.func.id
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
    }
    attrs = {
        n.func.attr
        for n in ast.walk(tree)
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
    }
    assert "_production_write_session_lock" in names
    assert not names & {
        "_load_production_write_credential_session",
        "persist_refreshed_production_write_token",
        "print",
        "open",
    }
    assert not attrs & {
        "write_bytes",
        "write_text",
        "unlink",
        "rename",
        "replace",
        "chmod",
        "authorize",
        "refresh",
        "sha256",
        "sha1",
    }
    for module in path.parent.glob("*.py"):
        if module != path:
            assert "production_write_token_pair_inspection" not in module.read_text(
                encoding="utf-8"
            )


@LINUX_ONLY
def test_real_failed_final_bundle_checkpoint_leaves_observable_but_unapproved_pair(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = _fixture(tmp_path)
    residual_token = f[1].with_name("residual-token.json")
    residual_state = f[2].with_name("residual-state.json")
    original = io._production_write_session_lock

    @contextmanager
    def fail_final(*args: Any) -> Any:
        with original(*args) as native:
            count = 0

            def checkpoint() -> None:
                nonlocal count
                native()
                count += 1
                if count == 2:
                    raise tokens.ProductionWriteTokenSessionLockError()

            yield checkpoint

    with monkeypatch.context() as scoped:
        scoped.setattr(io, "_production_write_session_lock", fail_final)
        with pytest.raises(io.ProductionWriteTokenIOError) as caught:
            io.write_production_write_token_bundle(f[3], residual_token, f[4], residual_state)
    assert caught.value.completed_output_count == 2
    assert caught.value.publication_possible is True
    residual = (f[0], residual_token, residual_state, f[3], f[4])
    _assert_summary(_inspect(residual), S.LOCAL_CONTENTS_CONSISTENT_NOT_APPROVED, residual)
    assert residual_token.exists() and residual_state.exists()


def test_double_read_and_final_checkpoint_remain_inside_one_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    f = _fixture(tmp_path)
    events = []
    state_reader = inspection.load_production_write_token_generation_state
    token_reader = inspection.load_production_write_authorized_user_token

    @contextmanager
    def held(*_a: Any) -> Any:
        events.append("enter")
        try:
            yield lambda: events.append("checkpoint")
        finally:
            events.append("exit")

    def read_state(p: Path) -> Any:
        events.append("state")
        return state_reader(p)

    def read_token(p: Path) -> Any:
        events.append("token")
        return token_reader(p)

    monkeypatch.setattr(inspection, "_production_write_session_lock", held)
    monkeypatch.setattr(inspection, "load_production_write_token_generation_state", read_state)
    monkeypatch.setattr(inspection, "load_production_write_authorized_user_token", read_token)
    _assert_summary(_inspect(f), S.LOCAL_CONTENTS_CONSISTENT_NOT_APPROVED, f)
    assert events == [
        "enter",
        "state",
        "token",
        "checkpoint",
        "state",
        "token",
        "checkpoint",
        "checkpoint",
        "exit",
    ]
