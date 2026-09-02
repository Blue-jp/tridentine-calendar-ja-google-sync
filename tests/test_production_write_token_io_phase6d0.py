"""Phase 6D.0 token-generation integrity and filesystem tests."""

from __future__ import annotations

import json
import os
import traceback
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path

import pytest
from phase6d0_auth_helpers import ISSUED_AT, production_target, production_token

from tridentine_calendar_google_sync.production_write_token import (
    ProductionWriteTokenConfigError,
    build_initial_production_write_token_generation_state,
    build_next_production_write_token_generation_state,
    calculate_production_write_token_generation_state_hash,
    private_production_write_token_generation_state_data,
    verify_production_write_token_generation_state,
    verify_production_write_token_generation_transition,
)
from tridentine_calendar_google_sync.production_write_token_io import (
    ProductionWriteTokenIOError,
    load_production_write_authorized_user_token,
    load_production_write_token_generation_state,
    parse_production_write_authorized_user_token_bytes,
    parse_production_write_token_generation_state_bytes,
    render_production_write_authorized_user_token_json,
    render_production_write_token_generation_state_json,
    write_production_write_authorized_user_token,
    write_production_write_token_generation_state,
)
from tridentine_calendar_google_sync.production_write_token_models import (
    ProductionTokenRole,
)
from tridentine_calendar_google_sync.production_write_token_report import (
    build_production_write_token_generation_inspection,
)
from tridentine_calendar_google_sync.sensitive_paths import SensitivePathError

pytestmark = pytest.mark.google_production_write


def test_first_generation_and_exact_plus_one_hash_link_are_verified() -> None:
    target = production_target()
    first = build_initial_production_write_token_generation_state(
        target,
        issued_at=ISSUED_AT,
    )
    second = build_next_production_write_token_generation_state(
        first,
        target,
        issued_at=ISSUED_AT + timedelta(seconds=1),
    )
    third = build_next_production_write_token_generation_state(
        second,
        target,
        issued_at=ISSUED_AT + timedelta(seconds=2),
    )

    assert first.generation == 1
    assert first.predecessor_state_hash is None
    assert (second.generation, third.generation) == (2, 3)
    assert second.predecessor_state_hash == first.content_hash
    assert third.predecessor_state_hash == second.content_hash
    verify_production_write_token_generation_transition(first, second, target=target)
    verify_production_write_token_generation_transition(second, third, target=target)


def test_generation_tamper_wrong_target_skip_and_clock_reuse_fail_closed() -> None:
    target = production_target()
    first = build_initial_production_write_token_generation_state(
        target,
        issued_at=ISSUED_AT,
    )
    tampered = first.model_copy(update={"content_hash": "f" * 64})
    with pytest.raises(ProductionWriteTokenConfigError) as captured:
        verify_production_write_token_generation_state(tampered, target=target)
    assert captured.value.code == "production_write_token_generation_hash_mismatch"

    forged = first.model_copy(
        update={
            "generation": 2,
            "predecessor_state_hash": "e" * 64,
            "content_hash": "0" * 64,
        }
    )
    forged = forged.model_copy(
        update={"content_hash": calculate_production_write_token_generation_state_hash(forged)}
    )
    with pytest.raises(ProductionWriteTokenConfigError) as skipped:
        verify_production_write_token_generation_transition(first, forged, target=target)
    assert skipped.value.code == "production_write_token_generation_transition_mismatch"

    with pytest.raises(ProductionWriteTokenConfigError) as clock:
        build_next_production_write_token_generation_state(
            first,
            target,
            issued_at=first.issued_at,
        )
    assert clock.value.code == "production_write_token_generation_clock_invalid"

    other = production_target().model_copy(update={"expected_summary": "Other Production"})
    with pytest.raises(ProductionWriteTokenConfigError) as mismatch:
        verify_production_write_token_generation_state(first, target=other)
    assert mismatch.value.code == "production_write_token_generation_target_mismatch"


def test_generation_state_contains_no_token_or_credential_content_binding() -> None:
    state = build_initial_production_write_token_generation_state(
        production_target(),
        issued_at=ISSUED_AT,
    )
    fields = set(type(state).model_fields)
    forbidden = {
        "access_token",
        "refresh_token",
        "token",
        "client_id",
        "client_secret",
        "calendar_id",
        "token_file_hash",
        "credential_file_hash",
        "authorization",
        "event_id",
        "etag",
    }
    assert fields.isdisjoint(forbidden)
    data = private_production_write_token_generation_state_data(state)
    assert not any(forbidden.intersection({key.casefold()}) for key in data)
    inspection = build_production_write_token_generation_inspection(state)
    assert set(inspection).isdisjoint({"target_config_hash", *forbidden})


def test_canonical_private_token_and_generation_round_trip(tmp_path: Path) -> None:
    state = build_initial_production_write_token_generation_state(
        production_target(),
        issued_at=ISSUED_AT,
    )
    token = production_token(state)
    token_path = tmp_path / "token.json"
    state_path = tmp_path / "generation.json"
    write_production_write_authorized_user_token(token, token_path)
    write_production_write_token_generation_state(state, state_path)

    assert load_production_write_authorized_user_token(token_path) == token
    assert load_production_write_token_generation_state(state_path) == state
    assert (
        parse_production_write_authorized_user_token_bytes(
            render_production_write_authorized_user_token_json(token).encode()
        )
        == token
    )
    assert (
        parse_production_write_token_generation_state_bytes(
            render_production_write_token_generation_state_json(state).encode()
        )
        == state
    )

    with pytest.raises(ProductionWriteTokenIOError):
        write_production_write_authorized_user_token(token, token_path)
    with pytest.raises(ProductionWriteTokenIOError):
        write_production_write_token_generation_state(state, state_path)


def test_posix_group_or_other_token_access_is_rejected(tmp_path: Path) -> None:
    state = build_initial_production_write_token_generation_state(
        production_target(),
        issued_at=ISSUED_AT,
    )
    token_path = tmp_path / "token.json"
    write_production_write_authorized_user_token(production_token(state), token_path)
    if os.name != "posix":
        assert token_path.is_file()
        return
    token_path.chmod(0o640)
    with pytest.raises(ProductionWriteTokenIOError) as captured:
        load_production_write_authorized_user_token(token_path)
    assert captured.value.code == "unsafe_production_write_token_path"


@pytest.mark.skipif(os.name != "posix", reason="requires the POSIX permission branch")
@pytest.mark.parametrize(
    ("loader", "expected_code", "filename"),
    [
        (
            load_production_write_authorized_user_token,
            "unsafe_production_write_token_path",
            "token.json",
        ),
        (
            load_production_write_token_generation_state,
            "unsafe_production_write_token_generation_path",
            "generation.json",
        ),
    ],
)
def test_posix_stat_errors_never_disclose_sensitive_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    loader: Callable[[str | Path], object],
    expected_code: str,
    filename: str,
) -> None:
    marker = "PRIVATE_PATH_MARKER"
    sensitive_path = tmp_path / marker / filename
    original_stat = Path.stat

    def injected_stat(
        path: Path,
        *,
        follow_symlinks: bool = True,
    ) -> os.stat_result:
        if path == sensitive_path:
            raise PermissionError(f"synthetic denial for {sensitive_path}")
        return original_stat(path, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", injected_stat)
    with pytest.raises(ProductionWriteTokenIOError) as captured:
        loader(sensitive_path)

    public_error = captured.value
    streams = capsys.readouterr()
    rendered_exception = "".join(traceback.format_exception(public_error))
    public_report = f"{public_error.code}:{public_error.public_message}"
    json_report = json.dumps(
        {"code": public_error.code, "message": public_error.public_message},
        sort_keys=True,
    )
    assert public_error.code == expected_code
    assert public_error.__cause__ is None
    assert public_error.__suppress_context__ is True
    for rendered in (
        str(public_error),
        rendered_exception,
        streams.out,
        streams.err,
        public_report,
        json_report,
    ):
        assert marker not in rendered
        assert str(sensitive_path) not in rendered


@pytest.mark.parametrize(
    ("loader", "expected_code"),
    [
        (load_production_write_authorized_user_token, "unsafe_production_write_token_path"),
        (
            load_production_write_token_generation_state,
            "unsafe_production_write_token_generation_path",
        ),
    ],
)
def test_loader_boundary_suppresses_path_bearing_exception_chains(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    loader: Callable[[str | Path], object],
    expected_code: str,
) -> None:
    marker = "PRIVATE_PATH_MARKER"
    sensitive_path = Path.cwd().anchor + marker

    def injected_repository_check(_path: Path) -> None:
        try:
            raise PermissionError(f"synthetic denial for {sensitive_path}")
        except PermissionError as exc:
            raise SensitivePathError(
                "sensitive_path_unavailable",
                "sensitive path cannot be safely inspected",
            ) from exc

    monkeypatch.setattr(
        "tridentine_calendar_google_sync.production_write_token_io._reject_repository_parent",
        injected_repository_check,
    )
    with pytest.raises(ProductionWriteTokenIOError) as captured:
        loader(sensitive_path)

    public_error = captured.value
    streams = capsys.readouterr()
    rendered_exception = "".join(traceback.format_exception(public_error))
    public_report = f"{public_error.code}:{public_error.public_message}"
    json_report = json.dumps(
        {"code": public_error.code, "message": public_error.public_message},
        sort_keys=True,
    )
    assert public_error.code == expected_code
    assert public_error.__cause__ is None
    assert public_error.__suppress_context__ is True
    for rendered in (
        str(public_error),
        rendered_exception,
        streams.out,
        streams.err,
        public_report,
        json_report,
    ):
        assert marker not in rendered
        assert sensitive_path not in rendered


def test_noncanonical_duplicate_unknown_and_role_tamper_are_rejected() -> None:
    state = build_initial_production_write_token_generation_state(
        production_target(),
        issued_at=ISSUED_AT,
    )
    token = production_token(state)
    token_document = json.loads(render_production_write_authorized_user_token_json(token))
    state_document = json.loads(render_production_write_token_generation_state_json(state))

    with pytest.raises(ProductionWriteTokenIOError):
        parse_production_write_authorized_user_token_bytes(
            json.dumps(token_document, sort_keys=True).encode()
        )
    with pytest.raises(ProductionWriteTokenIOError):
        parse_production_write_token_generation_state_bytes(
            json.dumps(state_document, sort_keys=True).encode()
        )

    token_document["unexpected"] = True
    with pytest.raises(ProductionWriteTokenIOError):
        parse_production_write_authorized_user_token_bytes(
            (json.dumps(token_document) + "\n").encode()
        )

    state_document["role"] = ProductionTokenRole.TEST_WRITE.value
    with pytest.raises(ProductionWriteTokenIOError):
        parse_production_write_token_generation_state_bytes(
            (json.dumps(state_document) + "\n").encode()
        )

    duplicate = b'{"schema_version":"1.0","schema_version":"1.0"}'
    with pytest.raises(ProductionWriteTokenIOError):
        parse_production_write_token_generation_state_bytes(duplicate)


@pytest.mark.parametrize(
    "unsafe", ("relative-token.json", "https://example.invalid/token", "file:///tmp/token")
)
def test_ambiguous_url_and_file_url_paths_are_rejected(unsafe: str) -> None:
    state = build_initial_production_write_token_generation_state(
        production_target(),
        issued_at=ISSUED_AT,
    )
    with pytest.raises(ProductionWriteTokenIOError):
        write_production_write_token_generation_state(state, unsafe)
