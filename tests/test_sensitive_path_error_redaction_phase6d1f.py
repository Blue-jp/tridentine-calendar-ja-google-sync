"""Regression tests for path-free Production token loader failures."""

from __future__ import annotations

import json
import traceback
from collections.abc import Callable
from pathlib import Path

import pytest

from tridentine_calendar_google_sync.production_write_token_io import (
    ProductionWriteTokenIOError,
    load_production_write_authorized_user_token,
    load_production_write_token_generation_state,
)

pytestmark = pytest.mark.google_production_write


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
def test_repository_resolution_loops_are_mapped_without_path_disclosure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    loader: Callable[[str | Path], object],
    expected_code: str,
    filename: str,
) -> None:
    marker = "PRIVATE_PATH_MARKER_LOOP"
    sensitive_path = tmp_path / marker / filename
    original_resolve = Path.resolve

    def injected_resolve(path: Path, strict: bool = False) -> Path:
        if path == sensitive_path:
            raise RuntimeError(f"synthetic filesystem loop at {sensitive_path}")
        return original_resolve(path, strict=strict)

    monkeypatch.setattr(Path, "resolve", injected_resolve)

    with pytest.raises(ProductionWriteTokenIOError) as captured:
        loader(sensitive_path)

    public_error = captured.value
    streams = capsys.readouterr()
    rendered_exception = "".join(traceback.format_exception(public_error))
    human_report = f"{public_error.code}:{public_error.public_message}"
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
        human_report,
        json_report,
    ):
        assert marker not in rendered
        assert str(sensitive_path) not in rendered
