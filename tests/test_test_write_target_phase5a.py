from __future__ import annotations

import os
from pathlib import Path

import pytest
from conftest import REPOSITORY_ROOT
from phase5a_helpers import (
    SYNTHETIC_TEST_CALENDAR_ID,
    SYNTHETIC_TEST_SUMMARY,
    make_test_target_config,
    make_test_target_observation,
)
from pydantic import ValidationError

from tridentine_calendar_google_sync.apply_policy import PRODUCTION_TARGET_REFERENCE
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetConfig as TargetConfig,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetConfigError as TargetConfigError,
)
from tridentine_calendar_google_sync.test_write_target import (
    TestWriteTargetPolicyError as TargetPolicyError,
)
from tridentine_calendar_google_sync.test_write_target import (
    load_test_write_target_config,
    validate_test_write_target_config,
    verify_test_write_target_metadata,
)
from tridentine_calendar_google_sync.test_write_target import (
    test_write_target_reference as target_reference,
)

pytestmark = pytest.mark.google_test_write


def _target_toml(*, extra: str = "") -> str:
    fingerprint = make_test_target_config().expected_target_fingerprint
    return f'''schema_version = 1
target_environment = "test"
target_label = "test"
target_purpose = "test_calendar_write_acceptance"
calendar_id = "{SYNTHETIC_TEST_CALENDAR_ID}"
expected_target_fingerprint = "{fingerprint}"
expected_summary = "{SYNTHETIC_TEST_SUMMARY}"
expected_access_role = "owner"
expected_time_zone = "Asia/Tokyo"
{extra}'''


def test_valid_test_target_and_exact_metadata_pass() -> None:
    config = make_test_target_config()
    fingerprint = validate_test_write_target_config(config)

    assert len(fingerprint) == 64
    assert target_reference(config) == f"T-{fingerprint[:12]}"
    assert target_reference(config) != PRODUCTION_TARGET_REFERENCE
    verify_test_write_target_metadata(config, make_test_target_observation())


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("target_environment", "production"),
        ("target_label", "production"),
        ("target_purpose", "production_calendar_sync"),
        ("expected_access_role", "reader"),
        ("expected_time_zone", "UTC"),
    ),
)
def test_closed_target_schema_rejects_non_test_policy(field: str, value: str) -> None:
    values = make_test_target_config().model_dump(mode="python")
    values[field] = value
    with pytest.raises(ValidationError):
        TargetConfig.model_validate(values, strict=True)


def test_primary_calendar_and_summary_without_test_marker_are_rejected() -> None:
    with pytest.raises(ValidationError):
        make_test_target_config(calendar_id="primary")
    with pytest.raises(ValidationError):
        make_test_target_config(expected_summary="Ordinary calendar")


def test_fingerprint_mismatch_is_rejected() -> None:
    with pytest.raises(ValidationError):
        make_test_target_config(expected_target_fingerprint="f" * 64)


def test_known_production_safe_reference_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    import tridentine_calendar_google_sync.test_write_target as target_module

    production_fingerprint = PRODUCTION_TARGET_REFERENCE.removeprefix("T-") + "0" * 52
    monkeypatch.setattr(
        target_module, "calendar_id_fingerprint", lambda _value: production_fingerprint
    )
    with pytest.raises(ValidationError):
        make_test_target_config(expected_target_fingerprint=production_fingerprint)


@pytest.mark.parametrize(
    ("overrides", "code"),
    (
        ({"summary": "Wrong Synthetic Test Calendar"}, "test_write_target_summary_mismatch"),
        ({"access_role": "writer"}, "test_write_target_not_owned"),
        ({"time_zone": "UTC"}, "test_write_target_timezone_mismatch"),
    ),
)
def test_remote_target_metadata_must_match_exactly(
    overrides: dict[str, object],
    code: str,
) -> None:
    with pytest.raises(TargetPolicyError) as captured:
        verify_test_write_target_metadata(
            make_test_target_config(),
            make_test_target_observation(**overrides),
        )
    assert captured.value.code == code
    assert SYNTHETIC_TEST_CALENDAR_ID not in str(captured.value)


def test_target_loader_accepts_repository_external_regular_file(tmp_path: Path) -> None:
    target = tmp_path / "fixture-test-target.toml"
    target.write_text(_target_toml(), encoding="utf-8")

    loaded = load_test_write_target_config(target)

    assert loaded.target_environment == "test"
    assert SYNTHETIC_TEST_CALENDAR_ID not in repr(loaded)
    assert loaded.expected_summary not in repr(loaded)


def test_target_loader_rejects_unknown_key_and_repository_path(tmp_path: Path) -> None:
    unknown = tmp_path / "fixture-test-target.toml"
    unknown.write_text(_target_toml(extra='unexpected = "rejected"\n'), encoding="utf-8")
    with pytest.raises(TargetConfigError):
        load_test_write_target_config(unknown)

    with pytest.raises(TargetConfigError) as captured:
        load_test_write_target_config(REPOSITORY_ROOT / "pyproject.toml")
    assert captured.value.code == "unsafe_test_write_target_path"
    assert str(REPOSITORY_ROOT) not in str(captured.value)


def test_target_loader_rejects_symlink(tmp_path: Path) -> None:
    real = tmp_path / "real-target.toml"
    link = tmp_path / "linked-target.toml"
    real.write_text(_target_toml(), encoding="utf-8")
    try:
        os.symlink(real, link)
    except OSError:
        pytest.skip("symlink creation is unavailable")

    with pytest.raises(TargetConfigError):
        load_test_write_target_config(link)
