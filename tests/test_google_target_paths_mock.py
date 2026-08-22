from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from types import ModuleType

import pytest
from conftest import REPOSITORY_ROOT
from pydantic import ValidationError

from tridentine_calendar_google_sync.google_optional import (
    GoogleOptionalDependencyError,
    load_google_optional_bindings,
)
from tridentine_calendar_google_sync.google_target import (
    TargetConfigError,
    TargetIdentityError,
    TargetMetadataObservation,
    calendar_id_fingerprint,
    load_target_config,
    short_target_reference,
    verify_target_fingerprint,
    verify_target_metadata,
)
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_json,
    atomic_write_private_text,
    read_sensitive_bytes,
    validate_sensitive_input_path,
    validate_sensitive_output_path,
)

pytestmark = pytest.mark.google_read


def _target_toml(calendar_id: str) -> str:
    fingerprint = calendar_id_fingerprint(calendar_id)
    return f'''schema_version = 1
target_label = "synthetic-test-target"
calendar_id = "{calendar_id}"
expected_target_fingerprint = "{fingerprint}"
expected_summary = "Synthetic target calendar"
expected_access_role = "owner"
expected_time_zone = "UTC"
'''


def test_target_config_loads_only_explicit_external_absolute_file(tmp_path: Path) -> None:
    path = tmp_path / "target.toml"
    path.write_text(_target_toml("fixture-private-target"), encoding="utf-8")

    config = load_target_config(path)

    assert config.label == "synthetic-test-target"
    assert verify_target_fingerprint(config) == config.expected_fingerprint
    assert short_target_reference(config.expected_fingerprint).startswith("T-")
    rendered = repr(config) + json.dumps(config.model_dump(mode="json"))
    assert "fixture-private-target" not in rendered


def test_target_fingerprint_mismatch_is_content_free(tmp_path: Path) -> None:
    path = tmp_path / "target.toml"
    text = _target_toml("fixture-private-target").replace(
        calendar_id_fingerprint("fixture-private-target"),
        "e" * 64,
    )
    path.write_text(text, encoding="utf-8")
    config = load_target_config(path)

    with pytest.raises(TargetIdentityError) as caught:
        verify_target_fingerprint(config)

    assert caught.value.code == "target_fingerprint_mismatch"
    assert "fixture-private-target" not in str(caught.value)
    assert str(path) not in str(caught.value)


def test_target_metadata_requires_exact_summary_role_and_timezone(tmp_path: Path) -> None:
    path = tmp_path / "target.toml"
    path.write_text(_target_toml("fixture-private-target"), encoding="utf-8")
    config = load_target_config(path)
    exact = TargetMetadataObservation(
        summary="Synthetic target calendar",
        access_role="owner",
        timezone="UTC",
    )

    verify_target_metadata(config, exact)

    mismatches = (
        TargetMetadataObservation(
            summary="Changed synthetic summary",
            access_role="owner",
            timezone="UTC",
        ),
        TargetMetadataObservation(
            summary="Synthetic target calendar",
            access_role="owner",
            timezone="Etc/UTC",
        ),
    )
    for observation in mismatches:
        with pytest.raises(TargetIdentityError):
            verify_target_metadata(config, observation)
    assert "Synthetic target calendar" not in repr(exact)


def test_target_config_rejects_relative_url_and_git_worktree_paths(tmp_path: Path) -> None:
    relative = Path("target.toml")
    for value in (relative, "https://example.invalid/target.toml", "file:///target.toml"):
        with pytest.raises(TargetConfigError) as caught:
            load_target_config(value)
        assert str(value) not in str(caught.value)

    with pytest.raises(TargetConfigError) as caught:
        load_target_config(REPOSITORY_ROOT / "README.md")
    assert str(REPOSITORY_ROOT) not in str(caught.value)


def test_sensitive_path_helpers_reject_repository_output_without_writing() -> None:
    candidate = REPOSITORY_ROOT / "must-not-create-private.json"

    with pytest.raises(SensitivePathError) as caught:
        validate_sensitive_output_path(candidate)

    assert caught.value.code == "sensitive_path_in_git_worktree"
    assert not candidate.exists()
    assert str(candidate) not in str(caught.value)


def test_atomic_private_json_write_is_deterministic_and_no_overwrite(tmp_path: Path) -> None:
    path = tmp_path / "private.json"
    payload = {"synthetic": "value", "count": 1}

    atomic_write_private_json(path, payload)

    assert path.read_text(encoding="utf-8") == '{"count":1,"synthetic":"value"}\n'
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with pytest.raises(SensitivePathError) as caught:
        atomic_write_private_json(path, {"synthetic": "changed"})
    assert caught.value.code == "sensitive_output_exists"
    assert path.read_text(encoding="utf-8") == '{"count":1,"synthetic":"value"}\n'


def test_atomic_private_write_can_overwrite_only_when_explicit(tmp_path: Path) -> None:
    path = tmp_path / "private.txt"
    atomic_write_private_text(path, "first")

    atomic_write_private_text(path, "second", overwrite=True)

    assert path.read_text(encoding="utf-8") == "second"


def test_sensitive_input_is_bounded_regular_external_file(tmp_path: Path) -> None:
    path = tmp_path / "private.bin"
    path.write_bytes(b"synthetic")

    assert validate_sensitive_input_path(path) == path
    assert read_sensitive_bytes(path) == b"synthetic"
    with pytest.raises(SensitivePathError) as caught:
        read_sensitive_bytes(path, max_size=2)
    assert caught.value.code == "sensitive_input_too_large"
    assert str(path) not in str(caught.value)


def test_sensitive_path_symlinks_are_rejected(tmp_path: Path) -> None:
    target = tmp_path / "target.txt"
    target.write_text("synthetic", encoding="utf-8")
    link = tmp_path / "link.txt"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symbolic links are unavailable in this test environment")

    with pytest.raises(SensitivePathError) as caught:
        validate_sensitive_input_path(link)
    assert caught.value.code == "sensitive_path_symlink"
    assert str(link) not in str(caught.value)


def test_optional_google_bindings_use_exact_lazy_module_set() -> None:
    requested: list[str] = []
    modules: dict[str, ModuleType] = {}
    for name in (
        "google.oauth2.credentials",
        "google_auth_oauthlib.flow",
        "google.auth.transport.requests",
        "googleapiclient.discovery",
        "googleapiclient.errors",
    ):
        modules[name] = ModuleType(name)
    modules["google.oauth2.credentials"].Credentials = object  # type: ignore[attr-defined]
    modules["google_auth_oauthlib.flow"].InstalledAppFlow = object  # type: ignore[attr-defined]
    modules["google.auth.transport.requests"].Request = object  # type: ignore[attr-defined]
    modules["googleapiclient.discovery"].build = lambda *args, **kwargs: (  # type: ignore[attr-defined]
        args,
        kwargs,
    )
    modules["googleapiclient.errors"].HttpError = RuntimeError  # type: ignore[attr-defined]

    def importer(name: str) -> ModuleType:
        requested.append(name)
        return modules[name]

    bindings = load_google_optional_bindings(importer=importer)

    assert requested == list(modules)
    assert bindings.http_error_class is RuntimeError


def test_optional_dependency_failure_is_safe_and_does_not_auto_install() -> None:
    requested: list[str] = []

    def missing_importer(name: str) -> ModuleType:
        requested.append(name)
        raise ImportError("synthetic missing package path")

    with pytest.raises(GoogleOptionalDependencyError) as caught:
        load_google_optional_bindings(importer=missing_importer)

    assert requested == ["google.oauth2.credentials"]
    assert "synthetic missing package path" not in str(caught.value)
    assert caught.value.code == "google_optional_dependencies_unavailable"


def test_invalid_target_role_is_rejected() -> None:
    with pytest.raises(ValidationError):
        TargetMetadataObservation(
            summary="Synthetic target calendar",
            access_role="administrator",  # type: ignore[arg-type]
            timezone="UTC",
        )
