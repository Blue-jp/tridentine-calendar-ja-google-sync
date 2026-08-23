from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path

import pytest
from conftest import REPOSITORY_ROOT, SyntheticBaselineBundle
from jsonschema import Draft202012Validator

import tridentine_calendar_google_sync.baseline_io as baseline_io
from tridentine_calendar_google_sync.baseline_engine import (
    BaselineConfirmationError,
    BaselineGuardError,
    BaselineInputError,
    BaselineValidationError,
    baseline_confirmation_phrase,
    baseline_inspection_data,
    build_baseline_candidate,
    render_baseline_inspection_json,
    render_baseline_text,
    trust_baseline,
    verify_baseline_content_hash,
)
from tridentine_calendar_google_sync.baseline_io import (
    load_baseline,
    parse_baseline_bytes,
    render_baseline_json,
    write_baseline,
)
from tridentine_calendar_google_sync.baseline_models import BaselineState
from tridentine_calendar_google_sync.diff_engine import diff_source_to_snapshot
from tridentine_calendar_google_sync.google_snapshot import load_google_snapshot
from tridentine_calendar_google_sync.source_ics import inspect_source

BundleFactory = Callable[..., SyntheticBaselineBundle]


def _bundle(
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> SyntheticBaselineBundle:
    return synthetic_baseline_bundle_factory(
        valid_source,
        synthetic_profile_factory,
        google_snapshots_dir / "exact_match.json",
    )


def test_exact_clean_inputs_build_candidate_and_explicit_trust_transition(
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )

    assert bundle.candidate.state is BaselineState.CANDIDATE
    assert bundle.candidate.managed_uid_count == 1
    assert bundle.candidate.managed_uids == ("fixture-valid-001@example.invalid",)
    verify_baseline_content_hash(bundle.candidate)
    phrase = baseline_confirmation_phrase(bundle.candidate)
    assert phrase.startswith("TRUST BASELINE T-")
    assert "fixture-valid-001@example.invalid" not in phrase

    assert bundle.trusted.state is BaselineState.TRUSTED
    assert bundle.trusted.managed_uids == bundle.candidate.managed_uids
    assert bundle.trusted.baseline_content_hash != bundle.candidate.baseline_content_hash
    verify_baseline_content_hash(bundle.trusted)


def test_trust_requires_exact_confirmation_and_candidate_state(
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )

    with pytest.raises(BaselineConfirmationError):
        trust_baseline(bundle.candidate, "TRUST BASELINE T-000000000000 000000000000")
    with pytest.raises(BaselineGuardError):
        baseline_confirmation_phrase(bundle.trusted)


def test_public_baseline_views_hide_uid_and_full_target_fingerprint(
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    raw_uid = bundle.candidate.managed_uids[0]
    internal_views = (
        repr(bundle.candidate),
        json.dumps(bundle.candidate.model_dump(mode="json")),
    )
    public_reports = (
        json.dumps(baseline_inspection_data(bundle.candidate)),
        render_baseline_inspection_json(bundle.candidate),
        render_baseline_text(bundle.candidate),
    )

    for report in (*internal_views, *public_reports):
        assert raw_uid not in report
    for report in public_reports:
        assert bundle.candidate.target_fingerprint not in report
    private = render_baseline_json(bundle.candidate)
    assert raw_uid in private
    for forbidden in (
        "event_id",
        "google_event_id",
        "etag",
        "summary",
        "description",
        "htmlLink",
    ):
        assert forbidden not in private


def test_private_baseline_json_round_trip_and_hash_are_deterministic(
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    first = render_baseline_json(bundle.trusted)
    second = render_baseline_json(bundle.trusted)

    assert first == second
    assert parse_baseline_bytes(first.encode("utf-8")) == bundle.trusted


def test_candidate_and_trusted_documents_validate_against_closed_schema(
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    schema = json.loads(
        (REPOSITORY_ROOT / "schemas" / "trusted-baseline-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )
    validator = Draft202012Validator(schema)

    for baseline in (bundle.candidate, bundle.trusted):
        validator.validate(json.loads(render_baseline_json(baseline)))


@pytest.mark.parametrize(
    "mutation",
    [
        lambda value: value.update(source_event_count=2),
        lambda value: value.update(managed_uid_count=2),
        lambda value: value["managed_uids"].append(value["managed_uids"][0]),
        lambda value: value.update(extra_forbidden_field=True),
    ],
)
def test_tampered_or_invalid_baseline_is_rejected(
    mutation: Callable[[dict[str, object]], None],
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    document = json.loads(render_baseline_json(bundle.trusted))
    mutation(document)

    with pytest.raises(BaselineValidationError):
        parse_baseline_bytes(json.dumps(document).encode("utf-8"))


@pytest.mark.parametrize(
    "raw",
    [
        b"not-json",
        b'{"schema_version":"2.0"}',
        b'{"schema_version":"1.0","schema_version":"1.0"}',
        b"[]",
    ],
)
def test_malformed_duplicate_or_unsupported_baseline_is_rejected(raw: bytes) -> None:
    with pytest.raises(BaselineValidationError):
        parse_baseline_bytes(raw)


@pytest.mark.parametrize(
    ("snapshot_name", "expected_code"),
    [
        ("summary_changed.json", "baseline_diff_not_exact"),
        ("missing_google_event.json", "baseline_snapshot_count_mismatch"),
        ("event_color.json", "baseline_diff_warning"),
    ],
)
def test_candidate_builder_rejects_nonexact_or_warning_inputs(
    snapshot_name: str,
    expected_code: str,
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    google_snapshots_dir: Path,
) -> None:
    profile = synthetic_profile_factory(valid_source)
    source = inspect_source(valid_source, profile)
    snapshot = load_google_snapshot(google_snapshots_dir / snapshot_name)
    diff = diff_source_to_snapshot(source, snapshot)

    with pytest.raises(BaselineGuardError) as caught:
        build_baseline_candidate(profile, source, snapshot, diff)

    assert caught.value.code == expected_code


def test_candidate_builder_rejects_incomplete_snapshot(
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    google_snapshots_dir: Path,
) -> None:
    profile = synthetic_profile_factory(valid_source)
    source = inspect_source(valid_source, profile)
    snapshot = load_google_snapshot(google_snapshots_dir / "exact_match.json").model_copy(
        update={"complete": False}
    )
    diff = diff_source_to_snapshot(source, snapshot)

    with pytest.raises(BaselineGuardError) as caught:
        build_baseline_candidate(profile, source, snapshot, diff)
    assert caught.value.code == "baseline_snapshot_incomplete"


def test_baseline_atomic_write_load_and_no_overwrite(
    tmp_path: Path,
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    path = tmp_path / "synthetic.baseline.json"

    assert write_baseline(bundle.trusted, path) == path
    assert load_baseline(path) == bundle.trusted
    with pytest.raises(BaselineInputError):
        write_baseline(bundle.trusted, path)


@pytest.mark.parametrize(
    "path",
    [
        Path("relative.baseline.json"),
        "https://example.invalid/baseline.json",
        "file:///synthetic/baseline.json",
    ],
)
def test_baseline_loader_rejects_unsafe_paths_without_echo(path: str | Path) -> None:
    with pytest.raises(BaselineInputError) as caught:
        load_baseline(path)
    assert str(path) not in str(caught.value)


def test_baseline_writer_rejects_repository_path_without_creating_file(
    valid_source: Path,
    synthetic_profile_factory: Callable[..., object],
    synthetic_baseline_bundle_factory: BundleFactory,
    google_snapshots_dir: Path,
) -> None:
    bundle = _bundle(
        valid_source,
        synthetic_profile_factory,
        synthetic_baseline_bundle_factory,
        google_snapshots_dir,
    )
    path = REPOSITORY_ROOT / "must-not-create.baseline.json"

    with pytest.raises(BaselineInputError):
        write_baseline(bundle.trusted, path)
    assert not path.exists()


def test_baseline_parser_enforces_size_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(baseline_io, "MAX_BASELINE_BYTES", 8)
    with pytest.raises(BaselineInputError) as caught:
        baseline_io.parse_baseline_bytes(b"123456789")
    assert caught.value.code == "baseline_too_large"
