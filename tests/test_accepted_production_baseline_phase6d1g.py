from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from tridentine_calendar_google_sync.accepted_production_baseline import (
    AcceptedProductionBaselineInputError,
    AcceptedProductionBaselineValidationError,
    build_accepted_production_baseline_pin,
    calculate_accepted_production_baseline_pin_hash,
    candidate_content_hash_from_trusted_baseline,
    verify_accepted_production_baseline_pin,
    verify_trusted_baseline_against_accepted_pin,
)
from tridentine_calendar_google_sync.accepted_production_baseline_models import (
    AcceptedProductionBaselinePin,
)
from tridentine_calendar_google_sync.accepted_production_baseline_registry import (
    PACKAGED_ACCEPTED_PRODUCTION_BASELINE_REGISTRY_HASH,
    AcceptedProductionBaselineRegistryError,
    active_accepted_production_baseline_pin,
    build_accepted_production_baseline_registry,
    calculate_accepted_production_baseline_registry_hash,
    load_active_accepted_production_baseline_pin,
    load_packaged_accepted_production_baseline_registry,
    parse_accepted_production_baseline_registry_bytes,
    render_accepted_production_baseline_registry_json,
    verify_accepted_production_baseline_registry,
)
from tridentine_calendar_google_sync.baseline_engine import (
    baseline_confirmation_phrase,
    calculate_baseline_content_hash,
    trust_baseline,
)
from tridentine_calendar_google_sync.baseline_models import BaselineState, TrustedBaseline
from tridentine_calendar_google_sync.production_write_target import (
    ProductionWriteTargetConfig,
    calendar_id_fingerprint,
)

ROOT = Path(__file__).resolve().parents[1]


def _candidate() -> TrustedBaseline:
    provisional = TrustedBaseline(
        schema_version="1.0",
        state=BaselineState.CANDIDATE,
        tool_version="0.1.0",
        target_fingerprint=calendar_id_fingerprint("phase6d1g-production@calendar.example"),
        source_profile="accepted-20990101",
        accepted_tag="accepted-phase6d1g",
        accepted_commit="1" * 40,
        source_sha256="2" * 64,
        source_event_count=2,
        snapshot_content_hash="3" * 64,
        snapshot_event_count=2,
        diff_content_hash="4" * 64,
        managed_uid_count=2,
        managed_uids=(
            "phase6d1g-000001@calendar.example",
            "phase6d1g-000002@calendar.example",
        ),
        baseline_content_hash="0" * 64,
    )
    return provisional.model_copy(
        update={"baseline_content_hash": calculate_baseline_content_hash(provisional)}
    )


def _trusted(candidate: TrustedBaseline | None = None) -> TrustedBaseline:
    resolved = _candidate() if candidate is None else candidate
    return trust_baseline(resolved, baseline_confirmation_phrase(resolved))


def _target() -> ProductionWriteTargetConfig:
    calendar_id = "phase6d1g-production@calendar.example"
    return ProductionWriteTargetConfig(
        schema_version=1,
        target_environment="production",
        target_label="production",
        target_purpose="production_calendar_single_update",
        calendar_id=calendar_id,
        expected_target_fingerprint=calendar_id_fingerprint(calendar_id),
        expected_summary="Phase 6D.1G Production Calendar",
        expected_access_role="owner",
        expected_time_zone="Asia/Tokyo",
    )


def _pin(
    *,
    generation: int = 1,
    previous_pin: AcceptedProductionBaselinePin | None = None,
) -> AcceptedProductionBaselinePin:
    candidate = _candidate()
    return build_accepted_production_baseline_pin(
        candidate,
        _trusted(candidate),
        _target(),
        generation=generation,
        previous_pin=previous_pin,
    )


def _rehash_baseline(baseline: TrustedBaseline, **updates: object) -> TrustedBaseline:
    provisional = baseline.model_copy(update={**updates, "baseline_content_hash": "0" * 64})
    return provisional.model_copy(
        update={"baseline_content_hash": calculate_baseline_content_hash(provisional)}
    )


def _rehash_pin(
    pin: AcceptedProductionBaselinePin,
    **updates: object,
) -> AcceptedProductionBaselinePin:
    provisional = pin.model_copy(update={**updates, "pin_content_hash": "0" * 64})
    return provisional.model_copy(
        update={"pin_content_hash": calculate_accepted_production_baseline_pin_hash(provisional)}
    )


def test_packaged_registry_is_canonical_empty_and_fail_closed() -> None:
    registry = load_packaged_accepted_production_baseline_registry()

    assert registry.pins == ()
    assert registry.active_pin_id is None
    assert registry.registry_content_hash == PACKAGED_ACCEPTED_PRODUCTION_BASELINE_REGISTRY_HASH
    with pytest.raises(AcceptedProductionBaselineRegistryError) as captured:
        active_accepted_production_baseline_pin(registry)
    assert captured.value.code == "accepted_production_baseline_registry_inactive"
    with pytest.raises(AcceptedProductionBaselineRegistryError):
        load_active_accepted_production_baseline_pin()


def test_pin_binds_exact_candidate_trusted_transition_and_target() -> None:
    candidate = _candidate()
    trusted = _trusted(candidate)
    pin = build_accepted_production_baseline_pin(
        candidate,
        trusted,
        _target(),
        generation=1,
    )

    verify_accepted_production_baseline_pin(pin)
    verify_trusted_baseline_against_accepted_pin(trusted, _target(), pin)
    assert pin.candidate_content_hash == candidate.baseline_content_hash
    assert pin.trusted_baseline_content_hash == trusted.baseline_content_hash
    assert candidate_content_hash_from_trusted_baseline(trusted) == candidate.baseline_content_hash
    assert pin.previous_pin_content_hash is None


def test_directly_rehashed_trusted_document_is_rejected_by_full_pin() -> None:
    pin = _pin()
    forged = _rehash_baseline(_trusted(), source_sha256="9" * 64)

    with pytest.raises(AcceptedProductionBaselineValidationError) as captured:
        verify_trusted_baseline_against_accepted_pin(forged, _target(), pin)
    assert captured.value.code == "accepted_production_baseline_binding_mismatch"


def test_mismatched_candidate_and_trusted_transition_is_rejected() -> None:
    candidate = _candidate()
    unrelated = _rehash_baseline(_trusted(candidate), accepted_commit="8" * 40)

    with pytest.raises(AcceptedProductionBaselineInputError) as captured:
        build_accepted_production_baseline_pin(
            candidate,
            unrelated,
            _target(),
            generation=1,
        )
    assert captured.value.code == "accepted_production_baseline_transition_mismatch"


def test_generation_chain_and_active_pin_are_strict() -> None:
    first = _pin()
    second = _pin(generation=2, previous_pin=first)
    registry = build_accepted_production_baseline_registry((first, second))

    verify_accepted_production_baseline_registry(registry)
    assert active_accepted_production_baseline_pin(registry) == second
    assert second.previous_pin_content_hash == first.pin_content_hash

    broken_second = _rehash_pin(second, previous_pin_content_hash="7" * 64)
    with pytest.raises(AcceptedProductionBaselineRegistryError):
        build_accepted_production_baseline_registry((first, broken_second))


def test_registry_is_schema_valid_canonical_and_privacy_safe() -> None:
    pin = _pin()
    registry = build_accepted_production_baseline_registry((pin,))
    rendered = render_accepted_production_baseline_registry_json(registry)
    reparsed = parse_accepted_production_baseline_registry_bytes(rendered.encode("utf-8"))
    schema = json.loads(
        (ROOT / "schemas" / "accepted-production-baseline-registry-v1.schema.json").read_text(
            encoding="utf-8"
        )
    )

    jsonschema.Draft202012Validator(schema).validate(json.loads(rendered))
    assert reparsed == registry
    for forbidden in (
        "phase6d1g-000001@calendar.example",
        "phase6d1g-000002@calendar.example",
        _candidate().target_fingerprint,
        _target().calendar_id,
    ):
        assert forbidden not in rendered


@pytest.mark.parametrize(
    "mutate",
    (
        lambda raw: raw.replace(
            b'"registry_content_hash":',
            b'"unexpected": true,\n  "registry_content_hash":',
            1,
        ),
        lambda raw: raw.replace(
            b'"schema_version": "1.0",',
            b'"schema_version": "1.0",\n  "schema_version": "1.0",',
            1,
        ),
        lambda raw: raw.rstrip(b"\n"),
        lambda raw: raw.replace(
            PACKAGED_ACCEPTED_PRODUCTION_BASELINE_REGISTRY_HASH.encode("ascii"),
            ("f" * 64).encode("ascii"),
            1,
        ),
    ),
)
def test_registry_parser_rejects_unknown_duplicate_noncanonical_or_tampered_json(
    mutate: Any,
) -> None:
    rendered = render_accepted_production_baseline_registry_json(
        build_accepted_production_baseline_registry()
    ).encode("utf-8")

    with pytest.raises(AcceptedProductionBaselineRegistryError):
        parse_accepted_production_baseline_registry_bytes(mutate(rendered))


def test_nonproduction_markers_and_wrong_target_fail_before_pin_creation() -> None:
    candidate = _candidate()
    marked = _rehash_baseline(
        candidate,
        source_profile="accepted-synthetic-calendar",
    )
    marked_trusted = _trusted(marked)
    with pytest.raises(AcceptedProductionBaselineInputError):
        build_accepted_production_baseline_pin(
            marked,
            marked_trusted,
            _target(),
            generation=1,
        )

    other_calendar_id = "other-production@calendar.example"
    wrong_target = _target().model_copy(
        update={
            "calendar_id": other_calendar_id,
            "expected_target_fingerprint": calendar_id_fingerprint(other_calendar_id),
        }
    )
    with pytest.raises(AcceptedProductionBaselineInputError) as captured:
        build_accepted_production_baseline_pin(
            candidate,
            _trusted(candidate),
            wrong_target,
            generation=1,
        )
    assert captured.value.code == "accepted_production_baseline_target_mismatch"


def test_registry_hash_changes_for_any_active_pin_change() -> None:
    first = build_accepted_production_baseline_registry((_pin(),))
    changed_pin = _rehash_pin(first.pins[0], accepted_commit="6" * 40)
    second = build_accepted_production_baseline_registry((changed_pin,))

    assert first.registry_content_hash != second.registry_content_hash
    assert (
        calculate_accepted_production_baseline_registry_hash(first) == first.registry_content_hash
    )
