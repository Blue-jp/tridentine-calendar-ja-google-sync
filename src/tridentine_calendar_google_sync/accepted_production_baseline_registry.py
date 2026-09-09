"""Canonical packaged registry for accepted Production baseline pins."""

from __future__ import annotations

import hashlib
import hmac
import json
from importlib import resources
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from tridentine_calendar_google_sync.accepted_production_baseline import (
    AcceptedProductionBaselineError,
    AcceptedProductionBaselineValidationError,
    accepted_production_baseline_pin_data,
    verify_accepted_production_baseline_pin,
)
from tridentine_calendar_google_sync.accepted_production_baseline_models import (
    ACCEPTED_PRODUCTION_BASELINE_SOURCE_REPOSITORY,
    ACCEPTED_PRODUCTION_BASELINE_SYNC_REPOSITORY,
    AcceptedProductionBaselinePin,
    AcceptedProductionBaselineRegistry,
)

MAX_ACCEPTED_PRODUCTION_BASELINE_REGISTRY_BYTES = 4 * 1024 * 1024
ACCEPTED_PRODUCTION_BASELINE_REGISTRY_FILENAME = "production-baseline-registry-v1.json"
PACKAGED_ACCEPTED_PRODUCTION_BASELINE_REGISTRY_HASH = (
    "f6b8e8206bb507d9a05f46d99a6787cadf6a9f1b6c96b2e35c06ab40616d1748"
)
_REGISTRY_HASH_DOMAIN = (
    b"tridentine-calendar-google-sync:accepted-production-baseline-registry:v1\x00"
)
_REGISTRY_KEYS = {
    "schema_version",
    "registry_type",
    "production",
    "synthetic",
    "source_repository",
    "sync_repository",
    "active_pin_id",
    "pins",
    "registry_content_hash",
}
_PIN_KEYS = set(AcceptedProductionBaselinePin.model_fields)
_ZERO_SHA256 = "0" * 64


class AcceptedProductionBaselineRegistryError(AcceptedProductionBaselineError):
    """A content- and path-free packaged-registry failure."""


class _DuplicateJsonKey(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError


def accepted_production_baseline_registry_data(
    registry: AcceptedProductionBaselineRegistry,
) -> dict[str, object]:
    """Return the complete canonical public-safe registry document."""

    return {
        "schema_version": registry.schema_version,
        "registry_type": registry.registry_type,
        "production": registry.production,
        "synthetic": registry.synthetic,
        "source_repository": registry.source_repository,
        "sync_repository": registry.sync_repository,
        "active_pin_id": registry.active_pin_id,
        "pins": [accepted_production_baseline_pin_data(pin) for pin in registry.pins],
        "registry_content_hash": registry.registry_content_hash,
    }


def _hash_mapping(value: dict[str, object]) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(_REGISTRY_HASH_DOMAIN + encoded).hexdigest()


def calculate_accepted_production_baseline_registry_hash(
    registry: AcceptedProductionBaselineRegistry,
) -> str:
    """Calculate the domain-separated full registry hash."""

    data = accepted_production_baseline_registry_data(registry)
    del data["registry_content_hash"]
    return _hash_mapping(data)


def verify_accepted_production_baseline_registry(
    registry: AcceptedProductionBaselineRegistry,
) -> None:
    """Verify every pin, generation link, fixed field, and registry hash."""

    if not isinstance(registry, AcceptedProductionBaselineRegistry):
        raise AcceptedProductionBaselineRegistryError(
            "invalid_accepted_production_baseline_registry",
            "Accepted Production baseline registry is invalid",
        )
    try:
        AcceptedProductionBaselineRegistry.model_validate(
            registry.model_dump(mode="python"),
            strict=True,
        )
    except ValidationError as exc:
        raise AcceptedProductionBaselineRegistryError(
            "accepted_production_baseline_registry_policy_mismatch",
            "Accepted Production baseline registry policy verification failed",
        ) from exc
    try:
        for pin in registry.pins:
            verify_accepted_production_baseline_pin(pin)
    except AcceptedProductionBaselineValidationError as exc:
        raise AcceptedProductionBaselineRegistryError(exc.code, exc.public_message) from exc
    if not hmac.compare_digest(
        calculate_accepted_production_baseline_registry_hash(registry),
        registry.registry_content_hash,
    ):
        raise AcceptedProductionBaselineRegistryError(
            "accepted_production_baseline_registry_hash_mismatch",
            "Accepted Production baseline registry integrity verification failed",
        )


def build_accepted_production_baseline_registry(
    pins: tuple[AcceptedProductionBaselinePin, ...] = (),
) -> AcceptedProductionBaselineRegistry:
    """Build one canonical registry; an empty registry remains fail-closed."""

    try:
        provisional = AcceptedProductionBaselineRegistry(
            source_repository=ACCEPTED_PRODUCTION_BASELINE_SOURCE_REPOSITORY,
            sync_repository=ACCEPTED_PRODUCTION_BASELINE_SYNC_REPOSITORY,
            active_pin_id=pins[-1].pin_id if pins else None,
            pins=pins,
            registry_content_hash=_ZERO_SHA256,
        )
    except ValidationError as exc:
        raise AcceptedProductionBaselineRegistryError(
            "accepted_production_baseline_registry_invalid",
            "Accepted Production baseline pins cannot form a valid registry",
        ) from exc
    registry = provisional.model_copy(
        update={
            "registry_content_hash": calculate_accepted_production_baseline_registry_hash(
                provisional
            )
        }
    )
    verify_accepted_production_baseline_registry(registry)
    return registry


def render_accepted_production_baseline_registry_json(
    registry: AcceptedProductionBaselineRegistry,
) -> str:
    """Render deterministic canonical registry JSON."""

    verify_accepted_production_baseline_registry(registry)
    return (
        json.dumps(
            accepted_production_baseline_registry_data(registry),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def _closed_registry(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _REGISTRY_KEYS:
        raise TypeError
    return cast(dict[str, Any], value)


def _closed_pin(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _PIN_KEYS:
        raise TypeError
    return cast(dict[str, Any], value)


def parse_accepted_production_baseline_registry_bytes(
    raw_bytes: bytes,
) -> AcceptedProductionBaselineRegistry:
    """Parse one exact canonical registry without accepting extensions."""

    if len(raw_bytes) > MAX_ACCEPTED_PRODUCTION_BASELINE_REGISTRY_BYTES:
        raise AcceptedProductionBaselineRegistryError(
            "accepted_production_baseline_registry_too_large",
            "Accepted Production baseline registry exceeds the size limit",
        )
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        data = _closed_registry(value)
        raw_pins = data.get("pins")
        if not isinstance(raw_pins, list):
            raise TypeError
        pins = tuple(
            AcceptedProductionBaselinePin.model_validate(_closed_pin(raw_pin), strict=True)
            for raw_pin in raw_pins
        )
        normalized = dict(data)
        normalized["pins"] = pins
        registry = AcceptedProductionBaselineRegistry.model_validate(normalized, strict=True)
        verify_accepted_production_baseline_registry(registry)
        canonical = render_accepted_production_baseline_registry_json(registry).encode("utf-8")
        if not hmac.compare_digest(raw_bytes, canonical):
            raise ValueError
        return registry
    except AcceptedProductionBaselineError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateJsonKey,
        KeyError,
        TypeError,
        ValueError,
        ValidationError,
    ) as exc:
        raise AcceptedProductionBaselineRegistryError(
            "invalid_accepted_production_baseline_registry",
            "Accepted Production baseline registry is invalid or noncanonical",
        ) from exc


def _packaged_registry_bytes() -> bytes:
    package_candidate = resources.files("tridentine_calendar_google_sync").joinpath(
        "_accepted_baselines",
        ACCEPTED_PRODUCTION_BASELINE_REGISTRY_FILENAME,
    )
    try:
        if package_candidate.is_file():
            raw = package_candidate.read_bytes()
            if len(raw) <= MAX_ACCEPTED_PRODUCTION_BASELINE_REGISTRY_BYTES:
                return raw
    except (OSError, RuntimeError):
        pass

    try:
        editable_candidate = (
            Path(__file__).resolve().parents[2]
            / "accepted_baselines"
            / ACCEPTED_PRODUCTION_BASELINE_REGISTRY_FILENAME
        )
        if editable_candidate.is_file():
            raw = editable_candidate.read_bytes()
            if len(raw) <= MAX_ACCEPTED_PRODUCTION_BASELINE_REGISTRY_BYTES:
                return raw
    except (OSError, RuntimeError):
        pass

    raise AcceptedProductionBaselineRegistryError(
        "accepted_production_baseline_registry_unavailable",
        "Packaged Accepted Production baseline registry is unavailable",
    )


def load_packaged_accepted_production_baseline_registry() -> AcceptedProductionBaselineRegistry:
    """Load only the package-owned registry; no external override exists."""

    registry = parse_accepted_production_baseline_registry_bytes(_packaged_registry_bytes())
    if not hmac.compare_digest(
        registry.registry_content_hash,
        PACKAGED_ACCEPTED_PRODUCTION_BASELINE_REGISTRY_HASH,
    ):
        raise AcceptedProductionBaselineRegistryError(
            "accepted_production_baseline_registry_package_mismatch",
            "Packaged Accepted Production baseline registry does not match the code pin",
        )
    return registry


def active_accepted_production_baseline_pin(
    registry: AcceptedProductionBaselineRegistry,
) -> AcceptedProductionBaselinePin:
    """Return the sole newest active pin or fail closed while uninitialized."""

    verify_accepted_production_baseline_registry(registry)
    if registry.active_pin_id is None or not registry.pins:
        raise AcceptedProductionBaselineRegistryError(
            "accepted_production_baseline_registry_inactive",
            "No Accepted Production baseline pin is active",
        )
    active = registry.pins[-1]
    if not hmac.compare_digest(active.pin_id, registry.active_pin_id):
        raise AcceptedProductionBaselineRegistryError(
            "accepted_production_baseline_registry_active_pin_mismatch",
            "Accepted Production baseline active pin is invalid",
        )
    return active


def load_active_accepted_production_baseline_pin() -> AcceptedProductionBaselinePin:
    """Load the package registry and require its newest active pin."""

    return active_accepted_production_baseline_pin(
        load_packaged_accepted_production_baseline_registry()
    )


__all__ = [
    "ACCEPTED_PRODUCTION_BASELINE_REGISTRY_FILENAME",
    "MAX_ACCEPTED_PRODUCTION_BASELINE_REGISTRY_BYTES",
    "PACKAGED_ACCEPTED_PRODUCTION_BASELINE_REGISTRY_HASH",
    "AcceptedProductionBaselineRegistryError",
    "accepted_production_baseline_registry_data",
    "active_accepted_production_baseline_pin",
    "build_accepted_production_baseline_registry",
    "calculate_accepted_production_baseline_registry_hash",
    "load_active_accepted_production_baseline_pin",
    "load_packaged_accepted_production_baseline_registry",
    "parse_accepted_production_baseline_registry_bytes",
    "render_accepted_production_baseline_registry_json",
    "verify_accepted_production_baseline_registry",
]
