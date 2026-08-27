"""Strict repository-external JSON I/O for Accepted Production manifests."""

from __future__ import annotations

import hmac
import json
from datetime import date
from pathlib import Path
from typing import Any, cast

from pydantic import ValidationError

from tridentine_calendar_google_sync.accepted_production_source_manifest import (
    AcceptedProductionSourceManifestError,
    accepted_production_source_manifest_data,
    verify_accepted_production_source_manifest,
)
from tridentine_calendar_google_sync.accepted_production_source_manifest_models import (
    AcceptedProductionSourceManifest,
)
from tridentine_calendar_google_sync.sensitive_paths import (
    SensitivePathError,
    atomic_write_private_text,
    read_sensitive_bytes,
)

MAX_ACCEPTED_PRODUCTION_SOURCE_MANIFEST_BYTES = 4 * 1024 * 1024
_MANIFEST_KEYS = {
    "schema_version",
    "manifest_type",
    "production",
    "acceptance_state",
    "synthetic",
    "repository_identity",
    "repository_tag",
    "repository_commit",
    "ics_sha256",
    "profile_id",
    "event_count",
    "first_date",
    "last_date",
    "all_day_count",
    "timed_count",
    "recurring_event_count",
    "source_content_hash",
    "manifest_content_hash",
}


class AcceptedProductionSourceManifestIOError(AcceptedProductionSourceManifestError):
    """A content-free manifest parse, canonicalization, or path failure."""


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


def _closed_manifest(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _MANIFEST_KEYS:
        raise TypeError
    return cast(dict[str, Any], value)


def render_accepted_production_source_manifest_json(
    manifest: AcceptedProductionSourceManifest,
) -> str:
    """Render deterministic canonical private JSON after full verification."""

    verify_accepted_production_source_manifest(manifest)
    return (
        json.dumps(
            accepted_production_source_manifest_data(manifest),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
            allow_nan=False,
        )
        + "\n"
    )


def parse_accepted_production_source_manifest_bytes(
    raw_bytes: bytes,
) -> AcceptedProductionSourceManifest:
    """Parse one exact canonical manifest without echoing input content."""

    if len(raw_bytes) > MAX_ACCEPTED_PRODUCTION_SOURCE_MANIFEST_BYTES:
        raise AcceptedProductionSourceManifestIOError(
            "accepted_production_source_manifest_too_large",
            "Accepted Production source manifest exceeds the size limit",
        )
    try:
        value = json.loads(
            raw_bytes.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
        data = _closed_manifest(value)
        normalized = dict(data)
        for field_name in ("first_date", "last_date"):
            field_value = normalized[field_name]
            if not isinstance(field_value, str):
                raise TypeError
            normalized[field_name] = date.fromisoformat(field_value)
        manifest = AcceptedProductionSourceManifest.model_validate(normalized, strict=True)
        verify_accepted_production_source_manifest(manifest)
        canonical = render_accepted_production_source_manifest_json(manifest).encode("utf-8")
        if not hmac.compare_digest(raw_bytes, canonical):
            raise ValueError
        return manifest
    except AcceptedProductionSourceManifestError:
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
        raise AcceptedProductionSourceManifestIOError(
            "invalid_accepted_production_source_manifest",
            "Accepted Production source manifest is invalid or noncanonical",
        ) from exc


def load_accepted_production_source_manifest(
    path: str | Path,
) -> AcceptedProductionSourceManifest:
    """Load one bounded repository-external manifest from an explicit path."""

    try:
        return parse_accepted_production_source_manifest_bytes(
            read_sensitive_bytes(
                path,
                max_size=MAX_ACCEPTED_PRODUCTION_SOURCE_MANIFEST_BYTES,
            )
        )
    except AcceptedProductionSourceManifestError:
        raise
    except SensitivePathError as exc:
        raise AcceptedProductionSourceManifestIOError(
            "unsafe_accepted_production_source_manifest_path",
            "Accepted Production source manifest path is unsafe or unavailable",
        ) from exc


def write_accepted_production_source_manifest(
    manifest: AcceptedProductionSourceManifest,
    path: str | Path,
) -> Path:
    """Atomically create one private repository-external manifest without overwrite."""

    verify_accepted_production_source_manifest(manifest)
    try:
        atomic_write_private_text(
            path,
            render_accepted_production_source_manifest_json(manifest),
            overwrite=False,
            max_size=MAX_ACCEPTED_PRODUCTION_SOURCE_MANIFEST_BYTES,
        )
        return Path(path)
    except SensitivePathError as exc:
        raise AcceptedProductionSourceManifestIOError(
            "accepted_production_source_manifest_write_failed",
            "Accepted Production source manifest could not be written safely",
        ) from exc


__all__ = [
    "MAX_ACCEPTED_PRODUCTION_SOURCE_MANIFEST_BYTES",
    "AcceptedProductionSourceManifestIOError",
    "load_accepted_production_source_manifest",
    "parse_accepted_production_source_manifest_bytes",
    "render_accepted_production_source_manifest_json",
    "write_accepted_production_source_manifest",
]
